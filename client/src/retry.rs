//! This file provides a `Retry` connection, which allows for reconnections
//! on top of a normal connection.
//!
//! TODO FOR ALL CRATES: figure out where we need to bail,
//! and where we can just return. Most of the errors already have
//! enough context from previous bails.

use std::{collections::HashSet, marker::PhantomData, sync::Arc, time::Duration};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use proto::{
    connection::{
        auth::user::UserAuth,
        protocols::{Connection, Protocol},
    },
    crypto::{KeyPair, Serializable},
    error::{Error, Result},
    message::{Message, Topic},
};
use tokio::{
    sync::{RwLock, Semaphore},
    time::sleep,
};
use tracing::error;

use crate::bail;

/// `Retry` is a wrapper around a `Fallible` connection.
///
/// It employs synchronization around a `Fallible`, as well as retry logic.
/// Can be cloned to provide a handle to the same underlying elastic connection.
#[derive(Clone)]
pub struct Retry<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
> {
    pub inner: Arc<Inner<SignatureScheme, ProtocolType>>,
}

/// `Inner` is held exclusively by `Retry`, wherein an `Arc` is used
/// to facilitate interior mutability.
pub struct Inner<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
> {
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal.
    endpoint: String,

    /// The underlying connection, which we modify to facilitate reconnections.
    connection: RwLock<ProtocolType::Connection>,

    /// The task that runs in the background that reconnects us when we need
    /// to be. This is so we don't spawn multiple tasks at once
    reconnect_semaphore: Semaphore,

    pub keypair: KeyPair<SignatureScheme>,

    /// The topics we're currently subscribed to. We need this here so we can send our subscriptions
    /// when we connect to a new server.
    pub subscribed_topics: Arc<RwLock<HashSet<Topic>>>,

    /// Phantom data that lets us use `ProtocolType`, `AuthFlow`, and
    /// `SignatureScheme` downstream.
    pd: PhantomData<(SignatureScheme, ProtocolType)>,
}

/// The configuration needed to construct a `Retry` connection.
pub struct Config<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
> {
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal.
    pub endpoint: String,

    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    pub keypair: KeyPair<SignatureScheme>,

    /// The topics we're currently subscribed to. We need this here so we can send our subscriptions
    /// when we connect to a new server.
    pub subscribed_topics: Vec<Topic>,

    /// The phantom data we need to be able to make use of these types
    pub pd: PhantomData<ProtocolType>,
}

/// This is a macro that helps with reconnections when sending
/// and receiving messages. You can specify the operation and it
/// will reconnect on the operation's failure, while handling all
/// reconnection logic and synchronization patterns.
///
/// TODO: document invariant with "messages will not retry"
macro_rules! try_with_reconnect {
    ($self: expr, $operation: ident,  $($arg:tt)*) => {{
        // Acquire read guard for sending and receiving messages
        let Ok(read_guard) = $self.inner.connection.try_read() else {
            return Err(Error::Connection("message failed: reconnection in progress".to_string()));
        };

        // Perform operation, see if it errors
        let operation = read_guard.$operation($($arg)*).await;
        match operation{
            Ok(res) => res,
            Err(err) => {
            // Acquire semaphore. If another task is doing this, just return an error
            // TODO: global sleep. If we try to connect twice, it happens sequentially without waiting (because the sleep
            // only happens on the failed case. We can maybe store a variable somewhere and wait for that.
            if $self.inner.reconnect_semaphore.try_acquire().is_ok() {
                // Acquire write guard, drop read guard
                drop(read_guard);

                // Clone everything we need to connect
                // TODO: we want to minimize cloning this. We should sign a message
                // earlier.
                let inner = $self.inner.clone();

                tokio::spawn(async move{
                    // Get write guard on connection so we can write to it
                    let mut write_guard = inner.connection.write().await;

                // Loop to connect and authenticate
                let connection = loop {
                    // Create a connection
                    match connect_and_authenticate::<SignatureScheme, ProtocolType>(
                        &inner.endpoint,
                        &inner.keypair,
                        inner.subscribed_topics.read().await.clone()
                    )
                    .await{
                        Ok(connection) => break connection,
                        Err(err) => {
                            error!("failed connection: {err}");
                            // Sleep so we don't overload the server
                            sleep(Duration::from_secs(5)).await;
                        }
                    }
                };

                // Set connection to new connection
                *write_guard = connection;

                // Drop here so other tasks can start sending messages
                drop(write_guard);
            });
        }

        // If somebody is already trying to reconnect, fail instantly
        return Err(Error::Connection(format!(
            "connection failed, reconnecting to endpoint: {err}"
        )));
    }
    }
}};
}

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > Retry<SignatureScheme, ProtocolType>
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    /// Creates a new `Retry` connection from a `Config` and an (optional) pre-existing
    /// `Fallible` connection.
    ///
    /// This allows us to create elastic clients that always try to maintain a connection
    /// with each other.
    ///
    /// # Errors
    /// - If we are unable to either parse or bind an endpoint to the local address.
    /// - If we are unable to make the initial connection
    /// TODO: figure out if we want retries here
    pub async fn from_config_and_connection(
        config: Config<SignatureScheme, ProtocolType>,
        maybe_connection: Option<ProtocolType::Connection>,
    ) -> Result<Self> {
        // Extrapolate values from the underlying client configuration
        let Config {
            endpoint,
            keypair,
            subscribed_topics,
            pd: _,
        } = config;

        // Wrap subscribed topics so we can use it now and later
        let subscribed_topics = Arc::new(RwLock::new(HashSet::from_iter(subscribed_topics)));

        // Perform the initial connection and authentication if not provided.
        // This is to validate that we have correct parameters and all.
        //
        // TODO: cancel conditionally depending on what kind of error, or retry-
        // based.
        //
        // TODO: clean this up
        let connection = if let Some(connection) = maybe_connection {
            connection
        } else {
            bail!(
                connect_and_authenticate::<SignatureScheme, ProtocolType>(
                    &endpoint,
                    &keypair,
                    subscribed_topics.read().await.clone()
                )
                .await,
                Connection,
                "failed initial connection"
            )
        };

        // Return the slightly transformed connection.
        Ok(Self {
            inner: Arc::from(Inner {
                endpoint,
                // Use the existing connection
                connection: RwLock::from(connection),
                reconnect_semaphore: Semaphore::const_new(1),
                keypair,
                subscribed_topics,
                pd: PhantomData,
            }),
        })
    }

    /// Sends a message to the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-send messages)
    ///
    /// # Errors
    /// - If we fail to serialize the message
    /// - If we are in the middle of reconnecting
    /// - If the message sending failed
    pub async fn send_message(&self, message: Message) -> Result<()> {
        // Serialize the message
        let message = Arc::from(bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        ));

        // Try to send the message, reconnecting if needed
        Ok(try_with_reconnect!(self, send_message_raw, message,))
    }

    /// Receives a message from the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-receive messages)
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    /// - If the message receiving failed
    pub async fn receive_message(&self) -> Result<Message> {
        // Try to send the message, reconnecting if needed
        Ok(try_with_reconnect!(self, recv_message,))
    }
}

async fn connect_and_authenticate<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
>(
    marshal_endpoint: &str,
    keypair: &KeyPair<SignatureScheme>,
    subscribed_topics: HashSet<Topic>,
) -> Result<ProtocolType::Connection>
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    // Make the connection to the marshal
    let connection = bail!(
        ProtocolType::Connection::connect(marshal_endpoint.to_owned()).await,
        Connection,
        "failed to connect to endpoint"
    );

    // Authenticate the connection to the marshal (if not provided)
    let (broker_address, permit) = bail!(
        UserAuth::<SignatureScheme, ProtocolType>::authenticate_with_marshal(&connection, keypair)
            .await,
        Authentication,
        "failed to authenticate to marshal"
    );

    // Make the connection to the broker
    let connection = bail!(
        ProtocolType::Connection::connect(broker_address).await,
        Connection,
        "failed to connect to broker"
    );

    // Authenticate the connection to the broker
    bail!(
        UserAuth::<SignatureScheme, ProtocolType>::authenticate_with_broker(
            &connection,
            permit,
            subscribed_topics
        )
        .await,
        Authentication,
        "failed to authenticate to broker"
    );

    Ok(connection)
}
