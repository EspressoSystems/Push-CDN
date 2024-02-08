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
        batch::BatchedSender,
        protocols::{Protocol, Receiver},
    },
    crypto::{KeyPair, Serializable},
    error::{Error, Result},
    message::{Message, Topic},
};
use tokio::{
    sync::{Mutex, RwLock, Semaphore},
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

    /// The send-side of the connection. We can `RwLock` here because the BatchedSender
    /// is already using interior mutability tricks.
    sender: RwLock<BatchedSender<ProtocolType>>,

    /// The receive side of the connection. We need a write-lock here because it needs to be
    /// mutable. TODO: do something like `BatchedSender` but with `OwnedReader` or something.
    receiver: Mutex<ProtocolType::Receiver>,

    /// The task that runs in the background that reconnects us when we need
    /// to be. This is so we don't spawn multiple tasks at once
    reconnect_semaphore: Semaphore,

    pub keypair: KeyPair<SignatureScheme>,

    /// The topics we're currently subscribed to. We need this so we can send our subscriptions
    /// when we connect to a new server.
    pub subscribed_topics: RwLock<HashSet<Topic>>,

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
macro_rules! try_with_reconnect {
    ($self: expr, $subject: ident, $out: expr) => {{
        // Perform operation, see if it errors
        match $out {
            Ok(res) => res,
            Err(err) => {
                // Acquire semaphore. If another task is doing this, just return an error
                if $self.inner.reconnect_semaphore.try_acquire().is_ok() {
                    // Clone everything we need to connect
                    let inner = $self.inner.clone();

                    // Spawn a task to reconnect
                    tokio::spawn(async move {
                        // Get write guard on connection so we can write to it
                        let mut send_guard = inner.sender.write().await;
                        let mut receive_guard = inner.receiver.lock().await;

                        // Loop to connect and authenticate
                        let connection = loop {
                            // Create a connection
                            match connect_and_authenticate::<SignatureScheme, ProtocolType>(
                                &inner.endpoint,
                                &inner.keypair,
                                inner.subscribed_topics.read().await.clone(),
                            )
                            .await
                            {
                                Ok(connection) => break connection,
                                Err(err) => {
                                    error!("failed connection: {err}");
                                    // Sleep so we don't overload the server
                                    sleep(Duration::from_secs(5)).await;
                                }
                            }
                        };

                        // Update sender and receiver
                        // TODO: parameterize duration and size
                        *send_guard =
                            BatchedSender::from(connection.0, Duration::from_millis(50), 1500);
                        *receive_guard = connection.1;

                        drop(send_guard);
                        drop(receive_guard);
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
    /// Creates a new `Retry` connection from a `Config`
    /// Attempts to make an initial connection.
    /// This allows us to create elastic clients that always try to maintain a connection.
    ///
    /// # Errors
    /// - If we are unable to either parse or bind an endpoint to the local address.
    /// - If we are unable to make the initial connection
    /// TODO: figure out if we want retries here
    pub async fn from_config(config: Config<SignatureScheme, ProtocolType>) -> Result<Self> {
        // Extrapolate values from the underlying client configuration
        let Config {
            endpoint,
            keypair,
            subscribed_topics,
            pd: _,
        } = config;

        // Wrap subscribed topics so we can use it now and later
        let subscribed_topics = RwLock::new(HashSet::from_iter(subscribed_topics));

        // Perform the initial connection and authentication
        let connection = bail!(
            connect_and_authenticate::<SignatureScheme, ProtocolType>(
                &endpoint,
                &keypair,
                subscribed_topics.read().await.clone()
            )
            .await,
            Connection,
            "failed initial connection"
        );

        // Return the slightly transformed connection.
        Ok(Self {
            inner: Arc::from(Inner {
                endpoint,
                // TODO: parameterize batch params
                sender: RwLock::from(BatchedSender::from(
                    connection.0,
                    Duration::from_millis(50),
                    1500,
                )),
                receiver: Mutex::from(connection.1),
                reconnect_semaphore: Semaphore::const_new(1),
                keypair,
                subscribed_topics,
                pd: PhantomData,
            }),
        })
    }

    /// Sends a message to the underlying fallible connection. Reconnection is handled under
    /// the hood. Messages will fail if the connection is currently closed or reconnecting.
    ///
    /// # Errors
    /// If the message sending fails. For example:
    /// - If we are reconnecting
    /// - If we are disconnected
    pub fn send_message(&self, message: &Message) -> Result<()> {
        // Serialize the message
        let message = bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        );

        // Try to acquire the read lock. If we can't, we are reconnecting.
        if let Ok(send_lock) = self.inner.sender.try_read() {
            // Continue if we were able to acquire the lock
            let out = send_lock.queue_message_back(Arc::from(message));
            Ok(try_with_reconnect!(self, send_lock, out))
        } else {
            // Return an error if we're reconnecting
            Err(Error::Connection("reconnection in progress".to_string()))
        }
    }

    /// Receives a message from the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-receive messages)
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    /// - If the message receiving failed
    pub async fn receive_message(&self) -> Result<Message> {
        // We can use `try_lock` here because only two tasks will be using it:
        // either we're receiving or somebody is reconnecting us.
        if let Ok(mut receiver_guard) = self.inner.receiver.try_lock() {
            // We were able to get the lock, we aren't reconnecting
            let out = receiver_guard.recv_message().await;
            Ok(try_with_reconnect!(self, send_lock, out))
        } else {
            // We couldn't get the lock, we are reconnecting
            // Return an error
            Err(Error::Connection("reconnection in progress".to_string()))
        }
    }
}

async fn connect_and_authenticate<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
>(
    marshal_endpoint: &str,
    keypair: &KeyPair<SignatureScheme>,
    subscribed_topics: HashSet<Topic>,
) -> Result<(ProtocolType::Sender, ProtocolType::Receiver)>
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    // Make the connection to the marshal
    let mut connection = bail!(
        ProtocolType::connect(marshal_endpoint.to_owned()).await,
        Connection,
        "failed to connect to endpoint"
    );

    // Authenticate the connection to the marshal (if not provided)
    let (broker_address, permit) = bail!(
        UserAuth::<SignatureScheme, ProtocolType>::authenticate_with_marshal(
            &mut connection,
            keypair
        )
        .await,
        Authentication,
        "failed to authenticate to marshal"
    );

    // Make the connection to the broker
    let mut connection = bail!(
        ProtocolType::connect(broker_address).await,
        Connection,
        "failed to connect to broker"
    );

    // Authenticate the connection to the broker
    bail!(
        UserAuth::<SignatureScheme, ProtocolType>::authenticate_with_broker(
            &mut connection,
            permit,
            subscribed_topics
        )
        .await,
        Authentication,
        "failed to authenticate to broker"
    );

    Ok(connection)
}
