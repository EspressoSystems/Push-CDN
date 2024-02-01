//! This file provides a `Sticky` connection, which allows for reconnections
//! on top of a normal implementation of a `Fallible` connection.
//!
//! TODO FOR ALL CRATES: figure out where we need to bail,
//! and where we can just return. Most of the errors already have
//! enough context from previous bails.

use std::{collections::HashSet, marker::PhantomData, sync::Arc, time::Duration};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use tokio::{
    sync::{Mutex, RwLock, Semaphore},
    time::sleep,
};
use tracing::error;

use crate::{
    bail,
    error::{Error, Result},
    message::{Message, Topic},
};

use super::{flow::Flow, Connection};

/// `Sticky` is a wrapper around a `Fallible` connection.
///
/// It employs synchronization around a `Fallible`, as well as retry logic for both switching
/// connections at a certain failure threshold and reconnecting under said threshold.
///
/// Can be cloned to provide a handle to the same underlying elastic connection.
#[derive(Clone)]
pub struct Sticky<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ConnectionType: Connection,
    ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
> {
    pub inner: Arc<StickyInner<SignatureScheme, ConnectionType, ConnectionFlow>>,
}

/// `StickyInner` is held exclusively by `Sticky`, wherein an `Arc` is used
/// to facilitate interior mutability.
pub struct StickyInner<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ConnectionType: Connection,
    ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
> {
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal. The authentication flow depends on the function defined in
    /// `auth_flow`, so this may not be the final address (e.g. if you are asking the
    /// marshal for it).
    remote_address: String,

    /// The underlying (public) verification key, used to authenticate with the server. Checked against the stake
    /// table.
    verification_key: SignatureScheme::VerificationKey,

    /// The underlying (private) signing key, used to sign messages to send to the server during the
    /// authentication phase.
    signing_key: SignatureScheme::SigningKey,

    /// A list of topics we are subscribed to. This allows us to, when reconnecting,
    /// easily provide the list of topics we care about.
    pub subscribed_topics: Mutex<HashSet<Topic>>,

    /// The underlying connection, which we modify to facilitate reconnections.
    connection: RwLock<ConnectionType>,

    /// The task that runs in the background that reconnects us when we need
    /// to be. This is so multiple tasks don't try doing it at the same time.
    reconnect_semaphore: Semaphore,

    _pd: PhantomData<(ConnectionType, ConnectionFlow)>,
}

/// The configuration needed to construct a client
pub struct Config<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ConnectionType: Connection,
    ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
> {
    /// The verification (public) key. Sent to the server to verify
    /// our identity.
    pub verification_key: SignatureScheme::VerificationKey,

    /// The signing (private) key. Only used for signing the authentication
    /// message sent to the server upon connection.
    pub signing_key: SignatureScheme::SigningKey,

    /// The remote address(es) to connect and authenticate to.
    pub remote_address: String,

    /// The topics we want to be subscribed to initially. This is needed so that
    /// we can resubscribe to the same topics upon reconnection.
    pub initial_subscribed_topics: Vec<Topic>,

    /// Phantom data that we pass down to `Sticky` and `StickInner`.
    /// Allows us to be generic over a connection method, because
    /// we need multiple.
    pub _pd: PhantomData<(ConnectionType, ConnectionFlow)>,
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
        let read_guard = match $self.inner.connection.try_read(){
            Ok(read_guard) => read_guard,
            Err(_) => {
                return Err(Error::Connection("message failed: reconnection in progress".to_string()));
            }
        };

        // Perform operation, see if it errors
        match read_guard.$operation($($arg)*).await{
            Ok(res) => res,
            Err(err) => {

            // Acquire semaphore. If another task is doing this, just return an error
            if $self.inner.reconnect_semaphore.try_acquire().is_ok() {
                // Acquire write guard, drop read guard
                drop(read_guard);
                let mut write_guard = $self.inner.connection.write().await;

                // Lock subscribed topics
                let subscribed_topics = &$self.inner.subscribed_topics.lock().await;
                let topics:Vec<Topic> = subscribed_topics.iter().cloned().collect();

                // Loop to connect and authenticate
                let connection = loop {
                    // Try to connect
                    match ConnectionFlow::connect(
                        $self.inner.remote_address.clone(),
                        &$self.inner.signing_key,
                        &$self.inner.verification_key,
                        topics.clone()
                    )
                    .await
                    {
                        Ok(connection) => break connection,
                        Err(err) => error!("failed to connect to endpoint: {err}. retrying"),
                    }

                    // Sleep so we don't overload the server
                    sleep(Duration::from_secs(5)).await;
                };

                // Set connection to new connection
                *write_guard = connection;
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
        ConnectionType: Connection,
        ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
    > Sticky<SignatureScheme, ConnectionType, ConnectionFlow>
{
    /// Creates a new `Sticky` connection from a `Config` and an (optional) pre-existing
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
        config: Config<SignatureScheme, ConnectionType, ConnectionFlow>,
        maybe_connection: Option<ConnectionType>,
    ) -> Result<Self> {
        // Extrapolate values from the underlying client configuration
        let Config {
            verification_key,
            signing_key,
            remote_address,
            initial_subscribed_topics,
            _pd,
        } = config;

        // Perform the initial connection if not provided. This is to validate
        // that we have correct parameters and all.
        //
        // TODO: cancel conditionally depending on what kind of error, or retry-
        // based.
        //
        // TODO: clean this up
        let connection = match maybe_connection {
            Some(connection) => connection,
            None => {
                bail!(
                    ConnectionFlow::connect(
                        remote_address.clone(),
                        &signing_key,
                        &verification_key,
                        initial_subscribed_topics.clone(),
                    )
                    .await,
                    Connection,
                    "failed to make initial connection"
                )
            }
        };

        // Return the slightly transformed connection.
        Ok(Self {
            inner: Arc::from(StickyInner {
                remote_address,
                signing_key,
                verification_key,
                subscribed_topics: Mutex::from(HashSet::from_iter(initial_subscribed_topics)),
                // Use the existing connection
                connection: RwLock::from(connection),
                reconnect_semaphore: Semaphore::const_new(1),
                _pd,
            }),
        })
    }

    /// Sends a message to the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-send messages)
    pub async fn send_message(&self, message: Arc<Message>) -> Result<()> {
        // Try to send the message, reconnecting if needed
        Ok(try_with_reconnect!(self, send_message, message,))
    }

    /// Receives a message from the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-receive messages)
    pub async fn receive_message(&self) -> Result<Message> {
        // Try to send the message, reconnecting if needed
        Ok(try_with_reconnect!(self, recv_message,))
    }
}
