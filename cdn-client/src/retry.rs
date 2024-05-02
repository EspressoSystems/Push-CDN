//! This file provides a `Retry` connection, which allows for reconnections
//! on top of a normal connection.
//!
//! TODO FOR ALL CRATES: figure out where we need to bail,
//! and where we can just return. Most of the errors already have
//! enough context from previous bails.

use std::{collections::HashSet, sync::Arc, time::Duration};

use cdn_proto::{
    connection::{
        auth::user::UserAuth,
        protocols::{Connection as _, Protocol as _},
    },
    crypto::signature::KeyPair,
    def::{Connection, ConnectionDef, Protocol, Scheme},
    error::{Error, Result},
    message::{Message, Topic},
};
use tokio::{
    sync::{OnceCell, RwLock},
    time::sleep,
};
use tracing::{error, info};

use crate::bail;

/// `Retry` is a wrapper around a fallible connection.
///
/// It employs synchronization as well as retry logic.
/// Can be cloned to provide a handle to the same underlying elastic connection.
#[derive(Clone)]
pub struct Retry<C: ConnectionDef> {
    pub inner: Arc<Inner<C>>,
}

/// `Inner` is held exclusively by `Retry`, wherein an `Arc` is used
/// to facilitate interior mutability.
pub struct Inner<C: ConnectionDef> {
    /// This is the remote endpoint of the marshal that we authenticate with.
    endpoint: String,

    /// Whether or not to use the trust the local, pinned CA. It is insecure to use this in
    /// a production environment.
    use_local_authority: bool,

    /// The underlying connection
    connection: Arc<RwLock<OnceCell<Connection<C>>>>,

    /// The keypair to use when authenticating
    pub keypair: KeyPair<Scheme<C>>,

    /// The topics we're currently subscribed to. We need this so we can send our subscriptions
    /// when we connect to a new server.
    pub subscribed_topics: RwLock<HashSet<Topic>>,
}

impl<C: ConnectionDef> Inner<C> {
    /// Attempt a reconnection to the remote marshal endpoint.
    /// Returns the connection verbatim without updating any internal
    /// structs.
    ///
    /// # Errors
    /// - If the connection failed
    /// - If authentication failed
    async fn connect(self: &Arc<Self>) -> Result<Connection<C>> {
        // Make the connection to the marshal
        let connection = bail!(
            Protocol::<C>::connect(&self.endpoint, self.use_local_authority).await,
            Connection,
            "failed to connect to endpoint"
        );

        // Authenticate the connection to the marshal (if not provided)
        let (broker_endpoint, permit) = bail!(
            UserAuth::<C>::authenticate_with_marshal(&connection, &self.keypair).await,
            Authentication,
            "failed to authenticate to marshal"
        );

        // Make the connection to the broker
        let connection = bail!(
            Protocol::<C>::connect(&broker_endpoint, self.use_local_authority).await,
            Connection,
            "failed to connect to broker"
        );

        // Authenticate the connection to the broker
        bail!(
            UserAuth::<C>::authenticate_with_broker(
                &connection,
                permit,
                self.subscribed_topics.read().await.clone()
            )
            .await,
            Authentication,
            "failed to authenticate to broker"
        );

        info!(id = broker_endpoint, "connected to broker");

        Ok(connection)
    }
}

/// The configuration needed to construct a `Retry` connection.
#[derive(Clone)]
pub struct Config<C: ConnectionDef> {
    /// This is the remote endpoint of the marshal that we authenticate with.
    pub endpoint: String,

    /// Whether or not to use the trust the local, pinned CA. It is insecure to use this in
    /// a production environment.
    pub use_local_authority: bool,

    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    pub keypair: KeyPair<Scheme<C>>,

    /// The topics we're currently subscribed to. We need this here so we can send our subscriptions
    /// when we connect to a new server.
    pub subscribed_topics: Vec<Topic>,
}

/// This is a macro that helps with reconnections when sending
/// and receiving messages. You can specify the operation and it
/// will reconnect on the operation's failure, while handling all
/// reconnection logic and synchronization patterns.
macro_rules! try_with_reconnect {
    ($self: expr, $out: expr) => {{
        // See if operation was an error
        match $out {
            Ok(res) => Ok(res),
            Err(err) => {
                // Acquire our "semaphore". If another task is doing this, just return an error
                if let Ok(mut connection_guard) = $self.inner.connection.clone().try_write_owned() {
                    error!("connection failed: {err}, reconnecting");
                    
                    // Clone `inner` so we can use it in the task
                    let inner = $self.inner.clone();
                    // We are the only ones reconnecting. Let's launch the task to reconnect
                    tokio::spawn(async move {
                        // Loop to connect and authenticate
                        let connection = loop {
                            // Sleep so we don't overload the server
                            sleep(Duration::from_secs(2)).await;

                            // Create a connection
                            match inner.connect().await {
                                Ok(connection) => break connection,
                                Err(err) => {
                                    error!("failed connection: {err}");
                                }
                            }
                        };

                        // Update the connection and drop the guard
                        *connection_guard = OnceCell::from(connection);
                    });
                }

                // We are trying to reconnect. Return an error.
                return Err(Error::Connection("reconnection in progress".to_string()));
            }
        }
    }};
}

impl<C: ConnectionDef> Retry<C> {
    /// Creates a new `Retry` connection from a `Config`
    /// Attempts to make an initial connection.
    /// This allows us to create elastic clients that always try to maintain a connection.
    ///
    /// # Errors
    /// - If we are unable to either parse or bind an endpoint to the local endpoint.
    /// - If we are unable to make the initial connection
    pub fn from_config(config: Config<C>) -> Self {
        // Extrapolate values from the underlying client configuration
        let Config {
            endpoint,
            use_local_authority,
            keypair,
            subscribed_topics,
        } = config;

        // Wrap subscribed topics so we can use it now and later
        let subscribed_topics = RwLock::new(HashSet::from_iter(subscribed_topics));

        // Return the slightly transformed connection.
        Self {
            inner: Arc::from(Inner {
                endpoint,
                use_local_authority,
                // TODO: parameterize batch params
                connection: Arc::default(),
                keypair,
                subscribed_topics,
            }),
        }
    }

    /// Returns only when the connection is fully initialized
    pub async fn ensure_initialized(&self) {
        // In a loop, attempt to initialize the connection (if not yet)
        while let Err(err) = self
            .inner
            .connection
            .read()
            .await
            .get_or_try_init(|| self.inner.connect())
            .await
        {
            error!("failed to initialize connection: {err}");

            // Wait a bit so we don't overload the server
            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Sends a message to the underlying connection. Reconnection is handled under
    /// the hood. Messages will fail if the connection is currently closed or reconnecting.
    ///
    /// # Errors
    /// If the message sending fails. For example:
    /// - If we are reconnecting
    /// - If we are disconnected
    pub async fn send_message(&self, message: Message) -> Result<()> {
        // Check if we're (probably) reconnecting or not
        if let Ok(connection_guard) = self.inner.connection.try_read() {
            // We're not reconnecting, try to send the message
            // Initialize the connection if it does not yet exist
            let out = connection_guard
                .get_or_try_init(|| self.inner.connect())
                .await?
                .send_message(message)
                .await;
            drop(connection_guard);

            try_with_reconnect!(self, out)
        } else {
            // We are reconnecting, return an error
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
        // Wait for a reconnection before trying to receive
        let connection_guard = self.inner.connection.read().await;

        // Initialize the connection if it does not yet exist
        let out = connection_guard
            .get_or_try_init(|| self.inner.connect())
            .await?
            .recv_message()
            .await;
        drop(connection_guard);

        // If we failed to receive a message, kick off reconnection logic
        try_with_reconnect!(self, out)
    }
}
