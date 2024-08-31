// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

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
        limiter::Limiter,
        protocols::{Connection, Protocol as _},
    },
    crypto::signature::KeyPair,
    def::{ConnectionDef, Protocol, Scheme},
    error::{Error, Result},
    message::{Message, Topic},
    util::AbortOnDropHandle,
};
use parking_lot::Mutex;
use tokio::{
    spawn,
    sync::{RwLock, Semaphore},
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
    connection: Arc<RwLock<Option<Connection>>>,

    /// The semaphore to ensure only one reconnection is happening at a time
    connecting_guard: Arc<Semaphore>,

    /// The (optional) task that is responsible for reconnecting
    reconnection_task: Arc<Mutex<Option<AbortOnDropHandle<()>>>>,

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
    async fn connect(self: &Arc<Self>) -> Result<Connection> {
        // Create the limiter we will use for all connections
        let limiter = Limiter::new(None, Some(1));

        // Make the connection to the marshal
        let connection = bail!(
            Protocol::<C>::connect(&self.endpoint, self.use_local_authority, limiter.clone()).await,
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
            Protocol::<C>::connect(&broker_endpoint, self.use_local_authority, limiter).await,
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

// Disconnects the current connection if an error was passed in and we're
// not already reconnecting.
macro_rules! disconnect_on_error {
    ($self:expr, $res: expr) => {
        match $res {
            Ok(t) => Ok(t),
            Err(e) => {
                // If we are not currently reconnecting, take the current connection
                if $self.inner.connecting_guard.available_permits() > 0 {
                    // If we ran into an error, take the current connection.
                    // This will only start reconnecting if we try to receive or send another message.
                    $self.inner.connection.write().await.take();
                }

                Err(e)
            }
        }
    };
}

impl<C: ConnectionDef> Retry<C> {
    /// Get the underlying connection if it exists, otherwise try to reconnect.
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    fn reconnect_if_needed(&self, possible_connection: Option<Connection>) -> Result<Connection> {
        let Some(connection) = possible_connection else {
            // If the connection is not initialized for one reason or another, try to reconnect
            // Acquire the semaphore to ensure only one reconnection is happening at a time
            if let Ok(permit) = Arc::clone(&self.inner.connecting_guard).try_acquire_owned() {
                // We were the first to try reconnecting, spawn a reconnection task
                let inner = self.inner.clone();
                let reconnection_task = AbortOnDropHandle(spawn(async move {
                    let mut connection = inner.connection.write().await;

                    // Forever,
                    loop {
                        // Try to reconnect
                        match inner.connect().await {
                            Ok(new_connection) => {
                                // We successfully reconnected
                                *connection = Some(new_connection);
                                break;
                            }
                            Err(err) => {
                                // We failed to reconnect
                                // Sleep for 2 seconds and then try again
                                error!("failed to connect: {err}");
                                sleep(Duration::from_secs(2)).await;
                            }
                        }
                    }
                    drop(permit);
                }));

                // Update the reconnection task
                *self.inner.reconnection_task.lock() = Some(reconnection_task);
            }

            // If we are in the middle of reconnecting, return an error
            return Err(Error::Connection("connection in progress".to_string()));
        };

        Ok(connection)
    }

    /// Get the connection if it exists, wait for a potential reconnection if it does not.
    ///
    /// # Errors
    /// - If somebody else is already reconnecting
    async fn get_connection(&self) -> Result<Connection> {
        let possible_connection = self.inner.connection.read().await;

        // TODO: figure out a potential way to remove this clone
        self.reconnect_if_needed(possible_connection.clone())
    }

    /// Try to get the connection if it exists, otherwise try to reconnect. Does not block.
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    fn try_get_connection(&self) -> Result<Connection> {
        let Ok(possible_connection) = self.inner.connection.try_read() else {
            // Someone else is already reconnecting
            return Err(Error::Connection("connection in progress".to_string()));
        };

        self.reconnect_if_needed(possible_connection.clone())
    }

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
                connection: Arc::default(),
                connecting_guard: Arc::from(Semaphore::const_new(1)),
                reconnection_task: Arc::default(),
                keypair,
                subscribed_topics,
            }),
        }
    }

    /// Returns only when the connection is fully initialized
    pub async fn ensure_initialized(&self) {
        // If we are already connected, return
        if self.try_get_connection().is_ok() {
            return;
        }

        // Otherwise, wait to acquire the connecting guard
        let _ = self.inner.connecting_guard.acquire().await;
    }

    /// Sends a message to the underlying connection. Reconnection is handled under
    /// the hood. Messages will fail if the connection is currently closed or reconnecting.
    ///
    /// # Errors
    /// If the message sending fails. For example:
    /// - If we are reconnecting
    /// - If we are disconnected
    pub async fn send_message(&self, message: Message) -> Result<()> {
        // Try to get the underlying connection
        let connection = self.try_get_connection()?;

        // Soft close the connection
        disconnect_on_error!(self, connection.send_message(message).await)
    }

    /// Receives a message from the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-receive messages)
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    /// - If the message receiving failed
    pub async fn receive_message(&self) -> Result<Message> {
        // Try to synchronously get the underlying connection
        let connection = self.get_connection().await?;

        // Receive a message
        disconnect_on_error!(self, connection.recv_message().await)
    }

    /// Soft close the connection, ensuring that all messages are sent.
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    /// - If the connection is closed
    pub async fn soft_close(&self) -> Result<()> {
        // Try to get the underlying connection
        let connection = self.try_get_connection()?;

        // Soft close the connection
        disconnect_on_error!(self, connection.soft_close().await)
    }
}
