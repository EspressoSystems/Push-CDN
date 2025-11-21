// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! In here we define an API that is a little more higher-level and ergonomic
//! for end users.

#![forbid(unsafe_code)]
use std::{collections::HashSet, sync::Arc, time::Duration};

use cdn_proto::{
    bail,
    connection::{
        auth::user::UserAuth,
        limiter::Limiter,
        protocols::{Connection, Protocol as _},
    },
    crypto::signature::{KeyPair, Serializable},
    def::{ConnectionDef, Protocol, PublicKey, Scheme},
    error::{Error, Result},
    message::{Broadcast, Direct, Message, Topic},
    util::AbortOnDropHandle,
};
use derive_more::derive::Deref;
use parking_lot::Mutex;
use tokio::{
    spawn,
    sync::{RwLock, Semaphore, TryAcquireError},
    time::{sleep, timeout},
};
use tracing::{error, info, warn};

pub mod reexports;

/// `Client` is a wrapper around a fallible connection.
///
/// It employs synchronization as well as Client logic.
/// Can be cloned to provide a handle to the same underlying elastic connection.
#[derive(Clone, Deref)]
pub struct Client<C: ConnectionDef>(Arc<ClientRef<C>>);

/// `ClientRef` is held exclusively by `Client`, wherein an `Arc` is used
/// to facilitate interior mutability.
pub struct ClientRef<C: ConnectionDef> {
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

impl<C: ConnectionDef> ClientRef<C> {
    /// Attempt a reconnection to the remote marshal endpoint.
    /// Returns the connection verbatim without updating any internal
    /// structs.
    ///
    /// # Errors
    /// - If the connection failed
    /// - If authentication failed
    async fn connect(self: &Arc<Self>) -> Result<Connection> {
        // If the connecting guard is closed, the client has been manually closed
        if self.connecting_guard.is_closed() {
            return Err(Error::Connection(
                "client has been manually closed".to_string(),
            ));
        }

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

/// The configuration needed to construct a `Client` connection.
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
                if $self.connecting_guard.available_permits() > 0 {
                    // If we ran into an error, take the current connection.
                    // This will only start reconnecting if we try to receive or send another message.
                    $self.connection.write().await.take();
                }

                Err(e)
            }
        }
    };
}

impl<C: ConnectionDef> Client<C> {
    /// Creates a new `Client` connection from a `Config`
    /// Attempts to make an initial connection.
    /// This allows us to create elastic clients that always try to maintain a connection.
    ///
    /// # Errors
    /// - If we are unable to either parse or bind an endpoint to the local endpoint.
    /// - If we are unable to make the initial connection
    pub fn new(config: Config<C>) -> Self {
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
        Self(Arc::from(ClientRef {
            endpoint,
            use_local_authority,
            connection: Arc::default(),
            connecting_guard: Arc::from(Semaphore::const_new(1)),
            reconnection_task: Arc::default(),
            keypair,
            subscribed_topics,
        }))
    }

    /// Get the underlying connection if it exists, otherwise try to reconnect.
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    /// - If the connection has been manually closed
    fn reconnect_if_needed(&self, possible_connection: Option<Connection>) -> Result<Connection> {
        let Some(connection) = possible_connection else {
            // If the connection is not initialized for one reason or another, try to reconnect
            // Acquire the semaphore to ensure only one reconnection is happening at a time
            match Arc::clone(&self.connecting_guard).try_acquire_owned() {
                Ok(permit) => {
                    // We were the first to try reconnecting, spawn a reconnection task
                    let self_clone = self.0.clone();
                    let reconnection_task = AbortOnDropHandle(spawn(async move {
                        let mut connection = self_clone.connection.write().await;

                        // Forever,
                        loop {
                            // Try to reconnect
                            match timeout(Duration::from_secs(10), self_clone.connect()).await {
                                Ok(Ok(new_connection)) => {
                                    // We successfully reconnected
                                    *connection = Some(new_connection);
                                    break;
                                }
                                Ok(Err(err)) => {
                                    // We failed to reconnect
                                    // Sleep for 2 seconds and then try again
                                    error!("Failed to connect to the CDN: {err}");
                                    sleep(Duration::from_secs(2)).await;
                                }
                                Err(_) => {
                                    // We timed out trying to reconnect
                                    warn!("Timed out while trying to connect to the CDN. Will retry in 2 seconds.");
                                    sleep(Duration::from_secs(2)).await;
                                }
                            }
                        }
                        drop(permit);
                    }));

                    // Update the reconnection task
                    *self.reconnection_task.lock() = Some(reconnection_task);
                }
                Err(TryAcquireError::Closed) => {
                    // The client has been manually closed
                    return Err(Error::Connection(
                        "client has been manually closed".to_string(),
                    ));
                }
                Err(TryAcquireError::NoPermits) => {}
            }

            // The reconnection task has either been started or there were no permits
            // available, so we're already reconnecting
            return Err(Error::Connection("connection in progress".to_string()));
        };

        Ok(connection)
    }

    /// Get the connection if it exists, wait for a potential reconnection if it does not.
    ///
    /// # Errors
    /// - If somebody else is already reconnecting
    /// - If the client has been manually closed
    async fn get_connection(&self) -> Result<Connection> {
        let possible_connection = self.connection.read().await;

        // TODO: figure out a potential way to remove this clone
        self.reconnect_if_needed(possible_connection.clone())
    }

    /// Try to get the connection if it exists, otherwise try to reconnect. Does not block.
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    /// - If the client has been manually closed
    fn try_get_connection(&self) -> Result<Connection> {
        let Ok(possible_connection) = self.connection.try_read() else {
            // Someone else is already reconnecting
            return Err(Error::Connection(
                "connection in progress or manually closed".to_string(),
            ));
        };

        self.reconnect_if_needed(possible_connection.clone())
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
    /// but Client logic needs to be handled by the caller (e.g. re-receive messages)
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

    /// Returns only when the connection is fully initialized
    ///
    /// # Errors
    /// - If the connection has been closed
    pub async fn ensure_initialized(&self) -> Result<()> {
        // Return early if the connecting guard is closed
        if self.connecting_guard.is_closed() {
            return Err(Error::Connection(
                "client has been manually closed".to_string(),
            ));
        }

        // If we are already connected, return
        if self.try_get_connection().is_ok() {
            return Ok(());
        }

        // Otherwise, wait to acquire the connecting guard
        let _ = self.connecting_guard.acquire().await;

        Ok(())
    }

    /// Sends a pre-serialized message to the server, denoting recipients in the form
    /// of a vector of topics. If it fails, we return an error but try to initiate a new connection
    /// in the background.
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn send_broadcast_message(&self, topics: Vec<Topic>, message: Vec<u8>) -> Result<()> {
        // Form and send the single message
        self.send_message(Message::Broadcast(Broadcast { topics, message }))
            .await
    }

    /// Sends a pre-serialized message to the server, denoting interest in delivery
    /// to a single recipient.
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn send_direct_message(
        &self,
        recipient: &PublicKey<C>,
        message: Vec<u8>,
    ) -> Result<()> {
        // Serialize recipient to a byte array before sending the message
        // TODO: maybe we can cache this.
        let recipient_bytes = bail!(
            recipient.serialize(),
            Serialize,
            "failed to serialize recipient"
        );

        // Form and send the single message
        self.send_message(Message::Direct(Direct {
            recipient: recipient_bytes,
            message,
        }))
        .await
    }

    /// Sends a message to the server that asserts that this client is interested in
    /// a specific topic
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn subscribe(&self, topics: Vec<Topic>) -> Result<()> {
        // Lock subscriptions here so we maintain parity during a reconnection
        let mut subscribed_guard = self.subscribed_topics.write().await;

        // Calculate the real topics to send based on whatever's already in the set
        let topics_to_send: Vec<Topic> = topics
            .into_iter()
            .filter(|topic| !subscribed_guard.contains(topic))
            .collect();

        // Send the topics
        bail!(
            self.send_message(Message::Subscribe(topics_to_send.clone()))
                .await,
            Connection,
            "failed to send subscription message"
        );

        // Add the topics to the list if successful
        for topic in topics_to_send {
            subscribed_guard.insert(topic);
        }

        // Drop the write guard
        drop(subscribed_guard);

        Ok(())
    }

    /// Sends a message to the server that asserts that this client is no longer
    /// interested in a specific topic
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn unsubscribe(&self, topics: Vec<Topic>) -> Result<()> {
        // Lock subscriptions here so we maintain parity during a reconnection
        let mut subscribed_guard = self.subscribed_topics.write().await;

        // Calculate the real topics to send based on whatever's already in the set
        let topics_to_send: Vec<Topic> = topics
            .into_iter()
            .filter(|topic| subscribed_guard.contains(topic))
            .collect();

        // Send the topics
        bail!(
            self.send_message(Message::Unsubscribe(topics_to_send.clone()))
                .await,
            Connection,
            "failed to send unsubscription message"
        );

        // Add the topics to the list if successful
        for topic in topics_to_send {
            subscribed_guard.remove(&topic);
        }

        // Drop the write guard
        drop(subscribed_guard);

        Ok(())
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

    /// Shut down the client, closing the connection and aborting all tasks.
    /// Assures that any future calls will fail and that reconnection does not
    /// take place. Does not make any guarantees about pending messages.
    ///
    /// Will block a maximum of 2 seconds for the connection to close.
    pub async fn close(&self) {
        // First close the connecting guard so no more reconnection tasks can be spawned
        // and the next call to `connect()` will fail
        self.connecting_guard.close();

        // Get the current reconnection task and abort it
        if let Some(reconnection_task) = self.reconnection_task.lock().take() {
            reconnection_task.abort();
        }

        // Take the connection
        self.connection.write().await.take();
    }

    /// Returns whether or not the client has been manually closed
    pub fn is_closed(&self) -> bool {
        self.connecting_guard.is_closed()
    }
}
