//! This file contains the implementation of the `Broker`, which routes messages
//! for the Push CDN.

// TODO: massive cleanup on this file

mod map;
mod state;

use std::{collections::HashSet, marker::PhantomData, sync::Arc, time::Duration};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use slotmap::Key;
// TODO: figure out if we should use Tokio's here
use proto::{
    authenticate_with_broker, bail,
    connection::{
        auth::broker::BrokerAuth,
        batch::{BatchedSender, Position},
        protocols::{Listener, Protocol, Receiver},
    },
    crypto::{KeyPair, Serializable},
    error::{Error, Result},
    message::Message,
    parse_socket_address,
    redis::{self, BrokerIdentifier},
    verify_broker,
};
use slotmap::DefaultKey;
use state::ConnectionLookup;
use tokio::{select, spawn, sync::RwLock, time::sleep};
use tracing::{error, info, warn};

/// The broker's configuration. We need this when we create a new one.
/// TODO: clean up these generics. could be a generic type that implements both
pub struct Config<BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>>
{
    /// The user (public) advertise address: what the marshals send to users upon authentication.
    /// Users connect to us with this address.
    pub user_advertise_address: String,
    /// The uaser (public) bind address: the public-facing address we bind to.
    pub user_bind_address: String,

    /// The broker (private) advertise address: what other brokers use to connect to us.
    pub broker_advertise_address: String,
    /// The broker (private) bind address: the private-facing address we bind to.
    pub broker_bind_address: String,

    /// The redis endpoint. We use this to maintain consistency between brokers and marshals.
    pub redis_endpoint: String,

    pub keypair: KeyPair<BrokerSignatureScheme>,

    /// An optional TLS cert path
    pub maybe_tls_cert_path: Option<String>,
    /// An optional TLS key path
    pub maybe_tls_key_path: Option<String>,
}

/// The broker `Inner` that we use to share common data between broker tasks.
struct Inner<
    // TODO: clean these up with some sort of generic trick or something
    BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    BrokerProtocolType: Protocol,
    UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserProtocolType: Protocol,
> where
    UserSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::SigningKey: Serializable,
{
    /// A broker identifier that we can use to establish uniqueness among brokers.
    identifier: BrokerIdentifier,

    /// The (clonable) `Redis` client that we will use to maintain consistency between brokers and marshals
    redis_client: redis::Client,

    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    keypair: KeyPair<BrokerSignatureScheme>,

    connected_broker_identities: RwLock<HashSet<BrokerIdentifier>>,

    /// A map of interests to their possible broker connections. We use this to facilitate
    /// where messages go. They need to be separate because of possibly different protocol
    /// types.
    broker_connection_lookup: RwLock<ConnectionLookup<BrokerProtocolType>>,

    /// A map of interests to their possible user connections. We use this to facilitate
    /// where messages go. They need to be separate because of possibly different protocol
    /// types.
    user_connection_lookup: RwLock<ConnectionLookup<UserProtocolType>>,

    // connected_keys: LoggedSet<UserSignatureScheme::VerificationKey>,
    /// The `PhantomData` that we need to be generic over protocol types.
    pd: PhantomData<(UserProtocolType, BrokerProtocolType, UserSignatureScheme)>,
}

macro_rules! send_or_remove_many {
    ($connections: expr, $lookup:expr, $message: expr, $position: expr) => {
        for connection in $connections {
            if connection
                .1
                .queue_message($message.clone(), $position)
                .is_err()
            {
                get_lock!($lookup, write).remove_connection(connection.0);
            };
        }
    };
}

macro_rules! send_direct {
    ($lookup: expr, $key: expr, $message: expr) => {{
        let connections = $lookup.read().await.get_connections_by_key(&$key).clone();
        send_or_remove_many!(connections, $lookup, $message, Position::Back);
    }};
}

macro_rules! send_broadcast {
    ($lookup:expr, $topics: expr, $message: expr) => {{
        let connections = $lookup
            .read()
            .await
            .get_connections_by_topic($topics.clone())
            .clone();
        send_or_remove_many!(connections, $lookup, $message, Position::Back);
    }};
}

macro_rules! get_lock {
    ($lock :expr, $type: expr) => {
        paste::item! {
            $lock.$type().await
        }
    };
}

macro_rules! new_serialized_message {
    ($type: ident, $data: expr) => {
        Arc::<Vec<u8>>::from(bail!(
            Message::$type($data).serialize(),
            Connection,
            "broker disconnected"
        ))
    };
}

/// The main `Broker` struct. We instantiate this when we want to run a broker.
pub struct Broker<
    BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    BrokerProtocolType: Protocol,
    UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserProtocolType: Protocol,
> where
    UserSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::SigningKey: Serializable,
{
    /// The broker's `Inner`. We clone this and pass it around when needed.
    inner: Arc<
        Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
    >,

    /// The public (user -> broker) listener
    user_listener: UserProtocolType::Listener,

    /// The private (broker <-> broker) listener
    broker_listener: BrokerProtocolType::Listener,
}

impl<
        BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        BrokerProtocolType: Protocol,
        UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        UserProtocolType: Protocol,
    > Broker<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>
where
    UserSignatureScheme::Signature: Serializable,
    UserSignatureScheme::VerificationKey: Serializable,
    UserSignatureScheme::SigningKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::SigningKey: Serializable,
{
    /// Create a new `Broker` from a `Config`
    ///
    /// # Errors
    /// - If we fail to create the `Redis` client
    /// - If we fail to bind to our public endpoint
    /// - If we fail to bind to our private endpoint
    pub async fn new(config: Config<BrokerSignatureScheme>) -> Result<Self> {
        // Extrapolate values from the underlying broker configuration
        let Config {
            user_advertise_address,
            user_bind_address,

            broker_advertise_address,
            broker_bind_address,

            keypair,

            redis_endpoint,
            maybe_tls_cert_path,
            maybe_tls_key_path,
        } = config;

        // Create a unique broker identifier
        let identifier = BrokerIdentifier {
            user_advertise_address,
            broker_advertise_address,
        };

        // Create the `Redis` client we will use to maintain consistency
        let redis_client = bail!(
            redis::Client::new(redis_endpoint, Some(identifier.clone()),).await,
            Parse,
            "failed to create Redis client"
        );

        // Create the user (public) listener
        let user_bind_address = parse_socket_address!(user_bind_address);
        let user_listener = bail!(
            UserProtocolType::bind(
                user_bind_address,
                maybe_tls_cert_path.clone(),
                maybe_tls_key_path.clone(),
            )
            .await,
            Connection,
            format!(
                "failed to bind to private (broker) bind address {}",
                broker_bind_address
            )
        );

        // Create the broker (private) listener
        let broker_bind_address = parse_socket_address!(broker_bind_address);
        let broker_listener = bail!(
            BrokerProtocolType::bind(broker_bind_address, maybe_tls_cert_path, maybe_tls_key_path,)
                .await,
            Connection,
            format!(
                "failed to bind to public (user) bind address {}",
                user_bind_address
            )
        );

        // Create and return `Self` as wrapping an `Inner` (with things that we need to share)
        Ok(Self {
            inner: Arc::from(Inner {
                redis_client,
                identifier,
                keypair,
                connected_broker_identities: RwLock::default(),
                broker_connection_lookup: RwLock::default(),
                user_connection_lookup: RwLock::default(),
                pd: PhantomData,
            }),
            user_listener,
            broker_listener,
        })
    }

    /// This function is the callback for handling a broker (private) connection.
    async fn handle_broker_connection(
        inner: Arc<
            Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
        >,
        mut connection: (BrokerProtocolType::Sender, BrokerProtocolType::Receiver),
        is_outbound: bool,
    ) {
        // Depending on which way the direction came in, we will want to authenticate with a different
        // flow.
        let broker_address = if is_outbound {
            // If we reached out to the other broker first, authenticate first.
            let broker_address = authenticate_with_broker!(connection, inner);
            verify_broker!(connection, inner);
            broker_address
        } else {
            // If the other broker reached out to us first, authenticate second.
            verify_broker!(connection, inner);
            authenticate_with_broker!(connection, inner)
        };

        // Create new batch sender
        let (sender, receiver) = connection;
        // TODO: parameterize max interval and max size
        let sender = Arc::from(BatchedSender::<BrokerProtocolType>::from(
            sender,
            Duration::from_millis(50),
            1500,
        ));

        // Add to our connected broker identities so we don't try to reconnect
        get_lock!(inner.connected_broker_identities, write).insert(broker_address.clone());

        // Freeze the sender before adding it to our connections so we don't receive messages out of order.
        // This is to enforce message ordering
        let _ = sender.freeze();

        // Add our connection to the list of connections
        let connection_id = inner
            .broker_connection_lookup
            .write()
            .await
            .add_connection(sender.clone());

        // Get all brokers (excluding ourselves)
        let all_brokers = get_lock!(inner.broker_connection_lookup, read).get_all_connections();

        // Send all relevant updates to brokers, flushing our updates. Send the partial updates
        // to everyone, and the full to the new broker.
        let _ = inner
            .send_updates_to_brokers(all_brokers, vec![(connection_id, sender.clone())])
            .await;

        // Unfreeze the sender, flushing the updates
        let _ = sender.unfreeze();

        info!("connected to broker {}", broker_address);

        // If we error, come back to the callback so we can remove the connection from the list.
        if let Err(err) = inner.broker_recv_loop(connection_id, receiver).await {
            error!("broker disconnected with error: {err}");
        };

        info!("disconnected from broker {}", broker_address);

        // Remove from the connected broker identities so that we may
        // try to reconnect inthe future.
        get_lock!(inner.connected_broker_identities, write).remove(&broker_address);

        // Remove from our connections so that we don't send any more data
        // their way.
        get_lock!(inner.broker_connection_lookup, write).remove_connection(connection_id);
    }

    /// This function handles a user (public) connection.
    async fn handle_user_connection(
        inner: Arc<
            Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
        >,
        mut connection: (UserProtocolType::Sender, UserProtocolType::Receiver),
    ) {
        // Verify (authenticate) the connection
        let Ok((verification_key, topics)) =
            BrokerAuth::<UserSignatureScheme, UserProtocolType>::verify_user(
                &mut connection,
                &inner.identifier,
                &mut inner.redis_client.clone(),
            )
            .await
        else {
            return;
        };

        // Create new batch sender
        let (sender, receiver) = connection;
        let sender = Arc::new(BatchedSender::<UserProtocolType>::from(
            sender,
            Duration::from_millis(50),
            1500,
        ));

        // Add the connection to the list of connections
        let connection_id = get_lock!(inner.user_connection_lookup, write).add_connection(sender);

        // Add the user for their topics
        get_lock!(inner.user_connection_lookup, write)
            .subscribe_connection_id_to_topics(connection_id, topics);

        // Add the user for their key
        get_lock!(inner.user_connection_lookup, write)
            .subscribe_connection_id_to_keys(connection_id, vec![verification_key]);

        info!("received connection from user {:?}", connection_id.data());

        // This runs the main loop for receiving information from the user
        let () = inner.user_recv_loop(connection_id, receiver).await;

        info!("user {:?} disconnected", connection_id.data());
        // Once the main loop ends, we remove the connection
        inner
            .user_connection_lookup
            .write()
            .await
            .remove_connection(connection_id);
    }

    /// The main loop for a broker.
    /// Consumes self.
    ///
    /// # Errors
    /// If any of the following tasks exit:
    /// - The heartbeat (Redis) task
    /// - The user connection handler
    /// - The broker connection handler
    pub async fn start(self) -> Result<()> {
        // Clone `inner` so we can use shared data
        let inner = self.inner.clone();

        // Spawn the heartbeat task, which we use to register with `Redis` every so often.
        // We also use it to check for new brokers who may have joined.
        let heartbeat_task = spawn(Self::heartbeat_task(inner.clone()));

        // Spawn the updates task, which updates other brokers with our topics and keys periodically.
        let send_updates_task = spawn(Self::send_updates_task(inner));

        // Clone `inner` so we can use shared data
        let inner = self.inner.clone();

        // Spawn the public (user) listener task
        // TODO: maybe macro this, since it's repeat code with the private listener task
        let user_listener_task = spawn(async move {
            loop {
                // Accept a connection. If we fail, print the error and keep going.
                //
                // TODO: figure out when an endpoint closes, should I be looping on it? What are the criteria
                // for closing? It would error but what does that actually _mean_? Is it recoverable?
                let connection = match self.user_listener.accept().await {
                    Ok(connection) => connection,
                    Err(err) => {
                        warn!("failed to accept connection: {}", err);
                        continue;
                    }
                };

                // Spawn a task to handle the [user/public] connection
                let inner = inner.clone();
                spawn(Self::handle_user_connection(inner, connection));
            }
        });

        // Clone `inner` so we can use shared data
        let inner = self.inner.clone();

        // Spawn the private (broker) listener task
        let broker_listener_task = spawn(async move {
            loop {
                // Accept a connection. If we fail, print the error and keep going.
                //
                // TODO: figure out when an endpoint closes, should I be looping on it? What are the criteria
                // for closing? It would error but what does that actually _mean_? Is it recoverable?
                let connection = match self.broker_listener.accept().await {
                    Ok(connection) => connection,
                    Err(err) => {
                        warn!("failed to accept connection: {}", err);
                        continue;
                    }
                };

                // Spawn a task to handle the [broker/private] connection
                let inner = inner.clone();
                spawn(Self::handle_broker_connection(inner, connection, false));
            }
        });

        // If one of the tasks exists, we want to return (stopping the program)
        select! {
            _ = send_updates_task => {
                Err(Error::Exited("send updates task exited!".to_string()))
            }
            _ = heartbeat_task => {
                Err(Error::Exited("heartbeat task exited!".to_string()))
            }
            _ = user_listener_task => {
                Err(Error::Exited("user listener task exited!".to_string()))
            }
            _ = broker_listener_task => {
                Err(Error::Exited("broker listener task exited!".to_string()))
            }
        }
    }

    async fn send_updates_task(
        inner: Arc<
            Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
        >,
    ) {
        loop {
            // Send other brokers our subscription and topic updates. None of them get full updates.
            if let Err(err) = inner
                .send_updates_to_brokers(
                    vec![],
                    get_lock!(inner.broker_connection_lookup, read)
                        .get_all_connections()
                        .clone(),
                )
                .await
            {
                error!("failed to send updates to other brokers: {err}")
            };

            sleep(Duration::from_secs(5)).await;
        }
    }

    async fn heartbeat_task(
        inner: Arc<
            Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
        >,
    ) {
        // Clone the `Redis` client, which needs to be mutable
        let mut redis_client = inner.redis_client.clone();

        // Run this forever, unless we run into a panic (e.g. the "as" conversion.)
        loop {
            // Register with `Redis` every n seconds, updating our number of connected users
            if let Err(err) = redis_client
                .perform_heartbeat(
                    get_lock!(inner.user_connection_lookup, read).get_connection_count() as u64,
                    Duration::from_secs(60),
                )
                .await
            {
                // If we fail, we want to see this
                error!("failed to perform heartbeat: {}", err);
            }

            // Check for new brokers, spawning tasks to connect to them if necessary
            match redis_client.get_other_brokers().await {
                Ok(brokers) => {
                    // Calculate the difference, spawn tasks to connect to them
                    for broker in brokers
                        .difference(&get_lock!(inner.connected_broker_identities, read).clone())
                    {
                        // TODO: make this into a separate function
                        // Extrapolate the address to connect to
                        let to_connect_address = broker.broker_advertise_address.clone();

                        // Clone the inner because we need it for the possible new broker task
                        let inner = inner.clone();

                        // Spawn task to connect to a broker we haven't seen
                        spawn(async move {
                            // Connect to the broker
                            let connection =
                                match BrokerProtocolType::connect(to_connect_address).await {
                                    Ok(connection) => connection,
                                    Err(err) => {
                                        error!("failed to connect to broker: {err}");
                                        return;
                                    }
                                };

                            // Handle the broker connection
                            Self::handle_broker_connection(inner, connection, true).await;
                        });
                    }
                }

                Err(err) => {
                    // This is an important error as well
                    error!("failed to get other brokers: {}", err);
                }
            }

            // Sleep for 20 seconds
            sleep(Duration::from_secs(20)).await;
        }
    }
}

macro_rules! send_update_to_brokers {
    ($lookup:expr, $message_type: ident, $data:expr, $recipients: expr, $position: ident) => {{
        // If the data is not empty, make a message of the specified type
        if !$data.is_empty() {
            // Create a `Subscribe` message, which contains the full list of topics we're subscribed to
            let message = new_serialized_message!($message_type, $data);

            // For each recipient, send to the destined position in the queue
            send_or_remove_many!(
                $recipients,
                $lookup,
                message,
                Position::$position
            );
        }
    }};
}

impl<
        BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        BrokerProtocolType: Protocol,
        UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        UserProtocolType: Protocol,
    > Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>
where
    UserSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::SigningKey: Serializable,
{
    pub async fn broker_recv_loop(
        self: &Arc<Self>,
        connection_id: DefaultKey,
        mut receiver: BrokerProtocolType::Receiver,
    ) -> Result<()> {
        while let Ok(message) = receiver.recv_message().await {
            match message {
                // If we receive a direct message from a broker, we want to send it to all users with that key
                Message::Direct(ref direct) => {
                    let message: Arc<Vec<u8>> =
                        Arc::from(message.serialize().expect("serialization failed"));

                    send_direct!(self.user_connection_lookup, direct.recipient, message);
                }

                // If we receive a broadcast message from a broker, we want to send it to all interested users
                Message::Broadcast(ref broadcast) => {
                    let message: Arc<Vec<u8>> =
                        Arc::from(message.serialize().expect("serialization failed"));

                    send_broadcast!(self.user_connection_lookup, broadcast.topics, message);
                }

                // If we receive a subscribe message from a broker, we add them as "interested" locally.
                Message::Subscribe(subscribe) => get_lock!(self.broker_connection_lookup, write)
                    .subscribe_connection_id_to_topics(connection_id, subscribe),

                // If we receive a subscribe message from a broker, we remove them as "interested" locally.
                Message::Unsubscribe(unsubscribe) => {
                    get_lock!(self.broker_connection_lookup, write)
                        .unsubscribe_connection_id_from_topics(connection_id, unsubscribe);
                }

                // If a broker has told us they have some users connected, we update our map as such
                Message::UsersConnected(users) => get_lock!(self.broker_connection_lookup, write)
                    .subscribe_connection_id_to_keys(connection_id, users),

                // If a broker has told us they have some users disconnected, we update our map as such
                Message::UsersDisconnected(users) => {
                    get_lock!(self.broker_connection_lookup, write)
                        .unsubscribe_connection_id_from_keys(connection_id, users);
                }

                // Do nothing if we receive an unexpected message
                _ => {}
            }
        }

        Err(Error::Connection("connection closed".to_string()))
    }

    pub async fn user_recv_loop(
        self: &Arc<Self>,
        connection_id: DefaultKey,
        mut receiver: UserProtocolType::Receiver,
    ) {
        while let Ok(message) = receiver.recv_message().await {
            match message {
                // If we get a direct message from a user, send it to both users and brokers.
                Message::Direct(ref direct) => {
                    let message: Arc<Vec<u8>> =
                        Arc::from(message.serialize().expect("serialization failed"));

                    send_direct!(self.broker_connection_lookup, direct.recipient, message);
                    send_direct!(self.user_connection_lookup, direct.recipient, message);
                }

                // If we get a broadcast message from a user, send it to both brokers and users.
                Message::Broadcast(ref broadcast) => {
                    let message: Arc<Vec<u8>> =
                        Arc::from(message.serialize().expect("serialization failed"));

                    send_broadcast!(self.broker_connection_lookup, broadcast.topics, message);
                    send_broadcast!(self.user_connection_lookup, broadcast.topics, message);
                }

                // Subscribe messages from users will just update the state locally
                Message::Subscribe(mut subscribe) => {
                    subscribe.dedup();

                    get_lock!(self.user_connection_lookup, write)
                        .subscribe_connection_id_to_topics(connection_id, subscribe);
                }

                // Unsubscribe messages from users will just update the state locally
                Message::Unsubscribe(mut unsubscribe) => {
                    unsubscribe.dedup();

                    get_lock!(self.user_connection_lookup, write)
                        .unsubscribe_connection_id_from_topics(connection_id, unsubscribe);
                }

                _ => return,
            }
        }
    }

    pub async fn send_updates_to_brokers(
        self: &Arc<Self>,
        full: Vec<(DefaultKey, Arc<BatchedSender<BrokerProtocolType>>)>,
        partial: Vec<(DefaultKey, Arc<BatchedSender<BrokerProtocolType>>)>,
    ) -> Result<()> {
        // When a broker connects, we have to send:
        // 1. Our snapshot to the new broker (of what topics/users we're subscribed for)
        // 2. A list of updates since that snapshot to all brokers.
        // This is so we're all on the same page.
        let topic_snapshot =
            get_lock!(self.user_connection_lookup, write).get_topic_updates_since();

        // Get the snapshot for which user keys we're responsible for
        let key_snapshot = get_lock!(self.user_connection_lookup, write).get_key_updates_since();

        // Send the full connected users to interested brokers first in the queue (so that it is the correct order)
        // TODO: clean up this function
        send_update_to_brokers!(
            self.broker_connection_lookup,
            UsersConnected,
            key_snapshot.snapshot,
            &full,
            Front
        );

        // Send the full topics list to interested brokers first in the queue (so that it is the correct order)
        send_update_to_brokers!(
            self.broker_connection_lookup,
            Subscribe,
            topic_snapshot.snapshot,
            &full,
            Front
        );

        // Send the insertion updates for keys, if any
        send_update_to_brokers!(
            self.broker_connection_lookup,
            UsersConnected,
            key_snapshot.insertions,
            &partial,
            Back
        );

        // Send the removal updates for keys, if any
        send_update_to_brokers!(
            self.broker_connection_lookup,
            UsersDisconnected,
            key_snapshot.removals,
            &partial,
            Back
        );

        // Send the insertion updates for topics, if any
        send_update_to_brokers!(
            self.broker_connection_lookup,
            Subscribe,
            topic_snapshot.insertions,
            &partial,
            Back
        );

        // Send the removal updates for topics, if any
        send_update_to_brokers!(
            self.broker_connection_lookup,
            Unsubscribe,
            topic_snapshot.removals,
            &partial,
            Back
        );

        Ok(())
    }
}
