//! This file contains the implementation of the `Broker`, which routes messages
//! for the Push CDN.

// TODO: massive cleanup on this file

mod state;

use std::{collections::HashSet, marker::PhantomData, sync::Arc, time::Duration};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
// TODO: figure out if we should use Tokio's here
use proto::{
    authenticate_with_broker, bail,
    connection::{
        auth::broker::BrokerAuth,
        batch::BatchedSender,
        protocols::{Listener, Protocol, Receiver},
    },
    crypto::{KeyPair, Serializable},
    error::{Error, Result},
    message::{Message, Subscribe, UsersConnected, UsersDisconnected},
    parse_socket_address,
    redis::{self, BrokerIdentifier},
    verify_broker,
};
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

    /// A set of all other brokers. We need this to send to all connected brokers.
    other_brokers: RwLock<HashSet<(BrokerIdentifier, Arc<BatchedSender<BrokerProtocolType>>)>>,

    /// A map of interests to their possible broker connections. We use this to facilitate
    /// where messages go. They need to be separate because of possible separate protocol
    /// types.
    broker_connection_lookup: RwLock<ConnectionLookup<BrokerProtocolType>>,

    /// A map of interests to their possible user connections. We use this to facilitate
    /// where messages go. They need to be separate because of possible separate protocol
    /// types.
    user_connection_lookup: RwLock<ConnectionLookup<UserProtocolType>>,

    // connected_keys: LoggedSet<UserSignatureScheme::VerificationKey>,
    /// The `PhantomData` that we need to be generic over protocol types.
    pd: PhantomData<(UserProtocolType, BrokerProtocolType, UserSignatureScheme)>,
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

macro_rules! remove_local_and_exit_on_error {
    ($operation: expr, $inner: expr, $sender: expr, $object: ident) => {
        match $operation {
            Ok(op) => op,
            Err(_) => {
                remove_local!($inner, $sender, $object);
                return;
            }
        }
    };
}

macro_rules! remove_local {
    ($inner: expr, $sender: expr, user) => {
        // Remove all connections associated with the user
        $inner
            .user_connection_lookup
            .write()
            .await
            .unsubscribe_connection(&$sender);
    };

    ($inner: expr, $sender: expr, broker) => {
        // Remove all connections associated with the broker
        $inner
            .broker_connection_lookup
            .write()
            .await
            .unsubscribe_connection(&$sender.clone());

        // Remove from "all brokers"
        $inner.other_brokers.write().await.retain(|(_, broker)| broker != &$sender);
    };
}

macro_rules! remove_remote_and_exit_on_error {
    ($operation: expr, $inner: expr, $key: expr) => {
        match $operation {
            Ok(op) => op,
            Err(_) => {
                remove_remote!($inner, $key);
                return;
            }
        }
    };
}

macro_rules! remove_remote {
    ($inner:expr, $key: expr) => {
        // Tell all other brokers that we're done with the user
        // TODO IMP: IF REMOVE TOPIC, SEND THAT TOPIC IS UNSUBSCRIBE
        let brokers:Vec<(BrokerIdentifier, Arc<BatchedSender<BrokerProtocolType>>)> =
            $inner.other_brokers.read().await.iter().cloned().collect();

        // For all brokers, send the disconect message
        if !brokers.is_empty() {
            let disconnected_message =
            // TODO: see if we need clone here
                Message::UsersDisconnected(UsersDisconnected { users: vec![$key.clone()] });

            // TODO: DOCUMENT THIS EXPECT
            // Serialize the message
            let disconnected_message:Arc<Vec<u8>> = Arc::from(
                disconnected_message
                    .serialize()
                    .expect("serialization to succeed"),
            );

            // Send the message
            for broker in brokers {
                // If we fail to send it, remove the broker
                // TODO: remove brokers here on error
                let _ = broker.1.queue_message_back(disconnected_message.clone());
            }
        }
    };
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
                other_brokers: RwLock::default(),
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
        let (sender, mut receiver) = connection;
        // TODO: parameterize max interval and max size
        let sender = Arc::new(BatchedSender::from(sender, Duration::from_millis(50), 1500));

        // Freeze the sender before adding it so we don't receive messages out of order
        let _ = sender.freeze();

        // Add to "other brokers" so we can start adding relevant messages to the queue
        inner
            .other_brokers
            .write()
            .await
            .insert((broker_address.clone(), sender.clone()));

        // Create and serialize a message with the keys we're connected to
        // TODO: macro for this
        let users = inner.user_connection_lookup.read().await.get_all_keys();
        let message = Message::UsersConnected(UsersConnected { users });

        // If we fail serialization, remove from the "all/other brokers" map.
        let message = Arc::from(remove_local_and_exit_on_error!(
            message.serialize(),
            inner,
            sender,
            broker
        ));

        // Put the message at the front of the queue so that we send messages in order
        let _ = sender.queue_message_front(message);

        // Create and serialize a message with the topics we're interested in
        let topics = inner.user_connection_lookup.read().await.get_all_topics();
        let message = Message::Subscribe(Subscribe { topics });

        // If we fail serialization, remove from the "all/other brokers" map.
        let message = Arc::from(remove_local_and_exit_on_error!(
            message.serialize(),
            inner,
            sender,
            broker
        ));

        // Put the message at the front of the queue so that we send messages in order
        let _ = sender.queue_message_front(message);

        // Unfreeze our queue, which flushes it and lets us finally send (in order) messages.
        let _ = sender.unfreeze();

        info!("received connection from broker {}", broker_address);

        // The message receive loop. On exit, remove the broker's connection everywhere
        while let Ok(message) = receiver.recv_message().await {
            // See what type of message this is
            match message {
                // A direct message. We want this to go to either the associated broker or user.
                Message::Direct(direct) => {
                    // Find out where the message is supposed to go
                    let possible_user = inner
                        .user_connection_lookup
                        .read()
                        .await
                        .get_connection_by_key(&direct.recipient);

                    // If user is connected, queue the message for sending
                    // TODO: max queue size before force quit
                    if let Some(user) = possible_user {
                        // Create a new `Data` and `Arc` it.
                        let message = Arc::new(remove_local_and_exit_on_error!(
                            Message::serialize(&Message::Direct(direct)),
                            inner,
                            sender,
                            broker
                        ));

                        // Send them the message. If we fail, remove them
                        if user.queue_message_back(message).is_err() {
                            remove_local!(inner, user, user);
                        }
                    }
                }

                Message::Broadcast(broadcast) => {
                    // TODO: macro this
                    // Find out where the message is supposed to go
                    let connections = inner
                        .user_connection_lookup
                        .read()
                        .await
                        .get_connections_by_topic(broadcast.topics.clone());

                    // If there are any users, queue the message to send for all of them
                    if !connections.is_empty() {
                        // Create a new `Data` and `Arc` it.
                        let message = Arc::new(remove_local_and_exit_on_error!(
                            Message::serialize(&Message::Broadcast(broadcast)),
                            inner,
                            sender,
                            broker
                        ));

                        // For each user, them the message. If we fail, remove them
                        for user in connections {
                            if user.queue_message_back(message.clone()).is_err() {
                                remove_local!(inner, user, user);
                            }
                        }
                    }
                }

                // If we receive a subscribe message from a broker, subscribe them to those topics
                Message::Subscribe(subscribe) => inner
                    .broker_connection_lookup
                    .write()
                    .await
                    .subscribe_connection_to_topics(sender.clone(), subscribe.topics),

                // If we receive an unsubscribe message from a broker, unsubscribe them from those topics
                Message::Unsubscribe(unsubscribe) => inner
                    .broker_connection_lookup
                    .write()
                    .await
                    .unsubscribe_connection_from_topics(&sender, unsubscribe.topics),

                // If we receive a `UsersConnected` message, subscribe that connection to the keys it presented
                Message::UsersConnected(users_connected) => inner
                    .broker_connection_lookup
                    .write()
                    .await
                    .subscribe_connection_to_keys(&sender, users_connected.users),

                // If we receive a `UsersConnected` message, unsubscribe that connection from the keys it presented
                Message::UsersDisconnected(users_disconnected) => inner
                    .broker_connection_lookup
                    .write()
                    .await
                    .unsubscribe_connection_from_keys(users_disconnected.users),

                // We should not be receiving any of these messages
                Message::AuthenticateResponse(_)
                | Message::AuthenticateWithKey(_)
                | Message::AuthenticateWithPermit(_) => {
                    remove_local!(inner, sender, broker);
                    return;
                }
            }
        }

        remove_local!(inner, sender, broker);
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
        let (sender, mut receiver) = connection;
        let sender = Arc::new(BatchedSender::<UserProtocolType>::from(
            sender,
            Duration::from_millis(50),
            1500,
        ));

        // Send the information to other brokers, if any.
        // Remove them if we failed to send to them,
        // TODO: WAL HERE maybe
        let brokers: Vec<(BrokerIdentifier, Arc<BatchedSender<BrokerProtocolType>>)> =
            inner.other_brokers.read().await.iter().cloned().collect();
        if !brokers.is_empty() {
            let connected_message = Message::UsersConnected(UsersConnected {
                users: vec![verification_key.clone()],
            });
            let subscribed_message = Message::Subscribe(Subscribe {
                topics: topics.clone(),
            });

            // Arc and serialize the messages, prepare for sending
            let connected_message: Arc<Vec<u8>> = Arc::from(remove_remote_and_exit_on_error!(
                connected_message.serialize(),
                inner,
                verification_key
            ));
            let subscribed_message: Arc<Vec<u8>> = Arc::from(remove_remote_and_exit_on_error!(
                subscribed_message.serialize(),
                inner,
                verification_key
            ));

            // Send the messages
            for broker in brokers {
                let _ = broker.1.queue_message_back(connected_message.clone());
                let _ = broker.1.queue_message_back(subscribed_message.clone());
            }
        };

        // Add the user for their topics
        inner
            .user_connection_lookup
            .write()
            .await
            .subscribe_connection_to_topics(sender.clone(), topics);

        // Add the user for their keys
        inner
            .user_connection_lookup
            .write()
            .await
            .subscribe_connection_to_keys(&sender, vec![verification_key.clone()]);

        info!(
            "received connection from user {:?}",
            hex::encode(&verification_key)
        );

        // The message receive loop. On exit, remove the broker's connection everywhere
        while let Ok(message) = receiver.recv_message().await {
            // See what type of message this is
            match message {
                // A direct message. This is supposed to go to the interested broker AND/OR interested user only
                Message::Direct(direct) => {
                    // Find out where the message is supposed to go
                    let broker_connection = inner
                        .broker_connection_lookup
                        .read()
                        .await
                        .get_connection_by_key(&direct.recipient);

                    let user_connection = inner
                        .user_connection_lookup
                        .read()
                        .await
                        .get_connection_by_key(&direct.recipient);

                    if let Some(connection) = user_connection {
                        // `Arc` and serialize it.
                        // TODO IMP DOCUMENT INVARIANT
                        let message = Arc::new(
                            Message::Direct(direct)
                                .serialize()
                                .expect("serialization to succeed"),
                        );

                        // If we fail to send the message, remove the user
                        if connection.queue_message_back(message).is_err() {
                            remove_local!(inner, sender, user);
                            remove_remote!(inner, verification_key);
                        }
                    } else if let Some(connection) = broker_connection {
                        // `Arc` and serialize it.
                        let message = Arc::new(
                            Message::Direct(direct)
                                .serialize()
                                .expect("serialization to succeed"),
                        );

                        // If we fail to send the message, remove the broker
                        if connection.queue_message_back(message).is_err() {
                            remove_local!(inner, connection, broker);
                        };
                    };
                }

                // A broadcast message. This is supposed to go to the interested brokers AND/OR interested users only
                Message::Broadcast(broadcast) => {
                    // Figure out which brokers this message should go to
                    let broker_connections = inner
                        .broker_connection_lookup
                        .read()
                        .await
                        .get_connections_by_topic(broadcast.topics.clone());

                    // Figure out which users the message is supposed to go
                    let user_connections = inner
                        .user_connection_lookup
                        .read()
                        .await
                        .get_connections_by_topic(broadcast.topics.clone());

                    // If there are any users, queue the message to send for all of them
                    if !(broker_connections.is_empty() && user_connections.is_empty()) {
                        // Create a new `Data` and `Arc` it.
                        let message = Arc::new(
                            Message::Broadcast(broadcast)
                                .serialize()
                                .expect("serialization failed"),
                        );

                        // For each broker, send them the message. If we fail, remove them
                        for broker in broker_connections {
                            if broker.queue_message_back(message.clone()).is_err() {
                                remove_local!(inner, broker, broker);
                            }
                        }

                        // For each broker, send them the message. If we fail, remove them
                        for user in user_connections {
                            if user.queue_message_back(message.clone()).is_err() {
                                remove_local!(inner, sender, user);
                                remove_remote!(inner, verification_key);
                            }
                        }
                    }
                }

                // If we receive a subscription from the user, send to other brokers and update locally
                Message::Subscribe(subscribe) => {
                    // Send the information to other brokers, if any.
                    // Remove them if we failed to send to them,
                    // TODO: WAL HERE maybe
                    let brokers: Vec<(BrokerIdentifier, Arc<BatchedSender<BrokerProtocolType>>)> =
                        inner.other_brokers.read().await.iter().cloned().collect();
                    if !brokers.is_empty() {
                        let subscribed_message = Message::Subscribe(subscribe);

                        // Arc and serialize the messages, prepare for sending
                        let subscribed_message: Arc<Vec<u8>> = Arc::from(
                            subscribed_message
                                .serialize()
                                .expect("serialization to succeed"),
                        );

                        // Send the messages
                        for broker in brokers {
                            // TODO: consider failing here
                            let _ = broker.1.queue_message_back(subscribed_message.clone());
                        }
                    };
                }

                // If we receive an unsubscription from the user, send to other brokers and update locally
                // TODO: THIS
                Message::Unsubscribe(_)
                | Message::AuthenticateResponse(_)
                | Message::AuthenticateWithKey(_)
                | Message::AuthenticateWithPermit(_)
                | Message::UsersConnected(_)
                | Message::UsersDisconnected(_) => {}
            }
        }

        // If we fail, remove locally and remote (with other brokers)
        remove_local!(inner, sender, user);
        remove_remote!(inner, verification_key);
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
        let heartbeat_task = spawn(async move {
            // Clone the `Redis` client, which needs to be mutable
            let mut redis_client = inner.redis_client.clone();
            loop {
                // Register with `Redis` every 20 seconds, updating our number of connected users
                if let Err(err) = redis_client
                    .perform_heartbeat(
                        // todo: actually pull in this number
                        inner.user_connection_lookup.read().await.get_key_count() as u64,
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
                        for broker in brokers.difference(
                            &inner
                                .other_brokers
                                .read()
                                .await
                                .iter()
                                .map(|(identifier, _)| identifier.clone())
                                .collect(),
                        ) {
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
        });

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
}
