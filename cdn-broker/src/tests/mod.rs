// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! Commonalities for deterministic (non-networked) testing of our broker.
//! This is not guarded by `![cfg(test)]` because we use the same functions
//! when running benchmarks.

use std::sync::Arc;

use cdn_proto::{
    connection::{
        limiter::Limiter,
        protocols::{Connection, Listener, Protocol, UnfinalizedConnection},
        UserPublicKey,
    },
    crypto::{
        rng::DeterministicRng,
        signature::KeyPair,
        tls::{generate_cert_from_ca, LOCAL_CA_CERT, LOCAL_CA_KEY},
    },
    database::BrokerIdentifier,
    def::TestingRunDef,
    message::{Message, Topic},
};
use jf_signature::{bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tokio::spawn;

use crate::{
    connections::{DirectMap, SubscriptionStatus, TopicSyncMap},
    Broker, Config,
};

#[cfg(test)]
mod broadcast;

#[cfg(test)]
mod direct;

/// This lets us send a message as a particular network actor. It just helps
/// readability.
#[macro_export]
macro_rules! send_message_as {
    ($obj:expr, $message: expr) => {
        $obj.send_message($message.clone())
            .await
            .expect("failed to send message");
    };

    // Send a message to all actors in a vector
    (all, $all: expr, $message: expr) => {
        for actor in &$all {
            send_message_as!(actor, $message);
        }
    };
}

#[macro_export]
/// This is a macro to help us assert that a particular message was or wasn't received.
macro_rules! assert_received {
    // Make sure nobody in the vector has received this message
    (no, all, $all: expr) => {
        for actor in &$all {
            assert_received!(no, actor);
        }
    };

    // Make sure everyone in the vector has received this message
    (yes, all, $all: expr, $message:expr) => {
        for actor in &$all {
            assert_received!(yes, actor, $message);
        }
    };

    // Make sure we haven't received this message
    (no, $actor: expr) => {
        assert!(
            timeout(Duration::from_millis(100), $actor.recv_message())
                .await
                .is_err(),
            "wasn't supposed to receive a message but did"
        )
    };

    // Make sure we have received the message in a timeframe of 50ms
    (yes, $actor: expr, $message:expr) => {
        // Receive the message with a timeout
        let Ok(message) = timeout(Duration::from_millis(50), $actor.recv_message_raw()).await
        else {
            panic!("timed out trying to receive message");
        };

        // Assert the message is the correct one
        assert!(
            message.unwrap()
                == Bytes::from_unchecked(
                    $message
                        .serialize()
                        .expect("failed to re-serialize message")
                ),
            "was supposed to receive a message but did not"
        )
    };
}

/// Get the public key of a user at a particular index
#[macro_export]
macro_rules! at_index {
    ($index: expr) => {
        ($index as usize).to_le_bytes().to_vec()
    };
}

/// A test user is a user that will be connected to the broker under test.
pub struct TestUser {
    /// The public key of the user
    pub public_key: UserPublicKey,

    /// The topics the user is subscribed to
    pub subscribed_topics: Vec<Topic>,
}

impl TestUser {
    /// Create a new test user with a particular index and subscribed topics
    pub fn with_index(index: usize, subscribed_topics: Vec<Topic>) -> Self {
        let public_key = Arc::new(at_index!(index));
        Self {
            public_key,
            subscribed_topics,
        }
    }
}

/// A test broker is a broker that will be connected to the broker under test.
pub struct TestBroker {
    /// The users connected to this broker
    pub connected_users: Vec<TestUser>,
}

impl TestBroker {
    /// Create a new test broker with a set of connected users
    pub fn new(connected_users: Vec<TestUser>) -> Self {
        Self { connected_users }
    }
}

/// This is what we use to describe tests. These are the [brokers/users] connected
/// _DIRECTLY_ to the broker under test, along with the topics they're subscribed to,
/// and the user index they are responsible for. A connected user has the same "identity"
/// as its index in the `connected_users` vector.
pub struct TestDefinition {
    pub connected_brokers: Vec<TestBroker>,
    pub connected_users: Vec<TestUser>,
}

/// A `TestRun` is converted from a `TestDefinition`. It contains actors with their
/// connections so we can pretend to be talking to the broker.
pub struct TestRun {
    /// The connected brokers and their connections
    pub connected_brokers: Vec<Connection>,

    /// The connected users and their connections
    pub connected_users: Vec<Connection>,
}

/// Generate `n` connection pairs for a given protocol
async fn gen_connection_pairs<P: Protocol>(num: usize) -> Vec<(Connection, Connection)> {
    // Generate cert signed by local CA
    let (cert, key) =
        generate_cert_from_ca(LOCAL_CA_CERT, LOCAL_CA_KEY).expect("failed to generate cert");

    // Get random port to bind to
    let bind_endpoint = format!(
        "127.0.0.1:{}",
        portpicker::pick_unused_port().expect("failed to get unused port")
    );

    // Create the listener
    let listener = P::bind(bind_endpoint.as_str(), cert, key)
        .await
        .expect("failed to bind");

    // Create the list of connection pairs we will return
    let mut connection_pairs = Vec::new();

    for _ in 0..num {
        // Spawn a task to connect the user to the broker
        let bind_endpoint_ = bind_endpoint.clone();
        let unfinalized_outgoing_connection =
            spawn(async move { P::connect(&bind_endpoint_, true, Limiter::none()).await });

        // Accept the connection from the user
        let incoming_connection = listener
            .accept()
            .await
            .expect("failed to accept connection")
            .finalize(Limiter::none())
            .await
            .expect("failed to finalize connection");

        // Finalize the outgoing connection
        let outgoing_connection = unfinalized_outgoing_connection
            .await
            .expect("failed to connect to broker")
            .expect("failed to connect to broker");

        // Add the connection pair to the list
        connection_pairs.push((incoming_connection, outgoing_connection));
    }

    connection_pairs
}
/// Create a new broker under test. All test users and brokers will be connected to this broker.
async fn new_broker_under_test<B: Protocol, U: Protocol>() -> Broker<TestingRunDef<B, U>> {
    // Create a key for our broker [under test]
    let (private_key, public_key) = BLS::key_gen(&(), &mut DeterministicRng(0)).unwrap();

    // Create a temporary SQLite file for the broker's database endpoint
    let temp_dir = std::env::temp_dir();
    let database_endpoint = temp_dir
        .join(format!("test-{}.sqlite", StdRng::from_entropy().next_u64()))
        .to_string_lossy()
        .into();

    // Build the broker's config
    let broker_config = Config {
        metrics_bind_endpoint: None,
        public_advertise_endpoint: String::new(),
        public_bind_endpoint: String::new(),
        private_advertise_endpoint: String::new(),
        private_bind_endpoint: String::new(),
        database_endpoint,
        keypair: KeyPair {
            public_key,
            private_key,
        },
        global_memory_pool_size: None,
        ca_cert_path: None,
        ca_key_path: None,
    };

    // Create and return the broker
    Broker::new(broker_config)
        .await
        .expect("failed to create broker")
}

/// This is a helper function to inject users from our `TestDefinition` into the broker under test.
/// It creates the relevant connections, spawns a receive loop on the broker, and adds the user to
/// the internal state.
///
/// After that, it sends subscription messages to the broker for the topics described in `TestDefinition`
async fn inject_users<B: Protocol, U: Protocol>(
    broker_under_test: &Broker<TestingRunDef<B, U>>,
    users: Vec<TestUser>,
) -> Vec<Connection> {
    // Generate a set of connected pairs, one for each user
    // incoming (listener), outgoing (connect)
    let mut connection_pairs = gen_connection_pairs::<U>(users.len()).await;

    // Create the list of users we will return
    let mut connected_users = Vec::new();

    // For each user,
    for user in users {
        // Pop the next connection
        let (incoming_connection, outgoing_connection) = connection_pairs
            .pop()
            .expect("not enough connections spawned");

        // Spawn a task to handle the user inside of the broker
        let inner = broker_under_test.inner.clone();
        let user_public_key = user.public_key.clone();
        let incoming_connection_ = incoming_connection.clone();
        let receive_handle = spawn(async move {
            inner
                .user_receive_loop(&user_public_key, incoming_connection_)
                .await
        })
        .abort_handle();

        // Inject our user into the connections
        broker_under_test.inner.connections.write().add_user(
            &user.public_key.clone(),
            incoming_connection,
            &user.subscribed_topics,
            receive_handle,
        );

        // Add our connection with our user so we can return it
        connected_users.push(outgoing_connection);
    }

    connected_users
}

/// This is a helper function to inject brokers from our `TestDefinition` into the broker under test.
/// It creates the relevant connections, spawns a receive loop on the broker, and adds the broker to
/// the internal state.
///
/// After that, it sends subscription messages to the broker for the topics described in `TestDefinition`,
/// and syncs the users up so the broker knows where to send messages.
async fn inject_brokers<B: Protocol, U: Protocol>(
    broker_under_test: &Broker<TestingRunDef<B, U>>,
    brokers: Vec<TestBroker>,
) -> Vec<Connection> {
    // Generate a set of connected pairs, one for each broker
    // incoming (listener), outgoing (connect)
    let mut connection_pairs = gen_connection_pairs::<B>(brokers.len()).await;

    // Create the list of brokers we will return
    let mut connected_brokers = Vec::new();

    // For each broker
    for (i, broker) in brokers.into_iter().enumerate() {
        // Create an identifier for the broker
        let identifier: BrokerIdentifier = format!("{i}/{i}")
            .try_into()
            .expect("failed to create broker identifier");

        // Pop the next connection
        let (incoming_connection, outgoing_connection) = connection_pairs
            .pop()
            .expect("not enough connections spawned");

        // Spawn a task to handle the broker inside of the broker under test
        let inner = broker_under_test.inner.clone();
        let identifier_ = identifier.clone();
        let incoming_connection_ = incoming_connection.clone();
        let receive_handle = spawn(async move {
            inner
                .broker_receive_loop(&identifier_, incoming_connection_)
                .await
        })
        .abort_handle();

        // Inject the broker into our connections
        broker_under_test.inner.connections.write().add_broker(
            identifier.clone(),
            incoming_connection,
            receive_handle,
        );

        // Aggregate the topics we should be subscribed to
        let mut topics = Vec::new();
        for user in &broker.connected_users {
            topics.extend(user.subscribed_topics.clone());
        }

        // Create a map of our topics
        // TODO: somehow make these automatically adjust to what really happens
        let mut topic_sync_map = TopicSyncMap::new(0);
        for topic in topics {
            topic_sync_map.insert(topic, SubscriptionStatus::Subscribed);
        }

        // Sync the map to the broker under test
        let topic_sync_message = Message::TopicSync(
            rkyv::to_bytes::<_, 256>(&topic_sync_map.diff())
                .expect("failed to serialize map")
                .to_vec(),
        );
        send_message_as!(outgoing_connection, topic_sync_message);

        // Create a map of our users
        let mut user_map = DirectMap::new(identifier.clone());
        for user in broker.connected_users {
            user_map.insert(user.public_key, identifier.clone());
        }

        // Sync the map to the broker under test
        let user_sync_message = Message::UserSync(
            rkyv::to_bytes::<_, 256>(&user_map.diff())
                .expect("failed to serialize map")
                .to_vec(),
        );
        send_message_as!(outgoing_connection, user_sync_message);

        // Add our connection with our broker so we can return it
        connected_brokers.push(outgoing_connection);
    }

    connected_brokers
}

impl TestDefinition {
    /// Start the test run, connecting all users and brokers to the broker under test.
    pub async fn into_run<B: Protocol, U: Protocol>(self) -> TestRun {
        // Create the `Run` we will return
        let mut run = TestRun {
            connected_users: Vec::new(),
            connected_brokers: Vec::new(),
        };

        // Create a new broker under test with the provided protocols
        let broker_under_test = new_broker_under_test::<B, U>().await;

        // Inject the users into the broker under test
        run.connected_users = inject_users(&broker_under_test, self.connected_users).await;

        // Inject the brokers into the broker under test
        run.connected_brokers = inject_brokers(&broker_under_test, self.connected_brokers).await;

        // Return the run
        run
    }
}
