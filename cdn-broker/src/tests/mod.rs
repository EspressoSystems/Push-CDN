//! Commonalities for deterministic (non-networked) testing of our broker.
//! This is not guarded by `![cfg(test)]` because we use the same functions
//! when running benchmarks.

use std::sync::Arc;

use cdn_proto::{
    connection::protocols::{
        memory::{Memory, MemoryConnection},
        Connection,
    },
    crypto::{rng::DeterministicRng, signature::KeyPair},
    def::TestingRunDef,
    discovery::BrokerIdentifier,
    message::{Message, Topic},
};
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tokio::spawn;

#[cfg(test)]
mod broadcast;

#[cfg(test)]
mod direct;

use crate::{connections::DirectMap, Broker, Config};

/// An actor is a [user/broker] that we inject to test message send functionality.
pub struct InjectedActor {
    /// The in-memory sender that sends to the broker under test
    pub sender: MemoryConnection,
    /// The in-memory receiver that receives from the broker under test
    pub receiver: MemoryConnection,
}

/// This lets us send a message as a particular network actor. It just helps
/// readability.
#[macro_export]
macro_rules! send_message_as {
    ($obj:expr, $message: expr) => {
        $obj.sender
            .send_message($message.clone())
            .await
            .expect("failed to send message");
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

    // Make sure we haven't received this message
    (no, $actor: expr) => {
        assert!(
            $actor.receiver.receiver.0.is_empty(),
            "wasn't supposed to receive a message but did"
        )
    };

    // Make sure we have received the message in a timeframe of 50ms
    (yes, $actor: expr, $message:expr) => {
        // Receive the message with a timeout
        let Ok(message) =
            timeout(Duration::from_millis(50), $actor.receiver.receiver.0.recv()).await
        else {
            panic!("timed out trying to receive message");
        };

        // Assert the message is the correct one
        assert!(
            message
                == Ok(Bytes::from_unchecked(
                    $message
                        .serialize()
                        .expect("failed to re-serialize message")
                )),
            "was supposed to receive a message but did not"
        )
    };
}

/// This is what we use to describe tests. These are the [brokers/users] connected
/// _DIRECTLY_ to the broker under test, along with the topics they're subscribed to,
/// and the user index they are responsible for. A connected user has the same "identity"
/// as its index in the `connected_users` vector.
pub struct TestDefinition {
    pub connected_brokers: Vec<(Vec<u8>, Vec<Topic>)>,
    pub connected_users: Vec<Vec<Topic>>,
}

/// A `TestRun` is converted from a `TestDefinition`. It contains actors with their
/// sending and receiving channels so we can pretend to be talking to the broker.
pub struct TestRun {
    /// The connected brokers and their handles
    pub connected_brokers: Vec<InjectedActor>,

    /// The connected users and their handles
    pub connected_users: Vec<InjectedActor>,
}

impl TestDefinition {
    /// Creates a new broker under test. This configures and starts a local broker
    /// who will be deterministically tested.
    async fn new_broker_under_test() -> Broker<TestingRunDef> {
        // Create a key for our broker [under test]
        let (private_key, public_key) = BLS::key_gen(&(), &mut DeterministicRng(0)).unwrap();

        // Create a temporary SQLite file for the broker's discovery endpoint
        let temp_dir = std::env::temp_dir();
        let discovery_endpoint = temp_dir
            .join(format!("test-{}.sqlite", StdRng::from_entropy().next_u64()))
            .to_string_lossy()
            .into();

        // Build the broker's config
        let broker_config: Config<TestingRunDef> = Config {
            metrics_bind_endpoint: None,
            public_advertise_endpoint: String::new(),
            public_bind_endpoint: String::new(),
            private_advertise_endpoint: String::new(),
            private_bind_endpoint: String::new(),
            discovery_endpoint,
            keypair: KeyPair {
                public_key,
                private_key,
            },

            ca_cert_path: None,
            ca_key_path: None,
        };

        // Create the broker
        Broker::new(broker_config)
            .await
            .expect("failed to create broker")
    }

    /// This is a helper function to inject users from our `TestDefinition` into the broker under test.
    /// It creates sending and receiving channels, spawns a receive loop on the broker,
    /// and adds the user to the internal state.
    ///
    /// Then, it sends subscription messages to the broker for the topics described in `TestDefinition`
    async fn inject_users(
        broker_under_test: &Broker<TestingRunDef>,
        users: &[Vec<Topic>],
    ) -> Vec<InjectedActor> {
        // Return this at the end, our running list of users
        let mut injected_users: Vec<InjectedActor> = Vec::new();

        // For each user,
        for (i, topics) in users.iter().enumerate() {
            // Extrapolate identifier
            #[allow(clippy::cast_possible_truncation)]
            let identifier: Arc<Vec<u8>> = Arc::from(vec![i as u8]);

            // Generate a testing pair of memory network channels
            let connection1 = Memory::gen_testing_connection();
            let connection2 = Memory::gen_testing_connection();

            // Create our user object
            let injected_user = InjectedActor {
                sender: connection1.clone(),
                receiver: connection2.clone(),
            };

            // Spawn our user receiver in the broker under test
            let inner = broker_under_test.inner.clone();
            let identifier_ = identifier.clone();
            let receive_handle =
                spawn(async move { inner.user_receive_loop(&identifier_, connection1).await })
                    .abort_handle();

            // Inject our user into the connections
            broker_under_test.inner.connections.write().await.add_user(
                &identifier,
                connection2,
                topics,
                receive_handle,
            );

            // Add to our running total
            injected_users.push(injected_user);
        }

        injected_users
    }

    /// This is a helper function to inject brokers from our `TestDefinition` into the broker under test.
    /// It creates sending and receiving channels, spawns a receive loop on the broker,
    /// and adds the broker to the internal state.
    ///
    /// Then, it sends subscription messages to the broker for the topics described in `TestDefinition`,
    /// and syncs the users up so the broker knows where to send messages.
    async fn inject_brokers(
        broker_under_test: &Broker<TestingRunDef>,
        brokers: Vec<(Vec<u8>, Vec<Topic>)>,
    ) -> Vec<InjectedActor> {
        // Return this at the end, our running list of brokers
        let mut injected_brokers: Vec<InjectedActor> = Vec::new();

        // For each broker,
        for (i, broker) in brokers.iter().enumerate() {
            // Create our identifier
            let identifier: BrokerIdentifier = format!("{i}/{i}")
                .try_into()
                .expect("failed to create broker identifier");

            // Generate a testing pair of memory network channels
            let connection1 = Memory::gen_testing_connection();
            let connection2 = Memory::gen_testing_connection();

            // Create our broker object
            let injected_broker = InjectedActor {
                sender: connection1.clone(),
                receiver: connection2.clone(),
            };

            // Spawn our receiver in the broker under test
            let inner = broker_under_test.inner.clone();
            let identifier_ = identifier.clone();
            let receive_handle = spawn(async move {
                inner
                    .broker_receive_loop(&identifier_, connection1)
                    .await
                    .unwrap();
            })
            .abort_handle();

            // Inject our broker into the connections
            broker_under_test
                .inner
                .connections
                .write()
                .await
                .add_broker(identifier.clone(), connection2, receive_handle);

            // Send our subscriptions to it
            let subscribe_message = Message::Subscribe(broker.1.clone());
            send_message_as!(injected_broker, subscribe_message);

            // Create a map of our users
            let mut user_map = DirectMap::new(identifier.clone());

            for user in broker.0.clone() {
                user_map.insert(Arc::from(vec![user]), identifier.clone());
            }

            // Sync the map to the broker under test
            let user_sync_message = Message::UserSync(
                rkyv::to_bytes::<_, 256>(&user_map.diff())
                    .expect("failed to serialize map")
                    .to_vec(),
            );
            send_message_as!(injected_broker, user_sync_message);

            // Add to our running total
            injected_brokers.push(injected_broker);
        }

        injected_brokers
    }

    /// This is the conversion from a `TestDefinition` into a `Run`. Implicitly, the broker is started
    /// and all sending and receiving operations on that broker start.
    pub async fn into_run(self) -> TestRun {
        // Create a new `Run`, which we will be returning
        let mut run = TestRun {
            connected_users: vec![],
            connected_brokers: vec![],
        };

        // Create our broker under test
        let broker_under_test = Self::new_broker_under_test().await;

        // Inject our brokers
        run.connected_brokers =
            Self::inject_brokers(&broker_under_test, self.connected_brokers).await;

        // Inject our users
        run.connected_users = Self::inject_users(&broker_under_test, &self.connected_users).await;

        // Return our injected brokers and users
        run
    }
}
