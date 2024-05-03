//! Contains connection-related integration tests, like testing
//! end-to-end connections and double connects.

use std::{sync::Arc, time::Duration};

use cdn_broker::{Broker, Config as BrokerConfig};
use cdn_client::{Client, Config as ClientConfig};
use cdn_marshal::{Config as MarshalConfig, Marshal};
use cdn_proto::{
    connection::UserPublicKey,
    crypto::signature::{KeyPair, Serializable},
    def::{TestingConnection, TestingRunDef},
    discovery::{embedded::Embedded, BrokerIdentifier, DiscoveryClient},
    message::Topic,
};
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};
use tokio::{
    spawn,
    time::{sleep, timeout},
};

/// Generate a deterministic keypair from a seed
macro_rules! keypair_from_seed {
    ($seed: expr) => {{
        BLS::key_gen(&(), &mut StdRng::seed_from_u64($seed)).expect("failed to generate key")
    }};
}

/// Generate a serialized public key from a seed deterministically
macro_rules! serialized_public_key_from_seed {
    ($seed: expr) => {{
        keypair_from_seed!($seed)
            .1
            .serialize()
            .expect("failed to serialize public key")
    }};
}

/// Get a path for a temporary `SQLite` database
macro_rules! get_temp_db_path {
    () => {{
        // Get a temporary directory
        let temp_dir = std::env::temp_dir();

        // Generate a random path
        temp_dir
            .join(format!("test-{}.sqlite", StdRng::from_entropy().next_u64()))
            .to_string_lossy()
            .to_string()
    }};
}

/// Create a new broker for testing purposes that uses the memory network.
/// Parameters include the key (as a u64), the public endpoint,
/// and the private endpoint.
macro_rules! new_broker {
    ($key: expr, $public_ep: expr, $private_ep: expr, $discovery_ep: expr) => {{
        // Generate keypair
        let (private_key, public_key) = keypair_from_seed!($key);

        // Create config
        let config: BrokerConfig<TestingRunDef> = BrokerConfig {
            ca_cert_path: None,
            ca_key_path: None,
            discovery_endpoint: $discovery_ep.clone(),
            keypair: KeyPair {
                public_key,
                private_key,
            },
            metrics_bind_endpoint: None,
            private_advertise_endpoint: $private_ep.to_string(),
            private_bind_endpoint: $private_ep.to_string(),
            public_advertise_endpoint: $public_ep.to_string(),
            public_bind_endpoint: $public_ep.to_string(),
        };

        // Create broker
        let broker = Broker::<TestingRunDef>::new(config)
            .await
            .expect("failed to create broker");

        // Spawn broker
        spawn(broker.start());
    }};
}

/// Create a new marshal for testing purposes that uses the memory network.
/// The only parameter is the endpoint (as a string) to bind to.
macro_rules! new_marshal {
    ($ep: expr, $discovery_ep: expr) => {{
        // Create the marshal's configuration
        let config = MarshalConfig {
            bind_endpoint: $ep.to_string(),
            discovery_endpoint: $discovery_ep.to_string(),
            metrics_bind_endpoint: None,
            ca_cert_path: None,
            ca_key_path: None,
        };

        // Create a new marshal
        let marshal = Marshal::<TestingRunDef>::new(config)
            .await
            .expect("failed to create marshal");

        // Spawn the marshal
        spawn(marshal.start());
    }};
}

/// Create a new client, supplying it with the given topics and marshal
/// endpoint. `Key` is a deterministic, seeded keypair.
macro_rules! new_client {
    ($key: expr, $topics: expr, $marshal_ep: expr) => {{
        // Generate keypair
        let (private_key, public_key) = keypair_from_seed!($key);

        // Build the client's config
        let config = ClientConfig {
            endpoint: $marshal_ep.to_string(),
            keypair: KeyPair {
                public_key,
                private_key,
            },
            subscribed_topics: $topics,
            use_local_authority: true,
        };

        // Create the client
        Client::<TestingConnection>::new(config)
    }};
}

/// Create a new database client with the given endpoint and identity.
macro_rules! new_db_client {
    ($discovery_ep: expr, $as: expr) => {{
        // Create a new DB client
        Embedded::new($discovery_ep.clone(), $as)
            .await
            .expect("failed to initialize db client")
    }};
}

/// Test that an end-to-end connection succeeds
#[tokio::test]
async fn test_end_to_end() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path!();

    // Create and start a new broker
    new_broker!(0, "8080", "8081", discovery_endpoint);

    // Create and start a new marshal
    new_marshal!("8082", discovery_endpoint);

    // Create and get the handle to a new client
    let client = new_client!(0, vec![Topic::Global], "8082");
    let client_public_key = keypair_from_seed!(0).1;

    // Send a message to ourself
    client
        .send_direct_message(&client_public_key, b"hello direct".to_vec())
        .await
        .expect("failed to send message");
}

/// Test that the whitelist works
#[tokio::test]
async fn test_whitelist() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path!();

    // Create and start a new broker
    new_broker!(0, "8083", "8084", discovery_endpoint);

    // Create and start a new marshal
    new_marshal!("8085", discovery_endpoint);

    // Create a client with keypair 1
    let client1_public_key: UserPublicKey = Arc::from(serialized_public_key_from_seed!(1));
    let client1 = new_client!(1, vec![Topic::Global], "8085");

    // Create a client with keypair 2
    let client2_public_key: UserPublicKey = Arc::from(serialized_public_key_from_seed!(2));
    let client2 = new_client!(2, vec![Topic::Global], "8085");

    // Assert both clients can connect
    let Ok(()) = timeout(Duration::from_secs(1), client1.ensure_initialized()).await else {
        panic!("failed to connect as client1");
    };
    let Ok(()) = timeout(Duration::from_secs(1), client2.ensure_initialized()).await else {
        panic!("failed to connect as client2");
    };

    // Create a new DB client
    let mut db = new_db_client!(discovery_endpoint, None);

    // Set the whitelist to only allow client1
    db.set_whitelist(vec![client1_public_key.clone()])
        .await
        .expect("failed to set whitelist");

    // Assert client1 is whitelisted
    assert!(db
        .check_whitelist(&client1_public_key)
        .await
        .is_ok_and(|x| x));

    // Assert client2 is not whitelisted
    assert!(db
        .check_whitelist(&client2_public_key)
        .await
        .is_ok_and(|x| !x));

    // Recreate clients
    let client1 = new_client!(1, vec![Topic::Global], "8085");
    let client2 = new_client!(2, vec![Topic::Global], "8085");

    // Assert we can connect as client1
    let Ok(()) = timeout(Duration::from_secs(1), client1.ensure_initialized()).await else {
        panic!("failed to connect as client1");
    };

    // Assert we can't connect as client2
    assert!(
        timeout(Duration::from_secs(1), client2.ensure_initialized())
            .await
            .is_err(),
        "client2 connected when it shouldn't have"
    );
}

/// Test for connecting twice to the same broker.
/// Should kick off the first connection.
#[tokio::test]
async fn test_double_connect_same_broker() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path!();

    // Create and start a new broker
    new_broker!(0, "8083", "8084", discovery_endpoint);

    // Create and start a new marshal
    new_marshal!("8085", discovery_endpoint);

    // Create 2 clients with the same keypair
    let client1 = new_client!(1, vec![Topic::Global], "8085");
    let client2 = new_client!(1, vec![Topic::Global], "8085");

    // Assert both clients are connected
    let Ok(()) = timeout(Duration::from_secs(1), client1.ensure_initialized()).await else {
        panic!("failed to connect as client1");
    };
    let Ok(()) = timeout(Duration::from_secs(1), client2.ensure_initialized()).await else {
        panic!("failed to connect as client2");
    };

    // Wait for a second
    sleep(Duration::from_millis(50)).await;

    // Attempt to send a message, should fail
    assert!(client1
        .send_direct_message(&keypair_from_seed!(1).1, b"hello direct".to_vec())
        .await
        .is_err());

    // The second client to connect should have succeeded
    client2
        .send_direct_message(&keypair_from_seed!(1).1, b"hello direct".to_vec())
        .await
        .expect("failed to send message from second client");
}

/// Test for connecting twice to different brokers
/// Should kick off the first connection.
#[tokio::test]
async fn test_double_connect_different_broker() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path!();

    // Create and start two brokers
    new_broker!(0, "8088", "8089", discovery_endpoint);
    new_broker!(0, "8086", "8087", discovery_endpoint);

    // Create and start a new marshal
    new_marshal!("8090", discovery_endpoint);

    // Create 2 clients with the same keypair
    let client1 = new_client!(1, vec![Topic::Global], "8090");
    let client2 = new_client!(1, vec![Topic::Global], "8090");

    // Get the brokers
    let brokers: Vec<BrokerIdentifier> = new_db_client!(discovery_endpoint, None)
        .get_other_brokers()
        .await
        .expect("failed to get brokers")
        .into_iter()
        .collect();

    // Create database clients as each broker
    let mut broker0_db_client = new_db_client!(discovery_endpoint, Some(brokers[0].clone()));
    let mut broker1_db_client = new_db_client!(discovery_endpoint, Some(brokers[1].clone()));

    // Make sure the first client connects to the first broker by setting the second
    // broker as having a higher number of connections
    broker1_db_client
        .perform_heartbeat(1, Duration::from_secs(60))
        .await
        .expect("broker failed to perform heartbeat");

    // Connect the first client
    let Ok(()) = timeout(Duration::from_secs(1), client1.ensure_initialized()).await else {
        panic!("failed to connect as client1");
    };

    // Set the number of connections for the first broker to be higher
    broker0_db_client
        .perform_heartbeat(2, Duration::from_secs(60))
        .await
        .expect("broker failed to perform heartbeat");

    // Connect the second client
    let Ok(()) = timeout(Duration::from_secs(1), client2.ensure_initialized()).await else {
        panic!("failed to connect as client2");
    };

    // Sleep for a second
    sleep(Duration::from_millis(50)).await;

    // Assert the second client can send a message
    client2
        .send_direct_message(&keypair_from_seed!(1).1, b"hello direct".to_vec())
        .await
        .expect("failed to send message from first client");

    // Assert the first client can't send a message
    assert!(
        client1
            .send_direct_message(&keypair_from_seed!(1).1, b"hello direct".to_vec())
            .await
            .is_err(),
        "second client connected when it shouldn't have"
    );
}
