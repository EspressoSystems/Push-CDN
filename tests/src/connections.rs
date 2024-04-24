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
    discovery::{embedded::Embedded, DiscoveryClient},
    message::Topic,
};
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};
use tokio::{spawn, time::timeout};

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
    let mut db = Embedded::new(discovery_endpoint, None)
        .await
        .expect("failed to initialize db client");

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
