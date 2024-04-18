//! Contains connection-related integration tests, like testing
//! end-to-end connections and double connects.

use cdn_broker::{Broker, Config as BrokerConfig};
use cdn_client::{Client, Config as ClientConfig};
use cdn_marshal::{Config as MarshalConfig, Marshal};
use cdn_proto::{crypto::signature::KeyPair, def::TestingRunDef, message::Topic};
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use rand::{rngs::StdRng, SeedableRng};
use tokio::spawn;

/// Generate a deterministic keypair from a seed
macro_rules! keypair_from_seed {
    ($seed: expr) => {{
        BLS::key_gen(&(), &mut StdRng::seed_from_u64($seed)).expect("failed to generate key")
    }};
}

/// Create a new broker for testing purposes that uses the memory network.
/// Parameters include the key (as a u64), the public endpoint,
/// and the private endpoint.
macro_rules! new_broker {
    ($key: expr, $public_ep: expr, $private_ep: expr) => {{
        // Generate keypair
        let (private_key, public_key) = keypair_from_seed!($key);

        // Create config
        let config: BrokerConfig<TestingRunDef> = BrokerConfig {
            ca_cert_path: None,
            ca_key_path: None,
            discovery_endpoint: "test.sqlite".to_string(),
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
    ($ep: expr) => {{
        // Create the marshal's configuration
        let config = MarshalConfig {
            bind_endpoint: $ep.to_string(),
            discovery_endpoint: "test.sqlite".to_string(),
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
        Client::<TestingRunDef>::new(config)
    }};
}

/// Test that an end-to-end connection succeeds
#[tokio::test]
async fn test_end_to_end() {
    // Create and start a new broker
    new_broker!(0, "8080", "8081");

    // Create and start a new marshal
    new_marshal!("8082");

    // Create and get the handle to a new client
    let client = new_client!(0, vec![Topic::Global], "8082");
    let client_public_key = keypair_from_seed!(0).1;

    // Send a message to ourself
    client
        .send_direct_message(&client_public_key, b"hello direct".to_vec())
        .await
        .expect("failed to send message");
}

// TODO: finish the below tests
// #[tokio::test]
// async fn test_double_connect_same_broker() {
//     // Create and start a new broker
//     new_broker!(0, "8083", "8084");

//     // Create and start a new marshal
//     new_marshal!("8085");

//     // Create and get the handle to a new client
//     let client_1 = new_client!(0, vec![Topic::Global], "8085").expect("client connection failed");
//     let client_public_key = keypair_from_seed!(0).1;

//     // Create another client with the same key
//     let client_2 = new_client!(0, vec![Topic::Global], "8085").expect("client connection failed");

//     sleep(Duration::from_secs(5)).await;

//     // Attempt to send a message from the first client
//     let send_1 = client_1
//         .send_direct_message(&client_public_key, b"hello direct".to_vec())
//         .await;

//     // Attempt to send a message from the second client
//     let send_2 = client_2
//         .send_direct_message(&client_public_key, b"hello direct".to_vec())
//         .await;

//     // Assert one of them failed
//     assert!(send_1.is_err() || send_2.is_err());
// }

// // #[tokio::test]
// // async fn test_double_connect_different_broker() {
// //     // Create and start a new broker
// //     new_broker!(0, "8086", "8087");

// //     // Create and start another new broker
// //     new_broker!(0, "8088", "8089");

// //     // Create and start a new marshal
// //     new_marshal!("8090");

// //     // Create and get the handle to a new client
// //     let client_1 = new_client!(0, vec![Topic::Global], "8090").expect("failed to create client");
// //     let client_public_key = keypair_from_seed!(0).1;

// //     // Create another client with the same key
// //     let client_2 = new_client!(0, vec![Topic::Global], "8090").expect("failed to create client");

// //     sleep(Duration::from_secs(20)).await;

// //     // Send a message to ourself
// //     client_1
// //         .send_direct_message(&client_public_key, b"hello direct".to_vec())
// //         .await
// //         .expect("failed to send message");

// //     client_2
// //         .send_direct_message(&client_public_key, b"hello direct".to_vec())
// //         .await
// //         .expect("failed to send message");
// // }
