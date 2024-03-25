//! The following is an example of a Push CDN client implementation.
//! In this example, we send messages to ourselves via broadcast and direct
//! systems.

use cdn_client::{Client, ConfigBuilder};
use cdn_proto::{
    connection::protocols::quic::Quic,
    crypto::signature::{KeyPair, Serializable},
    message::{Broadcast, Direct, Message, Topic},
};
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use rand::{rngs::StdRng, SeedableRng};

#[tokio::main]
async fn main() {
    // Generate a random keypair
    let (private_key, public_key) =
        BLS::key_gen(&(), &mut StdRng::from_entropy()).expect("failed to generate key");

    // Build the config, the endpoint being where we expect the marshal to be
    let config = ConfigBuilder::default()
        .endpoint("127.0.0.1:8082".to_string())
        // Private key is only used for signing authentication messages
        .keypair(KeyPair {
            public_key,
            private_key,
        })
        // Subscribe to the global consensus topic
        .subscribed_topics(vec![Topic::Global])
        .build()
        .expect("failed to build client config");

    // Create a client, specifying the BLS signature algorithm
    // and the `QUIC` protocol.
    let client = Client::<BLS, Quic>::new(config)
        .await
        .expect("failed to create client");

    // Send a direct message to ourselves
    client
        .send_direct_message(&public_key, b"hello direct".to_vec())
        .await
        .expect("failed to send message");

    // Receive the direct message
    let message = client
        .receive_message()
        .await
        .expect("failed to receive message");

    // Assert we've received the proper direct message
    assert!(
        message
            == Message::Direct(Direct {
                recipient: public_key.serialize().unwrap(),
                message: b"hello direct".to_vec()
            })
    );

    // Send a broadcast message to the global topic
    client
        .send_broadcast_message(vec![Topic::Global], b"hello broadcast".to_vec())
        .await
        .expect("failed to send message");

    // Receive the broadcast message
    let message = client
        .receive_message()
        .await
        .expect("failed to receive message");

    // Assert we've received the proper broadcast message
    assert!(
        message
            == Message::Broadcast(Broadcast {
                topics: vec![Topic::Global],
                message: b"hello broadcast".to_vec()
            })
    );
}
