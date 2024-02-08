//! The following is an example of a Push CDN client implementation.
//! We spawn two clients. In a single-broker run, this lets them connect
//! cross-broker.

use std::{marker::PhantomData, sync::Arc};

use client::{Client, Config};
use proto::{
    connection::protocols::{quic::Quic},
    crypto::{self, KeyPair},
    error::Result,
    message::{Message, Topic},
};

use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use rand::{rngs::StdRng, SeedableRng};
use tokio::{join, spawn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Generate two random keypairs, one for each client
    let (signing_key_1, verification_key_1) =
        crypto::generate_random_keypair::<BLS, StdRng>(StdRng::from_entropy())?;

    let (signing_key_2, verification_key_2) =
        crypto::generate_random_keypair::<BLS, StdRng>(StdRng::from_entropy())?;

    // Create our first client
    // TODO: constructors for config
    let client1 = Arc::new(
        // We are running with the `BLS` key signing algorithm
        // and `Quic` as a networking protocol.
        Client::<BLS, Quic>::new(Config {
            // Our marshal address, locally running on port 8082
            endpoint: "127.0.0.1:8082".to_string(),
            keypair: KeyPair {
                signing_key: signing_key_1,
                verification_key: verification_key_1,
            },

            // The topics we want to subscribe to initially
            subscribed_topics: vec![Topic::DA, Topic::Global],

            // TODO: remove this via means of constructor
            pd: PhantomData,
        })
        .await?,
    );

    // Create our second client
    let client2 = Arc::new(
        Client::<BLS, Quic>::new(Config {
            // This is the same marshal, but a possibly different broker.
            endpoint: "127.0.0.1:8082".to_string(),
            keypair: KeyPair {
                signing_key: signing_key_2,
                verification_key: verification_key_2,
            },
            subscribed_topics: vec![Topic::DA, Topic::Global],
            pd: PhantomData,
        })
        .await?,
    );

    // Run our first client, which sends a message to our second.
    let client1 = spawn(async move {
        // Clone our client
        let client1_ = client1.clone();

        // The sending side
        let jh1 = spawn(async move {
            // Send a message to client 2
            let message = "hello client2";
            client1_
                .send_direct_message(&verification_key_2, "hello client2".as_bytes().to_vec())
                .expect("failed to send message");

            println!("client 1 sent \"{message}\"");
        });

        // The receiving side
        let jh2 = spawn(async move {
            let message = client1
                .receive_message()
                .await
                .expect("failed to receive message");

            if let Message::Direct(direct) = message {
                println!(
                    "client 1 received {}",
                    String::from_utf8(direct.message).expect("failed to deserialize message")
                );
            } else {
                panic!("received wrong message type");
            }
        });

        let _ = tokio::join!(jh1, jh2);
    });

    // Run our second client, which sends a message to our first.
    let client2 = spawn(async move {
        // Clone our client
        let client2_ = client2.clone();

        // The sending side
        let jh1 = spawn(async move {
            // Send a message to client 2
            let message = "hello client1";
            client2_
                .send_direct_message(&verification_key_1, "hello client1".as_bytes().to_vec())
                .expect("failed to send message");

            println!("client 2 sent \"{message}\"");
        });

        // The receiving side
        let jh2 = spawn(async move {
            let message = client2
                .receive_message()
                .await
                .expect("failed to receive message");

            if let Message::Direct(direct) = message {
                println!(
                    "client 2 received {}",
                    String::from_utf8(direct.message).expect("failed to deserialize message")
                );
            } else {
                panic!("received wrong message type")
            }
        });

        let _ = tokio::join!(jh1, jh2);
    });

    // Wait for both to finish
    let _ = join!(client1, client2);

    Ok(())
}
