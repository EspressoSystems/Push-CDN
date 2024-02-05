//! The following is an example of a Push CDN client implementation.

use std::{marker::PhantomData, time::Duration};

use client::{Client, Config};
use proto::{connection::protocols::quic::Quic, crypto, error::Result, message::Topic};

use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use rand::{rngs::StdRng, SeedableRng};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Generate a random keypair
    let (signing_key, verification_key) =
        crypto::generate_random_keypair::<BLS, StdRng>(StdRng::from_entropy())?;

    // Create a client
    // TODO: constructors for config
    let client = Client::<BLS, Quic>::new(Config {
        endpoint: "127.0.0.1:8082".to_string(),
        verification_key,
        signing_key,
        subscribed_topics: vec![Topic::DA, Topic::Global],

        pd: PhantomData,
    })
    .await?;

    loop {
        // Send a direct message to ourselves
        let _ = client
            .send_direct_message(verification_key, vec![123])
            .await;

        // Receive the direct message (from ourselves)
        println!("{:?}", client.receive_message().await);
        sleep(Duration::from_secs(3)).await;
    }
}
