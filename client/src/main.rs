//! The following is an example of a Push CDN client implementation.

use std::collections::HashSet;

use client::{Client, Config};
use proto::{
    connection::{auth::UserAuthenticationData, protocols::quic::Quic},
    crypto,
    error::Result,
    message::Topic,
};

use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use rand::{rngs::StdRng, SeedableRng};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Generate a random keypair
    let (signing_key, verification_key) =
        crypto::generate_random_keypair::<BLS, StdRng>(StdRng::from_entropy())?;

    // Create the data we need to authenticate
    let auth_data = UserAuthenticationData {
        verification_key,
        signing_key,
        subscribed_topics: Mutex::from(HashSet::from_iter([Topic::DA, Topic::Global])),
    };

    // Create a client
    let client = Client::<BLS, Quic>::new(Config {
        endpoint: "127.0.0.1:8080".to_string(),
        auth_data,
    })
    .await?;

    // Send a direct message to ourselves
    client
        .send_direct_message(verification_key, vec![123])
        .await?;

    // Receive the direct message (from ourselves)
    println!("{:?}", client.receive_message().await);

    Ok(())
}
