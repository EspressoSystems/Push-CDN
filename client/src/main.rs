//! The following is an example of a Push CDN client implementation.
//! We spawn two clients. In a single-broker run, this lets them connect
//! cross-broker.

use std::{marker::PhantomData, time::Duration};

use clap::Parser;
use client::{Client, Config};
use proto::{
    connection::protocols::quic::Quic,
    crypto::{self, DeterministicRng, KeyPair},
    error::Result,
};

use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use tokio::time::sleep;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// The main component of the push CDN.
struct Args {
    /// The node's identifier (for deterministically creating keys)
    #[arg(short, long)]
    id: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Get command-line args
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Generate two random keypairs, one for each client
    let (signing_key, verification_key) =
        crypto::generate_random_keypair::<BLS, DeterministicRng>(DeterministicRng(args.id))?;

    let client = Client::<BLS, Quic>::new(Config {
        endpoint: "127.0.0.1:8082".to_string(),
        keypair: KeyPair {
            verification_key,
            signing_key,
        },
        subscribed_topics: vec![],
        pd: PhantomData,
    })
    .await?;

    // We want the first node to send to the second
    if args.id != 0 {
        // Generate two random keypairs, one for each client
        let (_, other_verification_key) =
            crypto::generate_random_keypair::<BLS, DeterministicRng>(DeterministicRng(0))?;

        loop {
            // Create a big 512MB message
            let m = vec![0u8; 256_000_000];

            if let Err(err) = client.send_direct_message(&other_verification_key, m) {
                tracing::error!("failed to send message: {}", err);
            };

            sleep(Duration::from_secs(1)).await;
        }
    } else {
        loop {
            if let Err(err) = client.receive_message().await {
                tracing::error!("failed to receive message: {}", err);
                continue;
            };
        }
    }
}
