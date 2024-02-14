//! The following is an example of a Push CDN client implementation.
//! We spawn two clients. In a single-broker run, this lets them connect
//! cross-broker.

use std::{marker::PhantomData, time::Duration};

use clap::Parser;
use client::{Client, Config, KeyPair};
use proto::{connection::protocols::quic::Quic, crypto::rng::DeterministicRng, error::Result};

use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
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

    let (private_key, public_key) = BLS::key_gen(&(), &mut DeterministicRng(args.id)).unwrap();

    let client = Client::<BLS, Quic>::new(Config {
        endpoint: "127.0.0.1:8082".to_string(),
        keypair: KeyPair {
            public_key,
            private_key,
        },
        subscribed_topics: vec![],
        pd: PhantomData,
    })
    .await?;

    // We want the first node to send to the second
    if args.id != 0 {
        // Generate two random keypairs, one for each client
        let (_, other_public_key) = BLS::key_gen(&(), &mut DeterministicRng(args.id)).unwrap();

        loop {
            // Create a big 512MB message
            let m = vec![0u8; 256_000_000];

            if let Err(err) = client.send_direct_message(&other_public_key, m) {
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
