//! The following is an example of a Push CDN client implementation.
//! We spawn two clients. In a single-broker run, this lets them connect
//! cross-broker.

use std::time::Duration;

use clap::Parser;
use client::{Client, ConfigBuilder};
use proto::{
    bail,
    connection::protocols::quic::Quic,
    crypto::{rng::DeterministicRng, signature::KeyPair},
    error::{Error, Result},
};

use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use tokio::time::sleep;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// The main component of the push CDN.
struct Args {
    /// The node's identifier (for deterministically creating keys)
    #[arg(short, long)]
    id: u64,
}

#[cfg_attr(feature = "runtime-tokio", tokio::main)]
#[cfg_attr(feature = "runtime-async-std", async_std::main)]
async fn main() -> Result<()> {
    // Get command-line args
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Generate two random keypairs, one for each client
    let (private_key, public_key) = BLS::key_gen(&(), &mut DeterministicRng(0)).unwrap();

    // Build the config, the endpoint being where we expect the marshal to be
    let config = bail!(
        ConfigBuilder::default()
            .endpoint("127.0.0.1:8082".to_string())
            .keypair(KeyPair {
                public_key,
                private_key,
            })
            .build(),
        Parse,
        "failed to build client config"
    );

    let client = Client::<BLS, Quic>::new(config).await?;

    // We want the first node to send to the second
    if args.id != 0 {
        // This client sends a message of a random size every second.
        loop {
            let m = vec![0u8; 10000];

            if let Err(err) = client.send_direct_message(&public_key, m).await {
                tracing::error!("failed to send message: {err}");
            };
            info!("sent message");

            sleep(Duration::from_secs(1)).await;
        }
    } else {
        // This client receives a direct message and prints the size.
        loop {
            if let Err(err) = client.receive_message().await {
                tracing::error!("failed to receive message: {err}");
            };

            info!("received message");
        }
    }
}
