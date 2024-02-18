//! The following is an example of a Push CDN client implementation.
//! We spawn two clients. In a single-broker run, this lets them connect
//! cross-broker.

use std::time::Instant;

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
    let (private_key, public_key) = BLS::key_gen(&(), &mut DeterministicRng(args.id)).unwrap();

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
        // Generate two random keypairs, one for each client
        let (_, other_public_key) = BLS::key_gen(&(), &mut DeterministicRng(0)).unwrap();

        let now = Instant::now();
        for _ in 0..2500 {
            // Create a big 512MB message
            let m = vec![0u8; 100000];

            if let Err(err) = client.send_direct_message(&other_public_key, m).await {
                tracing::error!("failed to send message: {}", err);
            };
        }
        println!("{:?}", now.elapsed());
    } else {
        for _ in 0..2500 {
            if let Err(err) = client.receive_message().await {
                tracing::error!("failed to receive message: {}", err);
            };
        }
    }

    Ok(())
}
