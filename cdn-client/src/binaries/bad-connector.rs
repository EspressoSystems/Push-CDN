// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! "Bad connector" is a simple example of a client that connects to the broker every
//! 200ms. This is useful for testing the broker's ability to handle many connections.

use std::time::Duration;

use cdn_client::{Client, Config};
use cdn_proto::{
    crypto::signature::KeyPair,
    def::{ProductionClientConnection, TestTopic},
};
use clap::Parser;
use jf_signature::{bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme};
use rand::{rngs::StdRng, SeedableRng};
use tokio::time::sleep;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// An example user of the Push CDN
struct Args {
    /// The remote marshal endpoint to connect to, including the port.
    #[arg(short, long)]
    marshal_endpoint: String,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    if std::env::var("RUST_LOG_FORMAT") == Ok("json".to_string()) {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    }

    // In a loop,
    loop {
        // Generate a random keypair
        let (private_key, public_key) =
            BLS::key_gen(&(), &mut StdRng::from_entropy()).expect("failed to generate key");

        // Build the config, the endpoint being where we expect the marshal to be
        let config = Config {
            endpoint: args.marshal_endpoint.clone(),
            keypair: KeyPair {
                public_key,
                private_key,
            },
            subscribed_topics: vec![TestTopic::Global as u8],
            use_local_authority: true,
        };

        // Create a client, specifying the BLS signature algorithm
        // and the `QUIC` protocol.
        let client = Client::<ProductionClientConnection>::new(config);

        client.ensure_initialized().await;
        sleep(Duration::from_millis(200)).await;
    }
}
