//! "Bad sender" is a simple example of a client that continuously sends a message to itself.
//! This is useful for testing the broker's ability to handle many messages.

use cdn_client::{Client, Config};
use cdn_proto::{
    crypto::signature::KeyPair,
    def::{ProductionClientConnection, TestTopic},
};
use clap::Parser;
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use rand::{rngs::StdRng, SeedableRng};
use tracing::info;
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

    // Generate a random keypair
    let (private_key, public_key) =
        BLS::key_gen(&(), &mut StdRng::from_entropy()).expect("failed to generate key");

    // Build the config, the endpoint being where we expect the marshal to be
    let config = Config {
        endpoint: args.marshal_endpoint,
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
    let message = vec![0u8; 10000];

    // In a loop,
    loop {
        // Send a direct message to ourselves
        if let Err(e) = client
            .send_direct_message(&public_key, message.clone())
            .await
        {
            println!("failed to send direct message: {e:?}");
            continue;
        }
        info!("successfully sent direct message");

        if let Err(e) = client.receive_message().await {
            println!("err: {e:?}");
            continue;
        }
        info!("successfully received direct message");

        // Send a direct message to ourselves
        if let Err(e) = client
            .send_broadcast_message(vec![TestTopic::Global as u8], message.clone())
            .await
        {
            println!("failed to send broadcast message: {e:?}");
            continue;
        }
        info!("successfully sent broadcast message");

        if let Err(e) = client.receive_message().await {
            println!("failed to send broadcast message: {e:?}");
            continue;
        }
        info!("successfully received broadcast message");
    }
}
