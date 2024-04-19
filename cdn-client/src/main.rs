//! The following is an example of a Push CDN client implementation.
//! In this example, we send messages to ourselves via broadcast and direct
//! systems.

use std::time::Duration;

use cdn_client::{Client, Config};
use cdn_proto::{
    crypto::signature::{KeyPair, Serializable},
    def::ProductionClientConnection,
    message::{Broadcast, Direct, Message, Topic},
};
use clap::Parser;
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use rand::{rngs::StdRng, SeedableRng};
use tokio::time::sleep;
use tracing::info;

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
        tracing_subscriber::fmt().json().init();
    } else {
        tracing_subscriber::fmt().init();
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
        subscribed_topics: vec![Topic::Global],
        use_local_authority: true,
    };

    // Create a client, specifying the BLS signature algorithm
    // and the `QUIC` protocol.
    let client = Client::<ProductionClientConnection>::new(config);

    // In a loop,
    loop {
        // Send a direct message to ourselves
        client
            .send_direct_message(&public_key, b"hello direct".to_vec())
            .await
            .expect("failed to send message");
        info!("direct messaged \"hello direct\" to ourselves");

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
        info!("received \"hello direct\" from ourselves");

        // Send a broadcast message to the global topic
        client
            .send_broadcast_message(vec![Topic::Global], b"hello broadcast".to_vec())
            .await
            .expect("failed to send message");
        info!("broadcasted \"hello broadcast\" to ourselves");

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
        info!("received \"hello broadcast\" from ourselves");

        // Sleep for 5 second
        info!("sleeping");
        sleep(Duration::from_secs(5)).await;
    }
}
