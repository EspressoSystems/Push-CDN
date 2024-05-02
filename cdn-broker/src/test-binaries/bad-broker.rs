//! `bad-broker` is a simple binary that starts a broker with a random key and
//! attempts to start a broker every 100ms. This is useful for testing the
//! broker's ability to handle multiple brokers connecting to it.
use std::time::Duration;

use cdn_broker::{Broker, Config};
use cdn_proto::{crypto::signature::KeyPair, def::ProductionRunDef, error::Result};
use clap::Parser;
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use rand::{rngs::StdRng, SeedableRng};
use tokio::{spawn, time::sleep};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// The main component of the push CDN.
struct Args {
    /// The discovery client endpoint (including scheme) to connect to.
    /// With the local discovery feature, this is a file path.
    /// With the remote (redis) discovery feature, this is a redis URL (e.g. `redis://127.0.0.1:6789`).
    #[arg(short, long)]
    discovery_endpoint: String,

    /// The endpoint to bind to for externalizing metrics (in `IP:port` form). If not provided,
    /// metrics are not exposed.
    #[arg(short, long)]
    metrics_bind_endpoint: Option<String>,

    /// The user-facing endpoint in `IP:port` form to bind to for connections from users
    #[arg(long, default_value = "0.0.0.0:1738")]
    public_bind_endpoint: String,

    /// The user-facing endpoint in `IP:port` form to advertise
    #[arg(long, default_value = "local_ip:1738")]
    public_advertise_endpoint: String,

    /// The broker-facing endpoint in `IP:port` form to bind to for connections from  
    /// other brokers
    #[arg(long, default_value = "0.0.0.0:1739")]
    private_bind_endpoint: String,

    /// The broker-facing endpoint in `IP:port` form to advertise
    #[arg(long, default_value = "local_ip:1739")]
    private_advertise_endpoint: String,

    /// The path to the CA certificate
    /// If not provided, a local, pinned CA is used
    #[arg(long)]
    ca_cert_path: Option<String>,

    /// The path to the CA key
    /// If not provided, a local, pinned CA is used
    #[arg(long)]
    ca_key_path: Option<String>,

    /// The seed for broker key generation
    #[arg(short, long, default_value_t = 0)]
    key_seed: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    #[cfg(not(tokio_unstable))]
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

    #[cfg(tokio_unstable)]
    console_subscriber::init();

    // Forever, generate a new broker key and start a broker
    loop {
        // Generate the broker key from the supplied seed
        let (private_key, public_key) = BLS::key_gen(&(), &mut StdRng::from_entropy()).unwrap();

        // Two random ports
        let public_port = portpicker::pick_unused_port().unwrap();
        let private_port = portpicker::pick_unused_port().unwrap();

        // Create config
        let broker_config: Config<ProductionRunDef> = Config {
            ca_cert_path: args.ca_cert_path.clone(),
            ca_key_path: args.ca_key_path.clone(),

            discovery_endpoint: args.discovery_endpoint.clone(),
            metrics_bind_endpoint: args.metrics_bind_endpoint.clone(),
            keypair: KeyPair {
                public_key,
                private_key,
            },

            public_bind_endpoint: format!("0.0.0.0:{public_port}"),
            public_advertise_endpoint: format!("local_ip:{public_port}"),
            private_bind_endpoint: format!("0.0.0.0:{private_port}"),
            private_advertise_endpoint: format!("local_ip:{private_port}"),
        };

        // Create new `Broker`
        // Uses TCP from broker connections and Quic for user connections.
        let broker = Broker::new(broker_config).await?;

        // Start the main loop, consuming it
        let jh = spawn(broker.start());

        sleep(Duration::from_millis(300)).await;
        jh.abort();
    }
}
