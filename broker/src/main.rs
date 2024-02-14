//! The following is the main `Broker` binary, which just instantiates and runs
//! a `Broker` object.

use broker::{Broker, Config};
use clap::Parser;
use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use local_ip_address::local_ip;
use proto::{
    bail,
    crypto::{generate_random_keypair, DeterministicRng},
    error::{Error, Result},
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// The main component of the push CDN.
struct Args {
    /// The discovery client endpoint (including scheme) to connect to
    #[arg(short, long)]
    discovery_endpoint: String,

    /// Whether or not metric collection and serving is enabled
    #[arg(long, default_value_t = true)]
    metrics_enabled: bool,

    /// The port to bind to for externalizing metrics
    #[arg(long, default_value = "127.0.0.1")]
    metrics_ip: String,

    /// The port to bind to for externalizing metrics
    #[arg(long, default_value_t = 9090)]
    metrics_port: u16,

    /// The port to bind to for connections from users
    #[arg(long, default_value = "127.0.0.1:1738")]
    public_advertise_address: String,

    /// The (public) port to bind to for connections from users
    #[arg(long, default_value_t = 1738)]
    public_bind_port: u16,

    /// The (private) port to bind to for connections from other brokers
    #[arg(long, default_value_t = 1739)]
    private_bind_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Get our local IP address
    let private_ip_address = bail!(local_ip(), Connection, "failed to get local IP address");

    // Create deterministic keys for brokers (for now, obviously)
    let (signing_key, verification_key) = generate_random_keypair::<BLS, _>(DeterministicRng(0))?;

    let broker_config = Config {
        // Public addresses: explicitly defined advertise address, bind address is on every interface
        // but with the specified port.
        public_advertise_address: args.public_advertise_address,
        public_bind_address: format!("0.0.0.0:{}", args.public_bind_port),

        metrics_enabled: args.metrics_enabled,
        metrics_port: args.metrics_port,
        metrics_ip: args.metrics_ip,

        // Private addresses: bind to the local interface with the specified port
        private_advertise_address: format!("{}:{}", private_ip_address, args.private_bind_port),
        private_bind_address: format!("{}:{}", private_ip_address, args.private_bind_port),

        discovery_endpoint: args.discovery_endpoint,

        keypair: proto::crypto::KeyPair {
            verification_key,
            signing_key,
        },

        // TODO: clap this
        maybe_tls_cert_path: None,
        maybe_tls_key_path: None,
    };

    // Create new `Broker`
    // Uses TCP from broker connections and Quic for user connections.
    let broker = Broker::<BLS, BLS>::new(broker_config).await?;

    // Start the main loop, consuming it
    broker.start().await?;

    Ok(())
}
