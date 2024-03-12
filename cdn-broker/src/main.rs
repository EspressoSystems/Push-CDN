//! The following is the main `Broker` binary, which just instantiates and runs
//! a `Broker` object.

use cdn_broker::{Broker, Config, ConfigBuilder};
use cdn_proto::{
    bail,
    connection::protocols::{quic::Quic, tcp::Tcp},
    crypto::{rng::DeterministicRng, signature::KeyPair},
    error::{Error, Result},
};
use clap::Parser;
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use local_ip_address::local_ip;

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
    let private_address = format!("{}:{}", private_ip_address, args.private_bind_port);

    // Create deterministic keys for brokers (for now, obviously)
    let (private_key, public_key) = BLS::key_gen(&(), &mut DeterministicRng(0)).unwrap();

    let broker_config: Config<BLS> = bail!(
        ConfigBuilder::default()
            .public_advertise_address(args.public_advertise_address)
            .public_bind_address(format!("0.0.0.0:{}", args.public_bind_port))
            .private_advertise_address(private_address.clone())
            .private_bind_address(private_address)
            .discovery_endpoint(args.discovery_endpoint)
            .metrics_port(args.metrics_port)
            .keypair(KeyPair {
                public_key,
                private_key
            })
            .build(),
        Parse,
        "failed to build broker configuration"
    );

    // Create new `Broker`
    // Uses TCP from broker connections and Quic for user connections.
    let broker = Broker::<BLS, BLS, Tcp, Quic>::new(broker_config).await?;

    // Start the main loop, consuming it
    broker.start().await?;

    Ok(())
}
