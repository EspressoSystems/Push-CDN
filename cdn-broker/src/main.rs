//! The following is the main `Broker` binary, which just instantiates and runs
//! a `Broker` object.
use cdn_broker::{Broker, Config, ConfigBuilder};
use cdn_proto::{
    bail,
    crypto::signature::KeyPair,
    def::ProductionDef,
    error::{Error, Result},
};
use clap::Parser;
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme,
};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// The main component of the push CDN.
struct Args {
    /// The discovery client endpoint (including scheme) to connect to.
    /// With the local discovery feature, this is a file path.
    /// With the remote (redis) discovery feature, this is a redis URL (e.g. `redis://127.0.0.1:6789`).
    #[arg(short, long)]
    discovery_endpoint: String,

    /// Whether or not metric collection and serving is enabled
    #[arg(long, default_value_t = false)]
    metrics_enabled: bool,

    /// The IP to bind to for externalizing metrics
    #[arg(long, default_value = "127.0.0.1")]
    metrics_ip: String,

    /// The port to bind to for externalizing metrics
    #[arg(long, default_value_t = 9090)]
    metrics_port: u16,

    /// The user-facing address to bind to for connections from users
    #[arg(long, default_value = "0.0.0.0:1738")]
    public_bind_address: String,

    /// The user-facing address to advertise
    #[arg(long, default_value = "127.0.0.1:1738")]
    public_advertise_address: String,

    /// The broker-facing address to bind to for connections from  
    /// other brokers
    #[arg(long, default_value = "0.0.0.0:1739")]
    private_bind_address: String,

    /// The broker-facing address to advertise
    #[arg(long, default_value = "127.0.0.1:1739")]
    private_advertise_address: String,

    /// The seed for broker key generation
    #[arg(long, default_value_t = 0)]
    key_seed: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Generate the broker key from the supplied seed
    let (private_key, public_key) =
        BLS::key_gen(&(), &mut StdRng::seed_from_u64(args.key_seed)).unwrap();

    let broker_config: Config<BLS> = bail!(
        ConfigBuilder::default()
            .public_advertise_address(args.public_advertise_address)
            .public_bind_address(args.public_bind_address)
            .private_advertise_address(args.private_advertise_address)
            .private_bind_address(args.private_bind_address)
            .metrics_enabled(args.metrics_enabled)
            .metrics_ip(args.metrics_ip)
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
    let broker = Broker::<ProductionDef>::new(broker_config).await?;

    // Start the main loop, consuming it
    broker.start().await?;

    Ok(())
}
