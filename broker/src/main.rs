//! The following is the main `Broker` binary, which just instantiates and runs
//! a `Broker` object.

use broker::{Broker, Config};
use clap::Parser;
use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use proto::{
    connection::protocols::{quic::Quic, tcp::Tcp},
    crypto::{generate_random_keypair, DeterministicRng},
    error::Result,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// The main component of the push CDN.
struct Args {
    /// The redis endpoint (including password and scheme) to connect to
    #[arg(short, long, default_value = "redis://:changeme!@127.0.0.1:6379")]
    redis_endpoint: String,

    /// The port to bind to for connections from users
    #[arg(short, long, default_value_t = 1738)]
    user_bind_port: u16,

    /// The port to bind to for connections from other brokers
    #[arg(short, long, default_value_t = 1739)]
    broker_bind_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // TODO: local IP address depending on whether or not we specified

    // Create deterministic keys for brokers (for now, obviously)
    let (signing_key, verification_key) = generate_random_keypair::<BLS, _>(DeterministicRng(0))?;

    // Create our config (TODO stubbed out for now, do clap)
    let broker_config = Config {
        // These are the same because we are testing locally
        // TODO: if possible make this better. Make it so that we can just specify
        // a port or something.
        user_advertise_address: format!("127.0.0.1:{}", args.user_bind_port),
        user_bind_address: format!("127.0.0.1:{}", args.user_bind_port),

        broker_advertise_address: format!("127.0.0.1:{}", args.broker_bind_port),
        broker_bind_address: format!("127.0.0.1:{}", args.broker_bind_port),

        redis_endpoint: args.redis_endpoint,

        signing_key,
        verification_key,

        // TODO: clap this
        maybe_tls_cert_path: None,
        maybe_tls_key_path: None,
    };

    // Create new `Broker`
    let marshal = Broker::<BLS, Tcp, BLS, Quic>::new(broker_config).await?;

    // Start the main loop, consuming it
    marshal.start().await?;

    Ok(())
}
