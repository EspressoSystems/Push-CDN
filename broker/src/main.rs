//! The following is the main `Broker` binary, which just instantiates and runs
//! a `Broker` object.

use broker::{Broker, Config};
use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use proto::{
    connection::protocols::{quic::Quic, tcp::Tcp},
    crypto::{generate_random_keypair, DeterministicRng},
    error::Result,
};

// TODO for all of these: clap

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create deterministic keys for brokers (for now, obviously)
    let (signing_key, verification_key) = generate_random_keypair::<BLS, _>(DeterministicRng(0))?;

    // Create our config (TODO stubbed out for now, do clap)
    let broker_config = Config {
        // These are the same because we are testing locally
        // TODO: if possible make this better. Make it so that we can just specify
        // a port or something.
        user_advertise_address: "127.0.0.1:8080".to_string(),
        user_bind_address: "127.0.0.1:8080".to_string(),

        broker_advertise_address: "127.0.0.1:8081".to_string(),
        broker_bind_address: "127.0.0.1:8081".to_string(),

        redis_endpoint: "127.0.0.1:6789".to_string(),

        signing_key,
        verification_key,

        // TODO: clap this
        maybe_tls_cert_path: None,
        maybe_tls_key_path: None,
    };

    // Create new `Broker`
    let marshal = Broker::<BLS, Quic, Tcp>::new(broker_config).await?;

    // Start the main loop, consuming it
    marshal.start().await?;

    Ok(())
}
