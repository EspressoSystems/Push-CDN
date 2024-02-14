//! The following is the main `Marshal` binary, which just instantiates and runs
//! a `Marshal` object.

use clap::Parser;
use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use marshal::{ConfigBuilder, Marshal};
use proto::{
    bail,
    error::{Error, Result},
};

//TODO: for both client and marshal, clean up and comment `main.rs`
// TODO: forall, add logging where we need it

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// The main component of the push CDN.
struct Args {
    /// The discovery client endpoint (including scheme) to connect to
    #[arg(short, long)]
    discovery_endpoint: String,

    /// The port to bind to for connections (from users)
    #[arg(short, long, default_value_t = 8082)]
    bind_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create a new `Config`
    let config = bail!(
        ConfigBuilder::default()
            .bind_address(format!("0.0.0.0:{}", args.bind_port))
            .discovery_endpoint(args.discovery_endpoint)
            .build(),
        Parse,
        "failed to build Marshal config"
    );

    // Create new `Marshal` from the config
    let marshal = Marshal::<BLS>::new(config).await?;

    // Start the main loop, consuming it
    marshal.start().await?;

    Ok(())
}
