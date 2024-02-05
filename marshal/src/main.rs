//! The following is the main `Marshal` binary, which just instantiates and runs
//! a `Marshal` object.

use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use marshal::Marshal;
use proto::{connection::protocols::quic::Quic, error::Result};

//TODO: for both client and marshal, clean up and comment `main.rs`
// TODO: forall, add logging where we need it

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create new `Marshal`
    let marshal = Marshal::<BLS, Quic>::new(
        "0.0.0.0:8082".to_string(),
        "redis://:changeme!@127.0.0.1:6379".to_string(),
        None,
        None,
    )
    .await?;

    // Start the main loop, consuming it
    marshal.start().await?;

    Ok(())
}
