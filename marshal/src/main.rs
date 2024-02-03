use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use marshal::Marshal;
use proto::{
    connection::{auth::UserToMarshal, protocols::quic::Quic},
    error::Result,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Create new `Marshal`
    let marshal =
        Marshal::<BLS, Quic, UserToMarshal>::new("0.0.0.0:8080".to_string(), None, None).await?;

    marshal.start().await?;

    Ok(())
}
