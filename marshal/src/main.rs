use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use marshal::Marshal;
use proto::{
    connection::{auth::UserToMarshal, protocols::quic::Quic},
    error::Result,
};

//TODO: for both client and marshal, clean up and comment `main.rs`
// TODO: forall, add logging where we need it

#[tokio::main]
async fn main() -> Result<()> {
    // Create new `Marshal`
    let marshal = Marshal::<BLS, Quic, UserToMarshal>::new(
        "0.0.0.0:8080".to_string(),
        "redis://:changeme!@127.0.0.1:6379".to_string(),
        None,
        None,
    )
    .await?;

    marshal.start().await?;

    Ok(())
}
