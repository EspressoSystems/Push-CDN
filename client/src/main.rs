use std::marker::PhantomData;

use client::{Client, Config};
use proto::{
    connection::{fallible::quic::Quic, flow::ToMarshal},
    crypto,
    error::Result,
    message::Topic,
};

use jf_primitives::signatures::bls_over_bn254::{BLSOverBN254CurveSignatureScheme as BLS, VerKey};

#[tokio::main]
async fn main() -> Result<()> {
    let (signing_key, verification_key) = crypto::generate_random_keypair::<BLS>()?;

    let client = Client::<BLS, Quic, ToMarshal>::new(Config {
        verification_key,
        signing_key,
        remote_address: "google.com:80".to_string(),
        initial_subscribed_topics: vec![Topic::Global],
        _pd: PhantomData,
    })
    .await?;

    Ok(())
}
