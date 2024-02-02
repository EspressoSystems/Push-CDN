use std::marker::PhantomData;

use client::{Client, Config};
use proto::{
    connection::{flow::UserToMarshal, protocols::quic::Quic},
    crypto,
    error::Result,
};

use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;

#[tokio::main]
async fn main() -> Result<()> {
    let (signing_key, verification_key) = crypto::generate_random_keypair::<BLS>()?;

    let connection_flow = UserToMarshal {
        verification_key,
        signing_key,
        endpoint: "google.com:80".to_string(),
    };

    let client = Client::<BLS, Quic, _>::new(Config {
        flow: connection_flow,
        pd: PhantomData,
    })
    .await?;

    client
        .send_direct_message(verification_key, vec![123])
        .await?;

    println!("{:?}", client.receive_message().await);

    Ok(())
}
