use std::{collections::HashSet, marker::PhantomData};

use client::{Client, Config};
use proto::{
    connection::{auth::UserAuthData, protocols::quic::Quic},
    crypto,
    error::Result,
    message::Topic,
};

use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<()> {
    let (signing_key, verification_key) = crypto::generate_random_keypair::<BLS>()?;

    let auth_data = UserAuthData {
        verification_key,
        signing_key,
        subscribed_topics: Mutex::from(HashSet::from_iter([Topic::DA, Topic::Global])),
    };

    let client = Client::<BLS, Quic>::new(Config {
        endpoint: "127.0.0.1:8080".to_string(),
        auth_data,
        pd: PhantomData,
    })
    .await?;

    client
        .send_direct_message(verification_key, vec![123])
        .await?;

    // println!("{:?}", client.receive_message().await);

    Ok(())
}
