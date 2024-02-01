//! In this module we define cryptography primitives we may need, as
//! well as any serialization/deserialization functions on those primitives.

use crate::{
    bail,
    error::{Error, Result},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::result::Result as StdResult;
use jf_primitives::signatures::SignatureScheme;
use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use rcgen::generate_simple_self_signed;
use rustls::ClientConfig;
use std::sync::Arc;

/// The oxymoron function. Used mostly with crypto key generation to generate
/// "random" values that are actually deterministic based on the input.
pub struct DeterministicRng(pub u64);

impl CryptoRng for DeterministicRng {}

/// This implementation is to satisfy the `RngCore` trait and allow us to use it
/// to generate "random" values.
#[allow(clippy::cast_possible_truncation)]
impl RngCore for DeterministicRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for item in dest {
            *item = self.0 as u8;
            self.0 >>= 8_i32;
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.0 as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> StdResult<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// A wrapper function for serializing anything that implements `CanonicalSerialize`
/// We need this to be generic over the key type.
///
/// # Errors
/// Will error if the transitive serialization fails.
pub fn serialize<K>(obj: &K) -> Result<Vec<u8>>
where
    K: CanonicalSerialize,
{
    // Create a new buffer and serialize the object to it
    let mut bytes = Vec::new();
    bail!(
        obj.serialize_uncompressed(&mut bytes),
        Crypto,
        "failed to serialize key"
    );

    // Return the serialized bytes
    Ok(bytes)
}

/// A wrapper function for deserializing anything that implements `CanonicalDeserialize`
/// We need this to be generic over the key type.
///
/// # Errors
/// Will error if the transitive deserialization fails.
pub fn deserialize<K>(bytes: &[u8]) -> Result<K>
where
    K: CanonicalDeserialize,
{
    // Deserialize the object
    Ok(bail!(
        K::deserialize_uncompressed(bytes),
        Crypto,
        "failed to deserialize key"
    ))
}

/// A generic function to create a random key with any signature scheme. Can be used for generation
/// or testing.
///
/// # Errors
/// Errors only if the transitive key generation fails.
pub fn generate_random_keypair<Scheme: SignatureScheme<PublicParameter = ()>>(
) -> Result<(Scheme::SigningKey, Scheme::VerificationKey)> {
    // Generate a new `prng` from system entropy
    let mut prng = StdRng::from_entropy();

    // Generate a key and return it
    Ok(bail!(
        Scheme::key_gen(&(), &mut prng),
        Crypto,
        "failed to generate keypair"
    ))
}

/// This lets us, while using `rustls` skip server verification
/// for when we test locally. This way we don't require a self-signed
/// certificate.
pub struct SkipServerVerification;

/// Here we implement some helper functions that let us create
/// a client configuration from the verification configuration.
impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    pub fn new_config() -> Arc<ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                .with_no_client_auth(),
        )
    }
}

/// This is the implementation for `ServerCertVerifier` that `rustls` requires us
/// to implement for server cert verification purposes.
impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> StdResult<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// Loads or self-signs a certificate and corresponding key based on the
/// arguments based in. If a path is missing for either the cert or the key,
/// we assume local operation. In this case, we will self-sign a certificate.
/// 
/// TODO: just take local_testing flag and decide whether to self-sign based
/// on that.
pub fn load_or_self_sign_tls_certificate_and_key(
    possible_tls_certificate_path: Option<&'static str>,
    possible_tls_key_path: Option<&'static str>,
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    let (certificate_bytes, key_bytes) = if let (Some(certificate_path), Some(key_path)) =
        (possible_tls_certificate_path, possible_tls_key_path)
    {
        // If we have both paths, we want to load them in
        // Read cert file in to bytes
        let encoded_certificate_bytes = bail!(
            std::fs::read(certificate_path),
            File,
            format!("failed to read certificate file {certificate_path}")
        );

        // Parse cert file as a `.PEM`
        let certificate_bytes = bail!(
            pem::parse(encoded_certificate_bytes),
            Parse,
            "failed to parse PEM file"
        )
        .into_contents();

        // Read key file in to bytes
        let encoded_key_bytes = bail!(
            std::fs::read(key_path),
            File,
            format!("failed to read key file {key_path}")
        );

        // Parse key file as a `.PEM`
        let key_bytes = bail!(
            pem::parse(encoded_key_bytes),
            Parse,
            "failed to parse PEM file"
        )
        .into_contents();

        // Return the (serialized) certificate and key bytes
        (certificate_bytes, key_bytes)
    }
    // We don't have one path or the other, so self-sign a certificate instead
    else {
        // Generate a cert with the local bind address, if possible
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();

        // Serialize certificate to DER format
        let certificate_bytes = cert.serialize_der().unwrap();

        // Serialize the key to DER format
        let key_bytes = cert.serialize_private_key_der();

        // Return the (serialized) certificate and key bytes
        (certificate_bytes, key_bytes)
    };

    // Convert to `rustls` types and retrun
    Ok((
        vec![rustls::Certificate(certificate_bytes)],
        rustls::PrivateKey(key_bytes),
    ))
}
