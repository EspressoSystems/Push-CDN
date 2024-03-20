//! In this module we define TLS-related items, such as an optional
//! way to skip server verification.

#[cfg(feature = "insecure")]
use std::sync::Arc;

use rcgen::generate_simple_self_signed;
// TODO: have `SkipServerVerify` as a separate module
#[cfg(feature = "insecure")]
use rustls::ClientConfig;

use crate::{
    bail,
    error::{Error, Result},
};

/// This lets us, while using `rustls` skip server verification
/// for when we test locally. This way we don't require a self-signed
/// certificate.
#[cfg(feature = "insecure")]
pub struct SkipServerVerification;

/// Here we implement some helper functions that let us create
/// a client configuration from the verification configuration.
#[cfg(feature = "insecure")]
impl SkipServerVerification {
    pub fn new_config() -> Arc<ClientConfig> {
        Arc::from(
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::from(Self {}))
                .with_no_client_auth(),
        )
    }
}

/// This is the implementation for `ServerCertVerifier` that `rustls` requires us
/// to implement for server cert verification purposes.
#[cfg(feature = "insecure")]
impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> core::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// Loads or self-signs a certificate and corresponding key based on the
/// arguments based in. If a path is missing for either the cert or the key,
/// we assume local operation. In this case, we will self-sign a certificate.
///
/// TODO: just take `local_testing` flag and decide whether to self-sign based
/// on that.
///
/// # Errors
/// - If we fail to read the certificate file
/// - If we fail to parse the `.PEM` file
/// - If we fail to read the key file
/// - If we fail to parse the key file
pub fn load_or_self_sign_tls_certificate_and_key(
    possible_tls_certificate_path: Option<String>,
    possible_tls_key_path: Option<String>,
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    let (certificate_bytes, key_bytes) = if let (Some(certificate_path), Some(key_path)) =
        (possible_tls_certificate_path, possible_tls_key_path)
    {
        // If we have both paths, we want to load them in
        // Read cert file in to bytes
        let encoded_certificate_bytes = bail!(
            std::fs::read(certificate_path.clone()),
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
            std::fs::read(key_path.clone()),
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
        let cert = bail!(
            generate_simple_self_signed(vec!["localhost".into()]),
            Crypto,
            "failed to self-sign cert"
        );

        // Serialize certificate to DER format
        let certificate_bytes = bail!(
            cert.serialize_der(),
            Crypto,
            "failed to serialize self-signed certificate"
        );

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
