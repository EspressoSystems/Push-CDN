//! In this module we define TLS-related items, such as an optional
//! way to skip server verification.

use rcgen::{generate_simple_self_signed, CertificateParams, KeyPair};
use rustls::{Certificate, PrivateKey};

use crate::{
    bail,
    error::{Error, Result},
};

// Include the build-generated testing certificates
include!(concat!(env!("OUT_DIR"), "/testing_certs.rs"));

/// The production CA cert
pub static PROD_CA_CERT: &str = "
-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgIUWZANCdQpMOjl2frhwHg8GCaZMAUwDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEBhMCVVMwIBcNMjQwMzIyMTkzNTI5WhgPMjEyNDAyMjcxOTM1
MjlaMA0xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEArFyiDfyhtSdt7tuveavvmr4aXeD37Joum4uc28ryj4qM/8zGh/Uxy71/GdfU
+Ki9IMCJK8C9B6aPprymT7g2oRMkdU21ir0bLaPPMUCRFm3h8xOdULM1VksBM+MS
IYBze3hn9/kOoK8+LrRcH47bc9MDx9JBL+1cTXRv2ndt6qQDgIO0zROUVV0noq6F
qq7Sag5pd34wUBbq4gJs9OYRDxNIgT6Qe2Xb9Q8suRY6RuULjr3trljJfKm6MOe4
cXPsCSBvl1ubpSnA3rgE404Y+duTFpudKyEiZZE2+/dlIf+IzVh++s3NMaUUpCYJ
mzBm5cm8JNl0xEwAmMl383sxuwIDAQABo1MwUTAdBgNVHQ4EFgQUL9vfstSqQxBN
q7J7yRcs3ApygvAwHwYDVR0jBBgwFoAUL9vfstSqQxBNq7J7yRcs3ApygvAwDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAPsRd9D2fMsKmGaJXbApJ
zz6KMlf1XjlAhQrr9N7wK7Wjc3AeFsnDBQP/qVGKsqUvDuC8ruCh/WLTlY/d+hh9
bNNgSWRFZD5X9gTHaVia6g7ldxmd1B9QYPjLrM6aiunXw0kU0Cc3oxGgptSOBAnH
o1xfSrRj1WmdI3wzBiian5ACo9KyWYSJDbvYAXDvOZ2tgCI1IhTM2QAPSvbXMLK9
e0qvjG2nl1jsvO3KK/05GShKxr3+t181UZm/aknLxl7/PEjxWORwXnx2CltCHDdA
TQiNtXFK7FS1Z87vvLCCm6aibxUBhEPE467kZSlaTpjthJ/roMVZHgZrh60jAMh8
hQ==
-----END CERTIFICATE-----
";

/// Generate and sign a certificate with the provided CA certificate
/// and key.
///
/// # Errors
/// - If we fail to parse the local certificate
pub fn generate_cert_from_ca(ca_cert: &str, ca_key: &str) -> Result<(Certificate, PrivateKey)> {
    // Load in the CA cert from the provided cert and key
    let ca_cert_params = bail!(
        CertificateParams::from_ca_cert_pem(
            ca_cert,
            bail!(
                KeyPair::from_pem(ca_key),
                File,
                "failed to load key from PEM"
            )
        ),
        File,
        "failed to create certificate from supplied CA"
    );

    // Convert the parameters to their cert representation
    let ca_cert = bail!(
        rcgen::Certificate::from_params(ca_cert_params),
        Crypto,
        "failed to generate certificate from parameters"
    );

    // Create a new self-signed certificate
    let new_cert = bail!(
        generate_simple_self_signed(vec!["espresso".to_string()]),
        Crypto,
        "failed to generate self-signed certificate"
    );

    // Sign the certificate chain with the CA pair and return the certificate
    let certificate = bail!(
        new_cert.serialize_der_with_signer(&ca_cert),
        Crypto,
        "failed to sign self-signed certificate"
    );

    // Extrapolate the certificate's key in binary format
    let key = new_cert.serialize_private_key_der();

    // Return both the new cert and the new key
    Ok((Certificate(certificate), PrivateKey(key)))
}

/// Conditionally load the CA key and cert from the filesystem. Returns the local
/// CA if both the cert and key are not specified.
///
/// # Errors
/// - If we could not read either file
pub fn load_ca(
    ca_cert_path: Option<String>,
    ca_key_path: Option<String>,
) -> Result<(String, String)> {
    if let (Some(ca_cert_path), Some(ca_key_path)) = (ca_cert_path, ca_key_path) {
        // If we have supplied both, load them in

        // Load in the CA cert from the file
        let ca_cert = bail!(
            std::fs::read_to_string(ca_cert_path),
            File,
            "failed to read cert file"
        );

        // Load in the CA key from the file
        let ca_key = bail!(
            std::fs::read_to_string(ca_key_path),
            File,
            "failed to read key file"
        );

        Ok((ca_cert, ca_key))
    } else {
        // If not, use the local one
        Ok((LOCAL_CA_CERT.to_string(), LOCAL_CA_KEY.to_string()))
    }
}
