// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! In this module we define TLS-related items, such as an optional
//! way to skip server verification.

use rcgen::{CertificateParams, Ia5String, IsCa, KeyPair, SanType};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    RootCertStore,
};

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
pub fn generate_cert_from_ca(
    ca_cert: &str,
    ca_key: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    // Parse the provided CA certificate
    let mut certificate_params = bail!(
        CertificateParams::from_ca_cert_pem(ca_cert),
        Crypto,
        "failed to parse provided CA cert"
    );

    // Create an `espresso` SAN for the certificate
    let espresso_san = SanType::DnsName(bail!(
        Ia5String::try_from("espresso"),
        Parse,
        "failed to parse \"espresso\" as `Ia5String`"
    ));

    // Set the SAN
    certificate_params.subject_alt_names = vec![espresso_san];

    // Explicitly set the certificate as not being a CA
    certificate_params.is_ca = IsCa::ExplicitNoCa;

    // Parse the provided CA key
    let key_pair = bail!(
        KeyPair::from_pem(ca_key),
        Crypto,
        "failed to parse provided CA key"
    );

    // Generate a self-signed certificate
    let certificate = bail!(
        certificate_params.self_signed(&key_pair),
        Crypto,
        "failed to generate self-signed certificate"
    );

    // Convert the certificate and key to DER format and return
    let key_pair = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    Ok((certificate.der().to_owned(), key_pair.into()))
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

/// Generate a root certificate store based on whether or not we want to use the
/// local authority.
///
/// # Errors
/// - If we fail to parse the provided CA certificate
/// - If we fail to add the certificate to the root store
pub fn generate_root_certificate_store(use_local_authority: bool) -> Result<RootCertStore> {
    // Pick which authority to trust based on whether or not we have requested
    // to use the local one
    let root_ca = if use_local_authority {
        LOCAL_CA_CERT
    } else {
        PROD_CA_CERT
    };

    // Parse the provided CA in `.PEM` format
    let root_ca = bail!(pem::parse(root_ca), Parse, "failed to parse PEM file").into_contents();

    // Create root certificate store and add our CA
    let mut root_cert_store = RootCertStore::empty();
    bail!(
        root_cert_store.add(CertificateDer::from(root_ca)),
        File,
        "failed to add certificate to root store"
    );

    Ok(root_cert_store)
}
