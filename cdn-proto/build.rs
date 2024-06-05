use std::{env, fs, path::Path};

use rcgen::{CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;

pub static KEYPAIR: [u8; 138] = [
    48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3,
    1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 189, 107, 193, 211, 25, 222, 92, 186, 228, 174, 92, 9,
    80, 243, 67, 83, 170, 46, 39, 112, 242, 110, 109, 25, 183, 26, 250, 229, 154, 43, 53, 71, 161,
    68, 3, 66, 0, 4, 145, 35, 243, 152, 127, 62, 24, 32, 139, 61, 24, 90, 203, 2, 130, 209, 207,
    227, 83, 246, 46, 145, 214, 34, 167, 151, 109, 230, 165, 206, 4, 33, 1, 151, 129, 52, 181, 66,
    117, 112, 126, 197, 74, 238, 65, 51, 83, 106, 245, 177, 241, 133, 123, 101, 251, 159, 22, 33,
    138, 138, 139, 13, 114, 48,
];

fn main() {
    // Get out directory
    let out_dir = env::var_os("OUT_DIR").unwrap();

    // Convert `KEYPAIR` to a `PrivatePkcs8KeyDer` and then to a `KeyPair`
    let key_pair = PrivatePkcs8KeyDer::from(KEYPAIR.to_vec());
    let key_pair = KeyPair::from_der_and_sign_algo(&key_pair.into(), &PKCS_ECDSA_P256_SHA256)
        .expect("failed to parse pinned keypair");

    // Create CA certificate generation parameters
    let mut ca_cert_params = CertificateParams::default();
    ca_cert_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    // Generate the CA certificate
    let ca_cert = ca_cert_params
        .self_signed(&key_pair)
        .expect("failed to generate testing CA certificate");

    // The path for the testing certificates
    let dest_path = Path::new(&out_dir).join("testing_certs.rs");

    // Write the testing certificate information to the file
    fs::write(
        dest_path,
        format!(
            "
            pub static LOCAL_CA_CERT: &str = \"{}\";
            pub static LOCAL_CA_KEY: &str = \"{}\";
            ",
            ca_cert.pem(),
            key_pair.serialize_pem()
        ),
    )
    .expect("failed to write to build directory");

    // Only re-run if this build script changes
    println!("cargo:rerun-if-changed=build.rs");
}
