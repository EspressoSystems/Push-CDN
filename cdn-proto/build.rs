use std::{env, fs, path::Path};

use rcgen::{Certificate, CertificateParams, IsCa};

fn main() {
    // Get out directory
    let out_dir = env::var_os("OUT_DIR").unwrap();

    // Create CA certificate generation parameters
    let mut ca_cert_params = CertificateParams::default();
    ca_cert_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    // Generate the CA certificate
    let ca_cert = Certificate::from_params(ca_cert_params)
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
            ca_cert.serialize_pem().expect("failed to serialize cert"),
            ca_cert.serialize_private_key_pem()
        ),
    )
    .expect("failed to write to ");

    // Only re-run if this build script changes
    println!("cargo::rerun-if-changed=build.rs");
}
