//! In this module we define TLS-related items, such as an optional
//! way to skip server verification.

use rcgen::{generate_simple_self_signed, CertificateParams, KeyPair};
use rustls::{Certificate, PrivateKey};

use crate::{
    bail,
    error::{Error, Result},
};

/// The local CA certificate for testing purposes
pub static LOCAL_CA_CERT: &'static str = "
-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgIUN676Be3OYql08WXJqSCQT84a0GUwDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEBhMCVVMwIBcNMjQwMzIyMTkyNTM2WhgPMjEyNDAyMjcxOTI1
MzZaMA0xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAlIi84Slsv1kc61GAXlLcGNMzPbHbLVVhV/9dPVIAQ4nXBbLakxB8/5yZX0wg
oqibAY4MVfWlC3WBj63wcSIEtJmSn8pCsXvvf6X3LcKD+xuhicBiydw7hvYIlqnm
LwXaRBmV9v/XMlr65ghxCsUsQ4UzgatGAegwTPbzaErSC5FsUNh5oRIcI12QSsvH
QWSdb/yhVqxWgv0V5PbQt70Kjjp0PIYdqG0jnMOkC0vZbH0SWykWL8Qf63SuXMZa
4TRJLVSqZBjiwrSzrF1ZExgBe35TYLfExDvOU+VuqZCTGen1ZgS77OY3ZKo+wqNu
BvfbzlHzrqPIYi2SWDbBGK3A0wIDAQABo1MwUTAdBgNVHQ4EFgQUk3KEFFpbONNc
XrrgE6e8fW+5TL0wHwYDVR0jBBgwFoAUk3KEFFpbONNcXrrgE6e8fW+5TL0wDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAL+s11IqudjyeK1vzYJMZ
sb3EVZ48Vi1KFnx7I2oB5R6Xqy4wg2qbc+lZ22XLV2WUgukfUeMN9VORdDbe2rz4
N9MmjMQcZ7iEP7/REsLLl5ku5m/6wXrli8XD3LnDyWImsjxqnGiuW4k2GekOjtax
atk/ZUFzqiwjqjgrYg22szjY877p4rhBWP+1+sEXxRsusWCCpuLpr71xkb/Y+aM9
rbufU03weYYDxVGEkgiYUGzIGHqQg9VLSrSLTZAegjfWFjSeWFfco2+lo+hfwoHE
eRRd8p99H8sOMJk5VIYed7ak+PXRYiBf92ofgxfuGlUgnaddmd4o1+0y5W+Y4JOF
bA==
-----END CERTIFICATE-----
";

/// The local CA key for testing purposes
pub static LOCAL_CA_KEY: &'static str = "
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCUiLzhKWy/WRzr
UYBeUtwY0zM9sdstVWFX/109UgBDidcFstqTEHz/nJlfTCCiqJsBjgxV9aULdYGP
rfBxIgS0mZKfykKxe+9/pfctwoP7G6GJwGLJ3DuG9giWqeYvBdpEGZX2/9cyWvrm
CHEKxSxDhTOBq0YB6DBM9vNoStILkWxQ2HmhEhwjXZBKy8dBZJ1v/KFWrFaC/RXk
9tC3vQqOOnQ8hh2obSOcw6QLS9lsfRJbKRYvxB/rdK5cxlrhNEktVKpkGOLCtLOs
XVkTGAF7flNgt8TEO85T5W6pkJMZ6fVmBLvs5jdkqj7Co24G99vOUfOuo8hiLZJY
NsEYrcDTAgMBAAECggEAJ7W60XOSuEFpwtvCNvVuFFD6hQb0stT9tln2Inu2yFek
nchoOSMSWAAU3O5sVzA+aJcCY0TOABdFMRVuj8Bpg6L/GSso02xv5i+HursjL9H+
SOafQppXa8iBGU6I1I96//PbLPLPJI5AP5mIJzn5kH+e+o7Ao6fgqeLnxj0ilKa+
82SVx3VeZ9Vsek3LtuAGj9Y+6cLwoIhxHFjmb57Sa2+ngajA3gXGSs5aZbjVby47
/Wb8A4bjM24bPNTJGX/4a6nGBYWqNuTrk0T5kVS5SW2CIWIz/fFZTlQMLqXoWu2j
Q/y6CHFjAJ64/jhd3gTATy7Ppz7TaSGDmFwrvsr74QKBgQDLdkRdH0c9R21FlXX4
yEB+3wt45e5mwKfoaBcnfcP78QmpVv7CH2YZKbtNch9dPrfzoSDxeCS77VDkdV/f
D3pYcVJm/NSB4dvu2gEpuyQny5mycgVHwO/2ap/hTj/5ptn/4WRXPEANXDzxFeaX
eIKfBcTVDlOIODHobd6L8K+k8QKBgQC643+B3PaS+yZ6yFrRXvn9SMQsmrx4Q1ye
sns+FzlcE/Zv2cNXwRhk5dYwsjpzcPEYxUwbnypJf49UrjKhTpdbcbV455m180Ez
oQowru2DxZ9ocp2Lk/SGMkcjJ0xY+S1ah5e6isGrlsHRvqj+uzAbmkp7KDfmKR9C
ngFbq+PyAwKBgB45ACixB70DiijG7dI5tNLjwOmBhis/PPHZ3G6iUOVwxZWg9ZDS
ZzEfsNHtPNl2Ao8vBRy5UwOTWevFv6r7upm+o5Xmwo5UhX3yZi/Tu6gppzgJld01
vK9m4T7vh7NG5KUMzwHiUkVpySeqsCkZ3pVOnxFi4meeqVM0VtWEuCKRAoGBAKxZ
16JUu9Tq5x6+nPqPY26RZ9FW1k72mHkGUp/9XPmss02NfxfzzOJoD7MS+tKxqrbU
ZQ7oJ2Bm0jEfATQ/vVgosloRBHGHJ29MqZAiEoq+evchFGe/h/cmcPJbcI5xJcFi
YKw5AMiUnKQo98MLsB8UmHGhsoOBEwIlo0z+ZZYvAoGAXMmdQYdO/hvS8HWvc0I9
uXJDyO47R60qpaCXVx0as9oYzA958gzPRbD/PuUkWVZbpF1hlauq+WVgaDVQ3qYl
nymFiogQaM7Bbp8NpMpI+7xmccefBfu5lhiTQdyETvIWsds0RUekK5aQzfFqtMoW
VI3tO/7cIXpdObDJsn6pZ7A=
-----END PRIVATE KEY-----
";

/// The production CA cert
pub static PROD_CA_CERT: &'static str = "
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
    let ca_cert_params =
        CertificateParams::from_ca_cert_pem(&ca_cert, KeyPair::from_pem(ca_key).expect("from"))
            .expect("parammies");

    // Convert the parameters to their cert representation
    let ca_cert = rcgen::Certificate::from_params(ca_cert_params).expect("meow");

    // Create a new self-signed certificate
    let new_cert = generate_simple_self_signed(vec!["espresso".to_string()]).expect("no");

    // Sign the certificate chain with the CA pair and return the certificate
    let certificate = new_cert.serialize_der_with_signer(&ca_cert).expect("meow");

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
