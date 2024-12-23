// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! In this module we define the interface for signing and authenticating
//! with a marshal.

use anyhow::Result;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jf_signature::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme as JfSignatureScheme,
};

use super::rng::DeterministicRng;

/// The auth namespaces for the signature scheme
pub enum Namespace {
    UserMarshalAuth,
    BrokerBrokerAuth,
}

impl Namespace {
    /// Get the namespace as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            Namespace::UserMarshalAuth => "espresso-cdn-user-marshal-auth",
            Namespace::BrokerBrokerAuth => "espresso-cdn-broker-broker-auth",
        }
    }
}

/// This trait defines a generic signature scheme, wherein we can sign and verify messages
/// with the associated public and private keys.
pub trait SignatureScheme: Send + Sync + 'static {
    /// The signing key type
    type PrivateKey: Clone + Send + Sync;
    /// The verification key type
    type PublicKey: Serializable + Eq + Clone + Send + Sync;

    /// Sign a message using a private key
    ///
    /// # Errors
    /// If signing fails
    fn sign(
        private_key: &Self::PrivateKey,
        namespace: &'static str,
        message: &[u8],
    ) -> Result<Vec<u8>>;

    /// Verify a message with the public key, the message itself, and the signature.
    ///
    /// # Returns
    /// - false if verification failed
    /// - true if verification succeeded
    fn verify(
        public_key: &Self::PublicKey,
        namespace: &'static str,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

/// Allows for us to be generic over a serializable [signature | public key].
pub trait Serializable: Sized {
    /// Serialize `Self` to a `Vec<u8>`.
    ///
    /// # Errors
    /// - If serialization fails
    fn serialize(&self) -> Result<Vec<u8>>;

    /// Deserialize `Self` from a `Vec<u8>`.
    ///
    /// # Errors
    /// - If deserialization fails
    fn deserialize(serialized: &[u8]) -> Result<Self>;
}

/// We encapsulate keys here to help readability.
#[derive(Clone)]
pub struct KeyPair<Scheme: SignatureScheme> {
    /// The underlying (public) verification key, used to authenticate with the server.
    pub public_key: Scheme::PublicKey,

    /// The underlying (private) signing key, used to sign messages to send to the server during the
    /// authentication phase.
    pub private_key: Scheme::PrivateKey,
}

/// An example implementation of `Serializable` for Jellyfish's `bls_over_bn254`.
impl Serializable for jf_signature::bls_over_bn254::VerKey {
    /// Serialize `Self` using `ark-serialize` (uncompressed)
    ///
    /// # Errors
    /// - If serialization fails
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.serialize_uncompressed(&mut buf)?;
        Ok(buf)
    }

    /// Deserialize `Self` using `ark-serialize` (uncompressed)
    ///
    /// # Errors
    /// - If deserialization fails
    fn deserialize(serialized: &[u8]) -> Result<Self> {
        Ok(Self::deserialize_uncompressed(serialized)?)
    }
}

/// An example implementation of `SignatureScheme` for Jellyfish's `bls_over_bn254` signature scheme.
impl SignatureScheme for BLS {
    /// The private and public key types
    type PrivateKey = jf_signature::bls_over_bn254::SignKey;
    type PublicKey = jf_signature::bls_over_bn254::VerKey;

    /// Sign using the private key and the message. We have to serialize the signature
    /// so we can return it as a `Vec<u8>`.
    ///
    /// # Errors
    /// - If serialization fails
    /// - If signing fails
    fn sign(
        private_key: &Self::PrivateKey,
        namespace: &'static str,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        // Add the namespace to the message
        let mut namespaced_message = namespace.as_bytes().to_vec();
        namespaced_message.extend_from_slice(message);

        // Sign the message
        let serialized_signature = <Self as JfSignatureScheme>::sign(
            &(),
            private_key,
            namespaced_message,
            &mut DeterministicRng(0),
        )?;

        // Serialize the signature
        let mut buf = vec![];
        serialized_signature.serialize_uncompressed(&mut buf)?;

        // Return it
        Ok(buf)
    }

    /// Verify the signature using the public key and the message. We have to deserialize the signature
    /// so we can return it as a `Vec<u8>`.
    ///
    /// # Errors
    /// - If signature deserialization fails
    /// - If signing fails
    fn verify(
        public_key: &Self::PublicKey,
        namespace: &'static str,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        // Add the namespace to the message
        let mut namespaced_message = namespace.as_bytes().to_vec();
        namespaced_message.extend_from_slice(message);

        // Deserialize the signature
        let Ok(signature) =
            <Self as JfSignatureScheme>::Signature::deserialize_uncompressed(signature)
        else {
            return false;
        };

        // Verify the signature
        <Self as JfSignatureScheme>::verify(&(), public_key, namespaced_message, &signature).is_ok()
    }
}

#[cfg(test)]
mod test {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn signature_namespace_parity() {
        // Generate a keypair
        let keypair =
            BLS::key_gen(&(), &mut StdRng::seed_from_u64(0)).expect("failed to generate key");

        // Sign a message with the namespace `UserMarshalAuth`
        let signature = <BLS as SignatureScheme>::sign(
            &keypair.0,
            crate::crypto::signature::Namespace::UserMarshalAuth.as_str(),
            b"hello world",
        )
        .expect("failed to sign message");

        // Verify the signature with the namespace `UserMarshalAuth`
        assert!(
            <BLS as SignatureScheme>::verify(
                &keypair.1,
                crate::crypto::signature::Namespace::UserMarshalAuth.as_str(),
                b"hello world",
                &signature,
            ),
            "failed to verify signature"
        );

        // Make sure it fails with the wrong namespace
        assert!(
            !<BLS as SignatureScheme>::verify(
                &keypair.1,
                crate::crypto::signature::Namespace::BrokerBrokerAuth.as_str(),
                b"hello world",
                &signature,
            ),
            "verified signature with wrong namespace"
        );
    }
}
