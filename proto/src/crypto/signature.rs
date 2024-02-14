//! In this module we define the interface for signing and authenticating
//! with a marshal.

use anyhow::Result;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme as JfSignatureScheme,
};

use super::rng::DeterministicRng;

/// This trait defines a generic signature scheme, wherein we can sign and verify messages
/// with the associated public and private keys.
pub trait SignatureScheme: Send + Sync + Clone + 'static {
    /// The signing key type
    type PrivateKey: Send + Sync;
    /// The verification key type
    type PublicKey: Serializable + Eq + Send + Sync;

    /// Sign a message using a private key
    ///
    /// # Errors
    /// If signing fails
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>>;

    /// Verify a message with the public key, the message itself, and the signature.
    ///
    /// # Returns
    /// - false if verification failed
    /// - true if verification succeeded
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &[u8]) -> bool;
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
pub struct KeyPair<Scheme: SignatureScheme> {
    /// The underlying (public) verification key, used to authenticate with the server.
    pub public_key: Scheme::PublicKey,

    /// The underlying (private) signing key, used to sign messages to send to the server during the
    /// authentication phase.
    pub private_key: Scheme::PrivateKey,
}

/// An example implementation of `Serializable` for Jellyfish's `bls_over_bn254`.
impl Serializable for jf_primitives::signatures::bls_over_bn254::VerKey {
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
    type PrivateKey = jf_primitives::signatures::bls_over_bn254::SignKey;
    type PublicKey = jf_primitives::signatures::bls_over_bn254::VerKey;

    /// Sign using the private key and the message. We have to serialize the signature
    /// so we can return it as a `Vec<u8>`.
    ///
    /// # Errors
    /// - If serialization fails
    /// - If signing fails
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>> {
        // Sign the message
        let serialized_signature =
            <Self as JfSignatureScheme>::sign(&(), private_key, message, &mut DeterministicRng(0))?;

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
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &[u8]) -> bool {
        // Deserialize the signature
        let Ok(signature) =
            <Self as JfSignatureScheme>::Signature::deserialize_uncompressed(signature)
        else {
            return false;
        };

        // Verify the signature
        <Self as JfSignatureScheme>::verify(&(), public_key, message, &signature).is_ok()
    }
}
