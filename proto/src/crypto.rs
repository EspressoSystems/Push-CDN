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
        CryptoError,
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
        CryptoError,
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
        CryptoError,
        "failed to generate keypair"
    ))
}
