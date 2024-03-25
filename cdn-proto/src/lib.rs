//! This crate defines the common code structures and constants used by both the
//! broker client and server.

#![forbid(unsafe_code)]

use std::hash::{Hash, Hasher};

use connection::UserPublicKey;

pub mod connection;
pub mod crypto;
pub mod def;
pub mod discovery;
pub mod error;
pub mod message;

#[cfg(feature = "metrics")]
pub mod metrics;

/// The maximum message size to be received over a connection.
/// After this, it will be automatically closed by the receiver.
pub const MAX_MESSAGE_SIZE: u32 = u32::MAX / 8;

/// Include the built `capnp-rust` bindings
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod messages_capnp {
    include!("../schema/messages_capnp.rs");
}

/// A function for generating a cute little user mnemonic from a hash
pub fn mnemonic(bytes: &UserPublicKey) -> String {
    let mut state = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut state);
    mnemonic::to_string(state.finish().to_le_bytes())
}
