//! This crate defines the common code structures and constants used by both the
//! broker client and server.

#![forbid(unsafe_code)]

use std::hash::{Hash, Hasher};

use connection::UserPublicKey;

pub mod connection;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod message;

#[cfg(feature = "metrics")]
pub mod metrics;

// If local discovery mode is set, we want to use an embedded DB instead of Redis
// for brokers to discover other brokers.
#[cfg(feature = "local_discovery")]
pub type DiscoveryClientType = discovery::embedded::Embedded;

// If local discovery mode is not set, we want to use Redis as opposed to the embedded
// DB.
#[cfg(not(feature = "local_discovery"))]
pub type DiscoveryClientType = discovery::redis::Redis;

/// The maximum message size to be received over a connection.
/// After this, it will be automatically closed by the receiver.
pub const MAX_MESSAGE_SIZE: u32 = u32::MAX;

/// Include the built `capnp-rust` bindings
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod messages_capnp {
    include!(concat!(env!("OUT_DIR"), "/messages_capnp.rs"));
}

/// A function for generating a cute little user mnemonic from a hash
pub fn mnemonic(bytes: &UserPublicKey) -> String {
    let mut state = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut state);
    mnemonic::to_string(state.finish().to_le_bytes())
}
