//! This crate defines the common code structures and constants used by both the
//! broker client and server.

#![forbid(unsafe_code)]

pub mod connection;
pub mod crypto;
pub mod def;
pub mod discovery;
pub mod error;
pub mod message;
pub mod util;

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
