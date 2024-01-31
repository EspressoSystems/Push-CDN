//! This crate defines the common code structures and constants used by both the
//! broker client and server.

pub mod connection;
pub mod error;
pub mod message;
pub mod wal;

/// Common constants used in both the client and server
///
/// The maximum message size to be received over a connection.
/// After this, it will be automatically closed by the receiver.
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024 * 1024;

/// The maximum amount of concurrent QUIC streams (messages) that can be opened.
/// Having a value that is too high can degrade performance.
pub const QUIC_MAX_CONCURRENT_STREAMS: u64 = 10;

/// Specifies the number of subsequent connection failures before we try
/// to connect to the next server address, if applicable (we might be
/// using a single server address).
pub const SUBSEQUENT_CONNECTION_FAILURES_BEFORE_NEXT_ADDRESS: usize = 3;

/// Specifies the number of subsequent operation (message send, authentication, etc)
/// failures before we try to reconnect to the current (or next) server.
pub const SUBSEQUENT_OPERATION_FAILURES_BEFORE_NEXT_RECONNECT: usize = 3;

/// Include the built capnp-rust bindings
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod messages_capnp {
    include!(concat!(env!("OUT_DIR"), "/messages_capnp.rs"));
}
