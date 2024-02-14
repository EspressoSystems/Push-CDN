//! This crate defines the common code structures and constants used by both the
//! broker client and server.

use connection::protocols::{quic::Quic, tcp::Tcp};

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
// DB.p
#[cfg(not(feature = "local_discovery"))]
pub type DiscoveryClientType = discovery::redis::Redis;

// Defines the protocol types for each protocol actor.
pub type BrokerProtocol = Tcp;
pub type UserProtocol = Quic;

/// Common constants used in both the client and server
///
/// The maximum message size to be received over a connection.
/// After this, it will be automatically closed by the receiver.
pub const MAX_MESSAGE_SIZE: u64 = 1024 * 1024 * 1024;

/// The maximum amount of concurrent QUIC streams (messages) that can be opened.
/// Having a value that is too high can degrade performance.
pub const QUIC_MAX_CONCURRENT_STREAMS: u64 = 10;

/// Include the built `capnp-rust` bindings
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod messages_capnp {
    include!(concat!(env!("OUT_DIR"), "/messages_capnp.rs"));
}
