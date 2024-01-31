pub mod connection;
pub mod error;
pub mod message;
pub mod wal;

/// Include the built capnp-rust bindings
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod messages_capnp {
    include!(concat!(env!("OUT_DIR"), "/messages_capnp.rs"));
}
