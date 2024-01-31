pub mod connection;
pub mod error;
pub mod message;
pub mod wal;

/// Include the built capnp-rust bindings
pub mod messages_capnp {
    include!(concat!(env!("OUT_DIR"), "/messages_capnp.rs"));
}
