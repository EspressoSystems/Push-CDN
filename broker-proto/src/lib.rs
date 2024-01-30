pub mod wal;
pub mod connection;
pub mod message;
pub mod error;

/// Include the built capnp-rust bindings
pub mod messages_capnp {
    include!(concat!(env!("OUT_DIR"), "/messages_capnp.rs"));
}
