//! This module defines re-exports that the broker uses and that
//! a downstream user may want to use.

pub mod connection {
    pub mod protocols {
        pub mod quic {
            pub use proto::connection::protocols::quic::Quic;
        }
    }
}

pub mod crypto {
    pub mod signature {
        pub use proto::crypto::signature::{KeyPair, Serializable, SignatureScheme};
    }
}

pub mod message {
    pub use proto::message::Topic;
}

pub mod error {
    pub use proto::error::{Error, Result};
}
