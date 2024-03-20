//! This module defines re-exports that the broker uses and that
//! a downstream user may want to use.

pub mod connection {
    pub mod protocols {
        pub use cdn_proto::connection::protocols::quic::Quic;
        pub use cdn_proto::connection::protocols::tcp::Tcp;
    }
}

pub mod discovery {
    pub use cdn_proto::discovery::{embedded::Embedded, redis::Redis, DiscoveryClient};
}

pub mod def {
    pub use cdn_proto::def::RunDef;
}

pub mod crypto {
    pub mod signature {
        pub use cdn_proto::crypto::signature::{KeyPair, Serializable, SignatureScheme};
    }
}

pub mod message {
    pub use cdn_proto::message::Topic;
}

pub mod error {
    pub use cdn_proto::error::{Error, Result};
}

/// This is not guarded by `![cfg(test)]` because we use the same functions
/// when doing benchmarks.
pub mod tests {
    pub use crate::tests::{TestDefinition, TestRun};
}
