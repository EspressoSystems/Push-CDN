// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This module defines re-exports that the broker uses and that
//! a downstream user may want to use.

pub mod connection {
    pub mod protocols {
        pub use cdn_proto::connection::protocols::quic::Quic;
        pub use cdn_proto::connection::protocols::tcp::Tcp;
        pub use cdn_proto::connection::protocols::tcp_tls::TcpTls;
    }
}

pub mod database {
    pub use cdn_proto::database::{embedded::Embedded, redis::Redis, DatabaseClient};
}

pub mod def {
    pub use cdn_proto::def::{ConnectionDef, RunDef, Topic};
    pub mod hook {
        pub use cdn_proto::def::{HookResult, MessageHook, MessageHookDef, NoMessageHook};
    }
}

pub mod crypto {
    pub mod signature {
        pub use cdn_proto::crypto::signature::{KeyPair, Serializable, SignatureScheme};
    }
}

pub mod error {
    pub use cdn_proto::error::{Error, Result};
}

pub mod message {
    pub use cdn_proto::message::{Broadcast, Direct, Message};
}

/// This is not guarded by `![cfg(test)]` because we use the same functions
/// when doing benchmarks.
pub mod tests {
    pub use crate::tests::{TestBroker, TestDefinition, TestRun, TestUser};
}
