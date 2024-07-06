// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This module defines re-exports that the client uses and that
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
    pub use cdn_proto::def::{ConnectionDef, RunDef, Topic};
}

pub mod crypto {
    pub mod signature {
        pub use cdn_proto::crypto::signature::{KeyPair, Serializable, SignatureScheme};
    }
}

pub mod message {
    pub use cdn_proto::message::{Broadcast, Direct, Message};
}

pub mod error {
    pub use cdn_proto::error::{Error, Result};
}
