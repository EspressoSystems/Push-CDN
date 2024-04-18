//! In this file we define network abstractions, which can be implemented
//! for any network protocol.

use std::sync::Arc;

pub mod auth;
pub mod middleware;
pub mod protocols;

use self::middleware::pool::Allocation;

/// Some type aliases to help with readability
pub type Bytes = Allocation<Vec<u8>>;
pub type UserPublicKey = Arc<Vec<u8>>;

#[cfg(feature = "metrics")]
pub mod metrics;
