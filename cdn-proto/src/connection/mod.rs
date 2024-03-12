//! In this file we define network abstractions, which can be implemented
//! for any network protocol.

use std::sync::Arc;

pub mod auth;
pub mod protocols;

/// Some type aliases to help with readability
pub type Bytes = Arc<Vec<u8>>;
pub type UserPublicKey = Bytes;

#[cfg(feature = "metrics")]
pub mod metrics;
