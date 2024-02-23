//! In this file we define network abstractions, which can be implemented
//! for any network protocol.

use std::sync::Arc;

pub mod auth;
pub mod protocols;

pub type Bytes = Arc<Vec<u8>>;

#[cfg(feature = "metrics")]
pub mod metrics;
