// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! In this file we define network abstractions, which can be implemented
//! for any network protocol.

use std::sync::Arc;

pub mod auth;
pub mod limiter;
pub mod protocols;

use self::limiter::pool::Allocation;

/// Some type aliases to help with readability
pub type Bytes = Allocation<Vec<u8>>;
pub type UserPublicKey = Arc<Vec<u8>>;

#[cfg(feature = "metrics")]
pub mod metrics;
