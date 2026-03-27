// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This is where we define routing for direct messages.
use cdn_proto::{connection::UserPublicKey, database::BrokerIdentifier};

use super::versioned_map::VersionedMap;

/// We define the direct map as just a type alias of a `VersionedMap`, which
// deals with version vectors.
pub type DirectMap = VersionedMap<UserPublicKey, BrokerIdentifier, BrokerIdentifier>;
