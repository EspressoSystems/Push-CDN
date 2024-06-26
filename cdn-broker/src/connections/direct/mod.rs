//! This is where we define routing for direct messages.
use cdn_proto::{connection::UserPublicKey, discovery::BrokerIdentifier};

use super::versioned_map::VersionedMap;

/// We define the direct map as just a type alias of a `VersionedMap`, which
// deals with version vectors.
pub type DirectMap = VersionedMap<UserPublicKey, BrokerIdentifier, BrokerIdentifier>;
