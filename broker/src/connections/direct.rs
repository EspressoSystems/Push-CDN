//! This is where we define routing for direct messages.
// TODO: write tests for this

use proto::{connection::UserPublicKey, discovery::BrokerIdentifier};

use super::versioned::VersionedMap;

/// We define the direct map as just a type alias of a `VersionedMap`, which
// deals with version vectors.
pub type DirectMap = VersionedMap<UserPublicKey, BrokerIdentifier, BrokerIdentifier>;
