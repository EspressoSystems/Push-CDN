use std::sync::Arc;

use proto::discovery::BrokerIdentifier;

use super::versioned::VersionedMap;

/// A little type alias to help readability
type Bytes = Arc<Vec<u8>>;

/// We define the direct map as just a type alias of a `VersionedMap`, which 
// deals with version vectors.
pub type DirectMap = VersionedMap<Bytes, BrokerIdentifier, BrokerIdentifier>;
