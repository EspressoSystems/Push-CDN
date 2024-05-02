//! This is where we define routing for broadcast messages.

mod relational_map;

use std::collections::HashSet;

use cdn_proto::{connection::UserPublicKey, discovery::BrokerIdentifier, message::Topic};

use self::relational_map::RelationalMap;

/// Our broadcast map is just two associative (bidirectional, multi) maps:
/// one for brokers and one for users.
pub struct BroadcastMap {
    pub users: RelationalMap<UserPublicKey, Topic>,
    pub brokers: RelationalMap<BrokerIdentifier, Topic>,

    pub previous_subscribed_topics: HashSet<Topic>,
}

/// Default for our map just wraps the items with locks.
impl Default for BroadcastMap {
    fn default() -> Self {
        Self {
            users: RelationalMap::new(),
            brokers: RelationalMap::new(),
            previous_subscribed_topics: HashSet::new(),
        }
    }
}

/// The new implementation just uses default
impl BroadcastMap {
    pub fn new() -> Self {
        Self::default()
    }
}
