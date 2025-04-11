// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This is where we define routing for broadcast messages.

mod relational_map;

use std::collections::HashSet;

use cdn_proto::{connection::UserPublicKey, database::BrokerIdentifier, message::Topic};
use relational_map::RelationalMap;
use rkyv::{Archive, Deserialize, Serialize};

use super::versioned_map::VersionedMap;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Archive, Clone)]
#[archive(check_bytes)]
pub enum SubscriptionStatus {
    Subscribed,
    Unsubscribed,
}

pub type TopicSyncMap = VersionedMap<Topic, SubscriptionStatus, u32>;

/// Our broadcast map is just two associative (bidirectional, multi) maps:
/// one for brokers and one for users.
pub struct BroadcastMap {
    pub users: RelationalMap<UserPublicKey, Topic>,
    pub brokers: RelationalMap<BrokerIdentifier, Topic>,

    pub topic_sync_map: TopicSyncMap,
    pub previous_subscribed_topics: HashSet<Topic>,
}

/// Default for our map just wraps the items with locks.
impl Default for BroadcastMap {
    fn default() -> Self {
        Self {
            users: RelationalMap::new(),
            brokers: RelationalMap::new(),
            previous_subscribed_topics: HashSet::new(),
            topic_sync_map: TopicSyncMap::new(0),
        }
    }
}

/// The new implementation just uses default
impl BroadcastMap {
    pub fn new() -> Self {
        Self::default()
    }
}
