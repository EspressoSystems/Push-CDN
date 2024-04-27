//! This module defines almost all of the connection lookup, addition,
//! and removal process.

use std::collections::{HashMap, HashSet};

use cdn_proto::{
    connection::UserPublicKey,
    def::{Connection, RunDef},
    discovery::BrokerIdentifier,
    message::Topic,
};
pub use direct::DirectMap;
use tokio::task::AbortHandle;

use self::broadcast::BroadcastMap;

mod broadcast;
mod direct;
mod versioned;
mod logic;
pub struct Connections<Def: RunDef> {
    // Our identity. Used for versioned vector conflict resolution.
    identity: BrokerIdentifier,

    // The current users connected to us
    users: HashMap<UserPublicKey, (Connection<Def::User>, AbortHandle)>,
    // The current brokers connected to us
    brokers: HashMap<BrokerIdentifier, (Connection<Def::Broker>, AbortHandle)>,

    // The versioned vector for looking up where direct messages should go
    direct_map: DirectMap,
    // The map for looking up where broadcast messages should go.
    broadcast_map: BroadcastMap,
}

impl<Def: RunDef> Connections<Def> {
    /// Create a new `Connections`. Requires an identity for
    /// version vector conflict resolution.
    pub fn new(identity: BrokerIdentifier) -> Self {
        Self {
            identity: identity.clone(),
            users: HashMap::new(),
            brokers: HashMap::new(),
            direct_map: DirectMap::new(identity),
            broadcast_map: BroadcastMap::new(),
        }
    }

    /// Get the number of users connected to us at any given time.
    pub fn num_users(&self) -> usize {
        self.users.len()
    }

    /// Get the full versioned vector map of user -> broker.
    /// We send this to other brokers so they can merge it.
    pub fn get_full_user_sync(&self) -> DirectMap {
        self.direct_map.get_full()
    }

    /// Get the differences in the versioned vector map of user -> broker
    /// We send this to other brokers so they can merge it.
    pub fn get_partial_user_sync(&mut self) -> DirectMap {
        self.direct_map.diff()
    }

    /// Apply a received user sync map. Overwrites our values if they are old.
    /// Kicks off users that are now connected elsewhere.
    pub fn apply_user_sync(&mut self, map: DirectMap) {
        // Merge the maps, returning the difference
        let users_to_remove = self.direct_map.merge(map);

        // We should remove the users that are different, if they exist locally.
        for user in users_to_remove {
            self.remove_user(user);
        }
    }

    /// Get the full list of topics that we are interested in.
    /// We send this to new brokers when they start.
    pub fn get_full_topic_sync(&self) -> Vec<Topic> {
        self.broadcast_map.users.get_values()
    }

    /// Get the partial list of topics that we are interested in. Returns the
    /// additions and removals as a tuple `(a, r)` in that order. We send this
    /// to other brokers whenever there are changes.
    pub fn get_partial_topic_sync(&mut self) -> (Vec<Topic>, Vec<Topic>) {
        // Lock the maps
        let previous = &mut self.broadcast_map.previous_subscribed_topics;
        let now = HashSet::from_iter(self.broadcast_map.users.get_values());

        // Calculate additions and removals
        let added = now.difference(previous);
        let removed = previous.difference(&now);

        // Clone them
        let differences = (added.cloned().collect(), removed.cloned().collect());

        // Set the previous to the new one
        *previous = now.clone();

        // Return the differences
        differences
    }

    /// Get all the brokers we are connected to. We use this to forward
    /// sync messages to all existing brokers.
    pub fn all_brokers(&self) -> Vec<BrokerIdentifier> {
        self.brokers.keys().cloned().collect()
    }

    /// Insert a broker with its connection into our map.
    pub fn add_broker(
        &mut self,
        broker_identifier: BrokerIdentifier,
        connection: Connection<Def::Broker>,
        handle: AbortHandle,
    ) {
        // Remove the old broker if it exists
        self.remove_broker(&broker_identifier);

        self.brokers.insert(broker_identifier, (connection, handle));
    }

    /// Insert a user into our map. Updates the versioned vector that
    /// keeps track of which users are connected where.
    pub fn add_user(
        &mut self,
        user_public_key: &UserPublicKey,
        connection: Connection<Def::User>,
        topics: &[Topic],
        handle: AbortHandle,
    ) {
        // Remove the old user if it exists
        self.remove_user(user_public_key.clone());

        // Add to our map. Remove the old one if it exists
        self.users
            .insert(user_public_key.clone(), (connection, handle));

        // Insert into our direct map
        self.direct_map
            .insert(user_public_key.clone(), self.identity.clone());

        // Subscribe user to topics
        self.broadcast_map
            .users
            .associate_key_with_values(user_public_key, topics.to_vec());
    }

    /// Remove a broker from our map by their identifier. Also removes them
    /// from our broadcast map, in case they were subscribed to any topics.
    pub fn remove_broker(&mut self, broker_identifier: &BrokerIdentifier) {
        // Remove from broker list, cancelling the previous task if it exists
        if let Some(previous_handle) = self.brokers.remove(broker_identifier).map(|(_, h)| h) {
            // Cancel the broker's task
            previous_handle.abort();
        };

        // Remove from all topics
        self.broadcast_map.brokers.remove_key(broker_identifier);

        // TODO: figure out if we can/should remove from direct map
    }

    /// Remove a user from our map by their public key. Also removes them
    /// from our broadcast map, in case they were subscribed to any topics, and
    /// the versioned vector map. This is so other brokers don't keep trying
    /// to send us messages for a disconnected user.
    pub fn remove_user(&mut self, user_public_key: UserPublicKey) {
        // Remove from user list, returning the previous handle if it exists
        if let Some(previous_handle) = self.users.remove(&user_public_key).map(|(_, h)| h) {
            // Cancel the user's task
            previous_handle.abort();
        };

        // Remove from user topics
        self.broadcast_map.users.remove_key(&user_public_key);

        // Remove from direct map if they're connected to us
        self.direct_map
            .remove_if_equals(user_public_key, self.identity.clone());
    }

    /// Locally subscribe a broker to some topics.
    pub fn subscribe_broker_to(
        &mut self,
        broker_identifier: &BrokerIdentifier,
        topics: Vec<Topic>,
    ) {
        self.broadcast_map
            .brokers
            .associate_key_with_values(broker_identifier, topics);
    }

    /// Locally subscribe a user to some topics.
    pub fn subscribe_user_to(&mut self, user_public_key: &UserPublicKey, topics: Vec<Topic>) {
        self.broadcast_map
            .users
            .associate_key_with_values(user_public_key, topics);
    }

    /// Locally unsubscribe a broker from some topics.
    pub fn unsubscribe_broker_from(
        &mut self,
        broker_identifier: &BrokerIdentifier,
        topics: &[Topic],
    ) {
        self.broadcast_map
            .brokers
            .dissociate_keys_from_value(broker_identifier, topics);
    }

    /// Locally unsubscribe a broker from some topics.
    pub fn unsubscribe_user_from(&mut self, user_public_key: &UserPublicKey, topics: &[Topic]) {
        self.broadcast_map
            .users
            .dissociate_keys_from_value(user_public_key, topics);
    }
}
