//! This module defines almost all of the connection lookup, addition,
//! and removal process.

use std::collections::{HashMap, HashSet};

use cdn_proto::{
    connection::UserPublicKey,
    def::{Connection, RunDef},
    discovery::BrokerIdentifier,
    message::Topic,
    mnemonic,
};
pub use direct::DirectMap;
use tokio::task::AbortHandle;
use tracing::{error, info, warn};

use crate::metrics;

use self::broadcast::BroadcastMap;

mod broadcast;
mod direct;

pub struct Connections<Def: RunDef> {
    // Our identity. Used for versioned vector conflict resolution.
    identity: BrokerIdentifier,

    // The current users connected to us
    users: HashMap<UserPublicKey, (Connection<Def::User>, Vec<AbortHandle>)>,
    // The current brokers connected to us
    brokers: HashMap<BrokerIdentifier, (Connection<Def::Broker>, Vec<AbortHandle>)>,

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

    /// Get the broker identifier for a given user (if it exists)
    pub fn get_broker_identifier_of_user(&self, user: &UserPublicKey) -> Option<BrokerIdentifier> {
        self.direct_map.get(user).cloned()
    }

    /// Get the broker connection for a given broker identifier (cloned)
    pub fn get_broker_connection(
        &self,
        broker_identifier: &BrokerIdentifier,
    ) -> Option<Connection<Def::Broker>> {
        self.brokers.get(broker_identifier).map(|(c, _)| c.clone())
    }

    /// Get the connection for a given user public key (cloned)
    pub fn get_user_connection(&self, user: &UserPublicKey) -> Option<Connection<Def::User>> {
        self.users.get(user).map(|(c, _)| c.clone())
    }

    /// Get all broker identifiers that we are connected to
    pub fn get_broker_identifiers(&self) -> Vec<BrokerIdentifier> {
        self.brokers.keys().cloned().collect()
    }

    /// Add a task to the list of tasks for a broker. This is used to
    /// cancel the task if the broker disconnects.
    /// TODO: macro this?
    pub fn add_broker_task(&mut self, broker_identifier: &BrokerIdentifier, handle: AbortHandle) {
        if let Some((_, handles)) = self.brokers.get_mut(broker_identifier) {
            // If the broker exists, add the handle to the list of tasks
            handles.push(handle);
        } else {
            // Otherwise, cancel the task
            handle.abort();
        }
    }

    /// Add a task to the list of tasks for a user. This is used to
    /// cancel the task if the user disconnects.
    /// TODO: macro this?
    pub fn add_user_task(&mut self, user: &UserPublicKey, handle: AbortHandle) {
        if let Some((_, handles)) = self.users.get_mut(user) {
            // If the user exists, add the handle to the list of tasks
            handles.push(handle);
        } else {
            // Otherwise, cancel the task
            handle.abort();
        }
    }

    /// Get all users and brokers interested in a list of topics.
    pub fn get_interested_by_topic(
        &self,
        topics: &Vec<Topic>,
        to_users_only: bool,
    ) -> (Vec<BrokerIdentifier>, Vec<UserPublicKey>) {
        // Aggregate recipients
        let mut broker_recipients = HashSet::new();
        let mut user_recipients = HashSet::new();

        // For each topic
        for topic in topics {
            // Get all users interested in the topic
            for user in self.broadcast_map.users.get_keys_by_value(topic) {
                user_recipients.insert(user);
            }

            // If we want to send to brokers as well,
            if !to_users_only {
                // Get all brokers interested in the topic
                for broker in self.broadcast_map.brokers.get_keys_by_value(topic) {
                    broker_recipients.insert(broker);
                }
            }
        }

        // Return the recipients
        (
            broker_recipients.into_iter().collect(),
            user_recipients.into_iter().collect(),
        )
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
            self.remove_user(user, "user connected elsewhere");
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
        // Increment the metric for the number of brokers connected
        metrics::NUM_BROKERS_CONNECTED.inc();
        info!(id = %broker_identifier, "broker connected");

        // Remove the old broker if it exists
        self.remove_broker(&broker_identifier, "already existed");

        self.brokers
            .insert(broker_identifier, (connection, vec![handle]));
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
        // Increment the metric for the number of brokers connected
        metrics::NUM_USERS_CONNECTED.inc();
        info!(id = mnemonic(user_public_key), "user connected");

        // Remove the old user if it exists
        self.remove_user(user_public_key.clone(), "already existed");

        // Add to our map. Remove the old one if it exists
        self.users
            .insert(user_public_key.clone(), (connection, vec![handle]));

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
    pub fn remove_broker(&mut self, broker_identifier: &BrokerIdentifier, reason: &str) {
        // Remove from broker list, cancelling the previous task if it exists
        if let Some(task_handles) = self.brokers.remove(broker_identifier).map(|(_, h)| h) {
            // Decrement the metric for the number of brokers connected
            metrics::NUM_BROKERS_CONNECTED.dec();
            error!(id = %broker_identifier, reason = reason, "broker disconnected");

            // Cancel all tasks
            for handle in task_handles {
                handle.abort();
            }
        };

        // Remove from all topics
        self.broadcast_map.brokers.remove_key(broker_identifier);

        // TODO: Remove all users from the direct map that are connected to this broker
        // self.direct_map.remove_by_value_no_modify(broker_identifier);
    }

    /// Remove a user from our map by their public key. Also removes them
    /// from our broadcast map, in case they were subscribed to any topics, and
    /// the versioned vector map. This is so other brokers don't keep trying
    /// to send us messages for a disconnected user.
    pub fn remove_user(&mut self, user_public_key: UserPublicKey, reason: &str) {
        // Remove from user list, returning the previous handle if it exists
        if let Some(task_handles) = self.users.remove(&user_public_key).map(|(_, h)| h) {
            // Decrement the metric for the number of users connected
            metrics::NUM_USERS_CONNECTED.dec();
            warn!(
                id = mnemonic(&user_public_key),
                reason = reason,
                "user disconnected"
            );

            // Cancel all tasks
            for handle in task_handles {
                handle.abort();
            }
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
