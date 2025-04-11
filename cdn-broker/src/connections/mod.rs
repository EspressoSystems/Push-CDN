// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This module defines almost all of the connection lookup, addition,
//! and removal process.

use std::collections::{HashMap, HashSet};

use broadcast::BroadcastMap;
use cdn_proto::{
    connection::{protocols::Connection, UserPublicKey},
    database::BrokerIdentifier,
    message::Topic,
    util::mnemonic,
};
use tokio::task::AbortHandle;
use tracing::{error, info, warn};
pub use {
    broadcast::{SubscriptionStatus, TopicSyncMap},
    direct::DirectMap,
};

use crate::metrics;

mod broadcast;
mod direct;
mod versioned_map;

/// A broker connection along with the topic sync information and
/// the task handle for the connection handler.
pub struct Broker {
    pub connection: Connection,
    pub topic_sync_map: TopicSyncMap,
    pub handle: AbortHandle,
}

pub struct Connections {
    // Our identity. Used for versioned vector conflict resolution.
    identity: BrokerIdentifier,

    // The current users connected to us, along with their running tasks
    users: HashMap<UserPublicKey, (Connection, AbortHandle)>,
    // The current brokers connected to us
    brokers: HashMap<BrokerIdentifier, Broker>,

    // The versioned vector for looking up where direct messages should go
    direct_map: DirectMap,
    // The map for looking up where broadcast messages should go.
    broadcast_map: BroadcastMap,
}

impl Connections {
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
    ) -> Option<Connection> {
        self.brokers
            .get(broker_identifier)
            .map(|b| b.connection.clone())
    }

    /// Get the connection for a given user public key (cloned)
    pub fn get_user_connection(&self, user: &UserPublicKey) -> Option<Connection> {
        self.users.get(user).map(|(c, _)| c.clone())
    }

    /// Get all broker identifiers that we are connected to
    pub fn get_broker_identifiers(&self) -> Vec<BrokerIdentifier> {
        self.brokers.keys().cloned().collect()
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
    pub fn get_full_user_sync(&self) -> Option<DirectMap> {
        if self.direct_map.underlying_map.is_empty() {
            None
        } else {
            Some(self.direct_map.clone())
        }
    }

    /// Get the differences in the versioned vector map of user -> broker
    /// We send this to other brokers so they can merge it.
    pub fn get_partial_user_sync(&mut self) -> Option<DirectMap> {
        let diff = self.direct_map.diff();
        if diff.is_empty() {
            None
        } else {
            Some(diff)
        }
    }

    /// Apply a received user sync map. Overwrites our values if they are old.
    /// Kicks off users that are now connected elsewhere.
    pub fn apply_user_sync(&mut self, map: DirectMap) {
        // Merge the maps, returning the difference
        let users_to_remove = self.direct_map.merge(map);

        // We should remove the users that are different, if they exist locally.
        for (user, _new_broker) in users_to_remove {
            self.remove_user(user, "user connected elsewhere");
        }
    }

    /// Apply a received topic sync map. Overwrites our values if they are old.
    pub fn apply_topic_sync(
        &mut self,
        broker_identifier: &BrokerIdentifier,
        remote_map: TopicSyncMap,
    ) {
        // Get the local map by broker identifier
        let local_map = if let Some(broker) = self.brokers.get_mut(broker_identifier) {
            &mut broker.topic_sync_map
        } else {
            self.remove_broker(broker_identifier, "broker did not exist");
            return;
        };

        // Merge the topic sync maps
        let changed_topics = local_map.merge(remote_map);

        // For each key changed,
        for (topic, status) in changed_topics {
            // If the value is `Subscribed`, add the broker to the topic
            if status == Some(SubscriptionStatus::Subscribed) {
                self.subscribe_broker_to(broker_identifier, vec![topic]);
            } else {
                // Otherwise, remove the broker from the topic
                self.unsubscribe_broker_from(broker_identifier, &[topic]);
            }
        }
    }

    /// Get the full list of topics that we are interested in.
    /// We send this to new brokers when they start.
    pub fn get_full_topic_sync(&self) -> Option<TopicSyncMap> {
        if self.broadcast_map.topic_sync_map.underlying_map.is_empty() {
            None
        } else {
            Some(self.broadcast_map.topic_sync_map.clone())
        }
    }

    /// Get the partial list of topics that we are interested in.
    /// We send this to existing brokers every so often.
    pub fn get_partial_topic_sync(&mut self) -> Option<TopicSyncMap> {
        // Lock the maps
        let previous = &mut self.broadcast_map.previous_subscribed_topics;
        let now = HashSet::from_iter(self.broadcast_map.users.get_values());

        // Calculate additions and removals
        let added: Vec<u8> = now.difference(previous).copied().collect();
        let removed: Vec<u8> = previous.difference(&now).copied().collect();

        // If there are no changes, return `None`
        if added.is_empty() && removed.is_empty() {
            return None;
        }

        // Set the previous to the new values
        previous.clone_from(&now);

        // Update the topic sync map
        for topic in added {
            self.broadcast_map
                .topic_sync_map
                .insert(topic, SubscriptionStatus::Subscribed);
        }

        for topic in removed {
            self.broadcast_map
                .topic_sync_map
                .insert(topic, SubscriptionStatus::Unsubscribed);
        }

        // Return the partial map
        Some(self.broadcast_map.topic_sync_map.diff())
    }

    /// Get all the brokers we are connected to. We use this to forward
    /// sync messages to all existing brokers.
    pub fn all_brokers(&self) -> Vec<BrokerIdentifier> {
        self.brokers.keys().cloned().collect()
    }

    /// Get all of the users that are connected to us. We use this when we need
    /// to check if they are still whitelisted.
    pub fn all_users(&self) -> Vec<UserPublicKey> {
        self.users.keys().cloned().collect()
    }

    /// Insert a broker with its connection into our map.
    pub fn add_broker(
        &mut self,
        broker_identifier: BrokerIdentifier,
        connection: Connection,
        handle: AbortHandle,
    ) {
        // Increment the metric for the number of brokers connected
        metrics::NUM_BROKERS_CONNECTED.inc();
        info!(id = %broker_identifier, "broker connected");

        // Remove the old broker if it exists
        self.remove_broker(&broker_identifier, "already existed");

        // Insert into our map with a new topic sync map
        self.brokers.insert(
            broker_identifier,
            Broker {
                connection,
                handle,
                topic_sync_map: TopicSyncMap::new(0),
            },
        );
    }

    /// Insert a user into our map. Updates the versioned vector that
    /// keeps track of which users are connected where.
    pub fn add_user(
        &mut self,
        user_public_key: &UserPublicKey,
        connection: Connection,
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
    pub fn remove_broker(&mut self, broker_identifier: &BrokerIdentifier, reason: &str) {
        // Remove from broker list, cancelling the previous task if it exists
        if let Some(broker) = self.brokers.remove(broker_identifier) {
            // Decrement the metric for the number of brokers connected
            metrics::NUM_BROKERS_CONNECTED.dec();
            error!(id = %broker_identifier, reason = reason, "broker disconnected");

            // Cancel the task
            broker.handle.abort();
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
        if let Some((_, task)) = self.users.remove(&user_public_key) {
            // Decrement the metric for the number of users connected
            metrics::NUM_USERS_CONNECTED.dec();
            warn!(
                id = mnemonic(&user_public_key),
                reason = reason,
                "user disconnected"
            );

            // Cancel the task
            task.abort();
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

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use cdn_proto::{
        connection::protocols::Connection, database::BrokerIdentifier, def::TestTopic,
    };
    use tokio::spawn;

    use super::Connections;

    /// Create a new broker identifier for testing
    fn new_broker_identifier(namespace: &str) -> BrokerIdentifier {
        format!("test/{namespace}")
            .try_into()
            .expect("failed to create broker identifier")
    }

    /// Test that subscribing and unsubscribing works as expected through use
    /// of the topic sync map.
    #[tokio::test]
    async fn test_topic_sync() {
        // The identifiers for the local and remote brokers
        let local_broker_identifier: BrokerIdentifier = new_broker_identifier("local");
        let remote_broker_identifier: BrokerIdentifier = new_broker_identifier("remote");

        // Create the local map that needs to stay in sync
        let mut local_map = Connections::new(local_broker_identifier.clone());
        let connection = Connection::new_test();
        let handle = spawn(async move {}).abort_handle();
        local_map.add_broker(remote_broker_identifier.clone(), connection, handle);

        // Create the remote map that will be having changes applied to it
        let mut remote_map = Connections::new(remote_broker_identifier.clone());
        let connection = Connection::new_test();
        let handle = spawn(async move {}).abort_handle();
        remote_map.add_broker(local_broker_identifier, connection, handle);

        // Subscribe a user to topics `Global` and `DA` in the remote map
        remote_map.subscribe_user_to(
            &Arc::from(vec![1]),
            vec![TestTopic::Global.into(), TestTopic::DA.into()],
        );

        // Get the full sync and make sure it is `None`
        let full_sync = remote_map.get_full_topic_sync();
        assert!(full_sync.is_none());

        // Get a partial sync from remote and apply it locally
        let partial_sync = remote_map.get_partial_topic_sync();
        local_map.apply_topic_sync(&remote_broker_identifier, partial_sync.unwrap());

        // Make sure we are subscribed to the Global topic
        let (brokers, _) =
            local_map.get_interested_by_topic(&vec![TestTopic::Global.into()], false);
        assert!(brokers.len() == 1);
        assert!(brokers.contains(&remote_broker_identifier));

        // Make sure we are subscribed to the DA topic
        let (brokers, _) = local_map.get_interested_by_topic(&vec![TestTopic::DA.into()], false);
        assert!(brokers.len() == 1);
        assert!(brokers.contains(&remote_broker_identifier));

        // Unsubscribe the remote user from the Global topic
        remote_map.unsubscribe_user_from(&Arc::from(vec![1]), &[TestTopic::Global.into()]);

        // Perform another partial sync from remote -> local
        let partial_sync = remote_map.get_partial_topic_sync();
        local_map.apply_topic_sync(&remote_broker_identifier, partial_sync.unwrap());

        // Make sure we are no longer subscribed to the Global topic
        let (brokers, _) =
            local_map.get_interested_by_topic(&vec![TestTopic::Global.into()], false);
        assert!(brokers.is_empty());

        // Make sure we are still subscribed to the DA topic
        let (brokers, _) = local_map.get_interested_by_topic(&vec![TestTopic::DA.into()], false);
        assert!(brokers.len() == 1);
        assert!(brokers.contains(&remote_broker_identifier));
    }

    /// Test that subscribing and unsubscribing works as expected even
    /// if messages are received and processed out of order.
    #[tokio::test]
    async fn test_topic_sync_out_of_order() {
        // The identifiers for the local and remote brokers
        let local_broker_identifier: BrokerIdentifier = new_broker_identifier("local");
        let remote_broker_identifier: BrokerIdentifier = new_broker_identifier("remote");

        // Create the local map that needs to stay in sync
        let mut local_map = Connections::new(local_broker_identifier.clone());
        let connection = Connection::new_test();
        let handle = spawn(async move {}).abort_handle();
        local_map.add_broker(remote_broker_identifier.clone(), connection, handle);

        // Create the remote map that will be having changes applied to it
        let mut remote_map = Connections::new(remote_broker_identifier.clone());
        let connection = Connection::new_test();
        let handle = spawn(async move {}).abort_handle();
        remote_map.add_broker(local_broker_identifier, connection, handle);

        // Subscribe a user to topics `Global` and `DA` in the remote map
        remote_map.subscribe_user_to(
            &Arc::from(vec![1]),
            vec![TestTopic::Global.into(), TestTopic::DA.into()],
        );

        // Do a partial sync but don't apply it
        let _partial_sync = remote_map.get_partial_topic_sync();

        // Unsuscribe the user from both topics
        remote_map.unsubscribe_user_from(&Arc::from(vec![1]), &[TestTopic::Global.into()]);
        remote_map.unsubscribe_user_from(&Arc::from(vec![1]), &[TestTopic::DA.into()]);

        // Do another partial sync and apply it
        let partial_sync = remote_map.get_partial_topic_sync();
        local_map.apply_topic_sync(&remote_broker_identifier, partial_sync.unwrap());

        // Subscribe the user to the DA topic
        remote_map.subscribe_user_to(&Arc::from(vec![1]), vec![TestTopic::DA.into()]);
        let partial_sync = remote_map.get_partial_topic_sync();
        local_map.apply_topic_sync(&remote_broker_identifier, partial_sync.unwrap());

        // Perform a full sync
        let full_sync = remote_map.get_full_topic_sync();
        local_map.apply_topic_sync(&remote_broker_identifier, full_sync.unwrap());

        // Make sure we are no longer subscribed to the Global topic
        let (brokers, _) =
            local_map.get_interested_by_topic(&vec![TestTopic::Global.into()], false);
        assert!(brokers.is_empty());

        // Make sure we are still subscribed to the DA topic
        let (brokers, _) = local_map.get_interested_by_topic(&vec![TestTopic::DA.into()], false);
        assert!(brokers.len() == 1);
        assert!(brokers.contains(&remote_broker_identifier));
    }
}
