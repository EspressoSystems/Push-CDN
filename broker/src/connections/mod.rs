//! This module defines almost all of the connection lookup, addition,
//! and removal process.

use std::{collections::HashSet, sync::Arc};

use dashmap::DashMap;
pub use direct::DirectMap;
use parking_lot::RwLock;
use proto::{
    connection::{
        protocols::{Protocol, Sender},
        Bytes,
    },
    discovery::BrokerIdentifier,
    message::Topic,
    mnemonic,
};
use tokio::spawn;
use tracing::{error, warn};

use self::{broadcast::BroadcastMap, versioned::VersionedMap};

mod broadcast;
mod direct;
mod versioned;

/// Associated type for readability
type UserPublicKey = Bytes;

/// Stores information about all current connections.
pub struct Connections<BrokerProtocol: Protocol, UserProtocol: Protocol> {
    // Our identity. Used for versioned vector conflict resolution.
    identity: BrokerIdentifier,

    // The current users connected to us
    users: DashMap<Bytes, UserProtocol::Sender>,
    // The current brokers connected to us
    brokers: DashMap<BrokerIdentifier, BrokerProtocol::Sender>,

    // The versioned vector for looking up where direct messages should go
    direct_map: RwLock<DirectMap>,
    // The map for looking up where broadcast messages should go.
    broadcast_map: BroadcastMap,
}

impl<BrokerProtocol: Protocol, UserProtocol: Protocol> Connections<BrokerProtocol, UserProtocol> {
    /// Create a new `Connections`. Requires an identity for
    /// version vector conflict resolution.
    pub fn new(identity: BrokerIdentifier) -> Self {
        Self {
            identity: identity.clone(),
            users: DashMap::new(),
            brokers: DashMap::new(),
            direct_map: RwLock::from(VersionedMap::new(identity)),
            broadcast_map: BroadcastMap::new(),
        }
    }

    /// Get the number of users connected to us at any given time.
    pub fn num_users(self: &Arc<Self>) -> usize {
        self.users.len()
    }

    /// Get the full versioned vector map of user -> broker.
    /// We send this to other brokers so they can merge it.
    pub fn get_full_user_sync(self: &Arc<Self>) -> DirectMap {
        self.direct_map.read().get_full()
    }

    /// Get the differences in the versioned vector map of user -> broker
    /// We send this to other brokers so they can merge it.
    pub fn get_partial_user_sync(self: &Arc<Self>) -> DirectMap {
        self.direct_map.write().diff()
    }

    /// Apply a received user sync map. Overwrites our values if they are old.
    /// Kicks off users that are now connected elsewhere.
    pub fn apply_user_sync(self: &Arc<Self>, map: DirectMap) {
        // Merge the maps, returning the difference
        let users_to_remove = self.direct_map.write().merge(map);

        // We should remove the users that are different, if they exist locally.
        for user in users_to_remove {
            self.remove_user(user);
        }
    }

    /// Get the full list of topics that we are interested in.
    /// We send this to new brokers when they start.
    pub fn get_full_topic_sync(self: &Arc<Self>) -> Vec<Topic> {
        self.broadcast_map.users.read().get_values()
    }

    /// Get the partial list of topics that we are interested in. Returns the
    /// additions and removals as a tuple `(a, r)` in that order. We send this
    /// to other brokers whenever there are changes.
    pub fn get_partial_topic_sync(self: &Arc<Self>) -> (Vec<Topic>, Vec<Topic>) {
        // Lock the maps
        let mut previous = self.broadcast_map.previous_subscribed_topics.write();
        let now = HashSet::from_iter(self.broadcast_map.users.read().get_values());

        // Calculate additions and removals
        let added = now.difference(&previous);
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
    pub fn all_brokers(self: &Arc<Self>) -> Vec<BrokerIdentifier> {
        self.brokers
            .clone()
            .into_read_only()
            .keys()
            .cloned()
            .collect()
    }

    /// Insert a broker with its connection into our map.
    pub fn add_broker(
        self: &Arc<Self>,
        broker_identifier: BrokerIdentifier,
        connection: <BrokerProtocol as Protocol>::Sender,
    ) {
        self.brokers.insert(broker_identifier, connection);
    }

    /// Insert a user into our map. Updates the versioned vector that
    /// keeps track of which users are connected where.
    pub fn add_user(
        self: &Arc<Self>,
        user_public_key: Bytes,
        connection: <UserProtocol as Protocol>::Sender,
    ) {
        // Add to our map
        self.users.insert(user_public_key.clone(), connection);

        // Insert into our direct map
        self.direct_map
            .write()
            .insert(user_public_key, self.identity.clone());
    }

    /// Remove a broker from our map by their identifier. Also removes them
    /// from our broadcast map, in case they were subscribed to any topics.
    pub fn remove_broker(self: &Arc<Self>, broker_identifier: &BrokerIdentifier) {
        // Remove from broker list
        self.brokers.remove(broker_identifier);

        // Remove from all topics
        self.broadcast_map
            .brokers
            .write()
            .remove_key(broker_identifier);
    }

    /// Remove a user from our map by their public key. Also removes them
    /// from our broadcast map, in case they were subscribed to any topics, and
    /// the versioned vector map. This is so other brokers don't keep trying
    /// to send us messages for a disconnected user.
    pub fn remove_user(self: &Arc<Self>, user_public_key: Bytes) {
        // Remove from user list
        self.users.remove(&user_public_key);

        // Remove from user topics
        self.broadcast_map
            .users
            .write()
            .remove_key(&user_public_key);

        // Remove from direct map if they're connected to us
        self.direct_map
            .write()
            .remove_if_equals(user_public_key, self.identity.clone());
    }

    /// Locally subscribe a broker to some topics.
    pub fn subscribe_broker_to(
        &self,
        broker_identifier: &BrokerIdentifier,
        topics: Vec<Topic>,
    ) {
        self.broadcast_map
            .brokers
            .write()
            .associate_key_with_values(broker_identifier, topics);
    }

    /// Locally subscribe a user to some topics.
    pub fn subscribe_user_to(&self, user_public_key: &Bytes, topics: Vec<Topic>) {
        self.broadcast_map
            .users
            .write()
            .associate_key_with_values(user_public_key, topics);
    }

    /// Locally unsubscribe a broker from some topics.
    pub fn unsubscribe_broker_from(
        &self,
        broker_identifier: &BrokerIdentifier,
        topics: &[Topic],
    ) {
        self.broadcast_map
            .brokers
            .write()
            .dissociate_keys_from_value(broker_identifier, topics);
    }

    /// Locally unsubscribe a broker from some topics.
    pub fn unsubscribe_user_from(&self, user_public_key: &Bytes, topics: Vec<Topic>) {
        self.broadcast_map
            .users
            .write()
            .dissociate_keys_from_value(user_public_key, &topics);
    }

    /// Send a message to all currently connected brokers. On failure,
    /// the broker will be removed.
    pub fn send_to_brokers(self: &Arc<Self>, message: &Bytes) {
        // Get our list of brokers
        let brokers = self.brokers.clone().into_read_only();

        // For each broker,
        for connection in brokers.iter() {
            // Clone things we will need downstream
            let message = message.clone();
            let broker_identifier = connection.0.clone();
            let connection = connection.1.clone();
            let inner = self.clone();

            // Spawn a task to send the message
            spawn(async move {
                if let Err(err) = connection.send_message_raw(message).await {
                    // If we fail, remove the broker from our map.
                    error!("broker send failed: {err}");
                    inner.remove_broker(&broker_identifier);
                };
            });
        }
    }

    /// Send a message to a particular broker. If it fails, remove the broker from our map.
    pub fn send_to_broker(self: &Arc<Self>, broker_identifier: &BrokerIdentifier, message: Bytes) {
        // If we are connected to them,
        if let Some(connection) = self.brokers.get(broker_identifier) {
            // Clone things we need
            let connection = connection.clone();
            let inner = self.clone();
            let broker_identifier = broker_identifier.clone();

            // Spawn a task to send the message
            spawn(async move {
                if let Err(err) = connection.send_message_raw(message).await {
                    // Remove them if we failed to send it
                    error!("broker send failed: {err}");
                    inner.remove_broker(&broker_identifier);
                };
            });
        }
    }

    /// Send a message to a user connected to us.
    /// If it fails, the user is removed from our map.
    pub fn send_to_user(self: &Arc<Self>, user_public_key: Bytes, message: Bytes) {
        // See if the user is connected
        if let Some(connection) = self.users.get(&user_public_key) {
            // If they are, clone things we will need
            let connection = connection.clone();
            let inner = self.clone();

            // Spawn a task to send the message
            spawn(async move {
                if connection.send_message_raw(message).await.is_err() {
                    // If we fail to send the message, remove the user.
                    inner.remove_user(user_public_key);
                };
            });
        }
    }

    /// Send a direct message to either a user or a broker. First figures out where the message
    /// is supposed to go, and then sends it. We have `to_user_only` bounds so we can stop thrashing;
    /// if we receive a message from a broker we should only be forwarding it to applicable users.
    pub fn send_direct(
        self: &Arc<Self>,
        user_public_key: UserPublicKey,
        message: Bytes,
        to_user_only: bool,
    ) {
        // Look up from our map
        if let Some(broker_identifier) = self.direct_map.read().get(&user_public_key) {
            if *broker_identifier == self.identity {
                // We own the user, send it this way
                self.send_to_user(user_public_key, message);
            } else {
                // If we don't have the stipulation to send it to ourselves only
                // This is so we don't thrash between brokers
                if !to_user_only {
                    // Send to the broker responsible
                    self.send_to_broker(broker_identifier, message);
                }
            }
        } else {
            // Warn if the recipient user did not exist.
            // TODO: remove this
            warn!("user {} did not exist in map", mnemonic(&user_public_key));
        }
    }

    /// Send a broadcast message to both users and brokers. First figures out where the message
    /// is supposed to go, and then sends it. We have `to_user_only` bounds so we can stop thrashing;
    /// if we receive a message from a broker we should only be forwarding it to applicable users.
    pub fn send_broadcast(
        self: &Arc<Self>,
        mut topics: Vec<Topic>,
        message: &Bytes,
        to_users_only: bool,
    ) {
        // Deduplicate topics
        topics.dedup();

        // Aggregate recipients
        let mut broker_recipients = HashSet::new();
        let mut user_recipients = HashSet::new();

        for topic in topics {
            // If we can send to brokers, we should do it
            if !to_users_only {
                broker_recipients
                    .extend(self.broadcast_map.brokers.read().get_keys_by_value(&topic));
            }
            user_recipients.extend(self.broadcast_map.users.read().get_keys_by_value(&topic));
        }

        // If we can send to brokers, do so
        if !to_users_only {
            // Send to all brokers
            for broker in broker_recipients {
                self.send_to_broker(&broker, message.clone());
            }
        }

        // Send to all aggregated users
        for user in user_recipients {
            self.send_to_user(user, message.clone());
        }
    }
}
