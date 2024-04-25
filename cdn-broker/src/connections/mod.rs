//! This module defines almost all of the connection lookup, addition,
//! and removal process.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use derive_more::Deref;

use cdn_proto::{
    connection::{protocols::Connection as _, Bytes, UserPublicKey},
    def::{Connection, RunDef},
    discovery::BrokerIdentifier,
    message::Topic,
    mnemonic,
};
pub use direct::DirectMap;
use parking_lot::RwLock;
use tokio::{spawn, task::AbortHandle};
use tracing::{debug, error};

use self::broadcast::BroadcastMap;

mod broadcast;
mod direct;
mod versioned;

/// Stores information about all current connections.
#[derive(Deref)]
pub struct Connections<Def: RunDef>(Arc<RwLock<ConnectionsInner<Def>>>);

impl<Def: RunDef> Connections<Def> {
    /// Create a new `Connections`. Requires an identity for
    /// version vector conflict resolution.
    pub fn new(identity: BrokerIdentifier) -> Self {
        Self(Arc::from(RwLock::from(ConnectionsInner {
            identity: identity.clone(),
            users: HashMap::new(),
            brokers: HashMap::new(),
            direct_map: DirectMap::new(identity),
            broadcast_map: BroadcastMap::new(),
        })))
    }

    /// Send a message to all currently connected brokers. On failure,
    /// the broker will be removed.
    pub fn send_to_brokers(&self, message: &Bytes) {
        // For each broker,
        for connection in &self.0.read().brokers {
            // Clone things we will need downstream
            let message = message.clone();
            let broker_identifier = connection.0.clone();
            let connection = connection.1 .0.clone();
            let inner = self.0.clone();

            // Spawn a task to send the message
            spawn(async move {
                if let Err(err) = connection.send_message_raw(message).await {
                    // If we fail, remove the broker from our map.
                    error!("broker send failed: {err}");
                    inner.write().remove_broker(&broker_identifier);
                };
            });
        }
    }

    /// Send a message to a particular broker. If it fails, remove the broker from our map.
    pub fn send_to_broker(&self, broker_identifier: &BrokerIdentifier, message: Bytes) {
        // If we are connected to them,
        if let Some(connection) = self.0.read().brokers.get(broker_identifier) {
            // Clone things we need
            let connection = connection.0.clone();
            let inner = self.0.clone();
            let broker_identifier = broker_identifier.clone();

            // Spawn a task to send the message
            spawn(async move {
                if let Err(err) = connection.send_message_raw(message).await {
                    // Remove them if we failed to send it
                    error!("broker send failed: {err}");
                    inner.write().remove_broker(&broker_identifier);
                };
            });
        }
    }

    /// Send a message to a user connected to us.
    /// If it fails, the user is removed from our map.
    pub fn send_to_user(&self, user_public_key: UserPublicKey, message: Bytes) {
        // See if the user is connected
        if let Some((connection, _)) = self.0.read().users.get(&user_public_key) {
            // If they are, clone things we will need
            let connection = connection.clone();
            let inner = self.0.clone();

            // Spawn a task to send the message
            spawn(async move {
                if connection.send_message_raw(message).await.is_err() {
                    // If we fail to send the message, remove the user.
                    inner.write().remove_user(user_public_key);
                };
            });
        }
    }

    /// Send a direct message to either a user or a broker. First figures out where the message
    /// is supposed to go, and then sends it. We have `to_user_only` bounds so we can stop thrashing;
    /// if we receive a message from a broker we should only be forwarding it to applicable users.
    pub fn send_direct(&self, user_public_key: UserPublicKey, message: Bytes, to_user_only: bool) {
        // Look up from our map
        if let Some(broker_identifier) = self.0.read().direct_map.get(&user_public_key) {
            if *broker_identifier == self.0.read().identity {
                // We own the user, send it this way
                debug!(
                    user = mnemonic(&user_public_key),
                    msg = mnemonic(&*message),
                    "direct",
                );
                self.send_to_user(user_public_key, message);
            } else {
                // If we don't have the stipulation to send it to ourselves only
                // This is so we don't thrash between brokers
                if !to_user_only {
                    debug!(
                        broker = %broker_identifier,
                        msg = mnemonic(&*message),
                        "direct",
                    );
                    // Send to the broker responsible
                    self.send_to_broker(broker_identifier, message);
                }
            }
        } else {
            // Debug warning if the recipient user did not exist.
            debug!(id = mnemonic(&user_public_key), "user did not exist in map");
        }
    }

    /// Send a broadcast message to both users and brokers. First figures out where the message
    /// is supposed to go, and then sends it. We have `to_user_only` bounds so we can stop thrashing;
    /// if we receive a message from a broker we should only be forwarding it to applicable users.
    pub fn send_broadcast(&self, mut topics: Vec<Topic>, message: &Bytes, to_users_only: bool) {
        // Deduplicate topics
        topics.dedup();

        // Aggregate recipients
        let mut broker_recipients = HashSet::new();
        let mut user_recipients = HashSet::new();

        for topic in topics {
            // If we can send to brokers, we should do it
            if !to_users_only {
                broker_recipients.extend(
                    self.0
                        .read()
                        .broadcast_map
                        .brokers
                        .get_keys_by_value(&topic),
                );
            }
            user_recipients.extend(self.0.read().broadcast_map.users.get_keys_by_value(&topic));
        }

        debug!(
            num_brokers = broker_recipients.len(),
            num_users = user_recipients.len(),
            msg = mnemonic(&**message),
            "broadcast",
        );

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

pub struct ConnectionsInner<Def: RunDef> {
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

impl<Def: RunDef> ConnectionsInner<Def> {
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
            println!("aborting broker");
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
            println!("aborting user");

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
