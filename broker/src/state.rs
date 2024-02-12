//! The following crate defines the internal state-tracking primitives as used
//! by the broker.

use std::{collections::HashSet, sync::Arc};

use proto::{
    connection::{batch::BatchedSender, protocols::Protocol},
    message::Topic,
};
use slotmap::{DefaultKey, DenseSlotMap};

use crate::map::{SnapshotMap, SnapshotWithChanges};

/// This helps with readability, it just defines a sender
pub type Sender<ProtocolType> = Arc<BatchedSender<ProtocolType>>;

/// These also help with readability.
pub type ConnectionId = DefaultKey;
pub type UserPublicKey = Vec<u8>;

/// This macro is basically `.entry().unwrap_or().extend()`. We need this
/// because it allows us to use our fancy `SnapshotVec` which doesn't implement
/// `entry()`.
macro_rules! extend {
    ($lookup: expr, $key: expr, $values: expr) => {{
        // Look up a value
        if let Some(values) = $lookup.get_mut(&$key) {
            // If it exists, extend it
            values.extend($values);
        } else {
            // Insert a new hashset if it doesn't exist
            $lookup.insert($key, HashSet::from_iter($values));
        }
    }};
}

// This macro helps us remove a connection from a particular map.
// It makes the code easier to look at.
macro_rules! remove_connection_from {
    ($connection_id:expr, $field:expr, $map: expr) => {{
        // For each set, remove the connection ID from it
        for item in $field {
            // Get the set, expecting it to exist
            if let Some(connection_ids) = $map.get_mut(&item) {
                // Remove our connection ID
                connection_ids.remove(&$connection_id);
                // Remove the topic if it's empty
                if connection_ids.is_empty() {
                    $map.remove(&item);
                }
            }
        }
    }};
}

// This is a light wrapper around a connection, which we use to facilitate
// removing from different parts of our state. For example, we store
// `keys`, as "which users are connected to us". When we remove a connection,
// we want to make sure the connection is not pointing to that key any more.
struct Connection<ProtocolType: Protocol> {
    // The actual connection (sender)
    inner: Sender<ProtocolType>,
    // A list of public keys that the sender is linked to
    keys: HashSet<UserPublicKey>,
    // A list of topics that the sender is linked to
    topics: HashSet<Topic>,
    // The stable ID for the connection.
    id: ConnectionId,
}

/// `ConnectionLookup` is what we use as a broker to "look up" where messages are supposed
/// to be directed to.
pub struct ConnectionLookup<ProtocolType: Protocol> {
    /// This `DenseSlotMap` is where we insert the actual connection (indexed by the connection "key").
    /// Slotted maps are basically `HashMaps`, but we only care about using it to index _another_ map,
    /// so the slotted map will give us a value to use on insert. Pretty cool.
    connections: DenseSlotMap<ConnectionId, Connection<ProtocolType>>,

    /// This is where we store the information on how public keys map to some connection IDs.
    /// It uses our fancy `SnapshotMap`, which can return both a list of updates and a full
    /// set if necessary.
    key_to_connection_ids: SnapshotMap<UserPublicKey, HashSet<ConnectionId>>,
    /// This is where we store the information on which topics particular connections care about.
    /// It also uses the `SnapshotMap`.
    topic_to_connection_ids: SnapshotMap<Topic, HashSet<ConnectionId>>,
}

impl<ProtocolType: Protocol> Default for ConnectionLookup<ProtocolType> {
    /// The default imeplementation is to just return empty maps. We need this because
    /// of the trait bounds.
    fn default() -> Self {
        Self {
            connections: DenseSlotMap::new(),
            key_to_connection_ids: SnapshotMap::new(),
            topic_to_connection_ids: SnapshotMap::new(),
        }
    }
}

impl<ProtocolType: Protocol> ConnectionLookup<ProtocolType> {
    /// Returns an empty `ConnectionLookup`
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of connections currently in the map. We use this to
    /// report to `Redis`, so the marshal knows who has the least connections.
    pub fn get_connection_count(&self) -> usize {
        self.connections.len()
    }

    /// This is a proxy function to the `SnapshotMap`. It lets us get the difference
    /// in users connected since last time we called it.
    pub fn get_key_updates_since(&mut self) -> SnapshotWithChanges<UserPublicKey> {
        // Get the difference since last call
        self.key_to_connection_ids.difference()
    }

    /// This is a proxy function to the `SnapshotMap`. It lets us get the difference
    /// in topics we care about since the last time we called it.
    pub fn get_topic_updates_since(&mut self) -> SnapshotWithChanges<Topic> {
        // Get the difference since last call
        self.topic_to_connection_ids.difference()
    }

    /// This lets us get an iterator over all of the connections, along with their unique identifier.
    /// We need this to send information to _all_ brokers when a broker connects.
    ///
    /// It returns a `Vec<(connection id, sender)>`.
    /// TODO: type alias
    pub fn get_all_connections(&self) -> Vec<(ConnectionId, Sender<ProtocolType>)> {
        // Iterate and collect every connection, cloning the necessary values.
        self.connections
            .values()
            .map(|conn| (conn.id, conn.inner.clone()))
            .collect()
    }

    /// Adds a connection to the state. It returns a key (the connection ID) with which
    /// we can use later when we want to reference that connection.
    pub fn add_connection(&mut self, connection: Sender<ProtocolType>) -> ConnectionId {
        // Add the connection with no keys and no topics
        self.connections.insert_with_key(|id| Connection {
            inner: connection,
            keys: HashSet::default(),
            topics: HashSet::default(),
            id,
        })
    }

    /// Removes a connection from the state. We insert the key we got during the insertion process,
    /// and we get back the connection if there was one.
    pub fn remove_connection(
        &mut self,
        connection_id: ConnectionId,
    ) -> Option<Sender<ProtocolType>> {
        // Remove a possible connection by its ID
        let possible_connection = self.connections.remove(connection_id);

        // If the connection exists
        if let Some(ref connection) = possible_connection {
            // For each topic, remove the connection ID from it
            remove_connection_from!(
                connection_id,
                &connection.topics,
                self.topic_to_connection_ids
            );

            // For each key, remove the connection ID from it
            remove_connection_from!(connection_id, &connection.keys, self.key_to_connection_ids);
        }

        // If it exists, return the actual connection we care about for `remove` parity.
        possible_connection.map(|conn| conn.inner)
    }

    /// Subscribes a connection to a list of topics, given both the
    /// connection ID and the list of topics.
    pub fn subscribe_connection_id_to_topics(
        &mut self,
        connection_id: ConnectionId,
        topics: Vec<Topic>,
    ) {
        // Get the connection, if it exists
        let possible_connection = self.connections.get_mut(connection_id);

        // If the connection exists:
        if let Some(connection) = possible_connection {
            // Add to the connections
            connection.topics.extend(topics.clone());

            // For each topic,
            for topic in topics {
                extend!(self.topic_to_connection_ids, topic, vec![connection_id]);
            }
        }
    }

    /// Unsubscribe a connection from all topics in the given list.
    pub fn unsubscribe_connection_id_from_topics(
        &mut self,
        connection_id: ConnectionId,
        topics: Vec<Topic>,
    ) {
        // Get the connection, if it exists
        let possible_connection = self.connections.get_mut(connection_id);

        // If the connection exists:
        if let Some(connection) = possible_connection {
            // Remove the connection from the topic
            // Remove the topic if it exists
            remove_connection_from!(connection_id, &topics, self.topic_to_connection_ids);

            // Remove the topic from the connection
            for topic in topics {
                connection.topics.remove(&topic);
            }
        }
    }

    /// Subscribes a connection to a list of user keys, given both the
    /// connection ID and the list of keys. We use this on the broker to bulk subscribe
    /// for a bunch of keys, and on the user side to subscribe to one only.
    pub fn subscribe_connection_id_to_keys(
        &mut self,
        connection_id: ConnectionId,
        keys: Vec<UserPublicKey>,
    ) {
        // Get the connection, if it exists
        let possible_connection = self.connections.get_mut(connection_id);

        // If the connection exists:
        if let Some(connection) = possible_connection {
            // Add to the connections
            connection.keys.extend(keys.clone());

            // For each topic,
            for key in keys {
                extend!(self.key_to_connection_ids, key, vec![connection_id]);
            }
        }
    }

    /// Unsubscribe a connection ID from all keys in the list./
    pub fn unsubscribe_connection_id_from_keys(
        &mut self,
        connection_id: ConnectionId,
        keys: Vec<UserPublicKey>,
    ) {
        // Get the connection, if it exists
        let possible_connection = self.connections.get_mut(connection_id);

        // If the connection exists:
        if let Some(connection) = possible_connection {
            // Remove the connection from the topic
            // Remove the topic if it exists
            remove_connection_from!(connection_id, &keys, self.key_to_connection_ids);

            // Remove the topic from the connection
            for key in keys {
                connection.keys.remove(&key);
            }
        }
    }

    /// Aggregate connections over a list of user keys. This is used to send messages
    /// to users with the corresponding key (generally direct).
    pub fn get_connections_by_key(
        &self,
        key: &UserPublicKey,
    ) -> Vec<(ConnectionId, Sender<ProtocolType>)> {
        // We return this at the end
        let mut connections = Vec::new();

        // Get each connection ID
        for connection_id in self
            .key_to_connection_ids
            .get(key)
            .unwrap_or(&HashSet::new())
        {
            // Get the connection, clone its inner, add it to the running vec
            connections.push((
                *connection_id,
                self.connections
                    .get(*connection_id)
                    .expect("connection id to exist")
                    .inner
                    .clone(),
            ));
        }

        connections
    }

    /// Aggregate connections over a list of topics. This is used to send messages
    /// to users who are subscribed to a particular topic.
    pub fn get_connections_by_topic(
        &self,
        topics: Vec<Topic>,
    ) -> Vec<(ConnectionId, Sender<ProtocolType>)> {
        // We return this at the end
        let mut connections = Vec::new();

        // For each topic,
        for topic in topics {
            // Get each connection ID
            for connection_id in self
                .topic_to_connection_ids
                .get(&topic)
                .unwrap_or(&HashSet::new())
            {
                // Get the connection, clone its inner, add it to the running vec
                // TODO: remove these expects
                connections.push((
                    *connection_id,
                    self.connections
                        .get(*connection_id)
                        .expect("connection id to exist")
                        .inner
                        .clone(),
                ));
            }
        }

        // Return the connections
        connections
    }
}

#[cfg(test)]
pub mod test {
    use std::time::Duration;

    use proto::connection::protocols::{MockProtocol, MockSender};

    use super::*;

    /// A helper macro for mocking a connection. We use this because I didn't want to
    /// have a lot of extra code to fake implement the connection trait.
    macro_rules! mock_connection {
        () => {
            Arc::new(BatchedSender::from(
                MockSender::new(),
                Duration::from_secs(1),
                1200,
            ))
        };
    }

    /// Here is where we test `insert` and `remove` operations for our state map.
    /// We also test subscriptions to both keys and topics.
    /// TODO: I want to add a lot more tests to this.
    #[tokio::test]
    async fn test_insert_remove() {
        // Mock map
        let mut lookup = ConnectionLookup::<MockProtocol>::new();
        let connection = mock_connection!();

        // Count check
        assert!(lookup.get_connection_count() == 0);
        let id1 = lookup.add_connection(connection.clone());
        assert!(lookup.get_connection_count() == 1);
        let id2 = lookup.add_connection(connection.clone());
        assert!(lookup.get_connection_count() == 2);

        // Remove check
        lookup.remove_connection(id1);
        lookup.remove_connection(id2);

        assert!(lookup.get_connection_count() == 0);
    }

    /// Here is where we test subscriptions/unsubscriptions
    #[tokio::test]
    async fn test_subscribe_unsubscribe_key() {
        // Mock map
        let mut lookup = ConnectionLookup::<MockProtocol>::new();

        let connection = mock_connection!();
        let id1 = lookup.add_connection(connection.clone());
        let id2 = lookup.add_connection(connection.clone());

        // Key subscription check
        lookup.subscribe_connection_id_to_keys(id1, vec![vec![0], vec![1]]);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_key(&vec![0])
            .iter()
            .map(|conn| conn.0)
            .collect();
        assert!(connections == vec![id1]);

        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_key(&vec![1])
            .iter()
            .map(|conn| conn.0)
            .collect();
        assert!(connections == vec![id1]);

        // Subscribe key2
        lookup.subscribe_connection_id_to_keys(id2, vec![vec![1]]);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_key(&vec![1])
            .iter()
            .map(|conn| conn.0)
            .collect();
        assert!(connections.contains(&id1));
        assert!(connections.contains(&id2));
        assert!(connections.len() == 2);

        // Check that we're not subscribed to the one we didn't subscribe to
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_key(&vec![0])
            .iter()
            .map(|conn| conn.0)
            .collect();
        assert!(connections == vec![id1]);

        // Unsubscribe key1. Should just be id2.
        lookup.unsubscribe_connection_id_from_keys(id1, vec![vec![1]]);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_key(&vec![1])
            .iter()
            .map(|conn| conn.0)
            .collect();
        assert!(connections == vec![id2]);

        // Remove id2, should be auto-unsubscribed
        // TODO: macro this
        lookup.remove_connection(id2);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_key(&vec![1])
            .iter()
            .map(|conn| conn.0)
            .collect();

        assert!(connections == vec![]);

        lookup.unsubscribe_connection_id_from_keys(id1, vec![vec![0]]);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_key(&vec![0])
            .iter()
            .map(|conn| conn.0)
            .collect();

        assert!(connections == vec![]);
    }

    /// Here is where we test subscriptions/unsubscriptions
    #[tokio::test]
    async fn test_subscribe_unsubscribe_topic() {
        // Mock map
        let mut lookup = ConnectionLookup::<MockProtocol>::new();

        let connection = mock_connection!();
        let id1 = lookup.add_connection(connection.clone());
        let id2 = lookup.add_connection(connection.clone());

        // Key subscription check
        lookup.subscribe_connection_id_to_topics(id1, vec![Topic::Global, Topic::DA]);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_topic(vec![Topic::Global])
            .iter()
            .map(|conn| conn.0)
            .collect();
        assert!(connections == vec![id1]);

        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_topic(vec![Topic::DA])
            .iter()
            .map(|conn| conn.0)
            .collect();
        assert!(connections == vec![id1]);

        // Subscribe key2
        lookup.subscribe_connection_id_to_topics(id2, vec![Topic::DA]);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_topic(vec![Topic::DA])
            .iter()
            .map(|conn| conn.0)
            .collect();
        // TODO: write assert for this
        assert!(connections.contains(&id1));
        assert!(connections.contains(&id2));
        assert!(connections.len() == 2);

        // Check that we're not subscribed to the one we didn't subscribe to
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_topic(vec![Topic::Global])
            .iter()
            .map(|conn| conn.0)
            .collect();
        assert!(connections == vec![id1]);

        // Unsubscribe key1. Should just be id2.
        lookup.unsubscribe_connection_id_from_topics(id1, vec![Topic::DA]);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_topic(vec![Topic::DA])
            .iter()
            .map(|conn| conn.0)
            .collect();
        assert!(connections == vec![id2]);

        // Remove id2, should be auto-unsubscribed
        // TODO: macro this
        lookup.remove_connection(id2);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_topic(vec![Topic::DA])
            .iter()
            .map(|conn| conn.0)
            .collect();

        assert!(connections == vec![]);

        lookup.unsubscribe_connection_id_from_topics(id1, vec![Topic::Global]);
        let connections: Vec<ConnectionId> = lookup
            .get_connections_by_topic(vec![Topic::Global])
            .iter()
            .map(|conn| conn.0)
            .collect();

        assert!(connections == vec![]);
    }
}
