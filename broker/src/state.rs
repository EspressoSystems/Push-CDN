//! The following crate defines the internal state-tracking primitives as used
//! by the broker.

use std::{collections::HashSet, sync::Arc};

use proto::{
    connection::{batch::BatchedSender, protocols::Protocol},
    message::Topic,
};
use slotmap::{DefaultKey, DenseSlotMap};

use crate::map::{SnapshotMap, SnapshotWithChanges};

macro_rules! extend {
    ($lookup: expr, $key: expr, $values: expr) => {{
        if let Some(values) = $lookup.get_mut(&$key) {
            // If it exists, extend it
            values.extend($values);
        } else {
            // Insert a new hashset if it doesn't exist
            $lookup.insert($key, HashSet::from_iter($values));
        }
    }};
}

macro_rules! remove_connection_from {
    ($connection_id:expr, $field:expr, $map: expr) => {{
        // For each set, remove the connection ID from it
        for item in $field {
            // Get the set, expecting it to exist
            let relevant_connection_ids = $map.get_mut(&item).expect("object to exist");

            // Remove our connection ID
            relevant_connection_ids.remove(&$connection_id);
            // Remove the topic if it's empty
            if relevant_connection_ids.is_empty() {
                $map.remove(&item);
            }
        }
    }};
}

struct Connection<ProtocolType: Protocol> {
    inner: Arc<BatchedSender<ProtocolType>>,
    keys: HashSet<Vec<u8>>,
    topics: HashSet<Topic>,
    id: DefaultKey,
}

/// `ConnectionLookup` is what we use as a broker to "look up" where messages are supposed
/// to be directed to.
pub struct ConnectionLookup<ProtocolType: Protocol> {
    connections: DenseSlotMap<DefaultKey, Connection<ProtocolType>>,

    key_to_connection_ids: SnapshotMap<Vec<u8>, HashSet<DefaultKey>>,
    topic_to_connection_ids: SnapshotMap<Topic, HashSet<DefaultKey>>,
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
    pub fn get_connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn get_key_updates_since(&mut self) -> SnapshotWithChanges<Vec<u8>> {
        // Get the difference since last call
        self.key_to_connection_ids.difference()
    }

    pub fn get_topic_updates_since(&mut self) -> SnapshotWithChanges<Topic> {
        // Get the difference since last call
        self.topic_to_connection_ids.difference()
    }

    pub fn get_all_connections(&self) -> Vec<(DefaultKey, Arc<BatchedSender<ProtocolType>>)> {
        // Iterate and collect every connection, cloning it
        self.connections
            .values()
            .map(|conn| (conn.id, conn.inner.clone()))
            .collect()
    }

    pub fn add_connection(&mut self, connection: Arc<BatchedSender<ProtocolType>>) -> DefaultKey {
        // Add the connection with no keys and no topics
        self.connections.insert_with_key(|id| Connection {
            inner: connection,
            keys: HashSet::default(),
            topics: HashSet::default(),
            id,
        })
    }

    pub fn remove_connection(
        &mut self,
        connection_id: DefaultKey,
    ) -> Option<Arc<BatchedSender<ProtocolType>>> {
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

    pub fn subscribe_connection_id_to_topics(
        &mut self,
        connection_id: DefaultKey,
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

    pub fn subscribe_connection_id_to_keys(
        &mut self,
        connection_id: DefaultKey,
        keys: Vec<Vec<u8>>,
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

    pub fn get_connections_by_key(
        &self,
        key: &Vec<u8>,
    ) -> Vec<(DefaultKey, Arc<BatchedSender<ProtocolType>>)> {
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

    pub fn get_connections_by_topic(
        &self,
        topics: Vec<Topic>,
    ) -> Vec<(DefaultKey, Arc<BatchedSender<ProtocolType>>)> {
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

        // Return
        connections
    }

    pub fn unsubscribe_connection_id_from_topics(
        &mut self,
        connection_id: DefaultKey,
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

    pub fn unsubscribe_connection_id_from_keys(
        &mut self,
        connection_id: DefaultKey,
        keys: Vec<Vec<u8>>,
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
}

#[cfg(test)]
pub mod test {}
