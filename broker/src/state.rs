//! The following crate defines the internal state-tracking primitives as used
//! by the broker.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use proto::{
    connection::{batch::BatchedSender, protocols::Protocol},
    message::Topic,
};

/// `ConnectionLookup` is what we use as a broker to "look up" where messages are supposed
/// to be directed to.
pub struct ConnectionLookup<ProtocolType: Protocol> {
    /// What we use to look up direct messages. The mapping is key -> sender
    key_to_connection: HashMap<Vec<u8>, Arc<BatchedSender<ProtocolType>>>,
    /// Map is sender -> key. Helps us remove a sender on disconnection
    connection_to_keys: HashMap<Arc<BatchedSender<ProtocolType>>, HashSet<Vec<u8>>>,
    /// What we use to look up broadcast messages. The mapping is topic -> set[sender]
    topic_to_connections: HashMap<Topic, HashSet<Arc<BatchedSender<ProtocolType>>>>,
    /// What we use when removing a key in O(1) from the forward broadcast map. The mapping is
    /// sender -> set[topic].
    connection_to_topics: HashMap<Arc<BatchedSender<ProtocolType>>, HashSet<Topic>>,
}

impl<ProtocolType: Protocol> Default for ConnectionLookup<ProtocolType> {
    /// The default imeplementation is to just return empty maps. We need this because
    /// of the trait bounds.
    fn default() -> Self {
        Self {
            key_to_connection: HashMap::default(),
            connection_to_keys: HashMap::default(),
            topic_to_connections: HashMap::default(),
            connection_to_topics: HashMap::default(),
        }
    }
}

impl<ProtocolType: Protocol> ConnectionLookup<ProtocolType> {
    /// Get the count of all keys
    pub fn get_key_count(&self) -> usize{
        self.key_to_connection.len()
    }

    /// This returns all keys we are currently responsible for.
    pub fn get_all_keys(&self) -> Vec<Vec<u8>> {
        // Iterate over every key in the direct lookup and return it.
        self.key_to_connection.keys().cloned().collect()
    }

    /// This returns all topics that we are currently responsible for.
    pub fn get_all_topics(&self) -> Vec<Topic> {
        // TODO: figure out if we need a clone here
        // Iterate over every key in the broadcast lookup and return it.
        self.topic_to_connections.keys().cloned().collect()
    }

    /// This gets the associated connection for a direct message (if existing)
    pub fn get_connection_by_key(&self, key: &Vec<u8>) -> Option<Arc<BatchedSender<ProtocolType>>> {
        // Look up the direct message key and return it.
        self.key_to_connection.get(key).cloned()
    }

    /// Subscribe a connection to some keys. This is used on the broker end
    /// when we receive either a connection from that user, or the message that a broker
    /// is interested in a particular user.
    pub fn subscribe_connection_to_keys(
        &mut self,
        connection: &Arc<BatchedSender<ProtocolType>>,
        keys: Vec<Vec<u8>>,
    ) {
        for key in keys {
            // Insert to the direct message lookup
            self.key_to_connection.insert(key.clone(), connection.clone());

            // Insert to the inverse
            self.connection_to_keys
                .entry(connection.clone())
                .or_default()
                .insert(key);
        };
    }

    /// Unsubscribe a connection from a particular key. This is used on the broker end
    /// when we lose a connection to a user, or a broker says they're not interested anymore.
    pub fn unsubscribe_connection_from_keys(&mut self, keys: Vec<Vec<u8>>) {
        for key in keys {
            // Remove the key from the lookup
            self.key_to_connection.remove(&key);
        }
    }

    /// Fully unsubscribes a connection from all messages. Used to completely wipe a connection
    /// when we are disconnected.
    pub fn unsubscribe_connection(&mut self, connection: &Arc<BatchedSender<ProtocolType>>) {
        if let Some(keys) = self.connection_to_keys.remove(connection) {
            for key in keys {
                self.key_to_connection.remove(&key);
            }
        };

        if let Some(topics) = self.connection_to_topics.remove(connection) {
            for topic in topics {
                self.topic_to_connections.remove(&topic);
            }
        }
    }

    /// Look up the connections that are interested in a particular topic so we can
    /// broadcast messages.
    pub fn get_connections_by_topic(
        &self,
        topics: Vec<Topic>,
    ) -> HashSet<Arc<BatchedSender<ProtocolType>>> {
        let mut all_connections = HashSet::new();

        // Since we don't want the intersection, iterate and add over every topic
        for topic in topics {
            // If the topic exists, add to our collection of connections.
            if let Some(connections) = self.topic_to_connections.get(&topic) {
                all_connections.extend(connections.clone());
            }
        }

        all_connections
    }

    /// This subscribes a particular connection to some topics.
    pub fn subscribe_connection_to_topics(
        &mut self,
        connection: Arc<BatchedSender<ProtocolType>>,
        topics: Vec<Topic>,
    ) {
        // Add the connection to each topic.
        // topic -> [connection]
        for topic in topics.clone() {
            self.topic_to_connections
                .entry(topic)
                .or_default()
                .insert(connection.clone());
        }
        // Add each topic to the connection (this is for O(1) removal later)
        // connection -> [topic]
        self.connection_to_topics
            .entry(connection)
            .or_default()
            .extend(topics);
    }

    /// This unsubscribes a particular connection from a topic.
    pub fn unsubscribe_connection_from_topics(
        &mut self,
        connection: &Arc<BatchedSender<ProtocolType>>,
        topics: Vec<Topic>,
    ) {
        // For each topic, remove connection from it.
        // topic -> [connection]
        for topic in topics.clone() {
            // Remove connection from topic
            if let Some(connections) = self.topic_to_connections.get_mut(&topic) {
                connections.remove(connection);
            }
        }

        // Remove the topic from the connection, if existing.
        // key -> [topic]
        if let Some(connection_topics) = self.connection_to_topics.get_mut(connection) {
            for topic in topics {
                connection_topics.remove(&topic);
            }
        }
    }
}
