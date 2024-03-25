//! This is where we define routing for broadcast messages.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use cdn_proto::{connection::UserPublicKey, discovery::BrokerIdentifier, message::Topic};
use parking_lot::RwLock;

/// Our broadcast map is just two associative (bidirectional, multi) maps:
/// one for brokers and one for users.
pub struct BroadcastMap {
    pub users: RwLock<RelationalMap<UserPublicKey, Topic>>,
    pub brokers: RwLock<RelationalMap<BrokerIdentifier, Topic>>,

    pub previous_subscribed_topics: RwLock<HashSet<Topic>>,
}

/// Default for our map just wraps the items with locks.
impl Default for BroadcastMap {
    fn default() -> Self {
        Self {
            users: RwLock::from(RelationalMap::new()),
            brokers: RwLock::from(RelationalMap::new()),
            previous_subscribed_topics: RwLock::from(HashSet::new()),
        }
    }
}

/// The new implementation just uses default
impl BroadcastMap {
    pub fn new() -> Self {
        Self::default()
    }
}

/// A relational, bidirectional multimap that relates keys to a set of values,
/// and values to a set of keys.
pub struct RelationalMap<K: Hash + PartialEq + Eq + Clone, V: Hash + PartialEq + Eq + Clone> {
    key_to_values: HashMap<K, HashSet<V>>,
    value_to_keys: HashMap<V, HashSet<K>>,
}

/// We can't deive this
impl<K: Hash + PartialEq + Eq + Clone, V: Hash + PartialEq + Eq + Clone> Default
    for RelationalMap<K, V>
{
    fn default() -> Self {
        Self {
            key_to_values: HashMap::new(),
            value_to_keys: HashMap::new(),
        }
    }
}

impl<K: Hash + PartialEq + Eq + Clone, V: Hash + PartialEq + Eq + Clone> RelationalMap<K, V> {
    /// Create a new, empty `RelationalMap`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get keys aggregated by the provided value. Returns a
    /// vector of all associated keys.
    pub fn get_keys_by_value(&self, v: &V) -> Vec<K> {
        // Just get the value and sum the keys over it
        self.value_to_keys
            .get(v)
            .unwrap_or(&HashSet::new())
            .iter()
            .cloned()
            .collect()
    }

    /// Get all values currently existing in the map. Is O(1) because it
    /// just clones the keys, which we have already indexed.
    pub fn get_values(&self) -> Vec<V> {
        // Clone the keys and collect them
        self.value_to_keys.keys().cloned().collect()
    }

    /// Bidirectionally associate a key in the map with a value.
    pub fn associate_key_with_values(&mut self, k: &K, vs: Vec<V>) {
        // Insert the key if it doesn't exist
        self.key_to_values
            .entry(k.clone())
            .or_default()
            .extend(vs.clone());

        // Extend each key by inserting the value
        for v in vs {
            self.value_to_keys.entry(v).or_default().insert(k.clone());
        }
    }

    /// Bidirectionally dissociate a key in the map with a value.
    pub fn dissociate_keys_from_value(&mut self, k: &K, vs: &[V]) {
        // For each value,
        for v in vs {
            // Get the keys associated with the value
            if let Some(ks) = self.value_to_keys.get_mut(v) {
                // Remove the keys from the value
                ks.remove(k);

                // If we're empty, remove the value
                if ks.is_empty() {
                    self.value_to_keys.remove(v);
                }
            }
        }

        // Remove values associated with that key
        if let Some(k_vs) = self.key_to_values.get_mut(k) {
            for v in vs {
                k_vs.remove(v);
            }
            // If we have no more values, remove the key
            if k_vs.is_empty() {
                self.key_to_values.remove(k);
            }
        }
    }

    /// Bidirectionally remove a key, dissociating it from
    /// all values.
    pub fn remove_key(&mut self, k: &K) {
        // If the key exists, remove it
        if let Some(vs) = self.key_to_values.remove(k) {
            // For each value that was associated, remove the value
            for v in &vs {
                self.value_to_keys.remove(v);
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::RelationalMap;

    macro_rules! vec_equal {
        ($a: expr, $b: expr) => {
            assert!($b.iter().all(|item| $a.contains(item)));
        };
    }

    #[test]
    fn test_relational_map() {
        let mut map: RelationalMap<&str, u64> = RelationalMap::new();

        // Associate "user0" with 0 and "user1" with 1
        map.associate_key_with_values(&"user0", vec![0, 1]);
        map.associate_key_with_values(&"user1", vec![1]);

        // Check that "user0" is only user associated with 0
        assert!(
            map.get_keys_by_value(&0) == vec!["user0"],
            "expected only user0 to be associated with value 0"
        );

        // Check that both users are associated with 1
        vec_equal!(map.get_keys_by_value(&1), vec!["user0", "user1"]);

        // Dissociate "user0" from 1
        map.dissociate_keys_from_value(&"user0", &[1]);

        // Check that only "user1" is now associated with 1
        assert!(
            map.get_keys_by_value(&1) == vec!["user1"],
            "expected user1 to be singularly associated with value 1"
        );

        // Remove "user1"
        map.remove_key(&"user1");

        // Check that nobody is associated with 1
        assert!(
            map.get_keys_by_value(&1).len() == 0,
            "expected no user to be associated with value 1"
        );

        // Check that there is no longer a value 1
        assert!(
            !map.get_values().contains(&1),
            "expected values to no longer contain 1"
        );

        // Assert only one key to value
        assert!(
            map.key_to_values.len() == 1,
            "expected `key_to_values` to be equal to length 1"
        );

        // Assert only one value to key
        assert!(
            map.value_to_keys.len() == 1,
            "expected `value_to_keys` to be equal to length 1"
        );

        // Dissociate "user1" from 1
        map.dissociate_keys_from_value(&"user0", &[0]);

        // Assert zero keys to value
        assert!(
            map.key_to_values.len() == 0,
            "expected `key_to_values` to be empty"
        );

        // Assert zero values to key
        assert!(
            map.value_to_keys.len() == 0,
            "expected `value_to_keys` to be empty"
        );
    }
}
