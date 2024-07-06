// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

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
            // For each value that was associated,
            for v in vs {
                if let Some(ks) = self.value_to_keys.get_mut(&v) {
                    // Remove the key that was associated with the value
                    ks.remove(k);

                    // If the value is empty, remove it
                    if ks.is_empty() {
                        self.value_to_keys.remove(&v);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
// Makes tests more readable
#[allow(clippy::unnecessary_get_then_check)]
pub mod tests {
    use super::RelationalMap;

    macro_rules! vec_equal {
        ($a: expr, $b: expr) => {
            assert!($b.iter().all(|item| $a.contains(item)));
            assert!($a.iter().all(|item| $b.contains(item)));
        };
    }

    #[test]
    fn test_relational() {
        let mut map: RelationalMap<&str, u64> = RelationalMap::new();

        // Associate "user0" with 0 and "user1" with 1
        map.associate_key_with_values(&"user0", vec![0, 1, 2]);
        map.associate_key_with_values(&"user1", vec![1, 2]);

        // Check that "user0" is only user associated with 0
        assert!(
            map.get_keys_by_value(&0) == vec!["user0"],
            "expected only user0 to be associated with value 0"
        );

        // Check that both users are associated with 1
        vec_equal!(map.get_keys_by_value(&1), ["user0", "user1"]);

        // Dissociate "user0" from 1
        map.dissociate_keys_from_value(&"user0", &[1]);

        // Check that only "user1" is now associated with 1
        assert!(
            map.get_keys_by_value(&1) == vec!["user1"],
            "expected user1 to be singularly associated with value 1"
        );

        // Remove "user1"
        map.remove_key(&"user1");

        // Check that 2 is still associated with user0
        vec_equal!(map.get_keys_by_value(&2), ["user0"]);

        // Dissociate "user0" from 2
        map.dissociate_keys_from_value(&"user0", &[2]);

        // Check that nobody is associated with 1
        assert!(
            map.get_keys_by_value(&1).is_empty(),
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
            map.key_to_values.is_empty(),
            "expected `key_to_values` to be empty"
        );

        // Assert zero values to key
        assert!(
            map.value_to_keys.is_empty(),
            "expected `value_to_keys` to be empty"
        );
    }

    #[test]
    fn test_relational_association() {
        let mut map: RelationalMap<&str, u64> = RelationalMap::new();

        // Associate "user0" with 0 and "user1" with 1
        map.associate_key_with_values(&"user0", vec![0, 1, 2]);
        map.associate_key_with_values(&"user1", vec![1, 2]);

        // Dissociate "user0" from 1
        map.dissociate_keys_from_value(&"user0", &[1]);

        // Check value-to-key associations
        vec_equal!(map.get_keys_by_value(&0), ["user0"]);
        vec_equal!(map.get_keys_by_value(&1), ["user1"]);
        vec_equal!(map.get_keys_by_value(&2), ["user0", "user1"]);

        // Check key-to-value associations
        vec_equal!(
            map.key_to_values.get(&"user1").expect("user1 not found"),
            [1, 2]
        );
        vec_equal!(
            map.key_to_values.get(&"user0").expect("user0 not found"),
            [0, 2]
        );

        // Check that there are 3 values
        assert!(map.get_values().len() == 3, "expected 3 values");

        // Check that there are 2 keys
        assert!(map.key_to_values.len() == 2, "expected 2 keys");

        // Dissociate "user0" from 0
        map.dissociate_keys_from_value(&"user0", &[0]);

        // Check value-to-key associations
        vec_equal!(map.get_keys_by_value(&0), []);
        vec_equal!(map.get_keys_by_value(&1), ["user1"]);
        vec_equal!(map.get_keys_by_value(&2), ["user0", "user1"]);

        // Check key-to-value associations
        vec_equal!(
            map.key_to_values.get(&"user1").expect("user1 not found"),
            [1, 2]
        );
        vec_equal!(
            map.key_to_values.get(&"user0").expect("user0 not found"),
            [2]
        );

        // Check that there are 2 values
        vec_equal!(map.get_values(), [1, 2]);

        // Dissociate "user1" from everything
        map.dissociate_keys_from_value(&"user1", &[1, 2]);

        // Check value-to-key associations
        vec_equal!(map.get_keys_by_value(&0), []);
        vec_equal!(map.get_keys_by_value(&1), []);
        vec_equal!(map.get_keys_by_value(&2), ["user0"]);

        // Check key-to-value associations
        assert!(map.key_to_values.get(&"user1").is_none());
        vec_equal!(
            map.key_to_values.get(&"user0").expect("user0 not found"),
            [2]
        );
    }

    #[test]
    fn test_relational_remove() {
        let mut map: RelationalMap<&str, u64> = RelationalMap::new();

        // Associate "user0" and "user1"
        map.associate_key_with_values(&"user0", vec![0, 1, 2]);
        map.associate_key_with_values(&"user1", vec![1, 2, 3]);

        // Assert that the users are associated with the proper values
        vec_equal!(
            map.key_to_values.get(&"user0").expect("user0 not found"),
            [0, 1, 2]
        );
        vec_equal!(
            map.key_to_values.get(&"user1").expect("user0 not found"),
            [1, 2, 3]
        );

        // Assert that the values are associated with the proper users
        vec_equal!(map.value_to_keys.get(&0).expect("0 not found"), ["user0"]);
        vec_equal!(
            map.value_to_keys.get(&1).expect("1 not found"),
            ["user0", "user1"]
        );
        vec_equal!(
            map.value_to_keys.get(&2).expect("2 not found"),
            ["user0", "user1"]
        );
        vec_equal!(map.value_to_keys.get(&3).expect("2 not found"), ["user1"]);

        // Remove "user1"
        map.remove_key(&"user1");

        // Assert that the users are associated with the proper values
        vec_equal!(
            map.key_to_values.get(&"user0").expect("user0 not found"),
            [0, 1, 2]
        );
        // Assert user1 is no longer in the map
        assert!(
            map.key_to_values.get(&"user1").is_none(),
            "expected user1 to be removed"
        );

        // Assert that the values are associated with the proper users
        vec_equal!(map.value_to_keys.get(&0).expect("0 not found"), ["user0"]);
        vec_equal!(map.value_to_keys.get(&1).expect("1 not found"), ["user0"]);
        vec_equal!(map.value_to_keys.get(&2).expect("2 not found"), ["user0"]);
        assert!(map.value_to_keys.get(&3).is_none());

        // Assert that 3 is no longer in the map
        assert!(
            !map.get_values().contains(&3),
            "expected 3 to be removed from values"
        );

        // Remove "user0"
        map.remove_key(&"user0");

        // Assert that the user is no longer in the map
        assert!(
            map.key_to_values.get(&"user0").is_none(),
            "expected user0 to be removed"
        );

        // Assert that the values are associated with the proper users
        assert!(
            map.value_to_keys.is_empty(),
            "expected all values to be removed"
        );
    }
}
