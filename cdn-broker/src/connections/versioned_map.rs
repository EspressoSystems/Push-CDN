//! This map defines our implementation of a map for making use
//! of versioned vectors. This lets us become eventually consistent
//! over connected user data.

use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

use derivative::Derivative;
use rkyv::{Archive, Deserialize, Serialize};

/// A tombstone is just a removed value.
type Tombstone<T> = Option<T>;

/// A `VersionedValue` defines a value with a global version that
/// we use for syncing purposes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Archive)]
#[archive(check_bytes)]
pub struct VersionedValue<T> {
    version: u64,
    value: Tombstone<T>,
}

#[derive(Clone, Archive, Serialize, Deserialize, Derivative)]
#[archive(check_bytes)]
#[derivative(PartialEq)]
/// A data structure responsible for remaining eventually consistent. It does this by
/// tracking version vectors for each value, and provides functions to help merge,
/// resolve conflicts, and generate deltas to send over the wire.
pub struct VersionedMap<K: Eq + Hash + Debug, V: Debug, C> {
    /// The actual underlying map that we pull values from when needed
    pub underlying_map: HashMap<K, VersionedValue<V>>,

    /// The locally modified keys that we use when calculating the delta. We can skip
    /// `PartialEq` for testing purposes.
    #[derivative(PartialEq = "ignore")]
    locally_modified_keys: HashSet<K>,

    /// The conflict identity for resolving conflicts. If there is a conflict, the higher value wins.
    /// There are no guarantees on what happens when two actors of the same identity try to make changes.
    #[derivative(PartialEq = "ignore")]
    conflict_identity: C,
}

impl<
        K: PartialEq + Eq + Hash + Clone + Debug,
        V: Clone + PartialEq + Debug,
        C: Clone + PartialOrd,
    > VersionedMap<K, V, C>
{
    /// Create a new `VersionedMap` from a conflict identity. We use this to resolve conflicts, if any arise.
    pub fn new(conflict_identity: C) -> Self {
        Self {
            underlying_map: HashMap::new(),
            locally_modified_keys: HashSet::new(),
            conflict_identity,
        }
    }

    /// Get a value from the underlying map, returning it as an optional reference. This maintains parity with
    /// `HashMap`.
    pub fn get(&self, k: &K) -> Option<&V> {
        // Get the value, returning it as a reference if it exists.
        self.underlying_map
            .get(k)
            .and_then(|value| value.value.as_ref())
    }

    /// An internal function used to modify entries internally. It logs the change so we can send to others.
    fn modify_local(&mut self, k: K, v: Option<V>) {
        match self.underlying_map.entry(k.clone()) {
            // If there is an existing entry,
            Entry::Occupied(mut entry) => {
                // Get the underlying value
                let entry = entry.get_mut();

                // If we haven't already made an unsynced local modification
                if !self.locally_modified_keys.contains(&k) {
                    // Add one to the version
                    entry.version += 1;
                }

                // Set the version equal to the one we supplied
                entry.value = v;
            }

            // If there isn't already an entry,
            Entry::Vacant(entry) => {
                // Insert it with a version of `1`.
                entry.insert(VersionedValue {
                    version: 1,
                    value: v,
                });
            }
        }

        // Insert it into our locally modified keys, updating the value if it already exists there.
        self.locally_modified_keys.insert(k);
    }

    /// Insert a value into the map. Underneath, we log this so we can send partial updates to other maps
    /// and remain eventually consistent.
    pub fn insert(&mut self, k: K, v: V) {
        self.modify_local(k, Some(v));
    }

    /// Remove a value from the map. Underneath, we log this so we can send partial updates to other maps
    /// and remain eventually consistent.
    pub fn remove(&mut self, k: K) {
        self.modify_local(k, None);
    }

    /// Remove a value from the map IFF it equals `V`.
    pub fn remove_if_equals(&mut self, k: K, v: V) {
        // Get the underlying value
        if let Some(vv) = self.underlying_map.get(&k) {
            // If it exists and equals the supplied value, remove it.
            if vv.value == Some(v) {
                self.remove(k);
            }
        }
    }

    /// Remove all entries from the map where the value equals `V`.
    /// Does not count as a local modification.
    /// TODO: see if we can remove some `.clone()`s here.
    pub fn remove_by_value_no_modify(&mut self, v: &V) {
        // Get all the keys that have the value we want to purge
        let keys: Vec<K> = self
            .underlying_map
            .iter()
            .filter(|(_, vv)| vv.value == Some(v.clone()))
            .map(|(k, _)| k.clone())
            .collect();

        // Remove all associated keys
        for key in keys {
            self.underlying_map.remove(&key);
        }
    }

    /// Get the full underlying map, cloning it. Returns our own conflict identity,
    /// but does not return any of the locally modified keys.
    pub fn get_full(&self) -> Self {
        Self {
            underlying_map: self.underlying_map.clone(),
            locally_modified_keys: HashSet::new(),
            conflict_identity: self.conflict_identity.clone(),
        }
    }

    /// Get the `diff`erence since last time we called it. Returns a `VersionedMap` that
    /// contains the differences as well as our conflict identity.
    pub fn diff(&mut self) -> Self {
        // Take out the locally modified keys
        let locally_modified_keys = std::mem::take(&mut self.locally_modified_keys);
        let mut diff_map = HashMap::new();

        // For each key that has been modified
        for modified_key in locally_modified_keys {
            // If the value exists in the map,
            if let Some(value) = self.underlying_map.get(&modified_key) {
                // Insert it into the map of differences
                diff_map.insert(modified_key.clone(), value.clone());

                // If the value is none,
                if value.value.is_none() {
                    // Remove it from the underlying map. We don't need to keep track of it any more.
                    self.underlying_map.remove(&modified_key);
                }
            }
        }

        // Return the differences as a map, and our conflict identity.
        Self {
            underlying_map: diff_map,
            locally_modified_keys: HashSet::new(),
            conflict_identity: self.conflict_identity.clone(),
        }
    }

    /// Merge the changes from two `VersionedMap`s, keeping only the newest changes. On a conflict,
    /// use the `conflict_identity` to figure out who should get the value.
    pub fn merge(&mut self, remote: Self) -> Vec<K> {
        // We want to return the changes
        let mut changes: Vec<K> = Vec::new();

        // For each `(k,v)` pair that has allegedly changed,
        for (remote_key, remote_value) in remote.underlying_map {
            // If we have a local value for it,
            if let Some(local_value) = self.underlying_map.get_mut(&remote_key) {
                // Compare the remote value's version to ours.
                match remote_value.version.cmp(&local_value.version) {
                    // If the remote version is greater, update our value.
                    Ordering::Greater => {
                        if remote_value.value.is_some() {
                            // Update our value if it is something.
                            local_value.value = remote_value.value;
                            local_value.version = remote_value.version;
                        } else {
                            // Remove if they sent us a tombstone.
                            self.underlying_map.remove(&remote_key);
                        }

                        // Remove it from our locally modified keys, in case we also tried to update it.
                        self.locally_modified_keys.remove(&remote_key);

                        // Push to our changes that we return.
                        changes.push(remote_key);
                    }

                    // If the remote value is equal to our value,
                    Ordering::Equal => {
                        // The value with the bigger conflict identity wins
                        if remote.conflict_identity > self.conflict_identity {
                            // If there is some value,
                            // TODO: duplicate code here and above. macro it?
                            if remote_value.value.is_some() {
                                // Update our value
                                local_value.value = remote_value.value;
                                local_value.version = remote_value.version;
                            } else {
                                // Remove the value if it wa snothing
                                self.underlying_map.remove(&remote_key);
                            }

                            // Remove it from our locally modified keys, in case we also tried to update it.
                            self.locally_modified_keys.remove(&remote_key);
                            // Push to our changes that we return.
                            changes.push(remote_key);
                        }
                    }

                    // If our value is newer, discard the update
                    Ordering::Less => {}
                }
            } else {
                // If we don't have a local value for it already,
                if remote_value.value.is_some() {
                    // If the value is something, insert it
                    self.underlying_map.insert(remote_key.clone(), remote_value);
                    changes.push(remote_key);
                }
            };
        }

        // Return the changes in case we need to do things with them.
        changes
    }
}

#[cfg(test)]
pub mod tests {
    use super::VersionedMap;

    #[test]
    fn test_insert_remove() {
        // Create the map under test
        let mut map: VersionedMap<&str, &str, u64> = VersionedMap::new(0);

        // Insert "user0" as having "broker0" value
        map.insert("user0", "broker0");
        assert!(map.get(&"user0") == Some(&"broker0"));

        // Remove "user0"
        map.remove("user0");
        assert!(map.get(&"user0").is_none());
    }

    #[test]
    fn test_conflict() {
        // Create the maps under test
        let mut map_0: VersionedMap<&str, &str, u64> = VersionedMap::new(0);
        let mut map_1: VersionedMap<&str, &str, u64> = VersionedMap::new(1);

        // Insert "user0" as having "broker0" value
        map_0.insert("user0", "broker0");

        // Insert "user0" as having "broker1" value (on map 1)
        map_1.insert("user0", "broker1");

        // Merge the maps, expect higher conflict identity to win
        map_0.merge(map_1.get_full());
        map_1.merge(map_0.get_full());
        assert!(map_0.get(&"user0") == Some(&"broker1"));
        assert!(map_1.get(&"user0") == Some(&"broker1"));
    }

    #[test]
    fn test_partial() {
        // Create the maps under test
        let mut map_0: VersionedMap<&str, &str, u64> = VersionedMap::new(0);
        let mut map_1: VersionedMap<&str, &str, u64> = VersionedMap::new(1);

        // Insert user0 as belonging to broker0
        map_0.insert("user0", "broker0");

        // Get diff, discarding current
        map_0.diff();

        // Insert user1 as belonging to broker0
        map_0.insert("user1", "broker0");

        // Get new diff
        let new_diff = map_0.diff();

        // Merge map_1 with new_diff, expecting user0 to have a value but not user1
        map_1.merge(new_diff);
        assert!(map_1.get(&"user0").is_none());
        assert!(map_1.get(&"user1") == Some(&"broker0"));

        // Full sync, expect now to be present
        map_1.merge(map_0.get_full());
        assert!(map_1.get(&"user0") == Some(&"broker0"));

        // Map 1 removes value, syncs
        map_1.remove("user0");

        // Merge map0 with map 1's diff
        map_0.merge(map_1.diff());

        // Expect user0 to be gone from map0
        assert!(map_0.get(&"user0").is_none());
    }

    #[test]
    fn test_purge() {
        // Create the map under test
        let mut map: VersionedMap<&str, &str, u64> = VersionedMap::new(0);

        // Insert "user0" as having "broker0" value
        map.insert("user0", "broker0");
        assert!(map.get(&"user0") == Some(&"broker0"));

        // Insert "user0" as having "broker0" value
        map.insert("user1", "broker0");
        assert!(map.get(&"user1") == Some(&"broker0"));

        // Insert "user2" as having "broker1" value
        map.insert("user2", "broker1");
        assert!(map.get(&"user2") == Some(&"broker1"));

        // Purge all values that are "broker0"
        map.remove_by_value_no_modify(&"broker0");

        // Expect user0 and user1 to be gone
        assert!(map.get(&"user0").is_none());
        assert!(map.get(&"user1").is_none());

        // Expect user2 to still be present
        assert!(map.get(&"user2") == Some(&"broker1"));

        // Test that the removes didn't count as local modifications
        let diff = map.diff();
        assert!(diff.underlying_map.len() == 1);
    }
}
