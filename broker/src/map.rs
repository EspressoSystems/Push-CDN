//! This is where we define the `SnapShotMap` implementation, a struct
//! that allows us to get full and partial updates on the list of keys in a map.
//!
//! We use this in broker <-> broker communication to save bandwidth, wherein
//! we only need to send partial updates over the wire.

use std::{
    cmp::Ordering,
    collections::HashMap,
    hash::Hash,
    ops::{AddAssign, SubAssign},
};

use delegate::delegate;

/// A primitive that allows us to get full and partial updates on the list
/// of keys in a map. It's a write-ahead-log that automatically prunes. This is helpful
/// for broker <-> broker communication, where we don't want to send the whole list every time.
pub struct SnapshotMap<K: Eq + PartialEq + Hash + Clone, V> {
    /// The previous snapshot, which is moved out when we calculate the difference.
    snapshot: Vec<K>,

    /// The log of operations, which we sum up and run calculations over to determine
    /// the actual (delta) difference. For example, if we have `Add(User(1)), Remove(User(1)) Add(User(1))`,
    /// the calculated output will be just `Add(User(1))`.
    log: Vec<Operation<K>>,

    /// The actual underlying `HashMap`, which contains the data.
    inner: HashMap<K, V>,
}

/// Represents an action taken on the inner map.
pub enum Operation<K> {
    /// An item was inserted to the map.
    Insert(K),
    /// An item was removed from the map.
    Remove(K),
}

/// The actual snapshot. Contains both the previous snapshot and
/// a list of insertions and removals _since_ that snapshot.
pub struct SnapshotWithChanges<K> {
    /// The previous snapshot
    pub snapshot: Vec<K>,
    /// Key insertions since the previous snapshot
    pub insertions: Vec<K>,
    /// Key removals since the previous snapshot
    pub removals: Vec<K>,
}

impl<K: Eq + PartialEq + Hash + Clone, V> SnapshotMap<K, V> {
    /// Create a new `SnapshotMap`.
    pub fn new() -> Self {
        Self {
            log: Vec::new(),
            inner: HashMap::new(),
            snapshot: Vec::new(),
        }
    }

    /// Insert an item into the `SnapshotMap`, returning the
    /// old value if there was one. Under the hood, it logs
    /// an `Insert()` operation.
    pub fn insert(&mut self, key: K, val: V) -> Option<V> {
        // Insert the value, saving to return for later.
        let res = self.inner.insert(key.clone(), val);

        if res.is_none() {
            // If the key wasn't already in our map, update the log
            self.log.push(Operation::Insert(key));
        }

        res
    }

    /// Remove an item from the `SnapshotMap`, returning the
    /// removed value if there was one. Under the hood, we add a
    /// `Remove` operation to the log as well.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        // Remove the value, saving the output for later.
        let res = self.inner.remove(key);

        if res.is_some() {
            // If the key existed, add a remove operation
            self.log.push(Operation::Remove(key.clone()));
        }

        res
    }

    /// Calculates the difference between the last time this was called. Returns
    /// a `SnapshotWithChanges`, which is both the old snapshot and a list of changes
    /// since the current one.
    pub fn difference(&mut self) -> SnapshotWithChanges<K> {
        // Take our inner logs, replacing with nothing.
        let logs = std::mem::take(&mut self.log);

        // Count the amount of each log for a particular key.
        let mut changes = HashMap::new();
        for log in logs {
            match log {
                Operation::Insert(item) => changes.entry(item).or_insert(0).add_assign(1),
                Operation::Remove(item) => changes.entry(item).or_insert(0).sub_assign(1),
            }
        }

        // Check the number of insertions and removals, and prune the log based on that.
        // This only works because we do not log an event for a key that was unchanged.
        let mut insertions = Vec::new();
        let mut removals = Vec::new();
        for change in changes {
            // Compare to 0.
            match change.1.cmp(&0) {
                Ordering::Greater => {
                    // If we are bigger than zero, we ended on an insertion. So make this part of the pruned log.
                    insertions.push(change.0);
                }

                Ordering::Less => {
                    // If we are less than zero, we ended on an removal. So make this part of the pruned log.
                    removals.push(change.0);
                }

                // If we are zero, do nothing
                Ordering::Equal => {}
            }
        }

        // Replace the snapshot with the current data and return the insertions and removals.
        SnapshotWithChanges {
            snapshot: std::mem::replace(&mut self.snapshot, self.inner.keys().cloned().collect()),
            insertions,
            removals,
        }
    }

    // We use this to delegate `get()` and `get_mut()` methods to the lower `HashMap`, as we don't
    // actually need to log those events.
    delegate! {
        to self.inner {
            pub fn get(&self, value: &K) -> Option<&V>;
            pub fn get_mut(&mut self, k: &K) -> Option<&mut V>;
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::SnapshotMap;

    /// This test is supposed to test various cases for the difference calculation, which is the meat
    /// of the `SnapshotMap`.
    #[test]
    fn test_snapshot_difference_calculation() {
        // Make sure that Add(1), Remove(1), Add(1) just prunes to `Add(1)`, and
        // has no removals.
        let mut map: SnapshotMap<u32, u32> = SnapshotMap::new();
        map.insert(1, 0);
        map.remove(&1);
        map.insert(1, 0);

        let difference = map.difference();
        assert!(difference.insertions == Vec::from(vec![1]));
        assert!(difference.removals.is_empty());

        // Make sure that Remove(1), Remove(1), Add(1) _AFTER_ the previous operation just prunes
        // away and has no removals. The snapshot should be the last value, which was 1.
        map.remove(&1);
        map.remove(&1);
        map.insert(1, 0);

        let difference = map.difference();
        assert!(difference.insertions.is_empty());
        assert!(difference.removals.is_empty());
        assert!(difference.snapshot == vec![1]);

        // Insert -> Remove -> Remove, make sure the only difference is the removal.
        map.insert(1, 0);
        map.remove(&1);
        map.remove(&1);

        let difference = map.difference();
        assert!(difference.insertions.is_empty());
        assert!(difference.removals == Vec::from(vec![1]));
        assert!(difference.snapshot == vec![1]);

        // At the last snapshot, we removed the last item. So let's make sure there is nothing
        // in this current snapshot.
        let difference = map.difference();
        assert!(difference.insertions.is_empty());
        assert!(difference.removals.is_empty());
        assert!(difference.snapshot.is_empty());
    }
}
