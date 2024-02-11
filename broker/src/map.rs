use std::{
    cmp::Ordering,
    collections::HashMap,
    hash::Hash,
    ops::{AddAssign, SubAssign},
};

use delegate::delegate;

pub struct SnapshotMap<K: Eq + PartialEq + Hash + Clone, V> {
    snapshot: Vec<K>,
    log: Vec<Operation<K>>,
    inner: HashMap<K, V>,
}

#[derive(Debug)]
pub enum Operation<K> {
    Insert(K),
    Remove(K),
}

pub struct SnapshotWithChanges<K> {
    pub snapshot: Vec<K>,
    pub insertions: Vec<K>,
    pub removals: Vec<K>,
}

impl<K: Eq + PartialEq + Hash + Clone, V> SnapshotMap<K, V> {
    pub fn new() -> Self {
        Self {
            log: Vec::new(),
            inner: HashMap::new(),
            snapshot: Vec::new(),
        }
    }

    pub fn insert(&mut self, key: K, val: V) -> Option<V> {
        let res = self.inner.insert(key.clone(), val);

        if res.is_none() {
            // If the key wasn't already in our map, update the log
            self.log.push(Operation::Insert(key));
        }

        res
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let res = self.inner.remove(key);

        if res.is_some() {
            // If the key existed, add a remove operation
            self.log.push(Operation::Remove(key.clone()));
        }

        res
    }

    pub fn difference(&mut self) -> SnapshotWithChanges<K> {
        let logs = std::mem::take(&mut self.log);

        let mut changes = HashMap::new();
        for log in logs {
            match log {
                Operation::Insert(item) => changes.entry(item).or_insert(0).add_assign(1),
                Operation::Remove(item) => changes.entry(item).or_insert(0).sub_assign(1),
            }
        }

        let mut insertions = Vec::new();
        let mut removals = Vec::new();
        for change in changes {
            match change.1.cmp(&0) {
                Ordering::Greater => {
                    insertions.push(change.0);
                }

                Ordering::Less => {
                    removals.push(change.0);
                }

                Ordering::Equal => {}
            }
        }

        SnapshotWithChanges {
            snapshot: std::mem::replace(&mut self.snapshot, self.inner.keys().cloned().collect()),
            insertions,
            removals,
        }
    }

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

    #[test]
    fn test_snapshot_difference_calculation() {
        let mut map: SnapshotMap<u32, u32> = SnapshotMap::new();
        map.insert(1, 0);
        map.remove(&1);
        map.insert(1, 0);

        let difference = map.difference();
        assert!(difference.insertions == Vec::from(vec![1]));
        assert!(difference.removals.is_empty());

        map.remove(&1);
        map.remove(&1);
        map.insert(1, 0);

        let difference = map.difference();
        assert!(difference.insertions.is_empty());
        assert!(difference.removals.is_empty());
        assert!(difference.snapshot == vec![1]);

        map.insert(1, 0);
        map.remove(&1);
        map.remove(&1);

        let difference = map.difference();
        assert!(difference.insertions.is_empty());
        assert!(difference.removals == Vec::from(vec![1]));
        assert!(difference.snapshot == vec![1]);

        let difference = map.difference();
        assert!(difference.insertions.is_empty());
        assert!(difference.removals.is_empty());
        assert!(difference.snapshot.is_empty());
    }
}
