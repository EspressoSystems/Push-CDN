//! This file defines a write-ahead log that we use for broker <-> broker replication.
//! It does not write to disk, but contains the primitive that allows us to
//! catch up from a snapshot or from a list of logs.

use std::{
    collections::{HashSet, VecDeque},
    hash::Hash,
};

/// An `enum` referring to every operation we can perform on the underlying set.
/// Right now, it supports inserting and removing elements.
#[derive(Clone, Debug)]
pub enum Log<V> {
    /// Insert an element into the underlying set
    Insert(V),
    /// Remove an element from the underlying set
    Remove(V),
}

/// `Update` is a primitive used by `LoggedSet` which allows us to update
/// either with a list of operations (`Log`s) from a specific point, or
/// by getting the whole set.
#[derive(Debug, Clone)]
pub enum Update<V> {
    /// Update by means of logs. This is meant to be used when it isn't too
    /// expensive to send them over.
    ByLogs(Vec<Log<V>>),
    /// Update by means of set. This is meant to be used when it's too expensive
    /// to send every individual log over.
    BySet(HashSet<V>, usize),
}

/// `LoggedSet` is a data structure on top of a `HashSet` that maintains:
/// - a set of unique elements (via `HashSet`)
/// - a log of operations performed on the set
///
/// The operation log performs automatic pruning.
///
/// This allows us to conditionally retrieve incremental or full (snapshot) updates from
/// a set, similar to a write-ahead log.
///
/// # Example
/// ```
/// use broker_proto::wal::LoggedSet;
///
/// let mut leader = LoggedSet::new();
/// let mut follower = LoggedSet::new();
/// // perform operations on the leader
/// for i in 0..100 {
///     leader.insert(i);
/// }
/// // Update the follower automatically, either via log or by
/// // Sending the entire set (based on what we've pruned)
/// follower.update(leader.get_updates_inclusive(follower.tail()));
/// ```
#[derive(Default, Clone)]
pub struct LoggedSet<V: Ord + Clone + Default + Hash> {
    /// The tail of the set. this refers to the latest (not yet seen) log
    tail: usize,
    /// The head of the set, meaning: the index of the oldest log we have
    head: usize,
    /// The underlying set that we are logging on top of
    set: HashSet<V>,
    /// A `VecDeque` of logs which we conditionally pull from or apply to.
    logs: VecDeque<Log<V>>,
}

impl<V: Ord + Clone + Default + Hash> LoggedSet<V> {
    /// Create a new, empty `LoggedSet`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an element into the `LoggedSet`. This is semantically equivalent
    /// to inserting an element into a `HashSet`.
    pub fn insert(&mut self, val: V) {
        if !self.set.contains(&val) {
            self.perform(Log::Insert(val));
        }
    }

    /// Remove an element into the `LoggedSet`. This is semantically equivalent
    /// to removing an element from a `HashSet`.
    pub fn remove(&mut self, val: &V) {
        if self.set.contains(val) {
            self.perform(Log::Remove(val.clone()));
        }
    }

    /// An internal function to perform set updates from a list of logs.
    /// Performs them in order.
    fn perform(&mut self, log: Log<V>) {
        // See what to do based on operation
        match &log {
            Log::Insert(val) => {
                self.set.insert(val.clone());
            }
            Log::Remove(val) => {
                self.set.remove(val);
            }
        }

        // Add to our logs
        self.logs.push_back(log);
        // Update tail, which helps us figure out our "latest seen" value
        self.tail += 1;

        // Prune the logs based on this constant factor. We want it to prune
        // so that we only maintain the logs where it makes sense in terms of
        // serialized size.
        //
        // This initial constant was just chosen by looking at bincode overhead for each.
        while self.logs.len() * 4 > self.set.len() {
            self.head += 1;
            self.logs.pop_front();
        }
    }

    /// Update the set given an `Update` object. We can either update with
    /// the full set or with a set of logs to save us network bandwidth.
    pub fn update(&mut self, update: Update<V>) {
        match update {
            Update::BySet(set, end_index) => {
                self.set = set;
                self.tail = end_index;
                self.head = end_index;
            }
            Update::ByLogs(logs) => {
                self.perform_many(logs);
            }
        }
    }

    /// Immutably returns the tail of the logged set.
    /// This way we don't expose the mutable, private `tail`.
    pub const fn tail(&self) -> usize {
        self.tail
    }

    /// Performs many operations. Just loops over and performs `set.update(update)`
    /// on each supplied log.
    fn perform_many(&mut self, logs: Vec<Log<V>>) {
        for log in logs {
            self.perform(log);
        }
    }

    /// This function gets the updates from the last seen log in an inclusive fashion.
    /// The tail supplied refers to the latest (not yet seen) log you wish to retrieve
    /// from.
    ///
    /// This function will return an `Update`, which internally can either refer
    /// to a full set or to a list of updates, depending on the pruning factor
    /// in `set.perform(log)`.
    ///
    /// # Example
    /// ```
    /// use broker_proto::wal::LoggedSet;
    ///
    /// let mut leader = LoggedSet::new();
    /// let mut follower = LoggedSet::new();
    /// // Perform operations on the leader
    /// for i in 0..100 {
    ///     leader.insert(i);
    /// }
    /// // Update the follower automatically, either via log or by
    /// // sending the entire set (based on what we've pruned)
    /// follower.update(leader.get_updates_inclusive(follower.tail()));
    pub fn get_updates_inclusive(&self, tail: usize) -> Update<V> {
        if self.head > tail {
            // The caller is behind, just send the whole set
            Update::BySet(self.set.clone(), self.tail)
        } else {
            // The caller is on track, send a list of logs
            let virtual_index = tail - self.head;

            // This avoids the range panic
            if self.logs.len() >= virtual_index {
                // If the virtual index falls within the expected range
                Update::ByLogs(self.logs.range(virtual_index..).cloned().collect())
            } else {
                // If we exceed the set limit
                Update::ByLogs(Vec::new())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// This test tests to make sure inserting and removes work in parity with
    /// a normal `HashSet`.
    #[test]
    fn test_insert_remove() {
        // Create the parity set and our set
        let mut log_set = LoggedSet::new();
        let mut hash_set = HashSet::new();

        // Insert the same element to both
        for i in 0..100 {
            log_set.insert(i);
            hash_set.insert(i);
        }

        // Check that the contents are equal
        assert_eq!(log_set.set, hash_set);

        // Remove the same elements from both
        for i in 50..100 {
            log_set.remove(&i);
            hash_set.remove(&i);
        }

        // Check that the contents are equal
        assert!(log_set.set == hash_set);
    }

    /// This test tests to make sure that update works as intended,
    /// and that a leader and a follower (who both end up making changes)
    /// are matched with each other after updates
    #[test]
    fn test_update() {
        // Create leader and follower set (although they're interchangeable)
        let mut leader = LoggedSet::new();
        let mut follower = LoggedSet::new();

        // Update by set
        for i in 0..100 {
            leader.insert(i);
        }

        // Update the follower by getting leader updates from the follower's tail
        follower.update(leader.get_updates_inclusive(follower.tail));

        // Assert the sets and tails (next log number to ask for) are equal.
        assert!(leader.set == follower.set);
        assert!(leader.tail == follower.tail);

        // Test updating by log
        follower.remove(&1);

        // Update the leader by getting follower updates from the leader's tail
        leader.update(follower.get_updates_inclusive(leader.tail));

        // Assert the sets and tails (next log number to ask for) are equal.
        assert!(leader.set == follower.set);
        assert!(leader.tail == follower.tail)
    }

    /// This test tests that we don't panic anywhere, as the range function
    /// can panic if we are out of bounds.
    #[test]
    fn test_get_updates_bounds_panic() {
        let mut set = LoggedSet::new();

        // create a range to iterate over
        for i in 0..100 {
            set.insert(i);
        }

        // tests that this operation shouldn't panic
        for i in 0..100 {
            set.get_updates_inclusive(i);
        }
    }

    /// This test tests the __bounds__ of the set. Meaning; do we update with the `Update::FromLog()`
    /// facility if we ask for the oldest one, and will we pull the whole set if we try to
    /// get `oldest_log-1`?
    #[test]
    fn test_get_updates_bounds() {
        let mut set = LoggedSet::new();

        // Insert some elements into our set
        for i in 0..100 {
            set.insert(i);
        }

        // Here we are using the insertion number as the log number.
        // Get the oldest log number through this means
        let oldest_log = if let Log::Insert(log) = set.logs.front().unwrap() {
            log
        } else {
            panic!("insert operation did not insert");
        };

        // Test getting the oldest log by means of `Update::FromLog`
        if let Update::ByLogs(logs) = set.get_updates_inclusive(*oldest_log) {
            // Assert that we have the correct number of logs
            assert!(logs.len() == 100 - oldest_log);
        } else {
            panic!("did not retrieve the oldest log by log")
        }

        // `oldest_log - 1` should be retrieved through `Update::FromSet`
        if let Update::BySet(set, new_tail) = set.get_updates_inclusive(*oldest_log - 1) {
            // Assert that the set is the correct length, and the tail is too
            assert!(set.len() == 100);
            assert!(new_tail == 100);
        } else {
            panic!("did not retrieve the oldest - 1 by set")
        }
    }
}
