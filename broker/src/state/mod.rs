//! This crate is where we define how brokers and their inner tasks hold their states,
//! for both users and other brokers.

// TODO: use broker state to only allow a user to connect to a single broker at once

mod broker;
mod user;

use core::hash::Hash;
use std::collections::{HashMap, HashSet};

/// This map is a general implementation of a bijective multimap. We use this
/// on the broker side to represent both 1. subscriptions and 2. connections
#[derive(Clone)]
pub struct BijectiveMultiMap<Key: Eq + Hash, Value: Eq + Hash> {
    /// Maps a key to a list of values. We need this to aggregate
    /// values based on what key they are a member of.
    key_to_values: HashMap<Key, HashSet<Value>>,

    /// Maps a value to the list of keys that identity is a member of.
    /// We need this to allow for O(1) removal from the `key_to_values`
    /// map.
    value_to_keys: HashMap<Value, HashSet<Key>>,
}

/// Implements the `Default` implementation. We need this because of generics.
impl<Topic: Eq + Hash, Identity: Eq + Hash> Default for BijectiveMultiMap<Topic, Identity> {
    fn default() -> Self {
        Self {
            key_to_values: HashMap::default(),
            value_to_keys: HashMap::default(),
        }
    }
}
