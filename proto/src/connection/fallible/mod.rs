//! This module defines `Fallible` connections and their implementations.
pub mod quic;
pub mod tcp;

/// Assert that we are at _least_ running on a 64-bit system
/// TODO: find out if there is a better way than the `u64` cast
const _: [(); 0 - (!(usize::BITS >= u64::BITS)) as usize] = [];
