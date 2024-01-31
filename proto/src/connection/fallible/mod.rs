//! This module defines `Fallible` connections and their implementations.
pub mod quic;
pub mod tcp;

/// Assert that we are at _least_ running on a 32-bit system
/// TODO: find out if there is a better way than the `u32` cast
const _: [(); 0 - (!(usize::BITS >= u32::BITS)) as usize] = [];
