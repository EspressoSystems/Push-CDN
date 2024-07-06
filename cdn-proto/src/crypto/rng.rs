// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! In this module we define rng-related items.

use core::result::Result as StdResult;

use rand::{CryptoRng, RngCore};

/// The oxymoron function. Used mostly with crypto key generation to generate
/// "random" values that are actually deterministic based on the input.
pub struct DeterministicRng(pub u64);

impl CryptoRng for DeterministicRng {}

/// This implementation is to satisfy the `RngCore` trait and allow us to use it
/// to generate "random" values.
#[allow(clippy::cast_possible_truncation)]
impl RngCore for DeterministicRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for item in dest {
            *item = self.0 as u8;
            self.0 >>= 8_i32;
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.0 as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> StdResult<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
