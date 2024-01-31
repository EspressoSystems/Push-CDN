//! This module defines connections and their implementations.

use std::sync::Arc;

use crate::{error::Result, message::Message};

pub mod quic;
pub mod tcp;

/// Assertion that we are at _least_ running on a 32-bit system
/// TODO: find out if there is a better way than the `u32` cast
const _: [(); 0 - (!(usize::BITS >= u32::BITS)) as usize] = [];

trait Connection {
    /// Receive a single message from the connection.
    ///
    /// # Errors
    /// Errors if we either fail to receive the message. This usually means a connection problem.
    async fn recv_message(&self) -> Result<Message>;

    /// Send a single message over the connection.
    ///
    /// # Errors
    /// Errors if we fail to deliver the message. This usually means a connection problem.
    async fn send_message(&self, message: Arc<Message>) -> Result<()>;
}
