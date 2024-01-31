use std::sync::Arc;

use crate::{error::Result, message::Message};

pub mod fallible;
pub mod sticky;

pub trait Connection {
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

