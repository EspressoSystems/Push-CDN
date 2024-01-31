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

    /// Connect to a remote address, returning an instance of `Self`.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: String) -> Result<Self>
    where
        Self: Sized;
}
