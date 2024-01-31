//! This file defines and implements a thin wrapper around a QUIC
//! connection that implements our message framing and connection
//! logic.

use crate::{
    bail,
    connection::Connection,
    error::{Error, Result},
    message::Message,
    MAX_MESSAGE_SIZE,
};
use core::hash::Hash;
use std::sync::Arc;

/// `Fallible` is a thin wrapper around `quinn::Connection` that implements
/// `Connection`.
#[derive(Clone)]
pub struct Fallible(pub quinn::Connection);

/// `PartialEq` for a `Fallible` connection is determined by the `stable_id` since it
/// will not change for the duration of the connection.
impl PartialEq for Fallible {
    fn eq(&self, other: &Self) -> bool {
        self.0.stable_id() == other.0.stable_id()
    }
}

/// Assertion for `Fallible` that `PartialEq` == `Eq`
impl Eq for Fallible {
    fn assert_receiver_is_total_eq(&self) {}
}

/// `Hash` for a `Fallible` connection is determined by the `stable_id` since it
/// will not change for the duration of the connection. We just want to hash that.
impl Hash for Fallible {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.stable_id().hash(state);
    }

    /// This just calls `hash` on each item in the slice.
    fn hash_slice<H: std::hash::Hasher>(data: &[Self], state: &mut H)
    where
        Self: Sized,
    {
        data.iter().for_each(|item| item.hash(state));
    }
}

impl Connection for Fallible {
    /// Receives a single message from the QUIC connection. Since we use
    /// virtual streams as a message framing method, this function first accepts a stream
    /// and then reads and deserializes a single message from it.
    ///
    /// # Errors
    /// Errors if we either failed to accept the stream or receive the message over that stream.
    /// This usually means a connection problem.
    async fn recv_message(&self) -> Result<Message> {
        // Accept the incoming unidirectional stream
        let mut stream = bail!(
            self.0.accept_uni().await,
            Connection,
            "failed to accept unidirectional stream"
        );

        // Read the full message, until the sender closes the stream
        let message_bytes = bail!(
            stream.read_to_end(MAX_MESSAGE_SIZE as usize).await,
            Connection,
            "failed to read from stream"
        );

        // Deserialize and return the message
        Ok(bail!(
            Message::deserialize(&message_bytes),
            Deserialize,
            "failed to deserialize message"
        ))
    }

    /// Sends a single message to the QUIC connection. This function first opens a
    /// stream and then serializes and sends a single message to it.
    ///
    /// # Errors
    /// Errors if we either failed to open the stream or send the message over that stream.
    /// This usually means a connection problem.
    async fn send_message(&self, message: Arc<Message>) -> Result<()> {
        // Open the outgoing unidirectional stream
        let mut stream = bail!(
            self.0.open_uni().await,
            Connection,
            "failed to open unidirectional stream"
        );

        // Serialize the message
        let message_bytes = bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        );

        // Write the full message to the stream
        bail!(
            stream.write_all(&message_bytes).await,
            Connection,
            "failed to write to stream"
        );

        // Finish the stream, denoting to the peer that the
        // message has been fully written
        Ok(bail!(
            stream.finish().await,
            Connection,
            "failed to finish stream"
        ))
    }
}