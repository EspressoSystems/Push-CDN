//! This file defines and implements a thin wrapper around a TCP
//! connection that implements our message framing and connection
//! logic.

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpSocket,
    },
    sync::Mutex,
};

use crate::{
    bail,
    connection::Connection,
    error::{Error, Result},
    message::Message,
    MAX_MESSAGE_SIZE,
};
use std::sync::Arc;

/// `Fallible` is a thin wrapper around `OwnedReadHalf` and `OwnedWriteHalf` that implements
/// `Connection`.
#[derive(Clone)]
pub struct Fallible {
    pub receiver: Arc<Mutex<OwnedReadHalf>>,
    pub sender: Arc<Mutex<OwnedWriteHalf>>,
}

impl Connection for Fallible {
    /// Receives a single message from the TCP connection. It reads the size
    /// of the message from the stream, reads the message, and then
    /// deserializes and returns it.
    ///
    /// # Errors
    /// Errors if we either failed to receive or deserialize the message.
    /// This usually means a connection problem.
    async fn recv_message(&self) -> Result<Message> {
        // Lock the stream so we don't receive message/message sizes interleaved
        let mut receiver_guard = self.receiver.lock().await;

        // Read the message size from the stream
        let message_size = bail!(
            receiver_guard.read_u32().await,
            Connection,
            "failed to read message size"
        );
        // Make sure the message isn't too big
        if message_size > MAX_MESSAGE_SIZE {
            return Err(Error::Connection(
                "expected to receive message that was too big".to_string(),
            ));
        }

        // Create buffer of the proper size
        let mut buffer = vec![0; message_size as usize];
        // Read the message from the stream
        bail!(
            receiver_guard.read_exact(&mut buffer).await,
            Connection,
            "failed to receive message from connection"
        );

        // Deserialize and return the message
        Ok(bail!(
            Message::deserialize(&buffer),
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
        // Lock the stream so we don't send message/message sizes interleaved
        let mut sender_guard = self.sender.lock().await;

        // Serialize the message
        let serialized_message = bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        );

        // Write the message size to the stream
        bail!(
            sender_guard
                .write_u32(serialized_message.len() as u32)
                .await,
            Connection,
            "failed to send message size"
        );

        // Write the message to the stream
        bail!(
            sender_guard.write_all(&serialized_message).await,
            Connection,
            "failed to send message"
        );

        Ok(())
    }

    /// Connect to a remote endpoint, returning an instance of `Self`.
    /// With TCP, this requires just connecting to the remote endpoint.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: String) -> Result<Self>
    where
        Self: Sized,
    {
        // Parse the socket address
        let remote_address = bail!(
            remote_endpoint.parse(),
            Parse,
            "failed to parse remote endpoint"
        );

        // Create a new TCP socket
        let socket = bail!(
            TcpSocket::new_v4(),
            Connection,
            "failed to bind to local socket"
        );

        // Connect the stream to the local socket
        let stream = bail!(
            socket.connect(remote_address).await,
            Connection,
            "failed to connect to remote address"
        );

        // Split the connection into a `ReadHalf` and `WriteHalf` so we can operate
        // concurrently over both
        let (read_half, write_half) = stream.into_split();

        // `Mutex` and `Arc` each side
        Ok(Self {
            receiver: Arc::from(Mutex::from(read_half)),
            sender: Arc::from(Mutex::from(write_half)),
        })
    }
}
