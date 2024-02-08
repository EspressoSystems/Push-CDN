//! This module defines connections, listeners, and their implementations.

use std::{collections::VecDeque, net::SocketAddr, sync::Arc};

use async_trait::async_trait;

use crate::{error::Result, message::Message};
pub mod quic;
pub mod tcp;

/// Assert that we are at _least_ running on a 64-bit system
/// TODO: find out if there is a better way than the `u64` cast
const _: [(); 0 - (!(usize::BITS >= u64::BITS)) as usize] = [];

/// The `Protocol` trait lets us be generic over a connection type (Tcp, Quic, etc).
#[async_trait]
pub trait Protocol: Send + Sync + 'static {
    // TODO: make these generic over reader/writer
    // TODO: make these connection type that defines into_split
    type Sender: Sender + Send + Sync;
    type Receiver: Receiver + Send + Sync;

    type Listener: Listener<Self::Sender, Self::Receiver> + Send + Sync;

    /// Connect to a remote address, returning an instance of `Self`.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: String) -> Result<(Self::Sender, Self::Receiver)>;

    /// Bind to the local address, returning an instance of `Listener`.
    ///
    /// # Errors
    /// If we fail to bind to the given socket address
    async fn bind(
        bind_address: SocketAddr,
        maybe_tls_cert_path: Option<String>,
        maybe_tls_key_path: Option<String>,
    ) -> Result<Self::Listener>;
}

#[async_trait]
pub trait Sender {
    /// Send a message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message(&mut self, message: Message) -> Result<()>;

    /// Send a vector of pre-formed messages over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver any of the messages. This usually means a connection problem.
    async fn send_messages(&mut self, messages: VecDeque<Arc<Vec<u8>>>) -> Result<()>;

    /// Gracefully shuts down the outgoing stream, ensuring all data
    /// has been written.
    ///
    /// # Errors
    /// - If we could not shut down the stream.
    async fn finish(&mut self) -> Result<()>;
}

#[async_trait]
pub trait Receiver {
    /// Receives a single message over the stream and deserializes
    /// it.
    ///
    /// # Errors
    /// - if we fail to receive the message
    /// - if we fail deserialization
    async fn recv_message(&mut self) -> Result<Message>;

    /// Receives a single message over the stream without deserializing
    /// it.
    ///
    /// # Errors
    /// - if we fail to receive the message
    async fn recv_message_raw(&mut self) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait Listener<Sender, Receiver> {
    /// Accept a connection from the local, bound socket.
    /// Returns a connection or an error if we encountered one.
    ///
    /// # Errors
    /// If we fail to accept a connection
    async fn accept(&self) -> Result<(Sender, Receiver)>;
}

/// A macro to write a length-delimited (serialized) message to a stream.
#[macro_export]
macro_rules! write_length_delimited {
    ($stream: expr, $message:expr) => {
        // Write the message size to the stream
        bail!(
            $stream.write_u64($message.len() as u64).await,
            Connection,
            "failed to send message size"
        );

        // Write the message to the stream
        bail!(
            $stream.write_all(&$message).await,
            Connection,
            "failed to send message"
        );
    };
}

/// A macro to read a length-delimited (serialized) message from a stream.
/// Has a bounds check for if the message is too big
#[macro_export]
macro_rules! read_length_delimited {
    ($stream: expr) => {{
        // Read the message size from the stream
        let message_size = bail!(
            $stream.read_u64().await,
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
        let mut buffer = vec![0; usize::try_from(message_size).expect("64 bit system")];

        // Read the message from the stream
        bail!(
            $stream.read_exact(&mut buffer).await,
            Connection,
            "failed to receive message from connection"
        );

        buffer
    }};
}
