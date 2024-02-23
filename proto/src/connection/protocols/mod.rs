//! This module defines connections, listeners, and their implementations.

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use mockall::automock;

/// A little type alias for helping readability.
/// TODO: put these in one place
type Bytes = Arc<Vec<u8>>;

use crate::{error::Result, message::Message};
pub mod quic;
pub mod tcp;

/// The `Protocol` trait lets us be generic over a connection type (Tcp, Quic, etc).
#[automock(type Sender=MockSender; type Receiver=MockReceiver; type UnfinalizedConnection=MockUnfinalizedConnection<MockSender, MockReceiver>; type Listener=MockListener<MockUnfinalizedConnection<MockSender, MockReceiver>>;)]
#[async_trait]
pub trait Protocol: Send + Sync + 'static {
    type Sender: Sender + Send + Sync + Clone;
    type Receiver: Receiver + Send + Sync + Clone;

    type UnfinalizedConnection: UnfinalizedConnection<Self::Sender, Self::Receiver> + Send + Sync;
    type Listener: Listener<Self::UnfinalizedConnection> + Send + Sync;

    /// Connect to a remote address, returning an instance of `Self`.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: &str) -> Result<(Self::Sender, Self::Receiver)>;

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

#[automock]
#[async_trait]
pub trait Sender {
    /// Send an (unserialized) message over the stream.
    ///
    /// # Errors
    /// If we fail to send or serialize the message
    async fn send_message(&self, message: Message) -> Result<()>;

    /// Send a pre-serialized message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message_raw(&self, raw_message: Bytes) -> Result<()>;
}

#[automock]
#[async_trait]
pub trait Receiver {
    /// Receives a message or message[s] over the stream and deserializes
    /// it.
    ///
    /// # Errors
    /// - if we fail to receive the message
    /// - if we fail deserialization
    async fn recv_message(&self) -> Result<Message>;
}

#[automock]
#[async_trait]
pub trait Listener<UnfinalizedConnection: Send + Sync> {
    /// Accept an unfinalized connection from the local, bound socket.
    /// Returns a connection or an error if we encountered one.
    ///
    /// # Errors
    /// If we fail to accept a connection
    async fn accept(&self) -> Result<UnfinalizedConnection>;
}

#[automock]
#[async_trait]
pub trait UnfinalizedConnection<Sender: Send + Sync, Receiver: Send + Sync> {
    /// Finalize an incoming connection. This is separated so we can prevent
    /// actors who are slow from clogging up the incoming connection by offloading
    /// it to a separate task.
    async fn finalize(self) -> Result<(Sender, Receiver)>;
}

/// We need to implement `clone` manually because we need it and `mockall` can't do it.
impl Clone for MockSender {
    fn clone(&self) -> Self {
        Self::default()
    }
}

/// We need to implement `clone` manually because we need it and `mockall` can't do it.
impl Clone for MockReceiver {
    fn clone(&self) -> Self {
        Self::default()
    }
}
