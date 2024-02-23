//! This module defines connections, listeners, and their implementations.

use async_trait::async_trait;
use mockall::automock;

use crate::{error::Result, message::Message};

use super::Bytes;
pub mod memory;
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
        bind_address: &str,
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

#[cfg(test)]
pub mod test {
    use anyhow::Result;
    use tokio::{join, spawn, task::JoinHandle};

    use crate::message::{Direct, Message};

    use super::{Listener, Protocol, Receiver, Sender, UnfinalizedConnection};

    /// Test connection establishment, listening for connections, and message
    /// sending and receiving. All protocols should be calling this test function
    pub async fn test_connection<P: Protocol>(bind_address: String) -> Result<()> {
        // Create listener
        let listener = P::bind(bind_address.as_str(), None, None).await?;

        // The messages we will send and receive
        let new_connection_to_listener = Message::Direct(Direct {
            recipient: vec![0, 1, 2],
            message: b"meowtown".to_vec(),
        });
        let listener_to_new_connection = Message::Direct(Direct {
            recipient: vec![3, 4, 5],
            message: b"town of meow".to_vec(),
        });

        // Spawn a task to listen for and accept connections
        let listener_to_new_connection_ = listener_to_new_connection.clone();
        let new_connection_to_listener_ = new_connection_to_listener.clone();
        let listener_jh: JoinHandle<Result<()>> = spawn(async move {
            // Accept the connection
            let unfinalized_connection = listener.accept().await?;

            // Finalize the connection
            let (sender, receiver) = unfinalized_connection.finalize().await?;

            // Send our message
            sender.send_message(listener_to_new_connection_).await?;

            // Receive a message, assert it's the correct one
            let message = receiver.recv_message().await?;
            assert!(message == new_connection_to_listener_);

            Ok(())
        });

        // Spawn a task to connect and send and receive the message
        let new_connection_jh: JoinHandle<Result<()>> = spawn(async move {
            // Connect to the remote
            let (sender, receiver) = P::connect(bind_address.as_str()).await?;

            // Receive a message, assert it's the correct one
            let message = receiver.recv_message().await?;
            assert!(message == listener_to_new_connection);

            // Send our message
            sender.send_message(new_connection_to_listener).await?;

            Ok(())
        });

        // Wait for the results
        let (listener_result, new_connection_result) = join!(listener_jh, new_connection_jh);

        // Ensure none of them errored
        listener_result??;
        new_connection_result??;

        // We were successful
        Ok(())
    }
}
