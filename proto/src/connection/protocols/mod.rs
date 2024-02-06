//! This module defines connections, listeners, and their implementations.

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;

use crate::{error::Result, message::Message};
pub mod quic;
pub mod tcp;

/// Assert that we are at _least_ running on a 64-bit system
/// TODO: find out if there is a better way than the `u64` cast
const _: [(); 0 - (!(usize::BITS >= u64::BITS)) as usize] = [];

pub trait Protocol: Send + Sync + 'static + Clone {
    type Connection: Connection;
    type Listener: Listener<Self::Connection>;
}

#[async_trait]
pub trait Connection: Send + Sync + 'static {
    /// Receive a single message from the connection.
    ///
    /// # Errors
    /// Errors if we either fail to receive the message. This usually means a connection problem.
    async fn recv_message(&self) -> Result<Message>;

    /// Send a single message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message
    /// - If we fail to serialize the message
    async fn send_message(&self, message: Message) -> Result<()>;

    /// Send a pre-formed message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message_raw(&self, message: Arc<Vec<u8>>) -> Result<()>;

    /// Send a vector of pre-formed messages over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver any of the messages. This usually means a connection problem.
    async fn send_messages_raw(&self, messages: Vec<Arc<Vec<u8>>>) -> Result<()>;


    /// Connect to a remote address, returning an instance of `Self`.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: String) -> Result<Self>
    where
        Self: Sized;
}

#[async_trait]
pub trait Listener<ConnectionType: Connection>: Send + Sync + 'static {
    /// Bind to the local address, returning an instance of `Self`.
    ///
    /// # Errors
    /// If we fail to bind to the given socket address
    async fn bind(
        bind_address: SocketAddr,
        maybe_tls_cert_path: Option<String>,
        maybe_tls_key_path: Option<String>,
    ) -> Result<Self>
    where
        Self: Sized;

    /// Accept a connection from the local, bound socket.
    /// Returns a connection or an error if we encountered one.
    ///
    /// # Errors
    /// If we fail to accept a connection
    async fn accept(&self) -> Result<ConnectionType>;
}
