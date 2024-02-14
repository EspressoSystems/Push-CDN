//! This file defines and implements a thin wrapper around a TCP
//! connection that implements our message framing and connection
//! logic.

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpSocket,
    },
};

#[cfg(feature = "metrics")]
use crate::connection::metrics;

use crate::{
    bail, bail_option,
    error::{Error, Result},
    message::Message,
    read_length_delimited, write_length_delimited, MAX_MESSAGE_SIZE,
};
use std::{collections::VecDeque, net::ToSocketAddrs, sync::Arc};

use super::{Listener, Protocol, Receiver, Sender};

/// The `Tcp` protocol. We use this to define commonalities between TCP
/// listeners, connections, etc.
#[derive(Clone, PartialEq, Eq)]
pub struct Tcp;

#[async_trait]
impl Protocol for Tcp {
    type Sender = TcpSender;
    type Receiver = TcpReceiver;
    type Listener = TcpListener;

    /// Connect to a remote endpoint, returning an instance of `Self`.
    /// With TCP, this requires just connecting to the remote endpoint.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: &str) -> Result<(Self::Sender, Self::Receiver)>
    where
        Self: Sized,
    {
        // Parse the socket address
        let remote_address = bail_option!(
            bail!(
                remote_endpoint.to_socket_addrs(),
                Parse,
                "failed to parse remote endpoint"
            )
            .next(),
            Connection,
            "did not find suitable address for endpoint"
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

        Ok((TcpSender(write_half), TcpReceiver(read_half)))
    }

    /// Binds to a local endpoint. Does not use a TLS configuration.
    ///
    /// # Errors
    /// - If we cannot bind to the local interface
    async fn bind(
        bind_address: std::net::SocketAddr,
        _maybe_tls_cert_path: Option<String>,
        _maybe_tls_key_path: Option<String>,
    ) -> Result<Self::Listener> {
        // Try to bind to the local address
        Ok(TcpListener(bail!(
            tokio::net::TcpListener::bind(bind_address).await,
            Connection,
            "failed to bind to local address"
        )))
    }
}

/// This struct is a light wrapper over the send half of a TCP connection.
pub struct TcpSender(OwnedWriteHalf);

#[async_trait]
impl Sender for TcpSender {
    /// Send an unserialized message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message(&mut self, message: Message) -> Result<()> {
        // Serialize the message
        let message = bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        );

        // Write the message to the stream
        write_length_delimited!(self.0, message);

        Ok(())
    }

    /// Send a vector of pre-formed messages over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_messages(&mut self, messages: VecDeque<Arc<Vec<u8>>>) -> Result<()> {
        // Write each message (length-delimited)
        for message in messages {
            write_length_delimited!(self.0, message);
        }

        Ok(())
    }

    /// Gracefully shuts down the outgoing stream, ensuring all data
    /// has been written.
    ///
    /// # Errors
    /// - If we could not shut down the stream.
    async fn finish(&mut self) -> Result<()> {
        bail!(
            self.0.shutdown().await,
            Connection,
            "failed to finish connection"
        );

        Ok(())
    }
}

/// This is a light wrapper over the read half of a TCP connection
pub struct TcpReceiver(OwnedReadHalf);

#[async_trait]
impl Receiver for TcpReceiver {
    /// Receives a single message over the stream and deserializes
    /// it.
    ///
    /// # Errors
    /// - if we fail to receive the message
    /// - if we fail deserialization
    async fn recv_message(&mut self) -> Result<Message> {
        // Receive the raw message
        let raw_message = bail!(
            self.recv_message_raw().await,
            Connection,
            "failed to receive message"
        );

        // Deserialize and return the message
        Ok(bail!(
            Message::deserialize(&raw_message),
            Deserialize,
            "failed to deserialize message"
        ))
    }

    /// Receives a single message over the stream without deserializing
    /// it.
    ///
    /// # Errors
    /// - if we fail to receive the message
    async fn recv_message_raw(&mut self) -> Result<Vec<u8>> {
        Ok(read_length_delimited!(self.0))
    }
}

/// The listener struct. Needed to receive messages over TCP. Is a light
/// wrapper around `tokio::net::TcpListener`.
pub struct TcpListener(pub tokio::net::TcpListener);

#[async_trait]
impl Listener<TcpSender, TcpReceiver> for TcpListener {
    /// Accept a connection from the listener.
    ///
    /// # Errors
    /// - If we fail to accept a connection from the listener.
    /// TODO: be more descriptive with this
    /// TODO: match on whether the endpoint is closed, return a different error
    async fn accept(&self) -> Result<(TcpSender, TcpReceiver)> {
        // Try to accept a connection from the underlying endpoint
        // Split into reader and writer half
        let (receiver, sender) = bail!(
            self.0.accept().await,
            Connection,
            "failed to accept connection"
        )
        .0
        .into_split();

        // Wrap our halves so they can be used across threads
        Ok((TcpSender(sender), TcpReceiver(receiver)))
    }
}
