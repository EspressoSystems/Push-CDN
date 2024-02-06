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
    sync::Mutex,
};

use crate::{
    bail, bail_option,
    error::{Error, Result},
    message::Message,
    MAX_MESSAGE_SIZE,
};
use std::{net::ToSocketAddrs, sync::Arc};

use super::{Connection, Listener, Protocol};

/// The `Tcp` protocol. We use this to define commonalities between TCP
/// listeners, connections, etc.
#[derive(Clone)]
pub struct Tcp;

/// We define the `Tcp` protocol as being composed of both a TCP listener
/// and connection.
impl Protocol for Tcp {
    type Connection = TcpConnection;
    type Listener = TcpListener;
}

/// `TcpConnection` is a thin wrapper around `OwnedReadHalf` and `OwnedWriteHalf` that implements
/// `Connection`.
#[derive(Clone)]
pub struct TcpConnection {
    pub receiver: Arc<Mutex<OwnedReadHalf>>,
    pub sender: Arc<Mutex<OwnedWriteHalf>>,
}

#[async_trait]
impl Connection for TcpConnection {
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
            receiver_guard.read_u64().await,
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
            receiver_guard.read_exact(&mut buffer).await,
            Connection,
            "failed to receive message from connection"
        );
        drop(receiver_guard);

        // Deserialize and return the message
        Ok(bail!(
            Message::deserialize(&buffer),
            Deserialize,
            "failed to deserialize message"
        ))
    }

    /// Sends a single (deserialized) message over the TCP connection
    ///
    /// # Errors
    /// - If we fail to serialize the message
    /// - If we fail to send the message
    async fn send_message(&self, message: Message) -> Result<()> {
        // Serialize the message
        let serialized_message = bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        );

        // Send the serialized message
        self.send_message_raw(Arc::from(serialized_message)).await
    }

    /// Send a pre-formed message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message_raw(&self, message: Arc<Vec<u8>>) -> Result<()> {
        // Lock the stream so we don't send message/message sizes interleaved
        let mut sender_guard = self.sender.lock().await;

        // Write the message size to the stream
        bail!(
            sender_guard.write_u64(message.len() as u64).await,
            Connection,
            "failed to send message size"
        );

        // Write the message to the stream
        bail!(
            sender_guard.write_all(&message).await,
            Connection,
            "failed to send message"
        );
        drop(sender_guard);

        Ok(())
    }

    /// Send a vector pre-formed messages over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_messages_raw(&self, messages: Vec<Arc<Vec<u8>>>) -> Result<()> {
        // Lock the stream so we don't send message/message sizes interleaved
        let mut sender_guard = self.sender.lock().await;

        // For each message:
        for message in messages {
            // Write the message size to the stream
            bail!(
                sender_guard.write_u64(message.len() as u64).await,
                Connection,
                "failed to send message size"
            );

            // Write the message to the stream
            bail!(
                sender_guard.write_all(&message).await,
                Connection,
                "failed to send message"
            );
        }

        drop(sender_guard);

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

        // `Mutex` and `Arc` each side
        Ok(Self {
            receiver: Arc::from(Mutex::from(read_half)),
            sender: Arc::from(Mutex::from(write_half)),
        })
    }
}

/// The listener struct. Needed to receive messages over TCP. Is a light
/// wrapper around `tokio::net::TcpListener`.
pub struct TcpListener(pub tokio::net::TcpListener);

#[async_trait]
impl Listener<TcpConnection> for TcpListener {
    /// Binds to a local endpoint. Does not use a TLS configuration.
    ///
    /// # Errors
    /// - If we cannot bind to the local interface
    async fn bind(
        bind_address: std::net::SocketAddr,
        _maybe_tls_cert_path: Option<String>,
        _maybe_tls_key_path: Option<String>,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        // Try to bind to the local address
        Ok(Self(bail!(
            tokio::net::TcpListener::bind(bind_address).await,
            Connection,
            "failed to bind to local address"
        )))
    }

    /// Accept a connection from the listener.
    ///
    /// # Errors
    /// - If we fail to accept a connection from the listener.
    /// TODO: be more descriptive with this
    /// TODO: match on whether the endpoint is closed, return a different error
    async fn accept(&self) -> Result<TcpConnection> {
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
        Ok(TcpConnection {
            receiver: Arc::from(Mutex::from(receiver)),
            sender: Arc::from(Mutex::from(sender)),
        })
    }
}
