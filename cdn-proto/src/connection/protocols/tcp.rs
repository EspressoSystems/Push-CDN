//! This file defines and implements a thin wrapper around a TCP
//! connection that implements our message framing and connection
//! logic.

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::time::Duration;
use std::{net::ToSocketAddrs, sync::Arc};

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpSocket, TcpStream},
};

use super::{
    read_length_delimited, write_length_delimited, Connection, Listener, Protocol,
    UnfinalizedConnection,
};
use crate::connection::middleware::Middleware;
use crate::{
    bail, bail_option,
    connection::Bytes,
    error::{Error, Result},
    message::Message,
    parse_endpoint,
};

/// The `Tcp` protocol. We use this to define commonalities between TCP
/// listeners, connections, etc.
#[derive(Clone, PartialEq, Eq)]
pub struct Tcp;

#[async_trait]
impl<M: Middleware> Protocol<M> for Tcp {
    type Connection = TcpConnection<M>;

    type Listener = TcpListener;
    type UnfinalizedConnection = UnfinalizedTcpConnection;

    /// Connect to a remote endpoint, returning an instance of `Self`.
    /// With TCP, this requires just connecting to the remote endpoint.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: &str, _use_local_authority: bool) -> Result<Self::Connection>
    where
        Self: Sized,
    {
        // Parse the socket endpoint
        let remote_endpoint = bail_option!(
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
            bail!(
                timeout(Duration::from_secs(5), socket.connect(remote_endpoint)).await,
                Connection,
                "timed out connecting to tcp endpoint"
            ),
            Connection,
            "failed to connect to tcp endpoint"
        );

        // Split the connection and create our wrapper
        let (receiver, sender) = stream.into_split();
        Ok(TcpConnection {
            sender: Arc::from(Mutex::from(sender)),
            receiver: Arc::from(Mutex::from(receiver)),
            pd: PhantomData,
        })
    }

    /// Binds to a local endpoint. Does not use a TLS configuration.
    ///
    /// # Errors
    /// - If we cannot bind to the local interface
    /// - If we cannot parse the bind endpoint
    async fn bind(
        bind_endpoint: &str,
        _certificate: CertificateDer<'static>,
        _key: PrivateKeyDer<'static>,
    ) -> Result<Self::Listener> {
        // Parse the bind endpoint
        let bind_endpoint: SocketAddr = parse_endpoint!(bind_endpoint);

        // Try to bind to the local endpoint
        Ok(TcpListener(bail!(
            tokio::net::TcpListener::bind(bind_endpoint).await,
            Connection,
            "failed to bind to local endpoint"
        )))
    }
}

#[derive(Clone)]
pub struct TcpConnection<M: Middleware> {
    sender: Arc<Mutex<OwnedWriteHalf>>,
    receiver: Arc<Mutex<OwnedReadHalf>>,
    pd: PhantomData<M>,
}

#[async_trait]
impl<M: Middleware> Connection for TcpConnection<M> {
    /// Send an unserialized message over the stream.
    ///
    /// # Errors
    /// If we fail to send or serialize the message
    async fn send_message(&self, message: Message) -> Result<()> {
        // Serialize our message
        let raw_message = Bytes::from_unchecked(bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        ));

        // Send the message in its raw form
        self.send_message_raw(raw_message).await
    }

    /// Send a pre-serialized message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message_raw(&self, raw_message: Bytes) -> Result<()> {
        // Write the message length-delimited
        write_length_delimited(&mut *self.sender.lock().await, raw_message).await
    }

    /// Flushes the connection, sending any remaining data.
    async fn finish(&self) {
        let _ = self.sender.lock().await.flush().await;
    }

    /// Receives a single message over the stream and deserializes
    /// it.
    ///
    /// # Errors
    /// - if we fail to receive the message
    /// - if we fail to deserialize the message
    async fn recv_message(&self) -> Result<Message> {
        // Receive the raw message
        let raw_message = self.recv_message_raw().await?;

        // Deserialize and return the message
        Ok(bail!(
            Message::deserialize(&raw_message),
            Deserialize,
            "failed to deserialize message"
        ))
    }

    /// Receives a single message over the stream and deserializes
    /// it.
    ///
    /// # Errors
    /// - if we fail to receive the message
    async fn recv_message_raw(&self) -> Result<Bytes> {
        // Receive the length-delimited message
        read_length_delimited::<_, M>(&mut *self.receiver.lock().await).await
    }
}

/// A connection that has yet to be finalized. Allows us to keep accepting
/// connections while we process this one.
pub struct UnfinalizedTcpConnection(TcpStream);

#[async_trait]
impl<M: Middleware> UnfinalizedConnection<TcpConnection<M>> for UnfinalizedTcpConnection {
    /// Finalize the connection by splitting it into a sender and receiver side.
    /// Conssumes `Self`.
    ///
    /// # Errors
    /// Does not actually error, but satisfies trait bounds.
    async fn finalize(self) -> Result<TcpConnection<M>> {
        // Split the connection and create our wrapper
        let (receiver, sender) = self.0.into_split();

        Ok(TcpConnection {
            sender: Arc::from(Mutex::from(sender)),
            receiver: Arc::from(Mutex::from(receiver)),
            pd: PhantomData,
        })
    }
}

/// The listener struct. Needed to receive messages over TCP. Is a light
/// wrapper around `tokio::net::TcpListener`.
pub struct TcpListener(pub tokio::net::TcpListener);

#[async_trait]
impl Listener<UnfinalizedTcpConnection> for TcpListener {
    /// Accept an unfinalized connection from the listener.
    ///
    /// # Errors
    /// - If we fail to accept a connection from the listener.
    async fn accept(&self) -> Result<UnfinalizedTcpConnection> {
        // Try to accept a connection from the underlying endpoint
        // Split into reader and writer half
        let connection = bail!(
            self.0.accept().await,
            Connection,
            "failed to accept connection"
        );

        // Return the unfinalized connection
        Ok(UnfinalizedTcpConnection(connection.0))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};

    use super::super::tests::test_connection as super_test_connection;
    use super::Tcp;

    #[tokio::test]
    /// Test connection establishment, listening for connections, and message
    /// sending and receiving. Just proxies to the super traits' function
    pub async fn test_connection() -> Result<()> {
        // Get random, available port
        let Some(port) = portpicker::pick_unused_port() else {
            return Err(anyhow!("no unused ports"));
        };

        // Test using the super's function
        super_test_connection::<Tcp>(format!("127.0.0.1:{port}")).await
    }
}
