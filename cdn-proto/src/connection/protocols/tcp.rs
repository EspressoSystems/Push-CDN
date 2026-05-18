// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This file defines and implements a thin wrapper around a TCP
//! connection that implements our message framing and connection
//! logic.

use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use super::SoftClose;
use super::{Connection, Listener, Protocol, UnfinalizedConnection};
use crate::connection::limiter::Limiter;
use crate::{
    bail, bail_option,
    error::{Error, Result},
    parse_endpoint,
};

/// The default TCP keepalive configuration applied to every accepted and
/// outgoing connection. With these values the kernel detects a dead peer in
/// roughly 60s + 5*10s ≈ 110s of unacknowledged data.
pub(super) fn keepalive_config() -> TcpKeepalive {
    TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10))
        .with_retries(5)
}

/// The `Tcp` protocol. We use this to define commonalities between TCP
/// listeners, connections, etc.
#[derive(Clone, PartialEq, Eq)]
pub struct Tcp;

#[async_trait]
impl Protocol for Tcp {
    type Listener = TcpListener;
    type UnfinalizedConnection = UnfinalizedTcpConnection;

    /// Connect to a remote endpoint, returning an instance of `Self`.
    /// With TCP, this requires just connecting to the remote endpoint.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(
        remote_endpoint: &str,
        _use_local_authority: bool,
        limiter: Limiter,
    ) -> Result<Connection>
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
        bail!(
            stream.set_nodelay(true),
            Connection,
            "failed to set nodelay"
        );
        bail!(
            SockRef::from(&stream).set_tcp_keepalive(&keepalive_config()),
            Connection,
            "failed to set TCP keepalive"
        );

        // Split the connection and create our wrapper
        let (receiver, sender) = stream.into_split();

        // Convert the streams into a `Connection`
        let connection = Connection::from_streams(sender, receiver, limiter, Some(remote_endpoint));

        Ok(connection)
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

/// A connection that has yet to be finalized. Allows us to keep accepting
/// connections while we process this one.
pub struct UnfinalizedTcpConnection(TcpStream);

#[async_trait]
impl UnfinalizedConnection for UnfinalizedTcpConnection {
    /// Finalize the connection by splitting it into a sender and receiver side.
    /// Conssumes `Self`.
    ///
    /// # Errors
    /// Does not actually error, but satisfies trait bounds.
    async fn finalize(self, limiter: Limiter) -> Result<Connection> {
        bail!(
            SockRef::from(&self.0).set_tcp_keepalive(&keepalive_config()),
            Connection,
            "failed to set TCP keepalive"
        );

        let peer_addr = self.0.peer_addr().ok();

        // Split the connection and create our wrapper
        let (receiver, sender) = self.0.into_split();

        // Convert the streams into a `Connection`
        let connection = Connection::from_streams(sender, receiver, limiter, peer_addr);

        Ok(connection)
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
        bail!(
            connection.0.set_nodelay(true),
            Connection,
            "failed to set nodelay"
        );

        // Return the unfinalized connection
        Ok(UnfinalizedTcpConnection(connection.0))
    }
}

/// Soft closing is a no-op for TCP connections.
#[async_trait]
impl SoftClose for OwnedWriteHalf {}

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
