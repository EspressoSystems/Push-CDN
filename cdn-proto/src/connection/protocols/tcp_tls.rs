//! This file defines and implements a thin wrapper around a TCP
//! + TLS connection that implements our message framing and connection
//! logic.

use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls::ServerConfig;
use tokio::io::WriteHalf;
use tokio::net::TcpListener;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

use super::SoftClose;
use super::{Connection, Listener, Protocol, UnfinalizedConnection};
use crate::connection::middleware::Middleware;
use crate::crypto::tls::generate_root_certificate_store;
use crate::{
    bail, bail_option,
    error::{Error, Result},
    parse_endpoint,
};

/// The `Tcp` protocol. We use this to define commonalities between TCP
/// listeners, connections, etc.
#[derive(Clone, PartialEq, Eq)]
pub struct TcpTls;

#[async_trait]
impl Protocol for TcpTls {
    type Listener = TcpTlsListener;
    type UnfinalizedConnection = UnfinalizedTcpTlsConnection;

    /// Connect to a remote endpoint, returning an instance of `Self`.
    /// With TCP, this requires just connecting to the remote endpoint.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(
        remote_endpoint: &str,
        use_local_authority: bool,
        middleware: Middleware,
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

        // Generate root certificate store based on the local authority
        let root_cert_store = generate_root_certificate_store(use_local_authority)?;

        // Create `rustls` config from the root store
        let config: ClientConfig = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            // this just means no mTLS
            .with_no_client_auth();

        // Create a new TLS connector from the config
        let tls_connector = TlsConnector::from(Arc::new(config));
        let espresso_san = bail!(
            ServerName::try_from("espresso"),
            Connection,
            "failed to parse server name \"espresso\""
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

        // Wrap the stream in the TLS connection
        let stream = bail!(
            bail!(
                timeout(
                    Duration::from_secs(5),
                    tls_connector.connect(espresso_san, stream)
                )
                .await,
                Connection,
                "timed out attempting tls handshake"
            ),
            Connection,
            "failed to perform tls handshake"
        );

        // Split the connection and create our wrapper
        let (receiver, sender) = tokio::io::split(stream);

        // Convert the streams into a `Connection`
        let connection = Connection::from_streams(sender, receiver, middleware);

        Ok(connection)
    }

    /// Binds to a local endpoint. Does not use a TLS configuration.
    ///
    /// # Errors
    /// - If we cannot bind to the local interface
    /// - If we cannot parse the bind endpoint
    async fn bind(
        bind_endpoint: &str,
        certificate: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self::Listener> {
        // Create server configuration from the loaded certificate
        let server_config = bail!(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], key),
            Connection,
            "failed to create tls server configuration"
        );

        // Create a new TLS acceptor from the server configuration
        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        // Parse the bind endpoint
        let bind_endpoint: SocketAddr = parse_endpoint!(bind_endpoint);

        // Try to bind to the local endpoint
        let tcp_listener = bail!(
            TcpListener::bind(bind_endpoint).await,
            Connection,
            "failed to bind to local endpoint"
        );

        // Return the listener and TLS acceptor
        Ok(TcpTlsListener {
            tcp_listener,
            tls_acceptor,
        })
    }
}

/// A connection that has yet to be finalized. Allows us to keep accepting
/// connections while we process this one.
pub struct UnfinalizedTcpTlsConnection {
    tcp_stream: TcpStream,
    tls_acceptor: TlsAcceptor,
}

#[async_trait]
impl UnfinalizedConnection for UnfinalizedTcpTlsConnection {
    /// Finalize the connection by splitting it into a sender and receiver side.
    /// Conssumes `Self`.
    ///
    /// # Errors
    /// Does not actually error, but satisfies trait bounds.
    async fn finalize(self, middleware: Middleware) -> Result<Connection> {
        // Wrap the stream in the TLS connection
        let stream = bail!(
            bail!(
                timeout(
                    Duration::from_secs(5),
                    self.tls_acceptor.accept(self.tcp_stream)
                )
                .await,
                Connection,
                "timed out attempting tls handshake"
            ),
            Connection,
            "failed to perform tls handshake"
        );

        // Split the connection and create our wrapper
        let (receiver, sender) = tokio::io::split(stream);

        // Convert the streams into a `Connection`
        let connection = Connection::from_streams(sender, receiver, middleware);

        Ok(connection)
    }
}

/// The listener struct. Needed to receive messages over TCP. Is a light
/// wrapper around `tokio::net::TcpListener` and `tokio_rustls::TlsAcceptor`.
pub struct TcpTlsListener {
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

#[async_trait]
impl Listener<UnfinalizedTcpTlsConnection> for TcpTlsListener {
    /// Accept an unfinalized connection from the listener.
    ///
    /// # Errors
    /// - If we fail to accept a connection from the listener.
    async fn accept(&self) -> Result<UnfinalizedTcpTlsConnection> {
        // Try to accept a connection from the underlying endpoint
        // Split into reader and writer half
        let connection = bail!(
            self.tcp_listener.accept().await,
            Connection,
            "failed to accept connection"
        );

        // Return the unfinalized connection
        Ok(UnfinalizedTcpTlsConnection {
            tcp_stream: connection.0,
            tls_acceptor: self.tls_acceptor.clone(),
        })
    }
}

/// Soft closing is a no-op for TCP connections.
#[async_trait]
impl<T> SoftClose for WriteHalf<T> {}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};

    use super::super::tests::test_connection as super_test_connection;
    use super::TcpTls;

    #[tokio::test]
    /// Test connection establishment, listening for connections, and message
    /// sending and receiving. Just proxies to the super traits' function
    pub async fn test_connection() -> Result<()> {
        // Get random, available port
        let Some(port) = portpicker::pick_unused_port() else {
            return Err(anyhow!("no unused ports"));
        };

        // Test using the super's function
        super_test_connection::<TcpTls>(format!("127.0.0.1:{port}")).await
    }
}
