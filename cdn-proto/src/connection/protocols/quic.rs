// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This file defines and implements a thin wrapper around a QUIC
//! connection that implements our message framing and connection
//! logic.

use std::time::Duration;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use async_trait::async_trait;
use quinn::{ClientConfig, Endpoint, Incoming, SendStream, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::{Connection, Listener, Protocol, SoftClose, UnfinalizedConnection};
use crate::connection::middleware::Middleware;
use crate::crypto::tls::generate_root_certificate_store;
use crate::parse_endpoint;
use crate::{
    bail, bail_option,
    error::{Error, Result},
};

/// The `Quic` protocol. We use this to define commonalities between QUIC
/// listeners, connections, etc.
#[derive(Clone, PartialEq, Eq)]
pub struct Quic;

#[async_trait]
impl Protocol for Quic {
    type UnfinalizedConnection = UnfinalizedQuicConnection;
    type Listener = QuicListener;

    async fn connect(
        remote_endpoint: &str,
        use_local_authority: bool,
        middleware: Middleware,
    ) -> Result<Connection> {
        // Parse the endpoint
        let remote_endpoint = bail_option!(
            bail!(
                remote_endpoint.to_socket_addrs(),
                Parse,
                "failed to parse remote endpoint"
            )
            .next(),
            Connection,
            "did not find suitable endpoint for address"
        );

        // Create QUIC endpoint
        let mut endpoint = bail!(
            Endpoint::client(bail!(
                "0.0.0.0:0".parse(),
                Parse,
                "failed to parse local bind endpoint"
            )),
            Connection,
            "failed to bind to local endpoint"
        );

        // Generate root certificate store based on the local authority
        let root_cert_store = generate_root_certificate_store(use_local_authority)?;

        // Create config from the root store
        let mut config: ClientConfig = bail!(
            ClientConfig::with_root_certificates(root_cert_store.into()),
            Crypto,
            "failed to create client config"
        );

        // Enable sending of keep-alives
        let mut transport_config = TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
        config.transport_config(Arc::from(transport_config));

        // Set default client config
        endpoint.set_default_client_config(config);

        // Connect with QUIC endpoint to remote endpoint
        let connection = bail!(
            bail!(
                timeout(
                    Duration::from_secs(5),
                    bail!(
                        endpoint.connect(remote_endpoint, "espresso"),
                        Connection,
                        "timed out connecting to remote endpoint"
                    )
                )
                .await,
                Connection,
                "failed quic connect to remote endpoint"
            ),
            Connection,
            "failed quic connect to remote endpoint"
        );

        // Open an outgoing bidirectional stream
        let (sender, receiver) = bail!(
            bail!(
                timeout(Duration::from_secs(5), open_bi(&connection)).await,
                Connection,
                "timed out opening bidirectional stream"
            ),
            Connection,
            "failed to open bidirectional stream"
        );

        // Convert the streams into a `Connection`
        let connection = Connection::from_streams::<_, _>(sender, receiver, middleware);

        Ok(connection)
    }

    /// Binds to a local endpoint using the given certificate and key.
    ///
    /// # Errors
    /// - If we cannot parse the bind endpoint
    /// - If we cannot load the certificate
    /// - If we cannot bind to the local interface
    async fn bind(
        bind_endpoint: &str,
        certificate: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self::Listener> {
        // Parse the bind endpoint
        let bind_endpoint: SocketAddr = parse_endpoint!(bind_endpoint);

        // Create server configuration from the loaded certificate
        let mut server_config = bail!(
            ServerConfig::with_single_cert(vec![certificate], key),
            Crypto,
            "failed to load TLS certificate"
        );

        // Set the maximum numbers of concurrent streams (one and zero because we're
        // not using them for framing)
        let mut transport_config = TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(1));
        transport_config.max_concurrent_uni_streams(VarInt::from_u32(0));
        server_config.transport_config(Arc::from(transport_config));

        // Create endpoint from the given server configuration and
        // bind endpoint
        Ok(QuicListener(bail!(
            Endpoint::server(server_config, bind_endpoint),
            Connection,
            "failed to bind to local endpoint"
        )))
    }
}

/// A connection that has yet to be finalized. Allows us to keep accepting
/// connections while we process this one.
pub struct UnfinalizedQuicConnection(Incoming);

#[async_trait]
impl UnfinalizedConnection for UnfinalizedQuicConnection {
    /// Finalize the connection by awaiting on `Connecting` and cloning the connection.
    ///
    /// # Errors
    /// If we to finalize our connection.
    async fn finalize(self, middleware: Middleware) -> Result<Connection> {
        // Await on the `Connecting` to obtain `Connection`
        let connection = bail!(self.0.await, Connection, "failed to finalize connection");

        // Accept an incoming bidirectional stream
        let (sender, receiver) = bail!(
            bail!(
                timeout(Duration::from_secs(5), accept_bi(&connection)).await,
                Connection,
                "timed out accepting bidirectional stream"
            ),
            Connection,
            "failed to accept bidirectional stream"
        );

        // Create a sender and receiver
        let connection = Connection::from_streams(sender, receiver, middleware);

        // Clone and return the connection
        Ok(connection)
    }
}

/// The listener struct. Needed to receive messages over QUIC. Is a light
/// wrapper around `quinn::Endpoint`.
pub struct QuicListener(pub quinn::Endpoint);

#[async_trait]
impl Listener<UnfinalizedQuicConnection> for QuicListener {
    /// Accept an unfinalized connection from the listener.
    ///
    /// # Errors
    /// - If we fail to accept a connection from the listener.
    /// TODO: be more descriptive with this
    async fn accept(&self) -> Result<UnfinalizedQuicConnection> {
        // Try to accept a connection from the QUIC endpoint
        let connection = bail_option!(
            self.0.accept().await,
            Connection,
            "failed to accept connection"
        );

        Ok(UnfinalizedQuicConnection(connection))
    }
}

/// A helper function for opening a new connection and atomically
/// writing to it to bootstrap it.
///
/// # Errors
/// - If we fail to open a bidirectional stream
/// - If we fail to write to the stream
async fn open_bi(connection: &quinn::Connection) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    // Open a bidirectional stream
    let (mut sender, receiver) = bail!(
        connection.open_bi().await,
        Connection,
        "failed to open unidirectional stream"
    );

    // Write a `u8` to bootstrap the connection
    bail!(
        sender.write_u8(0).await,
        Connection,
        "failed to write `u8` to unidirectional stream"
    );

    Ok((sender, receiver))
}

/// A helper function for accepting a new connection and atomically
/// reading from it to bootstrap it.
///
/// # Errors
/// - If we fail to accept a bidirectional stream
/// - If we fail to read from the stream
async fn accept_bi(
    connection: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    // Accept an incoming bidirectional stream
    let (sender, mut receiver) = bail!(
        connection.accept_bi().await,
        Connection,
        "failed to accept bidirectional stream"
    );

    // Read the `u8` required to bootstrap the connection
    bail!(
        receiver.read_u8().await,
        Connection,
        "failed to read `u8` from bidirectional stream"
    );

    Ok((sender, receiver))
}

#[async_trait]
impl SoftClose for SendStream {
    /// Soft close the stream by shutting down the write side and waiting for the
    /// read side to close (with a timeout of 3 seconds).
    async fn soft_close(&mut self) {
        if self.finish().is_ok() {
            let _ = timeout(Duration::from_secs(3), self.stopped()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};

    use super::super::tests::test_connection as super_test_connection;
    use super::Quic;

    #[tokio::test]
    /// Test connection establishment, listening for connections, and message
    /// sending and receiving. Just proxies to the super traits' function
    pub async fn test_connection() -> Result<()> {
        // Get random, available port
        let Some(port) = portpicker::pick_unused_port() else {
            return Err(anyhow!("no unused ports"));
        };

        // Test using the super traits' function
        super_test_connection::<Quic>(format!("127.0.0.1:{port}")).await
    }
}
