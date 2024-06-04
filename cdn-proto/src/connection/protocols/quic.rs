//! This file defines and implements a thin wrapper around a QUIC
//! connection that implements our message framing and connection
//! logic.

use std::time::Duration;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use async_trait::async_trait;
use quinn::{ClientConfig, Connecting, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::{Certificate, PrivateKey, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::{Connection, Listener, Protocol, UnfinalizedConnection};
use crate::connection::middleware::Middleware;
use crate::crypto::tls::{LOCAL_CA_CERT, PROD_CA_CERT};
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
impl<M: Middleware> Protocol<M> for Quic {
    type UnfinalizedConnection = UnfinalizedQuicConnection;
    type Listener = QuicListener;

    async fn connect(remote_endpoint: &str, use_local_authority: bool) -> Result<Connection> {
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

        // Pick which authority to trust based on whether or not we have requested
        // to use the local one
        let root_ca = if use_local_authority {
            LOCAL_CA_CERT
        } else {
            PROD_CA_CERT
        };

        // Parse the provided CA in `.PEM` format
        let root_ca = bail!(pem::parse(root_ca), Parse, "failed to parse PEM file").into_contents();

        // Create root certificate store and add our CA
        let mut root_cert_store = RootCertStore::empty();
        bail!(
            root_cert_store.add(&Certificate(root_ca)),
            File,
            "failed to add certificate to root store"
        );

        // Create config from the root store
        let mut config: ClientConfig = ClientConfig::with_root_certificates(root_cert_store);

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
        let (mut sender, receiver) = bail!(
            bail!(
                timeout(Duration::from_secs(5), connection.open_bi()).await,
                Connection,
                "timed out accepting stream"
            ),
            Connection,
            "failed to accept bidirectional stream"
        );

        // Write a `u8` to bootstrap the connection (make the sender aware of our
        // outbound stream request)
        bail!(
            sender.write_u8(0).await,
            Connection,
            "failed to bootstrap connection"
        );

        // Convert the streams into a `Connection`
        let connection = Connection::from_streams::<_, _, M>(sender, receiver);

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
        certificate: Certificate,
        key: PrivateKey,
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
pub struct UnfinalizedQuicConnection(Connecting);

#[async_trait]
impl<M: Middleware> UnfinalizedConnection<M> for UnfinalizedQuicConnection {
    /// Finalize the connection by awaiting on `Connecting` and cloning the connection.
    ///
    /// # Errors
    /// If we to finalize our connection.
    async fn finalize(self) -> Result<Connection> {
        // Await on the `Connecting` to obtain `Connection`
        let connection = bail!(self.0.await, Connection, "failed to finalize connection");

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
            "failed to bootstrap connection"
        );

        // Create a sender and receiver
        let connection = Connection::from_streams::<_, _, M>(sender, receiver);

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
