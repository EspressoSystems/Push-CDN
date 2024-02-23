//! This file defines and implements a thin wrapper around a QUIC
//! connection that implements our message framing and connection
//! logic.

use async_trait::async_trait;
use quinn::{ClientConfig, Connecting, Endpoint, ServerConfig, VarInt};

#[cfg(feature = "insecure")]
use crate::crypto::tls::SkipServerVerification;
use crate::{
    bail, bail_option, connection::Bytes, crypto, error::{Error, Result}, message::Message, parse_socket_address, MAX_MESSAGE_SIZE
};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use super::{Listener, Protocol, Receiver, Sender, UnfinalizedConnection};

#[cfg(feature = "metrics")]
use crate::connection::metrics::{BYTES_RECV, BYTES_SENT};

/// The `Quic` protocol. We use this to define commonalities between QUIC
/// listeners, connections, etc.
#[derive(Clone, PartialEq, Eq)]
pub struct Quic;

#[async_trait]
impl Protocol for Quic {
    type Sender = QuicSender;
    type Receiver = QuicReceiver;

    type UnfinalizedConnection = UnfinalizedQuicConnection;
    type Listener = QuicListener;

    async fn connect(remote_endpoint: &str) -> Result<(QuicSender, QuicReceiver)> {
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

        // Parse host for certificate. We need this to ensure that the
        // TLS cert matches what the server is providing.
        let domain_name = bail_option!(
            remote_endpoint.split(':').next(),
            Parse,
            "failed to parse suitable host from provided endpoint"
        );

        // Create QUIC endpoint
        let mut endpoint = bail!(
            Endpoint::client(bail!(
                "0.0.0.0:0".parse(),
                Parse,
                "failed to parse local bind address"
            )),
            Connection,
            "failed to bind to local address"
        );

        // Set up TLS configuration
        #[cfg(not(feature = "insecure"))]
        // Production mode: native certs
        let config = ClientConfig::with_native_roots();

        // Local testing mode: skip server verification, insecure
        #[cfg(feature = "insecure")]
        let config = ClientConfig::new(SkipServerVerification::new_config());

        // Set default client config
        endpoint.set_default_client_config(config);

        // Connect with QUIC endpoint to remote address
        let connection = bail!(
            bail!(
                endpoint.connect(remote_address, domain_name),
                Connection,
                "failed quic connect to remote address"
            )
            .await,
            Connection,
            "failed quic connect to remote address"
        );

        Ok((
            QuicSender(Arc::from(QuicSenderRef(connection.clone()))),
            QuicReceiver(Arc::from(QuicReceiverRef(connection))),
        ))
    }

    /// Binds to a local endpoint. Uses `maybe_tls_cert_path` and `maybe_tls_cert_key`
    /// to conditionally load or generate the given (or not given) certificate.
    ///
    /// # Errors
    /// - If we cannot parse the bind address
    /// - If we cannot load the certificate
    /// - If we cannot bind to the local interface
    async fn bind(
        bind_address: &str,
        maybe_tls_cert_path: Option<String>,
        maybe_tls_key_path: Option<String>,
    ) -> Result<Self::Listener> {
        // Parse the bind address
        let bind_address: SocketAddr = parse_socket_address!(bind_address);

        // Conditionally load or generate a certificate and key
        let (certificates, key) = bail!(
            crypto::tls::load_or_self_sign_tls_certificate_and_key(
                maybe_tls_cert_path,
                maybe_tls_key_path,
            ),
            Crypto,
            "failed to load or self-sign TLS certificate"
        );

        // Create server configuration from the loaded certificate
        let server_config = bail!(
            ServerConfig::with_single_cert(certificates, key),
            Crypto,
            "failed to load TLS certificate"
        );

        // Create endpoint from the given server configuration and
        // bind address
        Ok(QuicListener(bail!(
            Endpoint::server(server_config, bind_address),
            Connection,
            "failed to bind to local address"
        )))
    }
}

#[derive(Clone)]
pub struct QuicSender(Arc<QuicSenderRef>);

#[derive(Clone)]
pub struct QuicSenderRef(quinn::Connection);

#[async_trait]
impl Sender for QuicSender {
    /// Send an (unserialized) message over the stream.
    ///
    /// # Errors
    /// If we fail to send or serialize the message
    async fn send_message(&self, message: Message) -> Result<()> {
        // Serialize the message
        let raw_message = Bytes::from(bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        ));

        // Send the now-raw message
        self.send_message_raw(raw_message).await
    }

    /// Send a pre-serialized message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message_raw(&self, raw_message: Bytes) -> Result<()> {
        // Open an outgoing `SendStream`
        let mut send_stream = bail!(
            self.0 .0.open_uni().await,
            Connection,
            "failed to open outgoing stream"
        );

        // Send the serialized message over the stream
        bail!(
            send_stream.write_all(&raw_message).await,
            Connection,
            "failed to write message to stream"
        );

        // Close the stream, indiciating all data has been sent
        bail!(
            send_stream.finish().await,
            Connection,
            "failed to finish sending stream"
        );

        // If enabled, write to our metrics
        #[cfg(feature = "metrics")]
        BYTES_SENT.add(raw_message.len() as f64);

        Ok(())
    }
}

#[derive(Clone)]
pub struct QuicReceiver(Arc<QuicReceiverRef>);

#[derive(Clone)]
pub struct QuicReceiverRef(quinn::Connection);

#[async_trait]
impl Receiver for QuicReceiver {
    /// Receives a single message over the stream and deserializes
    /// it.
    ///
    /// # Errors
    /// - if we fail to accept an incoming stream
    /// - if we fail to receive the message
    /// - if we fail deserialization
    async fn recv_message(&self) -> Result<Message> {
        // Accept an incoming unidirectional stream
        let mut recv_stream = bail!(
            self.0 .0.accept_uni().await,
            Connection,
            "failed to accept incoming stream"
        );

        // Read until the end, when the sender has indicated it's done reading
        // TODO: serverside, set time out here
        let raw_message = Bytes::from(bail!(
            recv_stream.read_to_end(MAX_MESSAGE_SIZE as usize).await,
            Connection,
            "failed to read bytes from receiving stream"
        ));

        // If enabled, write to our metrics
        #[cfg(feature = "metrics")]
        BYTES_RECV.add(raw_message.len() as f64);

        // Deserialize and return the message
        Ok(bail!(
            Message::deserialize(&raw_message),
            Deserialize,
            "failed to deserialize message"
        ))
    }
}

/// A connection that has yet to be finalized. Allows us to keep accepting
/// connections while we process this one.
pub struct UnfinalizedQuicConnection(Connecting);

#[async_trait]
impl UnfinalizedConnection<QuicSender, QuicReceiver> for UnfinalizedQuicConnection {
    /// Finalize the connection by awaiting on `Connecting` and cloning the connection.
    ///
    /// # Errors
    /// If we to finalize our connection.
    async fn finalize(self) -> Result<(QuicSender, QuicReceiver)> {
        // Await on the `Connecting` to obtain `Connection`
        let connection = bail!(self.0.await, Connection, "failed to finalize connection");

        // Clone and return the connection
        Ok((
            QuicSender(Arc::from(QuicSenderRef(connection.clone()))),
            QuicReceiver(Arc::from(QuicReceiverRef(connection))),
        ))
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
    /// TODO: match on whether the endpoint is closed, return a different error
    /// TODO: I think we should exit the program here, it should be a failure.
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

/// If we drop the sender, we want to close the connection (to prevent us from sending data
/// to a stale connection)
impl Drop for QuicSenderRef {
    fn drop(&mut self) {
        // Close the connection with no reason
        self.0.close(VarInt::from_u32(0), b"");
    }
}

/// If we drop the receiver, we want to close the connection (to prevent us from sending data
/// to a stale connection)
impl Drop for QuicReceiverRef {
    fn drop(&mut self) {
        // Close the connection with no reason
        self.0.close(VarInt::from_u32(0), b"");
    }
}

#[cfg(test)]
mod test {
    use super::super::test::test_connection as super_test_connection;
    use super::Quic;
    use anyhow::{anyhow, Result};

    #[tokio::test]
    /// Test connection establishment, listening for connections, and message
    /// sending and receiving. Just proxies to the super traits' function
    pub async fn test_connection() -> Result<()> {
        // Get random, available port
        let Some(port) = portpicker::pick_unused_port() else {
            return Err(anyhow!("no unused ports"));
        };

        // Test using the super traits' function
        super_test_connection::<Quic>(format!("127.0.0.1:{}", port)).await
    }
}
