//! This file defines and implements a thin wrapper around a QUIC
//! connection that implements our message framing and connection
//! logic.

use async_trait::async_trait;
use quinn::{ClientConfig, Connecting, Endpoint, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "insecure")]
use crate::crypto::tls::SkipServerVerification;
use crate::{
    bail, bail_option,
    crypto::{self},
    error::{Error, Result},
    message::Message,
    read_length_delimited, write_length_delimited, MAX_MESSAGE_SIZE,
};
use std::{collections::VecDeque, net::ToSocketAddrs, sync::Arc};

use super::{Listener, Protocol, Receiver, Sender, UnfinalizedConnection};

#[cfg(feature = "metrics")]
use crate::connection::metrics;

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

        // Open a bidirectional stream over the connection
        let (sender, receiver) = bail!(
            connection.open_bi().await,
            Connection,
            "failed to open bidirectional stream"
        );

        Ok((QuicSender(sender), QuicReceiver(receiver)))
    }

    /// Binds to a local endpoint. Uses `maybe_tls_cert_path` and `maybe_tls_cert_key`
    /// to conditionally load or generate the given (or not given) certificate.
    ///
    /// # Errors
    /// - If we cannot load the certificate
    /// - If we cannot bind to the local interface
    async fn bind(
        bind_address: std::net::SocketAddr,
        maybe_tls_cert_path: Option<String>,
        maybe_tls_key_path: Option<String>,
    ) -> Result<Self::Listener> {
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

pub struct QuicSender(quinn::SendStream);

#[async_trait]
impl Sender for QuicSender {
    /// Send a message over the connection.
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
    /// - If we fail to deliver any of the messages. This usually means a connection problem.
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
            self.0.finish().await,
            Connection,
            "failed to finish connection"
        );

        Ok(())
    }
}

pub struct QuicReceiver(quinn::RecvStream);

#[async_trait]
impl Receiver for QuicReceiver {
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

/// A connection that has yet to be finalized. Allows us to keep accepting
/// connections while we process this one.
pub struct UnfinalizedQuicConnection(Connecting);

#[async_trait]
impl UnfinalizedConnection<QuicSender, QuicReceiver> for UnfinalizedQuicConnection {
    /// Finalize the connection by awaiting on `Connecting` and accepting a bidirectional
    /// stream.
    ///
    /// # Errors
    /// If we fail to accept a bidirectional stream or finish our connection.
    async fn finalize(self) -> Result<(QuicSender, QuicReceiver)> {
        // Await on the `Connecting` to obtain `Connection`
        let connection = bail!(self.0.await, Connection, "failed to finalize connection");

        // Accept a bidirectional stream from the connection
        let (sender, receiver) = bail!(
            connection.accept_bi().await,
            Connection,
            "failed to accept bidirectional stream"
        );

        // Split and return the finalized connection
        Ok((QuicSender(sender), QuicReceiver(receiver)))
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
