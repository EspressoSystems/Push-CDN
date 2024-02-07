//! This file defines and implements a thin wrapper around a QUIC
//! connection that implements our message framing and connection
//! logic.

use async_trait::async_trait;
use quinn::{ClientConfig, Endpoint, ServerConfig};

use crate::{
    bail, bail_option,
    crypto::{self, SkipServerVerification},
    error::{Error, Result},
    message::Message,
    MAX_MESSAGE_SIZE,
};
use core::hash::Hash;
use std::{net::ToSocketAddrs, sync::Arc};

use super::{Connection, Listener, Protocol};

/// The `Quic` protocol. We use this to define commonalities between QUIC
/// listeners, connections, etc.
#[derive(Clone, PartialEq)]
pub struct Quic;

/// We define the `Quic` protocol as being composed of both a QUIC listener
/// and connection.
impl Protocol for Quic {
    type Connection = QuicConnection;
    type Listener = QuicListener;
}

/// `QuicConnection` is a thin wrapper around `quinn::Connection` that implements
/// `Connection`.
#[derive(Clone)]
pub struct QuicConnection(pub quinn::Connection);

/// `PartialEq` for a `QuicConnection` connection is determined by the `stable_id` since it
/// will not change for the duration of the connection.
impl PartialEq for QuicConnection {
    fn eq(&self, other: &Self) -> bool {
        self.0.stable_id() == other.0.stable_id()
    }
}

/// Assertion for `QuicConnection` that `PartialEq` == `Eq`
impl Eq for QuicConnection {
    fn assert_receiver_is_total_eq(&self) {}
}

/// `Hash` for a `QuicConnection` connection is determined by the `stable_id` since it
/// will not change for the duration of the connection. We just want to hash that.
impl Hash for QuicConnection {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.stable_id().hash(state);
    }

    /// This just calls `hash` on each item in the slice.
    fn hash_slice<H: std::hash::Hasher>(data: &[Self], state: &mut H)
    where
        Self: Sized,
    {
        data.iter().for_each(|item| item.hash(state));
    }
}

#[async_trait]
impl Connection for QuicConnection {
    /// Receives a single message from the QUIC connection. Since we use
    /// virtual streams as a message framing method, this function first accepts a stream
    /// and then reads and deserializes a single message from it.
    ///
    /// # Errors
    /// Errors if we either failed to accept the stream or receive the message over that stream.
    /// This usually means a connection problem.
    async fn recv_message(&self) -> Result<Message> {
        // Accept the incoming unidirectional stream
        let mut stream = bail!(
            self.0.accept_uni().await,
            Connection,
            "failed to accept unidirectional stream"
        );

        // Read the full message, until the sender closes the stream
        let message_bytes = bail!(
            stream
                .read_to_end(usize::try_from(MAX_MESSAGE_SIZE).expect("64 bit system"))
                .await,
            Connection,
            "failed to read from stream"
        );

        // Deserialize and return the message
        Ok(bail!(
            Message::deserialize(&message_bytes),
            Deserialize,
            "failed to deserialize message"
        ))
    }

    /// Sends a single message to the QUIC connection. This function first opens a
    /// stream and then serializes and sends a single message to it.
    ///
    /// # Errors
    /// - If we fail to serialize the message
    /// - If we fail to open the stream
    /// - If we fail to send the message over that stream
    /// This usually means a connection problem.
    async fn send_message(&self, message: Message) -> Result<()> {
        // Serialize the message
        let message_bytes = bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        );

        // Send the message
        self.send_message_raw(Arc::from(message_bytes)).await
    }

    /// Send a pre-formed message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message_raw(&self, message: Arc<Vec<u8>>) -> Result<()> {
        // Open the outgoing unidirectional stream
        let mut stream = bail!(
            self.0.open_uni().await,
            Connection,
            "failed to open unidirectional stream"
        );

        // Write the full message to the stream
        bail!(
            stream.write_all(&message).await,
            Connection,
            "failed to write to stream"
        );

        // Finish the stream, denoting to the peer that the
        // message has been fully written
        Ok(bail!(
            stream.finish().await,
            Connection,
            "failed to finish stream"
        ))
    }

    /// Send a vector of pre-formed message over the connection.
    ///
    /// TODO: FIGURE OUT IF WE WANT TO FRAME LIKE THIS. it may be more performant with batching
    /// to not do it this way.
    ///
    /// # Errors
    /// - If we fail to deliver any of the messages. This usually means a connection problem.
    async fn send_messages_raw(&self, messages: Vec<Arc<Vec<u8>>>) -> Result<()> {
        // Send each message over the connection
        for message in messages {
            bail!(
                self.send_message_raw(message).await,
                Connection,
                "failed to send message"
            );
        }

        Ok(())
    }

    /// Connect to a remote endpoint, returning an instance of `Self`. With QUIC,
    /// this requires creating an endpoint, binding to it, and then attempting
    /// a connection.
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
        #[cfg(not(feature = "local-testing"))]
        // Production mode: native certs
        let config = ClientConfig::with_native_roots();

        // Local testing mode: skip server verification, insecure
        #[cfg(feature = "local-testing")]
        let config = ClientConfig::new(SkipServerVerification::new_config());

        // Set default client config
        endpoint.set_default_client_config(config);

        // Connect with QUIC endpoint to remote address
        let connection = Self(bail!(
            bail!(
                endpoint.connect(remote_address, domain_name),
                Connection,
                "failed to connect to remote address"
            )
            .await,
            Connection,
            "failed to connect to remote address"
        ));

        Ok(connection)
    }
}

/// The listener struct. Needed to receive messages over QUIC. Is a light
/// wrapper around `quinn::Endpoint`.
pub struct QuicListener(pub quinn::Endpoint);

#[async_trait]
impl Listener<QuicConnection> for QuicListener {
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
    ) -> Result<Self>
    where
        Self: Sized,
    {
        // Conditionally load or generate a certificate and key
        let (certificates, key) = bail!(
            crypto::load_or_self_sign_tls_certificate_and_key(
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
        Ok(Self(bail!(
            Endpoint::server(server_config, bind_address),
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
    async fn accept(&self) -> Result<QuicConnection> {
        // Try to accept a connection from the QUIC endpoint
        Ok(QuicConnection(bail!(
            bail_option!(
                self.0.accept().await,
                Connection,
                "failed to accept connection"
            )
            .await,
            Connection,
            "failed to accept connection"
        )))
    }
}
