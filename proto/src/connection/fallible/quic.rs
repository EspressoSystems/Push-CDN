//! This file defines and implements a thin wrapper around a QUIC
//! connection that implements our message framing and connection
//! logic.

use async_trait::async_trait;
use quinn::{ClientConfig, Endpoint};

use crate::{
    bail, bail_option,
    connection::Connection,
    crypto::SkipServerVerification,
    error::{Error, Result},
    message::Message,
    MAX_MESSAGE_SIZE,
};
use core::hash::Hash;
use std::{net::ToSocketAddrs, sync::Arc};

/// `Quic` is a thin wrapper around `quinn::Connection` that implements
/// `Connection`.
#[derive(Clone)]
pub struct Quic(pub quinn::Connection);

/// `PartialEq` for a `Quic` connection is determined by the `stable_id` since it
/// will not change for the duration of the connection.
impl PartialEq for Quic {
    fn eq(&self, other: &Self) -> bool {
        self.0.stable_id() == other.0.stable_id()
    }
}

/// Assertion for `Quic` that `PartialEq` == `Eq`
impl Eq for Quic {
    fn assert_receiver_is_total_eq(&self) {}
}

/// `Hash` for a `Quic` connection is determined by the `stable_id` since it
/// will not change for the duration of the connection. We just want to hash that.
impl Hash for Quic {
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

#[async_trait(?Send)]
impl Connection for Quic {
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
            stream.read_to_end(MAX_MESSAGE_SIZE as usize).await,
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
    /// Errors if we either failed to open the stream or send the message over that stream.
    /// This usually means a connection problem.
    async fn send_message(&self, message: Arc<Message>) -> Result<()> {
        // Open the outgoing unidirectional stream
        let mut stream = bail!(
            self.0.open_uni().await,
            Connection,
            "failed to open unidirectional stream"
        );

        // Serialize the message
        let message_bytes = bail!(
            message.as_ref().serialize(),
            Serialize,
            "failed to serialize message"
        );

        // Write the full message to the stream
        bail!(
            stream.write_all(&message_bytes).await,
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
        Ok(Self(bail!(
            bail!(
                endpoint.connect(remote_address, domain_name),
                Connection,
                "failed to connect to remote address"
            )
            .await,
            Connection,
            "failed to connect to remote address"
        )))
    }
}
