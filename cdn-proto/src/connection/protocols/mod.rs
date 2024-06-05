//! This module defines connections, listeners, and their implementations.

use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use super::{middleware::Middleware, Bytes};
use crate::{
    bail,
    error::{Error, Result},
    message::Message,
    MAX_MESSAGE_SIZE,
};

#[cfg(feature = "metrics")]
use crate::connection::metrics;

pub mod memory;
pub mod quic;
pub mod tcp;

/// The `Protocol` trait lets us be generic over a connection type (Tcp, Quic, etc).
#[async_trait]
pub trait Protocol<M: Middleware>: Send + Sync + 'static {
    type Connection: Connection + Send + Sync + Clone;

    type UnfinalizedConnection: UnfinalizedConnection<Self::Connection> + Send + Sync;
    type Listener: Listener<Self::UnfinalizedConnection> + Send + Sync;

    /// Connect to a remote endpoint, returning an instance of `Self`.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: &str, use_local_authority: bool) -> Result<Self::Connection>;

    /// Bind to the local endpoint, returning an instance of `Listener`.
    ///
    /// # Errors
    /// If we fail to bind to the given socket endpoint
    async fn bind(
        bind_endpoint: &str,
        certificate: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self::Listener>;
}

#[async_trait]
pub trait Connection {
    /// Send an (unserialized) message over the stream.
    ///
    /// # Errors
    /// If we fail to send or serialize the message
    async fn send_message(&self, message: Message) -> Result<()>;

    /// Send a pre-serialized message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message_raw(&self, raw_message: Bytes) -> Result<()>;

    /// Receives message over the stream and deserializes it.
    ///
    /// # Errors
    /// - if we fail to receive the message
    /// - if we fail deserialization
    async fn recv_message(&self) -> Result<Message>;

    /// Receives a message over the stream without deserializing.
    ///
    /// # Errors
    /// - if we fail to receive the message
    async fn recv_message_raw(&self) -> Result<Bytes>;

    /// Flush the connection, sending any remaining data.
    async fn flush(&self);
}

#[async_trait]
pub trait Listener<UnfinalizedConnection: Send + Sync> {
    /// Accept an unfinalized connection from the local, bound socket.
    /// Returns a connection or an error if we encountered one.
    ///
    /// # Errors
    /// If we fail to accept a connection
    async fn accept(&self) -> Result<UnfinalizedConnection>;
}

#[async_trait]
pub trait UnfinalizedConnection<Connection: Send + Sync> {
    /// Finalize an incoming connection. This is separated so we can prevent
    /// actors who are slow from clogging up the incoming connection by offloading
    /// it to a separate task.
    async fn finalize(self) -> Result<Connection>;
}

/// Read a length-delimited (serialized) message from a stream.
/// Has a bounds check for if the message is too big
async fn read_length_delimited<R: AsyncReadExt + Unpin + Send, M: Middleware>(
    mut stream: R,
) -> Result<Bytes> {
    // Read the message size from the stream
    let message_size = bail!(
        stream.read_u32().await,
        Connection,
        "failed to read message size from stream"
    );

    // Make sure the message isn't too big
    if message_size > MAX_MESSAGE_SIZE {
        return Err(Error::Connection("message was too large".to_string()));
    }

    // Acquire the allocation if necessary
    let permit = M::allocate_message_bytes(message_size).await;

    // Create buffer of the proper size
    let mut buffer = vec![0; usize::try_from(message_size).expect(">= 32 bit system")];

    // Read the message from the stream
    bail!(
        bail!(
            timeout(Duration::from_secs(5), stream.read_exact(&mut buffer)).await,
            Connection,
            "timed out trying to read a message"
        ),
        Connection,
        "failed to read message"
    );

    // Drop the stream since we're done with it
    drop(stream);

    // Add to our metrics, if desired
    #[cfg(feature = "metrics")]
    metrics::BYTES_RECV.add(message_size as f64);

    Ok(Bytes::from(buffer, permit))
}

/// Write a length-delimited (serialized) message to a stream.
async fn write_length_delimited<W: AsyncWriteExt + Unpin + Send>(
    mut stream: W,
    message: Bytes,
) -> Result<()> {
    // Get the length of the message
    let message_len = bail!(
        u32::try_from(message.len()),
        Connection,
        "message was too large"
    );

    // Write the message size to the stream
    bail!(
        bail!(
            timeout(Duration::from_secs(5), stream.write_u32(message_len)).await,
            Connection,
            "timed out trying to send message length"
        ),
        Connection,
        "failed to send message length"
    );

    // Write the message size to the stream
    bail!(
        bail!(
            timeout(Duration::from_secs(5), stream.write_all(&message)).await,
            Connection,
            "timed out trying to send message"
        ),
        Connection,
        "failed to send message"
    );

    // Drop the stream since we're done with it
    drop(stream);

    // Increment the number of bytes we've sent by this amount
    #[cfg(feature = "metrics")]
    metrics::BYTES_SENT.add(message_len as f64);

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use anyhow::Result;
    use tokio::{join, spawn, task::JoinHandle};

    use super::{Connection, Listener, Protocol, UnfinalizedConnection};
    use crate::{
        connection::middleware::NoMiddleware,
        crypto::tls::{generate_cert_from_ca, LOCAL_CA_CERT, LOCAL_CA_KEY},
        message::{Direct, Message},
    };

    /// Test connection establishment, listening for connections, and message
    /// sending and receiving. All protocols should be calling this test function
    ///
    /// # Panics
    /// If any asserts fail
    ///
    /// # Errors
    /// If the connection failed
    pub async fn test_connection<P: Protocol<NoMiddleware>>(bind_endpoint: String) -> Result<()> {
        // Generate cert signed by local CA
        let (cert, key) = generate_cert_from_ca(LOCAL_CA_CERT, LOCAL_CA_KEY)?;

        // Create listener
        let listener = P::bind(bind_endpoint.as_str(), cert, key).await?;

        // The messages we will send and receive
        let new_connection_to_listener = Message::Direct(Direct {
            recipient: vec![0, 1, 2],
            message: b"direct 0,1,2".to_vec(),
        });
        let listener_to_new_connection = Message::Direct(Direct {
            recipient: vec![3, 4, 5],
            message: b"direct 3,4,5".to_vec(),
        });

        // Spawn a task to listen for and accept connections
        let listener_to_new_connection_ = listener_to_new_connection.clone();
        let new_connection_to_listener_ = new_connection_to_listener.clone();
        let listener_jh: JoinHandle<Result<()>> = spawn(async move {
            // Accept the connection
            let unfinalized_connection = listener.accept().await?;

            // Finalize the connection
            let connection = unfinalized_connection.finalize().await?;

            // Send our message
            connection.send_message(listener_to_new_connection_).await?;

            // Receive a message, assert it's the correct one
            let message = connection.recv_message().await?;
            assert!(message == new_connection_to_listener_);

            Ok(())
        });

        // Spawn a task to connect and send and receive the message
        let new_connection_jh: JoinHandle<Result<()>> = spawn(async move {
            // Connect to the remote
            let connection = P::connect(bind_endpoint.as_str(), true).await?;

            // Receive a message, assert it's the correct one
            let message = connection.recv_message().await?;
            assert!(message == listener_to_new_connection);

            // Send our message
            connection.send_message(new_connection_to_listener).await?;

            connection.flush().await;

            Ok(())
        });

        // Wait for the results
        let (listener_result, new_connection_result) = join!(listener_jh, new_connection_jh);

        // Ensure none of them errored
        listener_result??;
        new_connection_result??;

        // We were successful
        Ok(())
    }
}
