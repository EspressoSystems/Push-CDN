// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This module defines connections, listeners, and their implementations.

use std::{sync::Arc, time::Duration};

use async_channel::{bounded, unbounded, Receiver, Sender};
use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    task::AbortHandle,
    time::timeout,
};
use tracing::warn;

use super::{limiter::Limiter, Bytes};
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
pub mod tcp_tls;

/// The `Protocol` trait lets us be generic over a connection type (Tcp, Quic, etc).
#[async_trait]
pub trait Protocol: Send + Sync + 'static {
    type UnfinalizedConnection: UnfinalizedConnection + Send + Sync;
    type Listener: Listener<Self::UnfinalizedConnection> + Send + Sync;

    /// Connect to a remote endpoint, returning an instance of `Self`.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(
        remote_endpoint: &str,
        use_local_authority: bool,
        limiter: Limiter,
    ) -> Result<Connection>;

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
pub trait Listener<UnfinalizedConnection: Send + Sync> {
    /// Accept an unfinalized connection from the local, bound socket.
    /// Returns a connection or an error if we encountered one.
    ///
    /// # Errors
    /// If we fail to accept a connection
    async fn accept(&self) -> Result<UnfinalizedConnection>;
}

#[async_trait]
pub trait UnfinalizedConnection {
    /// Finalize an incoming connection. This is separated so we can prevent
    /// actors who are slow from clogging up the incoming connection by offloading
    /// it to a separate task.
    async fn finalize(self, limiter: Limiter) -> Result<Connection>;
}

/// A connection to a remote endpoint.
#[derive(Clone)]
pub struct Connection(Arc<ConnectionRef>);

/// A message to send over the channel, either a raw message or a soft close.
/// Soft close is used to indicate that the connection should be closed after
/// all messages have been sent.
enum BytesOrSoftClose {
    Bytes(Bytes),
    SoftClose(oneshot::Sender<()>),
}

/// A reference to a delegated connection, containing the sender and
/// receiver channels.
#[derive(Clone)]
pub struct ConnectionRef {
    sender: Sender<BytesOrSoftClose>,
    receiver: Receiver<Bytes>,

    tasks: Arc<Vec<AbortHandle>>,
}

impl Drop for ConnectionRef {
    fn drop(&mut self) {
        // Close the channels
        self.sender.close();
        self.receiver.close();

        // Abort all tasks
        for task in self.tasks.iter() {
            task.abort();
        }
    }
}

/// Implement a soft close for all types that implement `SoftClose`.
/// This allows us to soft close a connection, allowing all messages to be sent
/// before closing.
#[async_trait]
trait SoftClose {
    async fn soft_close(&mut self) {}
}

impl Connection {
    /// Create a new connection with a set of dummy streams.
    /// Used for testing purposes.
    pub fn new_test() -> Self {
        Self(Arc::new(ConnectionRef {
            sender: unbounded().0,
            receiver: unbounded().1,
            tasks: Arc::new(vec![]),
        }))
    }

    /// Converts a set of writer and reader streams into a connection.
    /// Under the hood, this spawns sending and receiving tasks.
    fn from_streams<
        W: AsyncWriteExt + Unpin + Send + SoftClose + 'static,
        R: AsyncReadExt + Unpin + Send + 'static,
    >(
        mut writer: W,
        mut reader: R,
        limiter: Limiter,
    ) -> Self {
        // Create the channels that will be used to send and receive messages.
        // Conditionally create bounded channels if the user specifies a size
        let ((send_to_caller, receive_from_task), (send_to_task, receive_from_caller)) =
            limiter.connection_message_pool_size().map_or_else(
                || (unbounded(), unbounded()),
                |size| (bounded(size), bounded(size)),
            );

        // Spawn the task that receives from the caller and sends to the stream
        let sender_task = tokio::spawn(async move {
            // While we can successfully receive messages from the caller,
            while let Ok(message) = receive_from_caller.recv().await {
                match message {
                    BytesOrSoftClose::Bytes(message) => {
                        // Write the message to the stream
                        if let Err(err) = write_length_delimited(&mut writer, message).await {
                            warn!("failed to write message to stream: {:?}", err);
                            receive_from_caller.close();
                            return;
                        };

                        // Flush the writer
                        // Is a no-op for everything but TCP+TLS
                        if let Err(err) = writer.flush().await {
                            warn!("failed to flush writer: {:?}", err);
                            receive_from_caller.close();
                            return;
                        };
                    }
                    BytesOrSoftClose::SoftClose(result_sender) => {
                        // Soft close the writer, allowing it to finish sending
                        writer.soft_close().await;

                        // Acknowledge that we've processed up to this point
                        let _ = result_sender.send(());
                    }
                }
            }
        })
        .abort_handle();

        // Spawn the task that receives from the stream and sends to the caller
        let receiver_task = tokio::spawn(async move {
            // While we can successfully read messages from the stream,
            loop {
                // Read the message from the stream
                match read_length_delimited::<R>(&mut reader, &limiter).await {
                    Ok(message) => {
                        // If successful, send the message to the caller
                        if send_to_caller.send(message).await.is_err() {
                            send_to_caller.close();
                            return;
                        };
                    }
                    Err(err) => {
                        // If we fail to read the message, log the error and break
                        warn!("failed to read message from stream: {:?}", err);
                        break;
                    }
                }
            }
        })
        .abort_handle();

        // Return the connection
        Self(Arc::new(ConnectionRef {
            sender: send_to_task,
            receiver: receive_from_task,
            tasks: Arc::from(vec![sender_task, receiver_task]),
        }))
    }

    /// Send an (unserialized) message over the stream.
    ///
    /// # Errors
    /// If we fail to send or serialize the message
    pub async fn send_message(&self, message: Message) -> Result<()> {
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
    pub async fn send_message_raw(&self, raw_message: Bytes) -> Result<()> {
        // Send the message
        bail!(
            self.0
                .sender
                .send(BytesOrSoftClose::Bytes(raw_message))
                .await,
            Connection,
            "failed to send message"
        );

        Ok(())
    }

    /// Receives a message from the stream and deserializes it.
    ///
    /// # Errors
    /// - if we fail to receive the message
    /// - if we fail deserialization
    pub async fn recv_message(&self) -> Result<Message> {
        // Receive the raw message
        let raw_message = self.recv_message_raw().await?;

        // Deserialize and return the message
        Ok(bail!(
            Message::deserialize(&raw_message),
            Deserialize,
            "failed to deserialize message"
        ))
    }

    /// Receives a message over the stream without deserializing.
    ///
    /// # Errors
    /// - if we fail to receive the message
    pub async fn recv_message_raw(&self) -> Result<Bytes> {
        // Receive and return the message
        Ok(bail!(
            self.0.receiver.recv().await,
            Connection,
            "failed to receive message"
        ))
    }

    /// Soft close the connection, allowing all messages to be sent before closing.
    ///
    /// # Errors
    /// - If we fail to soft close the connection
    pub async fn soft_close(&self) -> Result<()> {
        // Create notifier to wait for the flush message to be acknowledged
        let (soft_close_sender, soft_close_receiver) = oneshot::channel();

        // Send the soft close message
        bail!(
            self.0
                .sender
                .send(BytesOrSoftClose::SoftClose(soft_close_sender))
                .await,
            Connection,
            "failed to flush connection"
        );

        // Wait to receive the result
        match soft_close_receiver.await {
            Ok(()) => Ok(()),
            _ => Err(Error::Connection("failed to flush connection".to_string())),
        }
    }
}

/// Read a length-delimited (serialized) message from a stream.
/// Has a bounds check for if the message is too big
async fn read_length_delimited<R: AsyncReadExt + Unpin + Send>(
    stream: &mut R,
    limiter: &Limiter,
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
    let permit = limiter.allocate_message_bytes(message_size).await;

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

    // Add to our metrics, if desired and available
    #[cfg(feature = "metrics")]
    if let Some(bytes_recv) = metrics::BYTES_RECV.as_ref() {
        bytes_recv.add(f64::from(message_size));
    }

    Ok(Bytes::from(buffer, permit))
}

/// Write a length-delimited (serialized) message to a stream.
async fn write_length_delimited<W: AsyncWriteExt + Unpin + Send>(
    stream: &mut W,
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

    // Increment the number of bytes we've sent by this amount, if available
    #[cfg(feature = "metrics")]
    if let Some(bytes_sent) = metrics::BYTES_SENT.as_ref() {
        bytes_sent.add(f64::from(message_len));
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use anyhow::Result;
    use tokio::{join, spawn, task::JoinHandle};

    use super::{Listener, Protocol, UnfinalizedConnection};
    use crate::{
        connection::limiter::Limiter,
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
    pub async fn test_connection<P: Protocol>(bind_endpoint: String) -> Result<()> {
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
            let connection = unfinalized_connection.finalize(Limiter::none()).await?;

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
            let connection = P::connect(bind_endpoint.as_str(), true, Limiter::none()).await?;

            // Receive a message, assert it's the correct one
            let message = connection.recv_message().await?;
            assert!(message == listener_to_new_connection);

            // Send our message
            connection.send_message(new_connection_to_listener).await?;

            // Soft close the connection, allowing all messages to be sent
            connection.soft_close().await?;

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
