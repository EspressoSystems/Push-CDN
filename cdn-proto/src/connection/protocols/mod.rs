//! This module defines connections, listeners, and their implementations.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use kanal::{AsyncReceiver, AsyncSender};
use rustls::{Certificate, PrivateKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    task::AbortHandle,
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
    type UnfinalizedConnection: UnfinalizedConnection<M> + Send + Sync;
    type Listener: Listener<Self::UnfinalizedConnection> + Send + Sync;

    /// Connect to a remote endpoint, returning an instance of `Self`.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: &str, use_local_authority: bool) -> Result<Connection>;

    /// Bind to the local endpoint, returning an instance of `Listener`.
    ///
    /// # Errors
    /// If we fail to bind to the given socket endpoint
    async fn bind(
        bind_endpoint: &str,
        certificate: Certificate,
        key: PrivateKey,
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
pub trait UnfinalizedConnection<M: Middleware> {
    /// Finalize an incoming connection. This is separated so we can prevent
    /// actors who are slow from clogging up the incoming connection by offloading
    /// it to a separate task.
    async fn finalize(self) -> Result<Connection>;
}

/// A connection to a remote endpoint.
#[derive(Clone)]
pub struct Connection(Arc<ConnectionRef>);

/// A message to send over the channel, either a raw message or a flush message.
/// The flush message is used to ensure that all messages are sent before we close the connection.
enum BytesOrFlush {
    Bytes(Bytes),
    Flush(oneshot::Sender<()>),
}

/// A reference to a delegated connection, containing the sender and
/// receiver channels.
#[derive(Clone)]
pub struct ConnectionRef {
    sender: AsyncSender<BytesOrFlush>,
    receiver: AsyncReceiver<Bytes>,

    tasks: Arc<Vec<AbortHandle>>,
}

impl Drop for ConnectionRef {
    fn drop(&mut self) {
        // Cancel all tasks
        for task in self.tasks.iter() {
            task.abort();
            self.sender.close();
            self.receiver.close();
        }
    }
}

impl Connection {
    /// Converts a set of writer and reader streams into a connection.
    /// Under the hood, this spawns sending and receiving tasks.
    fn from_streams<
        W: AsyncWriteExt + Unpin + Send + 'static,
        R: AsyncReadExt + Unpin + Send + 'static,
        M: Middleware,
    >(
        mut writer: W,
        mut reader: R,
    ) -> Self {
        // Create the channels that will be used to send and receive messages
        let (send_to_caller, receive_from_task) = kanal::unbounded_async();
        let (send_to_task, receive_from_caller) = kanal::unbounded_async();

        // Spawn the task that receives from the caller and sends to the stream
        let sender_task = tokio::spawn(async move {
            // While we can successfully receive messages from the caller,
            while let Ok(message) = receive_from_caller.recv().await {
                match message {
                    BytesOrFlush::Bytes(message) => {
                        // Write the message to the stream
                        if write_length_delimited(&mut writer, message).await.is_err() {
                            receive_from_caller.close();
                            return;
                        };
                    }
                    BytesOrFlush::Flush(result_sender) => {
                        // Acknowledge that we've finished successfully
                        let _ = result_sender.send(());
                    }
                }
            }
        })
        .abort_handle();

        // Spawn the task that receives from the stream and sends to the caller
        let receiver_task = tokio::spawn(async move {
            // While we can successfully read messages from the stream,
            while let Ok(message) = read_length_delimited::<R, M>(&mut reader).await {
                if send_to_caller.send(message).await.is_err() {
                    send_to_caller.close();
                    return;
                };
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
            self.0.sender.send(BytesOrFlush::Bytes(raw_message)).await,
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
            "failed to send message"
        ))
    }

    pub async fn flush(&self) -> Result<()> {
        // Create notifier to wait for the flush message to be acknowledged
        let (flush_sender, flush_receiver) = oneshot::channel();

        // Send the flush message
        bail!(
            self.0.sender.send(BytesOrFlush::Flush(flush_sender)).await,
            Connection,
            "failed to flush connection"
        );

        // Wait to receive the result
        match flush_receiver.await {
            Ok(()) => Ok(()),
            _ => Err(Error::Connection("failed to flush connection".to_string())),
        }
    }
}

/// Read a length-delimited (serialized) message from a stream.
/// Has a bounds check for if the message is too big
async fn read_length_delimited<R: AsyncReadExt + Unpin + Send, M: Middleware>(
    stream: &mut R,
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

    // Add to our metrics, if desired
    #[cfg(feature = "metrics")]
    metrics::BYTES_RECV.add(message_size as f64);

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

    // Increment the number of bytes we've sent by this amount
    #[cfg(feature = "metrics")]
    metrics::BYTES_SENT.add(message_len as f64);

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use anyhow::Result;
    use tokio::{join, spawn, task::JoinHandle};

    use super::{Listener, Protocol, UnfinalizedConnection};
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

            // Flush the connection, ensuring the message is sent
            connection.flush().await?;

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
