//! This file defines and implements a thin wrapper around a TCP
//! connection that implements our message framing and connection
//! logic.

use async_trait::async_trait;

use bytes::Bytes;
use kanal::{bounded_async, AsyncReceiver, AsyncSender};
use std::result::Result as StdResult;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    spawn,
    task::AbortHandle,
};

#[cfg(feature = "metrics")]
use crate::connection::metrics;

use crate::{
    bail, bail_option,
    error::{Error, Result},
    message::Message,
    read_length_delimited, write_length_delimited, MAX_MESSAGE_SIZE,
};
use std::{net::ToSocketAddrs, sync::Arc};

use super::{Listener, Protocol, Receiver, Sender, UnfinalizedConnection};

/// The `Tcp` protocol. We use this to define commonalities between TCP
/// listeners, connections, etc.
#[derive(Clone, PartialEq, Eq)]
pub struct Tcp;

#[async_trait]
impl Protocol for Tcp {
    type Sender = TcpSender;
    type Receiver = TcpReceiver;

    type Listener = TcpListener;
    type UnfinalizedConnection = UnfinalizedTcpConnection;

    /// Connect to a remote endpoint, returning an instance of `Self`.
    /// With TCP, this requires just connecting to the remote endpoint.
    ///
    /// # Errors
    /// Errors if we fail to connect or if we fail to bind to the interface we want.
    async fn connect(remote_endpoint: &str) -> Result<(Self::Sender, Self::Receiver)>
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

        // Create a new TCP socket
        let socket = bail!(
            TcpSocket::new_v4(),
            Connection,
            "failed to bind to local socket"
        );

        // Connect the stream to the local socket
        let stream = bail!(
            socket.connect(remote_address).await,
            Connection,
            "failed tcp connect to remote address"
        );

        // Split the connection into a `ReadHalf` and `WriteHalf`, spawning tasks so we can operate
        // concurrently over both
        let (sender, receiver) = into_split(stream);

        // Return the sender and receiver
        Ok((sender, receiver))
    }

    /// Binds to a local endpoint. Does not use a TLS configuration.
    ///
    /// # Errors
    /// - If we cannot bind to the local interface
    async fn bind(
        bind_address: std::net::SocketAddr,
        _maybe_tls_cert_path: Option<String>,
        _maybe_tls_key_path: Option<String>,
    ) -> Result<Self::Listener> {
        // Try to bind to the local address
        Ok(TcpListener(bail!(
            tokio::net::TcpListener::bind(bind_address).await,
            Connection,
            "failed to bind to local address"
        )))
    }
}

#[derive(Clone)]
pub struct TcpSender(Arc<TcpSenderRef>);

#[derive(Clone)]
struct TcpSenderRef(AsyncSender<Bytes>, Arc<AbortHandle>);

fn into_split(connection: TcpStream) -> (TcpSender, TcpReceiver) {
    // Create a channel for sending messages to the task. 40 messages was chosen arbitrarily
    let (send_to_task, receive_as_task) = bounded_async(40);

    // Create a channel for receiving messages from the task. 40 messages was chosen arbitrarily
    let (send_as_task, receive_from_task) = bounded_async(40);

    // Split the connection into owned halves
    let (mut read_half, mut write_half) = connection.into_split();

    // Start the sending task
    let sending_task = spawn(async move {
        loop {
            // Receive a message from our code
            let Ok(message): StdResult<Bytes, _> = receive_as_task.recv().await else {
                // If the channel is closed, stop.
                return;
            };

            // Send a message over the real connection
            write_length_delimited!(write_half, message);
        }
    })
    .abort_handle();

    // Start the receiving task
    let receiving_task = spawn(async move {
        loop {
            // Receive a message from the real connection
            let message = Bytes::from(read_length_delimited!(read_half));

            // Send a message to our code
            if send_as_task.send(message).await.is_err() {
                // If the channel is closed, stop
                return;
            };
        }
    })
    .abort_handle();

    (
        TcpSender(Arc::from(TcpSenderRef(
            send_to_task,
            Arc::from(receiving_task),
        ))),
        TcpReceiver(Arc::from(TcpReceiverRef(
            receive_from_task,
            Arc::from(sending_task),
        ))),
    )
}

#[async_trait]
impl Sender for TcpSender {
    async fn send_message(&self, message: Message) -> Result<()> {
        // Serialize our message
        let raw_message = Bytes::from(bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        ));

        // Send the message in its raw form
        self.send_message_raw(raw_message).await
    }

    async fn send_message_raw(&self, raw_message: Bytes) -> Result<()> {
        // Send the message over our channel
        bail!(
            self.0.0.send(raw_message).await,
            Connection,
            "failed to send message: connection closed"
        );

        Ok(())
    }
}

#[derive(Clone)]
pub struct TcpReceiver(Arc<TcpReceiverRef>);

#[derive(Clone)]
struct TcpReceiverRef(AsyncReceiver<Bytes>, Arc<AbortHandle>);

#[async_trait]
impl Receiver for TcpReceiver {
    async fn recv_message(&self) -> Result<Message> {
        // Receive the message
        let raw_message = bail!(
            self.0.0.recv().await,
            Connection,
            "failed to receive message: connection closed"
        );

        // Deserialize the message
        let message = bail!(
            Message::deserialize(&raw_message),
            Deserialize,
            "failed to deserialize message"
        );

        // Return the message
        Ok(message)
    }
}

/// A connection that has yet to be finalized. Allows us to keep accepting
/// connections while we process this one.
pub struct UnfinalizedTcpConnection(TcpStream);

#[async_trait]
impl UnfinalizedConnection<TcpSender, TcpReceiver> for UnfinalizedTcpConnection {
    /// Finalize the connection by splitting it into a sender and receiver side.
    /// Conssumes `Self`.
    ///
    /// # Errors
    /// Does not actually error, but satisfies trait bounds.
    async fn finalize(self) -> Result<(TcpSender, TcpReceiver)> {
        // Split the connection and start the sending and receiving tasks
        let (sender, receiver) = into_split(self.0);

        // Wrap and return the finalized connection
        Ok((sender, receiver))
    }
}

/// The listener struct. Needed to receive messages over TCP. Is a light
/// wrapper around `tokio::net::TcpListener`.
pub struct TcpListener(pub tokio::net::TcpListener);

#[async_trait]
impl Listener<UnfinalizedTcpConnection> for TcpListener {
    /// Accept an unfinalized connection from the listener.
    ///
    /// # Errors
    /// - If we fail to accept a connection from the listener.
    /// TODO: be more descriptive with this
    /// TODO: match on whether the endpoint is closed, return a different error
    async fn accept(&self) -> Result<UnfinalizedTcpConnection> {
        // Try to accept a connection from the underlying endpoint
        // Split into reader and writer half
        let connection = bail!(
            self.0.accept().await,
            Connection,
            "failed to accept connection"
        );

        // Return the unfinalized connection
        Ok(UnfinalizedTcpConnection(connection.0))
    }
}

/// A macro to read a length-delimited (serialized) message from a stream.
/// Has a bounds check for if the message is too big
#[macro_export]
macro_rules! read_length_delimited {
    ($stream: expr) => {{
        // Read the message size from the stream
        let Ok(message_size) = $stream.read_u64().await else {
            return;
        };

        // Make sure the message isn't too big
        if message_size > MAX_MESSAGE_SIZE {
            return;
        }

        // Create buffer of the proper size
        let mut buffer = vec![0; usize::try_from(message_size).expect("64 bit system")];

        // Read the message from the stream
        if $stream.read_exact(&mut buffer).await.is_err() {
            return;
        }

        // Add to our metrics, if desired
        #[cfg(feature = "metrics")]
        metrics::BYTES_RECV.add(message_size as f64);

        buffer
    }};
}

/// A macro to write a length-delimited (serialized) message to a stream.
#[macro_export]
macro_rules! write_length_delimited {
    ($stream: expr, $message:expr) => {
        // Get the length of the message
        let message_len = $message.len() as u64;

        // Write the message size to the stream
        if $stream.write_u64(message_len).await.is_err() {
            return;
        }

        // Write the message to the stream
        if $stream.write_all(&$message).await.is_err() {
            return;
        }

        // Increment the number of bytes we've sent by this amount
        #[cfg(feature = "metrics")]
        metrics::BYTES_SENT.add(message_len as f64);
    };
}

/// If we drop the sender, we want to shut down the receiver.
impl Drop for TcpSenderRef {
    fn drop(&mut self) {
        self.1.abort();
    }
}

/// If we drop the receiver, we want to shut down the sender.
impl Drop for TcpReceiverRef {
    fn drop(&mut self) {
        self.1.abort();
    }
}
