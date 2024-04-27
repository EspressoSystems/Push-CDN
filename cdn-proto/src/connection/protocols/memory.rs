//! The memory protocol is a completely in-memory channel-based protocol.
//! It can only be used intra-process.

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use kanal::{unbounded_async, AsyncReceiver, AsyncSender};
use rustls::{Certificate, PrivateKey};
use tokio::{sync::RwLock, task::spawn_blocking};

use super::{Connection, Listener, Protocol, UnfinalizedConnection};
#[cfg(feature = "metrics")]
use crate::connection::metrics::{BYTES_RECV, BYTES_SENT};
use crate::{
    bail,
    connection::{middleware::Middleware, Bytes},
    error::{Error, Result},
    message::Message,
};

type SenderChannel = AsyncSender<Bytes>;
type ReceiverChannel = AsyncReceiver<Bytes>;

type ChannelExchange = (AsyncSender<SenderChannel>, AsyncReceiver<SenderChannel>);

/// A global list of listeners that are initialized later. This is to help
/// connections find listeners.
static LISTENERS: OnceLock<RwLock<HashMap<String, ChannelExchange>>> = OnceLock::new();

#[derive(Clone, PartialEq, Eq)]
/// The `Memory` protocol. Runs everything through channels for local testing purposes.
pub struct Memory;

#[async_trait]
impl<M: Middleware> Protocol<M> for Memory {
    type Connection = MemoryConnection;

    type UnfinalizedConnection = UnfinalizedMemoryConnection;
    type Listener = MemoryListener;

    /// Connect to the internal, local endpoint.
    ///
    /// # Errors
    /// - If the listener is not listening
    async fn connect(
        remote_endpoint: &str,
        _use_local_authority: bool,
    ) -> Result<MemoryConnection> {
        // If the peer is not listening, return an error
        // Get or initialize the channels as a static value
        let listeners = LISTENERS.get_or_init(RwLock::default).read().await;
        let Some((channel_exchange_sender, channel_exchange_receiver)) =
            listeners.get(remote_endpoint)
        else {
            return Err(Error::Connection(
                "failed to connect to remote: connection refused".to_string(),
            ));
        };

        // Create a channel for sending messages and receiving them
        let (send_to_us, receive_from_them) = unbounded_async();

        // Send our channel to them
        bail!(
            channel_exchange_sender.send(send_to_us).await,
            Connection,
            "failed to connect to remote endpoint"
        );

        // Receive their channel
        let send_to_them = bail!(
            channel_exchange_receiver.recv().await,
            Connection,
            "failed to connect to remote endpoint"
        );

        // Return the conmunication channels
        Ok(MemoryConnection {
            sender: Arc::from(MemorySenderRef(send_to_them)),
            receiver: Arc::from(MemoryReceiverRef(receive_from_them)),
        })
    }

    /// Binds to a local endpoint. The bind endpoint should be numeric.
    ///
    /// # Errors
    /// - If we fail to parse the local bind endpoint
    /// - If we fail to bind to the local endpoint
    async fn bind(
        bind_endpoint: &str,
        _certificate: Certificate,
        _key: PrivateKey,
    ) -> Result<Self::Listener> {
        // Create our channels
        let (send_to_us, receive_from_them) = unbounded_async();
        let (send_to_them, receive_from_us) = unbounded_async();

        // Add to our listeners
        let mut listeners = LISTENERS.get_or_init(RwLock::default).write().await;
        listeners.insert(bind_endpoint.to_string(), (send_to_us, receive_from_us));

        // Return our listener as a u64 bind endpoint
        Ok(MemoryListener {
            bind_endpoint: bind_endpoint.to_string(),
            receive_new_connection: receive_from_them,
            send_to_new_connection: send_to_them,
        })
    }
}

#[derive(Clone)]
pub struct MemoryConnection {
    pub sender: Arc<MemorySenderRef>,
    pub receiver: Arc<MemoryReceiverRef>,
}

#[derive(Clone)]
pub struct MemorySenderRef(AsyncSender<Bytes>);

#[async_trait]
impl Connection for MemoryConnection {
    /// Send an (unserialized) message over the stream.
    ///
    /// # Errors
    /// If we fail to send or serialize the message
    async fn send_message(&self, message: Message) -> Result<()> {
        // Serialize the message
        let raw_message = Bytes::from_unchecked(bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        ));

        // Add to our metrics, if desired
        #[cfg(feature = "metrics")]
        BYTES_SENT.add(raw_message.len() as f64);

        // Send the now-raw message
        self.send_message_raw(raw_message).await
    }

    /// Send a pre-serialized message over the connection.
    ///
    /// # Errors
    /// - If we fail to deliver the message. This usually means a connection problem.
    async fn send_message_raw(&self, raw_message: Bytes) -> Result<()> {
        // Send the message over the channel
        bail!(
            self.sender.0.send(raw_message).await,
            Connection,
            "failed to send message over connection"
        );

        Ok(())
    }

    /// Receives a single message from our channel and deserializes
    /// it.
    ///
    /// # Errors
    /// - If the other side of the channel is closed
    /// - If we fail deserialization
    async fn recv_message(&self) -> Result<Message> {
        // Receive raw message
        let raw_message = self.recv_message_raw().await?;

        // Deserialize and return the message
        Ok(bail!(
            Message::deserialize(&raw_message),
            Deserialize,
            "failed to deserialize message"
        ))
    }

    /// Receives a single message from our channel without
    /// deserializing≥
    ///
    /// # Errors
    /// - If the other side of the channel is closed
    /// - If we fail deserialization
    async fn recv_message_raw(&self) -> Result<Bytes> {
        // Receive a message from the channel
        let raw_message = bail!(
            self.receiver.0.recv().await,
            Connection,
            "failed to receive message from connection"
        );

        // Add to our metrics, if desired
        #[cfg(feature = "metrics")]
        BYTES_RECV.add(raw_message.len() as f64);

        Ok(raw_message)
    }

    /// Finish the connection, sending any remaining data.
    /// Is a no-op for memory connections.
    async fn finish(&self) {}
}

#[derive(Clone)]
pub struct MemoryReceiverRef(pub AsyncReceiver<Bytes>);

/// A connection that has yet to be finalized. Allows us to keep accepting
/// connections while we process this one.
pub struct UnfinalizedMemoryConnection {
    bytes_sender: SenderChannel,
    bytes_receiver: ReceiverChannel,
}

#[async_trait]
impl UnfinalizedConnection<MemoryConnection> for UnfinalizedMemoryConnection {
    /// Prepares the `MemoryConnection` for usage by `Arc()ing` things.
    async fn finalize(self) -> Result<MemoryConnection> {
        Ok(MemoryConnection {
            sender: Arc::from(MemorySenderRef(self.bytes_sender)),
            receiver: Arc::from(MemoryReceiverRef(self.bytes_receiver)),
        })
    }
}

/// Contains a way to send and receive to new channels, and the bind endpoint
/// so we can remove on drop.
pub struct MemoryListener {
    bind_endpoint: String,
    receive_new_connection: AsyncReceiver<SenderChannel>,
    send_to_new_connection: AsyncSender<SenderChannel>,
}

#[async_trait]
impl Listener<UnfinalizedMemoryConnection> for MemoryListener {
    /// Accept an unfinalized connection from the listener. Just
    /// receives from our channel and performs channel exchange
    /// with the connector.
    ///
    /// # Errors
    /// - If we fail to accept a connection from the listener.
    async fn accept(&self) -> Result<UnfinalizedMemoryConnection> {
        // Accept a channel from the sender
        let bytes_sender = bail!(
            self.receive_new_connection.recv().await,
            Connection,
            "failed to accept remote connection"
        );

        // Create our bytes sender
        let (send_bytes_to_us, bytes_receiver) = unbounded_async();

        // Send the remote connection our channel
        bail!(
            self.send_to_new_connection.send(send_bytes_to_us).await,
            Connection,
            "failed to finalize connection"
        );

        // Return this as unfinalized
        Ok(UnfinalizedMemoryConnection {
            bytes_sender,
            bytes_receiver,
        })
    }
}

/// On `Drop`, we want to remove ourself from the map of listeners.
impl Drop for MemoryListener {
    fn drop(&mut self) {
        // Clone the bind endpoint so we can use it
        let bind_endpoint = self.bind_endpoint.clone();

        // Spawn a blocking task to remove the listener
        spawn_blocking(move || async move {
            let mut listeners = LISTENERS.get_or_init(RwLock::default).write().await;
            listeners.remove(&bind_endpoint);
        });
    }
}

/// If we drop the sender, we want to close the channel
impl Drop for MemorySenderRef {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// If we drop the receiver, we want to close the channel
impl Drop for MemoryReceiverRef {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl Memory {
    /// Generate a testing pair of channels for sending and receiving in memory.
    /// This is particularly useful for tests.
    #[must_use]
    pub fn gen_testing_connection() -> MemoryConnection {
        // Create channels
        let (sender, receiver) = unbounded_async();

        MemoryConnection {
            sender: Arc::from(MemorySenderRef(sender)),
            receiver: Arc::from(MemoryReceiverRef(receiver)),
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::super::tests::test_connection as super_test_connection;
    use super::Memory;

    #[tokio::test]
    /// Test connection establishment, listening for connections, and message
    /// sending and receiving. Just proxies to the super traits' function
    pub async fn test_connection() -> Result<()> {
        super_test_connection::<Memory>("0".to_string()).await?;

        // Do a second test here because of the global, shared values
        super_test_connection::<Memory>("1".to_string()).await
    }
}
