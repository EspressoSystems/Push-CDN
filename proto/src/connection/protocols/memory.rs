//! The memory protocol is a completely in-memory channel-based protocol.
//! It can only be used intra-process.

use async_trait::async_trait;
use kanal::{unbounded_async, AsyncReceiver, AsyncSender};
use tokio::{sync::RwLock, task::spawn_blocking};

use crate::{
    bail, connection::Bytes, error::{Error, Result}, message::Message
};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use super::{Listener, Protocol, Receiver, Sender, UnfinalizedConnection};

#[cfg(feature = "metrics")]
use crate::connection::metrics::{BYTES_RECV, BYTES_SENT};

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
impl Protocol for Memory {
    type Sender = MemorySender;
    type Receiver = MemoryReceiver;

    type UnfinalizedConnection = UnfinalizedMemoryConnection;
    type Listener = MemoryListener;

    /// Connect to the internal, local address.
    ///
    /// # Errors
    /// - If the listener is not listening
    async fn connect(remote_endpoint: &str) -> Result<(MemorySender, MemoryReceiver)> {
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
            "failed to connect to remote address"
        );

        // Receive their channel
        let send_to_them = bail!(
            channel_exchange_receiver.recv().await,
            Connection,
            "failed to connect to remote address"
        );

        // Return the conmunication channels
        Ok((
            MemorySender(Arc::from(MemorySenderRef(send_to_them))),
            MemoryReceiver(Arc::from(MemoryReceiverRef(receive_from_them))),
        ))
    }

    /// Binds to a local endpoint. The bind address should be numeric.
    ///
    /// # Errors
    /// - If we fail to parse the local bind address
    /// - If we fail to bind to the local address
    async fn bind(
        bind_address: &str,
        _maybe_tls_cert_path: Option<String>,
        _maybe_tls_key_path: Option<String>,
    ) -> Result<Self::Listener> {
        // Create our channels
        let (send_to_us, receive_from_them) = unbounded_async();
        let (send_to_them, receive_from_us) = unbounded_async();

        // Add to our listeners
        let mut listeners = LISTENERS.get_or_init(RwLock::default).write().await;
        listeners.insert(bind_address.to_string(), (send_to_us, receive_from_us));

        // Return our listener as a u64 bind address
        Ok(MemoryListener {
            bind_address: bind_address.to_string(),
            receive_new_connection: receive_from_them,
            send_to_new_connection: send_to_them,
        })
    }
}

#[derive(Clone)]
pub struct MemorySender(Arc<MemorySenderRef>);

#[derive(Clone)]
pub struct MemorySenderRef(AsyncSender<Bytes>);

#[async_trait]
impl Sender for MemorySender {
    /// Send an (unserialized) message over the stream.
    ///
    /// # Errors
    /// If we fail to send or serialize the message
    async fn send_message(&self, message: Message) -> Result<()> {
        // TODO: TRAIT DEFAULT FOR THIS. IT'S THE SAME
        // Serialize the message
        let raw_message = Bytes::from(bail!(
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
            self.0 .0.send(raw_message).await,
            Connection,
            "failed to send message over connection"
        );

        Ok(())
    }
}

#[derive(Clone)]
pub struct MemoryReceiver(Arc<MemoryReceiverRef>);

#[derive(Clone)]
pub struct MemoryReceiverRef(AsyncReceiver<Bytes>);

#[async_trait]
impl Receiver for MemoryReceiver {
    /// Receives a single message from our channel and deserializes
    /// it.
    ///
    /// # Errors
    /// - If the other side of the channel is closed
    /// - If we fail deserialization
    async fn recv_message(&self) -> Result<Message> {
        // Receive a message from the channel
        let raw_message = bail!(
            self.0 .0.recv().await,
            Connection,
            "failed to receive message from connection"
        );

        // Add to our metrics, if desired
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
pub struct UnfinalizedMemoryConnection {
    bytes_sender: SenderChannel,
    bytes_receiver: ReceiverChannel,
}

#[async_trait]
impl UnfinalizedConnection<MemorySender, MemoryReceiver> for UnfinalizedMemoryConnection {
    /// Prepares the `MemoryConnection` for usage by `Arc()ing` things.
    async fn finalize(self) -> Result<(MemorySender, MemoryReceiver)> {
        Ok((
            MemorySender(Arc::from(MemorySenderRef(self.bytes_sender))),
            MemoryReceiver(Arc::from(MemoryReceiverRef(self.bytes_receiver))),
        ))
    }
}

/// Contains a way to send and receive to new channels, and the bind address
/// so we can remove on drop.
pub struct MemoryListener {
    bind_address: String,
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
        // Clone the bind address so we can use it
        let bind_address = self.bind_address.clone();

        // Spawn a blocking task to remove the listener
        spawn_blocking(move || async move {
            let mut listeners = LISTENERS.get_or_init(RwLock::default).write().await;
            listeners.remove(&bind_address);
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

#[cfg(test)]
mod test {
    use super::super::test::test_connection as super_test_connection;
    use super::Memory;
    use anyhow::Result;

    #[tokio::test]
    /// Test connection establishment, listening for connections, and message
    /// sending and receiving. Just proxies to the super traits' function
    pub async fn test_connection() -> Result<()> {
        super_test_connection::<Memory>("0".to_string()).await?;

        // Do a second test here because of the global, shared values
        super_test_connection::<Memory>("1".to_string()).await
    }
}
