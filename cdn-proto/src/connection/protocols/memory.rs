// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! The memory protocol is a completely in-memory channel-based protocol.
//! It can only be used intra-process.

use std::{collections::HashMap, sync::OnceLock};

use async_trait::async_trait;
use kanal::{unbounded_async, AsyncReceiver, AsyncSender};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    io::{duplex, DuplexStream},
    sync::RwLock,
    task::spawn_blocking,
};

use super::{Connection, Listener, Protocol, SoftClose, UnfinalizedConnection};
use crate::{
    bail,
    connection::middleware::Middleware,
    error::{Error, Result},
};

type ChannelExchange = (AsyncSender<DuplexStream>, AsyncReceiver<DuplexStream>);

/// A global list of listeners that are initialized later. This is to help
/// connections find listeners.
static LISTENERS: OnceLock<RwLock<HashMap<String, ChannelExchange>>> = OnceLock::new();

#[derive(Clone, PartialEq, Eq)]
/// The `Memory` protocol. Runs everything through channels for local testing purposes.
pub struct Memory;

#[async_trait]
impl Protocol for Memory {
    type UnfinalizedConnection = UnfinalizedMemoryConnection;
    type Listener = MemoryListener;

    /// Connect to the internal, local endpoint.
    ///
    /// # Errors
    /// - If the listener is not listening
    async fn connect(
        remote_endpoint: &str,
        _use_local_authority: bool,
        middleware: Middleware,
    ) -> Result<Connection> {
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

        // Create a duplex stream to send and receive bytes
        let (send_to_us, receive_from_them) = duplex(8192);

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

        // Convert the streams into a `Connection`
        let connection = Connection::from_streams(send_to_them, receive_from_them, middleware);

        // Return our connection
        Ok(connection)
    }

    /// Binds to a local endpoint. The bind endpoint should be numeric.
    ///
    /// # Errors
    /// - If we fail to parse the local bind endpoint
    /// - If we fail to bind to the local endpoint
    async fn bind(
        bind_endpoint: &str,
        _certificate: CertificateDer<'static>,
        _key: PrivateKeyDer<'static>,
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

/// A connection that has yet to be finalized. Allows us to keep accepting
/// connections while we process this one.
pub struct UnfinalizedMemoryConnection {
    send_stream: DuplexStream,
    receive_stream: DuplexStream,
}

#[async_trait]
impl UnfinalizedConnection for UnfinalizedMemoryConnection {
    /// Prepares the `MemoryConnection` for usage by `Arc()ing` things.
    async fn finalize(self, middleware: Middleware) -> Result<Connection> {
        // Convert the streams into a `Connection`
        let connection =
            Connection::from_streams(self.send_stream, self.receive_stream, middleware);

        // Return our connection
        Ok(connection)
    }
}

/// Contains a way to send and receive to new channels, and the bind endpoint
/// so we can remove on drop.
pub struct MemoryListener {
    bind_endpoint: String,
    receive_new_connection: AsyncReceiver<DuplexStream>,
    send_to_new_connection: AsyncSender<DuplexStream>,
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
        let (send_bytes_to_us, bytes_receiver) = duplex(8192);

        // Send the remote connection our channel
        bail!(
            self.send_to_new_connection.send(send_bytes_to_us).await,
            Connection,
            "failed to finalize connection"
        );

        // Return our unfinalized connection
        Ok(UnfinalizedMemoryConnection {
            send_stream: bytes_sender,
            receive_stream: bytes_receiver,
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

impl Memory {
    /// Generate a testing pair of channels for sending and receiving in memory.
    /// This is particularly useful for tests.
    #[must_use]
    pub fn gen_testing_connection() -> Connection {
        // Create our channels
        let (sender, receiver) = duplex(8192);

        // Convert the streams into a `Connection`
        Connection::from_streams(sender, receiver, Middleware::none())
    }
}

/// Soft closing is a no-op for memory connections.
#[async_trait]
impl SoftClose for DuplexStream {}

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
