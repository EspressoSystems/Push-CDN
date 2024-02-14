//! This file contains the implementation of the `Marshal`, which the user
//! connects to before a broker. It is used to "marshal" a user to the broker
//! (right now) with the least amount of connections. It's basically a load
//! balancer for the brokers.

use std::{marker::PhantomData, sync::Arc};

mod handlers;

use derive_builder::Builder;
use proto::{
    bail,
    connection::protocols::{Listener, Protocol},
    crypto::signature::SignatureScheme,
    discovery::DiscoveryClient,
    error::{Error, Result},
    DiscoveryClientType, UserProtocol,
};
use tokio::spawn;
use tracing::warn;

/// The `Marshal's` configuration (with a Builder), to help with usability.
/// We need this to construct a `Marshal`
#[derive(Builder)]
pub struct Config {
    /// The bind address that users will reach. Example: `0.0.0.0:1738`
    bind_address: String,

    /// The discovery client endpoint (either Redis or local depending on feature)
    discovery_endpoint: String,

    /// The optional TLS cert path. If one is not specified, it will be self-signed
    #[builder(default)]
    tls_cert_path: Option<String>,

    /// The optional TLS key path. If one is not specified, it will be self-signed
    #[builder(default)]
    tls_key_path: Option<String>,
}

/// A connection `Marshal`. The user authenticates with it, receiving a permit
/// to connect to an actual broker. Think of it like a load balancer for
/// the brokers.
pub struct Marshal<Scheme: SignatureScheme> {
    /// The underlying connection listener. Used to accept new connections.
    listener: Arc<<UserProtocol as Protocol>::Listener>,

    /// The client we use to issue permits and check for brokers that are up
    discovery_client: DiscoveryClientType,

    /// We need this `PhantomData` to allow us to specify the signature scheme,
    /// protocol type, and authentication flow.
    pd: PhantomData<Scheme>,
}

impl<Scheme: SignatureScheme> Marshal<Scheme> {
    /// Create and return a new marshal from a bind address, and an optional
    /// TLS cert and key path.
    ///
    /// # Errors
    /// - If we fail to bind to the local address
    pub async fn new(config: Config) -> Result<Self> {
        // Extrapolate values from the underlying marshal configuration
        let Config {
            bind_address,
            discovery_endpoint,
            tls_cert_path,
            tls_key_path,
        } = config;

        // Parse bind address
        let bind_address = bail!(bind_address.parse(), Parse, "failed to parse bind address");

        // Create the `Listener` from the bind address
        let listener = bail!(
            <UserProtocol as Protocol>::bind(bind_address, tls_cert_path, tls_key_path).await,
            Connection,
            format!("failed to listen to address {}", bind_address)
        );

        // Create the discovery client
        let discovery_client = bail!(
            DiscoveryClientType::new(discovery_endpoint.clone(), None).await,
            Connection,
            "failed to create discovery client"
        );

        // Create `Self` from the `Listener`
        Ok(Self {
            listener: Arc::from(listener),
            discovery_client,
            pd: PhantomData,
        })
    }

    /// The main loop for a marshal.
    /// Consumes self.
    ///
    /// # Errors
    /// Right now, we return a `Result` but don't actually ever error.
    pub async fn start(self) -> Result<()> {
        // Listen for connections forever
        loop {
            // Accept a connection. If we fail, print the error and keep going.
            //
            // TODO: figure out when an endpoint closes, should I be looping on it? What are the criteria
            // for closing? It would error but what does that actually _mean_? Is it recoverable?
            let connection = match self.listener.accept().await {
                Ok(connection) => connection,
                Err(err) => {
                    warn!("failed to accept connection: {}", err);
                    continue;
                }
            };

            // Create a task to handle the connection
            let discovery_client = self.discovery_client.clone();
            spawn(Self::handle_connection(connection, discovery_client));
        }
    }
}
