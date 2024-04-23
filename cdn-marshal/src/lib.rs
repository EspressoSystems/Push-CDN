//! This file contains the implementation of the `Marshal`, which the user
//! connects to before a broker. It is used to "marshal" a user to the broker
//! (right now) with the least amount of connections. It's basically a load
//! balancer for the brokers.

#![forbid(unsafe_code)]

use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

mod handlers;

use cdn_proto::{
    bail,
    connection::protocols::{Listener as _, Protocol as _, UnfinalizedConnection},
    crypto::tls::{generate_cert_from_ca, load_ca},
    def::{Listener, Protocol, RunDef},
    discovery::DiscoveryClient,
    error::{Error, Result},
    metrics as proto_metrics,
};
use tokio::spawn;
use tracing::info;

/// The `Marshal's` configuration (with a Builder), to help with usability.
/// We need this to construct a `Marshal`
pub struct Config {
    /// The bind endpoint that users will reach. Example: `0.0.0.0:1738`
    pub bind_endpoint: String,

    /// The discovery client endpoint (either Redis or local depending on feature)
    pub discovery_endpoint: String,

    /// An optional TLS CA cert path. If not specified, will use the local one.
    pub ca_cert_path: Option<String>,

    /// An optional TLS CA key path. If not specified, will use the local one.
    pub ca_key_path: Option<String>,

    /// The endpoint to bind to for externalizing metrics (in `IP:port` form). If not provided,
    /// metrics are not exposed.
    pub metrics_bind_endpoint: Option<String>,
}

/// A connection `Marshal`. The user authenticates with it, receiving a permit
/// to connect to an actual broker. Think of it like a load balancer for
/// the brokers.
pub struct Marshal<R: RunDef> {
    /// The underlying connection listener. Used to accept new connections.
    listener: Arc<Listener<R::User>>,

    /// The client we use to issue permits and check for brokers that are up
    discovery_client: R::DiscoveryClientType,

    /// The endpoint to bind to for externalizing metrics (in `IP:port` form). If not provided,
    /// metrics are not exposed.
    metrics_bind_endpoint: Option<SocketAddr>,
}

impl<R: RunDef> Marshal<R> {
    /// Create and return a new marshal from a bind endpoint, and an optional
    /// TLS cert and key path.
    ///
    /// # Errors
    /// - If we fail to bind to the local endpoint
    pub async fn new(config: Config) -> Result<Self> {
        // Extrapolate values from the underlying marshal configuration
        let Config {
            bind_endpoint,
            discovery_endpoint,
            metrics_bind_endpoint,
            ca_cert_path,
            ca_key_path,
        } = config;

        // Conditionally load CA cert and key in
        let (ca_cert, ca_key) = load_ca(ca_cert_path, ca_key_path)?;

        // Generate a cert from the provided CA cert and key
        let (tls_cert, tls_key) = generate_cert_from_ca(&ca_cert, &ca_key)?;

        // Create the `Listener` from the bind endpoint
        let listener = bail!(
            Protocol::<R::User>::bind(bind_endpoint.as_str(), tls_cert, tls_key).await,
            Connection,
            format!("failed to bind to endpoint {}", bind_endpoint)
        );

        info!(bind = bind_endpoint, "listening for users");

        // Create the discovery client
        let discovery_client = bail!(
            R::DiscoveryClientType::new(discovery_endpoint, None).await,
            Connection,
            "failed to create discovery client"
        );

        // Parse the metrics IP and port
        let metrics_bind_endpoint: Option<SocketAddr> = metrics_bind_endpoint
            .map(|m| {
                bail!(
                    m.to_socket_addrs(),
                    Parse,
                    "failed to parse metrics bind endpoint"
                )
                .find(SocketAddr::is_ipv4)
                .ok_or_else(|| {
                    Error::Connection("failed to resolve metrics bind endpoint".to_string())
                })
            })
            .transpose()?;

        // Create `Self` from the `Listener`
        Ok(Self {
            listener: Arc::from(listener),
            metrics_bind_endpoint,
            discovery_client,
        })
    }

    /// The main loop for a marshal.
    /// Consumes self.
    ///
    /// # Errors
    /// Right now, we return a `Result` but don't actually ever error.
    pub async fn start(self) -> Result<()> {
        // Serve the (possible) metrics task
        if let Some(metrics_bind_endpoint) = self.metrics_bind_endpoint {
            // Spawn the serving task
            spawn(proto_metrics::serve_metrics(metrics_bind_endpoint));
        }

        // Listen for connections forever
        loop {
            // Accept an unfinalized connection. If we fail, print the error and keep going.
            let unfinalized_connection = bail!(
                self.listener.accept().await,
                Connection,
                "failed to accept connection"
            );

            // Create a task to handle the connection
            let discovery_client = self.discovery_client.clone();
            spawn(async move {
                // Finalize the connection
                let Ok(connection) = unfinalized_connection.finalize().await else {
                    return;
                };

                // Handle the connection
                Self::handle_connection(connection, discovery_client).await;
            });
        }
    }
}
