//! This file contains the implementation of the `Marshal`, which the user
//! connects to before a broker. It is used to "marshal" a user to the broker
//! (right now) with the least amount of connections. It's basically a load
//! balancer for the brokers.

#![forbid(unsafe_code)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

mod handlers;

use cdn_proto::{
    bail,
    connection::{
        hooks::Untrusted,
        protocols::{Listener, Protocol, UnfinalizedConnection},
    },
    crypto::tls::{generate_cert_from_ca, load_ca},
    def::RunDef,
    discovery::DiscoveryClient,
    error::{Error, Result},
    metrics as proto_metrics, parse_socket_address,
};
use derive_builder::Builder;
use tokio::spawn;
use tracing::info;

/// The `Marshal's` configuration (with a Builder), to help with usability.
/// We need this to construct a `Marshal`
#[derive(Builder)]
pub struct Config {
    /// The bind address that users will reach. Example: `0.0.0.0:1738`
    bind_address: String,

    /// The discovery client endpoint (either Redis or local depending on feature)
    discovery_endpoint: String,

    /// Whether or not we want to serve metrics
    #[builder(default = "true")]
    pub metrics_enabled: bool,

    /// The port we want to serve metrics on
    #[builder(default = "9090")]
    pub metrics_port: u16,

    /// The IP/interface we want to serve the metrics on
    #[builder(default = "String::from(\"127.0.0.1\")")]
    pub metrics_ip: String,

    /// An optional TLS CA cert path. If not specified, will use the local one.
    #[builder(default)]
    pub ca_cert_path: Option<String>,

    /// An optional TLS CA key path. If not specified, will use the local one.
    #[builder(default)]
    pub ca_key_path: Option<String>,
}

/// A connection `Marshal`. The user authenticates with it, receiving a permit
/// to connect to an actual broker. Think of it like a load balancer for
/// the brokers.
pub struct Marshal<Def: RunDef> {
    /// The underlying connection listener. Used to accept new connections.
    listener: Arc<<Def::UserProtocol as Protocol<Untrusted>>::Listener>,

    /// The client we use to issue permits and check for brokers that are up
    discovery_client: Def::DiscoveryClientType,

    /// The endpoint at which we serve metrics to, our none at all if we aren't serving.
    metrics_bind_address: Option<SocketAddr>,
}

impl<Def: RunDef> Marshal<Def> {
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
            metrics_enabled,
            metrics_ip,
            metrics_port,
            ca_cert_path,
            ca_key_path,
        } = config;

        // Conditionally load CA cert and key in
        let (ca_cert, ca_key) = load_ca(ca_cert_path, ca_key_path)?;

        // Generate a cert from the provided CA cert and key
        let (tls_cert, tls_key) = generate_cert_from_ca(&ca_cert, &ca_key)?;

        // Create the `Listener` from the bind address
        let listener = bail!(
            Def::UserProtocol::bind(bind_address.as_str(), tls_cert, tls_key).await,
            Connection,
            format!("failed to listen to address {}", bind_address)
        );

        info!("listening for users on {bind_address}");

        // Create the discovery client
        let discovery_client = bail!(
            Def::DiscoveryClientType::new(discovery_endpoint, None).await,
            Connection,
            "failed to create discovery client"
        );

        // Parse the metrics IP and port
        let metrics_bind_address = if metrics_enabled {
            let ip: Ipv4Addr = parse_socket_address!(metrics_ip);
            Some(SocketAddr::from((ip, metrics_port)))
        } else {
            None
        };

        // Create `Self` from the `Listener`
        Ok(Self {
            listener: Arc::from(listener),
            metrics_bind_address,
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
        if let Some(metrics_bind_address) = self.metrics_bind_address {
            // Spawn the serving task
            spawn(proto_metrics::serve_metrics(metrics_bind_address));
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
