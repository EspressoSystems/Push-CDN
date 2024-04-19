//! This file contains the implementation of the `Broker`, which routes messages
//! for the Push CDN.

#![forbid(unsafe_code)]

mod connections;
mod handlers;
pub mod reexports;
mod tasks;

/// This is not guarded by `![cfg(test)]` because we use the same functions
/// when running benchmarks.
mod tests;

use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

mod metrics;
use cdn_proto::{
    bail,
    connection::protocols::Protocol as _,
    crypto::tls::{generate_cert_from_ca, load_ca},
    def::{Listener, Protocol, RunDef, Scheme},
    discovery::{BrokerIdentifier, DiscoveryClient},
    error::{Error, Result},
};
use cdn_proto::{crypto::signature::KeyPair, metrics as proto_metrics};
use connections::Connections;
use local_ip_address::local_ip;
use tokio::{select, spawn, sync::Semaphore};
use tracing::info;

/// The broker's configuration. We need this when we create a new one.
pub struct Config<R: RunDef> {
    /// The user (public) advertise endpoint in `IP:port` form: what the marshals send to
    /// users upon authentication. Users connect to us with this endpoint.
    pub public_advertise_endpoint: String,
    /// The user (public) bind endpoint in `IP:port` form: the public-facing endpoint we bind to.
    pub public_bind_endpoint: String,

    /// The broker (private) advertise endpoint in `IP:port` form: what other brokers use
    /// to connect to us.
    pub private_advertise_endpoint: String,
    /// The broker (private) bind endpoint in `IP:port` form: the private-facing endpoint
    /// we bind to.
    pub private_bind_endpoint: String,

    /// The port we want to serve metrics on
    pub metrics_bind_endpoint: Option<String>,

    /// The discovery endpoint. We use this to maintain consistency between brokers and marshals.
    pub discovery_endpoint: String,

    pub keypair: KeyPair<Scheme<R::Broker>>,

    /// An optional TLS CA cert path. If not specified, will use the local one.
    pub ca_cert_path: Option<String>,

    /// An optional TLS CA key path. If not specified, will use the local one.
    pub ca_key_path: Option<String>,
}

/// The broker `Inner` that we use to share common data between broker tasks.
struct Inner<R: RunDef> {
    /// A broker identifier that we can use to establish uniqueness among brokers.
    identity: BrokerIdentifier,

    /// The (clonable) `Discovery` client that we will use to maintain consistency between brokers and marshals
    discovery_client: R::DiscoveryClientType,

    /// The underlying (public) verification key, used to authenticate with other brokers.
    keypair: KeyPair<Scheme<R::Broker>>,

    /// A lock on authentication so we don't thrash when authenticating with brokers.
    /// Only lets us authenticate to one broker at a time.
    auth_lock: Semaphore,

    /// The connections that currently exist. We use this everywhere we need to update connection
    /// state or send messages.
    connections: Arc<Connections<R>>,
}

/// The main `Broker` struct. We instantiate this when we want to run a broker.
pub struct Broker<R: RunDef> {
    /// The broker's `Inner`. We clone this and pass it around when needed.
    inner: Arc<Inner<R>>,

    /// The public (user -> broker) listener
    user_listener: Listener<R::User>,

    /// The private (broker <-> broker) listener
    broker_listener: Listener<R::Broker>,

    /// The endpoint to bind to for externalizing metrics (in `IP:port` form). If not provided,
    /// metrics are not exposed.
    metrics_bind_endpoint: Option<SocketAddr>,
}

impl<R: RunDef> Broker<R> {
    /// Create a new `Broker` from a `Config`
    ///
    /// # Errors
    /// - If we fail to create the `Discovery` client
    /// - If we fail to bind to our public endpoint
    /// - If we fail to bind to our private endpoint
    pub async fn new(config: Config<R>) -> Result<Self> {
        // Extrapolate values from the underlying broker configuration
        let Config {
            public_advertise_endpoint,
            public_bind_endpoint,

            metrics_bind_endpoint,

            private_advertise_endpoint,
            private_bind_endpoint,

            keypair,

            discovery_endpoint,
            ca_cert_path,
            ca_key_path,
        } = config;

        // Get the local IP address so we can replace in
        let local_ip = bail!(
            local_ip(),
            Connection,
            "failed to obtain local IP and none was supplied"
        )
        .to_string();

        // Replace "local_ip" with the actual local IP address
        let public_bind_endpoint = public_bind_endpoint.replace("local_ip", &local_ip);
        let public_advertise_endpoint = public_advertise_endpoint.replace("local_ip", &local_ip);
        let private_bind_endpoint = private_bind_endpoint.replace("local_ip", &local_ip);
        let private_advertise_endpoint = private_advertise_endpoint.replace("local_ip", &local_ip);

        // Create a unique broker identifier
        let identity = BrokerIdentifier {
            public_advertise_endpoint: public_advertise_endpoint.clone(),
            private_advertise_endpoint: private_advertise_endpoint.clone(),
        };

        // Create the `Discovery` client we will use to maintain consistency
        let discovery_client = bail!(
            R::DiscoveryClientType::new(discovery_endpoint, Some(identity.clone()),).await,
            Parse,
            "failed to create discovery client"
        );

        // Conditionally load CA cert and key in
        let (ca_cert, ca_key) = load_ca(ca_cert_path, ca_key_path)?;

        // Generate a cert from the provided CA cert and key
        let (tls_cert, tls_key) = generate_cert_from_ca(&ca_cert, &ca_key)?;

        // Create the user (public) listener
        let user_listener = bail!(
            Protocol::<R::User>::bind(
                public_bind_endpoint.as_str(),
                tls_cert.clone(),
                tls_key.clone()
            )
            .await,
            Connection,
            format!(
                "failed to bind to public (user) bind endpoint {}",
                public_bind_endpoint
            )
        );

        // Create the broker (private) listener
        let broker_listener = bail!(
            Protocol::<R::Broker>::bind(private_bind_endpoint.as_str(), tls_cert, tls_key).await,
            Connection,
            format!(
                "failed to bind to private (broker) bind endpoint {}",
                private_bind_endpoint
            )
        );

        info!("listening for users on {public_advertise_endpoint} -> {public_bind_endpoint}");
        info!("listening for brokers on {private_advertise_endpoint} -> {private_bind_endpoint}");

        // Parse the metrics bind endpoint
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

        // Create and return `Self` as wrapping an `Inner` (with things that we need to share)
        Ok(Self {
            inner: Arc::from(Inner {
                discovery_client,
                identity: identity.clone(),
                keypair,
                auth_lock: Semaphore::const_new(1),
                connections: Arc::from(Connections::new(identity)),
            }),
            metrics_bind_endpoint,
            user_listener,
            broker_listener,
        })
    }

    /// The main loop for a broker.
    /// Consumes self.
    ///
    /// # Errors
    /// If any of the following tasks exit:
    /// - The heartbeat (Discovery) task
    /// - The user connection handler
    /// - The broker connection handler
    /// - If time went backwards :(
    pub async fn start(self) -> Result<()> {
        // Spawn the heartbeat task, which we use to register with `Discovery` every so often.
        // We also use it to check for new brokers who may have joined.
        // let heartbeat_task = ;
        let heartbeat_task = spawn(self.inner.clone().run_heartbeat_task());

        // Spawn the sync task, which updates other brokers with our keys periodically.
        let sync_task = spawn(self.inner.clone().run_sync_task());

        // Spawn the public (user) listener task
        // TODO: maybe macro this, since it's repeat code with the private listener task
        let user_listener_task = spawn(
            self.inner
                .clone()
                .run_user_listener_task(self.user_listener),
        );

        // Spawn the private (broker) listener task
        let broker_listener_task = spawn(
            self.inner
                .clone()
                .run_broker_listener_task(self.broker_listener),
        );

        // Serve the (possible) metrics task
        if let Some(metrics_bind_endpoint) = self.metrics_bind_endpoint {
            // Spawn the serving task
            spawn(proto_metrics::serve_metrics(metrics_bind_endpoint));
        }

        // If one of the tasks exists, we want to return (stopping the program)
        select! {
            _ = heartbeat_task => {
                Err(Error::Exited("heartbeat task exited!".to_string()))
            }
            _ = sync_task => {
                Err(Error::Exited("sync task exited!".to_string()))
            }
            _ = user_listener_task => {
                Err(Error::Exited("user listener task exited!".to_string()))
            }
            _ = broker_listener_task => {
                Err(Error::Exited("broker listener task exited!".to_string()))
            }
        }
    }
}
