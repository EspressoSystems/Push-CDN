//! This file contains the implementation of the `Broker`, which routes messages
//! for the Push CDN.

// TODO: split out this file into multiple files.
// TODO: logging

#![forbid(unsafe_code)]

mod connections;
mod handlers;
pub mod reexports;
mod tasks;

/// This is not guarded by `![cfg(test)]` because we use the same functions
/// when running benchmarks.
mod tests;

use std::{
    marker::PhantomData,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

mod metrics;
use cdn_proto::{
    connection::hooks::{Trusted, Untrusted},
    crypto::signature::{KeyPair, SignatureScheme},
    metrics as proto_metrics,
};
use derive_builder::Builder;

// TODO: figure out if we should use Tokio's here
use cdn_proto::{
    bail,
    connection::protocols::Protocol,
    discovery::{BrokerIdentifier, DiscoveryClient},
    error::{Error, Result},
    parse_socket_address, DiscoveryClientType,
};
use connections::Connections;
use tokio::{select, spawn};
use tracing::info;

use crate::metrics::RUNNING_SINCE;

/// The broker's configuration. We need this when we create a new one.
#[derive(Builder)]
pub struct Config<BrokerScheme: SignatureScheme> {
    /// The user (public) advertise address: what the marshals send to users upon authentication.
    /// Users connect to us with this address.
    pub public_advertise_address: String,
    /// The user (public) bind address: the public-facing address we bind to.
    pub public_bind_address: String,

    /// Whether or not we want to serve metrics
    #[builder(default = "true")]
    pub metrics_enabled: bool,

    /// The port we want to serve metrics on
    #[builder(default = "9090")]
    pub metrics_port: u16,

    /// The IP/interface we want to serve the metrics on
    #[builder(default = "String::from(\"127.0.0.1\")")]
    pub metrics_ip: String,

    /// The broker (private) advertise address: what other brokers use to connect to us.
    pub private_advertise_address: String,
    /// The broker (private) bind address: the private-facing address we bind to.
    pub private_bind_address: String,

    /// The discovery endpoint. We use this to maintain consistency between brokers and marshals.
    pub discovery_endpoint: String,

    pub keypair: KeyPair<BrokerScheme>,

    /// An optional TLS cert path
    #[builder(default)]
    pub tls_cert_path: Option<String>,

    /// An optional TLS key path
    #[builder(default)]
    pub tls_key_path: Option<String>,
}

/// The broker `Inner` that we use to share common data between broker tasks.
struct Inner<
    BrokerScheme: SignatureScheme,
    UserScheme: SignatureScheme,
    BrokerProtocol: Protocol<Trusted>,
    UserProtocol: Protocol<Untrusted>,
> {
    /// A broker identifier that we can use to establish uniqueness among brokers.
    identity: BrokerIdentifier,

    /// The (clonable) `Discovery` client that we will use to maintain consistency between brokers and marshals
    discovery_client: DiscoveryClientType,

    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    keypair: KeyPair<BrokerScheme>,

    /// The connections that currently exist. We use this everywhere we need to update connection
    /// state or send messages.
    connections: Arc<Connections<BrokerProtocol, UserProtocol>>,

    /// The `PhantomData` that we need to be generic over protocol types.
    pd: PhantomData<UserScheme>,
}

/// The main `Broker` struct. We instantiate this when we want to run a broker.
pub struct Broker<
    BrokerScheme: SignatureScheme,
    UserScheme: SignatureScheme,
    BrokerProtocol: Protocol<Trusted>,
    UserProtocol: Protocol<Untrusted>,
> {
    /// The broker's `Inner`. We clone this and pass it around when needed.
    inner: Arc<Inner<BrokerScheme, UserScheme, BrokerProtocol, UserProtocol>>,

    /// The public (user -> broker) listener
    user_listener: UserProtocol::Listener,

    /// The private (broker <-> broker) listener
    broker_listener: BrokerProtocol::Listener,

    /// The endpoint at which we serve metrics to, our none at all if we aren't serving.
    metrics_bind_address: Option<SocketAddr>,
}

impl<
        BrokerScheme: SignatureScheme,
        UserScheme: SignatureScheme,
        BrokerProtocol: Protocol<Trusted>,
        UserProtocol: Protocol<Untrusted>,
    > Broker<BrokerScheme, UserScheme, BrokerProtocol, UserProtocol>
{
    /// Create a new `Broker` from a `Config`
    ///
    /// # Errors
    /// - If we fail to create the `Discovery` client
    /// - If we fail to bind to our public endpoint
    /// - If we fail to bind to our private endpoint
    pub async fn new(config: Config<BrokerScheme>) -> Result<Self> {
        // Extrapolate values from the underlying broker configuration
        let Config {
            public_advertise_address,
            public_bind_address,

            metrics_enabled,
            metrics_ip,
            metrics_port,

            private_advertise_address,
            private_bind_address,

            keypair,

            discovery_endpoint,
            tls_cert_path,
            tls_key_path,
        } = config;

        // Create a unique broker identifier
        let identity = BrokerIdentifier {
            public_advertise_address: public_advertise_address.clone(),
            private_advertise_address: private_advertise_address.clone(),
        };

        // Create the `Discovery` client we will use to maintain consistency
        let discovery_client = bail!(
            DiscoveryClientType::new(discovery_endpoint, Some(identity.clone()),).await,
            Parse,
            "failed to create discovery client"
        );

        // Create the user (public) listener
        let user_listener = bail!(
            UserProtocol::bind(
                public_bind_address.as_str(),
                tls_cert_path.clone(),
                tls_key_path.clone(),
            )
            .await,
            Connection,
            format!(
                "failed to bind to public (user) bind address {}",
                public_bind_address
            )
        );

        // Create the broker (private) listener
        let broker_listener = bail!(
            BrokerProtocol::bind(private_bind_address.as_str(), tls_cert_path, tls_key_path,).await,
            Connection,
            format!(
                "failed to bind to private (broker) bind address {}",
                private_bind_address
            )
        );

        info!("listening for users on {public_advertise_address} -> {public_bind_address}");
        info!("listening for brokers on {private_advertise_address} -> {private_bind_address}");

        // Parse the metrics IP and port
        let metrics_bind_address = if metrics_enabled {
            let ip: Ipv4Addr = parse_socket_address!(metrics_ip);
            Some(SocketAddr::from((ip, metrics_port)))
        } else {
            None
        };

        // Create and return `Self` as wrapping an `Inner` (with things that we need to share)
        Ok(Self {
            inner: Arc::from(Inner {
                discovery_client,
                identity: identity.clone(),
                keypair,
                connections: Arc::from(Connections::new(identity)),
                pd: PhantomData,
            }),
            metrics_bind_address,
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
        if let Some(metrics_bind_address) = self.metrics_bind_address {
            // Set that we are running for timekeeping purposes
            RUNNING_SINCE.set(
                bail!(
                    SystemTime::now().duration_since(UNIX_EPOCH),
                    Time,
                    "time went backwards"
                )
                .as_secs() as i64,
            );

            // Spawn the serving task
            spawn(proto_metrics::serve_metrics(metrics_bind_address));
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
