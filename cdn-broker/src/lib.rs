// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This file contains the implementation of the `Broker`, which routes messages
//! for the Push CDN.

#![forbid(unsafe_code)]

mod connections;
pub mod reexports;
mod tasks;

/// This is not guarded by `![cfg(test)]` because we use the same functions
/// when running benchmarks.
mod tests;

use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

mod metrics;
use anyhow::Context;
use cdn_proto::{
    bail,
    connection::{limiter::Limiter, protocols::Protocol as _},
    crypto::tls::{generate_cert_from_ca, load_ca},
    def::{Listener, MessageHook, Protocol, RunDef, Scheme},
    discovery::{BrokerIdentifier, DiscoveryClient},
    error::{Error, Result},
    util::AbortOnDropHandle,
};
use cdn_proto::{crypto::signature::KeyPair, metrics as proto_metrics};
use connections::Connections;
use local_ip_address::local_ip;
use parking_lot::RwLock;
use tokio::{select, spawn, time::timeout};
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

    /// The underlying (public) verification key, used to authenticate with other brokers.
    pub keypair: KeyPair<Scheme<R::Broker>>,

    /// An optional TLS CA cert path. If not specified, will use the local one.
    pub ca_cert_path: Option<String>,

    /// An optional TLS CA key path. If not specified, will use the local one.
    pub ca_key_path: Option<String>,

    /// The size of the global memory pool (in bytes). This is the maximum number of bytes that
    /// can be allocated at once for all connections. A connection will block if it
    /// tries to allocate more than this amount until some memory is freed.
    /// Default is 1GB.
    pub global_memory_pool_size: Option<usize>,

    /// The hook we use when receiving incoming messages from users
    pub user_message_hook: MessageHook<R::User>,

    /// The hook we use when receiving incoming messages from brokers
    pub broker_message_hook: MessageHook<R::Broker>,
}

/// The broker `Inner` that we use to share common data between broker tasks.
struct Inner<R: RunDef> {
    /// A broker identifier that we can use to establish uniqueness among brokers.
    identity: BrokerIdentifier,

    /// The (clonable) `Discovery` client that we will use to maintain consistency between brokers and marshals
    discovery_client: R::DiscoveryClientType,

    /// The underlying (public) verification key, used to authenticate with other brokers.
    keypair: KeyPair<Scheme<R::Broker>>,

    /// The connections that currently exist. We use this everywhere we need to update connection
    /// state or send messages.
    connections: Arc<RwLock<Connections>>,

    /// The shared limiter that we use for all connections.
    limiter: Limiter,

    /// The hook we use when receiving incoming messages from users
    user_message_hook: MessageHook<R::User>,

    /// The hook we use when receiving incoming messages from brokers
    broker_message_hook: MessageHook<R::Broker>,
}

/// The main `Broker` struct. We instantiate this when we want to run a broker.
pub struct Broker<R: RunDef> {
    /// The broker's `Inner`. We clone this and pass it around when needed.
    inner: Arc<Inner<R>>,

    /// The public (user -> broker) listener
    user_listener: Listener<R::User>,

    /// The public (second) (user -> broker) listener
    user_listener_2: Listener<R::User2>,

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

            global_memory_pool_size,

            user_message_hook,
            broker_message_hook,
        } = config;

        // Get the local IP address so we can replace in
        let local_ip = bail!(
            local_ip(),
            Connection,
            "failed to obtain local IP and none was supplied"
        )
        .to_string();

        // Get the public IP
        let public_ip = bail!(
            get_public_ip().await,
            Connection,
            "failed to obtain public IP"
        )
        .to_string();

        // Replace "local_ip" with the actual local IP address
        let public_bind_endpoint = public_bind_endpoint.replace("local_ip", &local_ip);
        let public_advertise_endpoint = public_advertise_endpoint.replace("local_ip", &local_ip);
        let private_bind_endpoint = private_bind_endpoint.replace("local_ip", &local_ip);
        let private_advertise_endpoint = private_advertise_endpoint.replace("local_ip", &local_ip);

        // Replace "public_ip" with the actual public IP address
        let public_bind_endpoint = public_bind_endpoint.replace("public_ip", &public_ip);
        let public_advertise_endpoint = public_advertise_endpoint.replace("public_ip", &public_ip);
        let private_bind_endpoint = private_bind_endpoint.replace("public_ip", &public_ip);
        let private_advertise_endpoint =
            private_advertise_endpoint.replace("public_ip", &public_ip);

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
                tls_key.clone_key()
            )
            .await,
            Connection,
            format!(
                "failed to bind to public (user) bind endpoint {}",
                public_bind_endpoint
            )
        );

        // Create the second user (public) listener
        let user_listener_2 = bail!(
            Protocol::<R::User2>::bind(
                public_bind_endpoint.as_str(),
                tls_cert.clone(),
                tls_key.clone_key()
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

        info!(
            advertise = public_advertise_endpoint,
            bind = public_bind_endpoint,
            "listening for users"
        );
        info!(
            advertise = private_advertise_endpoint,
            bind = private_bind_endpoint,
            "listening for brokers"
        );

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

        // Create the globally shared limiter
        let limiter = Limiter::new(global_memory_pool_size, None);

        // Create and return `Self` as wrapping an `Inner` (with things that we need to share)
        Ok(Self {
            inner: Arc::from(Inner {
                discovery_client,
                identity: identity.clone(),
                keypair,
                connections: Arc::from(RwLock::from(Connections::new(identity))),
                limiter,
                user_message_hook,
                broker_message_hook,
            }),
            metrics_bind_endpoint,
            user_listener,
            user_listener_2,
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
        let inner_ = self.inner.clone();
        let heartbeat_task = AbortOnDropHandle(spawn(inner_.run_heartbeat_task()));

        // Spawn the sync task, which updates other brokers with our keys periodically.
        let inner_ = self.inner.clone();
        let sync_task = AbortOnDropHandle(spawn(inner_.run_sync_task()));

        // Spawn the whitelist task, which retroactively checks if existing users are still
        // whitelisted
        let inner_ = self.inner.clone();
        let whitelist_task = AbortOnDropHandle(spawn(inner_.run_whitelist_task()));

        // Spawn the public (user) listener task
        // TODO: maybe macro this, since it's repeat code with the private listener task
        let inner_ = self.inner.clone();
        let user_listener_task = AbortOnDropHandle(spawn(
            inner_
                .clone()
                .run_user_listener_task::<R::User>(self.user_listener),
        ));

        // Spawn the second public (user) listener task
        // TODO: maybe macro this, since it's repeat code with the private listener task
        let inner_ = self.inner.clone();
        let user_listener_task_2 = AbortOnDropHandle(spawn(
            inner_
                .clone()
                .run_user_listener_task::<R::User2>(self.user_listener_2),
        ));

        // Spawn the private (broker) listener task
        let inner_ = self.inner.clone();
        let broker_listener_task =
            AbortOnDropHandle(spawn(inner_.run_broker_listener_task(self.broker_listener)));

        // Serve the (possible) metrics task
        let _possible_metrics_task = self
            .metrics_bind_endpoint
            .map(|endpoint| AbortOnDropHandle(spawn(proto_metrics::serve_metrics(endpoint))));

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
            _ = user_listener_task_2 => {
                Err(Error::Exited("user listener task 2 exited!".to_string()))
            }
            _ = broker_listener_task => {
                Err(Error::Exited("broker listener task exited!".to_string()))
            }
            _ = whitelist_task => {
                Err(Error::Exited("whitelist task exited!".to_string()))
            }
        }
    }
}

/// Use both resolvers to try to get the public IP
async fn get_public_ip() -> anyhow::Result<IpAddr> {
    // First try to get from AWS
    let aws_ip = get_public_ip_from_aws()
        .await
        .with_context(|| "failed to get public IP from AWS");

    // Return it we got it
    if let Ok(ip) = aws_ip {
        return Ok(ip);
    }

    // If not, fall back to IPify
    get_public_ip_from_ipify()
        .await
        .with_context(|| "failed to get public IP from IPify")
}

/// Try to get the public IP from IPify
async fn get_public_ip_from_ipify() -> anyhow::Result<IpAddr> {
    // Make the request
    let response = timeout(
        Duration::from_secs(10),
        reqwest::get("https://api.ipify.org/"),
    )
    .await
    .with_context(|| "timed out getting response")?
    .with_context(|| "failed to get response")?;

    // Get the response text
    let text = timeout(Duration::from_secs(10), response.text())
        .await
        .with_context(|| "timed out getting response text")?
        .with_context(|| "failed to get response text")?;

    // Make sure it's an IP address
    let ip =
        IpAddr::from_str(&text).with_context(|| format!("got invalid IP address: {}", text))?;

    // Return the IP address
    Ok(ip)
}

/// Try to get the public IP from AWS
async fn get_public_ip_from_aws() -> anyhow::Result<IpAddr> {
    // Make the request
    let response = timeout(
        Duration::from_secs(10),
        reqwest::get("https://checkip.amazonaws.com"),
    )
    .await
    .with_context(|| "timed out getting response")?
    .with_context(|| "failed to get response")?;

    // Get the response text
    let text = timeout(Duration::from_secs(10), response.text())
        .await
        .with_context(|| "timed out getting response text")?
        .with_context(|| "failed to get response text")?;

    // Split it by commas
    let parts = text.split(',').collect::<Vec<&str>>();

    // Get the last one
    let ip = parts
        .last()
        .ok_or_else(|| anyhow::anyhow!("no IP found in response"))?;

    // Make sure it's an IP address
    let ip = IpAddr::from_str(ip).with_context(|| format!("got invalid IP address: {}", text))?;

    // Return the IP address
    Ok(ip)
}
