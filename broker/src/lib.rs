//! This file contains the implementation of the `Broker`, which routes messages
//! for the Push CDN.

// TODO: split out this file into multiple files.
// TODO: logging

mod handlers;
mod map;
mod state;
mod tasks;

use std::{collections::HashSet, marker::PhantomData, sync::Arc};

// TODO: figure out if we should use Tokio's here
use proto::{
    bail,
    connection::protocols::Protocol,
    crypto::{KeyPair, Scheme, Serializable},
    discovery::{BrokerIdentifier, DiscoveryClient},
    error::{Error, Result},
    parse_socket_address, BrokerProtocol, DiscoveryClientType, UserProtocol,
};
use state::ConnectionLookup;
use tokio::{select, spawn, sync::RwLock};

/// The broker's configuration. We need this when we create a new one.
/// TODO: clean up these generics. could be a generic type that implements both
pub struct Config<BrokerSignatureScheme: Scheme> {
    /// The user (public) advertise address: what the marshals send to users upon authentication.
    /// Users connect to us with this address.
    pub public_advertise_address: String,
    /// The user (public) bind address: the public-facing address we bind to.
    pub public_bind_address: String,

    /// The broker (private) advertise address: what other brokers use to connect to us.
    pub private_advertise_address: String,
    /// The broker (private) bind address: the private-facing address we bind to.
    pub private_bind_address: String,

    /// The discovery endpoint. We use this to maintain consistency between brokers and marshals.
    pub discovery_endpoint: String,

    pub keypair: KeyPair<BrokerSignatureScheme>,

    /// An optional TLS cert path
    pub maybe_tls_cert_path: Option<String>,
    /// An optional TLS key path
    pub maybe_tls_key_path: Option<String>,
}

/// The broker `Inner` that we use to share common data between broker tasks.
struct Inner<
    // TODO: clean these up with some sort of generic trick or something
    BrokerSignatureScheme: Scheme,
    UserSignatureScheme: Scheme,
> {
    /// A broker identifier that we can use to establish uniqueness among brokers.
    identity: BrokerIdentifier,

    /// The (clonable) `Discovery` client that we will use to maintain consistency between brokers and marshals
    discovery_client: DiscoveryClientType,

    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    keypair: KeyPair<BrokerSignatureScheme>,

    /// The set of all broker identities we see. Mapped against the brokers we see in `Discovery`
    /// so that we don't connect multiple times.
    connected_broker_identities: RwLock<HashSet<BrokerIdentifier>>,

    /// A map of interests to their possible broker connections. We use this to facilitate
    /// where messages go. They need to be separate because of possibly different protocol
    /// types.
    broker_connection_lookup: RwLock<ConnectionLookup<BrokerProtocol>>,

    /// A map of interests to their possible user connections. We use this to facilitate
    /// where messages go. They need to be separate because of possibly different protocol
    /// types.
    user_connection_lookup: RwLock<ConnectionLookup<UserProtocol>>,

    // connected_keys: LoggedSet<UserSignatureScheme::VerificationKey>,
    /// The `PhantomData` that we need to be generic over protocol types.
    pd: PhantomData<UserSignatureScheme>,
}

/// The main `Broker` struct. We instantiate this when we want to run a broker.
pub struct Broker<BrokerSignatureScheme: Scheme, UserSignatureScheme: Scheme> {
    /// The broker's `Inner`. We clone this and pass it around when needed.
    inner: Arc<Inner<BrokerSignatureScheme, UserSignatureScheme>>,

    /// The public (user -> broker) listener
    user_listener: <UserProtocol as Protocol>::Listener,

    /// The private (broker <-> broker) listener
    broker_listener: <BrokerProtocol as Protocol>::Listener,
}

impl<BrokerSignatureScheme: Scheme, UserSignatureScheme: Scheme>
    Broker<BrokerSignatureScheme, UserSignatureScheme>
where
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    UserSignatureScheme::VerificationKey: Serializable,
    UserSignatureScheme::Signature: Serializable,
{
    /// Create a new `Broker` from a `Config`
    ///
    /// # Errors
    /// - If we fail to create the `Discovery` client
    /// - If we fail to bind to our public endpoint
    /// - If we fail to bind to our private endpoint
    pub async fn new(config: Config<BrokerSignatureScheme>) -> Result<Self> {
        // Extrapolate values from the underlying broker configuration
        let Config {
            public_advertise_address,
            public_bind_address,

            private_advertise_address,
            private_bind_address,

            keypair,

            discovery_endpoint,
            maybe_tls_cert_path,
            maybe_tls_key_path,
        } = config;

        // Create a unique broker identifier
        let identity = BrokerIdentifier {
            public_advertise_address,
            private_advertise_address,
        };

        // Create the `Discovery` client we will use to maintain consistency
        let discovery_client = bail!(
            DiscoveryClientType::new(discovery_endpoint, Some(identity.clone()),).await,
            Parse,
            "failed to create discovery client"
        );

        // Create the user (public) listener
        let public_bind_address = parse_socket_address!(public_bind_address);
        let user_listener = bail!(
            <UserProtocol as Protocol>::bind(
                public_bind_address,
                maybe_tls_cert_path.clone(),
                maybe_tls_key_path.clone(),
            )
            .await,
            Connection,
            format!(
                "failed to bind to private (broker) bind address {}",
                private_bind_address
            )
        );

        // Create the broker (private) listener
        let private_bind_address = parse_socket_address!(private_bind_address);
        let broker_listener = bail!(
            <BrokerProtocol as Protocol>::bind(
                private_bind_address,
                maybe_tls_cert_path,
                maybe_tls_key_path,
            )
            .await,
            Connection,
            format!(
                "failed to bind to public (user) bind address {}",
                public_bind_address
            )
        );

        // Create and return `Self` as wrapping an `Inner` (with things that we need to share)
        Ok(Self {
            inner: Arc::from(Inner {
                discovery_client,
                identity,
                keypair,
                connected_broker_identities: RwLock::default(),
                broker_connection_lookup: RwLock::default(),
                user_connection_lookup: RwLock::default(),
                pd: PhantomData,
            }),
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
    pub async fn start(self) -> Result<()> {
        // Spawn the heartbeat task, which we use to register with `Discovery` every so often.
        // We also use it to check for new brokers who may have joined.
        // let heartbeat_task = ;
        let heartbeat_task = spawn(self.inner.clone().run_heartbeat_task());

        // Spawn the updates task, which updates other brokers with our topics and keys periodically.
        let update_task = spawn(self.inner.clone().run_update_task());

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

        // If one of the tasks exists, we want to return (stopping the program)
        select! {
            _ = heartbeat_task => {
                Err(Error::Exited("heartbeat task exited!".to_string()))
            }
            _ = update_task => {
                Err(Error::Exited("updates task exited!".to_string()))
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
