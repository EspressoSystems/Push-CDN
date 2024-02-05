//! This file contains the implementation of the `Broker`, which routes messages
//! for the Push CDN.

use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use proto::{
    bail,
    connection::{
        auth::{broker::BrokerToUser, AuthenticationFlow},
        protocols::{Listener, Protocol},
    },
    crypto::Serializable,
    error::{Error, Result},
    parse_socket_address,
    redis::{self, BrokerIdentifier},
};
use tokio::{select, spawn, time::sleep};
use tracing::{error, warn};

/// The broker's configuration. We need this when we create a new one.
/// TODO: clean up these generics. could be a generic type that implements both
pub struct Config<BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>>
{
    /// The user (public) advertise address: what the marshals send to users upon authentication.
    /// Users connect to us with this address.
    pub user_advertise_address: String,
    /// The uaser (public) bind address: the public-facing address we bind to.
    pub user_bind_address: String,

    /// The broker (private) advertise address: what other brokers use to connect to us.
    pub broker_advertise_address: String,
    /// The broker (private) bind address: the private-facing address we bind to.
    pub broker_bind_address: String,

    /// The redis endpoint. We use this to maintain consistency between brokers and marshals.
    pub redis_endpoint: String,

    /// The underlying (public) verification key, used to authenticate with other brokers
    pub verification_key: BrokerSignatureScheme::VerificationKey,

    /// The underlying (private) signing key, used to authenticate with other brokers
    pub signing_key: BrokerSignatureScheme::SigningKey,

    /// An optional TLS cert path
    pub maybe_tls_cert_path: Option<String>,
    /// An optional TLS key path
    pub maybe_tls_key_path: Option<String>,
}

/// The broker `Inner` that we use to share common data between broker tasks.
struct Inner<
    // TODO: clean these up with some sort of generic trick or something
    BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserProtocolType: Protocol,
    BrokerProtocolType: Protocol,
> {
    /// The number of connected users (that we post to Redis so that marshals can equally
    /// distribute users)
    num_connected_users: AtomicU64,

    /// A broker identifier that we can use to establish uniqueness among brokers.
    identifier: BrokerIdentifier,

    // The `Redis` client that we will use to maintain consistency between brokers and marshals
    redis_client: redis::Client,

    /// The underlying (public) verification key, used to authenticate with other brokers
    verification_key: BrokerSignatureScheme::VerificationKey,

    /// The underlying (private) signing key, used to authenticate with other brokers
    signing_key: BrokerSignatureScheme::SigningKey,

    /// The `PhantomData` that we need to be generic over protocol types.
    pd: PhantomData<(UserProtocolType, BrokerProtocolType, UserSignatureScheme)>,
}

/// The main `Broker` struct. We instantiate this when we want to run a broker.
pub struct Broker<
    BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserProtocolType: Protocol,
    BrokerProtocolType: Protocol,
> {
    /// The broker's `Inner`. We clone this and pass it around when needed.
    inner: Arc<
        Inner<BrokerSignatureScheme, UserSignatureScheme, UserProtocolType, BrokerProtocolType>,
    >,

    /// The public (user -> broker) listener
    user_listener: UserProtocolType::Listener,

    /// The private (broker <-> broker) listener
    broker_listener: BrokerProtocolType::Listener,
}

impl<
        BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        UserProtocolType: Protocol,
        BrokerProtocolType: Protocol,
    > Broker<BrokerSignatureScheme, UserSignatureScheme, UserProtocolType, BrokerProtocolType>
where
    UserSignatureScheme::Signature: Serializable,
    UserSignatureScheme::VerificationKey: Serializable,
    UserSignatureScheme::SigningKey: Serializable,
{
    /// Create a new `Broker` from a `Config`
    /// 
    /// # Errors
    /// - If we fail to create the `Redis` client
    /// - If we fail to bind to our public endpoint
    /// - If we fail to bind to our private endpoint
    pub async fn new(config: Config<BrokerSignatureScheme>) -> Result<Self> {
        // Extrapolate values from the underlying broker configuration
        let Config {
            user_advertise_address,
            user_bind_address,

            broker_advertise_address,
            broker_bind_address,

            verification_key,
            signing_key,

            redis_endpoint,
            maybe_tls_cert_path,
            maybe_tls_key_path,
        } = config;

        // Create a unique broker identifier
        let identifier = BrokerIdentifier {
            user_advertise_address,
            broker_advertise_address,
        };

        // Create the `Redis` client we will use to maintain consistency
        let redis_client = bail!(
            redis::Client::new(redis_endpoint, Some(identifier.clone()),).await,
            Parse,
            "failed to create Redis client"
        );

        // Create the user (public) listener
        let user_bind_address = parse_socket_address!(user_bind_address);
        let user_listener = bail!(
            UserProtocolType::Listener::bind(
                user_bind_address,
                maybe_tls_cert_path.clone(),
                maybe_tls_key_path.clone(),
            )
            .await,
            Connection,
            format!(
                "failed to bind to private (broker) bind address {}",
                broker_bind_address
            )
        );

        // Create the broker (private) listener
        let broker_bind_address = parse_socket_address!(broker_bind_address);
        let broker_listener = bail!(
            BrokerProtocolType::Listener::bind(
                broker_bind_address,
                maybe_tls_cert_path,
                maybe_tls_key_path,
            )
            .await,
            Connection,
            format!(
                "failed to bind to public (user) bind address {}",
                user_bind_address
            )
        );

        // Create and return `Self` as wrapping an `Inner` (with things that we need to share)
        Ok(Self {
            inner: Arc::from(Inner {
                verification_key,
                signing_key,
                num_connected_users: AtomicU64::default(),
                redis_client,
                identifier,
                pd: PhantomData,
            }),
            user_listener,
            broker_listener,
        })
    }

    /// This function handles a broker (private) connection. We take the following steps:
    /// 1. Authenticate the broker
    /// 2. TODO
    async fn handle_broker_connection(
        inner: Arc<
            Inner<BrokerSignatureScheme, UserSignatureScheme, UserProtocolType, BrokerProtocolType>,
        >,
        connection: BrokerProtocolType::Connection,
    ) {
    }

    /// This function handles a user (public) connection. We take the following steps:
    /// 1. Authenticate the user
    /// 2. TODO
    async fn handle_user_connection(
        inner: Arc<
            Inner<BrokerSignatureScheme, UserSignatureScheme, UserProtocolType, BrokerProtocolType>,
        >,
        connection: UserProtocolType::Connection,
    ) {
        // Create verification data from the `Redis` client and our identifier
        let mut verification = BrokerToUser {
            redis_client: inner.redis_client.clone(),
            identifier: inner.identifier.clone(),
        };

        // Verify (authenticate) the connection
        if <BrokerToUser as AuthenticationFlow<
            UserSignatureScheme,
            UserProtocolType,
        >>::authenticate(&mut verification, &connection)
        .await.is_err()
        {
            return;
        };

        println!("meow");
    }

    /// The main loop for a broker.
    /// Consumes self.
    ///
    /// # Errors
    /// If any of the following tasks exit:
    /// - The heartbeat (Redis) task
    /// - The user connection handler
    /// - The broker connection handler
    pub async fn start(self) -> Result<()> {
        // Clone `inner` so we can use shared data
        let inner = self.inner.clone();

        // Spawn the heartbeat task, which we use to register with `Redis` every so often.
        let heartbeat_task = spawn(async move {
            // Clone the `Redis` client, which needs to be mutable
            let mut redis_client = inner.redis_client.clone();
            loop {
                // Register with `Redis` every 20 seconds, updating our number of connected users
                if let Err(err) = redis_client
                    .perform_heartbeat(
                        inner.num_connected_users.load(Ordering::Relaxed),
                        Duration::from_secs(60),
                    )
                    .await
                {
                    // If we fail, we want to see this
                    error!("failed to perform heartbeat: {}", err);
                }

                // Sleep for 20 seconds
                sleep(Duration::from_secs(20)).await;
            }
        });

        // Clone `inner` so we can use shared data
        let inner = self.inner.clone();

        // Spawn the public (user) listener task
        // TODO: maybe macro this, since it's repeat code with the private listener task
        let user_listener_task = spawn(async move {
            loop {
                // Accept a connection. If we fail, print the error and keep going.
                //
                // TODO: figure out when an endpoint closes, should I be looping on it? What are the criteria
                // for closing? It would error but what does that actually _mean_? Is it recoverable?
                let connection = match self.user_listener.accept().await {
                    Ok(connection) => connection,
                    Err(err) => {
                        warn!("failed to accept connection: {}", err);
                        continue;
                    }
                };

                // Spawn a task to handle the [user/public] connection
                let inner = inner.clone();
                spawn(Self::handle_user_connection(inner, connection));
            }
        });

        // Clone `inner` so we can use shared data
        let inner = self.inner.clone();

        // Spawn the private (broker) listener task
        let broker_listener_task = spawn(async move {
            loop {
                // Accept a connection. If we fail, print the error and keep going.
                //
                // TODO: figure out when an endpoint closes, should I be looping on it? What are the criteria
                // for closing? It would error but what does that actually _mean_? Is it recoverable?
                let connection = match self.broker_listener.accept().await {
                    Ok(connection) => connection,
                    Err(err) => {
                        warn!("failed to accept connection: {}", err);
                        continue;
                    }
                };

                // Spawn a task to handle the [broker/private] connection
                let inner = inner.clone();
                spawn(Self::handle_broker_connection(inner, connection));
            }
        });

        // If one of the tasks exists, we want to return (stopping the program)
        select! {
            _ = heartbeat_task => {
                Err(Error::Exited("heartbeat task exited!".to_string()))
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
