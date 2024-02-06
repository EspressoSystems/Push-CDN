//! This file contains the implementation of the `Broker`, which routes messages
//! for the Push CDN.

// TODO: convert QUIC to locked single sender/reciver

mod state;

use std::{marker::PhantomData, sync::Arc, time::Duration};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
// TODO: figure out if we should use Tokio's here
use proto::{
    authenticate_with_broker, bail,
    connection::{
        auth::broker::BrokerAuth,
        protocols::{Connection, Listener, Protocol},
    },
    crypto::Serializable,
    error::{Error, Result},
    parse_socket_address,
    redis::{self, BrokerIdentifier},
    verify_broker,
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
    BrokerProtocolType: Protocol,
    UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserProtocolType: Protocol,
> where
    UserSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::SigningKey: Serializable,
{
    /// A broker identifier that we can use to establish uniqueness among brokers.
    identifier: BrokerIdentifier,

    /// The (clonable) `Redis` client that we will use to maintain consistency between brokers and marshals
    redis_client: redis::Client,

    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    /// TODO: verif & signing key in one struct
    pub verification_key: BrokerSignatureScheme::VerificationKey,

    /// The underlying (private) signing key, used to sign messages to send to the server during the
    /// authentication phase.
    pub signing_key: BrokerSignatureScheme::SigningKey,

    // connected_keys: LoggedSet<UserSignatureScheme::VerificationKey>,
    /// The `PhantomData` that we need to be generic over protocol types.
    pd: PhantomData<(UserProtocolType, BrokerProtocolType, UserSignatureScheme)>,
}

/// The main `Broker` struct. We instantiate this when we want to run a broker.
pub struct Broker<
    BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    BrokerProtocolType: Protocol,
    UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserProtocolType: Protocol,
> where
    UserSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::SigningKey: Serializable,
{
    /// The broker's `Inner`. We clone this and pass it around when needed.
    inner: Arc<
        Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
    >,

    /// The public (user -> broker) listener
    user_listener: UserProtocolType::Listener,

    /// The private (broker <-> broker) listener
    broker_listener: BrokerProtocolType::Listener,
}

impl<
        BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        BrokerProtocolType: Protocol,
        UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        UserProtocolType: Protocol,
    > Broker<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>
where
    UserSignatureScheme::Signature: Serializable,
    UserSignatureScheme::VerificationKey: Serializable,
    UserSignatureScheme::SigningKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::SigningKey: Serializable,
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
                redis_client,
                identifier,
                verification_key,
                signing_key,
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
            Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
        >,
        connection: BrokerProtocolType::Connection,
        is_outbound: bool,
    ) {
        // Depending on which way the direction came in, we will want to authenticate with a different
        // flow.
        let broker_address = if is_outbound {
            // If we reached out to the other broker first, authenticate first.
            let broker_address = authenticate_with_broker!(connection, inner);
            verify_broker!(connection, inner);
            broker_address
        } else {
            // If the other broker reached out to us first, authenticate second.
            verify_broker!(connection, inner);
            authenticate_with_broker!(connection, inner)
        };
    }

    /// This function handles a user (public) connection. We take the following steps:
    /// 1. Authenticate the user
    /// 2. TODO
    async fn handle_user_connection(
        inner: Arc<
            Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
        >,
        connection: UserProtocolType::Connection,
    ) {
        // Verify (authenticate) the connection
        let Ok(verification_key) =
            BrokerAuth::<UserSignatureScheme, UserProtocolType>::verify_user(
                &connection,
                &inner.identifier,
                &mut inner.redis_client.clone(),
            )
            .await
        else {
            return;
        };

        println!("meow");

        // // Create a new queued connection
        // let connection_with_queue = ConnectionWithQueue{
        //     connection: connection,
        //     last_sent: SystemTime::now(),
        //     buffer: Arc::default(),

        // }

        // // Add to our direct map
        // inner.user_to_connection.write().await.insert(verification_key, Either::Left());
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
        // We also use it to check for new brokers who may have joined.
        let heartbeat_task = spawn(async move {
            // Clone the `Redis` client, which needs to be mutable
            let mut redis_client = inner.redis_client.clone();
            loop {
                // Register with `Redis` every 20 seconds, updating our number of connected users
                if let Err(err) = redis_client
                    .perform_heartbeat(
                        // todo: actually pull in this number
                        0,
                        Duration::from_secs(60),
                    )
                    .await
                {
                    // If we fail, we want to see this
                    error!("failed to perform heartbeat: {}", err);
                }

                // Check for new brokers, spawning tasks to connect to them if necessary
                match redis_client.get_other_brokers().await {
                    Ok(brokers) => {
                        // Calculate the difference, spawn tasks to connect to them
                        // TODO for broker in brokers.difference(&inner.brokers_connected.read()) {
                        for broker in brokers {
                            // TODO: make this into a separate function
                            // Extrapolate the address to connect to
                            let to_connect_address = broker.broker_advertise_address.clone();

                            // Clone the inner because we need it for the possible new broker task
                            let inner = inner.clone();

                            // Spawn task to connect to a broker we haven't seen
                            spawn(async move {
                                // Connect to the broker
                                let connection = match BrokerProtocolType::Connection::connect(
                                    to_connect_address,
                                )
                                .await
                                {
                                    Ok(connection) => connection,
                                    Err(err) => {
                                        error!("failed to connect to broker: {err}");
                                        return;
                                    }
                                };

                                // Handle the broker connection
                                Self::handle_broker_connection(inner, connection, true).await;
                            });
                        }
                    }

                    Err(err) => {
                        // This is an important error as well
                        error!("failed to get other brokers: {}", err);
                    }
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
                spawn(Self::handle_broker_connection(inner, connection, false));
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
