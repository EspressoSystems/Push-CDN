//! This file contains the implementation of the `Broker`, which routes messages
//! for the Push CDN.

use std::{marker::PhantomData, sync::Arc};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use proto::{
    bail,
    connection::protocols::{Connection, Listener, Protocol},
    error::{Error, Result},
    parse_socket_address,
    redis::{self, BrokerIdentifier},
};
use tokio::spawn;
use tracing::warn;

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

pub struct Inner<PrivateSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>>
{
    /// The underlying (public) verification key, used to authenticate with other brokers
    verification_key: PrivateSignatureScheme::VerificationKey,

    /// The underlying (private) signing key, used to authenticate with other brokers
    signing_key: PrivateSignatureScheme::SigningKey,
}

/// The main `Broker` struct. We instantiate this when we want to run a broker.
pub struct Broker<
    PrivateSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserProtocolType: Protocol,
    BrokerProtocolType: Protocol,
> {
    /// The broker's `Inner`. We clone this and pass it around when needed.
    inner: Arc<Inner<PrivateSignatureScheme>>,

    /// The `PhantomData` we need to be able to be generic over a signature scheme.
    pd: PhantomData<PrivateSignatureScheme>,

    /// The public (user -> broker) listener
    user_listener: UserProtocolType::Listener,

    /// The private (broker <-> broker) listener
    broker_listener: BrokerProtocolType::Listener,

    // The `Redis` client that we will use to maintain consistency between brokers and marshals
    redis_client: redis::Client,
}

impl<
        PrivateSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        UserProtocolType: Protocol,
        BrokerProtocolType: Protocol,
    > Broker<PrivateSignatureScheme, UserProtocolType, BrokerProtocolType>
{
    /// Create a new `Broker` from a `Config`
    pub async fn new(config: Config<PrivateSignatureScheme>) -> Result<Self> {
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

        // Create the `Redis` client we will use to maintain consistency
        let redis_client = bail!(
            redis::Client::new(
                redis_endpoint,
                Some(BrokerIdentifier {
                    user_advertise_address,
                    broker_advertise_address,
                }),
            )
            .await,
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

        Ok(Self {
            inner: Arc::from(Inner {
                verification_key,
                signing_key,
            }),
            user_listener,
            broker_listener,
            redis_client,
            pd: PhantomData,
        })
    }

    async fn handle_broker_connection(connection: BrokerProtocolType::Connection) {}

    async fn handle_user_connection(connection: UserProtocolType::Connection) {}

    /// The main loop for a broker.
    /// Consumes self.
    ///
    /// # Errors
    /// Right now, we return a `Result` but don't actually ever error.
    pub async fn start(self) -> Result<()> {
        // Spawn the public (user) listener task
        // TODO: maybe macro this, since it's repeat code with the private listener task
        spawn(async move {
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

                spawn(Self::handle_user_connection(connection));
            }
        });

        // Spawn the private (broker) listener task
        spawn(async move {
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

                spawn(Self::handle_broker_connection(connection));
            }
        });

        Ok(())
    }
}
