//! This file contains the implementation of the `Marshal`, which the user
//! connects to before a broker. It is used to "marshal" a user to the broker
//! (right now) with the least amount of connections. It's basically a load
//! balancer for the brokers.

use std::{marker::PhantomData, sync::Arc};

use proto::{
    bail,
    connection::{
        auth::marshal::MarshalAuth,
        protocols::{Listener, Protocol, Sender},
    },
    crypto::{Scheme, Serializable},
    error::{Error, Result},
    redis,
};
use tokio::spawn;
use tracing::warn;

/// A connection `Marshal`. The user authenticates with it, receiving a permit
/// to connect to an actual broker. Think of it like a load balancer for
/// the brokers.
pub struct Marshal<SignatureScheme: Scheme, ProtocolType: Protocol> {
    /// The underlying connection listener. Used to accept new connections.
    listener: Arc<ProtocolType::Listener>,

    /// The redis client we use to issue permits and check for brokers that are up
    redis_client: redis::Client,

    /// We need this `PhantomData` to allow us to specify the signature scheme,
    /// protocol type, and authentication flow.
    pd: PhantomData<SignatureScheme>,
}

impl<SignatureScheme: Scheme, ProtocolType: Protocol> Marshal<SignatureScheme, ProtocolType>
where
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::Signature: Serializable,
{
    /// Create and return a new marshal from a bind address, and an optional
    /// TLS cert and key path.
    ///
    /// # Errors
    /// - If we fail to bind to the local address
    pub async fn new(
        bind_address: String,
        redis_endpoint: String,
        maybe_tls_cert_path: Option<String>,
        maybe_tls_key_path: Option<String>,
    ) -> Result<Self> {
        // Parse bind address
        let bind_address = bail!(bind_address.parse(), Parse, "failed to parse bind address");

        // Create the `Listener` from the bind address
        let listener = bail!(
            ProtocolType::bind(bind_address, maybe_tls_cert_path, maybe_tls_key_path).await,
            Connection,
            format!("failed to listen to address {}", bind_address)
        );

        // Create the Redis client
        let redis_client = bail!(
            redis::Client::new(redis_endpoint.clone(), None).await,
            Connection,
            "failed to create Redis client"
        );

        // Create `Self` from the `Listener`
        Ok(Self {
            listener: Arc::from(listener),
            redis_client,
            pd: PhantomData,
        })
    }

    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        mut connection: (ProtocolType::Sender, ProtocolType::Receiver),
        mut redis_client: redis::Client,
    ) {
        // Verify (authenticate) the connection
        let _ = MarshalAuth::<SignatureScheme, ProtocolType>::verify_user(
            &mut connection,
            &mut redis_client,
        )
        .await;

        // We don't care about this, just drop the connection immediately.
        let _ = connection.0.finish().await;
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
            let redis_client = self.redis_client.clone();
            spawn(Self::handle_connection(connection, redis_client));
        }
    }
}
