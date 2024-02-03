//! This file contains the implementation of the `Marshal`, which the user
//! connects to before a broker. It is used to "marshal" a user to the broker
//! (right now) with the least amount of connections. It's basically a load
//! balancer for the brokers.

use std::{marker::PhantomData, sync::Arc};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use proto::{
    bail,
    connection::{
        auth::Flow,
        protocols::{Listener, Protocol},
    },
    error::{Error, Result},
};

/// A connection `Marshal`. The user authenticates with it, receiving a permit
/// to connect to an actual broker. Think of it like a load balancer for
/// the brokers.
pub struct Marshal<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
    AuthFlow: Flow<SignatureScheme, ProtocolType>,
> {
    listener: Arc<ProtocolType::Listener>,
    pd: PhantomData<(SignatureScheme, AuthFlow)>,
}

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
        AuthFlow: Flow<SignatureScheme, ProtocolType>,
    > Marshal<SignatureScheme, ProtocolType, AuthFlow>
{
    /// Create and return a new marshal from a bind address, and an optional
    /// TLS cert and key path.
    ///
    /// # Errors
    /// - If we fail to bind to the local address
    pub async fn new(
        bind_address: String,
        maybe_tls_cert_path: Option<String>,
        maybe_tls_key_path: Option<String>,
    ) -> Result<Self> {
        // Parse bind address
        let bind_address = bail!(bind_address.parse(), Parse, "failed to parse bind address");

        // Create the `Listener` from the bind address
        let listener = bail!(
            ProtocolType::Listener::bind(bind_address, maybe_tls_cert_path, maybe_tls_key_path)
                .await,
            Connection,
            format!("failed to listen to address {}", bind_address)
        );

        // Create `Self` from the `Listener`
        Ok(Self {
            listener: Arc::from(listener),
            pd: PhantomData,
        })
    }

    /// The main loop for a marshal.
    /// Consumes self.
    ///
    /// # Errors
    /// Right now, we return a `Result` but don't actually ever error.
    pub async fn start(self) -> Result<()> {
        // Listen for connections forever
        loop {
            // Accept a connection. If we fail, print the error cand keep going.
            //
            // TODO: figure out when an endpoint closes, should I be looping on it? What are the criteria
            // for closing? It would error but what does that actually _mean_? Is it recoverable?
            let connection = match self.listener.accept().await {
                Ok(connection) => connection,
                Err(err) => {
                    tracing::error!("failed to accept connection: {}", err);
                    continue;
                }
            };

            // Authenticate the connection
            AuthFlow::verify(connection).await?;
        }
    }
}
