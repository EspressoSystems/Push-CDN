//! The broker listener task listens and handles connections from new brokers.

use std::sync::Arc;

use proto::{
    connection::protocols::{Listener, Protocol},
    crypto::{Scheme, Serializable},
};
use tokio::spawn;
use tracing::warn;

use crate::Inner;

impl<
        BrokerSignatureScheme: Scheme,
        BrokerProtocolType: Protocol,
        UserSignatureScheme: Scheme,
        UserProtocolType: Protocol,
    > Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>
where
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    UserSignatureScheme::VerificationKey: Serializable,
    UserSignatureScheme::Signature: Serializable,
{
    /// Runs the broker listener task in a loop.
    pub async fn run_broker_listener_task(self: Arc<Self>, listener: BrokerProtocolType::Listener) {
        loop {
            // Accept a connection. If we fail, print the error and keep going.
            //
            // TODO: figure out when an endpoint closes, should I be looping on it? What are the criteria
            // for closing? It would error but what does that actually _mean_? Is it recoverable?
            let connection = match listener.accept().await {
                Ok(connection) => connection,
                Err(err) => {
                    warn!("failed to accept connection: {}", err);
                    continue;
                }
            };

            spawn(
                // Handle the broker connection
                self.clone().handle_broker_connection(connection, false),
            );
        }
    }
}
