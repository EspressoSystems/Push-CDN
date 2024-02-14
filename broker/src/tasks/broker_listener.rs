//! The broker listener task listens and handles connections from new brokers.

use std::sync::Arc;

use proto::{
    connection::protocols::{Listener, Protocol},
    crypto::signature::SignatureScheme,
    BrokerProtocol,
};
use tokio::spawn;
use tracing::warn;
// TODO: change connection to be named struct instead of tuple for readability purposes

use crate::Inner;

impl<BrokerScheme: SignatureScheme, UserScheme: SignatureScheme> Inner<BrokerScheme, UserScheme> {
    /// Runs the broker listener task in a loop.
    pub async fn run_broker_listener_task(
        self: Arc<Self>,
        listener: <BrokerProtocol as Protocol>::Listener,
    ) {
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
