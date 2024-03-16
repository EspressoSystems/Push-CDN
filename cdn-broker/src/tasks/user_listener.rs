//! The user listener tasks listens and deals with user connections.

use std::sync::Arc;

use cdn_proto::{
    connection::{
        hooks::{Trusted, Untrusted},
        protocols::{Listener, Protocol, UnfinalizedConnection},
    },
    crypto::signature::SignatureScheme,
};
use tokio::spawn;
use tracing::error;

use crate::Inner;

impl<
        BrokerScheme: SignatureScheme,
        UserScheme: SignatureScheme,
        BrokerProtocol: Protocol<Trusted>,
        UserProtocol: Protocol<Untrusted>,
    > Inner<BrokerScheme, UserScheme, BrokerProtocol, UserProtocol>
{
    // We run the user listener task in a loop, accepting and handling new connections as needed.
    pub async fn run_user_listener_task(self: Arc<Self>, listener: UserProtocol::Listener) {
        loop {
            // Accept an unfinalized connection. If we fail, print the error and keep going.
            //
            // TODO: figure out when an endpoint closes, should I be looping on it? What are the criteria
            // for closing? It would error but what does that actually _mean_? Is it recoverable?
            let unfinalized_connection = match listener.accept().await {
                Ok(connection) => connection,
                Err(err) => {
                    error!("failed to accept connection: {}", err);
                    return;
                }
            };

            // Create the user connection handler
            let inner = self.clone();
            spawn(async move {
                // Finalize the connection
                let Ok(connection) = unfinalized_connection.finalize().await else {
                    return;
                };

                // Handle the connection
                inner.handle_user_connection(connection).await;
            });
        }
    }
}
