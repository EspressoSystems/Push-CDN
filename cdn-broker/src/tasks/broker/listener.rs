//! The broker listener task listens and handles connections from new brokers.

use std::sync::Arc;

use cdn_proto::{
    connection::protocols::{Listener as _, UnfinalizedConnection},
    def::{Listener, RunDef},
};
use tokio::spawn;
use tracing::error;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    /// Runs the broker listener task in a loop.
    pub async fn run_broker_listener_task(self: Arc<Self>, listener: Listener<Def::Broker>) {
        loop {
            // Accept an unfinalized connection. If we fail, print the error and keep going.
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
                let Ok(connection) = unfinalized_connection
                    .finalize(inner.middleware.clone())
                    .await
                else {
                    return;
                };

                // Handle the connection
                inner.handle_broker_connection(connection, false).await;
            });
        }
    }
}
