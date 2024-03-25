//! The user listener tasks listens and deals with user connections.

use std::sync::Arc;

use cdn_proto::{
    connection::{
        hooks::Untrusted,
        protocols::{Listener, Protocol, UnfinalizedConnection},
    },
    def::RunDef,
};
use tokio::spawn;
use tracing::error;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    // We run the user listener task in a loop, accepting and handling new connections as needed.
    pub async fn run_user_listener_task(
        self: Arc<Self>,
        listener: <Def::UserProtocol as Protocol<Untrusted>>::Listener,
    ) {
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
                let Ok(connection) = unfinalized_connection.finalize().await else {
                    return;
                };

                // Handle the connection
                inner.handle_user_connection(connection).await;
            });
        }
    }
}
