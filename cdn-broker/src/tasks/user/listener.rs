// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! The user listener tasks listens and deals with user connections.

use std::sync::Arc;

use cdn_proto::{
    connection::protocols::{Listener as _, UnfinalizedConnection},
    def::{Listener, RunDef},
};
use tokio::spawn;
use tracing::error;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    // We run the user listener task in a loop, accepting and handling new connections as needed.
    pub async fn run_user_listener_task(self: Arc<Self>, listener: Listener<Def::User>) {
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
                let Ok(connection) = unfinalized_connection.finalize(inner.limiter.clone()).await
                else {
                    return;
                };

                // Handle the connection
                inner.handle_user_connection(connection).await;
            });
        }
    }
}
