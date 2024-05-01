use std::sync::Arc;

use cdn_proto::{
    connection::{protocols::Connection, Bytes},
    def::RunDef,
    discovery::BrokerIdentifier,
    error::{Error, Result},
};
use tokio::spawn;
use tracing::error;

use crate::Inner;

impl<R: RunDef> Inner<R> {
    /// Asynchronously send a message to all currently connected brokers. On failure,
    /// the broker will be removed.
    pub async fn spawn_send_to_brokers(self: &Arc<Self>, message: &Bytes) {
        // For each broker,
        for connection in &self.connections.read().await.brokers {
            // Clone things we will need downstream
            let message = message.clone();
            let broker_identifier = connection.0.clone();
            let connection = connection.1 .0.clone();
            let connections = self.connections.clone();

            // Spawn a task to send the message
            spawn(async move {
                if let Err(err) = connection.send_message_raw(message).await {
                    // If we fail, remove the broker from our map.
                    error!("failed to send message to broker: {err}");
                    connections
                        .write()
                        .await
                        .remove_broker(&broker_identifier, "failed to send message");
                };
            });
        }
    }

    /// Send a message to a particular broker. If it fails, it removes the broker from all maps.
    /// Awaits on message acknowledgement and returns the error if it does
    pub async fn send_to_broker(
        self: &Arc<Self>,
        broker_identifier: &BrokerIdentifier,
        message: Bytes,
    ) -> Result<()> {
        let connections_read_guard = self.connections.read().await;
        // If we are connected to them,
        if let Some((connection, _)) = connections_read_guard.brokers.get(broker_identifier) {
            // Send the message
            if let Err(err) = connection.send_message_raw(message).await {
                // Remove them if we failed to send it
                error!("failed to send message to broker: {err}");

                // Drop the read guard before acquiring the write lock
                drop(connections_read_guard);

                self.connections
                    .write()
                    .await
                    .remove_broker(broker_identifier, "failed to send message");

                // Return an error
                return Err(Error::Connection(
                    "failed to send message to broker".to_string(),
                ));
            };
        } else {
            // Drop the read guard before acquiring the write lock
            drop(connections_read_guard);

            // Remove the broker if they are not connected
            self.connections
                .write()
                .await
                .remove_broker(broker_identifier, "not connected");

            // Return an error
            return Err(Error::Connection(
                "failed to send message to broker".to_string(),
            ));
        }

        Ok(())
    }
}
