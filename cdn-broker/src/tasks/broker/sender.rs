use std::sync::Arc;

use cdn_proto::connection::protocols::Connection;
use cdn_proto::{connection::Bytes, def::RunDef, discovery::BrokerIdentifier};
use tokio::spawn;
use tracing::error;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    /// Attempts to asynchronously send a message to a broker.
    /// If it fails, the broker is removed from the list of connections.
    pub fn try_send_to_broker(
        self: &Arc<Self>,
        broker_identifier: &BrokerIdentifier,
        message: Bytes,
    ) {
        // Get the optional connection
        let connection = self
            .connections
            .read()
            .get_broker_connection(broker_identifier);

        // If the connection exists,
        if let Some(connection) = connection {
            // Clone what we need
            let self_ = self.clone();
            let broker_identifier_ = broker_identifier.clone();

            // Send the message
            let send_handle = spawn(async move {
                if let Err(e) = connection.send_message_raw(message).await {
                    error!("failed to send message to broker: {:?}", e);

                    // Remove the broker if we failed to send the message
                    self_
                        .connections
                        .write()
                        .remove_broker(&broker_identifier_, "failed to send message");
                };
            })
            .abort_handle();

            // Add the send handle to the list of tasks for the broker
            self.connections
                .write()
                .add_broker_task(broker_identifier, send_handle);
        }
    }

    /// Attempts to asynchronously send a message to all brokers.
    /// If it fails, the failing broker is removed from the list of connections.
    pub fn try_send_to_brokers(self: &Arc<Self>, message: &Bytes) {
        // Get the optional connection
        let brokers = self.connections.read().get_broker_identifiers();

        for broker in brokers {
            self.clone().try_send_to_broker(&broker, message.clone());
        }
    }
}
