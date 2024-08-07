// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

use std::sync::Arc;

use cdn_proto::{connection::Bytes, def::RunDef, discovery::BrokerIdentifier};
use tracing::error;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    /// Attempts to asynchronously send a message to a broker.
    /// If it fails, the broker is removed from the list of connections.
    pub async fn try_send_to_broker(
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
            if let Err(e) = connection.send_message_raw(message).await {
                error!("failed to send message to broker: {:?}", e);

                // Remove the broker if we failed to send the message
                self_
                    .connections
                    .write()
                    .remove_broker(&broker_identifier_, "failed to send message");
            }
        }
    }

    /// Attempts to asynchronously send a message to all brokers.
    /// If it fails, the failing broker is removed from the list of connections.
    pub async fn try_send_to_brokers(self: &Arc<Self>, message: &Bytes) {
        // Get the optional connection
        let brokers = self.connections.read().get_broker_identifiers();

        for broker in brokers {
            self.clone()
                .try_send_to_broker(&broker, message.clone())
                .await;
        }
    }
}
