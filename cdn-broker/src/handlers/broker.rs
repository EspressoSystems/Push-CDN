//! This file defines the broker connection handler.

use std::sync::Arc;

use cdn_proto::{
    authenticate_with_broker, bail,
    connection::{
        auth::broker::BrokerAuth,
        hooks::Trusted,
        protocols::{Protocol, Receiver},
        UserPublicKey,
    },
    def::RunDef,
    discovery::BrokerIdentifier,
    error::{Error, Result},
    message::Message,
    verify_broker,
};
use tracing::{error, info};

use crate::{connections::DirectMap, metrics, Inner};

impl<Def: RunDef> Inner<Def> {
    /// This function is the callback for handling a broker (private) connection.
    pub async fn handle_broker_connection(
        self: Arc<Self>,
        mut connection: (
            <Def::BrokerProtocol as Protocol<Trusted>>::Sender,
            <Def::BrokerProtocol as Protocol<Trusted>>::Receiver,
        ),
        is_outbound: bool,
    ) {
        // Depending on which way the direction came in, we will want to authenticate with a different
        // flow.
        let broker_identifier = if is_outbound {
            // If we reached out to the other broker first, authenticate first.
            let broker_address = authenticate_with_broker!(connection, self);
            verify_broker!(connection, self);
            broker_address
        } else {
            // If the other broker reached out to us first, authenticate second.
            verify_broker!(connection, self);
            authenticate_with_broker!(connection, self)
        };

        // Create new batch sender
        let (sender, receiver) = connection;

        // If we are already connected, ignore the new connection
        if self.connections.all_brokers().contains(&broker_identifier) {
            return;
        }

        // Add to our brokers
        self.connections
            .add_broker(broker_identifier.clone(), sender);

        // Send a full user sync
        if let Err(err) = self.full_user_sync(&broker_identifier) {
            error!("failed to perform full user sync: {err}");
            self.connections.remove_broker(&broker_identifier);
            return;
        };

        // Send a full topic sync
        // TODO: macro removals or something
        if let Err(err) = self.full_topic_sync(&broker_identifier) {
            error!("failed to perform full topic sync: {err}");
            self.connections.remove_broker(&broker_identifier);
            return;
        };

        // If we have `strong_consistency` enabled, send partials
        #[cfg(feature = "strong_consistency")]
        if let Err(err) = self.partial_topic_sync() {
            error!("failed to perform partial topic sync: {err}");
        }

        #[cfg(feature = "strong_consistency")]
        if let Err(err) = self.partial_user_sync() {
            error!("failed to perform partial user sync: {err}");
        }

        info!("connected to broker {}", broker_identifier);

        // Increment our metric
        metrics::NUM_BROKERS_CONNECTED.inc();

        // If we error, come back to the callback so we can remove the connection from the list.
        if let Err(err) = self.broker_receive_loop(&broker_identifier, receiver).await {
            error!("broker disconnected with error: {err}");
        };

        info!("disconnected from broker {}", broker_identifier);

        // Decrement our metric
        metrics::NUM_BROKERS_CONNECTED.dec();

        // Remove from the connected broker identities so that we may
        // try to reconnect inthe future.
        self.connections.remove_broker(&broker_identifier);
    }

    pub async fn broker_receive_loop(
        self: &Arc<Self>,
        broker_identifier: &BrokerIdentifier,
        receiver: <Def::BrokerProtocol as Protocol<Trusted>>::Receiver,
    ) -> Result<()> {
        while let Ok(raw_message) = receiver.recv_message_raw().await {
            // Attempt to deserialize the message
            let message = Message::deserialize(&raw_message)?;

            match message {
                // If we receive a direct message from a broker, we want to send it to the user with that key
                Message::Direct(ref direct) => {
                    let user_public_key = UserPublicKey::from(direct.recipient.clone());

                    self.connections
                        .send_direct(user_public_key, raw_message, true);
                }

                // If we receive a broadcast message from a broker, we want to send it to all interested users
                Message::Broadcast(ref broadcast) => {
                    let topics = broadcast.topics.clone();

                    self.connections.send_broadcast(topics, &raw_message, true);
                }

                // If we receive a subscribe message from a broker, we add them as "interested" locally.
                Message::Subscribe(subscribe) => {
                    self.connections
                        .subscribe_broker_to(broker_identifier, subscribe);
                }

                // If we receive a subscribe message from a broker, we remove them as "interested" locally.
                Message::Unsubscribe(unsubscribe) => {
                    self.connections
                        .unsubscribe_broker_from(broker_identifier, &unsubscribe);
                }

                // If we receive a `UserSync` message, we want to sync with our map
                Message::UserSync(user_sync) => {
                    // Deserialize via `rkyv`
                    let user_sync: DirectMap = bail!(
                        rkyv::from_bytes(&user_sync),
                        Deserialize,
                        "failed to deserialize user sync message"
                    );

                    self.connections.apply_user_sync(user_sync);
                }

                // Do nothing if we receive an unexpected message
                _ => {}
            }
        }

        Err(Error::Connection("connection closed".to_string()))
    }
}
