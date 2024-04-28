//! This file defines the broker connection handler.

use std::sync::Arc;

use cdn_proto::{
    authenticate_with_broker, bail,
    connection::{auth::broker::BrokerAuth, protocols::Connection as _, UserPublicKey},
    def::{Connection, RunDef},
    discovery::BrokerIdentifier,
    error::{Error, Result},
    message::Message,
    verify_broker,
};
use tokio::spawn;
use tracing::{error, info, warn};

use crate::{connections::DirectMap, metrics, Inner};

impl<Def: RunDef> Inner<Def> {
    /// This function is the callback for handling a broker (private) connection.
    pub async fn handle_broker_connection(
        self: Arc<Self>,
        mut connection: Connection<Def::Broker>,
        is_outbound: bool,
    ) {
        // Acquire a permit to authenticate with a broker. Removes the possibility for race
        // conditions when doing so.
        let Ok(auth_guard) = self.broker_auth_lock.acquire().await else {
            error!("needed semaphore has been closed");
            std::process::exit(-1);
        };

        // Depending on which way the direction came in, we will want to authenticate with a different
        // flow.
        let broker_identifier = if is_outbound {
            // If we reached out to the other broker first, authenticate first.
            let broker_endpoint = authenticate_with_broker!(connection, self);
            verify_broker!(connection, self);
            broker_endpoint
        } else {
            // If the other broker reached out to us first, authenticate second.
            verify_broker!(connection, self);
            authenticate_with_broker!(connection, self)
        };

        // Increment our metric
        metrics::NUM_BROKERS_CONNECTED.inc();

        let self_ = self.clone();
        let broker_identifier_ = broker_identifier.clone();
        let connection_ = connection.clone();
        let receive_handle = spawn(async move {
            info!(id = %broker_identifier_, "broker connected");

            // If we error, come back to the callback so we can remove the connection from the list.
            if let Err(err) = self_
                .broker_receive_loop(&broker_identifier_, connection_)
                .await
            {
                warn!(
                    id = %broker_identifier_,
                    error = err.to_string(),
                    "broker disconnected"
                );
            };

            // Decrement our metric
            metrics::NUM_BROKERS_CONNECTED.dec();
        })
        .abort_handle();

        // Add to our brokers and remove the old one if it exists
        self.connections
            .write()
            .add_broker(broker_identifier.clone(), connection, receive_handle);

        // Send a full user sync
        if let Err(err) = self.full_user_sync(&broker_identifier) {
            error!("failed to perform full user sync: {err}");
            return;
        };

        // Send a full topic sync
        // TODO: macro removals or something
        if let Err(err) = self.full_topic_sync(&broker_identifier) {
            error!("failed to perform full topic sync: {err}");
            return;
        };

        // If we have `strong-consistency` enabled, send partials
        #[cfg(feature = "strong-consistency")]
        if let Err(err) = self.partial_topic_sync() {
            error!("failed to perform partial topic sync: {err}");
        }

        #[cfg(feature = "strong-consistency")]
        if let Err(err) = self.partial_user_sync() {
            error!("failed to perform partial user sync: {err}");
        }

        // Once we have added the broker, drop the authentication guard
        drop(auth_guard);
    }

    pub async fn broker_receive_loop(
        self: &Arc<Self>,
        broker_identifier: &BrokerIdentifier,
        connection: Connection<Def::Broker>,
    ) -> Result<()> {
        loop {
            // Receive a message from the broker
            let raw_message = connection.recv_message_raw().await?;

            // Attempt to deserialize the message
            let message = Message::deserialize(&raw_message)?;

            match message {
                // If we receive a direct message from a broker, we want to send it to the user with that key
                Message::Direct(ref direct) => {
                    let user_public_key = UserPublicKey::from(direct.recipient.clone());

                    self.send_direct(user_public_key, raw_message, true);
                }

                // If we receive a broadcast message from a broker, we want to send it to all interested users
                Message::Broadcast(ref broadcast) => {
                    let topics = broadcast.topics.clone();

                    self.send_broadcast(topics, &raw_message, true);
                }

                // If we receive a subscribe message from a broker, we add them as "interested" locally.
                Message::Subscribe(subscribe) => {
                    self.connections
                        .write()
                        .subscribe_broker_to(broker_identifier, subscribe);
                }

                // If we receive a subscribe message from a broker, we remove them as "interested" locally.
                Message::Unsubscribe(unsubscribe) => {
                    self.connections
                        .write()
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

                    self.connections.write().apply_user_sync(user_sync);
                }

                // Do nothing if we receive an unexpected message
                _ => {}
            }
        }
    }
}
