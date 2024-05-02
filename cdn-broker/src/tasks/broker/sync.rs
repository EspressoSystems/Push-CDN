//! The sync task syncs both users and topics to other brokers.

use std::{sync::Arc, time::Duration};

use cdn_proto::{
    bail,
    connection::Bytes,
    def::RunDef,
    discovery::BrokerIdentifier,
    error::{Error, Result},
    message::Message,
};
use tokio::time::sleep;
use tracing::error;

use crate::Inner;

macro_rules! prepare_sync_message {
    ($map: expr) => {{
        // Serialize the map using `rkyv`
        let message = bail!(
            rkyv::to_bytes::<_, 2048>(&$map),
            Serialize,
            "failed to serialize full user sync map"
        );

        // Wrap the message in `UserSync` and serialize it
        Bytes::from_unchecked(bail!(
            Message::UserSync(message.to_vec()).serialize(),
            Serialize,
            "failed to serialize full user sync map"
        ))
    }};
}

impl<Def: RunDef> Inner<Def> {
    /// Perform a full user sync, sending our entire list of users to a remote broker. The broker is
    /// removed if we could not send it.
    ///
    /// # Errors
    /// - If we fail to serialize the message
    /// - If we fail to send the message
    pub fn full_user_sync(self: &Arc<Self>, broker: &BrokerIdentifier) -> Result<()> {
        // Get full user sync map
        let full_sync_map = self.connections.read().get_full_user_sync();

        // Serialize and send the message to the broker
        self.try_send_to_broker(broker, prepare_sync_message!(full_sync_map));

        Ok(())
    }

    /// Perform a partial user sync, sending our _partial_ list of users to a remote broker. The broker is
    /// removed if we could not send it.
    ///
    /// # Errors
    /// - If we fail to serialize the message
    pub fn partial_user_sync(self: &Arc<Self>) -> Result<()> {
        // Get partial user sync map
        let partial_sync_map = self.connections.write().get_partial_user_sync();

        // Return if we haven't had any changes
        if partial_sync_map.underlying_map.is_empty() {
            return Ok(());
        }

        // Serialize the message
        let raw_message = prepare_sync_message!(partial_sync_map);

        // Send to all brokers
        self.try_send_to_brokers(&raw_message);

        Ok(())
    }

    /// Perform a full topic sync, sending our entire list of topics to a remote broker. The broker is
    /// removed if we could not send it.
    ///
    /// # Errors
    /// - if we fail to serialize the message
    pub fn full_topic_sync(self: &Arc<Self>, broker_identifier: &BrokerIdentifier) -> Result<()> {
        // Get full list of topics
        let topics = self.connections.read().get_full_topic_sync();

        // Send to broker
        self.try_send_to_broker(
            broker_identifier,
            Bytes::from_unchecked(bail!(
                Message::Subscribe(topics).serialize(),
                Serialize,
                "failed to serialize topics"
            )),
        );

        Ok(())
    }

    /// Perform a partial topic sync, sending our _partial_ list of topics to a remote broker (if any have changed).
    /// The broker is removed if we could not send it.
    ///
    /// # Errors
    /// - If we fail to serialize the message
    pub fn partial_topic_sync(self: &Arc<Self>) -> Result<()> {
        // Get partial list of topics
        let (additions, removals) = self.connections.write().get_partial_topic_sync();

        // If we have some additions,
        if !additions.is_empty() {
            // Serialize the subscribe message
            let raw_subscribe_message = Bytes::from_unchecked(bail!(
                Message::Subscribe(additions).serialize(),
                Serialize,
                "failed to serialize topics"
            ));

            // Send to all brokers
            self.try_send_to_brokers(&raw_subscribe_message);
        }

        // If we have some removals,
        if !removals.is_empty() {
            // Serialize the unsubscribe message
            let raw_unsubscribe_message = Bytes::from_unchecked(bail!(
                Message::Unsubscribe(removals).serialize(),
                Serialize,
                "failed to serialize topics"
            ));

            // Send to all brokers
            self.try_send_to_brokers(&raw_unsubscribe_message);
        }

        Ok(())
    }

    /// Run the sync task. This is responsible for updating brokers with our user and topic states
    /// on an interval.
    pub async fn run_sync_task(self: Arc<Self>) {
        loop {
            // Perform user sync
            if let Err(err) = self.partial_user_sync() {
                error!("failed to perform partial user sync: {err}");
            };

            // Perform topic sync
            if let Err(err) = self.partial_topic_sync() {
                error!("failed to perform partial topic sync: {err}");
            };

            // Sleep
            sleep(Duration::from_secs(10)).await;
        }
    }
}
