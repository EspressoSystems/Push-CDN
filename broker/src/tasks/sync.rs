//! The sync task syncs both users and topics to other brokers.

use std::{sync::Arc, time::Duration};

use proto::{
    bail,
    crypto::signature::SignatureScheme,
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
        Arc::from(bail!(
            Message::UserSync(message.to_vec()).serialize(),
            Serialize,
            "failed to serialize full user sync map"
        ))
    }};
}

impl<BrokerScheme: SignatureScheme, UserScheme: SignatureScheme> Inner<BrokerScheme, UserScheme> {
    /// Perform a full user sync, sending our entire list of users to a remote broker. The broker is
    /// removed if we could not send it.
    ///
    /// # Errors
    /// - If we fail to serialize the message
    pub async fn full_user_sync(self: &Arc<Self>, broker: &BrokerIdentifier) -> Result<()> {
        // Get full user sync map
        let full_sync_map = self.connections.get_full_user_sync().await;

        // Serialize the message
        let raw_message = prepare_sync_message!(full_sync_map);

        // Send it to the broker
        self.connections.send_to_broker(broker, raw_message);

        Ok(())
    }

    /// Perform a partial user sync, sending our _partial_ list of users to a remote broker. The broker is
    /// removed if we could not send it.
    ///
    /// # Errors
    /// - If we fail to serialize the message
    pub async fn partial_user_sync(self: &Arc<Self>) -> Result<()> {
        // Get full user sync map
        let partial_sync_map = self.connections.get_partial_user_sync().await;

        // Return if we haven't had any changes
        if partial_sync_map.underlying_map.is_empty() {
            return Ok(());
        }

        // Serialize the message
        let raw_message = prepare_sync_message!(partial_sync_map);

        // Send it to all brokers
        self.connections.send_to_brokers(raw_message);

        Ok(())
    }

    /// Perform a full topic sync, sending our entire list of topics to a remote broker. The broker is
    /// removed if we could not send it.
    ///
    /// # Errors
    /// - if we fail to serialize the message
    pub async fn full_topic_sync(self: &Arc<Self>, broker: &BrokerIdentifier) -> Result<()> {
        // Get full list of topics
        let topics = self.connections.get_full_topic_sync().await;

        // Serialize the message
        let raw_message = Arc::from(bail!(
            Message::Subscribe(topics).serialize(),
            Serialize,
            "failed to serialize topics"
        ));

        // Send to the specified broker
        self.connections.send_to_broker(broker, raw_message);

        Ok(())
    }

    /// Perform a partial topic sync, sending our _partial_ list of topics to a remote broker (if any have changed).
    /// The broker is removed if we could not send it.
    ///
    /// # Errors
    /// - If we fail to serialize the message
    pub async fn partial_topic_sync(self: &Arc<Self>) -> Result<()> {
        // Get partial list of topics
        let (additions, removals) = self.connections.get_partial_topic_sync().await;

        // If we have some additions,
        if !additions.is_empty() {
            // Serialize the subscribe message
            let raw_subscribe_message = Arc::from(bail!(
                Message::Subscribe(additions).serialize(),
                Serialize,
                "failed to serialize topics"
            ));
            self.connections.send_to_brokers(raw_subscribe_message);
        }

        // If we have some removals,
        if !removals.is_empty() {
            // Serialize the unsubscribe message
            let raw_unsubscribe_message = Arc::from(bail!(
                Message::Unsubscribe(removals).serialize(),
                Serialize,
                "failed to serialize topics"
            ));

            // Send to all brokers
            self.connections.send_to_brokers(raw_unsubscribe_message);
        }

        Ok(())
    }

    
    /// Run the sync task. This is responsible for updating brokers with our user and topic states
    /// on an interval.
    pub async fn run_sync_task(self: Arc<Self>) {
        loop {
            // Perform user sync
            if let Err(err) = self.partial_user_sync().await {
                error!("failed to perform partial user sync: {err}");
            }

            // Perform topic sync
            if let Err(err) = self.partial_topic_sync().await {
                error!("failed to perform partial user sync: {err}");
            };

            // Sleep
            // TODO: parameterize this
            sleep(Duration::from_secs(30)).await;
        }
    }
}
