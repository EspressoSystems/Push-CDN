// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! The sync task syncs both users and topics to other brokers.

use std::{sync::Arc, time::Duration};

use cdn_proto::{
    bail,
    connection::Bytes,
    database::BrokerIdentifier,
    def::RunDef,
    error::{Error, Result},
    message::Message,
};
use tokio::time::sleep;
use tracing::error;

use crate::Inner;

macro_rules! prepare_sync_message {
    ($map: expr, $ty: expr) => {{
        // Serialize the map using `rkyv`
        let message = bail!(
            rkyv::to_bytes::<_, 2048>(&$map),
            Serialize,
            "failed to serialize user sync map"
        );

        // Wrap the message in `UserSync` and serialize it
        Bytes::from_unchecked(bail!(
            $ty(message.to_vec()).serialize(),
            Serialize,
            "failed to serialize user sync map"
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
    pub async fn full_user_sync(self: &Arc<Self>, broker: &BrokerIdentifier) -> Result<()> {
        // Get full user sync map
        let Some(full_sync_map) = self.connections.read().get_full_user_sync() else {
            return Ok(());
        };

        // Serialize and send the message to the broker
        self.try_send_to_broker(
            broker,
            prepare_sync_message!(full_sync_map, Message::UserSync),
        )
        .await;

        Ok(())
    }

    /// Perform a partial user sync, sending our _partial_ list of users to a remote broker. The broker is
    /// removed if we could not send it.
    ///
    /// # Errors
    /// - If we fail to serialize the message
    pub async fn partial_user_sync(self: &Arc<Self>) -> Result<()> {
        // Get partial user sync map
        let Some(partial_sync_map) = self.connections.write().get_partial_user_sync() else {
            return Ok(());
        };

        // Serialize the message
        let raw_message = prepare_sync_message!(partial_sync_map, Message::UserSync);

        // Send to all brokers
        self.try_send_to_brokers(&raw_message).await;

        Ok(())
    }

    /// Perform a full topic sync, sending our entire list of topics to a remote broker. The broker is
    /// removed if we could not send it.
    ///
    /// # Errors
    /// - if we fail to serialize the message
    pub async fn full_topic_sync(self: &Arc<Self>, broker: &BrokerIdentifier) -> Result<()> {
        // Get full topic sync map
        let Some(full_sync_map) = self.connections.read().get_full_topic_sync() else {
            return Ok(());
        };

        // Serialize and send the message to the broker
        self.try_send_to_broker(
            broker,
            prepare_sync_message!(full_sync_map, Message::TopicSync),
        )
        .await;

        Ok(())
    }

    /// Perform a partial topic sync, sending our _partial_ list of topics to a remote broker (if any have changed).
    /// The broker is removed if we could not send it.
    ///
    /// # Errors
    /// - If we fail to serialize the message
    pub async fn partial_topic_sync(self: &Arc<Self>) -> Result<()> {
        // Get partial topic sync map
        let Some(partial_sync_map) = self.connections.write().get_partial_topic_sync() else {
            // Return if we haven't had any changes
            return Ok(());
        };

        // Serialize the message
        let raw_message = prepare_sync_message!(partial_sync_map, Message::TopicSync);

        // Send to all brokers
        self.try_send_to_brokers(&raw_message).await;

        Ok(())
    }

    /// Run the sync task. This is responsible for updating brokers with our user and topic states
    /// on an interval.
    pub async fn run_sync_task(self: Arc<Self>) {
        loop {
            // Perform user sync
            if let Err(err) = self.partial_user_sync().await {
                error!("failed to perform partial user sync: {err}");
            };

            // Perform topic sync
            if let Err(err) = self.partial_topic_sync().await {
                error!("failed to perform partial topic sync: {err}");
            };

            // Sleep
            sleep(Duration::from_secs(10)).await;
        }
    }
}
