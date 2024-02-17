//! The update task is responsible for periodically sending state updates to other brokers.

use std::{sync::Arc, time::Duration};

use crate::{
    get_lock,
    state::{ConnectionId, Sender},
    Inner,
};
use crate::{new_serialized_message, send_or_remove_many};
use bytes::Bytes;
use proto::{
    bail,
    connection::batch::Position,
    crypto::signature::SignatureScheme,
    error::{Error, Result},
    message::Message,
    BrokerProtocol,
};
use tokio::time::sleep;
use tracing::error;

/// This is a macro that helps us send an update to other brokers. The message type depends on
/// whether it is a user update or a topic update. The recipients is the other brokers (or broker)
/// for which we want the partial/complete update, and the position refers to the position the message
/// should go in the queue.
macro_rules! send_update_to_brokers {
    ($self:expr, $message_type: ident, $data:expr, $recipients: expr, $position: ident) => {{
        // If the data is not empty, make a message of the specified type
        if !$data.is_empty() {
            // Create a `Subscribe` message, which contains the full list of topics we're subscribed to
            let message = new_serialized_message!($message_type, $data);

            // For each recipient, send to the destined position in the queue
            send_or_remove_many!(
                $recipients,
                $self.broker_connection_lookup,
                message,
                Position::$position
            );
        }
    }};
}

impl<BrokerScheme: SignatureScheme, UserScheme: SignatureScheme> Inner<BrokerScheme, UserScheme> {
    /// This task deals with sending connected user and topic updates to other brokers. It takes advantage of
    /// `SnapshotMap`, so we can send partial or full updates to the other brokers as they need it.
    /// Right now, we do it every 5 seconds, or on every user connect if the number of connections is
    /// sufficiently low.
    pub async fn run_update_task(self: Arc<Self>) {
        loop {
            // Send other brokers our subscription and topic updates. None of them get full updates.
            if let Err(err) = self
                .send_updates_to_brokers(
                    vec![],
                    get_lock!(self.broker_connection_lookup, read)
                        .get_all_connections()
                        .clone(),
                )
                .await
            {
                error!("failed to send updates to other brokers: {err}");
            };

            sleep(Duration::from_secs(5)).await;
        }
    }
    /// This function lets us send updates to brokers on demand. We need this to ensure consistency between brokers
    /// (e.g. which brokers have which users connected). We send these updates out periodically, but also
    /// on every user join if the number of connected users is sufficiently small.
    pub async fn send_updates_to_brokers(
        self: &Arc<Self>,
        full: Vec<(ConnectionId, Sender<BrokerProtocol>)>,
        partial: Vec<(ConnectionId, Sender<BrokerProtocol>)>,
    ) -> Result<()> {
        // When a broker connects, we have to send:
        // 1. Our snapshot to the new broker (of what topics/users we're subscribed for)
        // 2. A list of updates since that snapshot to all brokers.
        // This is so we're all on the same page.
        let topic_snapshot =
            get_lock!(self.user_connection_lookup, write).get_topic_updates_since();

        // Get the snapshot for which user keys we're responsible for
        let key_snapshot = get_lock!(self.user_connection_lookup, write).get_key_updates_since();

        // Send the full connected users to interested brokers first in the queue (so that it is the correct order)
        // TODO: clean up this function
        send_update_to_brokers!(self, UsersConnected, key_snapshot.snapshot, &full, Front);

        // Send the full topics list to interested brokers first in the queue (so that it is the correct order)
        send_update_to_brokers!(self, Subscribe, topic_snapshot.snapshot, &full, Front);

        // Send the insertion updates for keys, if any
        send_update_to_brokers!(
            self,
            UsersConnected,
            key_snapshot.insertions,
            &partial,
            Back
        );

        // Send the removal updates for keys, if any
        send_update_to_brokers!(
            self,
            UsersDisconnected,
            key_snapshot.removals,
            &partial,
            Back
        );

        // Send the insertion updates for topics, if any
        send_update_to_brokers!(self, Subscribe, topic_snapshot.insertions, &partial, Back);

        // Send the removal updates for topics, if any
        send_update_to_brokers!(self, Unsubscribe, topic_snapshot.removals, &partial, Back);

        Ok(())
    }
}
