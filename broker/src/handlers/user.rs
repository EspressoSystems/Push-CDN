//! This file defines the user handler module, wherein we define connection handlers for
//! `Arc<Inner>`.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use proto::{
    connection::{
        auth::broker::BrokerAuth,
        batch::{BatchedSender, Position},
        protocols::{Protocol, Receiver},
    },
    crypto::signature::SignatureScheme,
    message::Message,
    UserProtocol,
};
use tracing::info;

#[cfg(feature = "local_discovery")]
use proto::discovery::DiscoveryClient;

use crate::metrics;

use crate::{
    get_lock, send_broadcast, send_direct, send_or_remove_many, state::ConnectionId, Inner,
};

impl<BrokerScheme: SignatureScheme, UserScheme: SignatureScheme> Inner<BrokerScheme, UserScheme> {
    /// This function handles a user (public) connection.
    pub async fn handle_user_connection(
        self: Arc<Self>,
        mut connection: (
            <UserProtocol as Protocol>::Sender,
            <UserProtocol as Protocol>::Receiver,
        ),
    ) {
        // Verify (authenticate) the connection
        let Ok((public_key, topics)) = BrokerAuth::<UserScheme>::verify_user(
            &mut connection,
            &self.identity,
            &mut self.discovery_client.clone(),
        )
        .await
        else {
            return;
        };

        // Create a human-readable user identifier (by public key)
        let user_identifier = mnemonic::to_string(&public_key[0..4]);
        info!("{user_identifier} connected");

        // Create new batch sender
        let (sender, receiver) = connection;
        let sender = Arc::new(BatchedSender::<UserProtocol>::from(
            sender,
            Duration::from_millis(50),
            1500,
        ));

        // Add the connection to the list of connections
        let connection_id = get_lock!(self.user_connection_lookup, write).add_connection(sender);

        // Add the user for their topics
        get_lock!(self.user_connection_lookup, write)
            .subscribe_connection_id_to_topics(connection_id, topics);

        // Add the user for their key
        get_lock!(self.user_connection_lookup, write)
            .subscribe_connection_id_to_keys(connection_id, vec![public_key]);

        // If we are in local mode, send updates to brokers immediately. This makes
        // it more strongly consistent with the tradeoff of being a bit more intensive.
        #[cfg(feature = "local_discovery")]
        let _ = self
            .send_updates_to_brokers(
                vec![],
                get_lock!(self.broker_connection_lookup, read)
                    .get_all_connections()
                    .clone(),
            )
            .await;

        // We want to perform a heartbeat for every user connection so that the number
        // of users connected to brokers is always evenly distributed.
        #[cfg(feature = "local_discovery")]
        let _ = self
            .discovery_client
            .clone()
            .perform_heartbeat(
                get_lock!(self.user_connection_lookup, read).get_connection_count() as u64,
                Duration::from_secs(60),
            )
            .await;

        // Increment our metric
        metrics::NUM_USERS_CONNECTED.inc();

        // This runs the main loop for receiving information from the user
        let () = self.user_receive_loop(connection_id, receiver).await;

        info!("{user_identifier} disconnected");

        // Decrement our metric
        metrics::NUM_USERS_CONNECTED.dec();

        // Once the main loop ends, we remove the connection
        self.user_connection_lookup
            .write()
            .await
            .remove_connection(connection_id);
    }

    /// This is the main loop where we deal with user connectins. On exit, the calling function
    /// should remove the user from the map.
    pub async fn user_receive_loop(
        &self,
        connection_id: ConnectionId,
        mut receiver: <UserProtocol as Protocol>::Receiver,
    ) {
        while let Ok(message) = receiver.recv_message().await {
            match message {
                // If we get a direct message from a user, send it to both users and brokers.
                Message::Direct(ref direct) => {
                    let message = Bytes::from(message.serialize().expect("serialization failed"));

                    send_direct!(self.broker_connection_lookup, direct.recipient, message);
                    send_direct!(self.user_connection_lookup, direct.recipient, message);
                }

                // If we get a broadcast message from a user, send it to both brokers and users.
                Message::Broadcast(ref broadcast) => {
                    let message = Bytes::from(message.serialize().expect("serialization failed"));

                    send_broadcast!(self.broker_connection_lookup, broadcast.topics, message);
                    send_broadcast!(self.user_connection_lookup, broadcast.topics, message);
                }

                // Subscribe messages from users will just update the state locally
                Message::Subscribe(mut subscribe) => {
                    subscribe.dedup();

                    get_lock!(self.user_connection_lookup, write)
                        .subscribe_connection_id_to_topics(connection_id, subscribe);
                }

                // Unsubscribe messages from users will just update the state locally
                Message::Unsubscribe(mut unsubscribe) => {
                    unsubscribe.dedup();

                    get_lock!(self.user_connection_lookup, write)
                        .unsubscribe_connection_id_from_topics(connection_id, unsubscribe);
                }

                _ => return,
            }
        }
    }
}
