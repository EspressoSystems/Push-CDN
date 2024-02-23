//! This file defines the user handler module, wherein we define connection handlers for
//! `Arc<Inner>`.

use std::{sync::Arc, time::Duration};

use proto::discovery::DiscoveryClient;
use proto::{
    connection::{
        auth::broker::BrokerAuth,
        protocols::{Protocol, Receiver},
    },
    crypto::signature::SignatureScheme,
    message::Message,
    UserProtocol,
};
use tracing::{error, info};

type Bytes = Arc<Vec<u8>>;

use crate::{metrics, mnemonic, Inner};

impl<BrokerScheme: SignatureScheme, UserScheme: SignatureScheme> Inner<BrokerScheme, UserScheme> {
    /// This function handles a user (public) connection.
    pub async fn handle_user_connection(
        self: Arc<Self>,
        connection: (
            <UserProtocol as Protocol>::Sender,
            <UserProtocol as Protocol>::Receiver,
        ),
    ) {
        // Verify (authenticate) the connection
        let Ok((public_key, topics)) = BrokerAuth::<UserScheme>::verify_user(
            &connection,
            &self.identity,
            &mut self.discovery_client.clone(),
        )
        .await
        else {
            return;
        };

        // Create a human-readable user identifier (by public key)
        let public_key = Bytes::from(public_key);
        let user_identifier = mnemonic!(public_key);
        info!("{user_identifier} connected");

        // Create new batch sender
        let (sender, receiver) = connection;

        // Add our user
        self.connections.add_user(public_key.clone(), sender).await;

        // Subscribe our user to their connections
        self.connections
            .subscribe_user_to(&public_key, topics)
            .await;

        // If we have `strong_consistency` enabled, send partials
        #[cfg(feature = "strong_consistency")]
        if let Err(err) = self.partial_topic_sync().await {
            error!("failed to perform partial topic sync: {err}");
        }

        #[cfg(feature = "strong_consistency")]
        if let Err(err) = self.partial_user_sync().await {
            error!("failed to perform partial user sync: {err}");
        }

        // We want to perform a heartbeat for every user connection so that the number
        // of users connected to brokers is always evenly distributed.
        #[cfg(feature = "strong_consistency")]
        let _ = self
            .discovery_client
            .clone()
            .perform_heartbeat(self.connections.num_users() as u64, Duration::from_secs(60))
            .await;

        // Increment our metric
        metrics::NUM_USERS_CONNECTED.inc();

        // This runs the main loop for receiving information from the user
        let () = self.user_receive_loop(&public_key, receiver).await;

        info!("{user_identifier} disconnected");

        // Decrement our metric
        metrics::NUM_USERS_CONNECTED.dec();

        // Once the main loop ends, we remove the connection
        self.connections.remove_user(public_key).await;
    }

    /// This is the main loop where we deal with user connectins. On exit, the calling function
    /// should remove the user from the map.
    pub async fn user_receive_loop(
        &self,
        public_key: &Bytes,
        receiver: <UserProtocol as Protocol>::Receiver,
    ) {
        while let Ok(message) = receiver.recv_message().await {
            match message {
                // If we get a direct message from a user, send it to both users and brokers.
                Message::Direct(ref direct) => {
                    let message = Bytes::from(message.serialize().expect("serialization failed"));
                    let user_public_key = Bytes::from(direct.recipient.clone());

                    self.connections
                        .send_direct(user_public_key, message, false)
                        .await;
                }

                // If we get a broadcast message from a user, send it to both brokers and users.
                Message::Broadcast(ref broadcast) => {
                    let message = Bytes::from(message.serialize().expect("serialization failed"));
                    let topics = broadcast.topics.clone();

                    self.connections
                        .send_broadcast(topics, message, false)
                        .await;
                }

                // Subscribe messages from users will just update the state locally
                Message::Subscribe(subscribe) => {
                    self.connections
                        .subscribe_user_to(public_key, subscribe)
                        .await;
                }

                // Unsubscribe messages from users will just update the state locally
                Message::Unsubscribe(unsubscribe) => {
                    self.connections
                        .unsubscribe_user_from(public_key, unsubscribe)
                        .await;
                }

                _ => return,
            }
        }
    }
}
