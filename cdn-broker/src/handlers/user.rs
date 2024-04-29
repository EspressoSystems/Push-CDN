//! This file defines the user handler module, wherein we define connection handlers for
//! `Arc<Inner>`.

use std::sync::Arc;
use std::time::Duration;

use cdn_proto::connection::{protocols::Connection as _, UserPublicKey};
use cdn_proto::def::{Connection, RunDef};
#[cfg(feature = "strong-consistency")]
use cdn_proto::discovery::DiscoveryClient;
use cdn_proto::error::{Error, Result};
use cdn_proto::{connection::auth::broker::BrokerAuth, message::Message, mnemonic};
use tokio::spawn;
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{error, warn};

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    /// This function handles a user (public) connection.
    pub async fn handle_user_connection(self: Arc<Self>, connection: Connection<Def::User>) {
        // Verify (authenticate) the connection. Needs to happen within 5 seconds
        let Ok(Ok((public_key, topics))) = timeout(
            Duration::from_secs(5),
            BrokerAuth::<Def>::verify_user(
                &connection,
                #[cfg(not(feature = "global-permits"))]
                &self.identity,
                &mut self.discovery_client.clone(),
            ),
        )
        .await
        else {
            return;
        };

        // Create a human-readable user identifier (by public key)
        let public_key = UserPublicKey::from(public_key);
        let user_identifier = mnemonic(&public_key);

        // Create a notifier for the user receive loop to wait for
        let notify_initialized = Arc::new(Notify::new());
        let wait_initialized = notify_initialized.clone();

        // Clone the necessary data for the broker receive loop
        let self_ = self.clone();
        let public_key_ = public_key.clone();
        let connection_ = connection.clone();

        // Spawn the user receive loop
        let receive_handle = spawn(async move {
            // Wait for the handler to have finished initialization
            wait_initialized.notified().await;

            // If we error, come back to the callback so we can remove the connection from the list.
            if let Err(err) = self_.user_receive_loop(&public_key_, connection_).await {
                warn!(id = user_identifier, error = err.to_string(), "user error");

                // Remove the user from the map
                self_
                    .connections
                    .write()
                    .await
                    .remove_user(public_key_, "failed to receive message");
            };
        })
        .abort_handle();

        // Add our user and remove the old one if it exists
        self.connections
            .write()
            .await
            .add_user(&public_key, connection, &topics, receive_handle);

        // Notify the user receive loop that we are initialized
        notify_initialized.notify_one();

        // If we have `strong-consistency` enabled,
        #[cfg(feature = "strong-consistency")]
        {
            // Send partial topic data
            if let Err(err) = self.partial_topic_sync().await {
                error!("failed to perform partial topic sync: {err}");
            }

            // Send partial user data
            if let Err(err) = self.partial_user_sync().await {
                error!("failed to perform partial user sync: {err}");
            }

            // We want to perform a heartbeat for every user connection so that the number
            // of users connected to brokers is usually evenly distributed.
            let num_users = self.connections.read().await.num_users() as u64;
            let _ = self
                .discovery_client
                .clone()
                .perform_heartbeat(num_users, std::time::Duration::from_secs(60))
                .await;
        }
    }

    /// This is the main loop where we deal with user connectins. On exit, the calling function
    /// should remove the user from the map.
    pub async fn user_receive_loop(
        self: &Arc<Self>,
        public_key: &UserPublicKey,
        connection: Connection<Def::User>,
    ) -> Result<()> {
        loop {
            // Receive a message from the user
            let raw_message = connection.recv_message_raw().await?;

            // Attempt to deserialize the message
            let message = Message::deserialize(&raw_message)?;

            match message {
                // If we get a direct message from a user, send it to both users and brokers.
                Message::Direct(ref direct) => {
                    let user_public_key = UserPublicKey::from(direct.recipient.clone());

                    self.handle_direct_message(user_public_key, raw_message, false)
                        .await;
                }

                // If we get a broadcast message from a user, send it to both brokers and users.
                Message::Broadcast(ref broadcast) => {
                    let topics = broadcast.topics.clone();

                    self.handle_broadcast_message(topics, &raw_message, false)
                        .await;
                }

                // Subscribe messages from users will just update the state locally
                Message::Subscribe(subscribe) => {
                    // TODO: add handle functions for this to make it easier to read
                    self.connections
                        .write()
                        .await
                        .subscribe_user_to(public_key, subscribe);
                }

                // Unsubscribe messages from users will just update the state locally
                Message::Unsubscribe(unsubscribe) => {
                    self.connections
                        .write()
                        .await
                        .unsubscribe_user_from(public_key, &unsubscribe);
                }

                _ => return Err(Error::Connection("invalid message received".to_string())),
            }
        }
    }
}
