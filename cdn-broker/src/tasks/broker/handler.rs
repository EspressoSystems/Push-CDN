// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! This file defines the broker connection handler.

use std::{sync::Arc, time::Duration};

use cdn_proto::{
    authenticate_with_broker, bail,
    connection::{auth::broker::BrokerAuth, protocols::Connection, Bytes, UserPublicKey},
    def::{MessageHookDef, RunDef},
    discovery::BrokerIdentifier,
    error::{Error, Result},
    message::{Message, Topic},
    util::mnemonic,
    verify_broker,
};
use tokio::{spawn, time::timeout};
use tracing::{debug, error};

use crate::{
    connections::{DirectMap, TopicSyncMap},
    Inner,
};

impl<Def: RunDef> Inner<Def> {
    /// This function is the callback for handling a broker (private) connection.
    pub async fn handle_broker_connection(
        self: Arc<Self>,
        mut connection: Connection,
        is_outbound: bool,
    ) {
        // Depending on which way the direction came in, we will want to authenticate with a different
        // flow.

        // Give us 5 seconds to authenticate with the broker
        let broker_identifier = match timeout(Duration::from_secs(5), async {
            if is_outbound {
                // If we reached out to the other broker first, authenticate first.
                let broker_endpoint = authenticate_with_broker!(connection, self);
                verify_broker!(connection, self);
                broker_endpoint
            } else {
                // If the other broker reached out to us first, authenticate second.
                verify_broker!(connection, self);
                authenticate_with_broker!(connection, self)
            }
        })
        .await
        {
            Ok(Ok(broker_identifier)) => broker_identifier,
            Ok(Err(e)) => {
                error!("failed to authenticate with broker: {:?}", e);
                return;
            }
            _ => {
                error!("timed out while authenticating with broker");
                return;
            }
        };

        // Clone things we will need
        let self_ = self.clone();
        let connection_ = connection.clone();
        let broker_identifier_ = broker_identifier.clone();

        // Start the receiving end of the broker
        let receive_handle = spawn(async move {
            // If we error, come back to the callback so we can remove the connection from the list.
            if let Err(err) = self_
                .broker_receive_loop(&broker_identifier_, connection_)
                .await
            {
                error!(
                    id = %broker_identifier_,
                    error = err.to_string(),
                    "broker error"
                );

                // Remove the broker from the map
                self_
                    .connections
                    .write()
                    .remove_broker(&broker_identifier_, "failed to receive message");
            };
        })
        .abort_handle();

        // Add to our list of connections, removing the old one if it exists
        self.connections
            .write()
            .add_broker(broker_identifier.clone(), connection, receive_handle);

        // Send a full topic sync
        if let Err(err) = self.full_topic_sync(&broker_identifier).await {
            error!("failed to perform full topic sync: {err}");

            // Remove the broker if we fail the initial sync
            self.connections
                .write()
                .remove_broker(&broker_identifier, "failed to send full topic sync");

            return;
        };

        // Send a full user sync
        if let Err(err) = self.full_user_sync(&broker_identifier).await {
            error!("failed to perform full user sync: {err}");

            // Remove the broker if we fail the initial sync
            self.connections
                .write()
                .remove_broker(&broker_identifier, "failed to send full user sync");
        };
    }

    /// This is the default loop for handling broker connections
    pub async fn broker_receive_loop(
        self: &Arc<Self>,
        broker_identifier: &BrokerIdentifier,
        connection: Connection,
    ) -> Result<()> {
        // Clone the hook
        let local_message_hook = self.broker_message_hook.clone();

        loop {
            // Receive a message from the broker
            let raw_message = connection.recv_message_raw().await?;

            // Attempt to deserialize the message
            let message = Message::deserialize(&raw_message)?;

            // Call the hook for the broker
            bail!(
                local_message_hook.on_message_received(&message),
                Connection,
                "message hook returned error"
            );

            match message {
                // If we receive a direct message from a broker, we want to send it to the user with that key
                Message::Direct(ref direct) => {
                    let user_public_key = UserPublicKey::from(direct.recipient.clone());

                    self.handle_direct_message(&user_public_key, raw_message, true)
                        .await;
                }

                // If we receive a broadcast message from a broker, we want to send it to all interested users
                Message::Broadcast(ref broadcast) => {
                    let topics = broadcast.topics.clone();

                    self.handle_broadcast_message(&topics, &raw_message, true)
                        .await;
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

                // If we receive a `TopicSync` message, we want to sync with our version of their map
                Message::TopicSync(topic_sync) => {
                    // Deserialize via `rkyv`
                    let topic_sync: TopicSyncMap = bail!(
                        rkyv::from_bytes(&topic_sync),
                        Deserialize,
                        "failed to deserialize topic sync message"
                    );

                    // Apply the topic sync
                    self.connections
                        .write()
                        .apply_topic_sync(broker_identifier, topic_sync);
                }

                // Do nothing if we receive an unexpected message
                _ => {}
            }
        }
    }

    /// This function handles direct messages from users and brokers.
    pub async fn handle_direct_message(
        self: &Arc<Self>,
        user_public_key: &UserPublicKey,
        message: Bytes,
        to_user_only: bool,
    ) {
        // Get the corresponding broker for the user
        let broker_identifier = self
            .connections
            .read()
            .get_broker_identifier_of_user(user_public_key);

        // If the broker exists,
        if let Some(broker_identifier) = broker_identifier {
            // If the broker is us, send the message to the user
            if broker_identifier == self.identity {
                debug!(
                    user = mnemonic(user_public_key),
                    msg = mnemonic(&*message),
                    msg_size = message.len(),
                    "direct",
                );

                // Send the message to the user
                self.try_send_to_user(user_public_key, message).await;
            } else {
                // Otherwise, send the message to the broker (but only if we are not told to send to the user only)
                if !to_user_only {
                    debug!(
                        broker = %broker_identifier,
                        msg = mnemonic(&*message),
                        msg_size = message.len(),
                        "direct",
                    );

                    // Send the message to the broker
                    self.try_send_to_broker(&broker_identifier, message).await;
                }
            }
        }
    }

    /// This function handles broadcast messages from users and brokers.
    pub async fn handle_broadcast_message(
        self: &Arc<Self>,
        topics: &[Topic],
        message: &Bytes,
        to_users_only: bool,
    ) {
        // Get the list of actors interested in the topics
        let (interested_brokers, interested_users) = self
            .connections
            .read()
            .get_interested_by_topic(&topics.to_vec(), to_users_only);

        // Debug log the broadcast
        debug!(
            num_brokers = interested_brokers.len(),
            num_users = interested_users.len(),
            msg = mnemonic(&**message),
            msg_size = message.len(),
            "broadcast",
        );

        // Send the message to all interested brokers
        for broker_identifier in interested_brokers {
            self.try_send_to_broker(&broker_identifier, message.clone())
                .await;
        }

        // Send the message to all interested users
        for user_public_key in interested_users {
            self.try_send_to_user(&user_public_key, message.clone())
                .await;
        }
    }
}
