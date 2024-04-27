use std::{collections::HashSet, sync::Arc};

use cdn_proto::connection::protocols::Connection;
use cdn_proto::{
    connection::{Bytes, UserPublicKey},
    def::RunDef,
    discovery::BrokerIdentifier,
    message::Topic,
    mnemonic,
};
use tokio::spawn;
use tracing::{debug, warn};

use crate::Inner;

impl<R: RunDef> Inner<R> {
    /// Send a message to all currently connected brokers. On failure,
    /// the broker will be removed.
    pub fn send_to_brokers(self: &Arc<Self>, message: &Bytes) {
        // For each broker,
        for connection in &self.connections.read().brokers {
            // Clone things we will need downstream
            let message = message.clone();
            let broker_identifier = connection.0.clone();
            let connection = connection.1 .0.clone();
            let connections = self.connections.clone();

            // Spawn a task to send the message
            spawn(async move {
                if let Err(err) = connection.send_message_raw(message).await {
                    // If we fail, remove the broker from our map.
                    warn!("failed to send message to broker: {err}");
                    connections.write().remove_broker(&broker_identifier);
                };
            });
        }
    }

    /// Send a message to a particular broker. If it fails, remove the broker from our map.
    pub fn send_to_broker(self: &Arc<Self>, broker_identifier: &BrokerIdentifier, message: Bytes) {
        // If we are connected to them,
        let connections = self.connections.read();
        if let Some(connection) = connections.brokers.get(broker_identifier) {
            // Clone things we need
            let connection = connection.0.clone();
            let connections = self.connections.clone();
            let broker_identifier = broker_identifier.clone();

            // Spawn a task to send the message
            spawn(async move {
                if let Err(err) = connection.send_message_raw(message).await {
                    // Remove them if we failed to send it
                    warn!("failed to send message to broker: {err}");
                    connections.write().remove_broker(&broker_identifier);
                };
            });
        } else {
            // Remove the broker if they are not connected
            drop(connections);
            self.connections.write().remove_broker(broker_identifier);
        }
    }

    /// Send a message to a user connected to us.
    /// If it fails, the user is removed from our map.
    pub fn send_to_user(self: &Arc<Self>, user_public_key: UserPublicKey, message: Bytes) {
        // See if the user is connected
        let connections = self.connections.read();
        if let Some((connection, _)) = connections.users.get(&user_public_key) {
            // If they are, clone things we will need
            let connection = connection.clone();
            let connections = self.connections.clone();

            // Spawn a task to send the message
            spawn(async move {
                if let Err(err) = connection.send_message_raw(message).await {
                    // If we fail to send the message, remove the user.
                    warn!("failed to send message to user: {err}");
                    connections.write().remove_user(user_public_key);
                };
            });
        } else {
            // Remove the user if they are not connected
            drop(connections);
            self.connections.write().remove_user(user_public_key);
        }
    }

    /// Send a direct message to either a user or a broker. First figures out where the message
    /// is supposed to go, and then sends it. We have `to_user_only` bounds so we can stop thrashing;
    /// if we receive a message from a broker we should only be forwarding it to applicable users.
    pub fn send_direct(
        self: &Arc<Self>,
        user_public_key: UserPublicKey,
        message: Bytes,
        to_user_only: bool,
    ) {
        // Look up from our map
        if let Some(broker_identifier) = self.connections.read().direct_map.get(&user_public_key) {
            if *broker_identifier == self.connections.read().identity {
                // We own the user, send it this way
                debug!(
                    user = mnemonic(&user_public_key),
                    msg = mnemonic(&*message),
                    "direct",
                );
                self.send_to_user(user_public_key, message);
            } else {
                // If we don't have the stipulation to send it to ourselves only
                // This is so we don't thrash between brokers
                if !to_user_only {
                    debug!(
                        broker = %broker_identifier,
                        msg = mnemonic(&*message),
                        "direct",
                    );
                    // Send to the broker responsible
                    self.send_to_broker(broker_identifier, message);
                }
            }
        } else {
            // Debug warning if the recipient user did not exist.
            debug!(id = mnemonic(&user_public_key), "user did not exist in map");
        }
    }

    /// Send a broadcast message to both users and brokers. First figures out where the message
    /// is supposed to go, and then sends it. We have `to_user_only` bounds so we can stop thrashing;
    /// if we receive a message from a broker we should only be forwarding it to applicable users.
    pub fn send_broadcast(
        self: &Arc<Self>,
        mut topics: Vec<Topic>,
        message: &Bytes,
        to_users_only: bool,
    ) {
        // Deduplicate topics
        topics.dedup();

        // Aggregate recipients
        let mut broker_recipients = HashSet::new();
        let mut user_recipients = HashSet::new();

        for topic in topics {
            // If we can send to brokers, we should do it
            if !to_users_only {
                broker_recipients.extend(
                    self.connections
                        .read()
                        .broadcast_map
                        .brokers
                        .get_keys_by_value(&topic),
                );
            }
            user_recipients.extend(
                self.connections
                    .read()
                    .broadcast_map
                    .users
                    .get_keys_by_value(&topic),
            );
        }

        debug!(
            num_brokers = broker_recipients.len(),
            num_users = user_recipients.len(),
            msg = mnemonic(&**message),
            "broadcast",
        );

        // If we can send to brokers, do so
        if !to_users_only {
            // Send to all brokers
            for broker in broker_recipients {
                self.send_to_broker(&broker, message.clone());
            }
        }

        // Send to all aggregated users
        for user in user_recipients {
            self.send_to_user(user, message.clone());
        }
    }
}
