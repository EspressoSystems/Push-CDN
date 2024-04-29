//! This is where we define routing for broadcast messages.

mod relational_map;

use std::{collections::HashSet, sync::Arc};

use cdn_proto::{
    connection::{Bytes, UserPublicKey},
    def::RunDef,
    discovery::BrokerIdentifier,
    message::Topic,
    mnemonic,
};
use tokio::spawn;
use tracing::debug;

use crate::Inner;

use self::relational_map::RelationalMap;

/// Our broadcast map is just two associative (bidirectional, multi) maps:
/// one for brokers and one for users.
pub struct BroadcastMap {
    pub users: RelationalMap<UserPublicKey, Topic>,
    pub brokers: RelationalMap<BrokerIdentifier, Topic>,

    pub previous_subscribed_topics: HashSet<Topic>,
}

/// Default for our map just wraps the items with locks.
impl Default for BroadcastMap {
    fn default() -> Self {
        Self {
            users: RelationalMap::new(),
            brokers: RelationalMap::new(),
            previous_subscribed_topics: HashSet::new(),
        }
    }
}

/// The new implementation just uses default
impl BroadcastMap {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<Def: RunDef> Inner<Def> {
    /// Send a broadcast message to both users and brokers. First figures out where the message
    /// is supposed to go, and then sends it. We have `to_user_only` bounds so we can stop thrashing;
    /// if we receive a message from a broker we should only be forwarding it to applicable users.
    pub async fn handle_broadcast_message(
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
                        .await
                        .broadcast_map
                        .brokers
                        .get_keys_by_value(&topic),
                );
            }
            user_recipients.extend(
                self.connections
                    .read()
                    .await
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
                let self_ = self.clone();
                let broker_ = broker.clone();
                let message_ = message.clone();
                spawn(async move {
                    let _ = self_.send_to_broker(&broker_, message_).await;
                });
            }
        }

        // Send to all aggregated users
        for user in user_recipients {
            // Send to the corresponding user
            let self_ = self.clone();
            let message_ = message.clone();
            spawn(async move {
                let _ = self_.send_to_user(user, message_).await;
            });
        }
    }
}
