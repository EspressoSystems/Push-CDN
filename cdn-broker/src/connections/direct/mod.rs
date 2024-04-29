//! This is where we define routing for direct messages.

mod versioned_map;

use std::sync::Arc;

use cdn_proto::{
    connection::{Bytes, UserPublicKey},
    def::RunDef,
    discovery::BrokerIdentifier,
    mnemonic,
};
use tokio::spawn;
use tracing::{debug, warn};

use crate::Inner;

use self::versioned_map::VersionedMap;

/// We define the direct map as just a type alias of a `VersionedMap`, which
// deals with version vectors.
pub type DirectMap = VersionedMap<UserPublicKey, BrokerIdentifier, BrokerIdentifier>;

impl<Def: RunDef> Inner<Def> {
    /// Send a direct message to either a user or a broker. First figures out where the message
    /// is supposed to go, and then sends it. We have `to_user_only` bounds so we can stop thrashing;
    /// if we receive a message from a broker we should only be forwarding it to applicable users.
    pub async fn handle_direct_message(
        self: &Arc<Self>,
        user_public_key: UserPublicKey,
        message: Bytes,
        to_user_only: bool,
    ) {
        // Look up from our map
        if let Some(broker_identifier) = self
            .connections
            .read()
            .await
            .direct_map
            .get(&user_public_key)
        {
            if *broker_identifier == self.connections.read().await.identity {
                // We own the user, send it this way
                debug!(
                    user = mnemonic(&user_public_key),
                    msg = mnemonic(&*message),
                    "direct",
                );

                // Send to the corresponding user
                let self_ = self.clone();
                spawn(async move {
                    let _ = self_.send_to_user(user_public_key, message).await;
                });
            } else {
                // If we don't have the stipulation to send it to ourselves only
                // This is so we don't thrash between brokers
                if !to_user_only {
                    debug!(
                        broker = %broker_identifier,
                        msg = mnemonic(&*message),
                        "direct",
                    );

                    // Asynchronously send to the broker responsible
                    let self_ = self.clone();
                    let broker_identifier_ = broker_identifier.clone();
                    spawn(async move {
                        let _ = self_.send_to_broker(&broker_identifier_, message).await;
                    });
                }
            }
        } else {
            // Warning if the recipient user did not exist.
            // TODO: Add sync in here to prevent forking. This is likely a problem.
            warn!(id = mnemonic(&user_public_key), "user did not exist in map");
        }
    }
}
