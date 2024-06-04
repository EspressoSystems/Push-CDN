use std::sync::Arc;

use cdn_proto::connection::UserPublicKey;
use cdn_proto::{connection::Bytes, def::RunDef};
use tracing::error;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    pub async fn try_send_to_user(self: &Arc<Self>, user: &UserPublicKey, message: Bytes) {
        // Get the optional connection
        let connection = self.connections.read().get_user_connection(user);

        // If the connection exists,
        if let Some(connection) = connection {
            // Send the message
            if let Err(e) = connection.send_message_raw(message).await {
                error!("failed to send message to user: {:?}", e);

                // Remove the broker if we failed to send the message
                self.connections
                    .write()
                    .remove_user(user.clone(), "failed to send message");
            }
        }
    }
}
