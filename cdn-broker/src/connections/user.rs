use std::sync::Arc;

use cdn_proto::{
    connection::{protocols::Connection, Bytes, UserPublicKey},
    def::RunDef,
    error::{Error, Result},
};
use tracing::warn;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    /// Send a message to a user connected to us.
    /// If it fails, the user is removed from our map and an error is returned
    /// TODO: function this?
    pub async fn send_to_user(
        self: &Arc<Self>,
        user_public_key: UserPublicKey,
        message: Bytes,
    ) -> Result<()> {
        // Acquire the read guard for connections
        let connections_read_guard = self.connections.read().await;
        // See if the user is connected
        if let Some((connection, _)) = connections_read_guard.users.get(&user_public_key) {
            // If they are, clone things we will need
            let connection = connection.clone();
            let connections = self.connections.clone();

            // Send the message
            if let Err(err) = connection.send_message_raw(message).await {
                // Drop the read guard
                drop(connections_read_guard);

                // If we fail to send the message, remove the user.
                warn!("failed to send message to user: {err}");
                connections
                    .write()
                    .await
                    .remove_user(user_public_key, "failed to send message");

                // Return an error
                return Err(Error::Connection(
                    "failed to send message to broker".to_string(),
                ));
            };
        } else {
            // Drop the read guard
            drop(connections_read_guard);

            // Remove the user if they are not connected
            self.connections
                .write()
                .await
                .remove_user(user_public_key, "not connected");

            // Return an error
            return Err(Error::Connection(
                "failed to send message to user".to_string(),
            ));
        }

        Ok(())
    }
}
