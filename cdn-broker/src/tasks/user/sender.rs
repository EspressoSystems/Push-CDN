use std::sync::Arc;

use cdn_proto::connection::protocols::Connection;
use cdn_proto::connection::UserPublicKey;
use cdn_proto::{connection::Bytes, def::RunDef};
use tokio::spawn;
use tokio::sync::Notify;
use tracing::error;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    pub fn try_send_to_user(self: &Arc<Self>, user: &UserPublicKey, message: Bytes) {
        // Get the optional connection
        let connection = self.connections.read().get_user_connection(user);

        // If the connection exists,
        if let Some(connection) = connection {
            // Clone what we need
            let self_ = self.clone();
            let user_ = user.clone();

            // Create a random handle identifier
            let handle_identifier = rand::random::<u128>();

            // To notify the sender when the task has been added
            let notify = Arc::new(Notify::const_new());
            let notified = notify.clone();

            // Send the message
            let send_handle = spawn(async move {
                if let Err(e) = connection.send_message_raw(message).await {
                    error!("failed to send message to user: {:?}", e);

                    // Remove the broker if we failed to send the message
                    self_
                        .connections
                        .write()
                        .remove_user(user_, "failed to send message");
                } else {
                    // Wait for the sender to add the task to the list
                    notified.notified().await;

                    // If we successfully sent the message, remove the task from the list
                    self_
                        .connections
                        .write()
                        .remove_user_task(&user_, handle_identifier);
                };
            })
            .abort_handle();

            // Add the send handle to the list of tasks for the broker
            self.connections
                .write()
                .add_user_task(user, handle_identifier, send_handle);

            // Notify the sender that the task has been added
            notify.notify_one();
        }
    }
}
