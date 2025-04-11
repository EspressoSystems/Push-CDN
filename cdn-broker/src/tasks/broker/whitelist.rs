// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! The sync task syncs both users and topics to other brokers.

use std::{sync::Arc, time::Duration};

use cdn_proto::{database::DatabaseClient, def::RunDef};
use tokio::time::sleep;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    /// Run the whitelist task. This is responsible for checking if users are still whitelisted
    /// and kicking them off the network if they are not.
    pub async fn run_whitelist_task(self: Arc<Self>) {
        // Clone the database client because it's behind an `Arc`
        let mut database_client = self.database_client.clone();

        loop {
            // Run every minute
            sleep(Duration::from_secs(60)).await;

            // Get a list of all users
            let users = self.connections.read().all_users();

            // Make sure each user is still whitelisted
            for user in users {
                if !database_client.check_whitelist(&user).await.unwrap_or(true) {
                    // Kick the user off the network if they are not
                    self.connections
                        .write()
                        .remove_user(user, "not in whitelist");
                }
            }
        }
    }
}
