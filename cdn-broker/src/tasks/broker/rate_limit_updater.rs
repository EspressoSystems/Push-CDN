// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! The sync task syncs both users and topics to other brokers.

use std::collections::HashMap;
use std::{sync::Arc, time::Duration};

use cdn_proto::database::DatabaseClient;

use cdn_proto::def::RunDef;
use tokio::time::sleep;
use tracing::warn;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    /// Run the rate limit updater task. This is responsible for updating the rate limiter with
    /// the average number of messages and bytes consumed by each user.
    pub async fn run_rate_limit_updater_task(self: Arc<Self>) {
        // Clone the database client
        let mut database_client = self.database_client.clone();

        // Run this forever
        loop {
            // Get the global average number of messages and bytes consumed for each message type.
            // Default to an empty map if we fail to get the data, which downstream will just
            // allow almost all messages through.
            let global_average_consumed = database_client
                .rate_limit_get_global_averages()
                .await
                .unwrap_or_else(|err| {
                    warn!("Failed to get global average rate limits: {err:#}");
                    HashMap::new()
                });

            // Allow 2 * the global average consumed through for each node
            let global_average_consumed = global_average_consumed
                .into_iter()
                .map(|(message_type, (num_messages, num_bytes))| {
                    (
                        message_type,
                        (num_messages.saturating_mul(2), num_bytes.saturating_mul(2)),
                    )
                })
                .collect();

            // Update the global average rate limits
            *self.rate_limiter.global_average_rate_limits.write() = global_average_consumed;

            // Sleep for 60 seconds
            sleep(Duration::from_secs(60)).await;
        }
    }
}
