use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use cdn_proto::database::DatabaseClient;
use parking_lot::RwLock;
use tracing::warn;

// Type aliases for readability
type NumMessages = u64;
type NumBytes = u64;
type MessageType = String;

/// A rate limiter that
#[derive(Clone)]
pub struct RateLimiter<D: DatabaseClient> {
    /// The database client. This is shared across all connections.
    database_client: D,

    /// The (shared) global average rate limits for each message type.
    pub global_average_rate_limits: Arc<RwLock<HashMap<MessageType, (NumMessages, NumBytes)>>>,

    /// The number of messages since we last hit the database to check the rate limit.
    messages_since_last_update: u64,
    last_update_time: Instant,

    /// The size of each message type since the last update.
    queued_messages: HashMap<MessageType, (NumMessages, NumBytes)>,
}

impl<D: DatabaseClient> RateLimiter<D> {
    /// Create a new rate limiter.
    pub fn new(database_client: D) -> Self {
        Self {
            database_client,
            messages_since_last_update: 0,
            last_update_time: Instant::now(),
            queued_messages: HashMap::new(),
            global_average_rate_limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// The result of a rate limit check.
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum RateLimitResult {
    /// The message should be allowed through
    Allowed,
    /// The message should be rate limited
    Denied,
}

impl<D: DatabaseClient> RateLimiter<D> {
    /// Check if a connection should be rate limited based on the message type and size.
    /// Only hits the database every so often so that we can save on requests.
    pub async fn should_allow_message(
        &mut self,
        ip_address: &IpAddr,
        message_type: &str,
        message_size: u64,
    ) -> RateLimitResult {
        // If it's not been 30 seconds or we've processed 30 messages
        if self.messages_since_last_update < 30
            || self.last_update_time.elapsed() < Duration::from_secs(30)
        {
            // Queue the message
            let _ = self
                .queued_messages
                .entry(message_type.to_string())
                .or_insert((0, 0))
                .0
                .saturating_add(1);
            let _ = self
                .queued_messages
                .entry(message_type.to_string())
                .or_insert((0, 0))
                .1
                .saturating_add(message_size);

            // Return that we're allowed
            return RateLimitResult::Allowed;
        }

        // Take all entries from the `HashMap`
        let messages = std::mem::take(&mut self.queued_messages);

        // Consume the messages
        let result = self
            .database_client
            .rate_limit_insert_data(
                messages,
                self.global_average_rate_limits.read().clone(),
                ip_address,
            )
            .await;

        // Warn if we failed to insert the data
        if let Err(err) = result {
            warn!("Failed to insert rate limit data: {err}");
        }

        RateLimitResult::Allowed
    }
}
