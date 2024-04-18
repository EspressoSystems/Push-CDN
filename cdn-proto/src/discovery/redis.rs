//! This crate deals with `Redis` client abstractions. In the push CDN model,
//! the users of `Redis` and their uses are:
//! 1. Marshals and brokers to agree on the number of connections per broker
//! 2. Marshals to store permits
//! 3. Brokers to verify permits
//! 4. Brokers for peer discovery

use std::{collections::HashSet, time::Duration};

use async_trait::async_trait;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use redis::aio::ConnectionManager;

use super::{BrokerIdentifier, DiscoveryClient};
use crate::{
    bail,
    connection::UserPublicKey,
    error::{Error, Result},
};

/// This struct is a light wrapper around a managed `Redis` connection which encpasulates
/// an operator identifier for common operations
#[derive(Clone)]
pub struct Redis {
    /// The underlying `Redis` connection. Is managed, so we don't have to worry about reconnections
    underlying_connection: ConnectionManager,
    /// Our operator identifier (in practice, will be something like a concat of advertise endpointes)
    identifier: BrokerIdentifier,
}

#[async_trait]
impl DiscoveryClient for Redis {
    /// Create a new `Client` from the `Redis` endpoint and optional identifier. This is clonable, and
    /// we don't have to worry about reconnections anywhere.
    ///
    /// # Errors
    /// - If we couldn't parse the `Redis` endpoint
    async fn new(path: String, identity: Option<BrokerIdentifier>) -> Result<Self> {
        // Parse the `Redis` URL, creating a `redis-rs` client from it.
        let client = bail!(
            redis::Client::open(path),
            Connection,
            "failed to parse `Redis` URL"
        );

        // Use the supplied identifier or a blank one, if we don't need/want one.
        // We only "need" the identifier if we want to register with Redis
        let identifier = identity.map_or_else(
            || BrokerIdentifier {
                public_advertise_endpoint: String::new(),
                private_advertise_endpoint: String::new(),
            },
            |identifier| identifier,
        );

        // Return the thinly wrapped `Self`.
        Ok(Self {
            underlying_connection: bail!(
                ConnectionManager::new(client).await,
                Connection,
                "failed to create Redis connection manager"
            ),
            identifier,
        })
    }

    /// (as a broker) perform the heartbeat operation. The heartbeat operation
    /// consists of the following in an atomic transaction:
    /// 1. Add to the list of brokers
    /// 2. Set the expiry for the broker set member
    /// 3. Set the number of connections
    ///
    /// # Errors
    /// - If the `Redis` connection fails
    async fn perform_heartbeat(
        &mut self,
        num_connections: u64,
        heartbeat_expiry: Duration,
    ) -> Result<()> {
        // Atomically execute the following commands
        bail!(
            redis::pipe()
                .atomic()
                // Add our identifier to the broker list (if not there already)
                .cmd("SADD")
                .arg(&["brokers", &self.identifier.to_string()])
                // Set our expiry
                .cmd("EXPIREMEMBER")
                .arg(&[
                    "brokers",
                    &self.identifier.to_string(),
                    &heartbeat_expiry.as_secs().to_string()
                ])
                // Set our number of connections
                .cmd("SET")
                .arg(&[
                    format!("{}/num_connections", self.identifier),
                    num_connections.to_string(),
                    "EX".to_string(),
                    heartbeat_expiry.as_secs().to_string()
                ])
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        );

        Ok(())
    }

    /// Get the broker with the least number of connections (and permits).
    /// We use this to figure out which broker gets our permit issued
    ///
    /// # Errors
    /// - If the `Redis` connection fails
    async fn get_with_least_connections(&mut self) -> Result<BrokerIdentifier> {
        // Get all registered brokers
        let brokers: HashSet<String> = bail!(
            redis::cmd("SMEMBERS")
                .arg("brokers")
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        );

        // Return if we have no connected brokers
        if brokers.is_empty() {
            return Err(Error::Connection("no brokers connected".to_string()));
        }

        // Get the broker with the least number of connections
        let (mut least_connections, mut broker_with_least_connections) = (u64::MAX, String::new());

        for broker in brokers {
            // Get the number of connections the broker has
            let num_connections: u64 = bail!(
                redis::cmd("GET")
                    .arg(&format!("{broker}/num_connections"))
                    .query_async(&mut self.underlying_connection)
                    .await,
                Connection,
                "failed to connect to Redis"
            );

            // Get the number of permits the broker has
            let num_permits: u64 = bail!(
                redis::cmd("SCARD")
                    .arg(&format!("{broker}/permits"))
                    .query_async(&mut self.underlying_connection)
                    .await,
                Connection,
                "failed to connect to Redis"
            );

            let total_broker_connections = num_permits + num_connections;
            if total_broker_connections < least_connections {
                least_connections = total_broker_connections;
                broker_with_least_connections = broker;
            }
        }

        // Return the broker with the least amount of connections, for which we
        // will issue a permit. Try to parse the broker endpoint from a `String`.
        broker_with_least_connections.try_into()
    }

    /// Get all other brokers, not including our own identifier (if applicable).
    ///
    /// # Errors
    /// - If the `Redis` connection fails
    async fn get_other_brokers(&mut self) -> Result<HashSet<BrokerIdentifier>> {
        // Get all registered brokers
        let mut brokers: HashSet<String> = bail!(
            redis::cmd("SMEMBERS")
                .arg("brokers")
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        );

        // Remove ourselves
        brokers.remove(&self.identifier.to_string());

        // Convert to broker identifiers
        let mut brokers_parsed = HashSet::new();
        for broker in brokers {
            brokers_parsed.insert(broker.try_into()?);
        }

        // Return all brokers (excluding ourselves)
        Ok(brokers_parsed)
    }

    /// Issue a permit for a particular broker. This is separate from `get_with_least_connections`
    /// because it allows for more modularity; and it isn't atomic anyway.
    ///
    /// # Errors
    /// - If the `Redis` connection fails
    async fn issue_permit(
        &mut self,
        #[cfg(not(feature = "global-permits"))] for_broker: &BrokerIdentifier,
        expiry: Duration,
        public_key: Vec<u8>,
    ) -> Result<u64> {
        // Create random permit number
        // TODO: figure out if it makes sense to initialize this somewhere else
        let permit = StdRng::from_entropy().next_u64();

        // Issue this permit for either one broker or all brokers (if we have
        // the `global-permits` feature enabled)
        let mut cmd = redis::cmd("SET");
        #[cfg(not(feature = "global-permits"))]
        // Per-broker permit
        cmd.arg(&[format!("{for_broker}/permits/{permit}")]);
        #[cfg(feature = "global-permits")]
        // Global permit
        cmd.arg(&[format!("permits/{permit}")]);

        // Issue the permit
        bail!(
            cmd.arg(public_key)
                .arg(&["EX", &expiry.as_secs().to_string()])
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        );

        // Return the permit
        Ok(permit)
    }

    /// Validate and remove a permit belonging to a particular broker.
    /// Returns `Some(validation_key)` if successful, and `None` if not.
    ///
    /// # Errors
    /// - If the `Redis` connection fails
    async fn validate_permit(
        &mut self,
        #[cfg(not(feature = "global-permits"))] for_broker: &BrokerIdentifier,
        permit: u64,
    ) -> Result<Option<Vec<u8>>> {
        // Remove this permit verifying it exists for either one broker or
        // all brokers (with the `global-permits` feature enabled)
        let mut cmd = redis::cmd("GETDEL");
        #[cfg(not(feature = "global-permits"))]
        cmd.arg(&[format!("{for_broker}/permits/{permit}")]);
        #[cfg(feature = "global-permits")]
        cmd.arg(&[format!("permits/{permit}")]);

        // Remove the permit
        Ok(bail!(
            cmd.query_async(&mut self.underlying_connection).await,
            Connection,
            "failed to connect to Redis"
        ))
    }

    /// Atomically set the list of whitelisted users
    ///
    /// # Errors
    /// - If the connection fails
    async fn set_whitelist(&mut self, users: Vec<UserPublicKey>) -> Result<()> {
        let mut pipeline = redis::pipe();

        pipeline
            .atomic()
            // Delete the current whitelist, if it exists
            .cmd("DEL")
            .arg(&["whitelist"]);

        for user in users {
            pipeline
                // Add the user
                .cmd("SADD")
                .arg("whitelist")
                .arg(user.as_ref());
        }

        bail!(
            pipeline.query_async(&mut self.underlying_connection).await,
            Connection,
            "failed to query whitelist"
        );

        Ok(())
    }

    // (As a marshal) check Redis for the whitelist status of the key.
    ///
    /// # Errors
    /// - If the connection fails
    async fn check_whitelist(&mut self, user: &UserPublicKey) -> Result<bool> {
        // If the set does not exist, return true. The whitelist is not yet initialized
        if !bail!(
            redis::cmd("SCARD")
                .arg("whitelist")
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        ) {
            return Ok(true);
        };

        // Check if the user is a member
        Ok(bail!(
            redis::cmd("SISMEMBER")
                .arg("whitelist")
                .arg(user.as_ref())
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        ))
    }
}
