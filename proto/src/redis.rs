//! This crate deals with `Redis` client abstractions. In the push CDN model,
//! the users of `Redis` and their uses are:
//! 1. Marshals and brokers to agree on the number of connections per broker
//! 2. Marshals to store permits
//! 3. Brokers to verify permits
//! 4. Brokers for peer discovery

use std::{collections::HashSet, time::Duration};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use redis::aio::ConnectionManager;
use std::result::Result as StdResult;

use crate::{
    bail,
    error::{Error, Result},
};

/// This struct is a light wrapper around a managed `Redis` connection which encpasulates
/// an operator identifier for common operations
#[derive(Clone)]
pub struct Client {
    /// The underlying `Redis` connection. Is managed, so we don't have to worry about reconnections
    underlying_connection: ConnectionManager,
    /// Our operator identifier (in practice, will be something like a concat of advertise addresses)
    identifier: BrokerIdentifier,
}

impl Client {
    /// Create a new `Client` from the `Redis` endpoint and optional identifier. This is clonable, and
    /// we don't have to worry about reconnections anywhere.
    ///
    /// # Errors
    /// - If we couldn't parse the `Redis` endpoint
    pub async fn new(endpoint: String, identifier: Option<BrokerIdentifier>) -> Result<Self> {
        // Parse the `Redis` URL, creating a `redis-rs` client from it.
        let client = bail!(
            redis::Client::open(endpoint),
            Connection,
            "failed to parse `Redis` URL"
        );

        // Use the supplied identifier or a blank one, if we don't need/want one.
        // We only "need" the identifier if we want to register with Redis
        let identifier = identifier.map_or_else(
            || BrokerIdentifier {
                user_advertise_address: String::new(),
                broker_advertise_address: String::new(),
            },
            |identifier| identifier
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
    pub async fn perform_heartbeat(
        &mut self,
        num_connections: u64,
        heartbeat_expiry: Duration,
    ) -> Result<()> {
        // Set up atomic transaction
        // TODO: macro this bail to something like bail_redis
        bail!(
            redis::cmd("MULTI")
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        );

        // Add our identifier to the broker list (if not there already)
        bail!(
            redis::cmd("SADD")
                .arg(&["brokers", &self.identifier.to_string()])
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        );

        // Set our expiry
        bail!(
            redis::cmd("EXPIREMEMBER")
                .arg(&[
                    "brokers",
                    &self.identifier.to_string(),
                    &heartbeat_expiry.as_secs().to_string()
                ])
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        );

        // Set our number connections
        bail!(
            redis::cmd("SET")
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

        // Atomically execute all transactions
        bail!(
            redis::cmd("EXEC")
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
    /// TODO: document that this MIGHT cause a race condition where multiple locks
    /// are acquired when brokers are close in `num_connected`. But probably not,
    /// and probably not to where it matters.
    ///
    /// # Errors
    /// - If the `Redis` connection fails
    pub async fn get_with_least_connections(&mut self) -> Result<BrokerIdentifier> {
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
        let (mut least_connections, mut broker_with_least_connections) =
            (u64::MAX, "meowtown".to_string());

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
        // will issue a permit. Try to parse the broker address from a `String`.
        broker_with_least_connections.try_into()
    }

    /// Get all other brokers, not including our own identifier (if applicable).
    ///
    /// # Errors
    /// - If the `Redis` connection fails
    pub async fn get_other_brokers(&mut self) -> Result<Vec<BrokerIdentifier>> {
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
        let mut brokers_parsed = Vec::new();
        for broker in brokers {
            brokers_parsed.push(broker.try_into()?);
        }

        // Return all brokers (excluding ourselves)
        Ok(brokers_parsed)
    }

    /// Issue a permit for a particular broker. This is separate from `get_with_least_connections`
    /// because it allows for more modularity; and it isn't atomic anyway.
    ///
    /// # Errors
    /// - If the `Redis` connection fails
    pub async fn issue_permit(&mut self, broker: &BrokerIdentifier) -> Result<u64> {
        // Create random permit number
        // TODO: figure out if it makes sense to initialize this somewhere else
        let permit = StdRng::from_entropy().next_u64();

        // Issue the permit
        bail!(
            redis::cmd("SADD")
                .arg(&[format!("{broker}/permits"), permit.to_string()])
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        );

        // Return the permit
        Ok(permit)
    }

    /// Validate and remove a permit belonging to a particular broker.
    /// Returns `true` if validation was successful, and `false` if not.
    ///
    /// # Errors
    /// - If the `Redis` connection fails
    pub async fn validate_permit(
        &mut self,
        broker: &BrokerIdentifier,
        permit: u64,
    ) -> Result<bool> {
        // Remove the permit
        match bail!(
            redis::cmd("SREM")
                .arg(&[format!("{broker}/permits"), permit.to_string()])
                .query_async(&mut self.underlying_connection)
                .await,
            Connection,
            "failed to connect to Redis"
        ) {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Parse("unexpected Redis response".to_string())),
        }
    }
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct BrokerIdentifier {
    /// The address that a broker advertises to publicly (to users)
    pub user_advertise_address: String,
    /// The address that a broker advertises to privately (to other brokers)
    pub broker_advertise_address: String,
}

/// We need this to be able to convert a `String` to a broker identifier.
/// Allows us to be consistent about what we store in Redis.
impl TryFrom<String> for BrokerIdentifier {
    type Error = Error;
    fn try_from(value: String) -> StdResult<Self, Self::Error> {
        // Split the string
        let mut split = value.split('/');

        // Create a new `Self` from the split string
        Ok(Self {
            user_advertise_address: split
                .next()
                .ok_or_else(|| {
                    Error::Parse("failed to parse public advertise address from string".to_string())
                })?
                .to_string(),
            broker_advertise_address: split
                .next()
                .ok_or_else(|| {
                    Error::Parse(
                        "failed to parse private advertise address from string".to_string(),
                    )
                })?
                .to_string(),
        })
    }
}

/// We need this to convert in the opposite direction: to create a `String`
/// from a `BrokerIdentifier` for `Redis` purposes.
impl std::fmt::Display for BrokerIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}/{}",
            self.user_advertise_address, self.broker_advertise_address
        )
    }
}
