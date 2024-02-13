use std::{collections::HashSet, ops::Add, time::Duration};

use async_trait::async_trait;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sqlx::{query, query_as, types::time::OffsetDateTime, Row, SqlitePool};

use crate::{
    bail,
    error::{Error, Result},
};

use super::{BrokerIdentifier, DiscoveryClient};

#[derive(Clone)]
pub struct Embedded {
    pool: SqlitePool,
    identifier: BrokerIdentifier,
}

#[derive(sqlx::FromRow)]
struct BrokerRow {
    identifier: String,
    num_connections: i64,
    #[allow(unused)]
    expiry: OffsetDateTime,
}

#[async_trait]
impl DiscoveryClient for Embedded {
    /// Create a new `Client` from the `SQLite` path and optional identifier. This is clonable, and
    /// we don't have to worry about reconnections anywhere.
    ///
    /// # Errors
    /// - If we failed to connect to the `SqlitePool`
    async fn new(path: String, identity: Option<BrokerIdentifier>) -> Result<Self> {
        // Use the supplied identifier or a blank one, if we don't need/want one.
        // We only "need" the identifier if we want to register
        let identifier = identity.map_or_else(
            || BrokerIdentifier {
                user_advertise_address: String::new(),
                broker_advertise_address: String::new(),
            },
            |identifier| identifier,
        );

        // Open a test connection to the DB
        let pool = bail!(
            SqlitePool::connect(&path).await,
            File,
            "failed to open sqlite db"
        );

        // Return the thinly wrapped `Self`.
        Ok(Self { pool, identifier })
    }

    /// (as a broker) perform the heartbeat operation. The heartbeat operation
    /// consists of the following:
    /// 1. Add to the list of brokers
    /// 2. Set the expiry for the broker set member
    /// 3. Set the number of connections
    ///
    /// # Errors
    /// - If the `SQLite` connection fails
    async fn perform_heartbeat(
        &mut self,
        num_connections: u64,
        heartbeat_expiry: Duration,
    ) -> Result<()> {
        // Get the current time, add the expiry to it
        let expiry = OffsetDateTime::now_utc().add(heartbeat_expiry);

        // Do some type conversions
        let identifier = self.identifier.to_string();
        let num_connections = bail!(
            u32::try_from(num_connections),
            Parse,
            "failed to parse number of connections"
        );

        // Store us as a broker with the number of connections
        bail!(
            query(
                "INSERT or REPLACE INTO brokers (identifier, num_connections, expiry) VALUES (?, ?, ?)",
            ).bind(identifier).bind(num_connections).bind(expiry).execute(&self.pool).await,
            File,
            "failed to insert self into brokers table"
        );

        Ok(())
    }
    
    /// Get the broker with the least number of connections (and permits).
    /// We use this to figure out which broker gets our permit issued
    ///
    /// # Errors
    /// - If the `SQLite` connection fails
    async fn get_with_least_connections(&mut self) -> Result<BrokerIdentifier> {
        // Get all brokers
        let brokers: Vec<BrokerRow> = bail!(
            query_as("SELECT * from brokers")
                .fetch_all(&self.pool)
                .await,
            File,
            "failed to fetch broker list"
        );

        // Our tracker for the "least connected" broker
        let (mut least_connections, mut broker_with_least_connections) =
            (u64::MAX, "meowtown".to_string());

        // Iterate over every broker
        for broker in brokers {
            // Delete old permits
            bail!(
                query("DELETE FROM permits WHERE expiry < datetime()")
                    .execute(&self.pool)
                    .await,
                File,
                "failed to delete old permits"
            );

            // Get the number of permits
            let num_permits: u64 = u64::from(
                bail!(
                    query("SELECT COUNT(permit) as count FROM permits WHERE identifier = ?;")
                        .bind(&broker.identifier)
                        .fetch_one(&self.pool)
                        .await,
                    File,
                    "failed to get permit table"
                )
                .get::<u32, usize>(0),
            );

            let total_broker_connections = num_permits + broker.num_connections as u64;
            if total_broker_connections < least_connections {
                least_connections = total_broker_connections;
                broker_with_least_connections = broker.identifier;
            }
        }

        broker_with_least_connections.try_into()
    }

    /// Get all other brokers, not including our own identifier (if applicable). This is so we
    /// can connect to them if not already.
    ///
    /// # Errors
    /// - If the `SQLite` connection fails
    async fn get_other_brokers(&mut self) -> Result<HashSet<BrokerIdentifier>> {
        // Delete old brokers
        bail!(
            query("DELETE FROM brokers WHERE expiry < datetime()")
                .execute(&self.pool)
                .await,
            File,
            "failed to delete old brokers"
        );

        // Get all other brokers
        let brokers: Vec<BrokerRow> = bail!(
            query_as::<_, BrokerRow>("SELECT * from brokers")
                .fetch_all(&self.pool)
                .await,
            File,
            "failed to get other brokers"
        );

        // Convert to broker identifiers
        let mut brokers_parsed = HashSet::new();
        for broker in brokers {
            brokers_parsed.insert(broker.identifier.try_into().unwrap());
        }

        // Remove ourselves
        brokers_parsed.remove(&self.identifier);

        // Return all brokers (excluding ourselves)
        Ok(brokers_parsed)
    }


    /// Issue a permit for a particular broker. This is separate from `get_with_least_connections`
    /// because it allows for more modularity; and it isn't atomic anyway.
    ///
    /// # Errors
    /// - If the `SQLite` connection fails
    async fn issue_permit(
        &mut self,
        for_broker: &BrokerIdentifier,
        expiry: Duration,
        verification_key: Vec<u8>,
    ) -> Result<u64> {
        // Create random permit number
        // TODO: figure out if it makes sense to initialize this somewhere else
        let permit = StdRng::from_entropy().next_u32();

        let broker = for_broker.to_string();

        // Calculate record expiry
        let expiry = OffsetDateTime::now_utc().add(expiry);

        // Insert into permits
        bail!(
            query(
                "INSERT INTO permits (identifier, permit, user_pubkey, expiry) VALUES (?1, ?2, ?3, ?4)",
            ).bind(&broker).bind(permit).bind(verification_key).bind(expiry)
            .execute(&self.pool)
            .await,
            File,
            "failed to issue permit"
        );

        Ok(permit as u64)
    }

    /// Validate and remove a permit belonging to a particular broker.
    /// Returns `Some(validation_key)` if successful, and `None` if not.
    ///
    /// # Errors
    /// - If the `SQLite` connection fails
    async fn validate_permit(
        &mut self,
        broker: &BrokerIdentifier,
        permit: u64,
    ) -> Result<Option<Vec<u8>>> {
        // Delete old permits
        bail!(
            query("DELETE FROM permits WHERE expiry < datetime()")
                .execute(&self.pool)
                .await,
            File,
            "failed to get old permits"
        );

        // Do some type conversions
        let permit = bail!(
            u32::try_from(permit),
            Parse,
            "failed to parse permit as u32"
        );
        let broker = broker.to_string();

        // Get possible permit
        let res = bail!(
            query("DELETE FROM permits WHERE permit=(?1) AND identifier=(?2) RETURNING *;",)
                .bind(permit)
                .bind(broker)
                .fetch_optional(&self.pool)
                .await,
            File,
            "failed to get permits"
        );

        Ok(res.map(|row| row.get("user_pubkey")))
    }
}
