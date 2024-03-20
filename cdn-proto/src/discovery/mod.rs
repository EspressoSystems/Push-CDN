//! In this module we describe the `DiscoveryClient` trait. It defines a client that allows
//! us to derive a source of truth for the number of brokers, permits issued, and the
//! number of users connected per broker.

use std::result::Result as StdResult;
use std::{collections::HashSet, time::Duration};

use async_trait::async_trait;
use rkyv::{Archive, Deserialize, Serialize};

use crate::{
    connection::UserPublicKey,
    error::{Error, Result},
};

pub mod embedded;
pub mod redis;

#[async_trait]
// Defines a client that allows us to derive a source of truth for
// the number of brokers, permits issued, and the number of users connected per broker.
pub trait DiscoveryClient: Sized + Clone + Sync + Send + 'static {
    /// Create a new `DiscoveryClient` from the path to it (file or otherwise) and an optional
    /// identity that we store alongside our data, if appropriate.
    async fn new(path: String, identity: Option<BrokerIdentifier>) -> Result<Self>;

    /// (As a broker) perform a heartbeat. Publish our number of connections to the source of truth,
    /// which expires after `heartbeat_expiry`.
    async fn perform_heartbeat(
        &mut self,
        num_connections: u64,
        heartbeat_expiry: Duration,
    ) -> Result<()>;

    /// (As a marshal) get the broker with the least number of connections, for which we can issue a permit
    /// for.
    async fn get_with_least_connections(&mut self) -> Result<BrokerIdentifier>;

    /// (As a broker) get other registered brokers so we can connect to new ones.
    async fn get_other_brokers(&mut self) -> Result<HashSet<BrokerIdentifier>>;

    /// (As a marshal) issue a permit for a user to connect to a particular broker.
    async fn issue_permit(
        &mut self,
        for_broker: &BrokerIdentifier,
        expiry: Duration,
        public_key: Vec<u8>,
    ) -> Result<u64>;

    /// (As a broker) validate a permit as existing for a broker and remove it, returning
    /// the user's public key.
    async fn validate_permit(
        &mut self,
        broker: &BrokerIdentifier,
        permit: u64,
    ) -> Result<Option<Vec<u8>>>;

    /// (As a marshal)
    ///
    /// # Errors
    /// - If the connection fails
    async fn set_whitelist(&mut self, users: Vec<UserPublicKey>) -> Result<()>;

    /// (As a marshal) check Redis for the whitelist status of the key.
    ///
    /// # Errors
    /// - If the connection fails
    async fn check_whitelist(&mut self, user: &UserPublicKey) -> Result<bool>;
}

/// Used as a unique identifier for a broker. Defines both public and private addresses.
/// We need this to be ordered so we can use primitives like versioned vectors over it.
#[derive(Eq, PartialEq, Hash, Clone, Debug, PartialOrd, Ord, Serialize, Deserialize, Archive)]
#[archive(check_bytes)]
pub struct BrokerIdentifier {
    /// The address that a broker advertises to publicly (to users)
    pub public_advertise_address: String,
    /// The address that a broker advertises to privately (to other brokers)
    pub private_advertise_address: String,
}

/// We need this to convert in the opposite direction: to create a `String`
/// from a `BrokerIdentifier`.
impl std::fmt::Display for BrokerIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}/{}",
            self.public_advertise_address, self.private_advertise_address
        )
    }
}

/// We need this to be able to convert a `String` to a broker identifier.
/// Allows us to be consistent about what we store.
impl TryFrom<String> for BrokerIdentifier {
    type Error = Error;
    fn try_from(value: String) -> StdResult<Self, Self::Error> {
        // Split the string
        let mut split = value.split('/');

        // Create a new `Self` from the split string
        Ok(Self {
            public_advertise_address: split
                .next()
                .ok_or_else(|| {
                    Error::Parse("failed to parse public advertise address from string".to_string())
                })?
                .to_string(),
            private_advertise_address: split
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
