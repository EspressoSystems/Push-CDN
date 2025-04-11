// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

use cdn_broker::{Broker, Config as BrokerConfig};
use cdn_client::{Client, Config as ClientConfig};
use cdn_marshal::{Config as MarshalConfig, Marshal};
use cdn_proto::{
    connection::protocols::memory::Memory,
    crypto::signature::{KeyPair, Serializable, SignatureScheme},
    database::{embedded::Embedded, BrokerIdentifier, DatabaseClient},
    def::{TestingConnection, TestingRunDef},
    message::Topic,
};
use jf_signature::{bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS, SignatureScheme as _};
use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};
use tokio::spawn;

mod basic_connect;
mod double_connect;
mod subscribe;
mod whitelist;

/// Generate a keypair from a seed deterministically
fn keypair_from_seed(
    seed: u64,
) -> (
    <BLS as SignatureScheme>::PrivateKey,
    <BLS as SignatureScheme>::PublicKey,
) {
    // Generate the keypair
    BLS::key_gen(&(), &mut StdRng::seed_from_u64(seed)).expect("failed to generate key")
}

/// Generate a serialized public key from a seed deterministically
fn serialized_public_key_from_seed(seed: u64) -> Vec<u8> {
    // Generate and serialize a public key from the seed
    keypair_from_seed(seed)
        .1
        .serialize()
        .expect("failed to serialize public key")
}

/// Get a temporary path for a `SQLite` database
fn get_temp_db_path() -> String {
    // Get a temporary directory
    let temp_dir = std::env::temp_dir();

    // Generate a random path
    temp_dir
        .join(format!("test-{}.sqlite", StdRng::from_entropy().next_u64()))
        .to_string_lossy()
        .to_string()
}

/// Create a new broker for testing purposes that uses the memory network.
/// Parameters include the key (as a u64), the public endpoint,
/// and the private endpoint.
async fn new_broker(key: u64, public_ep: &str, private_ep: &str, database_ep: &str) {
    // Generate keypair
    let (private_key, public_key) = keypair_from_seed(key);

    // Create config
    let config: BrokerConfig<TestingRunDef<Memory, Memory>> = BrokerConfig {
        ca_cert_path: None,
        ca_key_path: None,
        database_endpoint: database_ep.to_string(),
        keypair: KeyPair {
            public_key,
            private_key,
        },
        metrics_bind_endpoint: None,
        private_advertise_endpoint: private_ep.to_string(),
        private_bind_endpoint: private_ep.to_string(),
        public_advertise_endpoint: public_ep.to_string(),
        public_bind_endpoint: public_ep.to_string(),
        global_memory_pool_size: None,
    };

    // Create broker
    let broker = Broker::<TestingRunDef<Memory, Memory>>::new(config)
        .await
        .expect("failed to create broker");

    // Spawn broker
    spawn(broker.start());
}

/// Create a new marshal for testing purposes that uses the memory network.
/// The only parameter is the endpoint (as a string) to bind to.
async fn new_marshal(ep: &str, database_ep: &str) {
    // Create the marshal's configuration
    let config = MarshalConfig {
        bind_endpoint: ep.to_string(),
        database_endpoint: database_ep.to_string(),
        metrics_bind_endpoint: None,
        ca_cert_path: None,
        ca_key_path: None,
        global_memory_pool_size: None,
    };

    // Create a new marshal
    let marshal = Marshal::<TestingRunDef<Memory, Memory>>::new(config)
        .await
        .expect("failed to create marshal");

    // Spawn the marshal
    spawn(marshal.start());
}

/// Create a new client, supplying it with the given topics and marshal
/// endpoint. `Key` is a deterministic, seeded keypair.
fn new_client(key: u64, topics: Vec<Topic>, marshal_ep: &str) -> Client<TestingConnection<Memory>> {
    // Generate keypair
    let (private_key, public_key) = keypair_from_seed(key);

    // Build the client's config
    let config = ClientConfig {
        endpoint: marshal_ep.to_string(),
        keypair: KeyPair {
            public_key,
            private_key,
        },
        subscribed_topics: topics,
        use_local_authority: true,
    };

    // Create the client
    Client::<TestingConnection<Memory>>::new(config)
}

/// Create a new database client with the given endpoint and identity.
async fn new_db_client(database_ep: &str, r#as: Option<BrokerIdentifier>) -> Embedded {
    // Create a new DB client
    Embedded::new(database_ep.to_string(), r#as)
        .await
        .expect("failed to initialize db client")
}
