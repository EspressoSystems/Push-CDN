//! Compile-time run configuration for all CDN components.

use jf_signature::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::connection::middleware::{
    Middleware as MiddlewareType, NoMiddleware, TrustedMiddleware, UntrustedMiddleware,
};
use crate::connection::protocols::memory::Memory;
use crate::connection::protocols::{quic::Quic, tcp::Tcp, Protocol as ProtocolType};
use crate::crypto::signature::SignatureScheme;
use crate::discovery::embedded::Embedded;
use crate::discovery::{redis::Redis, DiscoveryClient};
use crate::error::{Error, Result};

/// An implementation of `Topic` for testing purposes.
#[repr(u8)]
#[derive(IntoPrimitive, TryFromPrimitive, Clone, PartialEq, Eq)]
pub enum TestTopic {
    Global = 0,
    DA = 1,
}

/// Defines the topic type for CDN messages
pub trait Topic: Into<u8> + TryFrom<u8> + Clone + Send + Sync {
    /// Prunes the topics to only include valid topics.
    ///
    /// # Errors
    /// - If no valid topics are supplied
    fn prune(topics: &mut Vec<u8>) -> Result<()> {
        // Deduplicate the topics
        topics.dedup();

        // Retain only the topics that can be converted to the desired type
        topics.retain(|topic| Self::try_from(*topic).is_ok());

        // Make sure we have at least one topic
        if topics.is_empty() {
            Err(Error::Parse("supplied no valid topics".to_string()))
        } else {
            Ok(())
        }
    }
}
impl Topic for TestTopic {}

/// This trait defines the run configuration for all CDN components.
pub trait RunDef: 'static {
    type Broker: ConnectionDef;
    type User: ConnectionDef;
    type DiscoveryClientType: DiscoveryClient;
    type Topic: Topic;
}

/// This trait defines the connection configuration for a single CDN component.
pub trait ConnectionDef: 'static {
    type Scheme: SignatureScheme;
    type Protocol: ProtocolType<Self::Middleware>;
    type Middleware: MiddlewareType;
}

/// The production run configuration.
/// Uses the real network protocols and Redis for discovery.
pub struct ProductionRunDef;
impl RunDef for ProductionRunDef {
    type Broker = ProductionBrokerConnection;
    type User = ProductionUserConnection;
    type DiscoveryClientType = Redis;
    type Topic = TestTopic;
}

/// The production broker connection configuration.
/// Uses BLS signatures, TCP, and trusted middleware.
pub struct ProductionBrokerConnection;
impl ConnectionDef for ProductionBrokerConnection {
    type Scheme = BLS;
    type Protocol = Tcp;
    type Middleware = TrustedMiddleware;
}

/// The production user connection configuration.
/// Uses BLS signatures, QUIC, and untrusted middleware.
pub struct ProductionUserConnection;
impl ConnectionDef for ProductionUserConnection {
    type Scheme = BLS;
    type Protocol = Quic;
    type Middleware = UntrustedMiddleware;
}

/// The production client connection configuration.
/// Uses BLS signatures, QUIC, and no middleware.
/// Differs from `ProductionUserConnection` in that this is used by
/// the client, not the broker.
pub struct ProductionClientConnection;
impl ConnectionDef for ProductionClientConnection {
    type Scheme = Scheme<<ProductionRunDef as RunDef>::User>;
    type Protocol = Protocol<<ProductionRunDef as RunDef>::User>;
    type Middleware = NoMiddleware;
}

/// The testing run configuration.
/// Uses in-memory protocols and an embedded discovery client.
pub struct TestingRunDef;
impl RunDef for TestingRunDef {
    type Broker = TestingConnection;
    type User = TestingConnection;
    type DiscoveryClientType = Embedded;
    type Topic = TestTopic;
}

/// The testing connection configuration.
/// Uses BLS signatures, in-memory protocols, and no middleware.
pub struct TestingConnection;
impl ConnectionDef for TestingConnection {
    type Scheme = BLS;
    type Protocol = Memory;
    type Middleware = NoMiddleware;
}

// Type aliases to automatically disambiguate usage
pub type Scheme<A> = <A as ConnectionDef>::Scheme;
pub type PublicKey<A> = <Scheme<A> as SignatureScheme>::PublicKey;

// Type aliases to automatically disambiguate usage
pub type Protocol<A> = <A as ConnectionDef>::Protocol;
pub type Middleware<A> = <A as ConnectionDef>::Middleware;
pub type Listener<A> = <Protocol<A> as ProtocolType<Middleware<A>>>::Listener;
