// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! Compile-time run configuration for all CDN components.
use std::marker::PhantomData;

use jf_signature::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use num_enum::{IntoPrimitive, TryFromPrimitive};

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
    type Protocol: ProtocolType;
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
/// Uses BLS signatures, TCP, and trusted limiter.
pub struct ProductionBrokerConnection;
impl ConnectionDef for ProductionBrokerConnection {
    type Scheme = BLS;
    type Protocol = Tcp;
}

/// The production user connection configuration.
/// Uses BLS signatures, QUIC, and untrusted limiter.
pub struct ProductionUserConnection;
impl ConnectionDef for ProductionUserConnection {
    type Scheme = BLS;
    type Protocol = Quic;
}

/// The production client connection configuration.
/// Uses BLS signatures, QUIC, and trusted limiter.
/// Differs from `ProductionUserConnection` in that this is used by
/// the client, not the broker.
pub struct ProductionClientConnection;
impl ConnectionDef for ProductionClientConnection {
    type Scheme = Scheme<<ProductionRunDef as RunDef>::User>;
    type Protocol = Protocol<<ProductionRunDef as RunDef>::User>;
}

/// The testing run configuration.
/// Uses generic protocols and an embedded discovery client.
pub struct TestingRunDef<B: ProtocolType, U: ProtocolType> {
    pd: PhantomData<(B, U)>,
}
impl<B: ProtocolType, U: ProtocolType> RunDef for TestingRunDef<B, U> {
    type Broker = TestingConnection<B>;
    type User = TestingConnection<U>;
    type DiscoveryClientType = Embedded;
    type Topic = TestTopic;
}

/// The testing connection configuration.
/// Uses BLS signatures, generic protocols, and no limiter.
pub struct TestingConnection<P: ProtocolType> {
    pd: PhantomData<P>,
}
impl<P: ProtocolType> ConnectionDef for TestingConnection<P> {
    type Scheme = BLS;
    type Protocol = P;
}

// Type aliases to automatically disambiguate usage
pub type Scheme<A> = <A as ConnectionDef>::Scheme;
pub type PublicKey<A> = <Scheme<A> as SignatureScheme>::PublicKey;

// Type aliases to automatically disambiguate usage
pub type Protocol<A> = <A as ConnectionDef>::Protocol;
pub type Listener<A> = <Protocol<A> as ProtocolType>::Listener;
