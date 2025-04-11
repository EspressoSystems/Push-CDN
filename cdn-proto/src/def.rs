// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! Compile-time run configuration for all CDN components.
use std::marker::PhantomData;

use jf_signature::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::connection::protocols::tcp_tls::TcpTls;
use crate::connection::protocols::{tcp::Tcp, Protocol as ProtocolType};
use crate::crypto::signature::SignatureScheme;
use crate::database::embedded::Embedded;
use crate::database::{redis::Redis, DatabaseClient};
use crate::error::{Error, Result};
use crate::message::Message;
use anyhow::Result as AnyhowResult;

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
    type DatabaseClientType: DatabaseClient;
    type Topic: Topic;
}

/// This trait defines the connection configuration for a single CDN component
pub trait ConnectionDef: 'static {
    type Scheme: SignatureScheme;
    type Protocol: ProtocolType;
    type MessageHook: MessageHookDef;
}

/// The result of a message hooking operation
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HookResult {
    /// Skip processing the message
    SkipMessage,

    /// Process the message
    ProcessMessage,
}

/// This trait defines a hook that we use to perform additional actions on receiving a message
pub trait MessageHookDef: Send + Sync + 'static + Clone {
    /// The hook that is called when a message is received. If an error is returned, the connection
    /// will be closed.
    ///
    /// # Errors
    /// Is supposed to return an error if the other end should be disconnected.
    fn on_message_received(&mut self, _message: &mut Message) -> AnyhowResult<HookResult>;

    /// Set a unique identifier for the hook. This can be included with the hook and can be
    /// used to deterministically identify message producers.
    fn set_identifier(&mut self, _identifier: u64);
}

/// The no-op hook
#[derive(Clone)]
pub struct NoMessageHook;
impl MessageHookDef for NoMessageHook {
    fn on_message_received(&mut self, _message: &mut Message) -> AnyhowResult<HookResult> {
        Ok(HookResult::ProcessMessage)
    }
    fn set_identifier(&mut self, _identifier: u64) {}
}

/// The production run configuration.
/// Uses the real network protocols and Redis for database.
pub struct ProductionRunDef;
impl RunDef for ProductionRunDef {
    type Broker = ProductionBrokerConnection;
    type User = ProductionUserConnection;
    type DatabaseClientType = Redis;
    type Topic = TestTopic;
}

/// The production broker connection configuration.
/// Uses BLS signatures and TCP.
pub struct ProductionBrokerConnection;
impl ConnectionDef for ProductionBrokerConnection {
    type Scheme = BLS;
    type Protocol = Tcp;
    type MessageHook = NoMessageHook;
}

/// The production user connection configuration.
/// Uses BLS signatures and TCP+TLS.
pub struct ProductionUserConnection;
impl ConnectionDef for ProductionUserConnection {
    type Scheme = BLS;
    type Protocol = TcpTls;
    type MessageHook = NoMessageHook;
}

/// The production client connection configuration.
/// Uses BLS signatures and TCP+TLS.
/// Differs from `ProductionUserConnection` in that this is used by
/// the client, not the broker.
pub struct ProductionClientConnection;
impl ConnectionDef for ProductionClientConnection {
    type Scheme = Scheme<<ProductionRunDef as RunDef>::User>;
    type Protocol = Protocol<<ProductionRunDef as RunDef>::User>;
    type MessageHook = NoMessageHook;
}

/// The testing run configuration.
/// Uses generic protocols and an embedded database client.
pub struct TestingRunDef<B: ProtocolType, U: ProtocolType> {
    pd: PhantomData<(B, U)>,
}
impl<B: ProtocolType, U: ProtocolType> RunDef for TestingRunDef<B, U> {
    type Broker = TestingConnection<B>;
    type User = TestingConnection<U>;
    type DatabaseClientType = Embedded;
    type Topic = TestTopic;
}

/// The testing connection configuration.
/// Uses BLS signatures and generic protocols.
pub struct TestingConnection<P: ProtocolType> {
    pd: PhantomData<P>,
}
impl<P: ProtocolType> ConnectionDef for TestingConnection<P> {
    type Scheme = BLS;
    type Protocol = P;
    type MessageHook = NoMessageHook;
}

// Type aliases to automatically disambiguate usage
pub type Scheme<A> = <A as ConnectionDef>::Scheme;
pub type PublicKey<A> = <Scheme<A> as SignatureScheme>::PublicKey;
pub type MessageHook<A> = <A as ConnectionDef>::MessageHook;

// Type aliases to automatically disambiguate usage
pub type Protocol<A> = <A as ConnectionDef>::Protocol;
pub type Listener<A> = <Protocol<A> as ProtocolType>::Listener;
