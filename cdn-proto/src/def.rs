//! Compile-time run configuration for all CDN components.

use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;

use crate::connection::middleware::{
    Middleware as MiddlewareType, NoMiddleware, TrustedMiddleware, UntrustedMiddleware,
};
use crate::connection::protocols::{
    memory::Memory, quic::Quic, tcp::Tcp, Protocol as ProtocolType,
};
use crate::crypto::signature::SignatureScheme;
use crate::discovery::{embedded::Embedded, redis::Redis, DiscoveryClient};

/// This trait defines the run configuration for all CDN components.
pub trait RunDef: Send + Sync + 'static {
    type Broker: Def;
    type User: Def;
    type DiscoveryClientType: DiscoveryClient;
}

/// This trait defines the configuration for a single actor in the CDN.
pub trait Def: 'static + Clone {
    type Scheme: SignatureScheme;
    type Protocol: ProtocolType<Self::Middleware>;
    type Middleware: MiddlewareType;
}

/// The production run-time configuration.
/// Uses the real network protocols and the real discovery client.
#[derive(Clone)]
pub struct ProductionRunDef {}

impl RunDef for ProductionRunDef {
    type Broker = ProductionBrokerDef;
    type User = ProductionUserDef;
    type DiscoveryClientType = Redis;
}

/// The production run-time configuration for a broker.
/// Uses the real network protocols and trusted middleware.
#[derive(Clone)]
pub struct ProductionBrokerDef {}
impl Def for ProductionBrokerDef {
    type Scheme = BLS;
    type Protocol = Tcp;
    type Middleware = TrustedMiddleware;
}

/// The production run-time configuration for a broker.
/// Uses the real network protocols and untrusted middleware.
#[derive(Clone)]
pub struct ProductionUserDef {}
impl Def for ProductionUserDef {
    type Scheme = BLS;
    type Protocol = Quic;
    type Middleware = UntrustedMiddleware;
}

/// The testing run-time configuration.
/// Uses in-memory protocols and the embedded discovery client.
#[derive(Clone)]
pub struct TestingRunDef {}

impl RunDef for TestingRunDef {
    type User = TestingDef;
    type Broker = TestingDef;
    type DiscoveryClientType = Embedded;
}

/// The testing run-time configuration for a broker and user.
/// Uses in-memory protocols and no middleware.
#[derive(Clone)]
pub struct TestingDef {}
impl Def for TestingDef {
    type Scheme = BLS;
    type Protocol = Memory;
    type Middleware = NoMiddleware;
}

// Type aliases to automatically disambiguate usage
pub type Scheme<A> = <A as Def>::Scheme;
pub type PublicKey<A> = <Scheme<A> as SignatureScheme>::PublicKey;

// Type aliases to automatically disambiguate usage
pub type Protocol<A> = <A as Def>::Protocol;
pub type Middleware<A> = <A as Def>::Middleware;
pub type Sender<A> = <Protocol<A> as ProtocolType<Middleware<A>>>::Sender;
pub type Receiver<A> = <Protocol<A> as ProtocolType<Middleware<A>>>::Receiver;
pub type Listener<A> = <Protocol<A> as ProtocolType<Middleware<A>>>::Listener;
pub type Connection<A> = (
    <Protocol<A> as ProtocolType<Middleware<A>>>::Sender,
    <Protocol<A> as ProtocolType<Middleware<A>>>::Receiver,
);
