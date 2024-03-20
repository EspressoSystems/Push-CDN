//! Definition of the run-time configuration for all CDN components.

use jf_primitives::signatures::bls_over_bn254::BLSOverBN254CurveSignatureScheme as BLS;

use crate::connection::{
    hooks::{Trusted, Untrusted},
    protocols::{memory::Memory, quic::Quic, tcp::Tcp, Protocol},
};
use crate::crypto::signature::SignatureScheme;
use crate::discovery::{embedded::Embedded, redis::Redis, DiscoveryClient};

/// This trait defines the run-time configuration for all CDN components.
pub trait RunDef: Send + Sync + 'static {
    type BrokerScheme: SignatureScheme;
    type BrokerProtocol: Protocol<Trusted>;

    type UserScheme: SignatureScheme;
    type UserProtocol: Protocol<Untrusted>;

    type DiscoveryClientType: DiscoveryClient;
}

/// The production run-time configuration.
/// Uses the real network protocols and the real discovery client.
pub struct ProductionDef {}

impl RunDef for ProductionDef {
    type BrokerScheme = BLS;
    type BrokerProtocol = Tcp;

    type UserScheme = BLS;
    type UserProtocol = Quic;

    type DiscoveryClientType = Redis;
}

/// The testing run-time configuration.
/// Uses in-memory protocols and the embedded discovery client.
pub struct TestingDef {}

impl RunDef for TestingDef {
    type BrokerScheme = BLS;
    type BrokerProtocol = Memory;

    type UserScheme = BLS;
    type UserProtocol = Memory;

    type DiscoveryClientType = Embedded;
}
