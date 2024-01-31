//! This file provides a `Sticky` connection, which allows for reconnections
//! on top of a normal implementation of a `Fallible` connection.

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc},
};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use parking_lot::Mutex;
use tokio::sync::{OnceCell, RwLock};

use crate::{error::Result, message::Topic};

use super::Connection as ProtoConnection;

/// `Sticky` is a wrapper around a `Fallible` connection.
///
/// It employs synchronization around a `Fallible`, as well as retry logic for both switching
/// connections at a certain failure threshold and reconnecting under said threshold.
///
/// Can be cloned to provide a handle to the same underlying elastic connection.
#[derive(Clone)]
pub struct Sticky<SignatureScheme: JfSignatureScheme, Connection: ProtoConnection> {
    inner: Arc<StickyInner<SignatureScheme, Connection>>,
}

/// `StickyInner` is held exclusively by `Sticky`, wherein an `Arc` is used
/// to facilitate interior mutability.
struct StickyInner<SignatureScheme: JfSignatureScheme, Connection: ProtoConnection> {
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal. The authentication flow depends on the function defined in
    /// `auth_flow`, so this may not be the final address (e.g. if you are asking the
    /// marshal for it).
    remote_address: String,

    /// The authentication flow that is followed when connecting. Uses the `SocketAddr`
    /// as the endpoint for the connection. Takes the signing and verification keys
    /// in case they are needed.
    auth_flow: fn(
        SocketAddr,
        Connection,
        SignatureScheme::SigningKey,
        SignatureScheme::VerificationKey,
    ) -> Connection,

    /// A list of topics we are subscribed to. This allows us to, when reconnecting,
    /// easily provide the list of topics we care about.
    subscribed_topics: Mutex<HashSet<Topic>>,

    /// The underlying connection, which we modify to facilitate reconnections.
    connection: RwLock<OnceCell<Connection>>,

    /// The underlying (public) verification key, used to authenticate with the server. Checked against the stake
    /// table.
    verification_key: SignatureScheme::VerificationKey,

    /// The underlying (private) signing key, used to sign messages to send to the server during the
    /// authentication phase.
    signing_key: SignatureScheme::SigningKey,
}

/// The configuration needed to construct a client
pub struct Config<SignatureScheme: JfSignatureScheme, Connection: ProtoConnection> {
    /// The verification (public) key. Sent to the server to verify
    /// our identity.
    pub verification_key: SignatureScheme::VerificationKey,

    /// The signing (private) key. Only used for signing the authentication
    /// message sent to the server upon connection.
    pub signing_key: SignatureScheme::SigningKey,

    /// The remote address(es) to connect and authenticate to.
    pub remote_address: String,

    /// The topics we want to be subscribed to initially. This is needed so that
    /// we can resubscribe to the same topics upon reconnection.
    pub initial_subscribed_topics: Vec<Topic>,

    /// The authentication flow that is followed when connecting. Uses the `SocketAddr`
    /// as the endpoint for the connection. Takes the signing and verification keys
    /// in case they are needed.
    auth_flow: fn(
        SocketAddr,
        Connection,
        SignatureScheme::SigningKey,
        SignatureScheme::VerificationKey,
    ) -> Connection,
}

impl<SignatureScheme: JfSignatureScheme, Connection: ProtoConnection>
    Sticky<SignatureScheme, Connection>
{
    /// Creates a new `Sticky` connection from a `Config` and an (optional) pre-existing
    /// `Fallible` connection.
    ///
    /// This allows us to create elastic clients that always try to maintain a connection
    /// with each other.
    ///
    /// # Errors
    /// Errors if we are unable to either parse or bind an endpoint to the local address.
    pub fn from_config_and_connection(
        config: Config<SignatureScheme, Connection>,
        connection: OnceCell<Connection>,
    ) -> Result<Self> {
        // Extrapolate values from the underlying client configuration
        let Config {
            auth_flow,
            verification_key,
            signing_key,
            remote_address,
            initial_subscribed_topics,
        } = config;

        // Return the slightly transformed connection.
        Ok(Self {
            inner: Arc::from(StickyInner {
                remote_address,
                subscribed_topics: Mutex::from(HashSet::from_iter(initial_subscribed_topics)),
                // Use the existing connection
                connection: RwLock::from(connection),
                signing_key,
                verification_key,
                auth_flow,
            }),
        })
    }
}
