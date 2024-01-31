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

use crate::messages_capnp::Topic;

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
    /// `auth_flow`.
    address: SocketAddr,

    /// The authentication flow that is followed when connecting. Uses the `SocketAddr`
    /// as the endpoint for the connection.
    auth_flow: fn(SocketAddr, Connection) -> Connection,

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
