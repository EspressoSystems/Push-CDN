//! This file provides a `Sticky` connection, which allows for reconnections
//! on top of a normal implementation of a `Fallible` connection.
//!
//! TODO FOR ALL CRATES: figure out where we need to bail,
//! and where we can just return. Most of the errors already have
//! enough context from previous bails.

use std::{collections::HashSet, marker::PhantomData, sync::Arc};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use parking_lot::Mutex;
use tokio::sync::RwLock;

use crate::{
    bail,
    error::{Error, Result},
    message::{Message, Topic},
};

use super::{flow::Flow, Connection};

/// `Sticky` is a wrapper around a `Fallible` connection.
///
/// It employs synchronization around a `Fallible`, as well as retry logic for both switching
/// connections at a certain failure threshold and reconnecting under said threshold.
///
/// Can be cloned to provide a handle to the same underlying elastic connection.
#[derive(Clone)]
pub struct Sticky<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ConnectionType: Connection,
    ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
> {
    inner: Arc<StickyInner<SignatureScheme, ConnectionType, ConnectionFlow>>,
}

/// `StickyInner` is held exclusively by `Sticky`, wherein an `Arc` is used
/// to facilitate interior mutability.
struct StickyInner<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ConnectionType: Connection,
    ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
> {
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal. The authentication flow depends on the function defined in
    /// `auth_flow`, so this may not be the final address (e.g. if you are asking the
    /// marshal for it).
    remote_address: String,

    /// A list of topics we are subscribed to. This allows us to, when reconnecting,
    /// easily provide the list of topics we care about.
    subscribed_topics: Mutex<HashSet<Topic>>,

    /// The underlying connection, which we modify to facilitate reconnections.
    connection: RwLock<ConnectionType>,

    /// The underlying (public) verification key, used to authenticate with the server. Checked against the stake
    /// table.
    verification_key: SignatureScheme::VerificationKey,

    /// The underlying (private) signing key, used to sign messages to send to the server during the
    /// authentication phase.
    signing_key: SignatureScheme::SigningKey,

    pub _pd: PhantomData<(ConnectionType, ConnectionFlow)>,
}

/// The configuration needed to construct a client
pub struct Config<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ConnectionType: Connection,
    ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
> {
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

    /// Phantom data that we pass down to `Sticky` and `StickInner`.
    /// Allows us to be generic over a connection method, because
    /// we need multiple.
    pub _pd: PhantomData<(ConnectionType, ConnectionFlow)>,
}

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ConnectionType: Connection,
        ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
    > Sticky<SignatureScheme, ConnectionType, ConnectionFlow>
{
    /// Creates a new `Sticky` connection from a `Config` and an (optional) pre-existing
    /// `Fallible` connection.
    ///
    /// This allows us to create elastic clients that always try to maintain a connection
    /// with each other.
    ///
    /// # Errors
    /// - If we are unable to either parse or bind an endpoint to the local address.
    /// - If we are unable to make the initial connection
    /// TODO: figure out if we want retries here
    pub async fn from_config_and_connection(
        config: Config<SignatureScheme, ConnectionType, ConnectionFlow>,
        maybe_connection: Option<ConnectionType>,
    ) -> Result<Self> {
        // Extrapolate values from the underlying client configuration
        let Config {
            verification_key,
            signing_key,
            remote_address,
            initial_subscribed_topics,
            _pd,
        } = config;

        // Perform the initial connection. This is to validate that we have
        // correct parameters and all
        // TODO: cancel conditionally depending on what kind of error, or retry-
        // based.
        let connection = bail!(
            ConnectionFlow::connect(remote_address.clone(), &signing_key, &verification_key).await,
            Connection,
            "failed to make initial connection"
        );

        // Return the slightly transformed connection.
        Ok(Self {
            inner: Arc::from(StickyInner {
                remote_address,
                subscribed_topics: Mutex::from(HashSet::from_iter(initial_subscribed_topics)),
                // Use the existing connection
                connection: RwLock::from(connection),
                signing_key,
                verification_key,
                _pd,
            }),
        })
    }

    /// Sends a message to the underlying fallible connection. Retry logic is handled in
    /// the macro `retry_on_error` where it is conditionally propagated
    /// to `wait_connect()`.
    pub async fn send_message<M: AsRef<Message>>(&self, message: M) -> Result<()> {
        // Acquire the connection from the underlying `Option`
        let read_guard = self.inner.connection.read().await;

        Ok(())
    }

    /// Receives a  message to the underlying fallible connection. Retry
    /// logic is handled in the macro `retry_on_error` where it is conditionally propagated
    /// to `wait_connect()`.
    pub async fn receive_message(&self) -> Result<Message> {
        // TODO: check if this makes sense to bail, or can we just return
        // the downstream error

        // TODO: clean up clean up !!!!
        // possible macro
        //     Ok(bail!(
        //         bail!(
        //             self.inner
        //                 .connection
        //                 .read()
        //                 .await
        //                 .get_or_try_init(|| async {
        //                     Connection::connect(self.inner.remote_address.clone()).await
        //                 })
        //                 .await,
        //             Connection,
        //             "failed to connect"
        //         )
        //         .recv_message()
        //         .await,
        //         Connection,
        //         "failed to send message"
        //     ))
        todo!();
    }
}
