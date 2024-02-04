//! This file provides a `Sticky` connection, which allows for reconnections
//! on top of a normal implementation of a `Fallible` connection.
//!
//! TODO FOR ALL CRATES: figure out where we need to bail,
//! and where we can just return. Most of the errors already have
//! enough context from previous bails.

use std::{marker::PhantomData, sync::Arc, time::Duration};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use tokio::{
    sync::{RwLock, Semaphore},
    time::sleep,
};
use tracing::error;

use crate::{
    bail,
    error::{Error, Result},
    message::Message,
};

use super::{
    auth::Flow,
    protocols::{Connection, Protocol},
};

/// `Sticky` is a wrapper around a `Fallible` connection.
///
/// It employs synchronization around a `Fallible`, as well as retry logic for both switching
/// connections at a certain failure threshold and reconnecting under said threshold.
///
/// Can be cloned to provide a handle to the same underlying elastic connection.
#[derive(Clone)]
pub struct Sticky<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
    AuthFlow: Flow<SignatureScheme, ProtocolType>,
> {
    pub inner: Arc<Inner<SignatureScheme, ProtocolType, AuthFlow>>,
}

/// `Inner` is held exclusively by `Sticky`, wherein an `Arc` is used
/// to facilitate interior mutability.
pub struct Inner<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
    AuthFlow: Flow<SignatureScheme, ProtocolType>,
> {
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal.
    endpoint: String,

    /// The underlying connection, which we modify to facilitate reconnections.
    connection: RwLock<ProtocolType::Connection>,

    /// This is the authentication data that we need to be able to authenticate
    pub auth_data: AuthFlow::AuthenticationData,

    /// The task that runs in the background that reconnects us when we need
    /// to be. This is so we don't spawn multiple tasks at once
    reconnect_semaphore: Semaphore,

    /// Phantom data that lets us use `ProtocolType`, `AuthFlow`, and
    /// `SignatureScheme` downstream.
    pd: PhantomData<(SignatureScheme, ProtocolType, AuthFlow)>,
}

/// The configuration needed to construct a `Sticky` connection.
pub struct Config<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
    AuthFlow: Flow<SignatureScheme, ProtocolType>,
> {
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal.
    pub endpoint: String,

    /// This is the authentication data that we need to be able to authenticate
    pub auth_data: AuthFlow::AuthenticationData,
}

/// This is a macro that helps with reconnections when sending
/// and receiving messages. You can specify the operation and it
/// will reconnect on the operation's failure, while handling all
/// reconnection logic and synchronization patterns.
///
/// TODO: document invariant with "messages will not retry"
macro_rules! try_with_reconnect {
    ($self: expr, $operation: ident,  $($arg:tt)*) => {{
        // Acquire read guard for sending and receiving messages
        let Ok(read_guard) = $self.inner.connection.try_read() else {
            return Err(Error::Connection("message failed: reconnection in progress".to_string()));
        };

        // Perform operation, see if it errors
        let operation = read_guard.$operation($($arg)*).await;
        match operation{
            Ok(res) => res,
            Err(err) => {
            // Acquire semaphore. If another task is doing this, just return an error
            if $self.inner.reconnect_semaphore.try_acquire().is_ok() {
                // Acquire write guard, drop read guard
                drop(read_guard);

                // Clone everything we need to connect
                // TODO: we want to minimize cloning this. We should sign a message
                // earlier.
                let inner = $self.inner.clone();

                tokio::spawn(async move{
                    // Get write guard on connection so we can write to it
                    let mut write_guard = inner.connection.write().await;

                // Loop to connect and authenticate
                let connection = loop {
                    // Create a connection
                    let connection = match ProtocolType::Connection::connect(inner.endpoint.clone()).await {
                        Ok(connection) => connection,
                        Err(err) => {
                            error!("failed to connect to endpoint: {err} retrying");
                        continue
                        }
                    };

                    // Try to authenticate the connection
                    match AuthFlow::authenticate(&inner.auth_data, &connection)
                    .await
                    {
                        Ok(_) => break connection,
                        Err(err) => error!("failed to authenticate with endpoint: {err}. retrying"),
                    }

                    // Sleep so we don't overload the server
                    sleep(Duration::from_secs(5)).await;
                };

                // Set connection to new connection
                *write_guard = connection;

                // Drop here so other tasks can start sending messages
                drop(write_guard);
            });
        }

        // If somebody is already trying to reconnect, fail instantly
        return Err(Error::Connection(format!(
            "connection failed, reconnecting to endpoint: {err}"
        )));
    }
    }
}};
}

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
        AuthFlow: Flow<SignatureScheme, ProtocolType>,
    > Sticky<SignatureScheme, ProtocolType, AuthFlow>
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
        config: Config<SignatureScheme, ProtocolType, AuthFlow>,
        maybe_connection: Option<ProtocolType::Connection>,
    ) -> Result<Self> {
        // Extrapolate values from the underlying client configuration
        let Config {
            endpoint,
            auth_data,
        } = config;

        // Perform the initial connection and authentication if not provided.
        // This is to validate that we have correct parameters and all.
        //
        // TODO: cancel conditionally depending on what kind of error, or retry-
        // based.
        //
        // TODO: clean this up
        let connection = if let Some(connection) = maybe_connection {
            connection
        } else {
            // Make the connection
            let connection = bail!(
                ProtocolType::Connection::connect(endpoint.clone()).await,
                Connection,
                "failed to connect to endpoint"
            );

            // Authenticate the connection (if not provided)
            let _permit = bail!(
                AuthFlow::authenticate(&auth_data, &connection).await,
                Authentication,
                "failed to authenticate"
            );

            connection
        };

        // Return the slightly transformed connection.
        Ok(Self {
            inner: Arc::from(Inner {
                auth_data,
                endpoint,
                // Use the existing connection
                connection: RwLock::from(connection),
                reconnect_semaphore: Semaphore::const_new(1),
                pd: PhantomData,
            }),
        })
    }

    /// Sends a pre-formed message to the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-send messages)
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    /// - If the message sending failed
    pub async fn send_message_raw(&self, message: Vec<u8>) -> Result<()> {
        // Try to send the message, reconnecting if needed
        Ok(try_with_reconnect!(self, send_message_raw, message,))
    }

    /// Sends a message to the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-send messages)
    ///
    /// # Errors
    /// - If we fail to serialize the message
    /// - If we are in the middle of reconnecting
    /// - If the message sending failed
    pub async fn send_message(&self, message: Message) -> Result<()> {
        // Serialize the message
        let message = bail!(
            message.serialize(),
            Serialize,
            "failed to serialize message"
        );

        // Try to send the message, reconnecting if needed
        Ok(try_with_reconnect!(self, send_message_raw, message,))
    }

    /// Receives a message from the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-receive messages)
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    /// - If the message receiving failed
    pub async fn receive_message(&self) -> Result<Message> {
        // Try to send the message, reconnecting if needed
        Ok(try_with_reconnect!(self, recv_message,))
    }
}
