//! This file provides a `Retry` connection, which allows for reconnections
//! on top of a normal connection.
//!
//! TODO FOR ALL CRATES: figure out where we need to bail,
//! and where we can just return. Most of the errors already have
//! enough context from previous bails.

use std::{collections::HashSet, marker::PhantomData, sync::Arc, time::Duration};

use cdn_proto::{
    connection::{
        auth::user::UserAuth,
        protocols::{Protocol, Receiver, Sender},
    },
    crypto::signature::{KeyPair, SignatureScheme},
    error::{Error, Result},
    message::{Message, Topic},
};
use derive_builder::Builder;
use tokio::{
    sync::RwLock,
    time::{sleep},
};
use tracing::{error, info};

use crate::bail;

/// `Retry` is a wrapper around a fallible connection.
///
/// It employs synchronization as well as retry logic.
/// Can be cloned to provide a handle to the same underlying elastic connection.
#[derive(Clone)]
pub struct Retry<Scheme: SignatureScheme, ProtocolType: Protocol> {
    pub inner: Arc<Inner<Scheme, ProtocolType>>,
}

/// `Inner` is held exclusively by `Retry`, wherein an `Arc` is used
/// to facilitate interior mutability.
pub struct Inner<Scheme: SignatureScheme, ProtocolType: Protocol> {
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal.
    endpoint: String,

    /// The send-side of the connection.
    sender: Arc<RwLock<ProtocolType::Sender>>,

    /// The receive side of the connection.
    receiver: Arc<RwLock<ProtocolType::Receiver>>,

    /// The keypair to use when authenticating
    pub keypair: KeyPair<Scheme>,

    /// The topics we're currently subscribed to. We need this so we can send our subscriptions
    /// when we connect to a new server.
    pub subscribed_topics: RwLock<HashSet<Topic>>,

    /// Phantom data that lets us use `ProtocolType`, `AuthFlow`, and
    /// `SignatureScheme` downstream.
    pd: PhantomData<(Scheme, ProtocolType)>,
}

/// The configuration needed to construct a `Retry` connection.
#[derive(Builder, Clone)]
pub struct Config<Scheme: SignatureScheme, ProtocolType: Protocol> {
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal.
    pub endpoint: String,

    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    pub keypair: KeyPair<Scheme>,

    /// The topics we're currently subscribed to. We need this here so we can send our subscriptions
    /// when we connect to a new server.
    #[builder(default = "Vec::new()")]
    pub subscribed_topics: Vec<Topic>,

    /// The phantom data we need to be able to make use of these types
    #[builder(default)]
    pub pd: PhantomData<ProtocolType>,
}

/// This is a macro that helps with reconnections when sending
/// and receiving messages. You can specify the operation and it
/// will reconnect on the operation's failure, while handling all
/// reconnection logic and synchronization patterns.
macro_rules! try_with_reconnect {
    ($self: expr, $out: expr) => {{
        // See if operation was an error
        match $out {
            Ok(res) => Ok(res),
            Err(err) => {
                error!("connection failed: {err}");

                // Sleep so we don't overload the server
                sleep(Duration::from_secs(2)).await;

                // Acquire our "semaphore". If another task is doing this, just return an error
                if let Ok(mut sender_guard) = $self.inner.sender.clone().try_write_owned() {
                    let mut receiver_guard = $self.inner.receiver.clone().write_owned().await;
                    // Clone `inner` so we can use it in the task
                    let inner = $self.inner.clone();
                    // We are the only ones reconnecting. Let's launch the task to reconnect
                    tokio::spawn(async move {
                        // Loop to connect and authenticate
                        let connection = loop {
                            // Create a connection
                            match connect_and_authenticate::<Scheme, ProtocolType>(
                                &inner.endpoint,
                                &inner.keypair,
                                inner.subscribed_topics.read().await.clone(),
                            )
                            .await
                            {
                                Ok(connection) => break connection,
                                Err(err) => {
                                    error!("failed connection: {err}");
                                }
                            }
                        };

                        // Update sender and receiver
                        // TODO: parameterize duration and size
                        *sender_guard = connection.0;
                        *receiver_guard = connection.1;
                    });
                }

                // We are trying to reconnect. Return an error.
                return Err(Error::Connection("reconnection in progress".to_string()));
            }
        }
    }};
}

impl<Scheme: SignatureScheme, ProtocolType: Protocol> Retry<Scheme, ProtocolType> {
    /// Creates a new `Retry` connection from a `Config`
    /// Attempts to make an initial connection.
    /// This allows us to create elastic clients that always try to maintain a connection.
    ///
    /// # Errors
    /// - If we are unable to either parse or bind an endpoint to the local address.
    /// - If we are unable to make the initial connection
    /// TODO: figure out if we want retries here
    pub async fn from_config(config: Config<Scheme, ProtocolType>) -> Result<Self> {
        // Extrapolate values from the underlying client configuration
        let Config {
            endpoint,
            keypair,
            subscribed_topics,
            pd: _,
        } = config;

        // Wrap subscribed topics so we can use it now and later
        let subscribed_topics = RwLock::new(HashSet::from_iter(subscribed_topics));

        // Perform the initial connection and authentication
        let connection = bail!(
            connect_and_authenticate::<Scheme, ProtocolType>(
                &endpoint,
                &keypair,
                subscribed_topics.read().await.clone()
            )
            .await,
            Connection,
            "failed initial connection"
        );

        // Return the slightly transformed connection.
        Ok(Self {
            inner: Arc::from(Inner {
                endpoint,
                // TODO: parameterize batch params
                sender: Arc::from(RwLock::from(connection.0)),
                receiver: Arc::from(RwLock::from(connection.1)),
                keypair,
                subscribed_topics,
                pd: PhantomData,
            }),
        })
    }

    /// Sends a message to the underlying connection. Reconnection is handled under
    /// the hood. Messages will fail if the connection is currently closed or reconnecting.
    ///
    /// # Errors
    /// If the message sending fails. For example:
    /// - If we are reconnecting
    /// - If we are disconnected
    pub async fn send_message(&self, message: Message) -> Result<()> {
        // Check if we're (probably) reconnecting or not
        if let Ok(sender_guard) = self.inner.sender.try_read() {
            // We're not reconnecting, try to send the message
            let out = sender_guard.send_message(message).await;
            drop(sender_guard);

            try_with_reconnect!(self, out)
        } else {
            // We are reconnecting, return an error
            Err(Error::Connection("reconnection in progress".to_string()))
        }
    }

    /// Receives a message from the underlying fallible connection. Reconnection logic is here,
    /// but retry logic needs to be handled by the caller (e.g. re-receive messages)
    ///
    /// # Errors
    /// - If we are in the middle of reconnecting
    /// - If the message receiving failed
    pub async fn receive_message(&self) -> Result<Message> {
        // Wait for a reconnection before trying to receive
        let receiver_guard = self.inner.receiver.read().await;
        let out = receiver_guard.recv_message().await;
        drop(receiver_guard);

        // If we failed to receive a message, kick off reconnection logic
        try_with_reconnect!(self, out)
    }
}

/// Connect and authenticate to the marshal  and then broker at the given endpoint
/// and with the given keypair.
///
/// Subscribe to the topics laid out herein.
///
/// # Errors
/// If we failed to connect or authenticate to the marshal or broker.
async fn connect_and_authenticate<Scheme: SignatureScheme, ProtocolType: Protocol>(
    marshal_endpoint: &str,
    keypair: &KeyPair<Scheme>,
    subscribed_topics: HashSet<Topic>,
) -> Result<(ProtocolType::Sender, ProtocolType::Receiver)> {
    // Make the connection to the marshal
    let connection = bail!(
        ProtocolType::connect(marshal_endpoint).await,
        Connection,
        "failed to connect to endpoint"
    );

    // Authenticate the connection to the marshal (if not provided)
    let (broker_address, permit) = bail!(
        UserAuth::<Scheme, ProtocolType>::authenticate_with_marshal(&connection, keypair).await,
        Authentication,
        "failed to authenticate to marshal"
    );

    // Make the connection to the broker
    let connection = bail!(
        ProtocolType::connect(&broker_address).await,
        Connection,
        "failed to connect to broker"
    );

    // Authenticate the connection to the broker
    bail!(
        UserAuth::<Scheme, ProtocolType>::authenticate_with_broker(
            &connection,
            permit,
            subscribed_topics
        )
        .await,
        Authentication,
        "failed to authenticate to broker"
    );

    info!("connected to broker {}", broker_address);

    Ok(connection)
}
