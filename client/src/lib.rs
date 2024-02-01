//! In here we define an API that is a little more higher-level and ergonomic
//! for end users. It is a light wrapper on top of a `Sticky` connection.

use std::sync::Arc;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use proto::{
    bail,
    connection::{
        flow::Flow,
        sticky::{self, Sticky},
        Connection,
    },
    crypto,
    error::Error,
    error::Result,
    message::{Broadcast, Direct, Message, Subscribe, Topic, Unsubscribe},
};

/// `Client` is a light wrapper around a `Sticky` connection that provides functions
/// for common operations to and from a server. Mostly just used to make the API
/// more ergonomic.
pub struct Client<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ConnectionType: Connection,
    ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
>(Sticky<SignatureScheme, ConnectionType, ConnectionFlow>);

pub type Config<SignatureScheme, ConnectionType, ConnectionFlow> =
    sticky::Config<SignatureScheme, ConnectionType, ConnectionFlow>;

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ConnectionType: Connection,
        ConnectionFlow: Flow<SignatureScheme, ConnectionType>,
    > Client<SignatureScheme, ConnectionType, ConnectionFlow>
where
    SignatureScheme::Signature: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::VerificationKey: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::SigningKey: CanonicalSerialize + CanonicalDeserialize,
{
    /// Creates a new client from the given `Config`. Immediately will attempt
    /// a conection if none is supplied.
    ///
    /// # Errors
    /// Errors if the downstream `Sticky` object was unable to be made.
    /// This usually happens when we can't bind to the specified endpoint.
    pub async fn new(
        config: Config<SignatureScheme, ConnectionType, ConnectionFlow>,
    ) -> Result<Self> {
        Self::new_with_connection(config, Option::None).await
    }

    /// Creates a new client from the given `Config` and an optional `Connection`.
    /// Proxies the config to the `Sticky` constructor since a `Client` is just a
    /// light wrapper.
    ///
    /// # Errors
    /// Errors if the downstream `Sticky` object was unable to be created.
    /// This usually happens when we can't bind to the specified endpoint.
    pub async fn new_with_connection(
        config: Config<SignatureScheme, ConnectionType, ConnectionFlow>,
        connection: Option<ConnectionType>,
    ) -> Result<Self> {
        Ok(Client(bail!(
            Sticky::from_config_and_connection(config, connection).await,
            Connection,
            "failed to create client"
        )))
    }

    /// Receives the next message from the downstream server.
    /// If it fails, we return an error but try to initiate a new
    /// connection in the background.
    ///
    /// # Errors
    /// If the connection or deserialization has failed
    pub async fn receive_message(&self) -> Result<Message> {
        // TODO: conditionally match error on whether deserialization OR the connection failed
        // this way we don't reconnect if somebody sends us a bad message
        self.0.receive_message().await
    }

    /// Sends a pre-serialized message to the server, denoting recipients in the form
    /// of a vector of topics. Use `send_message_raw` when the message is already
    /// formed. If it fails, we return an error but try to initiate a new connection
    /// in the background.
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn send_broadcast_message(&self, topics: Vec<Topic>, message: Vec<u8>) -> Result<()> {
        // TODO: conditionally match error on whether deserialization OR the connection failed

        // Form and send the single message
        self.send_message_raw(Arc::from(Message::Broadcast(Broadcast { topics, message })))
            .await
    }

    /// Sends a pre-serialized message to the server, denoting interest in delivery
    /// to a single recipient. Use `send_message_raw` when the message is already formed.
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn send_direct_message(
        &self,
        recipient: SignatureScheme::VerificationKey,
        message: Vec<u8>,
    ) -> Result<()> {
        // Serialize recipient to a byte array before sending the message
        // TODO: maybe we can cache this.
        let recipient_bytes = bail!(
            crypto::serialize(&recipient),
            Serialize,
            "failed to serialize recipient"
        );

        // Form and send the single message
        self.send_message_raw(Arc::from(Message::Direct(Direct {
            recipient: recipient_bytes,
            message,
        })))
        .await
    }

    /// Sends a message to the server that asserts that this client is interested in
    /// a specific topic
    ///
    /// # Errors
    /// If the connection or serialization has failed
    /// 
    /// TODO IMPORTANT: see if we want this, or if we'd prefer `set_subscriptions()``
    pub async fn subscribe(&self, topics: Vec<Topic>) -> Result<()> {
        // Lock subscribed topics here so if we're reconnecting we maintain parity
        // with our list

        // Lock our topics here so we can't add them on failure
        let mut topic_guard = self.0.inner.subscribed_topics.lock().await;

        // Form and send the single message
        self.send_message_raw(Arc::from(Message::Subscribe(Subscribe {
            topics: topics.clone(),
        })))
        .await
        // Only add to our topic map if the message was successful
        .map(|_| topic_guard.extend(topics))
    }

    /// Sends a message to the server that asserts that this client is no longer
    /// interested in a specific topic
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn unsubscribe(&self, topics: Vec<Topic>) -> Result<()> {
        // Lock subscribed topics here so if we're reconnecting we maintain parity
        // with our list

        // Lock our topics here so we can't add them on failure
        let mut topic_guard = self.0.inner.subscribed_topics.lock().await;

        // Form and send the single message
        self.send_message_raw(Arc::from(Message::Unsubscribe(Unsubscribe {
            topics: topics.clone(),
        })))
        .await
        // Only add to our topic map if the message was successful
        .map(|_| topic_guard.extend(topics))
    }

    /// Sends a pre-formed message over the wire. Various functions make use
    /// of this one downstream.
    pub async fn send_message_raw(&self, message: Arc<Message>) -> Result<()> {
        self.0.send_message(message).await
    }
}
