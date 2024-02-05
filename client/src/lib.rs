//! In here we define an API that is a little more higher-level and ergonomic
//! for end users. It is a light wrapper on top of a `Sticky` connection.

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use proto::{
    bail,
    connection::{
        auth::user::UserToMarshalToBroker,
        protocols::Protocol,
        sticky::{self, Sticky},
    },
    crypto::{self, Serializable},
    error::Error,
    error::Result,
    message::{Broadcast, Direct, Message, Subscribe, Topic, Unsubscribe},
};

/// `Client` is a light wrapper around a `Sticky` connection that provides functions
/// for common operations to and from a server. Mostly just used to make the API
/// more ergonomic. Also keeps track of subscriptions.
pub struct Client<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
>(Sticky<SignatureScheme, ProtocolType, UserToMarshalToBroker<SignatureScheme>>)
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable;

pub type Config<SignatureScheme, ProtocolType, AuthFlow> =
    sticky::Config<SignatureScheme, ProtocolType, AuthFlow>;

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > Client<SignatureScheme, ProtocolType>
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    /// Creates a new client from the given `Config`. Immediately will attempt
    /// a conection if none is supplied.
    ///
    /// # Errors
    /// Errors if the downstream `Sticky` object was unable to be made.
    /// This usually happens when we can't bind to the specified endpoint.
    pub async fn new(
        config: Config<SignatureScheme, ProtocolType, UserToMarshalToBroker<SignatureScheme>>,
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
        config: Config<SignatureScheme, ProtocolType, UserToMarshalToBroker<SignatureScheme>>,
        connection: Option<ProtocolType::Connection>,
    ) -> Result<Self> {
        Ok(Self(bail!(
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
        self.send_message(Message::Broadcast(Broadcast { topics, message }))
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
        self.send_message(Message::Direct(Direct {
            recipient: recipient_bytes,
            message,
        }))
        .await
    }

    /// Sends a message to the server that asserts that this client is interested in
    /// a specific topic
    ///
    /// # Errors
    /// If the connection or serialization has failed
    ///
    /// TODO IMPORTANT: see if we want this, or if we'd prefer `set_subscriptions()`
    pub async fn subscribe(&self, topics: Vec<Topic>) -> Result<()> {
        // Lock subscriptions here so we maintain parity during a reconnection
        let mut subscribed_guard = self.0.inner.auth_data.subscribed_topics.lock().await;

        // Calculate the real topics to send based on whatever's already in the set
        let topics_to_send: Vec<Topic> = topics
            .into_iter()
            .filter(|topic| !subscribed_guard.contains(topic))
            .collect();

        // Send the topics
        bail!(
            self.send_message(Message::Subscribe(Subscribe {
                topics: topics_to_send.clone()
            }))
            .await,
            Connection,
            "failed to send subscription message"
        );

        // Add the topics to the list if successful
        for topic in topics_to_send {
            subscribed_guard.insert(topic);
        }

        // Drop the write guard
        drop(subscribed_guard);

        Ok(())
    }

    /// Sends a message to the server that asserts that this client is no longer
    /// interested in a specific topic
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn unsubscribe(&self, topics: Vec<Topic>) -> Result<()> {
        // Lock subscriptions here so we maintain parity during a reconnection
        let mut subscribed_guard = self.0.inner.auth_data.subscribed_topics.lock().await;

        // Calculate the real topics to send based on whatever's already in the set
        let topics_to_send: Vec<Topic> = topics
            .into_iter()
            .filter(|topic| subscribed_guard.contains(topic))
            .collect();

        // Send the topics
        bail!(
            self.send_message(Message::Unsubscribe(Unsubscribe {
                topics: topics_to_send.clone()
            }))
            .await,
            Connection,
            "failed to send unsubscription message"
        );

        // Add the topics to the list if successful
        for topic in topics_to_send {
            subscribed_guard.remove(&topic);
        }

        // Drop the write guard
        drop(subscribed_guard);

        Ok(())
    }

    /// Sends a pre-formed message over the wire. Various functions make use
    /// of this one downstream.
    ///
    /// # Errors
    /// - if the downstream message sending fails.
    pub async fn send_message(&self, message: Message) -> Result<()> {
        self.0.send_message(message).await
    }
}
