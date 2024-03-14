//! In here we define an API that is a little more higher-level and ergonomic
//! for end users. It is a light wrapper on top of a `Retry` connection.

#![forbid(unsafe_code)]

pub mod reexports;
mod retry;

use cdn_proto::{
    bail,
    crypto::signature::{Serializable, SignatureScheme},
    error::{Error, Result},
    message::{Broadcast, Direct, Message, Topic},
    Def,
};
use retry::Retry;

/// `Client` is a light wrapper around a `Retry` connection that provides functions
/// for common operations to and from a server. Mostly just used to make the API
/// more ergonomic. Also keeps track of subscriptions.
#[derive(Clone)]
pub struct Client<UserDef: Def>(Retry<UserDef>);

pub type Config<UserDef> = retry::Config<UserDef>;
pub type ConfigBuilder<UserDef> = retry::ConfigBuilder<UserDef>;

impl<UserDef: Def> Client<UserDef> {
    /// Creates a new `Retry` from a configuration.
    ///
    /// # Errors
    /// If the initial connection fails
    pub async fn new(config: Config<UserDef>) -> Result<Self> {
        Ok(Self(bail!(
            Retry::from_config(config).await,
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
    /// of a vector of topics. If it fails, we return an error but try to initiate a new connection
    /// in the background.
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn send_broadcast_message(&self, topics: Vec<Topic>, message: Vec<u8>) -> Result<()> {
        // Form and send the single message
        self.send_message(Message::Broadcast(Broadcast { topics, message }))
            .await
    }

    /// Sends a pre-serialized message to the server, denoting interest in delivery
    /// to a single recipient.
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn send_direct_message(
        &self,
        recipient: &<UserDef::SignatureScheme as SignatureScheme>::PublicKey,
        message: Vec<u8>,
    ) -> Result<()> {
        // Serialize recipient to a byte array before sending the message
        // TODO: maybe we can cache this.
        let recipient_bytes = bail!(
            recipient.serialize(),
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
    pub async fn subscribe(&self, topics: Vec<Topic>) -> Result<()> {
        // Lock subscriptions here so we maintain parity during a reconnection
        let mut subscribed_guard = self.0.inner.subscribed_topics.write().await;

        // Calculate the real topics to send based on whatever's already in the set
        let topics_to_send: Vec<Topic> = topics
            .into_iter()
            .filter(|topic| !subscribed_guard.contains(topic))
            .collect();

        // Send the topics
        bail!(
            self.send_message(Message::Subscribe(topics_to_send.clone()))
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
        let mut subscribed_guard = self.0.inner.subscribed_topics.write().await;

        // Calculate the real topics to send based on whatever's already in the set
        let topics_to_send: Vec<Topic> = topics
            .into_iter()
            .filter(|topic| subscribed_guard.contains(topic))
            .collect();

        // Send the topics
        bail!(
            self.send_message(Message::Unsubscribe(topics_to_send.clone()))
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

    /// Sends a message over the wire. Various functions make use
    /// of this one upstream.
    ///
    /// # Errors
    /// - if the downstream message sending fails.
    pub async fn send_message(&self, message: Message) -> Result<()> {
        self.0.send_message(message).await
    }
}
