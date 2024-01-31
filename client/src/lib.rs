//! In here we define an API that is a little more higher-level and ergonomic
//! for end users. It is a light wrapper on top of a `Sticky` connection.

use std::sync::Arc;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use proto::{
    bail,
    connection::{sticky::Sticky, Connection as ProtoConnection},
    crypto,
    error::Error,
    error::Result,
    message::{Broadcast, Direct, Message, Subscribe, Topic, Unsubscribe},
};
use tokio::sync::OnceCell;

/// `Client` is a light wrapper around a `Sticky` connection that provides functions
/// for common operations to and from a server. Mostly just used to make the API
/// more ergonomic.
pub struct Client<SignatureScheme: JfSignatureScheme, Connection: ProtoConnection>(
    Sticky<SignatureScheme, Connection>,
);

pub type Config<SignatureScheme, Connection> =
    proto::connection::sticky::Config<SignatureScheme, Connection>;

impl<SignatureScheme: JfSignatureScheme, Connection: ProtoConnection>
    Client<SignatureScheme, Connection>
where
    SignatureScheme::Signature: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::VerificationKey: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::SigningKey: CanonicalSerialize + CanonicalDeserialize,
{
    /// Creates a new client from the given `Config`. Does not attempt a connection until
    /// a function is called that requires one. Proxies to `new_with_connection` but with an
    /// empty connection.
    ///
    /// # Errors
    /// Errors if the downstream `Sticky` object was unable to be made.
    /// This usually happens when we can't bind to the specified endpoint.
    pub fn new(config: Config<SignatureScheme, Connection>) -> Result<Self> {
        Self::new_with_connection(config, OnceCell::new())
    }

    /// Creates a new client from the given `Config` and an optional `Connection`.
    /// Proxies the config to the `Sticky` constructor since a `Client` is just a
    /// light wrapper.
    ///
    /// # Errors
    /// Errors if the downstream `Sticky` object was unable to be made.
    /// This usually happens when we can't bind to the specified endpoint.
    pub fn new_with_connection(
        config: Config<SignatureScheme, Connection>,
        connection: OnceCell<Connection>,
    ) -> Result<Self> {
        Ok(Client(bail!(
            Sticky::from_config_and_connection(config, connection),
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
    /// of a vector of topics. Use `send_formed_message` when the message is already
    /// formed. If it fails, we return an error but try to initiate a new connection
    /// in the background.
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn send_broadcast_message(&self, topics: Vec<Topic>, message: Vec<u8>) -> Result<()> {
        // TODO: conditionally match error on whether deserialization OR the connection failed
        // Form and send the single message
        bail!(
            self.send_formed_message(Arc::from(Message::Broadcast(Broadcast { topics, message })))
                .await,
            Connection,
            "failed to send message"
        );

        Ok(())
    }

    /// Sends a pre-serialized message to the server, denoting interest in delivery
    /// to a single recipient. Use `send_formed_message` when the message is already formed.
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

        // Send the message with the serialized recipient
        self.send_formed_message(Arc::from(Message::Direct(Direct {
            recipient: recipient_bytes,
            message,
        })))
        .await;

        Ok(())
    }

    /// Sends a message to the server that asserts that this client is interested in
    /// a specific topic
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn subscribe(&self, topics: Vec<Topic>) {
        self.send_formed_message(Arc::from(Message::Subscribe(Subscribe { topics })))
            .await;
    }

    /// Sends a message to the server that asserts that this client is no longer
    /// interested in a specific topic
    ///
    /// # Errors
    /// If the connection or serialization has failed
    pub async fn unsubscribe(&self, topics: Vec<Topic>) {
        self.send_formed_message(Arc::from(Message::Unsubscribe(Unsubscribe { topics })))
            .await;
    }

    /// Sends a pre-formed message over the wire. Various functions make use
    /// of this one downstream.
    ///
    /// TODO: make this generic over a borrowed message so we can pass in either
    /// a reference or an Arc to the object itself
    pub async fn send_formed_message(&self, message: Arc<Message>) -> Result<()> {
        // self.0.send_message(message).await;
        todo!()
    }
}
