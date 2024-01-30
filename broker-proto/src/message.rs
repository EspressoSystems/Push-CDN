use crate::{error::Result, messages_capnp};

/// A wrapper for all message types. Allows us to match on a specific message type
/// downstream. Uses a zero-copy serialization and deserialization framework.
pub enum Message {
    /// The wrapper for an `Authenticate` message
    Authenticate(Authenticate),
    /// The wrapper for an `AuthenticateResponse` message
    AuthenticateResponse(AuthenticateResponse),

    /// The wrapper for a `Direct` message
    Direct(Direct),
    /// The wrapper for a `Broadcast` message
    Broadcast(Broadcast),

    /// The wrapper for an `Subscribe` message
    Subscribe(Subscribe),
    /// The wrapper for an `Unsubscribe` message
    Unsubscribe(Unsubscribe),
}

impl Message {
    /// `serialize` is used to serialize a message. It returns a
    /// byte array of the serialized message, or an error if there was one.
    ///
    /// # Errors
    /// Errors if the downstream serialization fails.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let message = capnp::message::Builder::new_default();
        let mut root: messages_capnp::message::Builder = message.init_root();

        match self {
            Message::Authenticate(to_serialize) => {
                // Initialize a new `Authenticate` message.
                let mut authenticate_message: messages_capnp::authenticate_message::Builder =
                    root.init_authenticate();

                // Convert each topic to the CapnProto enum equivalent
                let mut serialized_topics = Vec::new();
                for topic in to_serialize.subscribed_topics {
                    match topic {
                        Topic::DA => serialized_topics.push(messages_capnp::Topic::Da),
                        Topic::Global => serialized_topics.push(messages_capnp::Topic::Global),
                    }
                }

                // Set each field
                authenticate_message.set_signature(&to_serialize.signature);
                authenticate_message.set_subscribed_topics(serialized_topics.into());
                authenticate_message.set_signature(&to_serialize.signature);
            }
        }


        ()
    }

    /// `deserialize` is used to deserialize a message. It returns a
    /// message from a byte array, or the error if applicable.
    ///
    /// # Errors
    /// Errors if the downstream deserialization fails or
    /// if the message was deemed invalid when checked.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {}
}

/// This message is used to authenticate the client to a server. It contains a
/// list of subscriptions, along with a way of proving identity of the sender.
pub struct Authenticate {
    /// The verification key, used downstream against the signed timestamp to verify the sender.
    pub verification_key: Vec<u8>,
    /// The timestamp, unsigned. This is signed by the client to prevent replay attacks.
    pub timestamp: u64,
    /// The signature, which is the timestamp, but signed.
    pub signature: Vec<u8>,
    /// The initial topics to subscribe to on the new connection.
    pub subscribed_topics: Vec<Topic>,
}

/// This message is sent to the client upon authentication. It contains
/// if it was successful or not, and the reason.
pub struct AuthenticateResponse {
    /// If authentication was successful or not
    pub success: bool,
    /// The reason authentication was unsuccessful, if applicable
    pub reason: String,
}

/// This message is a direct message. It is sent by a client, used to deliver a
/// message to only the intended recipient.
pub struct Direct {
    // The recipient to send the message to
    pub recipient: Vec<u8>,
    // The actual message data
    pub message: Vec<u8>,
}

/// This message is a broadcast message. It is sent by a client, used to deliver a
/// message to all recipients who are interested in a topic. Uses the passed
/// vector of topics to denote interest.
pub struct Broadcast {
    // The topics to sent the message to
    pub topics: Vec<Topic>,
    // The actual message data
    pub message: Vec<u8>,
}

/// A message that is used to convey interest in some particular topic(s).
pub struct Subscribe {
    // The topics interested in
    pub topics: Vec<Topic>,
}

/// A message that is used to convey disinterest in some particular topic(s).
pub struct Unsubscribe {
    // The topics uninterested in
    pub topics: Vec<Topic>,
}

/// An enum for users to specify topics for subscription and unsubscription.
/// Also used on the sending side, where messages can be marked with
/// a topic and propagated to the interested users.
pub enum Topic {
    /// The global consensus topic. All conseneus participants should be subscribed
    /// to this.
    Global,
    /// The DA-specfic topic. Only participants in the DA committee should want to
    /// be subscribed to this.
    DA,
}
