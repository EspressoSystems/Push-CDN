use capnp::{message::ReaderOptions, serialize};

use crate::{
    bail,
    error::{Error, Result},
    messages_capnp::{
        self, authenticate_message, authenticate_response_message, broadcast_message,
        direct_message, subscribe_message, unsubscribe_message,
    },
};

/// A wrapper for all message types. Allows us to match on a specific message type
/// downstream. Uses a zero-copy serialization and deserialization framework.
#[derive(PartialEq)]
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
    pub fn serialize(&self) -> Vec<u8> {
        // Create a new root message, our message base
        let mut message = capnp::message::Builder::new_default();
        let root: messages_capnp::message::Builder = message.init_root();

        // Conditional logic based on what kind of message we passed in
        match self {
            Message::Authenticate(to_serialize) => {
                // Initialize a new `Authenticate` message.
                let mut message: authenticate_message::Builder = root.init_authenticate();

                // Transform topics to the CapnProto type
                let transformed_topics: Vec<messages_capnp::Topic> = to_serialize
                    .subscribed_topics
                    .clone()
                    .into_iter()
                    .map(|item| messages_capnp::Topic::from(item))
                    .collect();

                // Set each field
                message.set_verification_key(&to_serialize.verification_key);
                message.set_timestamp(to_serialize.timestamp);
                message.set_signature(&to_serialize.signature);
                message
                    .set_subscribed_topics(&*transformed_topics)
                    .expect("failed to serialize topics")
            }

            Message::AuthenticateResponse(to_serialize) => {
                // Initialize a new `AuthenticateResponse` message.
                let mut message: authenticate_response_message::Builder =
                    root.init_authenticate_response();

                // Set each field
                message.set_success(to_serialize.success);
                message.set_reason(to_serialize.reason.clone());
            }

            Message::Broadcast(to_serialize) => {
                // Initialize a new `Broadcast` message.
                let mut message: broadcast_message::Builder = root.init_broadcast();

                // Transform topics to the CapnProto type
                let transformed_topics: Vec<messages_capnp::Topic> = to_serialize
                    .topics
                    .clone()
                    .into_iter()
                    .map(|item| messages_capnp::Topic::from(item))
                    .collect();

                // Set each field
                message
                    .set_topics(&*transformed_topics)
                    .expect("failed to serialize topics");
                message.set_message(&to_serialize.message);
            }

            Message::Direct(to_serialize) => {
                // Initialize a new `Direct` message.
                let mut message: direct_message::Builder = root.init_direct();

                // Set each field
                message.set_recipient(&to_serialize.recipient);
                message.set_message(&to_serialize.message);
            }

            Message::Subscribe(to_serialize) => {
                // Initialize a new `Subscribe` message.
                let mut message: subscribe_message::Builder = root.init_subscribe();

                // Transform topics to the CapnProto type
                let transformed_topics: Vec<messages_capnp::Topic> = to_serialize
                    .topics
                    .clone()
                    .into_iter()
                    .map(|item| messages_capnp::Topic::from(item))
                    .collect();

                // Set each field
                message
                    .set_topics(&*transformed_topics)
                    .expect("failed to serialize topics")
            }

            Message::Unsubscribe(to_serialize) => {
                // Initialize a new `Subscribe` message.
                let mut message: unsubscribe_message::Builder = root.init_unsubscribe();

                // Transform topics to the CapnProto type
                let transformed_topics: Vec<messages_capnp::Topic> = to_serialize
                    .topics
                    .clone()
                    .into_iter()
                    .map(|item| messages_capnp::Topic::from(item))
                    .collect();

                // Set each field
                message
                    .set_topics(&*transformed_topics)
                    .expect("failed to serialize topics")
            }
        }

        serialize::write_message_segments_to_words(&message)
    }

    /// `deserialize` is used to deserialize a message. It returns a
    /// message from a byte array, or the error if applicable.
    ///
    /// # Errors
    /// Errors if the downstream deserialization fails or
    /// if the message was deemed invalid when checked.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        // Create reader
        let reader = bail!(
            serialize::read_message(bytes, ReaderOptions::new()),
            DeserializeError,
            "failed to create reader"
        );

        // Deserialize message from reader
        let message = bail!(
            reader.get_root::<messages_capnp::message::Reader>(),
            DeserializeError,
            "failed to deserialize message"
        );

        // Switch based on which message we see
        Ok(
            match bail!(message.which(), DeserializeError, "message not in schema") {
                messages_capnp::message::Authenticate(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");
                    Self::Authenticate(Authenticate {
                        verification_key: bail!(
                            message.get_verification_key(),
                            DeserializeError,
                            "failed to deserialize verification key"
                        )
                        .to_vec(),
                        timestamp: message.get_timestamp(),
                        signature: bail!(
                            message.get_signature(),
                            DeserializeError,
                            "failed to deserialize signature key"
                        )
                        .to_vec(),
                        subscribed_topics: bail!(
                            message.get_subscribed_topics(),
                            DeserializeError,
                            "failed to deserialize subscribed topics"
                        )
                        .into_iter()
                        .map(|topic| topic.unwrap().into())
                        .collect(),
                    })
                }
                messages_capnp::message::AuthenticateResponse(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");
                    Self::AuthenticateResponse(AuthenticateResponse {
                        success: message.get_success(),
                        reason: bail!(
                            bail!(
                                message.get_reason(),
                                DeserializeError,
                                "failed to deserialize reason"
                            )
                            .to_string(),
                            DeserializeError,
                            "failed to deserialize string"
                        ),
                    })
                }
                messages_capnp::message::Direct(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");
                    Self::Direct(Direct {
                        recipient: bail!(
                            message.get_recipient(),
                            DeserializeError,
                            "failed to deserialize recipient"
                        )
                        .to_vec(),
                        message: bail!(
                            message.get_message(),
                            DeserializeError,
                            "failed to deserialize message"
                        )
                        .to_vec(),
                    })
                }
                messages_capnp::message::Broadcast(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");

                    Self::Broadcast(Broadcast {
                        topics: bail!(
                            message.get_topics(),
                            DeserializeError,
                            "failed to deserialize topics"
                        )
                        .into_iter()
                        .map(|topic| topic.unwrap().into())
                        .collect(),
                        message: bail!(
                            message.get_message(),
                            DeserializeError,
                            "failed to deserialize message"
                        )
                        .to_vec(),
                    })
                }
                messages_capnp::message::Subscribe(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");

                    Self::Subscribe(Subscribe {
                        topics: bail!(
                            message.get_topics(),
                            DeserializeError,
                            "failed to deserialize topics"
                        )
                        .into_iter()
                        .map(|topic| topic.unwrap().into())
                        .collect(),
                    })
                }
                messages_capnp::message::Unsubscribe(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");

                    Self::Unsubscribe(Unsubscribe {
                        topics: bail!(
                            message.get_topics(),
                            DeserializeError,
                            "failed to deserialize topics"
                        )
                        .into_iter()
                        .map(|topic| topic.unwrap().into())
                        .collect(),
                    })
                }
            },
        )
    }
}

/// This message is used to authenticate the client to a server. It contains a
/// list of subscriptions, along with a way of proving identity of the sender.
#[derive(PartialEq)]
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
#[derive(PartialEq)]
pub struct AuthenticateResponse {
    /// If authentication was successful or not
    pub success: bool,
    /// The reason authentication was unsuccessful, if applicable
    pub reason: String,
}

/// This message is a direct message. It is sent by a client, used to deliver a
/// message to only the intended recipient.
#[derive(PartialEq)]
pub struct Direct {
    // The recipient to send the message to
    pub recipient: Vec<u8>,
    // The actual message data
    pub message: Vec<u8>,
}

/// This message is a broadcast message. It is sent by a client, used to deliver a
/// message to all recipients who are interested in a topic. Uses the passed
/// vector of topics to denote interest.
#[derive(PartialEq)]
pub struct Broadcast {
    // The topics to sent the message to
    pub topics: Vec<Topic>,
    // The actual message data
    pub message: Vec<u8>,
}

/// A message that is used to convey interest in some particular topic(s).
#[derive(PartialEq)]
pub struct Subscribe {
    // The topics interested in
    pub topics: Vec<Topic>,
}

/// A message that is used to convey disinterest in some particular topic(s).
#[derive(PartialEq)]
pub struct Unsubscribe {
    // The topics uninterested in
    pub topics: Vec<Topic>,
}

/// An enum for users to specify topics for subscription and unsubscription.
/// Also used on the sending side, where messages can be marked with
/// a topic and propagated to the interested users.
#[derive(Clone, PartialEq)]
pub enum Topic {
    /// The global consensus topic. All conseneus participants should be subscribed
    /// to this.
    Global,
    /// The DA-specfic topic. Only participants in the DA committee should want to
    /// be subscribed to this.
    DA,
}

/// We need this to convert our `Topic` to/from the CapnProto `Topic` primitive.
impl From<Topic> for messages_capnp::Topic {
    fn from(value: Topic) -> Self {
        // Just a simple match statement. Is non-exhaustive.
        match value {
            Topic::Global => messages_capnp::Topic::Global,
            Topic::DA => messages_capnp::Topic::Da,
        }
    }
}

/// We need this to convert our `Topic` to/from the CapnProto `Topic` primitive.
impl From<messages_capnp::Topic> for Topic {
    fn from(value: messages_capnp::Topic) -> Self {
        // Just a simple match statement. Is non-exhaustive.
        match value {
            messages_capnp::Topic::Da => Topic::DA,
            messages_capnp::Topic::Global => Topic::Global,
        }
    }
}

/// Serialization and deserialization parity tests
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serialization_parity() {
        // `Authenticate`` message
        {
            let original_message = Message::Authenticate(Authenticate {
                verification_key: vec![0, 1, 2],
                timestamp: 345,
                signature: vec![6, 7, 8],
                subscribed_topics: vec![Topic::DA],
            });

            // Serialize message
            let serialized_message = original_message.serialize();

            // Deserialize message
            let deserialized_message =
                Message::deserialize(&serialized_message).expect("deserialization failed");

            assert!(original_message == deserialized_message);
        }

        // `AuthenticateResponse` message
        {
            let original_message = Message::AuthenticateResponse(AuthenticateResponse {
                success: true,
                reason: "1234".to_string(),
            });

            // Serialize message
            let serialized_message = original_message.serialize();

            // Deserialize message
            let deserialized_message =
                Message::deserialize(&serialized_message).expect("deserialization failed");

            assert!(original_message == deserialized_message)
        }

        // `Direct` message
        {
            let original_message = Message::Direct(Direct {
                recipient: vec![0, 1, 2],
                message: vec![3, 4, 5],
            });

            // Serialize message
            let serialized_message = original_message.serialize();

            // Deserialize message
            let deserialized_message =
                Message::deserialize(&serialized_message).expect("deserialization failed");

            assert!(original_message == deserialized_message)
        }

        {
            // `Broadcast` message
            let original_message = Message::Broadcast(Broadcast {
                topics: vec![Topic::DA, Topic::Global],
                message: vec![0, 1, 2],
            });

            // Serialize message
            let serialized_message = original_message.serialize();

            // Deserialize message
            let deserialized_message =
                Message::deserialize(&serialized_message).expect("deserialization failed");

            assert!(original_message == deserialized_message)
        }

        {
            // `Subscribe` message
            let original_message = Message::Subscribe(Subscribe {
                topics: vec![Topic::DA, Topic::Global],
            });

            // Serialize message
            let serialized_message = original_message.serialize();

            // Deserialize message
            let deserialized_message =
                Message::deserialize(&serialized_message).expect("deserialization failed");

            assert!(original_message == deserialized_message)
        }

        {
            // `Unsubscribe` message
            let original_message = Message::Unsubscribe(Unsubscribe {
                topics: vec![Topic::DA, Topic::Global],
            });

            // Serialize message
            let serialized_message = original_message.serialize();

            // Deserialize message
            let deserialized_message =
                Message::deserialize(&serialized_message).expect("deserialization failed");

            assert!(original_message == deserialized_message)
        }
    }
}
