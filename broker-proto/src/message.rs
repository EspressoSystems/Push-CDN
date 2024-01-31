use capnp::{
    message::ReaderOptions,
    serialize::{self, write_message_segments_to_words},
};

use crate::{
    bail,
    error::{Error, Result},
    messages_capnp::{
        self, authenticate_message, authenticate_response_message, broadcast_message,
        direct_message, subscribe_message, unsubscribe_message, Topic,
    },
};

/// This is a helper macro for deserializing `CapnProto` values.
macro_rules! deserialize {
    // Rule to deserialize a `Topic`. We need to unwrap quite a few times.
    ($func_name:expr, Topic) => {
        bail!(
            $func_name,
            DeserializeError,
            format!("failed to deserialize topic")
        )
        .into_iter()
        .filter_map(|topic| topic.ok())
        .collect()
    };

    // Rule to deserialize a `Vec<u8>`
    ($func_name:expr, Vec<u8>) => {
        bail!(
            $func_name,
            DeserializeError,
            "failed to deserialize Vec<u8>"
        )
        .to_vec()
    };

    // Rule to deserialize a `String`
    ($func_name:expr, String) => {
        bail!(
            bail!($func_name, DeserializeError, "failed to deserialize String").to_string(),
            DeserializeError,
            "failed to parse String"
        )
    };

    // A rule for prettiness that just returns the value.
    // Helpful in the case it is a `bool` or similar primitive
    ($func_name:expr) => {
        $func_name
    };
}
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
    pub fn serialize(&self) -> Result<Vec<u8>> {
        // Create a new root message, our message base
        let mut message = capnp::message::Builder::new_default();
        let root: messages_capnp::message::Builder = message.init_root();

        // Conditional logic based on what kind of message we passed in
        match self {
            Message::Authenticate(to_serialize) => {
                // Initialize a new `Authenticate` message.
                let mut message: authenticate_message::Builder = root.init_authenticate();

                // Set each field
                message.set_verification_key(&to_serialize.verification_key);
                message.set_timestamp(to_serialize.timestamp);
                message.set_signature(&to_serialize.signature);
                bail!(
                    message.set_subscribed_topics(&*to_serialize.subscribed_topics),
                    SerializeError,
                    "failed to serialize subscribed topics"
                );
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

                // Set each field
                bail!(
                    message.set_topics(&*to_serialize.topics),
                    SerializeError,
                    "failed to serialize topics"
                );
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

                // Set each field
                bail!(
                    message.set_topics(&*to_serialize.topics),
                    SerializeError,
                    "failed to serialize topics"
                );
            }

            Message::Unsubscribe(to_serialize) => {
                // Initialize a new `Subscribe` message.
                let mut message: unsubscribe_message::Builder = root.init_unsubscribe();

                // Set each field
                bail!(
                    message.set_topics(&*to_serialize.topics),
                    SerializeError,
                    "failed to serialize topics"
                );
            }
        }

        Ok(write_message_segments_to_words(&message))
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
                        verification_key: deserialize!(message.get_verification_key(), Vec<u8>),
                        timestamp: deserialize!(message.get_timestamp()),
                        signature: deserialize!(message.get_signature(), Vec<u8>),
                        subscribed_topics: deserialize!(message.get_subscribed_topics(), Topic),
                    })
                }
                messages_capnp::message::AuthenticateResponse(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");

                    Self::AuthenticateResponse(AuthenticateResponse {
                        success: deserialize!(message.get_success()),
                        reason: deserialize!(message.get_reason(), String),
                    })
                }
                messages_capnp::message::Direct(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");

                    Self::Direct(Direct {
                        recipient: deserialize!(message.get_recipient(), Vec<u8>),
                        message: deserialize!(message.get_message(), Vec<u8>),
                    })
                }
                messages_capnp::message::Broadcast(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");

                    Self::Broadcast(Broadcast {
                        topics: deserialize!(message.get_topics(), Topic),
                        message: deserialize!(message.get_message(), Vec<u8>),
                    })
                }
                messages_capnp::message::Subscribe(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");

                    Self::Subscribe(Subscribe {
                        topics: deserialize!(message.get_topics(), Topic),
                    })
                }
                messages_capnp::message::Unsubscribe(message) => {
                    let message = bail!(message, DeserializeError, "failed to deserialize message");

                    Self::Unsubscribe(Unsubscribe {
                        topics: deserialize!(message.get_topics(), Topic),
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

/// Serialization and deserialization parity tests
#[cfg(test)]
mod test {
    use super::*;

    // A macro that tests if a message, once serialized and then deserialized again,
    // is equivalent to the original message.
    macro_rules! assert_serialize_deserialize {
        ($message:expr) => {
            // Serialize message
            let serialized_message = $message.serialize().unwrap();

            // Deserialize message
            let deserialized_message =
                Message::deserialize(&serialized_message).expect("deserialization failed");

            assert!($message == deserialized_message);
        };
    }

    #[test]
    fn test_serialization_parity() {
        // `Authenticate`  message
        assert_serialize_deserialize!(Message::Authenticate(Authenticate {
            verification_key: vec![0, 1, 2],
            timestamp: 345,
            signature: vec![6, 7, 8],
            subscribed_topics: vec![Topic::Da],
        }));

        // `AuthenticateResponse` message
        assert_serialize_deserialize!(Message::AuthenticateResponse(AuthenticateResponse {
            success: true,
            reason: "1234".to_string(),
        }));

        // `Direct` message
        assert_serialize_deserialize!(Message::Direct(Direct {
            recipient: vec![0, 1, 2],
            message: vec![3, 4, 5],
        }));

        // `Broadcast` message
        assert_serialize_deserialize!(Message::Broadcast(Broadcast {
            topics: vec![Topic::Da, Topic::Global],
            message: vec![0, 1, 2],
        }));

        // `Subscribe` message
        assert_serialize_deserialize!(Message::Subscribe(Subscribe {
            topics: vec![Topic::Da, Topic::Global],
        }));

        // `Unsubscribe` message
        assert_serialize_deserialize!(Message::Unsubscribe(Unsubscribe {
            topics: vec![Topic::Da, Topic::Global],
        }));
    }
}
