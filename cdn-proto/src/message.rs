// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! The message serialization and deserialization layer. Used by all
//! messages sent to/from a broker or user.
//! TODO: clean up. Maybe use Cap'n'Proto messages directly.

use capnp::{
    message::ReaderOptions,
    serialize::{self, write_message_segments_to_words},
};

use crate::{
    bail,
    error::{Error, Result},
    messages_capnp::{
        self, authenticate_response, authenticate_with_key, authenticate_with_permit, broadcast,
        direct,
    },
};

/// A type alias for a `Topic` to disambiguate it from `Vec<u8>`
pub type Topic = u8;

/// This is a helper macro for serializing `CapnProto` values.
macro_rules! serialize {
    // Rule to serialize a `Topic`.
    ($object:expr, Topic) => {
        $object.into_iter().map(|topic| topic.into()).collect()
    };
}

macro_rules! checked_to_u32 {
    ($from: expr) => {
        bail!(u32::try_from($from), Deserialize, "failed to try from u32")
    };
}

/// This is a helper macro for deserializing `CapnProto` values.
macro_rules! deserialize {
    // Rule to deserialize a `Topic`. We need to unwrap quite a few times.
    ($func_name:expr, Vec<Topic>) => {
        $func_name.into_iter().map(|topic| topic.into()).collect()
    };

    ($message: expr, List) => {{
        let mut deserialized_list = Vec::new();

        for i in 0..$message.len() {
            let item = try_get!($message, i);
            deserialized_list.push(item.into());
        }

        deserialized_list
    }};

    // Rule to deserialize a `Vec<u8>`
    ($func_name:expr, Vec<u8>) => {
        bail!($func_name, Deserialize, "failed to deserialize Vec<u8>").to_vec()
    };

    // Rule to deserialize a `String`
    ($func_name:expr, String) => {
        bail!(
            bail!($func_name, Deserialize, "failed to deserialize String").to_string(),
            Deserialize,
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
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Message {
    /// The wrapper for a `AuthenticateWithKey` message
    AuthenticateWithKey(AuthenticateWithKey),
    /// The wrapper for an `AuthenticateWithPermit` message
    AuthenticateWithPermit(AuthenticateWithPermit),
    /// The wrapper for an `AuthenticateResponse` message
    AuthenticateResponse(AuthenticateResponse),

    /// The wrapper for a `Direct` message
    Direct(Direct),
    /// The wrapper for a `Broadcast` message
    Broadcast(Broadcast),

    /// The wrapper for an `Subscribe` message
    Subscribe(Vec<Topic>),
    /// The wrapper for an `Unsubscribe` message
    Unsubscribe(Vec<Topic>),

    /// A message containing a map which we use to converge on user connection state
    UserSync(Vec<u8>),
    /// A message containing a map which we use to converge on subscribed topic state
    TopicSync(Vec<u8>),
}

impl Message {
    /// `serialize` is used to serialize a message. It returns a
    /// byte array of the serialized message, or an error if there was one.
    ///
    /// # Errors
    /// Errors if the downstream serialization fails.
    ///
    /// # Panics
    /// If we can't cast from a usize to a u32
    pub fn serialize(&self) -> Result<Vec<u8>> {
        // Create a new root message, our message base
        let mut default_message = capnp::message::Builder::new_default();
        let mut root: messages_capnp::message::Builder = default_message.init_root();

        // Conditional logic based on what kind of message we passed in
        match self {
            Self::AuthenticateWithKey(to_serialize) => {
                // Initialize a new `Authenticate` message.
                let mut message: authenticate_with_key::Builder = root.init_authenticate_with_key();

                // Set each field
                message.set_public_key(&to_serialize.public_key);
                message.set_timestamp(to_serialize.timestamp);
                message.set_signature(&to_serialize.signature);
            }

            Self::AuthenticateWithPermit(to_serialize) => {
                // Initialize a new `Authenticate` message.
                let mut message: authenticate_with_permit::Builder =
                    root.init_authenticate_with_permit();

                // Set each field
                message.set_permit(to_serialize.permit);
            }

            Self::AuthenticateResponse(to_serialize) => {
                // Initialize a new `AuthenticateResponse` message.
                let mut message: authenticate_response::Builder = root.init_authenticate_response();

                // Set each field
                message.set_permit(to_serialize.permit);
                message.set_context(to_serialize.context.clone());
            }

            Self::Broadcast(to_serialize) => {
                // Initialize a new `Broadcast` message.
                let mut message: broadcast::Builder = root.init_broadcast();

                // Serialize topics
                let serialized_topics: Vec<Topic> = serialize!(to_serialize.topics.clone(), Topic);

                // Set each field
                bail!(
                    message.set_topics(&*serialized_topics),
                    Serialize,
                    "failed to serialize topics"
                );
                message.set_message(&to_serialize.message);
            }

            Self::Direct(to_serialize) => {
                // Initialize a new `Direct` message.
                let mut message: direct::Builder = root.init_direct();

                // Set each field
                message.set_recipient(&to_serialize.recipient);
                message.set_message(&to_serialize.message);
            }

            Self::Subscribe(to_serialize) => {
                // Initialize a new `Subscribe` message.
                let mut message = root.init_subscribe(checked_to_u32!(to_serialize.len()));

                for (i, topic) in to_serialize.iter().enumerate() {
                    message.set(checked_to_u32!(i), *topic);
                }
            }

            Self::Unsubscribe(to_serialize) => {
                // Initialize a new `Subscribe` message.
                let mut message = root.init_unsubscribe(checked_to_u32!(to_serialize.len()));

                for (i, topic) in to_serialize.iter().enumerate() {
                    message.set(checked_to_u32!(i), *topic);
                }
            }

            Self::UserSync(to_serialize) => {
                root.set_user_sync(to_serialize);
            }

            Self::TopicSync(to_serialize) => {
                root.set_topic_sync(to_serialize);
            }
        }

        Ok(write_message_segments_to_words(&default_message))
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
            serialize::read_message(
                bytes,
                *ReaderOptions::new().traversal_limit_in_words(Some(bytes.len()))
            ),
            Deserialize,
            "failed to create reader"
        );

        // Deserialize message from reader
        let message = bail!(
            reader.get_root::<messages_capnp::message::Reader>(),
            Deserialize,
            "failed to deserialize message"
        );

        // Switch based on which message we see
        Ok(
            match bail!(message.which(), Deserialize, "message not in schema") {
                messages_capnp::message::AuthenticateWithKey(maybe_message) => {
                    let message =
                        bail!(maybe_message, Deserialize, "failed to deserialize message");

                    Self::AuthenticateWithKey(AuthenticateWithKey {
                        public_key: deserialize!(message.get_public_key(), Vec<u8>),
                        timestamp: deserialize!(message.get_timestamp()),
                        signature: deserialize!(message.get_signature(), Vec<u8>),
                    })
                }
                messages_capnp::message::AuthenticateWithPermit(maybe_message) => {
                    let message =
                        bail!(maybe_message, Deserialize, "failed to deserialize message");

                    Self::AuthenticateWithPermit(AuthenticateWithPermit {
                        permit: deserialize!(message.get_permit()),
                    })
                }
                messages_capnp::message::AuthenticateResponse(maybe_message) => {
                    let message =
                        bail!(maybe_message, Deserialize, "failed to deserialize message");

                    Self::AuthenticateResponse(AuthenticateResponse {
                        permit: deserialize!(message.get_permit()),
                        context: deserialize!(message.get_context(), String),
                    })
                }
                messages_capnp::message::Direct(maybe_message) => {
                    let message =
                        bail!(maybe_message, Deserialize, "failed to deserialize message");

                    Self::Direct(Direct {
                        recipient: deserialize!(message.get_recipient(), Vec<u8>),
                        message: deserialize!(message.get_message(), Vec<u8>),
                    })
                }
                messages_capnp::message::Broadcast(maybe_message) => {
                    let message =
                        bail!(maybe_message, Deserialize, "failed to deserialize message");

                    let topics = bail!(
                        message.get_topics(),
                        Deserialize,
                        "failed to deserialize topics"
                    );

                    Self::Broadcast(Broadcast {
                        topics: deserialize!(topics, Vec<Topic>),
                        message: deserialize!(message.get_message(), Vec<u8>),
                    })
                }
                messages_capnp::message::Subscribe(maybe_message) => {
                    let message =
                        bail!(maybe_message, Deserialize, "failed to deserialize message");

                    Self::Subscribe(deserialize!(message, Vec<Topic>))
                }
                messages_capnp::message::Unsubscribe(maybe_message) => {
                    let message =
                        bail!(maybe_message, Deserialize, "failed to deserialize message");

                    Self::Unsubscribe(deserialize!(message, Vec<Topic>))
                }

                messages_capnp::message::UserSync(maybe_message) => {
                    let message =
                        bail!(maybe_message, Deserialize, "failed to deserialize message");

                    Self::UserSync(message.to_vec())
                }

                messages_capnp::message::TopicSync(maybe_message) => {
                    let message =
                        bail!(maybe_message, Deserialize, "failed to deserialize message");

                    Self::TopicSync(message.to_vec())
                }
            },
        )
    }
}

/// This message is used to authenticate the client to a marshal or a broker
/// to a broker. It contains a way of proving identity of the sender.
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct AuthenticateWithKey {
    // The public verification key, used downstream against the signed timestamp to verify the sender.
    pub public_key: Vec<u8>,
    // The timestamp, unsigned. This is signed by the client to prevent replay attacks.
    pub timestamp: u64,
    // The signature, which is the timestamp, but signed.
    pub signature: Vec<u8>,
}

/// This message is used to authenticate the client to a server. It contains the permit
/// issued by the marshal.
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct AuthenticateWithPermit {
    // The permit issued by the marshal, if applicable.
    pub permit: u64,
}

/// This message is sent to the client or broker upon authentication. It contains
/// if it was successful or not, the context, and the permit, if applicable.
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct AuthenticateResponse {
    // The permit. Sent from servers to clients to verify authentication. Is `0`
    // if failed, `1` if successful, and neither if it is an actual permit.
    pub permit: u64,
    // The message context. Is an error reason if failed, or the endpoint
    // if successful.
    pub context: String,
}

/// This message is a direct message. It is sent by a client, used to deliver a
/// message to only the intended recipient.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Direct {
    // The recipient to send the message to
    pub recipient: Vec<u8>,
    // The actual message data
    pub message: Vec<u8>,
}

/// This message is a broadcast message. It is sent by a client, used to deliver a
/// message to all recipients who are interested in a topic. Uses the passed
/// vector of topics to denote interest.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Broadcast {
    // The topics to sent the message to
    pub topics: Vec<Topic>,
    // The actual message data
    pub message: Vec<u8>,
}

/// A message that is used to convey interest in some particular topic(s).
#[derive(PartialEq, Eq, Debug)]
pub struct Subscribe {
    // The topics interested in
    pub topics: Vec<Topic>,
}

/// A message that is used to convey disinterest in some particular topic(s).
#[derive(PartialEq, Eq, Debug)]
pub struct Unsubscribe {
    // The topics uninterested in
    pub topics: Vec<Topic>,
}

/// A message that is used to convey to other brokers that user(s) have connected to us.
#[derive(PartialEq, Eq, Debug)]
pub struct UsersConnected {
    // The users connected to us
    pub users: Vec<Vec<u8>>,
}

/// A message that is used to convey to other brokers that user(s) have disconnected from us.
#[derive(PartialEq, Eq, Debug)]
pub struct UsersDisconnected {
    // The users that have disconnected from us
    pub users: Vec<Vec<u8>>,
}

/// Serialization and deserialization parity tests
#[cfg(test)]
mod tests {
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
        // `AuthenticateWithKey`  message
        assert_serialize_deserialize!(Message::AuthenticateWithKey(AuthenticateWithKey {
            public_key: vec![0, 1, 2],
            timestamp: 345,
            signature: vec![6, 7, 8],
        }));

        // `AuthenticateWithPermit`  message
        assert_serialize_deserialize!(Message::AuthenticateWithPermit(AuthenticateWithPermit {
            permit: 1234,
        }));

        // `AuthenticateResponse` message
        assert_serialize_deserialize!(Message::AuthenticateResponse(AuthenticateResponse {
            permit: 1234,
            context: "1234".to_string(),
        }));

        // `Direct` message
        assert_serialize_deserialize!(Message::Direct(Direct {
            recipient: vec![0, 1, 2],
            message: vec![3, 4, 5],
        }));

        // `Broadcast` message
        assert_serialize_deserialize!(Message::Broadcast(Broadcast {
            topics: vec![0, 1, 99],
            message: vec![0, 1, 2],
        }));

        // `Subscribe` message
        assert_serialize_deserialize!(Message::Subscribe(vec![0, 1, 99]));

        // `Unsubscribe` message
        assert_serialize_deserialize!(Message::Unsubscribe(vec![0, 1, 99]));

        // `UserSync` message
        assert_serialize_deserialize!(Message::UserSync(vec![0u8, 1u8]));
    }
}
