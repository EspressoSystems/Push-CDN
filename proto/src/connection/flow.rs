//! This file defines the connection and authentication flows to be used when connecting
//! and reconnecting. We need this because it allows us to have the same connection code,
//! but with different connection and authentication methods. For example, broker <-> broker
//! is different from user <-> broker.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use crate::{
    bail,
    crypto::{self, DeterministicRng},
    error::{Error, Result},
    message::{AuthenticateWithKey, AuthenticateWithPermit, Message, Subscribe, Topic},
};

use super::protocols::Protocol;
use crate::connection::protocols::Connection;

/// TODO: BIDIRECTIONAL AUTHENTICATION FOR USERS<->BROKERS
///
/// The `Flow` trait implements a connection flow that takes in an endpoint,
/// signing key, and verification key and returns a connection.
#[async_trait]
pub trait Flow<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
>: Send + Sync
{
    /// This is the meat of `Flow`. We define this for every type of connection flow we have.
    async fn connect(
        endpoint: String,
        signing_key: &SignatureScheme::SigningKey,
        verification_key: &SignatureScheme::VerificationKey,
        subscribed_topics: Vec<Topic>,
    ) -> Result<ProtocolType::Connection>;
}

/// This struct implements `Flow`. It defines an implementation wherein we connect
/// to a marshal first, who returns the server address we should connect to, along
/// with a permit. Only after that do we try connecting to the broker.
pub struct ToMarshal {}

#[async_trait]
impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > Flow<SignatureScheme, ProtocolType> for ToMarshal
where
    SignatureScheme::Signature: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::VerificationKey: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::SigningKey: CanonicalSerialize + CanonicalDeserialize,
{
    /// The steps on `ToMarshal`'s connection:
    /// 1. Authenticate with the marshal with a signed message, who optionally
    ///     returns a permit and a server address
    /// 2. Use the permit and server address to connect to the broker
    async fn connect(
        endpoint: String,
        signing_key: &SignatureScheme::SigningKey,
        verification_key: &SignatureScheme::VerificationKey,
        subscribed_topics: Vec<Topic>,
    ) -> Result<ProtocolType::Connection> {
        // Create the initial connection, which is unauthenticated at this point
        let connection = bail!(
            ProtocolType::Connection::connect(endpoint).await,
            Connection,
            "failed to connect to marshal"
        );

        // Get the current timestamp, which we sign to avoid replay attacks
        let timestamp = bail!(
            SystemTime::now().duration_since(UNIX_EPOCH),
            Parse,
            "failed to get timestamp: time went backwards"
        )
        .as_secs();

        // Sign the timestamp from above
        let signature = bail!(
            SignatureScheme::sign(
                &(),
                signing_key,
                timestamp.to_le_bytes(),
                &mut DeterministicRng(0),
            ),
            Crypto,
            "failed to sign message"
        );

        // Serialize the verify key
        let verification_key_bytes = bail!(
            crypto::serialize(verification_key),
            Serialize,
            "failed to serialize verification key"
        );

        // Serialize the signature
        let signature_bytes = bail!(
            crypto::serialize(&signature),
            Serialize,
            "failed to serialize signature"
        );

        // We authenticate to the marshal with a key
        let authenticate_with_marshal = Message::AuthenticateWithKey(AuthenticateWithKey {
            timestamp,
            verification_key: verification_key_bytes,
            signature: signature_bytes,
        });

        // Create and send the authentication message from the above operations
        bail!(
            connection
                .send_message(Arc::from(authenticate_with_marshal))
                .await,
            Connection,
            "failed to auth message to marshal"
        );

        // Wait for the response with the permit and address
        let marshal_response = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from marshal"
        );

        // Make sure the message is the proper type
        let (broker_address, permit) =
            if let Message::AuthenticateResponse(response) = marshal_response {
                // Check if we have received an actual permit
                if response.permit > 1 {
                    // We have received an actual permit
                    (response.context, response.permit)
                } else {
                    // We haven't, we failed authentication :(
                    // TODO: fix these error types
                    return Err(Error::Authentication(format!(
                        "failed authentication: {}",
                        response.context
                    )));
                }
            } else {
                return Err(Error::Parse(
                    "failed to parse marshal response: wrong message type".to_string(),
                ));
            };

        // Create a connection to the broker. Drops the connection to the marshal.
        let connection = bail!(
            ProtocolType::Connection::connect(broker_address).await,
            Connection,
            "failed to connect to broker"
        );

        // We authenticate to the broker with the permit we got from the marshal
        let authenticate_with_broker =
            Message::AuthenticateWithPermit(AuthenticateWithPermit { permit });

        // Send our auth message to the broker
        bail!(
            connection
                .send_message(Arc::from(authenticate_with_broker))
                .await,
            Connection,
            "failed to send auth message to broker"
        );

        // Wait for a response
        let broker_response = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive response from broker"
        );

        // Verify what kind of message we received
        if let Message::AuthenticateResponse(response) = broker_response {
            // Check if we passed authentication
            if response.permit != 1 {
                // We haven't, we failed authentication :(
                // TODO: fix these error types
                return Err(Error::Authentication(format!(
                    "failed authentication: {}",
                    response.context
                )));
            }
        } else {
            return Err(Error::Parse(
                "failed to parse broker response: wrong message type".to_string(),
            ));
        };

        // Send our subscribed topics to the broker
        let subscribed_topics_to_broker = Message::Subscribe(Subscribe {
            topics: subscribed_topics,
        });

        // Subscribe to topics with the broker
        bail!(
            connection
                .send_message(Arc::from(subscribed_topics_to_broker))
                .await,
            Connection,
            "failed to send initial subscribe message to broker"
        );

        Ok(connection)
    }
}
