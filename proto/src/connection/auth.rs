//! This file defines authentication flows to be used when connecting
//! and reconnecting. We need this because it allows us to have the same connection code,
//! but with different authentication methods. For example, broker <-> broker
//! is different from user <-> broker.

// TODO IN GENERAL: figure out if connection dropping on big messages is working

use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use tokio::sync::Mutex;
use tracing::warn;

use crate::{
    bail,
    crypto::{self, DeterministicRng},
    error::{Error, Result},
    message::{AuthenticateResponse, AuthenticateWithKey, Message, Topic},
    redis,
};

use super::protocols::Protocol;
use crate::connection::protocols::Connection;

/// A macro that fails authentication early, providing the user with an error message.
/// Both sends the message and instantly returns.
macro_rules! fail_verification_with_message {
    ($connection: expr, $context: expr) => {
        // Send the error message
        let _ = $connection
            .send_message(Message::AuthenticateResponse(AuthenticateResponse {
                permit: 0,
                context: $context.to_string(),
            }))
            .await;

        // Return up the stack
        return Err(Error::Authentication($context.to_string()));
    };
}

/// The `Flow` trait implements a connection flow that can both authenticate
/// and verify authentication for a particular connection.
#[async_trait]
pub trait Flow<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
>: Send + Sync + 'static
{
    /// We need this to have extra data for when we authenticate and verify
    /// connections. For example, the signing and verification keys.
    /// TODO: FIGURE OUT IF NEED CLONE HERE
    type AuthenticationData: Send + Sync;

    /// The data we need to verify the particular entity
    type VerificationData: Send + Sync;

    /// We need this to pin a certain type of response
    type AuthResponse: Send + Sync;

    /// This is where we request or verify authentication. We pass in a connection, which,
    /// if it is verified, returns a resulting, successful connection.
    async fn authenticate(
        authentication_data: &Self::AuthenticationData,
        connection: &ProtocolType::Connection,
    ) -> Result<Self::AuthResponse>;

    /// This is the other side of the authentication flow. This is where we verify
    /// a particular authentication method.
    async fn verify(
        verification_data: &mut Self::VerificationData,
        connection: &ProtocolType::Connection,
    ) -> Result<()>;
}

/// This struct defines an implementation wherein we connect to a marshal
/// first, who returns the server address we should connect to, along
/// with a permit. Only after that do we try connecting to the broker.
pub struct UserToMarshal {}

/// We need this data to authenticate _as_ the user.
pub struct UserAuthenticationData<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
> {
    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    pub verification_key: SignatureScheme::VerificationKey,

    /// The underlying (private) signing key, used to sign messages to send to the server during the
    /// authentication phase.
    pub signing_key: SignatureScheme::SigningKey,

    /// The topics we're currently subscribed to. We need this here so we can send our subscriptions
    /// when we connect to a new server.
    pub subscribed_topics: Mutex<HashSet<Topic>>,
}

/// This is the other side of the `UserAuthenticationData`. We need this to verify
/// authentication of a user.
pub struct UserVerificationData {
    // The `Redis` client that we use to check and issue permits with
    pub redis_client: redis::Client,
}

#[async_trait]
impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > Flow<SignatureScheme, ProtocolType> for UserToMarshal
where
    SignatureScheme::Signature: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::VerificationKey: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::SigningKey: CanonicalSerialize + CanonicalDeserialize,
{
    type AuthenticationData = UserAuthenticationData<SignatureScheme>;
    type VerificationData = UserVerificationData;

    type AuthResponse = (String, u64);

    /// The steps on `UserToMarshal`'s connection:
    /// 1. Authenticate with the marshal with a signed message, who optionally
    ///     returns a permit and a server address
    /// 2. Use the permit and server address to connect to the broker
    async fn authenticate(
        authentication_data: &Self::AuthenticationData,
        connection: &ProtocolType::Connection,
    ) -> Result<Self::AuthResponse> {
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
                &authentication_data.signing_key,
                timestamp.to_le_bytes(),
                &mut DeterministicRng(0),
            ),
            Crypto,
            "failed to sign message"
        );

        // Serialize the verify key
        let verification_key_bytes = bail!(
            crypto::serialize(&authentication_data.verification_key),
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
            connection.send_message(authenticate_with_marshal).await,
            Connection,
            "failed to send auth message to marshal"
        );

        // Wait for the response with the permit and address
        let marshal_response = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from marshal"
        );

        // Make sure the message is the proper type
        Ok(
            if let Message::AuthenticateResponse(response) = marshal_response {
                println!("permit: {}, context: {}", response.permit, response.context);
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
            },
        )
    }

    async fn verify(
        verification_data: &mut Self::VerificationData,
        connection: &ProtocolType::Connection,
    ) -> Result<()> {
        // Receive the signed message from the user
        let message = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from user"
        );

        // See if we're the right type of message
        let Message::AuthenticateWithKey(message) = message else {
            // TODO: macro for this error thing
            fail_verification_with_message!(connection, "wrong message type");
        };

        // Deserialize the user's verification key
        let Ok(verification_key) = crypto::deserialize(&message.verification_key) else {
            fail_verification_with_message!(connection, "malformed verification key");
        };

        // Deserialize the signature
        let Ok(signature) = crypto::deserialize(&message.signature) else {
            fail_verification_with_message!(connection, "malformed signature");
        };

        // Verify the signature
        if SignatureScheme::verify(
            &(),
            &verification_key,
            message.timestamp.to_le_bytes(),
            &signature,
        )
        .is_err()
        {
            fail_verification_with_message!(connection, "failed to verify");
        }

        // Convert the timestamp to something usable
        let Ok(timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            fail_verification_with_message!(connection, "malformed timestamp");
        };

        // Make sure the timestamp is within 5 seconds
        if timestamp.as_secs() - message.timestamp > 5 {
            fail_verification_with_message!(connection, "timestamp is too old");
        }

        // Get the broker with the least amount of connections
        // TODO: do a macro for this
        let broker_with_least_connections = match verification_data
            .redis_client
            .get_with_least_connections()
            .await
        {
            Ok(broker) => broker,
            Err(err) => {
                warn!("failed to get brokers from Redis: {err}");
                fail_verification_with_message!(connection, "internal server error");
            }
        };

        // Generate and issue a permit for said broker
        let permit = match verification_data
            .redis_client
            .issue_permit(&broker_with_least_connections)
            .await
        {
            Ok(broker) => broker,
            Err(err) => {
                warn!("failed to issue permit to Redis: {err}");
                fail_verification_with_message!(connection, "internal server error");
            }
        };

        // Send the permit to the user, along with the public broker adcertise address
        if let Err(err) = connection
            .send_message(Message::AuthenticateResponse(AuthenticateResponse {
                permit,
                context: broker_with_least_connections.user_advertise_address,
            }))
            .await
        {
            warn!("failed to send authenticate response to user: {err}");
        }

        Ok(())
    }
}
