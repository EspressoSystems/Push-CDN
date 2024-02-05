//! In this crate we deal with the authentication flow as a broker.

use std::time::{SystemTime, UNIX_EPOCH};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use tracing::error;

use crate::{
    bail,
    connection::protocols::{Connection, Protocol},
    crypto::{self, DeterministicRng, Serializable},
    error::{Error, Result},
    fail_verification_with_message,
    message::{AuthenticateResponse, AuthenticateWithKey, Message},
    redis::{self, BrokerIdentifier},
};

use super::Auth;

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > Auth<SignatureScheme, ProtocolType>
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    /// The authentication implementation for a broker to a user. We take the following steps:
    /// 1. Receive a permit from the user
    /// 2. Validate and remove the permit from `Redis`
    /// 3. Send a response
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    pub async fn verify_by_permit(
        connection: &ProtocolType::Connection,
        broker_identifier: &BrokerIdentifier,
        redis_client: &mut redis::Client,
    ) -> Result<SignatureScheme::VerificationKey> {
        // Receive the permit
        let auth_message = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from user"
        );

        // See if we're the right type of message
        let Message::AuthenticateWithPermit(auth_message) = auth_message else {
            // TODO: macro for this error thing
            fail_verification_with_message!(connection, "wrong message type");
        };

        // Check the permit with `Redis`
        let serialized_verification_key = match redis_client
            .validate_permit(broker_identifier, auth_message.permit)
            .await
        {
            // The permit did not exist
            Ok(None) => {
                fail_verification_with_message!(connection, "invalid or expired permit");
            }

            // We failed to contact `Redis`
            Err(err) => {
                error!("failed to validate permit with Redis: {err}");
                fail_verification_with_message!(connection, "internal server error");
            }

            // The permit existed, return the associated verification key
            Ok(Some(serialized_verification_key)) => serialized_verification_key,
        };

        // Form the response message
        let response_message = Message::AuthenticateResponse(AuthenticateResponse {
            permit: 1,
            context: String::new(),
        });

        // Send the successful response to the user
        let _ = connection.send_message(response_message).await;

        // Serialize the verification key
        let verification_key = bail!(
            crypto::deserialize(&serialized_verification_key),
            Crypto,
            "failed to deserialize verification key"
        );

        // Return the verification key
        Ok(verification_key)
    }

    /// The authentication implementation for a broker to another broker (outbound). We take the
    /// following steps:
    /// 1. Send a signed message to the broker
    /// 2. Wait for a response
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    pub async fn authenticate_broker_outbound(
        connection: &ProtocolType::Connection,
        verification_key: &SignatureScheme::VerificationKey,
        signing_key: &SignatureScheme::SigningKey,
        identifier: &BrokerIdentifier,
    ) -> Result<BrokerIdentifier> {
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

        // We authenticate to the broker with our key
        let message = Message::AuthenticateWithKey(AuthenticateWithKey {
            timestamp,
            verification_key: verification_key_bytes,
            signature: signature_bytes,
        });

        // Create and send the authentication message from the above operations
        bail!(
            connection.send_message(message).await,
            Connection,
            "failed to send auth message to marshal"
        );

        // Wait for the response with the permit and address
        let response = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from marshal"
        );

        // Make sure the message is the proper type
        if let Message::AuthenticateResponse(response) = response {
            // We have failed authentication if the permit != 1
            if response.permit != 1 {
                return Err(Error::Authentication(format!(
                    "failed authentication: {}",
                    response.context
                )));
            }
        } else {
            // We received the wrong response message
            return Err(Error::Parse(
                "failed to parse broker response: wrong message type".to_string(),
            ));
        };

        todo!()
    }
}
