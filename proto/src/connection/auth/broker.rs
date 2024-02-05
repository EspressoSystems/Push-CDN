//! In this crate we deal with the authentication flow as a broker.

use async_trait::async_trait;
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use tracing::error;

use crate::{
    bail,
    connection::protocols::{Connection, Protocol},
    crypto::{self, Serializable},
    error::{Error, Result},
    fail_verification_with_message,
    message::{AuthenticateResponse, Message},
    redis::{self, BrokerIdentifier},
};

use super::AuthenticationFlow;

/// Contains the data we need to authenticate a user.
#[derive(Clone)]
pub struct BrokerToUser {
    /// Our personal identifier
    pub identifier: BrokerIdentifier,
    /// The `Redis` client, so we can check the user's permit
    pub redis_client: redis::Client,
}

#[async_trait]
impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > AuthenticationFlow<SignatureScheme, ProtocolType> for BrokerToUser
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    /// We want to return the user's verification key
    type Return = SignatureScheme::VerificationKey;

    /// The authentication implementation for a broker to a user. We take the following steps:
    /// 1. Receive a permit from the user
    /// 2. Validate and remove the permit from `Redis`
    /// 3. Validate the signature
    /// 4. Send a response
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    async fn authenticate(
        &mut self,
        connection: &ProtocolType::Connection,
    ) -> Result<Self::Return> {
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
        let serialized_verification_key = match self
            .redis_client
            .validate_permit(&self.identifier, auth_message.permit)
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
}
