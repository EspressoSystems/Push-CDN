//! In this crate we deal with the authentication flow as a broker.

use async_trait::async_trait;
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use tracing::error;

use crate::{
    bail,
    connection::protocols::{Connection, Protocol},
    crypto::Serializable,
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
    /// The authentication implementation for a broker to a user. We take the following steps:
    /// 1. Receive a permit from the user
    /// 2. Validate and remove the permit from `Redis`
    /// 3. Send a response
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    async fn authenticate(&mut self, connection: &ProtocolType::Connection) -> Result<()> {
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
        match self
            .redis_client
            .validate_permit(&self.identifier, auth_message.permit)
            .await
        {
            Ok(false) => {
                fail_verification_with_message!(connection, "malformed verification key");
            }
            Err(err) => {
                error!("failed to validate permit with Redis: {err}");
                fail_verification_with_message!(connection, "internal server error");
            }

            Ok(true) => (),
        };

        // Form the response message
        let response_message = Message::AuthenticateResponse(AuthenticateResponse {
            permit: 1,
            context: String::new(),
        });

        // Send the successful response to the user
        let _ = connection.send_message(response_message).await;

        Ok(())
    }
}
