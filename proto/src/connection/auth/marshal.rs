//! In this crate we deal with the authentication flow as a marshal.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    redis,
};

use super::AuthenticationFlow;

/// Contains the data we need to authenticate a user as a marshal
#[derive(Clone)]
pub struct MarshalToUser {
    /// The `Redis` client we use to issue permits
    pub redis_client: redis::Client,
}

#[async_trait]
impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > AuthenticationFlow<SignatureScheme, ProtocolType> for MarshalToUser
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    /// We have no auxiliary data to return
    type Return = ();

    /// The authentication implementation for a marshal to a user. We take the following steps:
    /// 1. Receive a signed message from the user
    /// 2. Validate and remove the message
    /// 3. Issue a permit
    /// 4. Return the permit
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    async fn authenticate(
        &mut self,
        connection: &ProtocolType::Connection,
    ) -> Result<Self::Return> {
        // Receive the signed message from the user
        let auth_message = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from user"
        );

        // See if we're the right type of message
        let Message::AuthenticateWithKey(auth_message) = auth_message else {
            // TODO: macro for this error thing
            fail_verification_with_message!(connection, "wrong message type");
        };

        // Deserialize the user's verification key
        let Ok(verification_key) = crypto::deserialize(&auth_message.verification_key) else {
            fail_verification_with_message!(connection, "malformed verification key");
        };

        // Deserialize the signature
        let Ok(signature) = crypto::deserialize(&auth_message.signature) else {
            fail_verification_with_message!(connection, "malformed signature");
        };

        // Verify the signature
        if SignatureScheme::verify(
            &(),
            &verification_key,
            auth_message.timestamp.to_le_bytes(),
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
        if timestamp.as_secs() - auth_message.timestamp > 5 {
            fail_verification_with_message!(connection, "timestamp is too old");
        }

        // Get the broker with the least amount of connections
        // TODO: do a macro for this
        let broker_with_least_connections =
            match self.redis_client.get_with_least_connections().await {
                Ok(broker) => broker,
                Err(err) => {
                    error!("failed to get the broker with the least connections from Redis: {err}");
                    fail_verification_with_message!(connection, "internal server error");
                }
            };

        // Generate and issue a permit for said broker
        // TODO: add bounds check for verification key. There's the possibility it could be too big, if
        // verify does not check that.
        let permit = match self
            .redis_client
            .issue_permit(
                &broker_with_least_connections,
                Duration::from_secs(5),
                auth_message.verification_key,
            )
            .await
        {
            Ok(broker) => broker,
            Err(err) => {
                error!("failed to issue a permit to Redis: {err}");
                fail_verification_with_message!(connection, "internal server error");
            }
        };

        // Form the response message
        let response_message = Message::AuthenticateResponse(AuthenticateResponse {
            permit,
            context: broker_with_least_connections.user_advertise_address,
        });

        // Send the permit to the user, along with the public broker advertise address
        let _ = connection.send_message(response_message).await;

        Ok(())
    }
}
