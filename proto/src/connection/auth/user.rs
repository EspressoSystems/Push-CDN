//! In this crate we deal with the authentication flow as a user.

use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use crate::{
    bail,
    connection::protocols::{Connection, Protocol},
    crypto::{self, DeterministicRng, Serializable},
    error::{Error, Result},
    message::{AuthenticateWithKey, AuthenticateWithPermit, Message},
};

/// This is the `BrokerAuth` struct that we define methods to for authentication purposes.
pub struct UserAuth<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
> {
    /// We use `PhantomData` here so we can be generic over a signature scheme
    /// and protocol type
    pub pd: PhantomData<(SignatureScheme, ProtocolType)>,
}

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > UserAuth<SignatureScheme, ProtocolType>
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    /// The authentication steps with a key:
    /// 1. Sign the timestamp with our private key
    /// 2. Send a signed message
    /// 3. Receive a permit
    ///
    /// # Errors
    /// - If we fail authentication
    /// - If our connection fails
    pub async fn authenticate_with_marshal(
        connection: &ProtocolType::Connection,
        verification_key: &SignatureScheme::VerificationKey,
        signing_key: &SignatureScheme::SigningKey,
    ) -> Result<(String, u64)> {
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
            // Check if we have received an actual permit
            if response.permit > 1 {
                // We have received an actual permit
                Ok((response.context, response.permit))
            } else {
                // We haven't, we failed authentication :(
                // TODO: fix these error types
                Err(Error::Authentication(format!(
                    "failed authentication: {}",
                    response.context
                )))
            }
        } else {
            Err(Error::Parse(
                "failed to parse marshal response: wrong message type".to_string(),
            ))
        }
    }

    /// TODO: clean up comments
    /// The authentication implementation for a user to a broker. We take the following steps:
    /// 1. Send the permit to the broker
    /// 2. Wait for a response
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    pub async fn authenticate_with_broker(
        connection: &ProtocolType::Connection,
        permit: u64,
    ) -> Result<()> {
        // Form the authentication message
        let auth_message = Message::AuthenticateWithPermit(AuthenticateWithPermit { permit });

        // Send the authentication message to the broker
        bail!(
            connection.send_message(auth_message).await,
            Connection,
            "failed to send message to broker"
        );

        // Wait for a response
        let response_message = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive response message from broker"
        );

        // See if we're the right type of message
        let Message::AuthenticateResponse(message) = response_message else {
            return Err(Error::Parse(
                "failed to parse broker response: wrong message type".to_string(),
            ));
        };

        // Return okay if our response was good, or an error if not
        if message.permit == 1 {
            Ok(())
        } else {
            Err(Error::Parse(format!(
                "authentication with broker failed: {}",
                message.context
            )))
        }
    }
}
