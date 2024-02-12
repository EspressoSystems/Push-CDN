//! In this crate we deal with the authentication flow as a broker.

use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use tracing::error;

use crate::{
    bail,
    connection::protocols::{Protocol, Receiver, Sender},
    crypto::{self, DeterministicRng, KeyPair, Scheme, Serializable},
    error::{Error, Result},
    fail_verification_with_message,
    message::{AuthenticateResponse, AuthenticateWithKey, Message, Topic},
    redis::{self, BrokerIdentifier},
};

/// This is the `BrokerAuth` struct that we define methods to for authentication purposes.
pub struct BrokerAuth<SignatureScheme: Scheme, ProtocolType: Protocol> {
    /// We use `PhantomData` here so we can be generic over a signature scheme
    /// and protocol type
    pub pd: PhantomData<(SignatureScheme, ProtocolType)>,
}

/// We  use this macro upstream to conditionally order broker authentication flows
/// TODO: do something else with these macros
#[macro_export]
macro_rules! authenticate_with_broker {
    ($connection: expr, $inner: expr) => {
        // Authenticate with the other broker, returning their reconnect address
        match BrokerAuth::<BrokerSignatureScheme, BrokerProtocolType>::authenticate_with_broker(
            &mut $connection,
            &$inner.keypair,
        )
        .await
        {
            Ok(broker_address) => broker_address,
            Err(err) => {
                error!("failed authentication with broker: {err}");
                return;
            }
        }
    };
}

/// We  use this macro upstream to conditionally order broker authentication flows
#[macro_export]
macro_rules! verify_broker {
    ($connection: expr, $inner: expr) => {
        // Verify the other broker's authentication
        if let Err(err) = BrokerAuth::<BrokerSignatureScheme, BrokerProtocolType>::verify_broker(
            &mut $connection,
            &$inner.identity,
            &$inner.keypair.verification_key,
        )
        .await
        {
            error!("failed to verify broker: {err}");
            return;
        };
    };
}

impl<SignatureScheme: Scheme, ProtocolType: Protocol> BrokerAuth<SignatureScheme, ProtocolType>
where
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::Signature: Serializable,
{
    /// The authentication implementation for a broker to a user. We take the following steps:
    /// 1. Receive a permit from the user
    /// 2. Validate and remove the permit from `Redis`
    /// 3. Send a response
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    pub async fn verify_user(
        connection: &mut (ProtocolType::Sender, ProtocolType::Receiver),
        broker_identifier: &BrokerIdentifier,
        redis_client: &mut redis::Client,
    ) -> Result<(Vec<u8>, Vec<Topic>)> {
        // Receive the permit
        let auth_message = bail!(
            connection.1.recv_message().await,
            Connection,
            "failed to receive message from user"
        );

        // See if we're the right type of message
        let Message::AuthenticateWithPermit(auth_message) = auth_message else {
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
        let _ = connection.0.send_message(response_message).await;

        // Try to serialize the verification key
        bail!(
            crypto::deserialize(&serialized_verification_key),
            Crypto,
            "failed to deserialize verification key"
        );

        // Receive the subscribed topics
        let subscribed_topics_message = bail!(
            connection.1.recv_message().await,
            Connection,
            "failed to receive message from user"
        );

        // See if we're the right type of message
        let Message::Subscribe(subscribed_topics_message) = subscribed_topics_message else {
            // TODO: macro for this error thing
            fail_verification_with_message!(connection, "wrong message type");
        };

        // Return the verification key
        Ok((serialized_verification_key, subscribed_topics_message))
    }

    /// Authenticate with a broker (as a broker).
    /// Is the same as the `authenticate_with_broker` flow as a user, but
    /// we return a `BrokerIdentifier` instead.
    ///
    /// # Errors
    /// - If we fail to authenticate
    /// - If we have a connection failure
    pub async fn authenticate_with_broker(
        connection: &mut (ProtocolType::Sender, ProtocolType::Receiver),
        keypair: &KeyPair<SignatureScheme>,
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
                &keypair.signing_key,
                timestamp.to_le_bytes(),
                &mut DeterministicRng(0),
            ),
            Crypto,
            "failed to sign message"
        );

        // Serialize the verify key
        let verification_key_bytes = bail!(
            crypto::serialize(&keypair.verification_key),
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
            connection.0.send_message(message).await,
            Connection,
            "failed to send auth message to broker"
        );

        // Wait for the response with the permit and address
        let response = bail!(
            connection.1.recv_message().await,
            Connection,
            "failed to receive message from broker"
        );

        // Make sure the message is the proper type
        let broker_address = if let Message::AuthenticateResponse(response) = response {
            // Check if we have passed authentication
            if response.permit == 1 {
                // We have. Return the address we received
                bail!(
                    response.context.try_into(),
                    Parse,
                    "failed to parse broker address"
                )
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
                "failed to parse broker response: wrong message type".to_string(),
            ));
        };

        Ok(broker_address)
    }

    /// Verify a broker as a broker.
    /// Will fail verification if it does not match our verification key.
    ///
    /// # Errors
    /// - If verification has failed
    pub async fn verify_broker(
        connection: &mut (ProtocolType::Sender, ProtocolType::Receiver),
        our_identifier: &BrokerIdentifier,
        our_verification_key: &SignatureScheme::VerificationKey,
    ) -> Result<()> {
        // Receive the signed message from the user
        let auth_message = bail!(
            connection.1.recv_message().await,
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

        // Check our verification key against theirs
        if verification_key != *our_verification_key {
            fail_verification_with_message!(connection, "signature did not use broker key");
        }

        // Form a response message
        let response_message = Message::AuthenticateResponse(AuthenticateResponse {
            permit: 1,
            context: our_identifier.to_string(),
        });

        // Send the permit to the user, along with the public broker advertise address
        let _ = connection.0.send_message(response_message).await;

        Ok(())
    }
}
