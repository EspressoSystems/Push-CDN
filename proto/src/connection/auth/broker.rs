//! In this crate we deal with the authentication flow as a broker.

use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use tracing::error;

use crate::crypto::signature::{KeyPair, Serializable};
use crate::{
    bail,
    connection::protocols::{Protocol, Receiver, Sender},
    crypto::signature::SignatureScheme,
    discovery::{BrokerIdentifier, DiscoveryClient},
    error::{Error, Result},
    fail_verification_with_message,
    message::{AuthenticateResponse, AuthenticateWithKey, Message, Topic},
    BrokerProtocol, DiscoveryClientType, UserProtocol,
};

/// This is the `BrokerAuth` struct that we define methods to for authentication purposes.
pub struct BrokerAuth<Scheme: SignatureScheme> {
    /// We use `PhantomData` here so we can be generic over a signature scheme
    /// and protocol type
    pub pd: PhantomData<Scheme>,
}

/// We  use this macro upstream to conditionally order broker authentication flows
/// TODO: do something else with these macros
#[macro_export]
macro_rules! authenticate_with_broker {
    ($connection: expr, $inner: expr) => {
        // Authenticate with the other broker, returning their reconnect address
        match BrokerAuth::<BrokerScheme>::authenticate_with_broker(
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
        if let Err(err) = BrokerAuth::<BrokerScheme>::verify_broker(
            &mut $connection,
            &$inner.identity,
            &$inner.keypair.public_key,
        )
        .await
        {
            error!("failed to verify broker: {err}");
            return;
        };
    };
}

impl<Scheme: SignatureScheme> BrokerAuth<Scheme> {
    /// The authentication implementation for a broker to a user. We take the following steps:
    /// 1. Receive a permit from the user
    /// 2. Validate and remove the permit from `Redis`
    /// 3. Send a response
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    pub async fn verify_user(
        connection: &(
            <UserProtocol as Protocol>::Sender,
            <UserProtocol as Protocol>::Receiver,
        ),
        broker_identifier: &BrokerIdentifier,
        discovery_client: &mut DiscoveryClientType,
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

        // Check the permit
        let serialized_public_key = match discovery_client
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

            // The permit existed, return the associated public key
            Ok(Some(serialized_public_key)) => serialized_public_key,
        };

        // Form the response message
        let response_message = Message::AuthenticateResponse(AuthenticateResponse {
            permit: 1,
            context: String::new(),
        });

        // Send the successful response to the user
        let _ = connection.0.send_message(response_message).await;

        // Try to serialize the public key
        bail!(
            Scheme::PublicKey::deserialize(&serialized_public_key),
            Crypto,
            "failed to deserialize public key"
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

        // Return the public key
        Ok((serialized_public_key, subscribed_topics_message))
    }

    /// Authenticate with a broker (as a broker).
    /// Is the same as the `authenticate_with_broker` flow as a user, but
    /// we return a `BrokerIdentifier` instead.
    ///
    /// # Errors
    /// - If we fail to authenticate
    /// - If we have a connection failure
    pub async fn authenticate_with_broker(
        connection: &(
            <BrokerProtocol as Protocol>::Sender,
            <BrokerProtocol as Protocol>::Receiver,
        ),
        keypair: &KeyPair<Scheme>,
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
            Scheme::sign(&keypair.private_key, &timestamp.to_le_bytes()),
            Crypto,
            "failed to sign message"
        );

        // Serialize the public key
        let public_key_bytes = bail!(
            keypair.public_key.serialize(),
            Serialize,
            "failed to serialize publi key"
        );

        // We authenticate to the marshal with a key
        let message = Message::AuthenticateWithKey(AuthenticateWithKey {
            timestamp,
            public_key: public_key_bytes,
            signature,
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
    /// Will fail verification if it does not match our public key.
    ///
    /// # Errors
    /// - If verification has failed
    pub async fn verify_broker(
        connection: &(
            <BrokerProtocol as Protocol>::Sender,
            <BrokerProtocol as Protocol>::Receiver,
        ),
        our_identifier: &BrokerIdentifier,
        our_public_key: &Scheme::PublicKey,
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

        // Deserialize the user's public key
        let Ok(public_key) = Scheme::PublicKey::deserialize(&auth_message.public_key) else {
            fail_verification_with_message!(connection, "malformed public key");
        };

        // Verify the signature
        if !Scheme::verify(
            &public_key,
            &auth_message.timestamp.to_le_bytes(),
            &auth_message.signature,
        ) {
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

        // Check our public key against theirs
        if public_key != *our_public_key {
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
