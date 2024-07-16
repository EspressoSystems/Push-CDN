//! In this crate we deal with the authentication flow as a broker.

use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use tracing::error;

use crate::{
    bail,
    connection::protocols::Connection,
    crypto::signature::SignatureScheme,
    def::{PublicKey, RunDef, Scheme},
    discovery::{BrokerIdentifier, DiscoveryClient},
    error::{Error, Result},
    fail_verification_with_message,
    message::{AuthenticateResponse, AuthenticateWithKey, Message, Topic},
};
use crate::{
    connection::UserPublicKey,
    crypto::signature::{KeyPair, Serializable},
};

/// This is the `BrokerAuth` struct that we define methods to for authentication purposes.
pub struct BrokerAuth<R: RunDef>(PhantomData<R>);

/// We  use this macro upstream to conditionally order broker authentication flows
/// TODO: do something else with these macros
#[macro_export]
macro_rules! authenticate_with_broker {
    ($connection: expr, $inner: expr) => {
        // Authenticate with the other broker, returning their reconnect endpoint
        match BrokerAuth::<Def>::authenticate_with_broker(&mut $connection, &$inner.keypair).await {
            Ok(broker_endpoint) => Ok(broker_endpoint),
            Err(err) => {
                return Err(Error::Connection(
                    "failed authentication with broker: {err}".to_string(),
                ));
            }
        }
    };
}

/// We  use this macro upstream to conditionally order broker authentication flows
#[macro_export]
macro_rules! verify_broker {
    ($connection: expr, $inner: expr) => {
        // Verify the other broker's authentication
        if let Err(err) = BrokerAuth::<Def>::verify_broker(
            &mut $connection,
            &$inner.identity,
            &$inner.keypair.public_key,
        )
        .await
        {
            return Err(Error::Connection("failed to verify broker".to_string()));
        };
    };
}

impl<R: RunDef> BrokerAuth<R> {
    /// The authentication implementation for a broker to a user. We take the following steps:
    /// 1. Receive a permit from the user
    /// 2. Validate and remove the permit from `Redis`
    /// 3. Send a response
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    pub async fn verify_user(
        connection: &Connection,
        #[cfg(not(feature = "global-permits"))] broker_identifier: &BrokerIdentifier,
        discovery_client: &mut R::DiscoveryClientType,
    ) -> Result<(UserPublicKey, Vec<Topic>)> {
        // Receive the permit
        let auth_message = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from user"
        );

        // See if we're the right type of message
        let Message::AuthenticateWithPermit(auth_message) = auth_message else {
            fail_verification_with_message!(connection, "wrong message type");
        };

        // Check the permit
        let serialized_public_key = match discovery_client
            .validate_permit(
                #[cfg(not(feature = "global-permits"))]
                broker_identifier,
                auth_message.permit,
            )
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
        let _ = connection.send_message(response_message).await;

        // Try to serialize the public key
        bail!(
            PublicKey::<R::User>::deserialize(&serialized_public_key),
            Crypto,
            "failed to deserialize public key"
        );

        // Receive the subscribed topics
        let subscribed_topics_message = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from user"
        );

        // See if we're the right type of message
        let Message::Subscribe(subscribed_topics_message) = subscribed_topics_message else {
            fail_verification_with_message!(connection, "wrong message type");
        };

        // Return the public key and the initially subscribed topics
        Ok((
            UserPublicKey::from(serialized_public_key),
            subscribed_topics_message,
        ))
    }

    /// Authenticate with a broker (as a broker).
    /// Is the same as the `authenticate_with_broker` flow as a user, but
    /// we return a `BrokerIdentifier` instead.
    ///
    /// # Errors
    /// - If we fail to authenticate
    /// - If we have a connection failure
    pub async fn authenticate_with_broker(
        connection: &Connection,
        keypair: &KeyPair<Scheme<R::Broker>>,
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
            Scheme::<R::Broker>::sign(&keypair.private_key, &timestamp.to_le_bytes()),
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
            connection.send_message(message).await,
            Connection,
            "failed to send auth message to broker"
        );

        // Wait for the response with the permit and endpoint
        let response = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from broker"
        );

        // Make sure the message is the proper type
        let broker_endpoint = if let Message::AuthenticateResponse(response) = response {
            // Check if we have passed authentication
            if response.permit == 1 {
                // We have. Return the endpoint we received
                bail!(
                    response.context.try_into(),
                    Parse,
                    "failed to parse broker endpoint"
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

        Ok(broker_endpoint)
    }

    /// Verify a broker as a broker.
    /// Will fail verification if it does not match our public key.
    ///
    /// # Errors
    /// - If verification has failed
    pub async fn verify_broker(
        connection: &Connection,
        our_identifier: &BrokerIdentifier,
        our_public_key: &PublicKey<R::Broker>,
    ) -> Result<()> {
        // Receive the signed message from the user
        let auth_message = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from user"
        );

        // See if we're the right type of message
        let Message::AuthenticateWithKey(auth_message) = auth_message else {
            fail_verification_with_message!(connection, "wrong message type");
        };

        // Deserialize the user's public key
        let Ok(public_key) = PublicKey::<R::Broker>::deserialize(&auth_message.public_key) else {
            fail_verification_with_message!(connection, "malformed public key");
        };

        // Verify the signature
        if !Scheme::<R::Broker>::verify(
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

        // Send the permit to the user, along with the public broker advertise endpoint
        let _ = connection.send_message(response_message).await;

        Ok(())
    }
}
