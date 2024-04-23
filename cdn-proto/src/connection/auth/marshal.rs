//! In this crate we deal with the authentication flow as a marshal.

use std::{
    marker::PhantomData,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tracing::error;

use crate::{
    bail,
    connection::protocols::{Receiver, Sender},
    def::{Connection, PublicKey, RunDef, Scheme},
    discovery::DiscoveryClient,
    error::{Error, Result},
    fail_verification_with_message,
    message::{AuthenticateResponse, Message},
};
use crate::{
    connection::UserPublicKey,
    crypto::signature::{Serializable, SignatureScheme},
};

/// This is the `BrokerAuth` struct that we define methods to for authentication purposes.
pub struct MarshalAuth<R: RunDef>(PhantomData<R>);

impl<R: RunDef> MarshalAuth<R> {
    /// The authentication implementation for a marshal to a user. We take the following steps:
    /// 1. Receive a signed message from the user
    /// 2. Validate the message
    /// 3. Issue a permit
    /// 4. Return the permit
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    pub async fn verify_user(
        connection: &Connection<R::User>,
        discovery_client: &mut R::DiscoveryClientType,
    ) -> Result<UserPublicKey> {
        // Receive the signed message from the user
        let auth_message = bail!(
            connection.1.recv_message().await,
            Connection,
            "failed to receive message from user"
        );

        // See if we're the right type of message
        let Message::AuthenticateWithKey(auth_message) = auth_message else {
            fail_verification_with_message!(connection, "wrong message type");
        };

        // Deserialize the user's public key
        let Ok(public_key) = PublicKey::<R::User>::deserialize(&auth_message.public_key) else {
            fail_verification_with_message!(connection, "malformed public key");
        };

        // Verify the signature
        if !Scheme::<R::User>::verify(
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

        // Serialize the public key so we can get its mnemonic and whitelist status
        let Ok(public_key) = public_key.serialize() else {
            fail_verification_with_message!(connection, "failed to serialize public key");
        };

        // Check if the user is in the whitelist
        match discovery_client
            .check_whitelist(&UserPublicKey::from(public_key.clone()))
            .await
        {
            Ok(false) => {
                fail_verification_with_message!(connection, "not in whitelist");
            }

            Ok(true) => {}

            Err(err) => {
                error!("failed to get the get user whitelist status: {err}");
                fail_verification_with_message!(connection, "internal server error");
            }
        };

        // Get the broker with the least amount of connections
        // TODO: do a macro for this
        let broker_with_least_connections = match discovery_client
            .get_with_least_connections()
            .await
        {
            Ok(broker) => broker,
            Err(err) => {
                error!("failed to get the broker with the least connections from discovery client: {err}");
                fail_verification_with_message!(connection, "internal server error");
            }
        };

        // Generate and issue a permit for said broker
        let permit = match discovery_client
            .issue_permit(
                #[cfg(not(feature = "global-permits"))]
                &broker_with_least_connections,
                Duration::from_secs(30),
                auth_message.public_key,
            )
            .await
        {
            Ok(broker) => broker,
            Err(err) => {
                error!("failed to issue a permit: {err}");
                fail_verification_with_message!(connection, "internal server error");
            }
        };

        // Form a response message
        let response_message = Message::AuthenticateResponse(AuthenticateResponse {
            permit,
            context: broker_with_least_connections.public_advertise_endpoint,
        });

        // Send the permit to the user, along with the public broker advertise endpoint
        let _ = connection.0.send_message(response_message).await;

        Ok(UserPublicKey::from(public_key))
    }
}
