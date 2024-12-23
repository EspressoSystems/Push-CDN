// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! In this crate we deal with the authentication flow as a user.

use std::{
    collections::HashSet,
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::crypto::signature::Serializable;
use crate::{
    bail,
    crypto::signature::{KeyPair, SignatureScheme},
    def::{ConnectionDef, Scheme},
    error::{Error, Result},
    message::{AuthenticateWithKey, AuthenticateWithPermit, Message, Topic},
};
use crate::{connection::protocols::Connection, crypto::signature::Namespace};

/// This is the `UserAuth` struct that we define methods to for authentication purposes.
pub struct UserAuth<C: ConnectionDef>(PhantomData<C>);

impl<C: ConnectionDef> UserAuth<C> {
    /// The authentication steps with a key:
    /// 1. Sign the timestamp with our private key
    /// 2. Send a signed message
    /// 3. Receive a permit
    ///
    /// # Errors
    /// - If we fail authentication
    /// - If our connection fails
    pub async fn authenticate_with_marshal(
        connection: &Connection,
        keypair: &KeyPair<Scheme<C>>,
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
            Scheme::<C>::sign(
                &keypair.private_key,
                Namespace::UserMarshalAuth.as_str(),
                &timestamp.to_le_bytes()
            ),
            Crypto,
            "failed to sign message"
        );

        // Serialize the public key
        let public_key_bytes = bail!(
            keypair.public_key.serialize(),
            Serialize,
            "failed to serialize public key"
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
            "failed to send auth message to marshal"
        );

        // Wait for the response with the permit and endpoint
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

    /// The authentication implementation for a user to a broker. We take the following steps:
    /// 1. Send the permit to the broker
    /// 2. Wait for a response
    ///
    /// # Errors
    /// - If authentication fails
    /// - If our connection fails
    pub async fn authenticate_with_broker(
        connection: &Connection,
        permit: u64,
        subscribed_topics: HashSet<Topic>,
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
        if message.permit != 1 {
            return Err(Error::Parse(format!(
                "authentication with broker failed: {}",
                message.context
            )));
        }

        // Send our interested topics to the broker
        let topic_message = Message::Subscribe(Vec::from_iter(subscribed_topics));
        bail!(
            connection.send_message(topic_message).await,
            Connection,
            "failed to send topics to broker"
        );

        Ok(())
    }
}
