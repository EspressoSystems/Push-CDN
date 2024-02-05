//! In this crate we deal with the authentication flow as a user.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use tokio::sync::Mutex;

use crate::{
    bail,
    connection::protocols::{Connection, Protocol},
    crypto::{self, DeterministicRng, Serializable},
    error::{Error, Result},
    message::{AuthenticateWithKey, AuthenticateWithPermit, Message, Topic},
};

use super::AuthenticationFlow;

/// This struct defines an implementation wherein we connect to the broker
/// using the permit issued to us by the marshal.
#[derive(Clone)]
pub struct UserToMarshalToBroker<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
> {
    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    pub verification_key: Arc<SignatureScheme::VerificationKey>,

    /// The underlying (private) signing key, used to sign messages to send to the server during the
    /// authentication phase.
    pub signing_key: Arc<SignatureScheme::SigningKey>,

    /// The topics we're currently subscribed to. We need this here so we can send our subscriptions
    /// when we connect to a new server.
    pub subscribed_topics: Arc<Mutex<HashSet<Topic>>>,
}

#[async_trait]
impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > AuthenticationFlow<SignatureScheme, ProtocolType> for UserToMarshalToBroker<SignatureScheme>
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    /// We have no auxiliary data to return
    type Return = ();

    /// The authentication steps on `UserToBrokerToMarshal`'s connection:
    /// 1. Sign the timestamp with our private key
    /// 2. Send a signed message to the marshal
    /// 3. Receive a permit from the marshal
    /// 4. Authenticate with the permit to a broker
    ///
    /// # Errors
    /// - If we fail authentication
    /// - If our connection fails
    async fn authenticate(&mut self, connection: &ProtocolType::Connection) -> Result<()> {
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
                &self.signing_key,
                timestamp.to_le_bytes(),
                &mut DeterministicRng(0),
            ),
            Crypto,
            "failed to sign message"
        );

        // Serialize the verify key
        let verification_key_bytes = bail!(
            crypto::serialize(&self.verification_key),
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
        let (broker_address, permit) = if let Message::AuthenticateResponse(response) = response {
            // Check if we have received an actual permit
            if response.permit > 1 {
                // We have received an actual permit
                (response.context, response.permit)
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
                "failed to parse marshal response: wrong message type".to_string(),
            ));
        };

        // Disconnect from the marshal, connect to the broker
        let connection = bail!(
            ProtocolType::Connection::connect(broker_address).await,
            Connection,
            "failed to connect to broker"
        );

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
