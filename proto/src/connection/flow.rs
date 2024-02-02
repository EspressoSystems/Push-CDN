//! This file defines the connection and authentication flows to be used when connecting
//! and reconnecting. We need this because it allows us to have the same connection code,
//! but with different connection and authentication methods. For example, broker <-> broker
//! is different from user <-> broker.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use crate::{
    bail,
    crypto::{self, DeterministicRng},
    error::{Error, Result},
    message::{AuthenticateWithKey, AuthenticateWithPermit, Message},
};

use super::protocols::Protocol;
use crate::connection::protocols::Connection;

/// TODO: BIDIRECTIONAL AUTHENTICATION FOR USERS<->BROKERS
///
/// The `Flow` trait implements a connection flow that takes in a `Flow implementation`,
/// and returns an authenticated endpoint (or an error).
#[async_trait]
pub trait Flow<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
>: Send + Sync + 'static
{
    /// This is the meat of `Flow`. We define this for every type of connection flow we have.
    async fn connect(&self) -> Result<ProtocolType::Connection>;
}

/// This struct implements `Flow`. It defines an implementation wherein we connect
/// to a marshal first, who returns the server address we should connect to, along
/// with a permit. Only after that do we try connecting to the broker.
#[derive(Clone)]
pub struct UserToMarshal<SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>>
{
    /// This is the remote address that we authenticate to. It can either be a broker
    /// or a marshal.
    pub endpoint: String,

    /// The underlying (public) verification key, used to authenticate with the server. Checked
    /// against the stake table.
    pub verification_key: SignatureScheme::VerificationKey,

    /// The underlying (private) signing key, used to sign messages to send to the server during the
    /// authentication phase.
    pub signing_key: SignatureScheme::SigningKey,
}

#[async_trait]
impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > Flow<SignatureScheme, ProtocolType> for UserToMarshal<SignatureScheme>
where
    SignatureScheme::Signature: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::VerificationKey: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::SigningKey: CanonicalSerialize + CanonicalDeserialize,
{
    /// The steps on `UserToMarshal`'s connection:
    /// 1. Authenticate with the marshal with a signed message, who optionally
    ///     returns a permit and a server address
    /// 2. Use the permit and server address to connect to the broker
    async fn connect(&self) -> Result<ProtocolType::Connection> {
        // Create the initial connection, which is unauthenticated at this point
        let connection = bail!(
            ProtocolType::Connection::connect(self.endpoint.clone()).await,
            Connection,
            "failed to connect to marshal"
        );

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
        let authenticate_with_marshal = Message::AuthenticateWithKey(AuthenticateWithKey {
            timestamp,
            verification_key: verification_key_bytes,
            signature: signature_bytes,
        });

        // Create and send the authentication message from the above operations
        bail!(
            connection
                .send_message(Arc::from(authenticate_with_marshal))
                .await,
            Connection,
            "failed to auth message to marshal"
        );

        // Wait for the response with the permit and address
        let marshal_response = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive message from marshal"
        );

        // Make sure the message is the proper type
        let (broker_address, permit) =
            if let Message::AuthenticateResponse(response) = marshal_response {
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

        // Create a connection to the broker. Drops the connection to the marshal.
        let connection = bail!(
            ProtocolType::Connection::connect(broker_address).await,
            Connection,
            "failed to connect to broker"
        );

        // We authenticate to the broker with the permit we got from the marshal
        let authenticate_with_broker =
            Message::AuthenticateWithPermit(AuthenticateWithPermit { permit });

        // Send our auth message to the broker
        bail!(
            connection
                .send_message(Arc::from(authenticate_with_broker))
                .await,
            Connection,
            "failed to send auth message to broker"
        );

        // Wait for a response
        let broker_response = bail!(
            connection.recv_message().await,
            Connection,
            "failed to receive response from broker"
        );

        // Verify what kind of message we received
        if let Message::AuthenticateResponse(response) = broker_response {
            // Check if we passed authentication
            if response.permit != 1 {
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

        Ok(connection)
    }
}
