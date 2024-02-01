//! This file defines the connection and authentication flows
//! to be used when connecting and reconnecting.

use std::time::{SystemTime, UNIX_EPOCH};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use crate::{
    bail,
    connection::Connection,
    crypto::{self, DeterministicRng},
    error::{Error, Result},
    message::{AuthenticateWithKey, Message},
};

pub trait Flow<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ConnectionType: Connection,
>
{
    async fn connect(
        endpoint: String,
        signing_key: &SignatureScheme::SigningKey,
        verification_key: &SignatureScheme::VerificationKey,
    ) -> Result<ConnectionType>;
}


pub struct ToMarshal {}

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ConnectionType: Connection,
    > Flow<SignatureScheme, ConnectionType> for ToMarshal
where
    SignatureScheme::Signature: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::VerificationKey: CanonicalSerialize + CanonicalDeserialize,
    SignatureScheme::SigningKey: CanonicalSerialize + CanonicalDeserialize,
{
    async fn connect(
        endpoint: String,
        signing_key: &SignatureScheme::SigningKey,
        verification_key: &SignatureScheme::VerificationKey,
    ) -> Result<ConnectionType> {
        let connection = bail!(
            ConnectionType::connect(endpoint).await,
            Connection,
            "failed to connect to remote"
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
                &signing_key,
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

        let message = Message::AuthenticateWithKey(AuthenticateWithKey {
            timestamp,
            verification_key: verification_key_bytes,
            signature: signature_bytes,
        });

        // Create and send the authentication message from the above operations
        // bail!(
        //     connection.send_message(message).await,
        //     Connection,
        //     "failed to send message"
        // );

        // Ok(connection)
        todo!()
    }
}
