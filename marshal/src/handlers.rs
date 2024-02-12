use proto::{
    connection::{
        auth::marshal::MarshalAuth,
        protocols::{Protocol, Sender},
    },
    crypto::{Scheme, Serializable},
    redis,
};

use crate::Marshal;

impl<SignatureScheme: Scheme, ProtocolType: Protocol> Marshal<SignatureScheme, ProtocolType>
where
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::Signature: Serializable,
{
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        mut connection: (ProtocolType::Sender, ProtocolType::Receiver),
        mut redis_client: redis::Client,
    ) {
        // Verify (authenticate) the connection
        let _ = MarshalAuth::<SignatureScheme, ProtocolType>::verify_user(
            &mut connection,
            &mut redis_client,
        )
        .await;

        // We don't care about this, just drop the connection immediately.
        let _ = connection.0.finish().await;
    }
}
