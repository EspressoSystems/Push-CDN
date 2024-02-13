use proto::{
    connection::{
        auth::marshal::MarshalAuth,
        protocols::{Protocol, Sender},
    },
    crypto::{Scheme, Serializable},
    DiscoveryClientType, UserProtocol,
};

use crate::Marshal;

impl<SignatureScheme: Scheme> Marshal<SignatureScheme>
where
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::Signature: Serializable,
{
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        mut connection: (
            <UserProtocol as Protocol>::Sender,
            <UserProtocol as Protocol>::Receiver,
        ),
        mut discovery_client: DiscoveryClientType,
    ) {
        // Verify (authenticate) the connection
        let _ = MarshalAuth::<SignatureScheme>::verify_user(&mut connection, &mut discovery_client)
            .await;

        // We don't care about this, just drop the connection immediately.
        let _ = connection.0.finish().await;
    }
}
