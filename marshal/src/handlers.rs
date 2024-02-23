use proto::{
    connection::{auth::marshal::MarshalAuth, protocols::Protocol},
    crypto::signature::SignatureScheme,
    mnemonic, DiscoveryClientType, UserProtocol,
};
use tracing::info;

use crate::Marshal;

impl<Scheme: SignatureScheme> Marshal<Scheme> {
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        connection: (
            <UserProtocol as Protocol>::Sender,
            <UserProtocol as Protocol>::Receiver,
        ),
        mut discovery_client: DiscoveryClientType,
    ) {
        // Verify (authenticate) the connection
        if let Ok(user_public_key) =
            MarshalAuth::<Scheme>::verify_user(&connection, &mut discovery_client).await
        {
            info!("user {} authenticated", mnemonic(&user_public_key));
        }
    }
}
