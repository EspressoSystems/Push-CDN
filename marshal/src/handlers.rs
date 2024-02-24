use proto::{
    connection::{auth::marshal::MarshalAuth, protocols::Protocol},
    crypto::signature::SignatureScheme,
    mnemonic, DiscoveryClientType,
};
use tracing::info;

use crate::Marshal;

impl<Scheme: SignatureScheme, UserProtocol: Protocol> Marshal<Scheme, UserProtocol> {
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        connection: (UserProtocol::Sender, UserProtocol::Receiver),
        mut discovery_client: DiscoveryClientType,
    ) {
        // Verify (authenticate) the connection
        if let Ok(user_public_key) =
            MarshalAuth::<Scheme, UserProtocol>::verify_user(&connection, &mut discovery_client)
                .await
        {
            info!("user {} authenticated", mnemonic(&user_public_key));
        }
    }
}
