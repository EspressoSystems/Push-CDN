use cdn_proto::{
    connection::{auth::marshal::MarshalAuth, protocols::Protocol, protocols::Sender},
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

        // Finish the connection to ensure all data is sent
        connection.0.finish().await;
    }
}