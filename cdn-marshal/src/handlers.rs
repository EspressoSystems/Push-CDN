use std::time::Duration;

use cdn_proto::{
    connection::{
        auth::marshal::MarshalAuth,
        hooks::Untrusted,
        protocols::{Protocol, Sender},
    },
    crypto::signature::SignatureScheme,
    mnemonic, DiscoveryClientType,
};
use tokio::time::timeout;
use tracing::info;

use crate::Marshal;

impl<Scheme: SignatureScheme, UserProtocol: Protocol<Untrusted>> Marshal<Scheme, UserProtocol> {
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        connection: (UserProtocol::Sender, UserProtocol::Receiver),
        mut discovery_client: DiscoveryClientType,
    ) {
        // Verify (authenticate) the connection
        if let Ok(Ok(user_public_key)) = timeout(
            Duration::from_secs(5),
            MarshalAuth::<Scheme, UserProtocol>::verify_user(&connection, &mut discovery_client),
        )
        .await
        {
            info!("user {} authenticated", mnemonic(&user_public_key));
        }

        // Finish the connection to ensure all data is sent
        connection.0.finish().await;
    }
}
