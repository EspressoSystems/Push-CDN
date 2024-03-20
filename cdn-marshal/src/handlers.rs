use std::time::Duration;

use cdn_proto::{
    connection::{
        auth::marshal::MarshalAuth,
        hooks::Untrusted,
        protocols::{Protocol, Sender},
    },
    def::RunDef,
    mnemonic,
};
use tokio::time::timeout;
use tracing::info;

use crate::Marshal;

impl<Def: RunDef> Marshal<Def> {
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        connection: (
            <Def::UserProtocol as Protocol<Untrusted>>::Sender,
            <Def::UserProtocol as Protocol<Untrusted>>::Receiver,
        ),
        mut discovery_client: Def::DiscoveryClientType,
    ) {
        // Verify (authenticate) the connection
        if let Ok(Ok(user_public_key)) = timeout(
            Duration::from_secs(5),
            MarshalAuth::<Def>::verify_user(&connection, &mut discovery_client),
        )
        .await
        {
            info!("user {} authenticated", mnemonic(&user_public_key));
        }

        // Finish the connection to ensure all data is sent
        connection.0.finish().await;
    }
}
