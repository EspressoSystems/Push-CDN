use cdn_proto::{
    connection::{
        auth::marshal::MarshalAuth,
        protocols::{Protocol, Sender},
    },
    mnemonic, Def, DiscoveryClientType,
};
use tracing::info;

use crate::Marshal;

impl<UserDef: Def> Marshal<UserDef> {
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        connection: (
            <UserDef::Protocol as Protocol>::Sender,
            <UserDef::Protocol as Protocol>::Receiver,
        ),
        mut discovery_client: DiscoveryClientType,
    ) {
        // Verify (authenticate) the connection
        if let Ok(user_public_key) =
            MarshalAuth::<UserDef>::verify_user(&connection, &mut discovery_client).await
        {
            info!("user {} authenticated", mnemonic(&user_public_key));
        }

        // Finish the connection to ensure all data is sent
        connection.0.finish().await;
    }
}
