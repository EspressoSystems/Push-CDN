use std::time::Duration;

use cdn_proto::{
    connection::{auth::marshal::MarshalAuth, protocols::Connection as _},
    def::{Connection, RunDef},
    mnemonic,
};
use tokio::time::timeout;
use tracing::info;

use crate::Marshal;

impl<R: RunDef> Marshal<R> {
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        connection: Connection<R::User>,
        mut discovery_client: R::DiscoveryClientType,
    ) {
        // Verify (authenticate) the connection
        if let Ok(Ok(user_public_key)) = timeout(
            Duration::from_secs(5),
            MarshalAuth::<R>::verify_user(&connection, &mut discovery_client),
        )
        .await
        {
            info!(id = mnemonic(&user_public_key), "user authenticated");
        }

        // Finish the connection, sending any remaining data.
        connection.finish().await;
    }
}
