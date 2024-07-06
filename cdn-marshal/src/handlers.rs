// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

use std::time::Duration;

use cdn_proto::{
    connection::{auth::marshal::MarshalAuth, protocols::Connection},
    def::RunDef,
    mnemonic,
};
use tokio::time::timeout;
use tracing::info;

use crate::Marshal;

impl<R: RunDef> Marshal<R> {
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        connection: Connection,
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

        // Soft close the connection, ensuring all data was sent
        let _ = connection.soft_close().await;
    }
}
