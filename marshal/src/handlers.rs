use proto::{
    connection::{
        auth::marshal::MarshalAuth,
        protocols::{Protocol, Sender},
    },
    crypto::signature::SignatureScheme,
    DiscoveryClientType, UserProtocol,
};

use crate::Marshal;

impl<Scheme: SignatureScheme> Marshal<Scheme> {
    /// Handles a user's connection, including authentication.
    pub async fn handle_connection(
        mut connection: (
            <UserProtocol as Protocol>::Sender,
            <UserProtocol as Protocol>::Receiver,
        ),
        mut discovery_client: DiscoveryClientType,
    ) {
        // Verify (authenticate) the connection
        let _ = MarshalAuth::<Scheme>::verify_user(&mut connection, &mut discovery_client).await;

        // We don't care about this, just drop the connection immediately.
        let _ = connection.0.finish().await;
    }
}
