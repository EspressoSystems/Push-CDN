use proto::{
    connection::{auth::marshal::MarshalAuth, protocols::Protocol},
    crypto::signature::SignatureScheme,
    DiscoveryClientType, UserProtocol,
};

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
        let _ = MarshalAuth::<Scheme>::verify_user(&connection, &mut discovery_client).await;
    }
}
