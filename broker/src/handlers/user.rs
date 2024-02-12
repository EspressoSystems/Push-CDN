use std::{sync::Arc, time::Duration};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
use proto::{
    connection::{auth::broker::BrokerAuth, batch::BatchedSender, protocols::Protocol},
    crypto::Serializable,
};
use slotmap::Key;
use tracing::info;

use crate::{get_lock, Inner};

/// This function handles a user (public) connection.
pub async fn handle_connection<
    BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    BrokerProtocolType: Protocol,
    UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserProtocolType: Protocol,
>(
    inner: Arc<
        Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
    >,
    mut connection: (UserProtocolType::Sender, UserProtocolType::Receiver),
) where
    UserSignatureScheme::VerificationKey: Serializable,
    UserSignatureScheme::Signature: Serializable,
    UserSignatureScheme::SigningKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::SigningKey: Serializable,
{
    // Verify (authenticate) the connection
    let Ok((verification_key, topics)) =
        BrokerAuth::<UserSignatureScheme, UserProtocolType>::verify_user(
            &mut connection,
            &inner.identifier,
            &mut inner.redis_client.clone(),
        )
        .await
    else {
        return;
    };

    // Create new batch sender
    let (sender, receiver) = connection;
    let sender = Arc::new(BatchedSender::<UserProtocolType>::from(
        sender,
        Duration::from_millis(50),
        1500,
    ));

    // Add the connection to the list of connections
    let connection_id = get_lock!(inner.user_connection_lookup, write).add_connection(sender);

    // Add the user for their topics
    get_lock!(inner.user_connection_lookup, write)
        .subscribe_connection_id_to_topics(connection_id, topics);

    // Add the user for their key
    get_lock!(inner.user_connection_lookup, write)
        .subscribe_connection_id_to_keys(connection_id, vec![verification_key]);

    info!("received connection from user {:?}", connection_id.data());

    // If we have a small amount of users, send the updates immediately
    if get_lock!(inner.user_connection_lookup, read).get_connection_count() < 50 {
        // TODO NEXT: Move this into just asking the task nicely to do it
        let _ = inner
            .send_updates_to_brokers(
                vec![],
                get_lock!(inner.broker_connection_lookup, read)
                    .get_all_connections()
                    .clone(),
            )
            .await;
    }

    // This runs the main loop for receiving information from the user
    let () = inner.user_recv_loop(connection_id, receiver).await;

    info!("user {:?} disconnected", connection_id.data());
    // Once the main loop ends, we remove the connection
    inner
        .user_connection_lookup
        .write()
        .await
        .remove_connection(connection_id);
}
