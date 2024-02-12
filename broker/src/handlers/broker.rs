use std::{sync::Arc, time::Duration};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
// TODO: figure out if we should use Tokio's here
use proto::{
    authenticate_with_broker,
    connection::{auth::broker::BrokerAuth, batch::BatchedSender, protocols::Protocol},
    crypto::Serializable,
    verify_broker,
};
use tracing::{error, info};

use crate::{get_lock, Inner};

/// This function is the callback for handling a broker (private) connection.
pub async fn handle_connection<
    BrokerSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    BrokerProtocolType: Protocol,
    UserSignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    UserProtocolType: Protocol,
>(
    inner: Arc<
        Inner<BrokerSignatureScheme, BrokerProtocolType, UserSignatureScheme, UserProtocolType>,
    >,
    mut connection: (BrokerProtocolType::Sender, BrokerProtocolType::Receiver),
    is_outbound: bool,
) where
    UserSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::Signature: Serializable,
    BrokerSignatureScheme::VerificationKey: Serializable,
    BrokerSignatureScheme::SigningKey: Serializable,
{
    // Depending on which way the direction came in, we will want to authenticate with a different
    // flow.
    let broker_address = if is_outbound {
        // If we reached out to the other broker first, authenticate first.
        let broker_address = authenticate_with_broker!(connection, inner);
        verify_broker!(connection, inner);
        broker_address
    } else {
        // If the other broker reached out to us first, authenticate second.
        verify_broker!(connection, inner);
        authenticate_with_broker!(connection, inner)
    };

    // Create new batch sender
    let (sender, receiver) = connection;
    // TODO: parameterize max interval and max size
    let sender = Arc::from(BatchedSender::<BrokerProtocolType>::from(
        sender,
        Duration::from_millis(50),
        1500,
    ));

    // Add to our connected broker identities so we don't try to reconnect
    get_lock!(inner.connected_broker_identities, write).insert(broker_address.clone());

    // Freeze the sender before adding it to our connections so we don't receive messages out of order.
    // This is to enforce message ordering
    let _ = sender.freeze();

    // Add our connection to the list of connections
    let connection_id = inner
        .broker_connection_lookup
        .write()
        .await
        .add_connection(sender.clone());

    // Get all brokers (excluding ourselves)
    let all_brokers = get_lock!(inner.broker_connection_lookup, read).get_all_connections();

    // Send all relevant updates to brokers, flushing our updates. Send the partial updates
    // to everyone, and the full to the new broker.
    let _ = inner
        .send_updates_to_brokers(all_brokers, vec![(connection_id, sender.clone())])
        .await;

    // Unfreeze the sender, flushing the updates
    let _ = sender.unfreeze();

    info!("connected to broker {}", broker_address);

    // If we error, come back to the callback so we can remove the connection from the list.
    if let Err(err) = inner.broker_recv_loop(connection_id, receiver).await {
        error!("broker disconnected with error: {err}");
    };

    info!("disconnected from broker {}", broker_address);

    // Remove from the connected broker identities so that we may
    // try to reconnect inthe future.
    get_lock!(inner.connected_broker_identities, write).remove(&broker_address);

    // Remove from our connections so that we don't send any more data
    // their way.
    get_lock!(inner.broker_connection_lookup, write).remove_connection(connection_id);
}
