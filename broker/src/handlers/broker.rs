//! This file defines the broker connection handler.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use proto::{
    authenticate_with_broker,
    connection::{
        auth::broker::BrokerAuth,
        batch::{BatchedSender, Position},
        protocols::{Protocol, Receiver},
    },
    crypto::signature::SignatureScheme,
    error::{Error, Result},
    message::Message,
    verify_broker, BrokerProtocol,
};
use tracing::{error, info};

use crate::{
    get_lock, send_broadcast, send_direct, send_or_remove_many, state::ConnectionId, Inner,
};

use crate::metrics;

impl<BrokerScheme: SignatureScheme, UserScheme: SignatureScheme> Inner<BrokerScheme, UserScheme> {
    /// This function is the callback for handling a broker (private) connection.
    pub async fn handle_broker_connection(
        self: Arc<Self>,
        mut connection: (
            <BrokerProtocol as Protocol>::Sender,
            <BrokerProtocol as Protocol>::Receiver,
        ),
        is_outbound: bool,
    ) {
        // Depending on which way the direction came in, we will want to authenticate with a different
        // flow.
        let broker_address = if is_outbound {
            // If we reached out to the other broker first, authenticate first.
            let broker_address = authenticate_with_broker!(connection, self);
            verify_broker!(connection, self);
            broker_address
        } else {
            // If the other broker reached out to us first, authenticate second.
            verify_broker!(connection, self);
            authenticate_with_broker!(connection, self)
        };

        // Create new batch sender
        let (sender, receiver) = connection;
        // TODO: parameterize max interval and max size
        let sender = Arc::from(BatchedSender::<BrokerProtocol>::from(
            sender,
            Duration::from_millis(50),
            1500,
        ));

        // Add to our connected broker identities so we don't try to reconnect
        let mut connected_broker_guard = get_lock!(self.connected_broker_identities, write);
        if connected_broker_guard.contains(&broker_address) {
            // If the address is already there (we're already connected), drop this one
            return;
        }

        // If we aren't already connected, add it
        connected_broker_guard.insert(broker_address.clone());

        drop(connected_broker_guard);

        // Freeze the sender before adding it to our connections so we don't receive messages out of order.
        // This is to enforce message ordering
        let _ = sender.freeze().await;

        // Add our connection to the list of connections
        let connection_id = self
            .broker_connection_lookup
            .write()
            .await
            .add_connection(sender.clone());

        // Get all brokers (excluding ourselves)
        let all_brokers = get_lock!(self.broker_connection_lookup, read).get_all_connections();

        // Send all relevant updates to brokers, flushing our updates. Send the partial updates
        // to everyone, and the full to the new broker.
        let _ = self
            .send_updates_to_brokers(all_brokers, vec![(connection_id, sender.clone())])
            .await;

        // Unfreeze the sender, flushing the updates
        let _ = sender.unfreeze().await;

        info!("connected to broker {}", broker_address);

        // Increment our metric
        metrics::NUM_BROKERS_CONNECTED.inc();

        // If we error, come back to the callback so we can remove the connection from the list.
        if let Err(err) = self.broker_receive_loop(connection_id, receiver).await {
            error!("broker disconnected with error: {err}");
        };

        info!("disconnected from broker {}", broker_address);

        // Decrement our metric
        metrics::NUM_BROKERS_CONNECTED.dec();

        // Remove from the connected broker identities so that we may
        // try to reconnect inthe future.
        get_lock!(self.connected_broker_identities, write).remove(&broker_address);

        // Remove from our connections so that we don't send any more data
        // their way.
        get_lock!(self.broker_connection_lookup, write).remove_connection(connection_id);
    }

    pub async fn broker_receive_loop(
        &self,
        connection_id: ConnectionId,
        mut receiver: <BrokerProtocol as Protocol>::Receiver,
    ) -> Result<()> {
        while let Ok(message) = receiver.recv_message().await {
            match message {
                // If we receive a direct message from a broker, we want to send it to all users with that key
                Message::Direct(ref direct) => {
                    let message = Bytes::from(message.serialize().expect("serialization failed"));

                    send_direct!(self.user_connection_lookup, direct.recipient, message);
                }

                // If we receive a broadcast message from a broker, we want to send it to all interested users
                Message::Broadcast(ref broadcast) => {
                    let message = Bytes::from(message.serialize().expect("serialization failed"));

                    send_broadcast!(self.user_connection_lookup, broadcast.topics, message);
                }

                // If we receive a subscribe message from a broker, we add them as "interested" locally.
                Message::Subscribe(subscribe) => get_lock!(self.broker_connection_lookup, write)
                    .subscribe_connection_id_to_topics(connection_id, subscribe),

                // If we receive a subscribe message from a broker, we remove them as "interested" locally.
                Message::Unsubscribe(unsubscribe) => {
                    get_lock!(self.broker_connection_lookup, write)
                        .unsubscribe_connection_id_from_topics(connection_id, unsubscribe);
                }

                // If a broker has told us they have some users connected, we update our map as such
                Message::UsersConnected(users) => get_lock!(self.broker_connection_lookup, write)
                    .subscribe_connection_id_to_keys(connection_id, users),

                // If a broker has told us they have some users disconnected, we update our map as such
                Message::UsersDisconnected(users) => {
                    get_lock!(self.broker_connection_lookup, write)
                        .unsubscribe_connection_id_from_keys(connection_id, users);
                }

                // Do nothing if we receive an unexpected message
                _ => {}
            }
        }

        Err(Error::Connection("connection closed".to_string()))
    }
}
