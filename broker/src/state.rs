use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;
// TODO: maybe use Tokio's RwLock
use parking_lot::RwLock;
use proto::{
    connection::protocols::{Connection, Protocol},
    crypto::Serializable,
    message::Topic,
};
use tokio::{spawn, sync::Mutex, time::Instant};

pub struct ConnectionLookup<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
> where
    SignatureScheme::VerificationKey: Serializable,
{
    direct_message_lookup:
        HashMap<SignatureScheme::VerificationKey, Arc<ConnectionWithQueue<ProtocolType>>>,
    broadcast_message_lookup: HashMap<Topic, HashSet<Arc<ConnectionWithQueue<ProtocolType>>>>,
    inverse_broadcast_message_lookup:
        HashMap<Arc<ConnectionWithQueue<ProtocolType>>, HashSet<Topic>>,
}

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > Default for ConnectionLookup<SignatureScheme, ProtocolType>
where
    SignatureScheme::Signature: Serializable,
    SignatureScheme::VerificationKey: Serializable,
    SignatureScheme::SigningKey: Serializable,
{
    fn default() -> Self {
        Self {
            direct_message_lookup: HashMap::default(),
            broadcast_message_lookup: HashMap::default(),
            inverse_broadcast_message_lookup: HashMap::default(),
        }
    }
}

impl<
        SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
        ProtocolType: Protocol,
    > ConnectionLookup<SignatureScheme, ProtocolType>
where
    SignatureScheme::VerificationKey: Serializable,
{
    pub fn subscribe_connection_to_broadcast(
        &mut self,
        connection: Arc<ConnectionWithQueue<ProtocolType>>,
        topics: Vec<Topic>,
    ) {
        //topic -> [connection]
        for topic in topics.clone() {
            self.broadcast_message_lookup
                .entry(topic)
                .or_default()
                .insert(connection.clone());
        }
        //connection -> [topic]
        self.inverse_broadcast_message_lookup
            .entry(connection)
            .or_default()
            .extend(topics);
    }

    pub fn unsubscribe_connection_from_broadcast(
        &mut self,
        connection: Arc<ConnectionWithQueue<ProtocolType>>,
        topics: Vec<Topic>,
    ) {
        //topic -> [connection]
        for topic in topics.clone() {
            // remove connection from topic, and remove topic if empty
            if let Some(connections) = self.broadcast_message_lookup.get_mut(&topic) {
                connections.remove(&connection);
            }
        }

        //key -> [topic]
        if let Some(connection_topics) = self.inverse_broadcast_message_lookup.get_mut(&connection)
        {
            for topic in topics {
                connection_topics.remove(&topic);
            }
        }
    }

    pub fn subscribe_connection_to_direct(
        &mut self,
        connection: Arc<ConnectionWithQueue<ProtocolType>>,
        key: SignatureScheme::VerificationKey,
    ) {
        self.direct_message_lookup.insert(key, connection);
    }

    pub fn unsubscribe_connection_from_direct(&mut self, key: SignatureScheme::VerificationKey) {
        self.direct_message_lookup.remove(&key);
    }
}

pub struct ConnectionWithQueue<ProtocolType: Protocol> {
    queue: Mutex<Vec<Arc<Vec<u8>>>>,
    connection: ProtocolType::Connection,

    current_size: AtomicU64,
    last_sent: RwLock<Instant>,

    min_duration: Duration,
    min_size: u64,
}

impl<ProtocolType: Protocol> PartialEq for ConnectionWithQueue<ProtocolType> {
    fn eq(&self, other: &Self) -> bool {
        self.connection == other.connection
    }
}

impl<ProtocolType: Protocol> Eq for ConnectionWithQueue<ProtocolType> {
    fn assert_receiver_is_total_eq(&self) {}
}

impl<ProtocolType: Protocol> Hash for ConnectionWithQueue<ProtocolType> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.connection.hash(state);
    }

    /// This just calls `hash` on each item in the slice.
    fn hash_slice<H: std::hash::Hasher>(data: &[Self], state: &mut H)
    where
        Self: Sized,
    {
        data.iter().for_each(|item| item.hash(state));
    }
}

impl<ProtocolType: Protocol> ConnectionWithQueue<ProtocolType> {
    pub fn from_connection_and_params(
        connection: ProtocolType::Connection,
        min_duration: Duration,
        min_size: u64,
    ) -> Self {
        Self {
            queue: Mutex::default(),
            connection,
            current_size: AtomicU64::default(),
            last_sent: RwLock::from(Instant::now()),
            min_duration,
            min_size,
        }
    }

    pub async fn add_or_queue_message(&self, message: Arc<Vec<u8>>) {
        // Push the reference to the message
        let message_length = message.len() as u64;
        let mut queue_guard = self.queue.lock().await;
        queue_guard.push(message);

        // Update our size
        let before_send_size = self
            .current_size
            .fetch_add(message_length, Ordering::Relaxed);

        // Bounds check to see if we should send
        if (before_send_size + message_length) >= self.min_size
            || self.last_sent.read().elapsed() >= self.min_duration
        {
            // Move messages out
            // TODO: VEC WITH CAPACITY HERE
            let messages = std::mem::replace(&mut *queue_guard, Vec::new());

            // Spawn a task to flush our queue
            // TODO: see if it's faster to not have this here
            let connection = self.connection.clone();
            spawn(async move {
                // Send the entire batch of messages
                let _ = connection.send_messages_raw(messages).await;
            });
        }
    }
}
