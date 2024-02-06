// use std::{
//     sync::{atomic::AtomicU64, Arc},
//     time::SystemTime,
// };

// use proto::connection::protocols::Protocol;
// use tokio::sync::Mutex;

// pub struct ConnectionWithQueue<ProtocolType: Protocol> {
//     pub connection: Arc<Mutex<ProtocolType::Connection>>,
//     pub last_sent: SystemTime,
//     pub buffer: Arc<Mutex<Vec<Arc<Vec<u8>>>>>,
//     pub size: AtomicU64,
// }
