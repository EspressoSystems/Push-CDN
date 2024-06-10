//! Feature-gated connection specific metrics

use lazy_static::lazy_static;
use prometheus::{register_gauge, register_histogram, Gauge, Histogram};

lazy_static! {
    // The total number of bytes sent
    pub static ref BYTES_SENT: Gauge =
        register_gauge!("total_bytes_sent", "the total number of bytes sent").unwrap();

    // The total number of bytes received
    pub static ref BYTES_RECV: Gauge =
        register_gauge!("total_bytes_recv", "the total number of bytes received").unwrap();

    // Per-message latency
    pub static ref LATENCY: Histogram =
        register_histogram!("message_latency", "message delivery latency").unwrap();
}
