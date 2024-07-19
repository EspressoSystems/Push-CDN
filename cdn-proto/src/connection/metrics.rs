//! Feature-gated connection specific metrics

use lazy_static::lazy_static;
use prometheus::{register_gauge, register_histogram, Gauge, Histogram};

lazy_static! {
    // The total number of bytes sent
    pub static ref BYTES_SENT: Option<Gauge> =
        register_gauge!("total_bytes_sent", "the total number of bytes sent").map_err(|e| eprintln!("Could not register metric: {:?}", e)).ok();

    // The total number of bytes received
    pub static ref BYTES_RECV: Option<Gauge> =
        register_gauge!("total_bytes_recv", "the total number of bytes received").map_err(|e| eprintln!("Could not register metric: {:?}", e)).ok();

    // Per-message latency
    pub static ref LATENCY: Option<Histogram> =
        register_histogram!("latency", "message delivery latency").map_err(|e| eprintln!("Could not register metric: {:?}", e)).ok();

    // The per-message latency over the last 30 seconds
    pub static ref RUNNING_LATENCY: Option<Gauge> =
        register_gauge!("running_latency", "average tail latency over the last 30s").map_err(|e| eprintln!("Could not register metric: {:?}", e)).ok();
}
