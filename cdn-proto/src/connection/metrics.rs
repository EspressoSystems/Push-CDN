// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

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
        register_histogram!("latency", "message delivery latency").unwrap();

    // The per-message latency over the last 30 seconds
    pub static ref RUNNING_LATENCY: Gauge =
        register_gauge!("running_latency", "average tail latency over the last 30s").unwrap();
}
