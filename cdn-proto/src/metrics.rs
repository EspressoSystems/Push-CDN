//! A simple metrics server that allows us to serve process metrics as-needed.

use std::{net::SocketAddr, time::Duration};

use tokio::time::sleep;
use tracing::error;
use warp::Filter;

use crate::connection::metrics;

/// Start the metrics server that should run forever on a particular port
pub async fn serve_metrics(bind_endpoint: SocketAddr) {
    // Spawn an additional task to calculate the running latency
    tokio::spawn(running_latency_calculator());

    // The `/metrics` route is standard for Prometheus deployments
    let route = warp::path("metrics").map(|| {
        // Gather all metrics, encode them, and return them.
        let encoder = prometheus::TextEncoder::new();
        let metric_families = prometheus::gather();

        match encoder.encode_to_string(&metric_families) {
            Ok(metrics) => metrics,
            Err(err) => {
                error!("failed to encode metrics: {err}");
                "failed to encode metrics".to_string()
            }
        }
    });

    // Serve the route on the specified port
    warp::serve(route).run(bind_endpoint).await;
}

/// A simple latency calculator that calculates the running latency every 30s
/// and sets the corresponding `RUNNING_LATENCY` gauge.
pub async fn running_latency_calculator() {
    // Initialize the values to 0
    let mut latency_sum = 0.0;
    let mut latency_count = 0;

    // Start calculating the latency
    loop {
        // Sleep for 30s
        sleep(Duration::from_secs(30)).await;

        // Fetch the current sum and count
        let current_sum = metrics::LATENCY.get_sample_sum();
        let current_count = metrics::LATENCY.get_sample_count();

        // Calculate the running latency by subtracting the previous sum and count
        latency_sum = current_sum - latency_sum;
        latency_count = current_count - latency_count;

        // Set the running latency if the new count is not 0
        if latency_count != 0 {
            metrics::RUNNING_LATENCY.set(latency_sum / latency_count as f64);
        }

        // Update the previous sum and count for the next iteration
        latency_sum = current_sum;
        latency_count = current_count;
    }
}
