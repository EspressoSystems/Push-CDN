//! A simple metrics server that allows us to serve process metrics as-needed.

use std::net::SocketAddr;

use warp::Filter;

/// Start the metrics server that should run forever on a particular port
pub async fn serve_metrics(bind_address: SocketAddr) {
    // The `/metrics` route is standard for Prometheus deployments
    let route = warp::path("metrics").map(|| {
        // Gather all metrics, encode them, and return them.
        let encoder = prometheus::TextEncoder::new();
        let metric_families = prometheus::gather();

        encoder.encode_to_string(&metric_families).unwrap()
    });

    // Serve the route on the specified port
    warp::serve(route).run(bind_address).await;
}
