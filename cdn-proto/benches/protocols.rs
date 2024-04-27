//! Benchmarks for network protocols [Quic/TCP]

use cdn_proto::{
    connection::{
        middleware::NoMiddleware,
        protocols::{quic::Quic, tcp::Tcp, Connection, Listener, Protocol, UnfinalizedConnection},
        Bytes,
    },
    crypto::tls::{generate_cert_from_ca, LOCAL_CA_CERT, LOCAL_CA_KEY},
    message::{Broadcast, Message},
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pprof::criterion::{Output, PProfProfiler};
use tokio::{join, runtime::Runtime, spawn};

/// Transfer a message `raw_message` from `conn1` to `conn2.` This is the primary
/// function used for testing network protocol speed.
async fn transfer<Proto: Protocol<NoMiddleware>>(
    conn1: Proto::Connection,
    conn2: Proto::Connection,
    raw_message: Bytes,
) {
    // Send from the first connection
    let conn1_jh = spawn(async move {
        conn1
            .send_message_raw(raw_message.clone())
            .await
            .expect("failed to send message");
    });

    // Receive from the second connection
    let conn2_jh = spawn(async move {
        conn2
            .recv_message_raw()
            .await
            .expect("failed to receive message");
    });

    // Wait for both to finish
    let _ = join!(conn1_jh, conn2_jh);
}

/// Set up our protocol benchmarks, including async runtime, given the message size
/// to test.
fn set_up_bench<Proto: Protocol<NoMiddleware>>(
    message_size: usize,
) -> (Runtime, Proto::Connection, Proto::Connection, Bytes) {
    // Create new tokio runtime
    let benchmark_runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");

    // Set up our protocol under test
    let (conn1, conn2, message) = benchmark_runtime.block_on(async move {
        // Find random, open port to use
        let port = portpicker::pick_unused_port().expect("no ports available");

        // Generate cert from local CA for testing
        let (tls_cert, tls_key) = generate_cert_from_ca(LOCAL_CA_CERT, LOCAL_CA_KEY)
            .expect("failed to generate TLS cert from CA");

        // Create listener, bind to port
        let listener = Proto::bind(&format!("127.0.0.1:{port}"), tls_cert, tls_key)
            .await
            .expect("failed to listen on port");

        // Spawn future that resolves to our inbound connection
        let listener_jh = spawn(async move {
            // Accept connection
            let unfinalized_connection =
                listener.accept().await.expect("failed to open connection");

            // Finalize the connection
            unfinalized_connection
                .finalize()
                .await
                .expect("failed to finalize connection")
        });

        // Attempt to connect
        let conn1 = Proto::connect(&format!("127.0.0.1:{port}"), true)
            .await
            .expect("failed to connect to listener");

        // Wait for listener to resolve
        let conn2 = listener_jh.await.expect("failed to join listener task");

        // Create message of particular size
        let message = Bytes::from_unchecked(
            Message::Broadcast(Broadcast {
                topics: vec![],
                message: vec![0; message_size],
            })
            .serialize()
            .expect("failed to serialize message"),
        );

        (conn1, conn2, message)
    });

    (benchmark_runtime, conn1, conn2, message)
}

/// Bench the `QUIC` protocol implementation
fn bench_quic(c: &mut Criterion) {
    static KB: usize = 1024;
    static MB: usize = 1024 * 1024;
    let mut group = c.benchmark_group("quic_transfer");
    // The message sizes we want to test
    for size in &[100, KB, 100 * KB, 10 * MB, 100 * MB] {
        // Set up our bench
        let (runtime, conn1, conn2, message) = set_up_bench::<Quic>(*size);

        // Run with variable throughput
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.to_async(&runtime).iter(|| {
                transfer::<Quic>(
                    black_box(conn1.clone()),
                    black_box(conn2.clone()),
                    black_box(message.clone()),
                )
            });
        });
    }

    group.finish();
}

/// Bench the `TCP` protocol implementation
fn bench_tcp(c: &mut Criterion) {
    static KB: usize = 1024;
    static MB: usize = 1024 * 1024;
    let mut group = c.benchmark_group("tcp_transfer");
    // The message sizes we want to test
    for size in &[100, KB, 100 * KB, 10 * MB, 100 * MB] {
        // Set up our bench
        let (runtime, conn1, conn2, message) = set_up_bench::<Tcp>(*size);

        // Run with variable throughput
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.to_async(&runtime).iter(|| {
                transfer::<Tcp>(
                    black_box(conn1.clone()),
                    black_box(conn2.clone()),
                    black_box(message.clone()),
                )
            });
        });
    }

    group.finish();
}

// Set up the benchmnark with the optional flamegraph profiler
criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_quic, bench_tcp
}

criterion_main!(benches);
