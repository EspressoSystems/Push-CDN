//! Benchmarks for allocating and sending broadcast messages.
//! If run with `--profile-time=N seconds`, it will output a flamegraph.

use cdn_proto::connection::{protocols::Sender, Bytes};
use std::time::Duration;

use broker::reexports::tests::{Run, RunDefinition};
use broker::{assert_received, send_message_as};
use cdn_proto::message::{Broadcast, Message, Topic};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pprof::criterion::{Output, PProfProfiler};

/// The function under bench for broadcasting a message to two users.
async fn broadcast_user(run: &Run) {
    // Allocate a rather large message
    let message = Message::Broadcast(Broadcast {
        topics: vec![Topic::Global],
        message: vec![0; 10000],
    });

    // Send the message, assert we've received it
    send_message_as!(run.connected_users[0], message);
    assert_received!(yes, run.connected_users[0], message);
    assert_received!(yes, run.connected_users[1], message);
}

/// The function under bench for broadcasting a message to two brokers.
async fn broadcast_broker(run: &Run) {
    // Allocate a rather large message
    let message = Message::Broadcast(Broadcast {
        topics: vec![Topic::Global],
        message: vec![0; 10000],
    });

    // Send the message, assert we've received it
    send_message_as!(run.connected_users[0], message);
    assert_received!(yes, run.connected_brokers[0], message);
    assert_received!(yes, run.connected_brokers[1], message);
}

use tokio::time::timeout;

/// Bench broadcasting to two users subscribed to the same topic.
fn bench_broadcast_user(c: &mut Criterion) {
    // Create new tokio runtime
    let benchmark_runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");

    // Set up our broker under test
    let run = benchmark_runtime.block_on(async move {
        let run_definition = RunDefinition {
            connected_users: vec![vec![Topic::Global], vec![Topic::Global]],
            connected_brokers: vec![],
        };

        let run = run_definition.into_run().await;

        run
    });

    // Benchmark
    c.bench_function("broadcast: users", |b| {
        b.to_async(&benchmark_runtime)
            .iter(|| broadcast_user(black_box(&run)))
    });
}

/// Bench broadcasting to two brokers subscribed to the same topi.c
fn bench_broadcast_broker(c: &mut Criterion) {
    // Create new tokio runtime
    let benchmark_runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");

    // Set up our broker under test
    let run = benchmark_runtime.block_on(async move {
        let run_definition = RunDefinition {
            connected_users: vec![vec![]],
            connected_brokers: vec![(vec![], vec![Topic::Global]), (vec![], vec![Topic::Global])],
        };

        let run = run_definition.into_run().await;

        run
    });

    // Benchmark
    c.bench_function("broadcast: brokers", |b| {
        b.to_async(&benchmark_runtime)
            .iter(|| broadcast_broker(black_box(&run)))
    });
}

// Set up the benchmnark with the optional flamegraph profiler
criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_broadcast_user, bench_broadcast_broker
}

criterion_main!(benches);
