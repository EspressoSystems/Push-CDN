//! Benchmarks for allocating and sending direct messages.
//! If run with `--profile-time=N seconds`, it will output a flamegraph.

use std::time::Duration;

use cdn_broker::reexports::tests::{TestDefinition, TestRun};
use cdn_broker::{assert_received, send_message_as};
use cdn_proto::connection::{protocols::Connection as _, Bytes};
use cdn_proto::message::{Direct, Message, Topic};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pprof::criterion::{Output, PProfProfiler};

/// The function under bench for direct messaging a user to itself.
async fn direct_user_to_self(run: &TestRun) {
    // Allocate a rather large message
    let message = Message::Direct(Direct {
        recipient: vec![0],
        message: vec![0; 10000],
    });

    // Send the message, assert we've received it
    send_message_as!(run.connected_users[0], message);
    assert_received!(yes, run.connected_users[0], message);
}

/// The function under bench for direct messaging a user to another user on
/// the same broker.
async fn direct_user_to_user(run: &TestRun) {
    // Allocate a rather large message
    let message = Message::Direct(Direct {
        recipient: vec![1],
        message: vec![0; 10000],
    });

    // Send the message, assert we've received it
    send_message_as!(run.connected_users[0], message);
    assert_received!(yes, run.connected_users[1], message);
}

/// The function under bench for direct messaging a user to another user on
/// a different broker.
async fn direct_user_to_broker(run: &TestRun) {
    // Allocate a rather large message
    let message = Message::Direct(Direct {
        recipient: vec![2],
        message: vec![0; 10000],
    });

    // Send the message, assert we've received it
    send_message_as!(run.connected_users[0], message);
    assert_received!(yes, run.connected_brokers[0], message);
}

/// The function under bench for direct messaging (as a broker) a user to a broker
/// with a particular user.
async fn direct_broker_to_user(run: &TestRun) {
    // Allocate a rather large message
    let message = Message::Direct(Direct {
        recipient: vec![0],
        message: vec![0; 10000],
    });

    // Send the message, assert we've received it
    send_message_as!(run.connected_brokers[0], message);
    assert_received!(yes, run.connected_users[0], message);
}

use tokio::time::timeout;

/// Benchmark sending a direct message as a user through a broker to the same user.
fn bench_direct_user_to_self(c: &mut Criterion) {
    // Create new tokio runtime
    let benchmark_runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");

    // Set up our broker under test
    let run = benchmark_runtime.block_on(async move {
        let run_definition = TestDefinition {
            connected_users: vec![vec![Topic::Global]],
            connected_brokers: vec![],
        };

        run_definition.into_run().await
    });

    // Run the benchmark
    c.bench_function("direct: user -> broker -> same user", |b| {
        b.to_async(&benchmark_runtime)
            .iter(|| direct_user_to_self(black_box(&run)));
    });
}

/// Benchmark sending a direct message as a user through a broker to a different user
/// on that broker.
fn bench_direct_user_to_user(c: &mut Criterion) {
    // Create new tokio runtime
    let benchmark_runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");

    // Set up our broker under test
    let run = benchmark_runtime.block_on(async move {
        let run_definition = TestDefinition {
            connected_users: vec![vec![Topic::Global], vec![Topic::Global]],
            connected_brokers: vec![],
        };

        run_definition.into_run().await
    });

    // Run the benchmark
    c.bench_function("direct: user -> broker -> different user", |b| {
        b.to_async(&benchmark_runtime)
            .iter(|| direct_user_to_user(black_box(&run)));
    });
}

/// Benchmark sending a direct message as a user through the broker to another broker
/// that owns a different user.
fn bench_direct_user_to_broker(c: &mut Criterion) {
    // Create new tokio runtime
    let benchmark_runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");

    // Set up our broker under test
    let run = benchmark_runtime.block_on(async move {
        let run_definition = TestDefinition {
            connected_users: vec![vec![Topic::Global], vec![Topic::Global]],
            connected_brokers: vec![(vec![2], vec![Topic::Global])],
        };

        run_definition.into_run().await
    });

    // Run the benchmark
    c.bench_function("direct: user -> broker -> broker", |b| {
        b.to_async(&benchmark_runtime)
            .iter(|| direct_user_to_broker(black_box(&run)));
    });
}

/// Benchmark sending a direct message as a broker through the broker to a user that
/// we own.
fn bench_direct_broker_to_user(c: &mut Criterion) {
    // Create new tokio runtime
    let benchmark_runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");

    // Set up our broker under test
    let run = benchmark_runtime.block_on(async move {
        let run_definition = TestDefinition {
            connected_users: vec![vec![Topic::Global], vec![Topic::Global]],
            connected_brokers: vec![(vec![2], vec![Topic::Global])],
        };

        run_definition.into_run().await
    });

    // Run the benchmark
    c.bench_function("direct: broker -> broker -> user", |b| {
        b.to_async(&benchmark_runtime)
            .iter(|| direct_broker_to_user(black_box(&run)));
    });
}

// Group the benchmarl. Specify using an optional `flamegraph` profiler.
criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_direct_user_to_self, bench_direct_user_to_user, bench_direct_user_to_broker, bench_direct_broker_to_user
}

criterion_main!(benches);
