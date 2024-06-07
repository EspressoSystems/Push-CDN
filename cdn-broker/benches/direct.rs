//! Benchmarks for allocating and sending direct messages.
//! If run with `--profile-time=N seconds`, it will output a flamegraph.

use std::time::Duration;

use cdn_broker::reexports::tests::{TestBroker, TestDefinition, TestRun, TestUser};
use cdn_broker::{assert_received, at_index, send_message_as};
use cdn_proto::connection::protocols::memory::Memory;
use cdn_proto::connection::Bytes;
use cdn_proto::def::TestTopic;
use cdn_proto::message::{Direct, Message};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pprof::criterion::{Output, PProfProfiler};

/// The function under bench for direct messaging a user to itself.
async fn direct_user_to_self(run: &TestRun) {
    // Allocate a rather large message
    let message = Message::Direct(Direct {
        recipient: at_index![0],
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
        recipient: at_index![1],
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
        recipient: at_index![2],
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
        recipient: at_index![0],
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
            connected_users: vec![TestUser::with_index(0, vec![TestTopic::Global as u8])],
            connected_brokers: vec![],
        };

        run_definition.into_run::<Memory, Memory>().await
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
            connected_users: vec![
                TestUser::with_index(0, vec![TestTopic::Global as u8]),
                TestUser::with_index(1, vec![TestTopic::Global as u8]),
            ],
            connected_brokers: vec![],
        };

        run_definition.into_run::<Memory, Memory>().await
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
            connected_users: vec![
                TestUser::with_index(0, vec![TestTopic::Global as u8]),
                TestUser::with_index(1, vec![TestTopic::Global as u8]),
            ],
            connected_brokers: vec![TestBroker {
                connected_users: vec![TestUser::with_index(2, vec![TestTopic::Global as u8])],
            }],
        };

        run_definition.into_run::<Memory, Memory>().await
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
            connected_users: vec![
                TestUser::with_index(0, vec![TestTopic::Global as u8]),
                TestUser::with_index(1, vec![TestTopic::Global as u8]),
            ],
            connected_brokers: vec![TestBroker {
                connected_users: vec![TestUser::with_index(0, vec![TestTopic::Global as u8])],
            }],
        };

        run_definition.into_run::<Memory, Memory>().await
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
