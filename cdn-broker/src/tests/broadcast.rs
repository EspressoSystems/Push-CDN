//! Deterministic tests for sending and receiving broadcast messages.
//! Asserts they all go to the right place.

use std::time::Duration;

use cdn_proto::{
    connection::{protocols::memory::Memory, Bytes},
    def::TestTopic,
    message::{Broadcast, Message},
};
use tokio::time::{sleep, timeout};

use super::{TestBroker, TestDefinition, TestUser};
use crate::{assert_received, send_message_as};

/// Test sending a broadcast message from a user.
/// This test makes sure that:
/// 1. Any user that sends a topic will see it routed to both users and brokers
/// 2. The user sending it, if subscribed, will receive it themselves
#[tokio::test]
async fn test_broadcast_user() {
    // This run definition: 3 brokers, 6 users
    let run_definition = TestDefinition {
        connected_users: vec![
            TestUser::with_index(0, vec![TestTopic::Global.into(), TestTopic::DA.into()]),
            TestUser::with_index(1, vec![TestTopic::DA.into()]),
            TestUser::with_index(2, vec![TestTopic::Global.into()]),
        ],
        connected_brokers: vec![
            TestBroker {
                connected_users: vec![TestUser::with_index(3, vec![TestTopic::DA.into()])],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(
                    4,
                    vec![TestTopic::Global.into(), TestTopic::DA.into()],
                )],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(5, vec![])],
            },
        ],
    };

    // Start the run
    let run = run_definition.into_run::<Memory, Memory>().await;

    // We need a little time for our subscribe messages to propagate
    sleep(Duration::from_millis(25)).await;

    // Create a broadcast message with the global topic
    let message = Message::Broadcast(Broadcast {
        topics: vec![TestTopic::Global as u8],
        message: b"test broadcast global".to_vec(),
    });

    // (As a user) send the broadcast message
    send_message_as!(run.connected_users[0], message);

    // Ensure everyone subscribed to the topic has seen it
    assert_received!(yes, run.connected_users[0], message);
    assert_received!(yes, run.connected_users[2], message);
    assert_received!(yes, run.connected_brokers[1], message);

    // Ensure everyone not subscribed has not seen it, and we don't
    // see messages twice.
    assert_received!(no, all, run.connected_users);
    assert_received!(no, all, run.connected_brokers);

    // Now we test the DA topic
    let message = Message::Broadcast(Broadcast {
        topics: vec![TestTopic::DA as u8],
        message: b"test broadcast DA".to_vec(),
    });

    // (As a user) send the broadcast message
    send_message_as!(run.connected_users[2], message);

    // Ensure everyone subscribed to the topic has seen it
    assert_received!(yes, run.connected_users[0], message);
    assert_received!(yes, run.connected_users[1], message);
    assert_received!(yes, run.connected_brokers[0], message);
    assert_received!(yes, run.connected_brokers[1], message);

    // Ensure everyone not subscribed has not seen it, and we don't
    // see messages twice.
    assert_received!(no, all, run.connected_users);
    assert_received!(no, all, run.connected_brokers);
}

/// Test sending a broadcast message from a broker.
/// This test makes sure that:
/// 1. Any broker that sends a topic will see it routed to only users
/// 2. The broker sending it, if subscribed, will NOT receive it
#[tokio::test]
async fn test_broadcast_broker() {
    // This run definition: 3 brokers, 6 users
    let run_definition = TestDefinition {
        connected_users: vec![
            TestUser::with_index(0, vec![TestTopic::Global.into(), TestTopic::DA.into()]),
            TestUser::with_index(1, vec![TestTopic::DA.into()]),
            TestUser::with_index(2, vec![TestTopic::Global.into()]),
        ],
        connected_brokers: vec![
            TestBroker {
                connected_users: vec![TestUser::with_index(3, vec![TestTopic::DA.into()])],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(
                    4,
                    vec![TestTopic::Global.into(), TestTopic::DA.into()],
                )],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(5, vec![])],
            },
        ],
    };

    // Start the run
    let run = run_definition.into_run::<Memory, Memory>().await;

    // We need a little time for our subscribe messages to propagate
    sleep(Duration::from_millis(25)).await;

    // Create a broadcast message with the global topic
    let message = Message::Broadcast(Broadcast {
        topics: vec![TestTopic::Global as u8],
        message: b"test broadcast global".to_vec(),
    });

    // (As a user) send the broadcast message
    send_message_as!(run.connected_brokers[2], message);

    // Ensure everyone subscribed to the topic has seen it
    assert_received!(yes, run.connected_users[0], message);
    assert_received!(yes, run.connected_users[2], message);

    // Ensure everyone not subscribed has not seen it, and we don't
    // see messages twice.
    assert_received!(no, all, run.connected_users);
    assert_received!(no, all, run.connected_brokers);

    // Now we test the DA topic
    let message = Message::Broadcast(Broadcast {
        topics: vec![TestTopic::DA as u8],
        message: b"test broadcast DA.".to_vec(),
    });

    // (As a user) send the broadcast message
    send_message_as!(run.connected_brokers[1], message);

    // Ensure everyone subscribed to the topic has seen it
    assert_received!(yes, run.connected_users[0], message);
    assert_received!(yes, run.connected_users[1], message);

    // Ensure everyone not subscribed has not seen it, and we don't
    // see messages twice.
    assert_received!(no, all, run.connected_users);
    assert_received!(no, all, run.connected_brokers);
}
