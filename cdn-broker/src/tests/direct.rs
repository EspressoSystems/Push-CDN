// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! Deterministic tests for sending and receiving direct messages.
//! Asserts they all go to the right place.

use std::time::Duration;

use cdn_proto::{
    connection::{protocols::memory::Memory, Bytes},
    def::TestTopic,
    message::{Direct, Message},
};
use tokio::time::{sleep, timeout};

use super::{TestBroker, TestDefinition, TestUser};
use crate::{assert_received, at_index, send_message_as};

/// This test tests that:
/// 1. A user sending a message to itself on a broker has it delivered
/// 2. A user sending a message to another user on the same broker has it delivered
/// 3. Nobody else receives anything
/// 4. We don't receive a duplicate message
#[tokio::test]
async fn test_direct_user_to_user() {
    // This run definition: 3 brokers, 6 users
    let run_definition = TestDefinition {
        connected_users: vec![
            TestUser::with_index(0, vec![TestTopic::Global.into()]),
            TestUser::with_index(1, vec![TestTopic::DA.into()]),
        ],
        connected_brokers: vec![
            TestBroker {
                connected_users: vec![TestUser::with_index(2, vec![TestTopic::DA.into()])],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(3, vec![])],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(4, vec![])],
            },
        ],
    };

    // Start the run
    let run = run_definition.into_run::<Memory, Memory>().await;

    // Send a message from user_0 to itself
    let message = Message::Direct(Direct {
        recipient: at_index![0],
        message: b"test direct 0".to_vec(),
    });

    // Send the message to our broker
    send_message_as!(run.connected_users[0], message);

    // Assert user_0 received it
    assert_received!(yes, run.connected_users[0], message);

    // Assert no one else got it, and we didn't get it again
    assert_received!(no, all, run.connected_users);
    assert_received!(no, all, run.connected_brokers);

    // Create a message that user_1 will use to send to user_0
    let message = Message::Direct(Direct {
        recipient: at_index![1],
        message: b"test direct 1".to_vec(),
    });

    // Send the message to user0 from user1
    send_message_as!(run.connected_users[1], message);

    // Assert user0 received it and nobody else
    assert_received!(yes, run.connected_users[1], message);

    // Assert no one else got it, and we didn't get it again
    assert_received!(no, all, run.connected_users);
    assert_received!(no, all, run.connected_brokers);
}

/// This test tests that:
/// 1. A user sending a message to a user connected to another broker -> the broker is the only one who receives it
/// 2. Nobody else receives anything
/// 3. We don't receive a duplicate message
#[tokio::test]
async fn test_direct_user_to_broker() {
    // This run definition: 3 brokers, 6 users
    let run_definition = TestDefinition {
        connected_users: vec![
            TestUser::with_index(0, vec![TestTopic::Global.into()]),
            TestUser::with_index(1, vec![TestTopic::Global.into(), TestTopic::DA.into()]),
        ],
        connected_brokers: vec![
            TestBroker {
                connected_users: vec![TestUser::with_index(2, vec![])],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(3, vec![TestTopic::DA.into()])],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(4, vec![])],
            },
        ],
    };

    // Start the run
    let run = run_definition.into_run::<Memory, Memory>().await;

    // Send a message as a user to another user that another broker owns (user_0 to user_2)
    let message = Message::Direct(Direct {
        recipient: at_index![2],
        message: b"test direct 2".to_vec(),
    });

    // Send the message as user_0
    send_message_as!(run.connected_users[0], message);

    // Assert broker_0 received it
    assert_received!(yes, run.connected_brokers[0], message);

    // Assert no one else got it, and we didn't get it again
    assert_received!(no, all, run.connected_users);
    assert_received!(no, all, run.connected_brokers);
}

/// This test tests that:
/// 1. A broker sending a message to another broker doesn't have it come back to them
/// 2. Nobody else receives anything
/// 3. We don't receive a duplicate message
#[tokio::test]
async fn test_direct_broker_to_user() {
    // This run definition: 3 brokers, 6 users
    let run_definition = TestDefinition {
        connected_users: vec![
            TestUser::with_index(0, vec![TestTopic::Global.into()]),
            TestUser::with_index(1, vec![TestTopic::Global.into(), TestTopic::DA.into()]),
        ],
        connected_brokers: vec![
            TestBroker {
                connected_users: vec![TestUser::with_index(2, vec![])],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(3, vec![TestTopic::DA.into()])],
            },
            TestBroker {
                connected_users: vec![TestUser::with_index(4, vec![])],
            },
        ],
    };

    // Start the run
    let run = run_definition.into_run::<Memory, Memory>().await;

    // Send a message as a broker through the test broker to a user that we own
    // Tests that broker_1 -> test_broker should not come back to us.
    let message = Message::Direct(Direct {
        recipient: at_index![2],
        message: b"test direct 2".to_vec(),
    });

    // Send the message as broker_1
    send_message_as!(run.connected_brokers[1], message);

    // Wait a bit for the message to propagate
    sleep(Duration::from_millis(25)).await;

    // Assert nobody received it
    assert_received!(no, all, run.connected_users);
    assert_received!(no, all, run.connected_brokers);
}
