use std::time::Duration;

use cdn_proto::{
    def::TestTopic,
    message::{Broadcast, Message},
};
use tokio::time::timeout;

use super::*;

/// Test that an end-to-end connection succeeds
#[tokio::test]
async fn test_subscribe() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path();

    // Create and start a new broker
    new_broker(0, "8080", "8081", &discovery_endpoint).await;

    // Create and start a new marshal
    new_marshal("8082", &discovery_endpoint).await;

    // Create and get the handle to a new client subscribed to the global topic
    let client = new_client(0, vec![TestTopic::Global as u8], "8082");

    // Send a message to the global topic
    client
        .send_broadcast_message(vec![TestTopic::Global as u8], b"hello global".to_vec())
        .await
        .expect("failed to send message to topic we were in");

    // Make sure we received the message
    // The message that we expect to receive
    let expected_message = Message::Broadcast(Broadcast {
        topics: vec![TestTopic::Global as u8],
        message: b"hello global".to_vec(),
    });

    // Assert we have received the message
    assert!(
        client
            .receive_message()
            .await
            .expect("failed to receive message from subscribed topic")
            == expected_message,
        "wrong message received from subscribed topic"
    );

    // Send a message to the DA topic
    client
        .send_broadcast_message(vec![TestTopic::DA as u8], b"hello DA".to_vec())
        .await
        .expect("failed to send message to topic we weren't in");

    // Make sure we didn't receive the message
    assert!(timeout(Duration::from_secs(1), client.receive_message())
        .await
        .is_err());

    // Subscribe to the DA topic
    client
        .subscribe(vec![TestTopic::DA as u8])
        .await
        .expect("failed to subscribe to topic");

    // Send a message to the DA topic
    client
        .send_broadcast_message(vec![TestTopic::DA as u8], b"hello DA".to_vec())
        .await
        .expect("failed to send message to topic we were in");

    // Make sure we received the message
    // The message that we expect to receive
    let expected_message = Message::Broadcast(Broadcast {
        topics: vec![TestTopic::DA as u8],
        message: b"hello DA".to_vec(),
    });

    // Assert we have received the message
    assert!(
        client
            .receive_message()
            .await
            .expect("failed to receive message from newly subscribed topic")
            == expected_message,
        "wrong message received from newly subscribed topic"
    );

    // Unsubscribe from the DA topic
    client
        .unsubscribe(vec![TestTopic::DA as u8])
        .await
        .expect("failed to unsubscribe from topic");

    // Send a message to the DA topic
    client
        .send_broadcast_message(vec![TestTopic::DA as u8], b"hello DA".to_vec())
        .await
        .expect("failed to send message to topic we were in");

    // Make sure we didn't receive the message
    assert!(timeout(Duration::from_secs(1), client.receive_message())
        .await
        .is_err());
}
