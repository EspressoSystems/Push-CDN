use std::time::Duration;

use cdn_proto::{
    def::TestTopic,
    message::{Broadcast, Message},
};
use tokio::time::{sleep, timeout};

use super::*;

/// Test that subscribing and unsubscribing to topics works as expected
/// on a single broker.
#[tokio::test]
async fn test_subscribe() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path();

    // Create and start a new broker
    new_broker(0, "8095", "8096", &discovery_endpoint).await;

    // Create and start a new marshal
    new_marshal("8097", &discovery_endpoint).await;

    // Create and get the handle to a new client subscribed to the global topic
    let client = new_client(0, vec![TestTopic::Global as u8], "8097");

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
    assert!(
        timeout(Duration::from_secs(1), client.receive_message())
            .await
            .is_err(),
        "received message from topic we weren't in"
    );

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

/// Test that subscribing to an invalid topic kills the connection.
#[tokio::test]
async fn test_invalid_subscribe() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path();

    // Create and start a new broker
    new_broker(0, "8098", "8099", &discovery_endpoint).await;

    // Create and start a new marshal
    new_marshal("8100", &discovery_endpoint).await;

    // Create and get the handle to a new client subscribed to an invalid topic
    let client = new_client(0, vec![99], "8100");

    // Ensure the connection is open
    let Ok(()) = timeout(Duration::from_secs(1), client.ensure_initialized()).await else {
        panic!("client failed to connect");
    };

    // Subscribe to an invalid topic
    let _ = client.subscribe(vec![99]).await;

    // Sleep for a bit to allow the client to disconnect
    sleep(Duration::from_millis(50)).await;

    // Assert we can't send a message (as we are disconnected)
    assert!(
        client
            .send_broadcast_message(vec![1], b"hello invalid".to_vec())
            .await
            .is_err(),
        "sent message but should've been disconnected"
    );

    // Reinitialize the connection
    let Ok(()) = timeout(Duration::from_secs(4), client.ensure_initialized()).await else {
        panic!("client failed to connect");
    };

    // Unsubscribe from the invalid topic
    let _ = client.unsubscribe(vec![99]).await;

    // Sleep for a bit to allow the client to disconnect
    sleep(Duration::from_millis(50)).await;

    // Assert we can't send a message (as we are disconnected)
    assert!(
        client
            .send_broadcast_message(vec![1], b"hello invalid".to_vec())
            .await
            .is_err(),
        "sent message but should've been disconnected"
    );
}
