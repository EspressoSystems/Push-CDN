use std::time::Duration;

use cdn_proto::discovery::BrokerIdentifier;
use tokio::time::{sleep, timeout};

use super::*;

/// Test for connecting twice to the same broker.
/// Should kick off the first connection.
#[tokio::test]
async fn test_double_connect_same_broker() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path();

    // Create and start a new broker
    new_broker(0, "8086", "8087", &discovery_endpoint).await;

    // Create and start a new marshal
    new_marshal("8088", &discovery_endpoint).await;

    // Create 2 clients with the same keypair
    let client1 = new_client(1, vec![Topic::Global], "8088");
    let client2 = new_client(1, vec![Topic::Global], "8088");

    // Assert both clients are connected
    let Ok(()) = timeout(Duration::from_secs(1), client1.ensure_initialized()).await else {
        panic!("failed to connect as client1");
    };
    let Ok(()) = timeout(Duration::from_secs(1), client2.ensure_initialized()).await else {
        panic!("failed to connect as client2");
    };

    // Wait for a second
    sleep(Duration::from_millis(50)).await;

    // Attempt to send a message, should fail
    assert!(client1
        .send_direct_message(&keypair_from_seed(1).1, b"hello direct".to_vec())
        .await
        .is_err());

    // The second client to connect should have succeeded
    client2
        .send_direct_message(&keypair_from_seed(1).1, b"hello direct".to_vec())
        .await
        .expect("failed to send message from second client");
}

/// Test for connecting twice to different brokers
/// Should kick off the first connection.
#[tokio::test]
async fn test_double_connect_different_broker() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path();

    // Create and start two brokers
    new_broker(0, "8092", "8093", &discovery_endpoint).await;
    new_broker(0, "8090", "8091", &discovery_endpoint).await;

    // Create and start a new marshal
    new_marshal("8094", &discovery_endpoint).await;

    // Create 2 clients with the same keypair
    let client1 = new_client(1, vec![Topic::Global], "8094");
    let client2 = new_client(1, vec![Topic::Global], "8094");

    // Wait a little
    sleep(Duration::from_millis(50)).await;

    // Get the brokers
    let brokers: Vec<BrokerIdentifier> = new_db_client(&discovery_endpoint, None)
        .await
        .get_other_brokers()
        .await
        .expect("failed to get brokers")
        .into_iter()
        .collect();

    // Create database clients as each broker
    let mut broker0_db_client = new_db_client(&discovery_endpoint, Some(brokers[0].clone())).await;
    let mut broker1_db_client = new_db_client(&discovery_endpoint, Some(brokers[1].clone())).await;

    // Make sure the first client connects to the first broker by setting the second
    // broker as having a higher number of connections
    broker1_db_client
        .perform_heartbeat(1, Duration::from_secs(60))
        .await
        .expect("broker failed to perform heartbeat");

    // Connect the first client
    let Ok(()) = timeout(Duration::from_secs(1), client1.ensure_initialized()).await else {
        panic!("failed to connect as client1");
    };

    // Set the number of connections for the first broker to be higher
    broker0_db_client
        .perform_heartbeat(2, Duration::from_secs(60))
        .await
        .expect("broker failed to perform heartbeat");

    // Connect the second client
    let Ok(()) = timeout(Duration::from_secs(1), client2.ensure_initialized()).await else {
        panic!("failed to connect as client2");
    };

    // Sleep for a bit
    sleep(Duration::from_millis(50)).await;

    // Assert the second client can send a message
    client2
        .send_direct_message(&keypair_from_seed(1).1, b"hello direct".to_vec())
        .await
        .expect("failed to send message from first client");

    // Assert the first client can't send a message
    assert!(
        client1
            .send_direct_message(&keypair_from_seed(1).1, b"hello direct".to_vec())
            .await
            .is_err(),
        "second client connected when it shouldn't have"
    );
}
