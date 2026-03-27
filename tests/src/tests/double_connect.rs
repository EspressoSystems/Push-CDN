// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

use std::time::Duration;

use cdn_proto::{database::BrokerIdentifier, def::TestTopic};
use tokio::time::{sleep, timeout};

use super::*;

/// Test for connecting twice to the same broker.
/// Should kick off the first connection.
#[tokio::test]
async fn test_double_connect_same_broker() {
    // Get a temporary path for the database endpoint
    let database_endpoint = get_temp_db_path();

    // Create and start a new broker
    new_broker(0, "8086", "8087", &database_endpoint).await;

    // Create and start a new marshal
    new_marshal("8088", &database_endpoint).await;

    // Create 2 clients with the same keypair
    let client1 = new_client(1, vec![TestTopic::Global as u8], "8088");
    let client2 = new_client(1, vec![TestTopic::Global as u8], "8088");

    // Assert both clients are connected
    timeout(Duration::from_secs(1), client1.ensure_initialized())
        .await
        .expect("client1 timed out while connecting")
        .unwrap();
    timeout(Duration::from_secs(1), client2.ensure_initialized())
        .await
        .expect("client2 timed out while connecting")
        .unwrap();

    // Wait for a bit
    sleep(Duration::from_millis(50)).await;

    // Attempt to send a message, should fail
    assert!(
        client1
            .send_direct_message(&keypair_from_seed(1).1, b"hello direct".to_vec())
            .await
            .is_err()
            || client1.soft_close().await.is_err()
    );

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
    // Get a temporary path for the database endpoint
    let database_endpoint = get_temp_db_path();

    // Create and start two brokers
    new_broker(0, "8092", "8093", &database_endpoint).await;
    sleep(Duration::from_millis(50)).await;
    new_broker(0, "8090", "8091", &database_endpoint).await;

    // Wait a little for them to connect
    sleep(Duration::from_millis(100)).await;

    // Create and start a new marshal
    new_marshal("8094", &database_endpoint).await;

    // Create 2 clients with the same keypair
    let client1 = new_client(1, vec![TestTopic::Global as u8], "8094");
    let client2 = new_client(1, vec![TestTopic::Global as u8], "8094");

    // Wait a little
    sleep(Duration::from_millis(50)).await;

    // Get the brokers
    let brokers: Vec<BrokerIdentifier> = new_db_client(&database_endpoint, None)
        .await
        .get_other_brokers()
        .await
        .expect("failed to get brokers")
        .into_iter()
        .collect();

    // Create database clients as each broker
    let mut broker0_db_client = new_db_client(&database_endpoint, Some(brokers[0].clone())).await;
    let mut broker1_db_client = new_db_client(&database_endpoint, Some(brokers[1].clone())).await;

    // Make sure the first client connects to the first broker by setting the second
    // broker as having a higher number of connections
    broker1_db_client
        .perform_heartbeat(1, Duration::from_secs(60))
        .await
        .expect("broker failed to perform heartbeat");

    // Connect the first client
    timeout(Duration::from_secs(1), client1.ensure_initialized())
        .await
        .expect("client1 timed out while connecting")
        .unwrap();

    // Set the number of connections for the first broker to be higher
    broker0_db_client
        .perform_heartbeat(2, Duration::from_secs(60))
        .await
        .expect("broker failed to perform heartbeat");

    // Connect the second client
    timeout(Duration::from_secs(1), client2.ensure_initialized())
        .await
        .expect("client2 timed out while connecting")
        .unwrap();

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
            .is_err()
            || client1.soft_close().await.is_err(),
        "second client connected when it shouldn't have"
    );
}
