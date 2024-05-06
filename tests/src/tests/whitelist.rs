use std::{sync::Arc, time::Duration};

use cdn_proto::{connection::UserPublicKey, def::TestTopic};
use tokio::time::timeout;

use crate::tests::*;

/// Test that the whitelist works
#[tokio::test]
async fn test_whitelist() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path();

    // Create and start a new broker
    new_broker(0, "8083", "8084", &discovery_endpoint).await;

    // Create and start a new marshal
    new_marshal("8085", &discovery_endpoint).await;

    // Create a client with keypair 1
    let client1_public_key: UserPublicKey = Arc::from(serialized_public_key_from_seed(1));
    let client1 = new_client(1, vec![TestTopic::Global as u8], "8085");

    // Create a client with keypair 2
    let client2_public_key: UserPublicKey = Arc::from(serialized_public_key_from_seed(2));
    let client2 = new_client(2, vec![TestTopic::Global as u8], "8085");

    // Assert both clients can connect
    let Ok(()) = timeout(Duration::from_secs(1), client1.ensure_initialized()).await else {
        panic!("failed to connect as client1");
    };
    let Ok(()) = timeout(Duration::from_secs(1), client2.ensure_initialized()).await else {
        panic!("failed to connect as client2");
    };

    // Create a new DB client
    let mut db = new_db_client(&discovery_endpoint, None).await;

    // Set the whitelist to only allow client1
    db.set_whitelist(vec![client1_public_key.clone()])
        .await
        .expect("failed to set whitelist");

    // Assert client1 is whitelisted
    assert!(db
        .check_whitelist(&client1_public_key)
        .await
        .is_ok_and(|x| x));

    // Assert client2 is not whitelisted
    assert!(db
        .check_whitelist(&client2_public_key)
        .await
        .is_ok_and(|x| !x));

    // Recreate clients
    let client1 = new_client(1, vec![TestTopic::Global as u8], "8085");
    let client2 = new_client(2, vec![TestTopic::Global as u8], "8085");

    // Assert we can connect as client1
    let Ok(()) = timeout(Duration::from_secs(1), client1.ensure_initialized()).await else {
        panic!("failed to connect as client1");
    };

    // Assert we can't connect as client2
    assert!(
        timeout(Duration::from_secs(1), client2.ensure_initialized())
            .await
            .is_err(),
        "client2 connected when it shouldn't have"
    );
}
