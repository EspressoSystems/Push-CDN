// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

use cdn_proto::{
    def::TestTopic,
    message::{Direct, Message},
};

use crate::tests::*;

/// Test that an end-to-end connection succeeds
#[tokio::test]
async fn test_end_to_end_connection() {
    // Get a temporary path for the discovery endpoint
    let discovery_endpoint = get_temp_db_path();

    // Create and start a new broker
    new_broker(0, "8080", "8081", &discovery_endpoint).await;

    // Create and start a new marshal
    new_marshal("8082", &discovery_endpoint).await;

    // Create and get the handle to a new client
    let client = new_client(0, vec![TestTopic::Global as u8], "8082");
    let client_public_key = keypair_from_seed(0).1;

    // Ensure we are connected
    client.ensure_initialized().await.unwrap();

    // Send a message to ourself
    client
        .send_direct_message(&client_public_key, b"hello direct".to_vec())
        .await
        .expect("failed to send message");

    // The message that we expect to receive
    let expected_message = Message::Direct(Direct {
        recipient: client_public_key
            .serialize()
            .expect("failed to serialize public key"),
        message: b"hello direct".to_vec(),
    });

    // Assert we have received the message
    assert!(
        client
            .receive_message()
            .await
            .expect("failed to receive message")
            == expected_message,
        "wrong message received"
    );
}
