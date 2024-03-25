# Push-CDN

## What is the Push-CDN?
The Push-CDN is a distributed and fault tolerant messaging system purpose-built to support peer-to-peer networks.

## Feature highlights
- Fast, reliable, and efficient
- Support for both publish-subscribe and direct messaging models
- First class support for routing and authentication on top of public-key cryptosystems

## System components
- `Broker`: The discrete message-passing unit of the system.
- `Marshal`: Deals with user authentication and load balancing
- `Redis`: Used as a consistent core for authentication states and broker discovery 

## Diagrams
![supports 1..n brokers](https://github.com/EspressoSystems/push-cdn/blob/master/diagrams/nbrokers.png?raw=true)
*supports 1..n brokers*

![high level connection map](https://github.com/EspressoSystems/push-cdn/blob/master/diagrams/high-level-connections.png?raw=true)
*high level connection map*

## Client example using `jellyfish` keys
```rust
#[tokio::main]
async fn main() {
    // Generate a random keypair
    let (private_key, public_key) =
        BLS::key_gen(&(), &mut StdRng::from_entropy()).unwrap();

    // Build the config, the endpoint being where we expect the marshal to be
    let config = ConfigBuilder::default()
        .endpoint("127.0.0.1:8082".to_string())
        // Private key is only used for signing authentication messages
        .keypair(KeyPair {
            public_key,
            private_key,
        })
        // Subscribe to the global consensus topic
        .subscribed_topics(vec![Topic::Global])
        .build()
        .unwrap();

    // Create a client, specifying the BLS signature algorithm
    // and the `QUIC` protocol.
    let client = Client::<BLS, Quic>::new(config)
        .await
        .unwrap();

    // Send a direct message to ourselves
    client
        .send_direct_message(&public_key, b"hello direct".to_vec())
        .await
        .unwrap();

    // Receive the direct message
    let message = client
        .receive_message()
        .await
        .unwrap();

    // Assert we've received the proper direct message
    assert!(
        message
            == Message::Direct(Direct {
                recipient: public_key.serialize().unwrap(),
                message: b"hello direct".to_vec()
            })
    );

    // Send a broadcast message to the global topic
    client
        .send_broadcast_message(vec![Topic::Global], b"hello broadcast".to_vec())
        .await
        .unwrap();

    // Receive the broadcast message
    let message = client
        .receive_message()
        .await
        .unwrap();

    // Assert we've received the proper broadcast message
    assert!(
        message
            == Message::Broadcast(Broadcast {
                topics: vec![Topic::Global],
                message: b"hello broadcast".to_vec()
            })
    );
}
```
Full example available [here](./cdn-client/src/main.rs)

## Running locally
Running locally can be achieved via the supplied `process-compose.yaml`:
```bash
process-compose up
```

It requires installation of `KeyDB` or `Redis`.

## License
### Copyright
**(c) 2024 Espresso Systems**.
`Push-CDN` was developed by Espresso Systems. While we plan to adopt an open source license, we have not yet selected one. As such, all rights are reserved for the time being. Please reach out to us if you have thoughts on licensing.
