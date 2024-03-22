//! The heartbeat task periodically posts our state to either Redis or an embeddable file DB.

use std::{collections::HashSet, sync::Arc, time::Duration};

use cdn_proto::{connection::protocols::Protocol, def::RunDef, discovery::DiscoveryClient};
use tokio::{spawn, time::sleep};
use tracing::{error, warn};

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    /// This task deals with setting the number of our connected users in Redis or the embedded db. It allows
    /// the marshal to correctly choose the broker with the least amount of connections.
    pub async fn run_heartbeat_task(self: Arc<Self>) {
        // Clone the `discovery` client, which needs to be mutable
        let mut discovery_client = self.discovery_client.clone();

        // Run this forever, unless we run into a panic (e.g. the "as" conversion.)
        loop {
            // Register with the discovery service every n seconds, updating our number of connected users
            if let Err(err) = discovery_client
                .perform_heartbeat(self.connections.num_users() as u64, Duration::from_secs(60))
                .await
            {
                // If we fail, we want to see this
                error!("failed to perform heartbeat: {}", err);
            }

            // Check for new brokers, spawning tasks to connect to them if necessary
            match discovery_client.get_other_brokers().await {
                Ok(brokers) => {
                    // Calculate the difference, spawn tasks to connect to them
                    for broker in
                        brokers.difference(&HashSet::from_iter(self.connections.all_brokers()))
                    {
                        // TODO: make this into a separate function
                        // Extrapolate the address to connect to
                        let to_connect_address = broker.private_advertise_address.clone();

                        // Clone the inner because we need it for the possible new broker task
                        let inner = self.clone();

                        // Spawn task to connect to a broker we haven't seen
                        spawn(async move {
                            // Connect to the broker
                            let connection =
                                // Our TCP protocol is unsecured, so the cert we use does not matter.
                                match Def::BrokerProtocol::connect(&to_connect_address, true).await
                                {
                                    Ok(connection) => connection,
                                    Err(err) => {
                                        warn!("failed to connect to broker: {err}");
                                        return;
                                    }
                                };

                            inner.handle_broker_connection(connection, true).await;
                        });
                    }
                }

                Err(err) => {
                    // This is an important error as well
                    error!("failed to get other brokers: {}", err);
                }
            }

            // Sleep for 20 seconds
            sleep(Duration::from_secs(20)).await;
        }
    }
}
