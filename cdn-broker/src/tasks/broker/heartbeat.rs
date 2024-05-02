//! The heartbeat task periodically posts our state to either Redis or an embeddable file DB.

use std::{collections::HashSet, sync::Arc, time::Duration};

use cdn_proto::{
    connection::protocols::Protocol as _,
    def::{Protocol, RunDef},
    discovery::{BrokerIdentifier, DiscoveryClient},
};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use tokio::{
    spawn,
    time::{sleep, timeout},
};
use tracing::error;

use crate::Inner;

impl<Def: RunDef> Inner<Def> {
    /// This task deals with setting the number of our connected users in Redis or the embedded db. It allows
    /// the marshal to correctly choose the broker with the least amount of connections.
    pub async fn run_heartbeat_task(self: Arc<Self>) {
        // Clone the `discovery` client, which needs to be mutable
        let mut discovery_client = self.discovery_client.clone();

        // Run this forever, unless we run into a panic (e.g. the "as" conversion.)
        loop {
            let num_connections = self.connections.read().num_users() as u64;

            // Register with the discovery service every n seconds, updating our number of connected users
            match timeout(
                Duration::from_secs(5),
                discovery_client.perform_heartbeat(num_connections, Duration::from_secs(60)),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    error!("failed to perform heartbeat: {}", err);
                }
                Err(_) => {
                    error!("timed out trying to perform heartbeat");
                }
            }

            // Attempt to get all other brokers
            let other_brokers =
                match timeout(Duration::from_secs(5), discovery_client.get_other_brokers()).await {
                    Ok(Ok(brokers)) => brokers,
                    Ok(Err(err)) => {
                        error!("failed to get other brokers: {}", err);
                        continue;
                    }
                    Err(_) => {
                        // This is an important error
                        error!("timed out trying to get other brokers");
                        continue;
                    }
                };

            // Calculate which brokers to connect to by taking the difference
            // Only connect to brokers with a larger identifier
            let mut brokers_to_connect_to: Vec<BrokerIdentifier> = other_brokers
                .difference(&HashSet::from_iter(self.connections.read().all_brokers()))
                .filter(|broker| broker >= &&self.identity)
                .cloned()
                .collect();

            // Shuffle the list (so we don't get stuck in an authentication lock
            // on a broker that is down)
            brokers_to_connect_to.shuffle(&mut StdRng::from_entropy());

            // Calculate the difference, spawn tasks to connect to them
            for broker in brokers_to_connect_to {
                // Extrapolate the endpoint to connect to
                let to_connect_endpoint = broker.private_advertise_endpoint.clone();

                // Clone the inner because we need it for the possible new broker task
                let inner = self.clone();

                // Spawn task to connect to a broker we haven't seen
                spawn(async move {
                    // Connect to the broker
                    let connection =
                        // Our TCP protocol is unsecured, so the cert we use does not matter.
                        // Time out is at protocol level
                        match Protocol::<Def::Broker>::connect(&to_connect_endpoint, true).await
                        {
                            Ok(connection) => connection,
                            Err(err) => {
                                error!("failed to connect to broker: {err}");
                                return;
                            }
                        };

                    inner.handle_broker_connection(connection, true).await;
                });
            }

            // Sleep for 10 seconds
            sleep(Duration::from_secs(10)).await;
        }
    }
}
