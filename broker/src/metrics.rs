//! Here is where we define broker-specific metrics that we need. 
//! They are lazily loaded during runtime.

use lazy_static::lazy_static;
use prometheus::{register_int_gauge, IntGauge};

lazy_static! {
    // The number of users connected
    pub static ref NUM_USERS_CONNECTED: IntGauge =
        register_int_gauge!("num_users_connected", "the number of users connected").unwrap();
    
    // The number of brokers connected
    pub static ref NUM_BROKERS_CONNECTED: IntGauge =
        register_int_gauge!("num_brokers_connected", "the number of brokers connected").unwrap();
    
    // The timestamp (unix epoch time) when we started
    pub static ref RUNNING_SINCE: IntGauge =
        register_int_gauge!("running_since", "the timestamp at which we were started").unwrap();
}
