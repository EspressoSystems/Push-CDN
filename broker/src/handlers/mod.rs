//! This file defines the handler module, wherein we define connection handlers for
//! `Arc<Inner>`.

pub mod broker;
pub mod user;

/// This macro is a helper macro that lets us "send many messages", and remove
/// the actor from the local state if the message failed to send
#[macro_export]
macro_rules! send_or_remove_many {
    ($connections: expr, $lookup:expr, $message: expr, $position: expr) => {
        // For each connection,
        for connection in $connections {
            // Queue a message back
            if connection
                .1
                .queue_message($message.clone(), $position)
                .is_err()
            {
                // If it fails, remove the connection.
                get_lock!($lookup, write).remove_connection(connection.0);
            };
        }
    };
}

/// We use this macro to help send direct messages. It just makes the code easier
/// to look at.
#[macro_export]
macro_rules! send_direct {
    ($lookup: expr, $key: expr, $message: expr) => {{
        let connections = $lookup.read().await.get_connections_by_key(&$key).clone();
        send_or_remove_many!(connections, $lookup, $message, Position::Back);
    }};
}

/// We use this macro to help send broadcast messages. It just makes the code easier
/// to look at.
#[macro_export]
macro_rules! send_broadcast {
    ($lookup:expr, $topics: expr, $message: expr) => {{
        let connections = $lookup
            .read()
            .await
            .get_connections_by_topic($topics.clone())
            .clone();
        send_or_remove_many!(connections, $lookup, $message, Position::Back);
    }};
}

/// This is a macro to acquire an async lock, which helps readability.
#[macro_export]
macro_rules! get_lock {
    ($lock :expr, $type: expr) => {
        paste::item! {
            $lock.$type().await
        }
    };
}

// Creates and serializes a new message of the specified type with the specified data.
#[macro_export]
macro_rules! new_serialized_message {
    ($type: ident, $data: expr) => {
        Arc::<Vec<u8>>::from(bail!(
            Message::$type($data).serialize(),
            Connection,
            "broker disconnected"
        ))
    };
}
