//! This file defines common errors used by CDN clients and servers.

use core::result::Result as StdResult;
use thiserror::Error;

/// A wrapper around Result<T, E> that pins this error type.
pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, Error)]
#[error("{0}")]
/// A common error type used by both the client and server. Allows for conditional
/// reconnections based on the type of error. For example: we do not want to reconnect on a malformed
/// message, but we do on a connection error.
pub enum Error {
    /// A generic connection error. Implies the connection is severed and needs to be
    /// reconnected.
    Connection(String),
    /// A message serialization error. Does not denote connection failure for a client,
    /// but will not continue sending the message.
    Serialize(String),
    /// A message deserialization error. Implies the connection is severed, warrants a
    /// reconnection.
    Deserialize(String),
    /// A generic "crypto" error. Usually refers to issues with signing and verifying
    /// messages.
    Crypto(String),
    /// An error occurred while authenticating with the server.
    Authentication(String),
    /// A generic parsing-related error. An example is a failed parse of a socket address.
    Parse(String),
    /// A file-related (either read or write) error. An example is a failed read of a certificate file.
    File(String),
}

#[macro_export]
/// A macro that bails early using the specified error type and context.
/// Is semantically equivalent to `return Error::Type("context: {error}")`.
macro_rules! bail {
    ($expr: expr, $type: ident, $context: expr) => {
        $expr.map_err(|err| Error::$type(format!("{}: {err}", $context)))?
    };
}

#[macro_export]
/// A macro that bails when an option does not exist. Uses the specified error
/// type and context. Uses `ok_or_else` under the hood.
macro_rules! bail_option {
    ($expr: expr, $type: ident, $context: expr) => {
        $expr.ok_or_else(|| Error::$type($context.to_owned()))?
    };
}

/// The following is a macro that helps us parse socket addresses. We use it to
/// deduplicate code where we parse multiple addresses. It basically combines `.parse()`
/// and `bail!()`
#[macro_export]
macro_rules! parse_socket_address {
    ($address:expr) => {
        bail!($address.parse(), Parse, "failed to parse socket address")
    };
}
