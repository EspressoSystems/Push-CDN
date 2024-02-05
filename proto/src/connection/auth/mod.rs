//! This file defines authentication flows to be used when connecting
//! and reconnecting. We need this because it allows us to have the same connection code,
//! but with different authentication methods. For example, broker <-> broker
//! is different from user <-> broker.

// TODO IN GENERAL: figure out if connection dropping on big messages is working

use async_trait::async_trait;
use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use crate::error::Result;

use super::protocols::Protocol;

pub mod broker;
pub mod marshal;
pub mod user;

/// A macro that fails authentication early, providing the user with an error message.
/// Both sends the message and instantly returns.
#[macro_export]
macro_rules! fail_verification_with_message {
    ($connection: expr, $context: expr) => {
        // Send the error message
        let _ = $connection
            .send_message(Message::AuthenticateResponse(AuthenticateResponse {
                permit: 0,
                context: $context.to_string(),
            }))
            .await;

        // Return up the stack
        return Err(Error::Authentication($context.to_string()));
    };
}

/// The `Authentication` trait implements a connection flow that can both authenticate
/// and verify authentication for a particular connection.
#[async_trait]
pub trait AuthenticationFlow<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
>: Send + Sync + 'static + Clone
{
    /// Used for if we want to return an authentication `Result`. Perhaps something like the
    /// verification key.
    type Return;

    /// This is where we request or verify authentication. We pass in a connection, which,
    /// if it is verified, returns a resulting, successful connection.
    async fn authenticate(&mut self, connection: &ProtocolType::Connection) -> Result<Self::Return>;
}
