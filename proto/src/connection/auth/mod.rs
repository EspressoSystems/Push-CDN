//! This file defines all authentication flows that the Push CDN implements.

// TODO IN GENERAL: figure out if connection dropping on big messages is working

use std::marker::PhantomData;

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

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

/// This is the `Auth` struct that we define methods to for authentication purposes.
pub struct Auth<
    SignatureScheme: JfSignatureScheme<PublicParameter = (), MessageUnit = u8>,
    ProtocolType: Protocol,
> {
    /// We use `PhantomData` here so we can be generic over a signature scheme
    /// and protocol type
    pub pd: PhantomData<(SignatureScheme, ProtocolType)>,
}
