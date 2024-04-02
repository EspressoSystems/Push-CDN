//! This file defines all authentication flows that the Push CDN implements.

use crate::def::RunDef;

use super::{hooks::Untrusted, protocols::Protocol};

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
            .0
            .send_message(Message::AuthenticateResponse(AuthenticateResponse {
                permit: 0,
                context: $context.to_string(),
            }))
            .await;

        // Return up the stack
        return Err(Error::Authentication($context.to_string()));
    };
}

/// A type alias to help readability
type UserConnection<Def> = Connection<<Def as RunDef>::UserProtocol, Untrusted>;

/// A type alias to help readability
type Connection<ProtocolType, H> = (
    <ProtocolType as Protocol<H>>::Sender,
    <ProtocolType as Protocol<H>>::Receiver,
);
