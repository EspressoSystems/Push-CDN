@0xc2e09b062d0af52f;

# A wrapper for all message types. Allows us to match on a specific message type
# upstream.
struct Message {
    union {
        # The wrapper for an `AuthenticateWithKey` message
        authenticateWithKey @0 :AuthenticateWithKey;
        # The wrapper for an `AuthenticateWithPermit` message
        authenticateWithPermit @1 :AuthenticateWithPermit;
        # The wrapper for an `AuthenticateWithPermitResponse` message
        authenticateResponse @2 :AuthenticateResponse;
        
        # The wrapper for a `Direct` message
        direct @3 :Direct;
        # The wrapper for a `Broadcast` message
        broadcast @4 :Broadcast;

        # A message denoting we'd like to subscribe to some topics
        subscribe @5 :List(UInt8);
        # A message denoting we'd like to unsubscribe from some topics
        unsubscribe @6 :List(UInt8);

        # A message containing a map which we use to converge on user connection state
        userSync @7: Data;
    }
}

# This message is used to authenticate the client to a marshal or a broker
# to a broker. It contains a way of proving identity of the sender.
struct AuthenticateWithKey {
    # The public key, used downstream against the signed timestamp to verify the sender.
    publicKey @0: Data;
    # The timestamp, unsigned. This is signed by the client to prevent replay attacks.
    timestamp @1: UInt64;
    # The signature, which is the timestamp, but signed.
    signature @2: Data;
}

# This message is used to authenticate the client to a server. It contains the permit
# issued by the marshal.
struct AuthenticateWithPermit {
    # The permit issued by the marshal, if applicable.
    permit @0: UInt64;
}

# This message is sent to the client or broker upon authentication. It contains
# if it was successful or not, the reason, and the permit, if applicable.
struct AuthenticateResponse {
    # The permit. Sent from marshals to clients to verify authentication.
    permit @0: UInt64;
    # The message context. Is an error reason if failed, or the endpoint
    # if successful.
    context @1: Text;
}

# This message is a direct message. It is sent by a client, used to deliver a
# message to only the intended recipient.
struct Direct {
    # The recipient of the message
    recipient @0: Data;
    # The actual message data
    message @1: Data;
}

# This message is a broadcast message. It is sent by a client, used to deliver a
# message to all recipients who are interested in a topic. Uses the passed
# vector of topics to denote interest.
struct Broadcast {
    # The topics to sent the message to
    topics @0: List(UInt8);
    # The actual message data
    message @1: Data;
}