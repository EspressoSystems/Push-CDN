@0xc2e09b062d0af52f;

# A wrapper for all message types. Allows us to match on a specific message type
# upstream.
struct Message {
    union {
        # The wrapper for an `Authenticate` message
        authenticate @0 :AuthenticateMessage;
        # The wrapper for an `AuthenticateResponse` message
        authenticateResponse @1 :AuthenticateResponseMessage;
        
        # The wrapper for a `Direct` message
        direct @2 :DirectMessage;
        # The wrapper for a `Broadcast` message
        broadcast @3 :BroadcastMessage;

        # The wrapper for a `Subscribe` message
        subscribe @4 :SubscribeMessage;
        # The wrapper for an `Unsubscribe` message
        unsubscribe @5 :UnsubscribeMessage;
    }
}

# An enum for users to specify topics for subscription and unsubscription.
# Also used on the sending side, where messages can be marked with 
# a topic and propagated to the interested users.
enum Topic {
    # The global consensus topic. All conseneus participants should be subscribed
    # to this.
    global @0;

    # The DA-specfic topic. Only participants in the DA committee should want to
    # be subscribed to this.
    da @1;
}

# This message is sent to the client upon authentication. It contains
# if it was successful or not, and the reason.
struct AuthenticateMessage {
    # The verification key, used downstream against the signed timestamp to verify the sender.
    verificationKey @0: Data;
    # The timestamp, unsigned. This is signed by the client to prevent replay attacks.
    timestamp @1: UInt64;
    # The signature, which is the timestamp, but signed.
    signature @2: Data;
    # The initial topics to subscribe to on the new connection.
    subscribedTopics @3: List(Topic);
}

# This message is sent to the client upon authentication. It contains
# if it was successful or not, and the reason.
struct AuthenticateResponseMessage {
    # If authentication was successful or not
    success @0: Bool;
    # The reason authentication was unsuccessful, if applicable
    reason @1: Text;
}

# This message is a direct message. It is sent by a client, used to deliver a
# message to only the intended recipient.
struct DirectMessage {
    # The recipient of the message
    recipient @0: Data;
    # The actual message data
    message @1: Data;
}

# This message is a broadcast message. It is sent by a client, used to deliver a
# message to all recipients who are interested in a topic. Uses the passed
# vector of topics to denote interest.
struct BroadcastMessage {
    # The topics to sent the message to
    topics @0: List(Topic);
    # The actual message data
    message @1: Data;
}

# A message that is used to convey interest in some particular topic(s).
struct SubscribeMessage {
    # The topics interested in
    topics @0: List(Topic);
}

# A message that is used to convey disinterest in some particular topic(s).
struct UnsubscribeMessage {
    # The topics no longer interested in
    topics @0: List(Topic);
}
