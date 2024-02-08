//! This crate defines a batching system for sending messages, wherein
//! we spawn a task that owns the sender and have a handle to a channel it's
//! listening on.
//!
//! TODO: dynamic batch size and time

use std::{collections::VecDeque, hash::Hash, marker::PhantomData, sync::Arc, time::Duration};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use tokio::{
    select, spawn,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
};
use tracing::error;

use crate::{
    bail,
    connection::protocols::Sender,
    error::{Error, Result},
};

use super::protocols::Protocol;

/// This is the format we send messages to the task with. Can either be a control message
/// or a data message.
enum QueueMessage {
    /// A data message is something we actually want to send.
    Data(Arc<Vec<u8>>, Position),
    /// A control message is an enshrined message that is supposed to control the stream.
    Control(Control),
}

/// This is coupled with a data message, where we denote the position in the queue we want
/// our message to go to. This can be useful for implemtning monotonic writes or write-ahead
/// logging.
enum Position {
    /// Add our message to the front of the batch
    Front,
    /// Add our message to the back of the batch
    Back,
}

/// These are our control messages, which we use to tell the task to do something other than
/// send the message.
enum Control {
    /// Freeze sending messages in the queue. This can be useful when coupled with `Position::Front`
    /// so we can delay and order messages the way we want to.
    Freeze,
    /// Unfreeze the queue. Allows for sending messages again
    Unfreeze,
    /// Shut down the task. The task will be killed
    Shutdown,
}

/// `BatchedSender` is a wrapper around a send stream that owns the sender. It allows us
/// to queue messages for sending with a minimum time or size. Is clonable through an `Arc`.
pub struct BatchedSender<ProtocolType: Protocol> {
    /// The underlying channel that we receive messages over.
    channel: UnboundedSender<QueueMessage>,
    /// A unique, randomly generated ID that we use to compare and hash against.
    stable_id: u64,
    /// The `PhantomData` we need to use a generic protocol type.
    pd: PhantomData<ProtocolType>,
}

/// `PartialEq` here uses the randomly generated `stable_id`
impl<ProtocolType: Protocol> PartialEq for BatchedSender<ProtocolType> {
    fn eq(&self, other: &Self) -> bool {
        self.stable_id == other.stable_id
    }
}

/// Asserts that `PartialEq` == `Eq`
impl<ProtocolType: Protocol> Eq for BatchedSender<ProtocolType> {}

/// `Hash` here uses the randomly generated `stable_id`
impl<ProtocolType: Protocol> Hash for BatchedSender<ProtocolType> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.stable_id.hash(state);
    }
}

/// The underlying queue object that a `BatchedSender`'s task operates over.
/// Contains the queue as fields for data tracking purposes.
pub struct Queue {
    /// The actual message queue
    inner: VecDeque<Arc<Vec<u8>>>,

    /// The current size of the queue, in bytes
    current_size: u64,

    /// The maximum duration to wait before sending a message.
    max_duration: Duration,
    /// The maximum message size before sending, in bytes
    max_size_in_bytes: u64,

    /// Whether or not the queue is currently frozen
    frozen: bool,
}

macro_rules! flush_queue {
    ($queue:expr, $sender:expr) => {
        // Atomically replace the inner with a new `VecDeque::default()`
        let messages = std::mem::take(&mut $queue.inner);
        // Reset the size
        $queue.current_size = 0;

        // Send the replaced messages
        if let Err(e) = $sender.send_messages(messages).await {
            error!("message send failed: {e}");
            return;
        };
    };
}

impl<ProtocolType: Protocol> BatchedSender<ProtocolType> {
    /// Freeze sending messages in the queue. This can be useful when coupled with `Position::Front`
    /// so we can delay and order messages the way we want to.
    ///
    /// # Errors
    /// - If the send-side is closed.
    pub fn freeze(&self) -> Result<()> {
        // Send a control message to freeze the queue
        bail!(
            self.channel.send(QueueMessage::Control(Control::Freeze)),
            Connection,
            "connection closed"
        );

        Ok(())
    }

    /// Unfreeze message sending operations in the queue.
    ///
    /// # Errors
    /// - If the send-side is closed.
    pub fn unfreeze(&self) -> Result<()> {
        // Send a control message to unfreeze the queue
        bail!(
            self.channel.send(QueueMessage::Control(Control::Unfreeze)),
            Connection,
            "connection closed"
        );

        Ok(())
    }

    /// Queue a serialized message to the front of the queue. Can be useful in conjunction with
    /// `.freeze()` or if we have an important message.
    ///
    /// # Errors
    /// - If the send-side is closed.
    pub fn queue_message_front(&self, message: Arc<Vec<u8>>) -> Result<()> {
        // Send a data message
        bail!(
            self.channel
                .send(QueueMessage::Data(message, Position::Front)),
            Connection,
            "connection closed"
        );

        Ok(())
    }

    /// Queue a serialized message to the front of the queue.
    ///
    /// # Errors
    /// - If the send-side is closed.
    pub fn queue_message_back(&self, message: Arc<Vec<u8>>) -> Result<()> {
        // Send a data message
        bail!(
            self.channel
                .send(QueueMessage::Data(message, Position::Back)),
            Connection,
            "connection closed"
        );

        Ok(())
    }

    /// Create a `BatchedSender` from a normal sender, along with a maximum duration and maximum
    /// queue size before we flush.
    pub fn from(
        sender: ProtocolType::Sender,
        max_duration: Duration,
        max_size_in_bytes: u64,
    ) -> Self {
        // Create the send and receive sides of a channel.
        let (send_side, receive_side) = unbounded_channel();

        // Create a new queue from our parameters and defaults
        let batch_params = Queue {
            inner: VecDeque::default(),
            current_size: 0,
            max_duration,
            max_size_in_bytes,
            frozen: false,
        };

        // Spawn the sending task where the send handle moves into. Would normally use a `JoinHandle` shutdown
        // but we don't have that luxury with the `async_compatibility_layer`
        spawn(Self::batch_loop(sender, receive_side, batch_params));

        // Return a sender with a unique `stable_id`.
        Self {
            stable_id: StdRng::from_entropy().next_u64(),
            channel: send_side,
            pd: PhantomData,
        }
    }

    /// This is the main loop that the send-side runs. This is where we deal with incoming
    /// data and control messages.
    async fn batch_loop(
        mut sender: ProtocolType::Sender,
        mut receiver: UnboundedReceiver<QueueMessage>,
        mut queue: Queue,
    ) {
        // Create a timer that ticks every max interval. We reset it if we actually send a message.
        let mut timer = tokio::time::interval(queue.max_duration);

        loop {
            // Select on either a new message or a timer event
            select! {
               // Receive a message. Will return `None` if the send side is closed.
            possible_message = receiver.recv() => {
                let Some(message) = possible_message else {
                    // If the send-side is closed, drop everything and stop.
                    return
                };

                // See what type of message we have
                match message{
                    // A data message. This is a message that we actually want to add
                    // to the queue.
                    QueueMessage::Data(data, position) => {
                        // Get the current length of data.
                        let data_len = data.len();

                        // See in which position we wanted to add to the queue
                        match position{
                            Position::Front => {
                                queue.inner.push_front(data);
                            }
                            Position::Back => {
                                queue.inner.push_back(data);
                            }
                        }

                        // Increase the queue size by the data length
                        queue.current_size += data_len as u64;

                        // If we're frozen, don't continue to any sending logic
                        if queue.frozen{
                            continue
                        }

                        // Bounds check to see if we should send
                        if queue.current_size >= queue.max_size_in_bytes{
                            // Flush the queue, sending all in-flight messages.
                            flush_queue!(queue, sender);
                        }
                    }

                    // We got a control message; a message we don't actually want to send.
                    QueueMessage::Control(control) => {
                        match control {
                            Control::Freeze => {queue.frozen = true}
                            Control::Unfreeze => {queue.frozen = false}
                            // Return if we see a shutdown message
                            Control::Shutdown => return
                        }
                    }
                }
            }
            // We hit this when the timer expires without having sent a message.
            _ = timer.tick() => {
                // Don't do anything if the queue is currently frozen
                if queue.frozen{
                    continue
                }

                // Flush the queue, sending all in-flight messages.
                flush_queue!(queue, sender);
            }
            }

            // Reset the timer when we are done sending the message.
            timer.reset();
        }
    }
}

// When we drop, we want to send the shutdown message to the sender.
impl<ProtocolType: Protocol> Drop for BatchedSender<ProtocolType> {
    fn drop(&mut self) {
        // Shut down the channel
        let _ = self.channel.send(QueueMessage::Control(Control::Shutdown));
    }
}
