use std::{
    future::Future,
    hash::{Hash, Hasher},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::task::{JoinError, JoinHandle};

/// A function for generating a cute little user mnemonic from a hash
#[must_use]
pub fn mnemonic<H: Hash>(bytes: H) -> String {
    let mut state = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut state);
    mnemonic::to_string(state.finish().to_le_bytes())
}

/// A wrapper for a `JoinHandle` that will abort the task if dropped
pub struct AbortOnDropHandle<T>(pub JoinHandle<T>);

impl<T> Drop for AbortOnDropHandle<T> {
    fn drop(&mut self) {
        let _ = self.0.abort();
    }
}

impl<T> Future for AbortOnDropHandle<T> {
    type Output = Result<T, JoinError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}
