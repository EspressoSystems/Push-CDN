//! An asynchronous memory-Permitted `Arc`. Allows for atomic tracking for allocations and deallocations.
//!
//! Almost like a bounded channel, but has globally allocated counters of bytes instead of
//! per-channel counters of messages.
//!
//! We need this on the broker side to reduce the chance of an out-of-memory issue. When we
//! receive a message, we await on allocating it. When we are done sending it out to everyone,
//! we drop the `Parc`, allowing for re-allocation.

use std::{ops::Deref, sync::Arc};

use anyhow::Result;
use derivative::Derivative;
use lazy_static::lazy_static;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

lazy_static! {
    pub static ref MEMORY_POOL: MemoryPool =
        MemoryPool::new(usize::try_from(u32::MAX).expect(">= 32 bit system"));
}

/// A global memory arena that tracks but does not allocate memory.
/// Allows for asynchronous capping of memory usage.
#[derive(Clone)]
pub struct MemoryPool(Arc<Semaphore>);

impl MemoryPool {
    /// Create a new `MemoryPool` from the number of bytes to
    fn new(n: usize) -> Self {
        Self(Arc::from(Semaphore::const_new(n)))
    }
}

/// An acquired permit that allows for allocation of a memory region
/// of a particular size.
#[allow(dead_code)]
pub struct AllocationPermit(OwnedSemaphorePermit);

impl MemoryPool {
    /// Asynchronously allocate `n` bytes from the global pool, waiting
    /// if there are no more available
    ///
    /// # Errors
    /// If the semaphore is dropped
    pub async fn alloc(&self, n: u32) -> Result<AllocationPermit> {
        // Acquire many permits to the underlying semaphore
        let permit = self.0.clone().acquire_many_owned(n).await?;
        Ok(AllocationPermit(permit))
    }
}

/// Allow for dereference of the object to the underlying value
impl<T> Deref for Allocation<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

#[derive(Derivative)]
#[derivative(PartialEq, Eq)]
#[derive(Clone)]
/// A struct representing a combination of a value taking up `n` bytes,
/// along with its (optional) permit to acquire those bytes. When the object
/// is dropped, the bytes are freed.
pub struct Allocation<T> {
    /// The underlying value
    ptr: Arc<T>,

    /// The optional permit for those `n` bytes
    #[derivative(PartialEq = "ignore")]
    _permit: Option<Arc<AllocationPermit>>,
}

impl<T> Allocation<T> {
    /// Create an allocation from a permit and the underlying value
    pub fn from(value: T, permit: Option<AllocationPermit>) -> Self {
        Self {
            ptr: Arc::from(value),
            _permit: permit.map(Arc::from),
        }
    }

    /// Create an allocation from a value but without checking if memory
    /// is available.
    pub fn from_unchecked(value: T) -> Self {
        Self {
            ptr: Arc::from(value),
            _permit: None,
        }
    }
}
