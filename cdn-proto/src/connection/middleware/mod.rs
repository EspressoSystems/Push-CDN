use async_trait::async_trait;
use lazy_static::lazy_static;

use self::pool::{AllocationPermit, MemoryPool};

pub mod pool;

lazy_static! {
    /// A global semaphore that prevents the server from allocating too much memory at once.
    static ref MEMORY_POOL: MemoryPool = MemoryPool::new((u32::MAX / 4) as usize);
}

/// A trait that defines middleware for a connection.
#[async_trait]
pub trait Middleware: 'static + Send + Sync + Clone {
    async fn allocate_message_bytes(num_bytes: u32) -> Option<AllocationPermit> {
        // Acquire and return a permit for the number of bytes requested
        let permit = MEMORY_POOL
            .alloc(num_bytes)
            .await
            .expect("required semaphore has been dropped");

        Some(permit)
    }
}

/// Middleware that does not do anything
#[derive(Clone)]
pub struct NoMiddleware;
#[async_trait]
impl Middleware for NoMiddleware {
    async fn allocate_message_bytes(_num_bytes: u32) -> Option<AllocationPermit> {
        None
    }
}

/// Middleware for untrusted connections
#[derive(Clone)]
pub struct UntrustedMiddleware;
#[async_trait]
impl Middleware for UntrustedMiddleware {}

/// Middleware for trusted connections
#[derive(Clone)]
pub struct TrustedMiddleware;
#[async_trait]
impl Middleware for TrustedMiddleware {}
