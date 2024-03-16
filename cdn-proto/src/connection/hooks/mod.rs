use async_trait::async_trait;

pub mod pool;

use pool::{AllocationPermit, MEMORY_POOL};

#[async_trait]
pub trait Hooks: Send + Sync + 'static + Clone {
    async fn allocate_before_read(_num_bytes: u32) -> Option<AllocationPermit> {
        None
    }
}

#[derive(Clone)]
pub struct None {}

#[async_trait]
impl Hooks for None {}

#[derive(Clone)]
pub struct Untrusted {}

#[async_trait]
impl Hooks for Untrusted {
    async fn allocate_before_read(num_bytes: u32) -> Option<AllocationPermit> {
        MEMORY_POOL.alloc(num_bytes).await.ok()
    }
}

#[derive(Clone)]
pub struct Trusted {}

#[async_trait]
impl Hooks for Trusted {
    async fn allocate_before_read(num_bytes: u32) -> Option<AllocationPermit> {
        MEMORY_POOL.alloc(num_bytes).await.ok()
    }
}
