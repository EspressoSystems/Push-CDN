use pool::MemoryPool;

use self::pool::AllocationPermit;

pub mod pool;

/// Shared middleware for all connections.
#[derive(Clone)]
pub struct Middleware {
    /// The global memory pool to check with before allocating.
    global_memory_pool: Option<MemoryPool>,

    /// Per connection, the size of the channel buffer.
    connection_message_pool_size: Option<usize>,
}

impl Middleware {
    /// Create a new middleware with a global memory pool of `global_memory_pool_size` bytes
    /// and a connection message pool size of `connection_message_pool_size` bytes.
    ///
    /// If the global memory pool is not set, it will not be used.
    /// If the connection message pool size is not set, an unbounded channel will be used.
    pub fn new(
        global_memory_pool_size: Option<usize>,
        connection_message_pool_size: Option<usize>,
    ) -> Self {
        // Create a new global memory pool if the size is set, otherwise set it to `None`.
        Self {
            global_memory_pool: global_memory_pool_size.map(MemoryPool::new),
            connection_message_pool_size,
        }
    }

    /// Create a new middleware with no global memory pool and no connection message pool size.
    /// This means an unbounded channel will be used for connections and no global memory pool
    /// will be checked.
    pub const fn none() -> Self {
        // Create a new middleware with no global memory pool and no connection message pool size.
        Self {
            global_memory_pool: None,
            connection_message_pool_size: None,
        }
    }

    /// Allocate a permit for a message of `num_bytes` bytes.
    /// If the global memory pool is not set, this will return `None`.
    ///
    /// # Panics
    /// - If the required semaphore has been dropped. This should never happen
    pub async fn allocate_message_bytes(&self, num_bytes: u32) -> Option<AllocationPermit> {
        if let Some(pool) = &self.global_memory_pool {
            // If the global memory pool is set, allocate a permit
            Some(
                pool.alloc(num_bytes)
                    .await
                    .expect("required semaphore has been dropped"),
            )
        } else {
            // If the global memory pool is not set, return `None`
            None
        }
    }

    /// Get the connection message pool size, if set.
    pub const fn connection_message_pool_size(&self) -> Option<usize> {
        // Return the connection message pool size
        self.connection_message_pool_size
    }
}
