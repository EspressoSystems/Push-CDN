//! This file provides a `Sticky` connection, which allows for reconnections
//! on top of a normal implementation of a `Fallible` connection.

use std::sync::Arc;

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use super::Connection;

/// `Sticky` is a wrapper around a `Fallible` connection.
///
/// It employs synchronization around a `Fallible`, as well as retry logic for both switching
/// connections at a certain failure threshold and reconnecting under said threshold.
///
/// Can be cloned to provide a handle to the same underlying elastic connection.
#[derive(Clone)]
pub struct Sticky<SignatureScheme: JfSignatureScheme, Protocol: Connection> {
    inner: Arc<StickyInner<SignatureScheme>>,
}

