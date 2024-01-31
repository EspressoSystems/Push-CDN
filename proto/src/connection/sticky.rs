//! This file provides a `Sticky` connection, which allows for reconnections
//! on top of a normal implementation of a `Fallible` connection.

use std::sync::Arc;

use jf_primitives::signatures::SignatureScheme as JfSignatureScheme;

use super::Connection;

