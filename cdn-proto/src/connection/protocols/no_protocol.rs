// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Push-CDN repository.

// You should have received a copy of the MIT License
// along with the Push-CDN repository. If not, see <https://mit-license.org/>.

//! A no-op `Protocol`. Used in tests to disable a listener slot (e.g. the
//! second user listener on the broker/marshal) so that two listeners on the
//! same endpoint don't collide. `bind` always succeeds without actually
//! binding anything; the resulting listener's `accept` never resolves.

use std::future::pending;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::{Connection, Listener, Protocol, UnfinalizedConnection};
use crate::{
    connection::limiter::Limiter,
    error::{Error, Result},
};

#[derive(Clone, PartialEq, Eq)]
pub struct NoProtocol;

#[async_trait]
impl Protocol for NoProtocol {
    type Listener = NoListener;
    type UnfinalizedConnection = NoUnfinalizedConnection;

    async fn connect(
        _remote_endpoint: &str,
        _use_local_authority: bool,
        _limiter: Limiter,
    ) -> Result<Connection> {
        Err(Error::Connection(
            "NoProtocol does not support connecting".to_string(),
        ))
    }

    async fn bind(
        _bind_endpoint: &str,
        _certificate: CertificateDer<'static>,
        _key: PrivateKeyDer<'static>,
    ) -> Result<Self::Listener> {
        Ok(NoListener)
    }
}

pub struct NoListener;

#[async_trait]
impl Listener<NoUnfinalizedConnection> for NoListener {
    async fn accept(&self) -> Result<NoUnfinalizedConnection> {
        pending().await
    }
}

pub struct NoUnfinalizedConnection;

#[async_trait]
impl UnfinalizedConnection for NoUnfinalizedConnection {
    async fn finalize(self, _limiter: Limiter) -> Result<Connection> {
        Err(Error::Connection(
            "NoProtocol connections cannot be finalized".to_string(),
        ))
    }
}
