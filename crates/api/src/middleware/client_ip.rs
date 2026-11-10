// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The per-IP governor's key, on the server's one client-address rule.
//!
//! The rule itself — only the entries our own proxies appended to
//! `X-Forwarded-For` are evidence, so the client is the entry just left of
//! the trusted suffix, else the socket peer — lives in
//! [`meshharbor_core::client_ip`] since FR-102 P3c, so that the `fleet`
//! module's install trace reads a client address exactly as the limiter
//! does. Re-exported here for the crate's existing callers (the credential
//! gate, the `/ws` analytics session).

use std::net::IpAddr;

use axum::http::Request;
use tower_governor::{GovernorError, key_extractor::KeyExtractor};

pub use meshharbor_core::client_ip::{client_ip, client_ip_from_headers};

/// [`KeyExtractor`] keyed on the trusted client address.
#[derive(Clone, Debug)]
pub struct TrustedProxyIpKeyExtractor {
    pub trusted_hops: usize,
}

impl KeyExtractor for TrustedProxyIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        client_ip(req, self.trusted_hops).ok_or(GovernorError::UnableToExtractKey)
    }
}
