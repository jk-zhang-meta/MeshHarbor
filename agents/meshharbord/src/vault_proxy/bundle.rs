// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-6d-1 — a dynamic secret's bundle, as each minter reads it: its
//! issuer's fields, and the one audience to mint toward. The vault seals it
//! (`crates/modules/vault/src/dynamic.rs`); `pg_mint` and `mysql_mint` open
//! it here, so every minter reads one shape the same way.

use std::collections::BTreeMap;

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use super::pg::Upstream;
use super::tls;

/// A bundle as the vault seals it.
#[derive(Deserialize)]
struct Sealed {
    audience: String,
    fields: Fields,
}

/// A bundle's fields, as parsed: each value zeroed when they drop, so the
/// parse leaves no copy of the issuer's password behind.
#[derive(Deserialize)]
#[serde(transparent)]
struct Fields(BTreeMap<String, String>);

impl Drop for Fields {
    fn drop(&mut self) {
        self.0.values_mut().for_each(Zeroize::zeroize);
    }
}

/// A bundle, opened.
pub(crate) struct Opened {
    audience: String,
    fields: Fields,
}

impl Opened {
    /// Err, in words that name no value, for a bundle that does not parse.
    pub(crate) fn open(bundle: &[u8]) -> Result<Self, String> {
        let Sealed { audience, fields } =
            serde_json::from_slice(bundle).map_err(|_| "the bundle does not parse".to_string())?;
        Ok(Self { audience, fields })
    }

    /// A field no mint can do without: Err `the issuer has no <name>` when it
    /// is absent or empty.
    pub(crate) fn required(&self, name: &str) -> Result<&String, String> {
        self.optional(name)
            .ok_or_else(|| format!("the issuer has no {name}"))
    }

    /// P3-6f-1 — the one audience the bundle mints toward, as the lease was
    /// decided for it: a Kubernetes issuer reads it as an origin.
    pub(crate) fn audience(&self) -> &str {
        &self.audience
    }

    /// A field that may be absent: `None` when it is, or is empty.
    pub(crate) fn optional(&self, name: &str) -> Option<&String> {
        self.fields.0.get(name).filter(|v| !v.is_empty())
    }

    /// A field of one name per line: each trimmed, the empty lines dropped.
    pub(crate) fn lines(&self, name: &str) -> Vec<String> {
        self.optional(name)
            .map(|v| {
                v.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The issuer's upstream: its `admin_user` and `admin_password`, at the
    /// bundle's audience as `upstream_of` reads it (the endpoint's own
    /// spelling of `host:port`), over TLS verified against its `ca` or the
    /// system's roots.
    pub(crate) fn upstream(
        &self,
        upstream_of: impl Fn(&str) -> Result<(String, u16), String>,
    ) -> Result<Upstream, String> {
        let (host, port) = upstream_of(&self.audience)?;
        let (user, with) = (
            self.required("admin_user")?,
            self.required("admin_password")?,
        );
        Ok(Upstream {
            host,
            port,
            user: user.clone(),
            password: Zeroizing::new(with.clone()),
            tls: tls::connector_for(tls::roots(self.optional("ca").map(String::as_str))?, None)?,
        })
    }
}
