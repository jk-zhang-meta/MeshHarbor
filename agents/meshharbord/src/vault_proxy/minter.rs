// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-6d-1b — the minter a dynamic secret's provider names: one issuer,
//! one mint and one revocation for each provider this build mints for on the
//! device (`docs/fr/FR-90-hive-agent-sessions.md` §3e, "P3-6d, MySQL, SQL
//! Server and Redis users, as designed"). The lease client
//! (`crate::vault`) calls these, and never names a database or a cluster.
//!
//! | Provider | Minter | Its end, as the mint gives it |
//! |---|---|---|
//! | `postgres` | [`pg_mint`] | `VALID UNTIL`, RFC 3339 |
//! | `mysql` | [`mysql_mint`] | an event, at a count of seconds |
//! | `kubernetes` | [`k8s_mint`] (P3-6f-2) | the Secret the token is bound to, deleted; the token's own expiry, the lease's TTL or 600 s |

use meshharbor_remote_control::vault::lease_limits::MAX_TTL_SECS;
use meshharbor_remote_control::vault::providers;
use zeroize::Zeroizing;

use super::{k8s_mint, mysql_mint, pg_mint, upstream_of};

/// The providers this build mints for, on the device: a lease of theirs is
/// held (its bundle lent to no tool) and its credential minted at its first
/// use. Every other provider's bundle is refused unopened. `pub`, as
/// `crate::vault` re-exports it.
pub const MINTS: [&str; 3] = [
    providers::POSTGRES.name,
    providers::MYSQL.name,
    providers::KUBERNETES.name,
];

/// A dynamic secret's issuer, read from its lease's bundle by its provider's
/// minter.
pub(crate) enum Issuer {
    Postgres(pg_mint::Issuer),
    Mysql(mysql_mint::Issuer),
    /// P3-6f-2.
    Kubernetes(k8s_mint::Issuer),
}

impl Issuer {
    /// The issuer `provider` names, in `bundle`. Err, in words that name no
    /// value, for a provider this build mints nothing for, or a bundle its
    /// minter refuses.
    pub(crate) fn from_bundle(provider: &str, bundle: &[u8]) -> Result<Self, String> {
        if provider == providers::POSTGRES.name {
            pg_mint::Issuer::from_bundle(bundle, upstream_of).map(Self::Postgres)
        } else if provider == providers::MYSQL.name {
            mysql_mint::Issuer::from_bundle(bundle, upstream_of).map(Self::Mysql)
        } else if provider == providers::KUBERNETES.name {
            k8s_mint::Issuer::from_bundle(bundle).map(Self::Kubernetes)
        } else {
            Err(format!("this build mints nothing for {provider:?}"))
        }
    }
}

/// A credential minted for a lease, by the minter its provider names.
pub(crate) enum Minted {
    /// A database user, Postgres's or MySQL's.
    Database(pg_mint::Minted),
    /// P3-6f-2 — a service account's token, and the Secret it is bound to.
    Kubernetes(k8s_mint::Minted),
}

impl Minted {
    /// One of its fields, by the name a session gives it (its provider's
    /// minted fields); `None` for any other name.
    pub(crate) fn field(&self, name: &str) -> Option<Zeroizing<String>> {
        match self {
            Self::Database(m) => m.field(name),
            Self::Kubernetes(m) => m.field(name),
        }
    }

    /// What it is called, for a log: a database user's name, or the Secret a
    /// token is bound to. Never a value.
    pub(crate) fn label(&self) -> &str {
        match self {
            Self::Database(m) => &m.user,
            Self::Kubernetes(m) => &m.secret,
        }
    }
}

/// Mint for `lease_id`, its end the lease's: `until_ms`, in milliseconds of
/// the server's clock, given to each minter in the form it takes.
pub(crate) async fn mint(issuer: &Issuer, lease_id: &str, until_ms: i64) -> Result<Minted, String> {
    match issuer {
        Issuer::Postgres(i) => pg_mint::mint(i, lease_id, &rfc3339(until_ms)?)
            .await
            .map(Minted::Database),
        // Whole seconds, rounded down: never past the lease's end.
        Issuer::Mysql(i) => mysql_mint::mint(i, lease_id, until_ms.div_euclid(1000))
            .await
            .map(Minted::Database),
        Issuer::Kubernetes(i) => {
            k8s_mint::mint(i, lease_id, ttl_secs(until_ms, now_ms()), until_ms)
                .await
                .map(Minted::Kubernetes)
        }
    }
}

/// Take `minted` back, as its issuer.
pub(crate) async fn revoke(issuer: &Issuer, minted: &Minted) -> Result<(), String> {
    match (issuer, minted) {
        (Issuer::Postgres(i), Minted::Database(m)) => pg_mint::revoke(i, &m.user).await,
        (Issuer::Mysql(i), Minted::Database(m)) => mysql_mint::revoke(i, &m.user).await,
        (Issuer::Kubernetes(i), Minted::Kubernetes(m)) => {
            k8s_mint::revoke(i, &m.secret, &m.uid).await
        }
        _ => Err("a credential its issuer did not mint".into()),
    }
}

/// `ms` (milliseconds of the server's clock) as RFC 3339, what a minted
/// Postgres role's `VALID UNTIL` is given.
fn rfc3339(ms: i64) -> Result<String, String> {
    bson::DateTime::from_millis(ms)
        .try_to_rfc3339_string()
        .map_err(|_| "the lease's end is not a time Postgres takes".to_string())
}

fn now_ms() -> i64 {
    bson::DateTime::now().timestamp_millis()
}

/// P3-6f-2 — what is left of a lease ending at `until_ms` at `now_ms`, in
/// whole seconds: what a token is asked for (its minter asks 600 s where
/// this is less). At least a second, and never past the longest lease, so
/// a clock that is off cannot ask for a long-lived token.
fn ttl_secs(until_ms: i64, now_ms: i64) -> u32 {
    let left = until_ms.saturating_sub(now_ms).div_euclid(1000);
    u32::try_from(left.clamp(1, i64::from(MAX_TTL_SECS))).unwrap_or(MAX_TTL_SECS)
}

#[cfg(test)]
mod tests;
