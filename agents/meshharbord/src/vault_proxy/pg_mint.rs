// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-6b-2 — a Postgres user minted for one lease by a dynamic
//! secret's issuer (`docs/fr/FR-90-hive-agent-sessions.md` §3e, "P3-6,
//! `short-lived`, as designed"; `docs/vault.md` §20).
//!
//! | Step | What happens |
//! |---|---|
//! | the issuer | the bundle's `admin_user` and `admin_password`, signed in by SCRAM-SHA-256 over verified TLS (its `ca`, or the system's roots) to its `database`, at the bundle's one audience ([`Issuer::from_bundle`]) |
//! | the sweep | first, every minted role whose `VALID UNTIL` has passed, found by its comment, dropped where the issuer may: what a daemon that died before revoking left |
//! | the mint | `CREATE ROLE "meshharbor_<lease>" LOGIN PASSWORD '<verifier>' VALID UNTIL '<end>' IN ROLE <grants>`, and its comment, in one transaction ([`mint`]) |
//! | the password | 32 random bytes, base64url; sent as its SCRAM-SHA-256 verifier ([`scram::verifier`]), never itself, so a database that logs its statements logs no password |
//! | the revocation | `NOLOGIN`, its sessions ended where the issuer may, what it owns given to the issuer, then `DROP ROLE` ([`revoke`]) |
//!
//! ⚠️ Every name goes in quoted as an identifier, and every value as a
//! literal; nothing a session wrote reaches a statement here. A grant is the
//! issuer's configuration, written by an administrator.
//!
//! ⚠️ A role is never dropped unless its name is a minted one
//! ([`ROLE_PREFIX`] and a lease's id): a revocation can take back what this
//! module made, and nothing else.

use base64::Engine;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::warn;
use zeroize::Zeroizing;

use super::bundle::Opened;
use super::pg::{self, Upstream};
use super::scram;

/// What every minted role's name begins with.
pub(crate) const ROLE_PREFIX: &str = "meshharbor_";
/// What every minted role's comment begins with: the sweep's mark.
const COMMENT_PREFIX: &str = "meshharbor lease ";

/// A dynamic secret's Postgres issuer, read from its lease's bundle.
pub(crate) struct Issuer {
    pub(crate) up: Upstream,
    pub(crate) database: String,
    /// The roles a minted user joins: the issuer's configuration.
    pub(crate) grants: Vec<String>,
}

impl Issuer {
    /// The issuer in a lease's `bundle` (`super::bundle`), its audience read
    /// by `upstream_of` (the endpoint's own spelling of `host:port`). Err, in
    /// words that name no value, for a bundle that does not parse or lacks a
    /// field no mint can do without.
    pub(crate) fn from_bundle(
        bundle: &[u8],
        upstream_of: impl Fn(&str) -> Result<(String, u16), String>,
    ) -> Result<Self, String> {
        let opened = Opened::open(bundle)?;
        Ok(Self {
            up: opened.upstream(upstream_of)?,
            database: opened.required("database")?.clone(),
            grants: opened.lines("grants"),
        })
    }
}

/// A credential minted for a lease: what a session names, under the
/// provider's names (`meshharbor_remote_control::vault::providers::POSTGRES`).
pub(crate) struct Minted {
    pub(crate) user: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) database: String,
}

impl Minted {
    /// One of its fields, by the name a session gives it; `None` for any
    /// other name.
    pub(crate) fn field(&self, name: &str) -> Option<Zeroizing<String>> {
        let value = match name {
            "user" => self.user.clone(),
            "password" => self.password.to_string(),
            "host" => self.host.clone(),
            "port" => self.port.to_string(),
            "database" => self.database.clone(),
            _ => return None,
        };
        Some(Zeroizing::new(value))
    }
}

/// The role minted for a lease: [`ROLE_PREFIX`] and the lease's id, its 24
/// hex characters, which no other name has.
pub(crate) fn role_for(lease_id: &str) -> Result<String, String> {
    if lease_id.len() == 24 && lease_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(format!("{ROLE_PREFIX}{lease_id}"))
    } else {
        Err("a lease's id is 24 hex characters".into())
    }
}

/// Whether `role` is a name a mint made: Err for any other, which nothing
/// here ever drops. Shared with `mysql_mint`, whose users are named the same.
pub(crate) fn minted(role: &str) -> Result<(), String> {
    let lease = role
        .strip_prefix(ROLE_PREFIX)
        .ok_or("only a minted role is ever dropped")?;
    role_for(lease).map(|_| ())
}

/// A name, quoted as an identifier.
fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// A value, quoted as a literal (Postgres's `standard_conforming_strings`,
/// on by default since 9.1: a backslash is itself).
fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Mint a user for `lease_id`, valid until `until` (a timestamp, RFC 3339),
/// after sweeping the expired ones. The statement holds the password's
/// verifier, never the password.
pub(crate) async fn mint(issuer: &Issuer, lease_id: &str, until: &str) -> Result<Minted, String> {
    let role = role_for(lease_id)?;
    let password = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
    );
    let verifier = scram::verifier(
        &password,
        &rand::random::<[u8; 16]>(),
        scram::VERIFIER_ITERATIONS,
    )?;
    let mut s = pg::sign_in(&issuer.up, &issuer.database).await?;
    sweep(&mut s).await;
    let grants = if issuer.grants.is_empty() {
        String::new()
    } else {
        let names: Vec<String> = issuer.grants.iter().map(|g| ident(g)).collect();
        format!(" IN ROLE {}", names.join(", "))
    };
    let sql = format!(
        "CREATE ROLE {r} LOGIN PASSWORD {v} VALID UNTIL {u}{grants}; COMMENT ON ROLE {r} IS {c}",
        r = ident(&role),
        v = literal(&verifier),
        u = literal(until),
        c = literal(&format!("{COMMENT_PREFIX}{lease_id}")),
    );
    let made = pg::simple_query(&mut s, &sql).await;
    pg::terminate(s).await;
    made.map_err(|why| format!("the database refused the mint: {why}"))?;
    Ok(Minted {
        user: role,
        password,
        host: issuer.up.host.clone(),
        port: issuer.up.port,
        database: issuer.database.clone(),
    })
}

/// Take `role` back: signed in as its issuer, gone (see [`drop_role`]). A
/// name no mint made is refused before anything is dialled.
pub(crate) async fn revoke(issuer: &Issuer, role: &str) -> Result<(), String> {
    minted(role)?;
    let mut s = pg::sign_in(&issuer.up, &issuer.database).await?;
    let gone = drop_role(&mut s, role).await;
    pg::terminate(s).await;
    gone
}

/// The roles minted here whose `VALID UNTIL` has passed, each found by its
/// comment, dropped where the issuer may. Best effort: whatever this cannot
/// drop can no longer sign in.
async fn sweep(s: &mut TlsStream<TcpStream>) {
    let sql = format!(
        "SELECT r.rolname FROM pg_catalog.pg_roles r WHERE r.rolname LIKE {p} \
         AND r.rolvaliduntil < now() \
         AND pg_catalog.shobj_description(r.oid, 'pg_authid') LIKE {m}",
        p = literal(&format!("{}%", ROLE_PREFIX.replace('_', "\\_"))),
        m = literal(&format!("{COMMENT_PREFIX}%")),
    );
    let expired = match pg::simple_query(s, &sql).await {
        Ok(rows) => rows,
        Err(why) => {
            warn!(%why, "vault: the expired minted roles were not listed");
            return;
        }
    };
    for name in expired
        .into_iter()
        .filter_map(|r| r.into_iter().next().flatten())
    {
        if let Err(why) = drop_role(s, &name).await {
            warn!(role = %name, %why, "vault: an expired minted role was not dropped");
        }
    }
}

/// One minted role gone: no more logins, its sessions ended where the issuer
/// may (`pg_signal_backend`, or the role's own privileges), what it owns in
/// this database given to the issuer, then dropped. A role that is already
/// gone is done.
async fn drop_role(s: &mut TlsStream<TcpStream>, role: &str) -> Result<(), String> {
    minted(role)?;
    let found = pg::simple_query(
        s,
        &format!(
            "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {}",
            literal(role)
        ),
    )
    .await?;
    if found.is_empty() {
        return Ok(());
    }
    let r = ident(role);
    pg::simple_query(s, &format!("ALTER ROLE {r} NOLOGIN")).await?;
    if let Err(why) = pg::simple_query(
        s,
        &format!(
            "SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity \
             WHERE usename = {}",
            literal(role)
        ),
    )
    .await
    {
        warn!(%role, %why, "vault: a minted role's sessions were not ended: NOLOGIN refuses new ones");
    }
    if let Err(why) = pg::simple_query(
        s,
        &format!("REASSIGN OWNED BY {r} TO CURRENT_USER; DROP OWNED BY {r}"),
    )
    .await
    {
        warn!(%role, %why, "vault: what a minted role owns was not given back");
    }
    pg::simple_query(s, &format!("DROP ROLE IF EXISTS {r}"))
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests;
