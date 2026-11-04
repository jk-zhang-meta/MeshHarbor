// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-6d-1 — a MySQL user minted for one lease by a dynamic secret's
//! issuer (`docs/fr/FR-90-hive-agent-sessions.md` §3e, "P3-6d, MySQL, SQL
//! Server and Redis users, as designed").
//!
//! | Step | What happens |
//! |---|---|
//! | the issuer | the bundle's `admin_user` and `admin_password`, signed in by `caching_sha2_password` over verified TLS (its `ca`, or the system's roots), to its `database`, at the bundle's one audience ([`Issuer::from_bundle`]) |
//! | the sweep | first, each `roomler_` user whose `ATTRIBUTE` says its lease has ended, dropped where the issuer may: what an event that never ran left |
//! | the mint | `CREATE USER 'roomler_<lease>'@'%' IDENTIFIED WITH caching_sha2_password AS '<form>' ATTRIBUTE '{"roomler": …}'`, each grant and `SET DEFAULT ROLE ALL`, then its end: `CREATE EVENT … ON SCHEDULE AT FROM_UNIXTIME(<end>) ON COMPLETION NOT PRESERVE DO DROP USER IF EXISTS …` in its `database` ([`mint`]) |
//! | the password | 32 random bytes, base64url; sent as its `caching_sha2_password` form ([`sha_crypt::mysql_caching_sha2`]), never itself |
//! | the revocation | `ACCOUNT LOCK`; its connections ended where the issuer may (`KILL`); `DROP USER`; `DROP EVENT` ([`revoke`]) |
//!
//! ⚠️ MySQL's DDL commits as it goes, so there is no transaction to roll a
//! half-made user back. A step refused takes the user back here, and the mint
//! is refused: no user is left without its end.
//!
//! ⚠️ A user is never dropped unless its name is a minted one (`roomler_` and
//! a lease's id). That is checked before a revocation dials, and again before
//! each drop, whatever the sweep's query returns.

use base64::Engine;
use tracing::warn;
use zeroize::Zeroizing;

use super::bundle::Opened;
use super::mysql::{self, Session};
use super::pg::Upstream;
use super::pg_mint::{Minted, ROLE_PREFIX, minted, role_for};
use super::sha_crypt;

/// A dynamic secret's MySQL issuer, read from its lease's bundle.
pub(crate) struct Issuer {
    pub(crate) up: Upstream,
    /// Where the issuer signs in, the minted user's database, and where its
    /// end (the event) lives.
    pub(crate) database: String,
    /// The roles a minted user is granted, each `name` or `name@host`: the
    /// issuer's configuration.
    pub(crate) grants: Vec<String>,
}

impl Issuer {
    /// The issuer in a lease's `bundle`, its audience read by `upstream_of`
    /// (the endpoint's own spelling of `host:port`). Err, in words that name
    /// no value, for a bundle that does not parse, lacks a field no mint can
    /// do without, or names a role or a database no statement here may hold.
    pub(crate) fn from_bundle(
        bundle: &[u8],
        upstream_of: impl Fn(&str) -> Result<(String, u16), String>,
    ) -> Result<Self, String> {
        let opened = Opened::open(bundle)?;
        let database = opened.required("database")?.clone();
        ident(&database)?;
        let grants = opened.lines("grants");
        for g in &grants {
            account(g)?;
        }
        Ok(Self {
            up: opened.upstream(upstream_of)?,
            database,
            grants,
        })
    }
}

/// A name, quoted as an identifier: refused when it holds a backtick, a
/// backslash or a control character, which no name here needs.
fn ident(name: &str) -> Result<String, String> {
    if name.is_empty() || name.contains(['`', '\\']) || name.chars().any(char::is_control) {
        return Err("the issuer's database is not a name the minter quotes".into());
    }
    Ok(format!("`{name}`"))
}

/// A role, `name` or `name@host`, as MySQL names an account: `'name'@'host'`,
/// `%` its host when none is given. Refused when a part holds a quote, a
/// backslash or a control character, so no grant is read as SQL.
fn account(role: &str) -> Result<String, String> {
    let (name, host) = role.split_once('@').unwrap_or((role, "%"));
    let fine = |s: &str| {
        !s.is_empty() && !s.contains(['\'', '\\', '`']) && !s.chars().any(char::is_control)
    };
    if !fine(name) || !fine(host) {
        return Err("a grant is not a role's name the minter quotes".into());
    }
    Ok(format!("'{name}'@'{host}'"))
}

/// The event that ends `user` (a minted one): `roomler_end_` and its lease's
/// id.
fn event_of(user: &str) -> String {
    format!(
        "roomler_end_{}",
        user.strip_prefix(ROLE_PREFIX).unwrap_or(user)
    )
}

/// Mint a user for `lease_id`, its end at `until` (Unix seconds), after
/// sweeping the ended ones. The statement holds the password's form, never
/// the password.
pub(crate) async fn mint(issuer: &Issuer, lease_id: &str, until: i64) -> Result<Minted, String> {
    let user = role_for(lease_id)?;
    let password = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
    );
    let form = sha_crypt::mysql_caching_sha2(&password, &sha_crypt::mysql_salt());
    let mut s = mysql::sign_in(&issuer.up, &issuer.database).await?;
    sweep(&mut s, &issuer.database).await;
    let made = make(&mut s, issuer, &user, lease_id, &form, until).await;
    if made.is_err() {
        // Half made: what was made is taken back before the refusal.
        if let Err(why) = drop_user(&mut s, &user, &issuer.database).await {
            warn!(%user, %why, "vault: a half-minted user was not taken back");
        }
    }
    mysql::quit(s).await;
    made?;
    Ok(Minted {
        user,
        password,
        host: issuer.up.host.clone(),
        port: issuer.up.port,
        database: issuer.database.clone(),
    })
}

/// The user, its grants, and its end.
async fn make(
    s: &mut Session,
    issuer: &Issuer,
    user: &str,
    lease_id: &str,
    form: &str,
    until: i64,
) -> Result<(), String> {
    let u = format!("'{user}'@'%'");
    let refused = |why: String| format!("the database refused the mint: {why}");
    mysql::query(
        s,
        &format!(
            "CREATE USER {u} IDENTIFIED WITH caching_sha2_password AS '{form}' \
             ATTRIBUTE '{{\"roomler\": {{\"lease\": \"{lease_id}\", \"until\": {until}}}}}'"
        ),
    )
    .await
    .map_err(refused)?;
    for g in &issuer.grants {
        mysql::query(s, &format!("GRANT {} TO {u}", account(g)?))
            .await
            .map_err(refused)?;
    }
    if !issuer.grants.is_empty() {
        mysql::query(s, &format!("SET DEFAULT ROLE ALL TO {u}"))
            .await
            .map_err(refused)?;
    }
    mysql::query(
        s,
        &format!(
            "CREATE EVENT {}.{} ON SCHEDULE AT FROM_UNIXTIME({until}) \
             ON COMPLETION NOT PRESERVE DO DROP USER IF EXISTS {u}",
            ident(&issuer.database)?,
            ident(&event_of(user))?,
        ),
    )
    .await
    .map_err(|why| format!("the database refused the user's end: {why}"))?;
    Ok(())
}

/// Take `user` back: signed in as its issuer, gone (see [`drop_user`]). A
/// name no mint made is refused before anything is dialled.
pub(crate) async fn revoke(issuer: &Issuer, user: &str) -> Result<(), String> {
    minted(user)?;
    let mut s = mysql::sign_in(&issuer.up, &issuer.database).await?;
    let gone = drop_user(&mut s, user, &issuer.database).await;
    mysql::quit(s).await;
    gone
}

/// The users minted here whose lease has ended by their `ATTRIBUTE`, each
/// dropped where the issuer may. Best effort: an event drops them anyway,
/// where the scheduler runs.
async fn sweep(s: &mut Session, database: &str) {
    let ended = match mysql::query(
        s,
        "SELECT USER FROM information_schema.USER_ATTRIBUTES WHERE USER LIKE 'roomler\\_%' \
         AND CAST(JSON_EXTRACT(ATTRIBUTE, '$.roomler.until') AS UNSIGNED) < UNIX_TIMESTAMP()",
    )
    .await
    {
        Ok(rows) => rows,
        Err(why) => {
            warn!(%why, "vault: the ended minted users were not listed");
            return;
        }
    };
    for user in ended
        .into_iter()
        .filter_map(|r| r.into_iter().next().flatten())
    {
        if let Err(why) = drop_user(s, &user, database).await {
            warn!(%user, %why, "vault: an ended minted user was not dropped");
        }
    }
}

/// One minted user gone: locked, its connections ended where the issuer may
/// (`PROCESS` to see them, `CONNECTION_ADMIN` to end them), dropped, and its
/// event with it. A user already gone is done, its event dropped all the same.
async fn drop_user(s: &mut Session, user: &str, database: &str) -> Result<(), String> {
    minted(user)?;
    let u = format!("'{user}'@'%'");
    let event = format!("{}.{}", ident(database)?, ident(&event_of(user))?);
    let found = mysql::query(
        s,
        &format!("SELECT USER FROM information_schema.USER_ATTRIBUTES WHERE USER = '{user}'"),
    )
    .await?;
    if !found.is_empty() {
        mysql::query(s, &format!("ALTER USER {u} ACCOUNT LOCK")).await?;
        match mysql::query(
            s,
            &format!("SELECT ID FROM information_schema.PROCESSLIST WHERE USER = '{user}'"),
        )
        .await
        {
            Ok(ids) => {
                for id in ids
                    .into_iter()
                    .filter_map(|r| r.into_iter().next().flatten())
                {
                    // A thread id is digits alone; anything else is not sent.
                    if !id.bytes().all(|b| b.is_ascii_digit()) {
                        continue;
                    }
                    if let Err(why) = mysql::query(s, &format!("KILL {id}")).await {
                        warn!(%user, %why, "vault: a minted user's connection was not ended: it is locked");
                    }
                }
            }
            Err(why) => warn!(%user, %why, "vault: a minted user's connections were not listed"),
        }
        mysql::query(s, &format!("DROP USER IF EXISTS {u}")).await?;
    }
    if let Err(why) = mysql::query(s, &format!("DROP EVENT IF EXISTS {event}")).await {
        warn!(%user, %why, "vault: a minted user's event was not dropped: it drops nothing that is gone");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
