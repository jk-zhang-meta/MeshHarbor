// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-4c-3 — `vault_request`: a lease asked for ahead of its use.
//!
//! | Step | What holds |
//! |---|---|
//! | the call | `handle` (a path or this org's RRN, `#field` for a field), `mode` (`exec`, `file` or `proxy`, the modes a use takes), `audience` (a bare name: the program `vault_exec` will run, or the file `vault_render` will write; for `proxy`, the upstream `vault_connect` will sign in to: `host:port`, an origin, or (P3-5f-2) `ssh://[user@]host[:port]`), `ttl_s` (30 to 900, default 300) |
//! | the lease | asked for once, decided by the vault's `secret:use` with its guardrails, recorded; held in daemon memory, never handed to the session |
//! | its use | a later `vault_exec`, `vault_render` or `vault_connect` naming the same secret toward the same audience takes it, while it covers what that call needs, instead of asking again; every such call still asks a person |
//! | its end | its expiry, `rc:vault.revoke`, or the run's end: no call lets it go |
//! | a dynamic secret | P3-6b-2b: asked for as a whole in `short-lived`, whatever the use; the first use that takes it mints its credential, and every later one shares it. Not for `proxy`: `vault_connect` serves no dynamic secret |
//!
//! A use takes the lease by WHAT it is, not by its id: the call still names
//! the secret it hands on, so a person approving it reads which.

use bson::oid::ObjectId;
use serde_json::{Value, json};

use super::toolbelt::VaultTools;
use super::vault_exec::{Handle, dynamic_of, handle_of};
use crate::vault::SHORT_LIVED;

/// How long a lease asked for ahead lasts when the call does not say.
const DEFAULT_TTL: u32 = 300;

/// One `vault_request` call, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AheadRequest {
    pub(crate) handle: Handle,
    /// `exec`, `file` or `proxy`: the modes a use tool takes.
    pub(crate) mode: &'static str,
    pub(crate) audience: String,
    pub(crate) ttl: u32,
}

pub(crate) fn parse(args: &Value) -> Result<AheadRequest, String> {
    use meshharbor_remote_control::vault::lease_limits::{MAX_TTL_SECS, MIN_TTL_SECS};
    let handle = args
        .get("handle")
        .and_then(Value::as_str)
        .ok_or("handle is required: a secret's path, or rrn:<org>:secret:<path>")?;
    let handle = handle_of(handle)?;
    let mode = match args.get("mode").and_then(Value::as_str) {
        Some("exec") => "exec",
        Some("file") => "file",
        Some("proxy") => "proxy",
        _ => {
            return Err(
                "mode must be exec (for vault_exec), file (for vault_render) or proxy (for \
                 vault_connect)"
                    .into(),
            );
        }
    };
    let audience = args
        .get("audience")
        .and_then(Value::as_str)
        .ok_or("audience is required: the program's or the file's bare name, or an upstream")?;
    // P3-5b-2 — an upstream, as `vault_connect` will name it: a database's
    // `host:port`, (P3-5d-2) an HTTP upstream's origin, or (P3-5f-2) an SSH
    // host's `ssh://` upstream.
    if mode == "proxy" {
        let named = super::vault_connect::upstream_of(audience).is_ok()
            || super::vault_connect::origin_of(audience).is_ok()
            || super::vault_connect::ssh_of(audience).is_ok();
        if !named {
            return Err(format!(
                "a proxy's audience is its upstream, as vault_connect will name it: a database's \
                 host:port (such as db.internal:5432), an origin for http and kubernetes (such as \
                 https://github.com), or an ssh host (such as ssh://git@github.com): got \
                 {audience:?}"
            ));
        }
    }
    // Otherwise a bare name, by the one rule the vault holds `exec_allow` to,
    // as the use that takes the lease will name it.
    else if !meshharbor_remote_control::vault::program_name_ok(audience) {
        return Err(format!(
            "audience must be a bare name (letters, digits, `.`, `_`, `+` or `-`, not \
             starting with `.` or `-`): got {audience:?}"
        ));
    }
    let ttl = match args.get("ttl_s") {
        None | Some(Value::Null) => DEFAULT_TTL,
        Some(v) => match v.as_u64().and_then(|s| u32::try_from(s).ok()) {
            Some(s) if (MIN_TTL_SECS..=MAX_TTL_SECS).contains(&s) => s,
            _ => {
                return Err(format!("ttl_s must be {MIN_TTL_SECS} to {MAX_TTL_SECS}"));
            }
        },
    };
    Ok(AheadRequest {
        handle,
        mode,
        audience: audience.to_string(),
        ttl,
    })
}

/// What a session's `vault_request` call answers: the lease and how long it
/// lasts, never a value; or why there is none.
pub(crate) async fn call(
    vault: &dyn VaultTools,
    session: ObjectId,
    fence: u64,
    args: &Value,
) -> Result<Value, String> {
    let req = parse(args)?;
    // P3-6b-2b — a dynamic secret is asked for as a whole, in `short-lived`,
    // whatever use it is for: the use that takes it mints its credential,
    // once, and every use that takes it after shares that credential.
    if let Some(d) = dynamic_of(vault, session, fence, &req.handle.secret).await? {
        if req.mode == "proxy" {
            return Err(format!(
                "{}: vault_connect does not sign in with a dynamic secret's credential: vault_exec \
                 and vault_render serve it",
                req.handle
            ));
        }
        if !req.handle.field.is_empty() && !d.fields.contains(&req.handle.field) {
            return Err(format!(
                "{}: {} is a dynamic secret: name a field of the credential minted for it, #{}",
                req.handle,
                req.handle.secret,
                d.fields.join(", #")
            ));
        }
        let all = Handle {
            secret: req.handle.secret.clone(),
            field: String::new(),
        };
        let lease = vault
            .lease_ahead(session, fence, &all, SHORT_LIVED, "", req.ttl)
            .await
            .map_err(|why| format!("{}: {why}", req.handle))?;
        let ttl_s = vault.left(&lease).map_or(0, |left| left.as_secs());
        return Ok(json!({
            "lease_id": lease,
            "handle": all.to_string(),
            "mode": SHORT_LIVED,
            "provider": d.provider,
            "ttl_s": ttl_s,
        }));
    }
    let lease = vault
        .lease_ahead(
            session,
            fence,
            &req.handle,
            req.mode,
            &req.audience,
            req.ttl,
        )
        .await
        .map_err(|why| format!("{}: {why}", req.handle))?;
    let ttl_s = vault.left(&lease).map_or(0, |d| d.as_secs());
    Ok(json!({
        "lease_id": lease,
        "handle": req.handle.to_string(),
        "mode": req.mode,
        "audience": req.audience,
        "ttl_s": ttl_s,
    }))
}

#[cfg(test)]
mod tests;
