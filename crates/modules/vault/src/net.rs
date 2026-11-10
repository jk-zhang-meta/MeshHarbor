// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-7-1b — a session's own egress: the vault's answer to `rc:vault.net`,
//! a grant the network module believes without calling a module (P3-7-2).
//!
//! A session's device asks over its own control connection, in the queue its
//! leases share, and the vault answers on that connection: a grant
//! (`rc:vault.net.granted`), a token signed by core's auth service under an
//! audience of its own (`net_grant`), or one word (`rc:vault.refused`,
//! [`LeaseRefusal`]).
//!
//! | Check, in order | Refused as | Recorded |
//! |---|---|---|
//! | the request within its bounds: a kind this build names; a forward's host one [`canonical_net_host`] spells, and a port; SOCKS naming neither | `bad_request` | no |
//! | the vault serves the organization | `not_served` | no |
//! | the device takes leases: its hello advertised `vault` and carried a key | `unsupported` | no |
//! | a session of the organization whose record places it on THIS device | `not_located` | no |
//! | at the record's fence | `stale_fence` | yes |
//! | live | `ended` | yes |
//! | within the session's per-minute ceiling, which its leases share | `busy` | no |
//! | holding a vault role | `no_role` | yes |
//! | the exit a live device of the organization | `no_exit` | yes |
//! | Cedar's `net:socks` or `net:forward`, the node's facts and the device's read from their ROWS | `denied` | yes, with the request |
//! | signed | `unavailable` | yes |
//! | the allow recorded | `undecided` | — |
//!
//! ⚠️ The allow is recorded BEFORE the grant is sent: a grant the vault could
//! not record is never given.
//!
//! ⚠️ A forward is decided toward its host as [`canonical_net_host`] spells
//! it, and granted toward exactly that: `DB.internal.` is decided, and
//! granted, as `db.internal`, so no spelling steps around a `forbid`.
//!
//! ⚠️ A grant is no lease: no `vault_leases` row, nothing `rc:vault.revoke`
//! names. The device closes the listener when the session's run ends there,
//! and the grant's end bounds the rest (the spec's §3e, "its life").

use bson::{DateTime, oid::ObjectId};
use meshharbor_remote_control::vault::{LeaseRefusal, NetKind, canonical_net_host, lease_limits};
use meshharbor_services::auth::NetGrant;
use meshharbor_services::dao::base::DaoError;
use tracing::warn;

use crate::VaultState;
use crate::lease::{Conn, identify, os_name, reason_of};
use crate::policy::{self, Ask, DeviceFacts, NodeFacts, SessionFacts};
use crate::policy_routes::decide_for_org;

/// One `rc:vault.net`, as it arrived.
#[derive(Debug, Clone)]
pub struct NetRequest {
    pub req_id: String,
    pub session_id: ObjectId,
    pub fence: u64,
    pub exit: ObjectId,
    pub kind: String,
    pub host: String,
    pub port: u16,
    pub ttl_secs: u32,
}

/// What a granted request answers with.
#[derive(Debug)]
pub struct Granted {
    pub grant_id: ObjectId,
    /// The signed grant.
    pub grant: String,
    /// When it ends: whole seconds, as the grant names its end.
    pub expires_at: DateTime,
    /// A forward's destination exactly as granted; `None` for SOCKS.
    pub dst: Option<(String, u16)>,
}

/// The request's kind and destination once it is within its bounds, a
/// forward's host in its canonical spelling; `None` past a bound.
fn within_bounds(req: &NetRequest) -> Option<(NetKind, Option<(String, u16)>)> {
    if req.req_id.is_empty()
        || req.req_id.len() > lease_limits::MAX_REQ_ID_LEN
        || req.req_id.chars().any(char::is_control)
    {
        return None;
    }
    match NetKind::from_wire(&req.kind)? {
        NetKind::Socks => (req.host.is_empty() && req.port == 0).then_some((NetKind::Socks, None)),
        NetKind::Forward => {
            let host = canonical_net_host(&req.host)?;
            (req.port != 0).then_some((NetKind::Forward, Some((host, req.port))))
        }
    }
}

/// Decide one request, and grant it when it is allowed.
pub async fn grant(
    state: &VaultState,
    conn: Conn,
    req: &NetRequest,
) -> Result<Granted, LeaseRefusal> {
    let Some((kind, dst)) = within_bounds(req) else {
        return Err(LeaseRefusal::BadRequest);
    };
    let action = match kind {
        NetKind::Socks => policy::ACTION_NET_SOCKS,
        NetKind::Forward => policy::ACTION_NET_FORWARD,
    };
    let exit_hex = req.exit.to_hex();
    let (agent, session, mut rec) = identify(
        state,
        conn,
        req.session_id,
        req.fence,
        &exit_hex,
        action,
        "grant",
    )
    .await?;
    if session.vault_role.is_none() {
        let why = LeaseRefusal::NoRole;
        return Err(rec.refuse(why, why.wire()).await);
    }
    // The exit as its ROW holds it, and only within this organization: a
    // device of another is no exit, and the refusal says no more than that.
    let exit = match state
        .agents
        .find_live_in_tenant(conn.tenant_id, req.exit)
        .await
    {
        Ok(a) => a,
        Err(DaoError::NotFound) => {
            let why = LeaseRefusal::NoExit;
            return Err(rec.refuse(why, why.wire()).await);
        }
        Err(e) => {
            warn!(exit = %req.exit, %e, "vault: a grant's exit was not read");
            return Err(rec.refuse(LeaseRefusal::Unavailable, "exit_unread").await);
        }
    };
    let device = match DeviceFacts::new(os_name(agent.os), &agent.tags, agent.owner_user_id) {
        Ok(d) => d,
        Err(why) => {
            return Err(rec
                .refuse(LeaseRefusal::Denied, &format!("device: {why}"))
                .await);
        }
    };
    let node = match NodeFacts::new(req.exit, os_name(exit.os), &exit.tags, exit.owner_user_id) {
        Ok(n) => n,
        Err(why) => {
            return Err(rec
                .refuse(LeaseRefusal::Denied, &format!("node: {why}"))
                .await);
        }
    };
    let facts = SessionFacts {
        id: req.session_id.to_hex(),
        owner: session.owner_id,
        role: session.vault_role.clone(),
        playbook: None,
    };
    let ask = match &dst {
        None => Ask::NetSocks {
            session: facts,
            node,
            device,
        },
        Some((host, port)) => Ask::NetForward {
            session: facts,
            node,
            host: host.clone(),
            port: *port,
            device,
        },
    };
    let verdict = decide_for_org(state, conn.tenant_id, &ask).await;
    let reason = reason_of(&verdict);
    if !verdict.allow {
        if let Err(e) = rec.decided(false, &reason, &ask, None).await {
            warn!(session = %req.session_id, %e, "vault: a grant's deny was not recorded");
        }
        return Err(LeaseRefusal::Denied);
    }

    // Allowed: sign it, BEFORE the allow is recorded, so a recorded allow is
    // one that was ready to give.
    let ttl = req
        .ttl_secs
        .clamp(lease_limits::MIN_TTL_SECS, lease_limits::MAX_TTL_SECS);
    let exp = DateTime::now().timestamp_millis().div_euclid(1000) + i64::from(ttl);
    let grant_id = ObjectId::new();
    let signed = state.core.auth.issue_net_grant(&NetGrant {
        session_id: req.session_id,
        tenant_id: conn.tenant_id,
        fence: req.fence,
        owner_user_id: session.owner_id,
        origin_agent_id: conn.device_id,
        exit_agent_id: req.exit,
        net: kind,
        dst: dst.as_ref().map(|(host, port)| (host.as_str(), *port)),
        grant_id,
        exp,
    });
    let grant = match signed {
        Ok(g) => g,
        Err(e) => {
            warn!(session = %req.session_id, %e, "vault: a grant was not signed");
            return Err(rec.refuse(LeaseRefusal::Unavailable, "unsigned").await);
        }
    };
    rec.grant = Some(grant_id);
    if let Err(e) = rec.decided(true, &reason, &ask, None).await {
        warn!(session = %req.session_id, %e, "vault: a grant's allow was not recorded — not given");
        return Err(LeaseRefusal::Undecided);
    }
    Ok(Granted {
        grant_id,
        grant,
        expires_at: DateTime::from_millis(exp * 1000),
        dst,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(kind: &str, host: &str, port: u16) -> NetRequest {
        NetRequest {
            req_id: "n1".into(),
            session_id: ObjectId::new(),
            fence: 1,
            exit: ObjectId::new(),
            kind: kind.into(),
            host: host.into(),
            port,
            ttl_secs: 60,
        }
    }

    /// SOCKS names no destination and a forward names one, its host taken in
    /// its one spelling; anything else is refused before the session is read.
    #[test]
    fn a_request_names_what_its_kind_needs() {
        assert_eq!(
            within_bounds(&req("socks", "", 0)),
            Some((NetKind::Socks, None))
        );
        assert_eq!(
            within_bounds(&req("forward", "DB.Internal.", 5432)),
            Some((NetKind::Forward, Some(("db.internal".into(), 5432))))
        );
        for bad in [
            req("socks", "db.internal", 0),
            req("socks", "", 5432),
            req("forward", "", 5432),
            req("forward", "db.internal", 0),
            req("forward", "db.internal:5432", 5432),
            req("forward", "010.0.0.5", 5432),
            req("udp", "", 0),
            req("SOCKS", "", 0),
        ] {
            assert_eq!(within_bounds(&bad), None, "{bad:?}");
        }
        for req_id in [
            String::new(),
            "a\nb".to_string(),
            "r".repeat(lease_limits::MAX_REQ_ID_LEN + 1),
        ] {
            let r = NetRequest {
                req_id,
                ..req("socks", "", 0)
            };
            assert_eq!(within_bounds(&r), None, "{r:?}");
        }
    }
}
