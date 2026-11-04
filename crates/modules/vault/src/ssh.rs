// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-8-1a — a session's command on another device: the vault's answer to
//! `rc:vault.ssh`, a ticket the network module believes without calling a
//! module (P3-8-1b).
//!
//! A session's device asks over its own control connection, in the queue its
//! leases share, and the vault answers on that connection: a ticket
//! (`rc:vault.ssh.granted`), a token signed by core's auth service under an
//! audience of its own (`ssh_ticket`), or one word (`rc:vault.refused`,
//! [`LeaseRefusal`]). A ticket, not a grant: `rc:ssh.grant` is the target's
//! (FR-83), and the request carries both.
//!
//! | Check, in order | Refused as | Recorded |
//! |---|---|---|
//! | the request within its bounds: its id | `bad_request` | no |
//! | the vault serves the organization | `not_served` | no |
//! | the device takes leases: its hello advertised `vault` and carried a key | `unsupported` | no |
//! | a session of the organization whose record places it on THIS device | `not_located` | no |
//! | at the record's fence | `stale_fence` | yes |
//! | live | `ended` | yes |
//! | within the session's per-minute ceiling, which its leases share | `busy` | no |
//! | the target another device than this one | `bad_request` | yes, as `own_device` |
//! | holding a vault role | `no_role` | yes |
//! | the target a live device of the organization | `no_target` | yes |
//! | Cedar's `ssh:run`: the node's facts, the account its SSH policy maps, and the device's, each read from its ROW | `denied` | yes, with the request |
//! | signed | `unavailable` | yes |
//! | the allow recorded | `undecided` | — |
//!
//! ⚠️ Never the device it runs on: a session already runs there, as its own
//! account, and SSH would run its command as whatever that device's policy
//! maps, the daemon's among them. The auth service signs no such ticket
//! either.
//!
//! ⚠️ The account is the target ROW's (`ssh_policy.account_mode`): decided on,
//! so a policy can forbid a session the daemon's, and named in the ticket, so
//! a policy changed since is refused at the network module (P3-8-1b).
//!
//! ⚠️ The allow is recorded BEFORE the ticket is sent: a ticket the vault
//! could not record is never given. A ticket is no lease: no `vault_leases`
//! row, nothing `rc:vault.revoke` names; its end bounds it.

use bson::{DateTime, oid::ObjectId};
use meshharbor_remote_control::models::SshAccountMode;
use meshharbor_remote_control::vault::{LeaseRefusal, lease_limits};
use meshharbor_services::auth::SshTicket;
use meshharbor_services::dao::base::DaoError;
use tracing::warn;

use crate::VaultState;
use crate::lease::{Conn, identify, os_name, reason_of};
use crate::policy::{self, Ask, DeviceFacts, NodeFacts, SessionFacts};
use crate::policy_routes::decide_for_org;

/// One `rc:vault.ssh`, as it arrived.
#[derive(Debug, Clone)]
pub struct SshRequest {
    pub req_id: String,
    pub session_id: ObjectId,
    pub fence: u64,
    pub target: ObjectId,
    pub ttl_secs: u32,
}

/// What an allowed request answers with.
#[derive(Debug)]
pub struct Ticketed {
    pub ticket_id: ObjectId,
    /// The signed ticket.
    pub ticket: String,
    /// When it ends: whole seconds, as the ticket names its end.
    pub expires_at: DateTime,
    /// The target's OS, as its row holds it.
    pub os: String,
    /// The account decided on: the one the target's SSH policy maps.
    pub account: SshAccountMode,
}

/// Whether the request is within its bounds: an id an answer can name.
fn within_bounds(req: &SshRequest) -> bool {
    !req.req_id.is_empty()
        && req.req_id.len() <= lease_limits::MAX_REQ_ID_LEN
        && !req.req_id.chars().any(char::is_control)
}

/// Decide one request, and ticket it when it is allowed.
pub async fn ticket(
    state: &VaultState,
    conn: Conn,
    req: &SshRequest,
) -> Result<Ticketed, LeaseRefusal> {
    if !within_bounds(req) {
        return Err(LeaseRefusal::BadRequest);
    }
    let target_hex = req.target.to_hex();
    let (agent, session, mut rec) = identify(
        state,
        conn,
        req.session_id,
        req.fence,
        &target_hex,
        policy::ACTION_SSH_RUN,
        "ticket",
    )
    .await?;
    // Never the device it runs on: SSH there would run the command as
    // whatever that device maps, not as the session.
    if req.target == conn.device_id {
        return Err(rec.refuse(LeaseRefusal::BadRequest, "own_device").await);
    }
    if session.vault_role.is_none() {
        let why = LeaseRefusal::NoRole;
        return Err(rec.refuse(why, why.wire()).await);
    }
    // The target as its ROW holds it, and only within this organization: a
    // device of another is no target, and the refusal says no more than that.
    let target = match state
        .agents
        .find_live_in_tenant(conn.tenant_id, req.target)
        .await
    {
        Ok(a) => a,
        Err(DaoError::NotFound) => {
            let why = LeaseRefusal::NoTarget;
            return Err(rec.refuse(why, why.wire()).await);
        }
        Err(e) => {
            warn!(target = %req.target, %e, "vault: a ticket's target was not read");
            return Err(rec.refuse(LeaseRefusal::Unavailable, "target_unread").await);
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
    let os = os_name(target.os);
    let node = match NodeFacts::new(req.target, os, &target.tags, target.owner_user_id) {
        Ok(n) => n,
        Err(why) => {
            return Err(rec
                .refuse(LeaseRefusal::Denied, &format!("node: {why}"))
                .await);
        }
    };
    let account = target.ssh_policy.account_mode;
    let ask = Ask::SshRun {
        session: SessionFacts {
            id: req.session_id.to_hex(),
            owner: session.owner_id,
            role: session.vault_role.clone(),
            playbook: None,
        },
        node,
        account: account.wire().to_string(),
        device,
    };
    let verdict = decide_for_org(state, conn.tenant_id, &ask).await;
    let reason = reason_of(&verdict);
    if !verdict.allow {
        if let Err(e) = rec.decided(false, &reason, &ask, None).await {
            warn!(session = %req.session_id, %e, "vault: a ticket's deny was not recorded");
        }
        return Err(LeaseRefusal::Denied);
    }

    // Allowed: sign it, BEFORE the allow is recorded, so a recorded allow is
    // one that was ready to give.
    let ttl = req
        .ttl_secs
        .clamp(lease_limits::MIN_TTL_SECS, lease_limits::MAX_TTL_SECS);
    let exp = DateTime::now().timestamp_millis().div_euclid(1000) + i64::from(ttl);
    let ticket_id = ObjectId::new();
    let signed = state.core.auth.issue_ssh_ticket(&SshTicket {
        session_id: req.session_id,
        tenant_id: conn.tenant_id,
        fence: req.fence,
        owner_user_id: session.owner_id,
        origin_agent_id: conn.device_id,
        target_agent_id: req.target,
        account,
        ticket_id,
        exp,
    });
    let ticket = match signed {
        Ok(t) => t,
        Err(e) => {
            warn!(session = %req.session_id, %e, "vault: a ticket was not signed");
            return Err(rec.refuse(LeaseRefusal::Unavailable, "unsigned").await);
        }
    };
    rec.ticket = Some(ticket_id);
    if let Err(e) = rec.decided(true, &reason, &ask, None).await {
        warn!(session = %req.session_id, %e, "vault: a ticket's allow was not recorded — not given");
        return Err(LeaseRefusal::Undecided);
    }
    Ok(Ticketed {
        ticket_id,
        ticket,
        expires_at: DateTime::from_millis(exp * 1000),
        os: os.to_string(),
        account,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(req_id: &str) -> SshRequest {
        SshRequest {
            req_id: req_id.into(),
            session_id: ObjectId::new(),
            fence: 1,
            target: ObjectId::new(),
            ttl_secs: 60,
        }
    }

    /// A request names itself by an id an answer can carry; anything else is
    /// refused before the session is read.
    #[test]
    fn a_request_names_itself_within_its_bounds() {
        assert!(within_bounds(&req("s1")));
        for bad in [
            String::new(),
            "a\nb".to_string(),
            "r".repeat(lease_limits::MAX_REQ_ID_LEN + 1),
        ] {
            assert!(!within_bounds(&req(&bad)), "{bad:?}");
        }
    }
}
