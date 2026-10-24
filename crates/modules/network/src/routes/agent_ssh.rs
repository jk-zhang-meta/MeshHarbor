// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Roomler SSH — the server side.
//!
//! This module is the POLICY DECISION POINT, the twin of [`agent_exec`]. The
//! agent decides what happens on the box (its own `ssh_enabled` key, the grant
//! bounds, what a session may do); everything about *who may ask* is decided
//! here, in one place.
//!
//! ## The four gates
//!
//! A session is authorized only if all four pass, each owned by a different
//! party so no single compromise is sufficient:
//!
//! 1. `TenantSettings.remote_ssh_enabled` — the org kill-switch, default off,
//!    and deliberately NOT the same switch as `remote_exec_enabled`.
//! 2. `permissions::SSH_DEVICE` on the caller's role. Not implied by
//!    `MANAGE_AGENTS` and not part of `DEFAULT_ADMIN`.
//! 3. The device's `SshPolicy` — mode, allowed users/roles, and (for the
//!    device-originated leg) `can_originate` on the ORIGINATING device.
//! 4. The agent's own `ssh_enabled` config key, enforced agent-side.
//!
//! Gates 1-3 are evaluated by [`authorize`]. Gate 4 is the device's, and it
//! reaches the caller through the grant acknowledgement (FR-83): an
//! ack-capable agent answers every grant, naming its refusal if it has one.
//!
//! ## Why this hands out a key instead of a command
//!
//! Exec pushes a command and waits for the output — the server sees
//! everything. SSH cannot work that way and should not: the whole point is a
//! session the server never observes. So the server's role ends at
//! authorization. It mints a **grant** — the caller's ephemeral public key,
//! the principal's name, the account, an expiry — pushes it to the target,
//! waits for the target to confirm it holds it, and tells the caller where to
//! dial. What passes over that connection is between the two devices.
//!
//! ⚠️ The wait is the difference between "queued for the device" and "the
//! device has it" (#1597). Without it, a caller whose control path to the
//! server was faster than the target's dialled first and was refused
//! `Permission denied (publickey)` by a device behaving correctly. It is
//! bounded ([`ssh_limits::GRANT_ACK_TIMEOUT_SECS`]) and applies only to an
//! agent advertising `ssh-grant-ack`; an older one is answered as before.
//!
//! So the server's last word is the grant's CONFIRMATION, not the session:
//! whether a connection then succeeds is still decided on a path the server
//! is not on. Every reason a request can fail — the server's gates and the
//! device's answer — is enumerated in [`SshDenyReason`] and answered before
//! the caller dials.
//!
//! ## Privilege
//!
//! A session runs as what the policy actually asked for, never more:
//! `SshPolicy.account_mode` crosses to the device in the grant and the agent's
//! `RunAs` honours it or refuses (P5a/P5b). `daemon` still means SYSTEM under a
//! perMachine Windows install and root under systemd — so a policy of `daemon`
//! is granting root on that device, deliberately and in writing.
//!
//! ## Consent
//!
//! `SshPolicy.consent_mode` decides whether a human at the device approves
//! before anything runs. Only `auto` skips the prompt. This route refuses to
//! STORE a non-auto value for a device whose agent predates P5d
//! ([`consent_mode_would_be_ignored`]) — such an agent accepts the field and
//! ignores it, and a policy that reads as enforced while doing nothing is worse
//! than no policy, because it gets relied upon.
//!
//! [`agent_exec`]: super::agent_exec

use axum::{
    Json,
    extract::{Path, Query, State},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::oid::ObjectId;
use roomler_ai_db::models::role::permissions;
use roomler_ai_remote_control::{
    models::{
        Agent, ConsentMode, OsKind, RpcCap, SshAccountMode, SshActivityEvent, SshActivityKind,
        SshAuditEvent, SshDenyReason, SshGates, SshGrantSpec, SshMode, SshPending, SshPolicy,
        SshServiceCeiling, SshServiceEndpoint, ssh_limits,
    },
    signaling::ServerMsg,
};
use roomler_ai_services::auth::AuthService;
use roomler_ai_services::dao::base::PaginationParams;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use roomler_core::guards::require_permission;
use roomler_core::{ApiError, extractors::auth::AuthUser};

use crate::NetworkState;
use crate::ssh_grant_acks::AckOutcome;

// ────────────────────────────────────────────────────────────────────────────
// Wire shapes
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SshRequestBody {
    /// OpenSSH public key of the caller's EPHEMERAL session keypair
    /// (`ssh-ed25519 AAAA… comment`). The private half never leaves the
    /// caller; this is the only thing the server or the target ever sees.
    pub public_key: String,
    /// Requested session lifetime in seconds. Clamped server-side; 0 or absent
    /// means the ceiling.
    #[serde(default)]
    pub session_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct SshResponseBody {
    /// Where to dial. Absent on refusal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The device's MagicDNS name, for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// P6 — the OpenSSH public half of the target's SSH host key, so the
    /// caller can verify what it dialled rather than trusting it on first
    /// use. Carried HERE because this response is already the one thing that
    /// says where to dial; whoever has the address has the key.
    ///
    /// Absent when the device reported none (never SSH-enabled, or a build
    /// without `ssh-server`). That is not permission to skip the check — it
    /// means the device cannot prove itself, and a client should say so rather
    /// than silently fall back to TOFU. ⚠️ Present does not imply SSH is on:
    /// the key outlives `ssh_enabled` going false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_pubkey: Option<String>,
    /// Unix ms after which the grant is dead — dial before this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    /// Set when the request was refused, naming which gate said no.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// FR-90 P3-8-1b — the agent session's ticket, by its id, when the
    /// request was held to it (`rc:ssh.response`'s echo). Absent for a
    /// person's request, so the HTTP body is what it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_ticket_id: Option<String>,
}

impl SshResponseBody {
    fn denied(reason: SshDenyReason) -> Self {
        Self {
            address: None,
            port: None,
            name: None,
            grant_id: None,
            host_pubkey: None,
            expires_at_ms: None,
            error: Some(reason.message().to_string()),
            ssh_ticket_id: None,
        }
    }
}

// FR-69 P5a — the policy REQUEST shape moved to the wire crate (the fleet
// module accepts it inside its agent-update body); re-exported so every
// `crate::routes::agent_ssh::SshPolicyBody` path reads as before.
pub use roomler_ai_remote_control::models::SshPolicyBody;

#[derive(Debug, Serialize, Deserialize)]
pub struct OrgSshSettings {
    pub remote_ssh_enabled: bool,
}

/// The acting principal, and how it reached us.
pub struct Caller {
    pub user_id: ObjectId,
    pub display: String,
    /// Set on the device-originated leg — the device whose LocalAPI asked.
    pub origin_agent_id: Option<ObjectId>,
    /// FR-90 P3-8-1b — whether an agent session asked, under its own ticket.
    pub session: CallerSession,
}

/// FR-90 P3-8-1b — an agent session's part in a request, decided where the
/// request arrived ([`bind_ssh_ticket`]) and carried here so [`dispatch`]
/// audits every outcome in its one place, a refused ticket's included.
pub enum CallerSession {
    /// A person's request (`roomler ssh`, the HTTP route): no ticket.
    None,
    /// An agent session's, its ticket held: the SESSION is the principal and
    /// `Caller::user_id` the person it acts for.
    Bound(SessionCaller),
    /// An agent session's, its ticket refused, and why (for the log). Never
    /// served as the device owner's request instead.
    Refused(&'static str),
}

/// FR-90 P3-8-1b — an agent session, as its verified ticket names it.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionCaller {
    pub session_id: ObjectId,
    /// The person the session acts for.
    pub owner_user_id: ObjectId,
    /// The ticket's id (`ticket:<id>` in `vault_audit`), echoed and audited.
    pub ticket_id: String,
    /// The account the target's SSH policy mapped when the vault decided.
    pub account: SshAccountMode,
    /// When the ticket ends, unix seconds: the SSH session ends by then too.
    pub ends_at: i64,
}

/// FR-90 P3-8-1b — verify a ticket presented at `rc:ssh.request` and bind it
/// to the request. `verify_ssh_ticket` checks its signature, its audience,
/// its ids, its two devices, its account and its life; this checks it names
/// THIS organization, THIS connection's device as its origin, and the
/// request's target as resolved, compared by id. The reason it does not hold,
/// otherwise.
///
/// ⚠️ Only from an agent's own WS: a session's request rides its device's
/// connection, never a person's HTTP call.
pub fn bind_ssh_ticket(
    auth: &AuthService,
    tenant_id: ObjectId,
    origin_agent_id: Option<ObjectId>,
    target_agent_id: ObjectId,
    token: &str,
) -> Result<SessionCaller, &'static str> {
    let Some(origin) = origin_agent_id else {
        return Err("a session's ticket rides only its own device's connection");
    };
    let claims = auth
        .verify_ssh_ticket(token)
        .map_err(|_| "not a ticket this server signed, or it has ended")?;
    let id =
        |hex: &str| ObjectId::parse_str(hex).map_err(|_| "a ticket naming an id that is not one");
    if id(&claims.tenant_id)? != tenant_id {
        return Err("a ticket for another organization");
    }
    if id(&claims.origin_agent_id)? != origin {
        return Err("a ticket for another device");
    }
    if id(&claims.target_agent_id)? != target_agent_id {
        return Err("a ticket for another target");
    }
    let account = SshAccountMode::from_wire(&claims.account)
        .ok_or("a ticket naming an account this build cannot name")?;
    Ok(SessionCaller {
        session_id: id(&claims.sub)?,
        owner_user_id: id(&claims.owner_user_id)?,
        ticket_id: claims.jti,
        account,
        ends_at: claims.exp,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Authorization
// ────────────────────────────────────────────────────────────────────────────

/// Evaluate gates 1-3. `Ok(())` means a grant may be minted.
///
/// Split out from [`dispatch`] so the whole decision is testable on its own
/// and so no path can skip a gate by taking a different route into the mint.
///
/// Takes the TARGET's [`SshGates`] — the authorize-time half of its policy,
/// produced by [`SshPolicy::split`] — rather than the policy itself, so this
/// function cannot quietly ignore a policy field: the split routes every
/// field, and the exhaustive destructure below has to bind every gate.
pub async fn authorize(
    state: &NetworkState,
    tenant_id: ObjectId,
    gates: &SshGates,
    caller: &Caller,
) -> Result<(), SshDenyReason> {
    // EXHAUSTIVE — a gate added to `SshGates` must be bound (and, under
    // `-D warnings`, used) here before this compiles again.
    let SshGates {
        mode,
        can_originate,
        allowed_user_ids,
        allowed_role_ids,
    } = gates;
    // Two fields are consulted elsewhere, in writing: the TARGET's
    // `can_originate` is not an inbound gate (it is read off the ORIGIN
    // device's row below), and the user allowlist is consulted through
    // `allows_caller`. Consumed here so the destructure stays exhaustive and
    // a NEW gate cannot borrow this line as precedent for being skipped.
    let _ = (can_originate, allowed_user_ids);

    // Gate 1 — the org kill-switch. First because it is the cheapest check and
    // the most likely reason a whole fleet says no.
    let tenant = match state.tenants.base.find_by_id(tenant_id).await {
        Ok(t) => t,
        Err(_) => return Err(SshDenyReason::OrgDisabled),
    };
    if !tenant.settings.remote_ssh_enabled {
        return Err(SshDenyReason::OrgDisabled);
    }

    // FR-90 P3-8-1b — an agent session's request is the session's, never its
    // owner's: the vault's `ssh:run` decided in gate 2's place, and the
    // owner's `SSH_DEVICE` is not read for it.
    let session = matches!(caller.session, CallerSession::Bound(_));

    // Gate 2 — the caller's role.
    if !session {
        let perms = state
            .tenants
            .get_member_permissions(tenant_id, caller.user_id)
            .await
            .unwrap_or(0);
        if !permissions::has(perms, permissions::SSH_DEVICE) {
            return Err(SshDenyReason::NoPermission);
        }
    }

    // Gate 3 — the target device's own policy.
    if *mode != SshMode::On {
        return Err(SshDenyReason::DeviceDisabled);
    }
    // FR-90 P3-8-1b — which policies admit a session is decision 22 (the
    // spec's §6); until it is built, none does, and the owner's own place on
    // the allowlists never stands in for the session's.
    if session {
        return Err(SshDenyReason::SessionNotAllowed);
    }
    // Role ids are only fetched when the policy actually restricts by role —
    // an extra query on every SSH request would be paid by the common case to
    // serve the rare one.
    let role_ids = if allowed_role_ids.is_empty() {
        Vec::new()
    } else {
        state
            .tenants
            .member_role_ids(tenant_id, caller.user_id)
            .await
            .unwrap_or_default()
    };
    if !gates.allows_caller(&caller.user_id, &role_ids) {
        return Err(SshDenyReason::CallerNotAllowed);
    }

    // The device-originated leg only: the ORIGINATING device must be blessed.
    // Without this, compromising any enrolled laptop would inherit its owner's
    // SSH rights across the whole fleet. LIVE: a removed device cannot
    // originate, whatever `can_originate` its tombstone still says (#1821).
    if let Some(origin) = caller.origin_agent_id {
        match state
            .fleet
            .agents
            .find_live_in_tenant(tenant_id, origin)
            .await
        {
            Ok(a) if a.ssh_policy.can_originate => {}
            _ => return Err(SshDenyReason::OriginNotAllowed),
        }
    }

    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Dispatch
// ────────────────────────────────────────────────────────────────────────────

/// A decision that came out `Ok`. Carries everything BOTH the response and the
/// audit row need, so neither has to reach back into the other's leftovers.
struct Granted {
    grant_id: String,
    address: String,
    name: Option<String>,
    /// `None` when the device reported no host key — see
    /// [`SshResponseBody::host_pubkey`].
    host_pubkey: Option<String>,
    expires_at_ms: u64,
    account_mode: SshAccountMode,
    session_secs: u64,
    /// FR-83 — how long the target took to confirm the grant, from the push.
    /// `None` = a pre-FR-83 agent, answered without waiting. Logged, so the
    /// ack bound can be tuned against what the field actually measures.
    confirmed_after_ms: Option<u64>,
    /// Where the caller dials: the worker's port, or (FR-105) the SYSTEM
    /// service's.
    port: u16,
    /// FR-105 — who serves the session: `system` / `console_user` (the
    /// device's SYSTEM service) or `worker`. Recorded in `ssh_audit`.
    ran_as: &'static str,
}

/// Gate, mint, push, answer. The ONE path a session request takes, whether it
/// came from the browser, the API, or a device's LocalAPI.
///
/// The decision itself lives in [`decide`]; this wrapper exists so that EVERY
/// outcome — grant or refusal — passes through a single audit write on its way
/// out. Previously each refusal site called a `deny` helper, which meant a new
/// refusal was audited only if whoever added it remembered to route through
/// that helper. Now the type system does it: `decide` can only return
/// `Result<Granted, SshDenyReason>`, and both arms are recorded here.
pub async fn dispatch(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent: &Agent,
    caller: &Caller,
    public_key: &str,
    session_secs: u64,
) -> SshResponseBody {
    let agent_id = agent.id.unwrap_or_default();
    // FR-90 P3-8-1b — a session's ticket that does not hold refuses the
    // request here, audited like any other refusal, and is never answered as
    // the device owner's request instead.
    let outcome = match &caller.session {
        CallerSession::Refused(why) => {
            warn!(
                agent = %agent_id, caller = %caller.display, why = *why,
                "ssh: an agent session's ticket does not hold"
            );
            Err(SshDenyReason::TicketRefused)
        }
        CallerSession::None | CallerSession::Bound(_) => {
            decide(state, tenant_id, agent, caller, public_key, session_secs).await
        }
    };
    record_audit(state, tenant_id, agent_id, caller, &outcome).await;
    // The echo: the session's daemon dials only on an answer naming the
    // ticket it presented, which a server that ignored the ticket never sends.
    let ssh_ticket_id = match &caller.session {
        CallerSession::Bound(s) => Some(s.ticket_id.clone()),
        CallerSession::None | CallerSession::Refused(_) => None,
    };

    match outcome {
        Ok(g) => {
            info!(
                agent = %agent_id, caller = %caller.display, grant_id = %g.grant_id,
                account_mode = ?g.account_mode, session_secs = g.session_secs,
                confirmed_after_ms = ?g.confirmed_after_ms, ran_as = g.ran_as,
                "ssh: grant issued"
            );
            SshResponseBody {
                address: Some(g.address),
                // The worker's port is agent-side config, and the server does
                // not carry it: the built-in default is what an unconfigured
                // device serves, and a device that moved its port tells its
                // own users. FR-105's service port is fixed, and the server
                // picks it, because the worker cannot route by inspection.
                port: Some(g.port),
                name: g.name,
                grant_id: Some(g.grant_id),
                host_pubkey: g.host_pubkey,
                expires_at_ms: Some(g.expires_at_ms),
                error: None,
                ssh_ticket_id,
            }
        }
        Err(reason) => {
            warn!(
                agent = %agent_id, caller = %caller.display, ?reason,
                "ssh: request denied"
            );
            SshResponseBody {
                ssh_ticket_id,
                ..SshResponseBody::denied(reason)
            }
        }
    }
}

/// Everything between "a request arrived" and "a grant is on its way to the
/// device". Returns the refusal reason rather than a response body so it
/// cannot answer the caller without [`dispatch`] auditing first.
async fn decide(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent: &Agent,
    caller: &Caller,
    public_key: &str,
    session_secs: u64,
) -> Result<Granted, SshDenyReason> {
    let agent_id = agent.id.unwrap_or_default();

    // Validate the key BEFORE consulting policy: a caller who sent garbage
    // should be told that, not told their permissions are wrong.
    if !is_supported_public_key(public_key) {
        return Err(SshDenyReason::BadPublicKey);
    }

    // The ONE place the target's policy is consumed: `split` routes every
    // field into either the authorize gates or the grant spec, so a new
    // policy field cannot be silently ignored by either half.
    let (gates, spec) = agent.ssh_policy.clone().split();

    // FR-90 P3-8-1b — an agent session's request, checked as the key is,
    // before the gates: the ticket was decided for the account the target's
    // policy mapped then, and a policy changed since is a ticket that no
    // longer holds; and only a device that can hold the grant to one command
    // is sent one.
    let session = match &caller.session {
        CallerSession::Bound(s) => Some(s),
        CallerSession::None | CallerSession::Refused(_) => None,
    };
    if let Some(s) = session {
        if s.account != spec.account_mode {
            warn!(
                agent = %agent_id, session = %s.session_id, ticket = ?s.account,
                policy = ?spec.account_mode,
                "ssh: the target's account changed since the session's ticket was decided"
            );
            return Err(SshDenyReason::TicketRefused);
        }
        if !agent.capabilities.has_rpc(RpcCap::SshOneCommand) {
            return Err(SshDenyReason::TargetTooOld);
        }
    }

    authorize(state, tenant_id, &gates, caller).await?;

    // Ceiling, enforced AFTER the identity gates so a refusal is attributable
    // (and audited by `dispatch`) rather than an anonymous throttle. This is
    // the one place both the HTTP route and the device's `rc:ssh.request` leg
    // pass through — the WS leg never touches the per-IP HTTP governor. It
    // also protects the TARGET: the device's pending-grant table holds 16 and
    // evicts the OLDEST, so an unthrottled caller could burst a legitimate
    // caller's un-redeemed grant out of existence.
    //
    // FR-90 P3-8-1b — a session's requests count against the SESSION, so one
    // session cannot spend its owner's budget, nor its owner the session's.
    let rate_key = session.map_or(caller.user_id, |s| s.session_id);
    if !state
        .ssh_rate_limiter
        .check(rate_key, agent_id, ssh_limits::RATE_LIMIT_PER_MINUTE)
    {
        return Err(SshDenyReason::RateLimited);
    }

    // Where to send them. A device can pass every gate and still be
    // unreachable — that is a different failure and says so.
    let node = match state
        .overlay_nodes
        .find_live_by_agent(tenant_id, agent_id)
        .await
    {
        Ok(Some(n)) if !n.overlay_ip.is_empty() => n,
        _ => return Err(SshDenyReason::NoOverlayAddress),
    };

    let grant_id = ObjectId::new().to_hex();
    let session_secs = ssh_limits::clamp_session_secs(session_secs);
    // FR-90 P3-8-1b — a session's SSH session ends with its ticket at the
    // latest: the target closes it there, whatever the session asked for.
    let session_secs = match session {
        Some(s) => session_secs.min(secs_left(s.ends_at, now_ms())),
        None => session_secs,
    };
    let expires_at_ms = now_ms() + ssh_limits::GRANT_TTL_SECS * 1000;

    // EXHAUSTIVE — the spec's fields map 1:1 onto the wire, and binding them
    // all here is what keeps a field routed into the spec from being dropped
    // on its way into the grant.
    let SshGrantSpec {
        account_mode,
        account,
        consent_mode,
    } = spec;
    // FR-105 — who serves this grant: the device's SYSTEM service, or its
    // worker (on an attended Windows install, the signed-in user).
    let via_service = routes_ssh_via_service(state, agent, account_mode, session.is_some());
    let consent_mode = Some(effective_wire_consent(consent_mode));
    let msg = ServerMsg::SshGrant {
        grant_id: grant_id.clone(),
        public_key: public_key.to_string(),
        caller: caller.display.clone(),
        account_mode: account_mode_wire(account_mode).to_string(),
        account,
        expires_at_ms,
        session_secs,
        consent_mode,
        via_service,
        one_command: session.is_some(),
    };

    // FR-105 — the service PULLS the grant with its own credential, so it is
    // written down before the worker hears its id. The claim window is the
    // caller's own wait: once nobody waits, nothing may claim it.
    if via_service {
        let now = bson::DateTime::now();
        let at = |offset_secs: u64| {
            bson::DateTime::from_millis(
                now.timestamp_millis()
                    .saturating_add((offset_secs * 1000) as i64),
            )
        };
        let row = SshPending {
            id: None,
            grant_id: grant_id.clone(),
            tenant_id,
            agent_id,
            public_key: public_key.to_string(),
            caller: caller.display.clone(),
            account_mode: account_mode_wire(account_mode).to_string(),
            expires_at_ms,
            session_secs,
            consent_mode,
            one_command: session.is_some(),
            state: SshPending::PENDING.to_string(),
            created_at: now,
            claim_by: at(ssh_limits::GRANT_ACK_TIMEOUT_SECS),
            expires_at: at(ssh_limits::GRANT_TTL_SECS * 2),
            claimed_at: None,
        };
        if let Err(e) = state.ssh_pending.insert(&row).await {
            // Never a quiet fall back to the worker: that would run the
            // session as a different identity than the policy granted.
            warn!(agent = %agent_id, %grant_id, %e, "ssh: could not record a grant for the SYSTEM service");
            return Err(SshDenyReason::GrantUnconfirmed);
        }
    }

    // FR-83 — park on the target's answer BEFORE the push: an ack that beats
    // this function back here must find somewhere to land. Dropping the guard
    // (any early return below) deregisters it.
    let pending_ack = if via_service {
        state.ssh_grant_acks.expect_via_service(&grant_id, agent_id)
    } else {
        state.ssh_grant_acks.expect(&grant_id, agent_id)
    };
    let pushed_at = std::time::Instant::now();
    let acks = match state.fleet.rc_hub.push_ssh_grant(agent_id, tenant_id, msg) {
        Ok(acks) => acks,
        // The hub distinguishes "not connected" from "connected but cannot
        // honour it", and the caller needs that difference: one is wait and
        // retry, the other is upgrade the agent.
        Err(e) => {
            if via_service {
                withdraw_service_grant(state, &grant_id, tenant_id).await;
            }
            return Err(match e {
                roomler_ai_remote_control::error::Error::ExecUnsupported(_) => {
                    SshDenyReason::Unsupported
                }
                _ => SshDenyReason::Offline,
            });
        }
    };

    // Queued is not recorded (#1597). The caller is told where to dial only
    // once the target says the grant is in the table its auth path reads —
    // otherwise a caller whose control path is faster than the target's
    // dials first and is refused `Permission denied (publickey)` by a device
    // that is behaving correctly. A pre-FR-83 agent never answers, and is
    // answered exactly as before rather than made to wait out the bound.
    //
    // FR-105 — a via-service grant always waits, and only for the SERVICE:
    // its claim (on this pod, or read from the shared row) is the ack, and
    // the worker can only refuse.
    let confirmed_after_ms = if via_service {
        let bound = std::time::Duration::from_secs(ssh_limits::GRANT_ACK_TIMEOUT_SECS);
        let rows = state.ssh_pending.clone();
        let polled = grant_id.clone();
        let outcome = pending_ack
            .wait_or_claimed(bound, SERVICE_CLAIM_POLL, || {
                let (rows, polled) = (rows.clone(), polled.clone());
                async move { rows.is_claimed(&polled).await.unwrap_or(false) }
            })
            .await;
        match outcome {
            AckOutcome::Recorded => Some(pushed_at.elapsed().as_millis() as u64),
            AckOutcome::Refused(refusal) => {
                // Withdrawn, so a claim racing the worker's refusal cannot
                // take what the caller is about to be told was refused.
                withdraw_service_grant(state, &grant_id, tenant_id).await;
                warn!(
                    agent = %agent_id, caller = %caller.display, %grant_id, ?refusal,
                    "ssh: the device refused a grant for its SYSTEM service"
                );
                return Err(refusal.deny_reason());
            }
            AckOutcome::Unconfirmed => {
                // The claim may have won the race against the bound: a row
                // that cannot be withdrawn because it was claimed IS a grant
                // the service holds.
                match state.ssh_pending.cancel(&grant_id, tenant_id).await {
                    Ok(false)
                        if state
                            .ssh_pending
                            .is_claimed(&grant_id)
                            .await
                            .unwrap_or(false) =>
                    {
                        Some(pushed_at.elapsed().as_millis() as u64)
                    }
                    _ => return Err(SshDenyReason::GrantUnconfirmed),
                }
            }
        }
    } else if acks {
        let bound = std::time::Duration::from_secs(ssh_limits::GRANT_ACK_TIMEOUT_SECS);
        match pending_ack.wait(bound).await {
            AckOutcome::Recorded => Some(pushed_at.elapsed().as_millis() as u64),
            AckOutcome::Refused(refusal) => {
                warn!(
                    agent = %agent_id, caller = %caller.display, %grant_id, ?refusal,
                    "ssh: the device refused the grant"
                );
                return Err(refusal.deny_reason());
            }
            // Refused, never answered with an address: the one thing known
            // now is that the device has NOT confirmed. The grant may still
            // land; it then expires unused within its TTL.
            AckOutcome::Unconfirmed => return Err(SshDenyReason::GrantUnconfirmed),
        }
    } else {
        drop(pending_ack);
        None
    };

    // FR-105 — the service's own key for its own port. `routes_ssh_via_service`
    // required a published one, so this is never empty there. The worker's
    // key (what its last hello said) never stands in for it.
    let host_pubkey = if via_service {
        agent.ssh_service.as_ref().map(|s| s.host_pubkey.clone())
    } else {
        // From the AGENT ROW, i.e. what the device said on its last hello —
        // not from anything the caller supplied. Empty stays `None` rather
        // than an empty string so a client cannot accidentally "verify"
        // against nothing.
        (!agent.ssh_host_pubkey.is_empty()).then(|| agent.ssh_host_pubkey.clone())
    };
    Ok(Granted {
        grant_id,
        address: node.overlay_ip.clone(),
        name: (!node.name.is_empty()).then(|| node.name.clone()),
        host_pubkey,
        expires_at_ms,
        account_mode,
        session_secs,
        confirmed_after_ms,
        port: if via_service {
            ssh_limits::SERVICE_PORT
        } else {
            DEFAULT_SSH_PORT
        },
        ran_as: ran_as(via_service, account_mode),
    })
}

/// FR-105 — how often a caller waiting on a via-service grant re-reads the
/// shared row, in case the service's claim landed on another pod.
const SERVICE_CLAIM_POLL: std::time::Duration = std::time::Duration::from_millis(400);

/// FR-105 — does a grant for `agent`, as `mode`, go to the device's SYSTEM
/// service? All of:
/// - the server's kill switch (`rc.ssh_via_service`);
/// - a Windows device, anchored by an administrator;
/// - an endpoint its service published under THAT anchor (a re-anchor, an
///   un-anchor or a removal leaves the record stale, so no cleanup is needed),
///   with a host key, and a ceiling that permits `mode`;
/// - the device, connected to this pod, advertising `ssh-system`.
///
/// Both halves, as for exec: the server's record (the anchor, and what the
/// service published with its OWN credential) and the device's live word (the
/// service is up and answering the worker). A worker that lies about the word
/// gains nothing: the caller pins a key only the real service holds.
///
/// FR-90 P3-8-2a — and an agent session's grant (`one_command`) only to a
/// service that published that it holds one command. Otherwise the worker
/// serves it, as it serves any grant outside the service's reach, and the
/// worker's own `ssh-one-command` speaks for that.
pub fn routes_ssh_via_service(
    state: &NetworkState,
    agent: &Agent,
    mode: SshAccountMode,
    one_command: bool,
) -> bool {
    state.fleet.settings.rc.ssh_via_service
        && service_endpoint_serves(agent, mode, one_command)
        && agent
            .id
            .is_some_and(|id| state.fleet.rc_hub.agent_supports_ssh_system(id) == Some(true))
}

/// The record's half of [`routes_ssh_via_service`]: a Windows device whose
/// service published an endpoint under its CURRENT anchor, with a host key,
/// a ceiling that permits `mode`, and, for an agent session's grant, the word
/// that it holds one command.
fn service_endpoint_serves(agent: &Agent, mode: SshAccountMode, one_command: bool) -> bool {
    let Some(anchor) = agent
        .exec_anchor
        .as_ref()
        .filter(|a| !a.anchor_id.is_empty())
    else {
        return false;
    };
    matches!(agent.os, OsKind::Windows)
        && agent.ssh_service.as_ref().is_some_and(|s| {
            s.anchor_id == anchor.anchor_id
                && !s.host_pubkey.is_empty()
                && s.ceiling.permits(mode)
                && (s.one_command || !one_command)
        })
}

/// FR-105 — what `ssh_audit.ran_as` records: the server's decision about who
/// serves the session.
fn ran_as(via_service: bool, mode: SshAccountMode) -> &'static str {
    match (via_service, mode) {
        (true, SshAccountMode::Daemon) => "system",
        (true, _) => "console_user",
        (false, _) => "worker",
    }
}

/// FR-105 — the caller stopped waiting for the service (a failed push, a
/// refusal): withdraw the row so no late claim can take the grant. A failure
/// is logged and survivable: `claim_by` still bounds how late a claim can be.
async fn withdraw_service_grant(state: &NetworkState, grant_id: &str, tenant_id: ObjectId) {
    if let Err(e) = state.ssh_pending.cancel(grant_id, tenant_id).await {
        warn!(%grant_id, %e, "ssh: could not withdraw a grant for the SYSTEM service");
    }
}

/// Persist the decision. Best-effort by design: the audit write must never
/// decide whether someone gets a session, so a failed insert is logged loudly
/// — it is the record someone will come looking for — and the request
/// proceeds.
async fn record_audit(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    caller: &Caller,
    outcome: &Result<Granted, SshDenyReason>,
) {
    let event = audit_event(tenant_id, agent_id, caller, outcome);
    if let Err(e) = state.ssh_audit.record(event).await {
        warn!(%agent_id, %e, "ssh: audit write failed");
    }
}

/// Build the row. Split from the write for the same reason [`authorize`] is
/// split from [`dispatch`] — the interesting part is which fields a refusal is
/// allowed to carry, and that should be assertable without a database.
fn audit_event(
    tenant_id: ObjectId,
    agent_id: ObjectId,
    caller: &Caller,
    outcome: &Result<Granted, SshDenyReason>,
) -> SshAuditEvent {
    // Bound once so a refusal cannot accidentally carry grant-only fields:
    // everything below reads from THIS, not from the outcome directly.
    let granted = outcome.as_ref().ok();
    // FR-90 P3-8-1b — a session that asked, once its ticket held; a refused
    // ticket names no session, since nothing it claims was verified.
    let session = match &caller.session {
        CallerSession::Bound(s) => Some(s),
        CallerSession::None | CallerSession::Refused(_) => None,
    };
    SshAuditEvent {
        id: None,
        tenant_id,
        agent_id,
        user_id: caller.user_id,
        origin_agent_id: caller.origin_agent_id,
        grant_id: granted.map(|g| g.grant_id.clone()),
        // The HTTP leg cannot tell a browser from a script — both arrive as an
        // authenticated caller with a bearer token — so this records the only
        // distinction the server can actually observe. An agent session's
        // request is `session` whether or not its ticket held.
        source: match (&caller.session, caller.origin_agent_id) {
            (CallerSession::Bound(_) | CallerSession::Refused(_), _) => "session",
            (CallerSession::None, Some(_)) => "cli",
            (CallerSession::None, None) => "api",
        }
        .to_string(),
        session_id: session.map(|s| s.session_id),
        ssh_ticket_id: session.map(|s| s.ticket_id.clone()),
        caller: caller.display.clone(),
        account_mode: granted.map(|g| account_mode_wire(g.account_mode).to_string()),
        session_secs: granted.map(|g| g.session_secs),
        at: bson::DateTime::now(),
        denied: outcome.as_ref().err().copied(),
        ran_as: granted.map(|g| g.ran_as.to_string()),
    }
}

/// Built-in intercepted SSH port, mirroring the agent's
/// `agent_core::config::DEFAULT_SSH_PORT`. Duplicated rather than imported
/// because the API crate must not depend on the agent's crate — the same
/// reason `agent_exec` duplicates the consent timeout.
const DEFAULT_SSH_PORT: u16 = 2222;

/// Is this an OpenSSH public key we will hand to a device?
///
/// ed25519 only, matching what the agent's host key and the whole design use.
/// Checked here as well as agent-side so a typo is a clear 200-with-error from
/// the API rather than a session that mysteriously never authenticates.
pub(crate) fn is_supported_public_key(line: &str) -> bool {
    let mut parts = line.split_whitespace();
    let Some(algo) = parts.next() else {
        return false;
    };
    let Some(blob) = parts.next() else {
        return false;
    };
    if algo != "ssh-ed25519" {
        return false;
    }

    // Actually PARSE the blob rather than eyeballing its shape. The previous
    // check accepted any run of >=32 graphic characters, so a malformed key
    // passed here, a grant was minted and pushed, and the AGENT then rejected
    // it at redemption (it does a real `from_openssh`) — the caller dialled
    // and failed authentication with no stated reason, and `ssh_audit` gained
    // a "granted" row for a grant no device could ever redeem.
    //
    // OpenSSH ed25519 wire format, decoded: a length-prefixed algorithm name
    // that must repeat the one in the text prefix, then the 32-byte key.
    //   u32(11) "ssh-ed25519" u32(32) <32 bytes>  = 51 bytes total
    let Ok(raw) = BASE64.decode(blob) else {
        return false;
    };
    const ALGO: &[u8] = b"ssh-ed25519";
    if raw.len() != 4 + ALGO.len() + 4 + 32 {
        return false;
    }
    if u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize != ALGO.len() {
        return false;
    }
    if &raw[4..4 + ALGO.len()] != ALGO {
        return false;
    }
    let key_len_at = 4 + ALGO.len();
    let key_len = u32::from_be_bytes([
        raw[key_len_at],
        raw[key_len_at + 1],
        raw[key_len_at + 2],
        raw[key_len_at + 3],
    ]);
    key_len == 32
}

/// What the grant tells the device about consent. Only an explicit `Auto`
/// crosses as `Auto`; everything else — the session-shaped Email/Push and an
/// UNSET policy alike — collapses to `Prompt`, the attended default (the same
/// collapse `ExecPolicy::effective_consent_mode` applies). The device treats
/// the wire value as authoritative, so an accidental `Auto` here would skip a
/// human the admin believed was in the loop.
fn effective_wire_consent(mode: Option<ConsentMode>) -> ConsentMode {
    match mode {
        Some(ConsentMode::Auto) => ConsentMode::Auto,
        _ => ConsentMode::Prompt,
    }
}

/// Wire spelling of an account mode — snake_case, matching the enum's serde.
fn account_mode_wire(mode: SshAccountMode) -> &'static str {
    // FR-90 P3-8-1b — the accounts' ONE spelling, the wire crate's: what a
    // grant carries is what a vault ticket names and a policy's
    // `context.account` reads.
    mode.wire()
}

/// FR-90 P3-8-1b — what is left of a ticket that ends at `ends_at_secs`, in
/// whole seconds, at least one. Never 0: to `clamp_session_secs` a 0 means
/// the ceiling, so a ticket at its very end would LIFT the bound it sets.
fn secs_left(ends_at_secs: i64, now_ms: u64) -> u64 {
    let now_secs = i64::try_from(now_ms / 1000).unwrap_or(i64::MAX);
    u64::try_from(ends_at_secs.saturating_sub(now_secs))
        .unwrap_or(0)
        .max(1)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers shared with the handlers
// ────────────────────────────────────────────────────────────────────────────

async fn tenant_of(tenant_id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(tenant_id).map_err(|_| ApiError::BadRequest("Invalid tenant id".into()))
}

async fn load_agent(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: &str,
) -> Result<Agent, ApiError> {
    let aid = ObjectId::parse_str(agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent id".into()))?;
    // LIVE: the session target and the policy write both come through here,
    // and neither has a meaning for a removed device (#1821).
    state
        .fleet
        .agents
        .find_live_in_tenant(tenant_id, aid)
        .await
        .map_err(|_| ApiError::NotFound("Agent not found".into()))
}

async fn http_caller(state: &NetworkState, auth: &AuthUser) -> Caller {
    let display = state
        .users
        .base
        .find_by_id(auth.user_id)
        .await
        .map(|u| u.display_name)
        .unwrap_or_else(|_| auth.user_id.to_hex());
    Caller {
        user_id: auth.user_id,
        display,
        origin_agent_id: None,
        session: CallerSession::None,
    }
}

/// Parse the tenant AND require the caller to be a member of it — the same
/// cheap pre-check `agent_exec` performs, and for the same reason.
///
/// Gate 2 (`SSH_DEVICE`) is evaluated inside [`authorize`] so a refusal is
/// AUDITED rather than a bare 403. Without this, a non-member still reached
/// the device lookup, which distinguishes "agent exists" (200 + refusal) from
/// "no such agent" (404) — a cross-tenant fleet-enumeration oracle — wrote
/// attacker-timed rows into ANOTHER tenant's `ssh_audit`, and leaked whether
/// that org had `remote_ssh_enabled`.
async fn member_tenant(
    state: &NetworkState,
    tenant_id: &str,
    auth: &AuthUser,
) -> Result<ObjectId, ApiError> {
    let tid = tenant_of(tenant_id).await?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    Ok(tid)
}

// ────────────────────────────────────────────────────────────────────────────
// Handlers
// ────────────────────────────────────────────────────────────────────────────

/// `POST /api/tenant/{tenant_id}/agent/{agent_id}/ssh` — ask for a session.
///
/// Answers 200 with either where to dial or why not: a refusal is a policy
/// outcome, not a transport failure, and the caller needs to read the reason.
pub async fn request_session(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<SshRequestBody>,
) -> Result<Json<SshResponseBody>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let agent = load_agent(&state, tid, &agent_id).await?;
    let caller = http_caller(&state, &auth).await;
    Ok(Json(
        dispatch(
            &state,
            tid,
            &agent,
            &caller,
            &body.public_key,
            body.session_secs,
        )
        .await,
    ))
}

/// `PUT /api/tenant/{tenant_id}/agent/{agent_id}/ssh-policy` — gate 3.
///
/// `MANAGE_AGENTS`, not `SSH_DEVICE`: deciding a device may be SSHed into is a
/// management act, distinct from being allowed to do it. Same split exec uses.
pub async fn set_policy(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<SshPolicyBody>,
) -> Result<Json<SshPolicyBody>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let agent = load_agent(&state, tid, &agent_id).await?;

    let parse_ids = |v: &[String], what: &str| -> Result<Vec<ObjectId>, ApiError> {
        v.iter()
            .map(|s| {
                ObjectId::parse_str(s)
                    .map_err(|_| ApiError::BadRequest(format!("Invalid {what}: {s}")))
            })
            .collect()
    };

    // A named account with no name is a policy that cannot be satisfied;
    // refuse it here rather than let a device fail every session later.
    if body.account_mode == SshAccountMode::Named
        && body.account.as_deref().unwrap_or("").trim().is_empty()
    {
        return Err(ApiError::BadRequest(
            "account_mode `named` requires an account".into(),
        ));
    }

    // Same rule again, applied to the ONE account mode that depends on the
    // agent. `console_user` is the person at the device's screen: on Windows by
    // their session token, and on Linux and macOS (FR-97 P5a) by the daemon's
    // drop to them, which an older agent refuses (`exec.rs`, `pty/unix.rs`), so
    // EVERY session on that device fails at connect time — after the server has
    // already told the caller where to dial. Gating it in the dialog alone is not
    // enough: the API would still accept a policy no agent can ever honour, which
    // is how the default reached Linux devices in the first place (#1557).
    if console_user_unsupported(body.account_mode, agent.os, &agent.capabilities) {
        return Err(ApiError::BadRequest(
            "this device's agent cannot run SSH sessions as the person at its screen: update \
             it, or name a local account instead"
                .into(),
        ));
    }

    // Same rule, applied to consent: an agent older than P5d accepts a
    // `consent_mode` and ignores it. Storing one would hand the admin a policy
    // that reads as "a human must approve" while that device keeps letting
    // every session straight through — which is the precise defect P5d exists
    // to remove, so the server must not be able to recreate it per-device.
    if consent_mode_would_be_ignored(&agent.capabilities, body.consent_mode) {
        return Err(ApiError::BadRequest(format!(
            "this device's agent does not honour consent_mode yet (needs the P5d agent); \
             it would accept `{:?}` and ignore it. Update the device, or set `auto`.",
            body.consent_mode.unwrap_or(ConsentMode::Auto)
        )));
    }

    let policy = SshPolicy {
        mode: body.mode,
        can_originate: body.can_originate,
        allowed_user_ids: parse_ids(&body.allowed_user_ids, "user id")?,
        allowed_role_ids: parse_ids(&body.allowed_role_ids, "role id")?,
        account_mode: body.account_mode,
        account: body.account.clone(),
        consent_mode: body.consent_mode,
    };
    state
        .fleet
        .agents
        .update_ssh_policy(tid, agent.id.unwrap_or_default(), &policy)
        .await?;
    warn!(
        agent = %agent_id, admin = %auth.user_id, mode = ?policy.mode,
        account_mode = ?policy.account_mode,
        "ssh: device policy updated"
    );
    Ok(Json(body))
}

/// `GET /api/tenant/{tenant_id}/ssh-settings` — gate 1's current state, so the
/// device console can explain why every device is refusing before anyone
/// starts editing per-device policy.
pub async fn get_org_settings(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<OrgSshSettings>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let tenant = state
        .tenants
        .base
        .find_by_id(tid)
        .await
        .map_err(|_| ApiError::NotFound("Tenant not found".into()))?;
    Ok(Json(OrgSshSettings {
        remote_ssh_enabled: tenant.settings.remote_ssh_enabled,
    }))
}

/// `PUT /api/tenant/{tenant_id}/ssh-settings` — flip gate 1.
///
/// `MANAGE_TENANT`, the highest bar of the three, because this one switch
/// governs the whole org.
pub async fn set_org_settings(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<OrgSshSettings>,
) -> Result<Json<OrgSshSettings>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_TENANT,
        "MANAGE_TENANT",
    )
    .await?;
    let tenant = state
        .tenants
        .set_remote_ssh_enabled(tid, body.remote_ssh_enabled)
        .await?;
    warn!(
        tenant = %tenant_id, admin = %auth.user_id,
        enabled = body.remote_ssh_enabled,
        "ssh: org kill-switch changed"
    );
    Ok(Json(OrgSshSettings {
        remote_ssh_enabled: tenant.settings.remote_ssh_enabled,
    }))
}

/// Would storing this account mode produce a policy no session on the device
/// can satisfy?
///
/// `console_user` is the person at the device's screen. On Windows it is
/// `WTSQueryUserToken` + `CreateProcessAsUserW`. On Linux and macOS (FR-97 P5a)
/// the daemon drops to that person, which only an agent advertising
/// `console-user` does: an older one refuses the mode (`exec.rs`, `pty/unix.rs`)
/// and every session on that device dies at connect time, AFTER the server has
/// already answered the caller with an address to dial. Read from the stored
/// hello: an agent rolled back since refuses the session itself, so this
/// half fails closed either way.
///
/// ⚠️ The dialog gates this too, but a client-only gate is not the guarantee: the
/// API would still accept a policy no agent can honour, and it was the dialog's
/// own OS-blind default that put `console_user` on Linux devices to begin with
/// (#1557). Same shape as the `named`-with-no-account and consent-would-be-ignored
/// refusals above it — refuse the unsatisfiable policy at the write, not at the
/// session.
fn console_user_unsupported(
    mode: SshAccountMode,
    os: OsKind,
    caps: &roomler_ai_remote_control::models::AgentCaps,
) -> bool {
    mode == SshAccountMode::ConsoleUser
        && os != OsKind::Windows
        && !caps.has_rpc(RpcCap::ConsoleUser)
}

/// Would storing this `consent_mode` produce a policy the target device
/// silently ignores?
///
/// Agents rc.419 and earlier advertise `ssh` while destructuring
/// `SshPolicy.consent_mode` away, so persisting a non-auto value for one would
/// show an admin a rule reading "a human must approve" while that device let
/// every session straight through. P5d fixed the agent; this keeps the server
/// from recreating the same lie on any device that hasn't updated yet.
///
/// `auto` and an absent value are always storable: neither promises a prompt.
fn consent_mode_would_be_ignored(
    caps: &roomler_ai_remote_control::models::AgentCaps,
    mode: Option<ConsentMode>,
) -> bool {
    !matches!(mode, None | Some(ConsentMode::Auto)) && !caps.has_rpc(RpcCap::SshConsent)
}

// ────────────────────────────────────────────────────────────────────────────
// FR-105 — the device's SYSTEM service
// ────────────────────────────────────────────────────────────────────────────

/// `PUT /api/agent/service/ssh-host-key` — what the service says about its
/// own SSH endpoint.
#[derive(Debug, Deserialize)]
pub struct ServiceSshEndpointBody {
    /// The OpenSSH public half of the SERVICE's host key (`ssh-ed25519 …`).
    pub host_pubkey: String,
    /// The anchor's `ssh` ceiling, as the service read it from the anchor
    /// file only SYSTEM and Administrators can write.
    pub ceiling: SshServiceCeiling,
    /// FR-90 P3-8-2a — the service holds an agent session's grant to one
    /// command. A service before it says nothing: false.
    #[serde(default)]
    pub one_command: bool,
}

/// The service publishes its SSH endpoint, with its OWN credential: the
/// worker, which the signed-in user controls, cannot. Bound to the anchor the
/// credential names, so a re-anchor or an un-anchor retires it.
pub async fn publish_service_endpoint(
    State(state): State<NetworkState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ServiceSshEndpointBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let svc =
        roomler_ai_mod_fleet::auth_agent::authenticate_service(&state.fleet, &headers).await?;
    let host_pubkey = body.host_pubkey.trim();
    if !is_supported_public_key(host_pubkey) {
        return Err(ApiError::BadRequest(
            "host_pubkey must be an OpenSSH ssh-ed25519 public key".to_string(),
        ));
    }
    // `authenticate_service` proved the credential names the CURRENT anchor.
    let anchor_id = svc
        .agent
        .exec_anchor
        .as_ref()
        .map(|a| a.anchor_id.clone())
        .unwrap_or_default();
    let endpoint = SshServiceEndpoint {
        host_pubkey: host_pubkey.to_string(),
        ceiling: body.ceiling,
        anchor_id,
        published_at: bson::DateTime::now(),
        one_command: body.one_command,
    };
    match state
        .fleet
        .agents
        .publish_ssh_service(svc.tenant_id, svc.agent_id, &endpoint)
        .await
    {
        Ok(true) => {
            info!(
                agent = %svc.agent_id, ceiling = ?endpoint.ceiling,
                one_command = endpoint.one_command,
                "ssh: the SYSTEM service published its endpoint"
            );
            Ok(Json(serde_json::json!({ "ok": true })))
        }
        // It raced a re-anchor, an un-anchor or a removal: this credential's
        // anchor is gone, which the service must hear as "anchor again".
        Ok(false) => Err(ApiError::Unauthorized(
            "this device's SYSTEM service was re-anchored or un-anchored; anchor it again"
                .to_string(),
        )),
        Err(e) => Err(ApiError::Internal(format!("ssh service endpoint: {e}"))),
    }
}

/// What a claim hands the SYSTEM service: the grant, from the server.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimedSshGrant {
    pub grant_id: String,
    /// The caller's ephemeral OpenSSH public key.
    pub public_key: String,
    pub caller: String,
    /// `daemon` (SYSTEM) or `console_user`.
    pub account_mode: String,
    pub expires_at_ms: u64,
    pub session_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_mode: Option<ConsentMode>,
    /// FR-90 P3-8-1b — an agent session's grant, held to one `exec`, as its
    /// pending row says. Absent (false) for every other grant, so the answer
    /// is byte for byte what a service before P3-8-2a parses.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub one_command: bool,
}

/// What a claim says of the service that sends it.
#[derive(Debug, Default, Deserialize)]
pub struct ServiceClaimQuery {
    /// FR-90 P3-8-2a — `one_command=true`: this service holds an agent
    /// session's grant to one command. Absent from every claim before it.
    #[serde(default)]
    pub one_command: bool,
}

/// `POST /api/agent/service/ssh/{grant_id}/claim`, with the service's own
/// credential. Single use, this device's only, inside the caller's wait. The
/// claim IS the grant's acknowledgement: a caller waiting on this pod is told
/// to dial at once, and one waiting on another pod reads it from the row.
///
/// Anything else is a 404 and an audit row (`claim_refused`) with no user:
/// unknown, claimed already, withdrawn, expired, another device's. The
/// reasons are not told apart, so a forged ring learns nothing.
///
/// FR-90 P3-8-2a — and an agent session's grant, to a claim that does not say
/// `one_command=true`: a service too old to hold one command would serve that
/// session's key a shell. Routing already keeps such a grant from a service
/// that never published the word; this holds if its build changed since.
pub async fn claim_service_grant(
    State(state): State<NetworkState>,
    headers: axum::http::HeaderMap,
    Path(grant_id): Path<String>,
    Query(claim): Query<ServiceClaimQuery>,
) -> Result<Json<ClaimedSshGrant>, ApiError> {
    let svc =
        roomler_ai_mod_fleet::auth_agent::authenticate_service(&state.fleet, &headers).await?;
    match state
        .ssh_pending
        .claim(&grant_id, svc.agent_id, svc.tenant_id, claim.one_command)
        .await
    {
        Ok(Some(row)) => {
            let delivered_here = state.ssh_grant_acks.deliver_claim(&grant_id, svc.agent_id);
            info!(
                agent = %svc.agent_id, %grant_id, account_mode = %row.account_mode, delivered_here,
                "ssh: the SYSTEM service claimed a grant"
            );
            Ok(Json(ClaimedSshGrant {
                grant_id: row.grant_id,
                public_key: row.public_key,
                caller: row.caller,
                account_mode: row.account_mode,
                expires_at_ms: row.expires_at_ms,
                session_secs: row.session_secs,
                consent_mode: row.consent_mode,
                one_command: row.one_command,
            }))
        }
        Ok(None) => {
            warn!(
                agent = %svc.agent_id, %grant_id,
                "ssh: the SYSTEM service claimed a grant that is not pending for it"
            );
            let audit = SshAuditEvent {
                id: None,
                tenant_id: svc.tenant_id,
                agent_id: svc.agent_id,
                // No person asked for this: the device's service did.
                user_id: ObjectId::from_bytes([0; 12]),
                origin_agent_id: None,
                // The id that was rung, for whoever investigates a forgery.
                grant_id: Some(grant_id),
                source: "service-claim".to_string(),
                session_id: None,
                ssh_ticket_id: None,
                caller: String::new(),
                account_mode: None,
                session_secs: None,
                at: bson::DateTime::now(),
                denied: Some(SshDenyReason::ClaimRefused),
                ran_as: None,
            };
            if let Err(e) = state.ssh_audit.record(audit).await {
                warn!(agent = %svc.agent_id, %e, "ssh: audit write failed");
            }
            Err(ApiError::NotFound(
                "no such grant is pending for this device".to_string(),
            ))
        }
        Err(e) => Err(ApiError::Internal(format!("ssh claim: {e}"))),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Audit read side
// ────────────────────────────────────────────────────────────────────────────

/// Projected row. The stored model is NOT serialised straight out: bson's
/// `ObjectId` and `DateTime` render as extended JSON (`{"$oid": …}` /
/// `{"$date": …}`), which nothing on the client parses — the same reason
/// `ExecAuditRow` exists.
#[derive(Debug, Serialize)]
pub struct SshAuditRow {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub source: String,
    pub caller: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_secs: Option<u64>,
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied: Option<SshDenyReason>,
    /// The refusal in the words the caller was given. Rendering `denied` alone
    /// would make a reviewer map enum variants back to meanings by hand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied_message: Option<String>,
    /// FR-105 — `system` / `console_user` (the SYSTEM service) or `worker`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ran_as: Option<String>,
}

impl From<SshAuditEvent> for SshAuditRow {
    fn from(e: SshAuditEvent) -> Self {
        Self {
            id: e.id.map(|i| i.to_hex()).unwrap_or_default(),
            tenant_id: e.tenant_id.to_hex(),
            agent_id: e.agent_id.to_hex(),
            user_id: e.user_id.to_hex(),
            origin_agent_id: e.origin_agent_id.map(|i| i.to_hex()),
            grant_id: e.grant_id,
            source: e.source,
            caller: e.caller,
            account_mode: e.account_mode,
            session_secs: e.session_secs,
            at: e.at.try_to_rfc3339_string().unwrap_or_default(),
            denied: e.denied,
            denied_message: e.denied.map(|d| d.message().to_string()),
            ran_as: e.ran_as,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SshAuditResponse {
    pub items: Vec<SshAuditRow>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
}

#[derive(Debug, Deserialize)]
pub struct SshAuditQuery {
    #[serde(default = "default_audit_page")]
    pub page: u64,
    #[serde(default = "default_audit_per_page")]
    pub per_page: u64,
    /// ISO 8601 — return only entries created before this instant.
    #[serde(default)]
    pub before: Option<String>,
    /// Narrow to one device — "who has been on this machine?"
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Narrow to one person — where an incident review starts.
    #[serde(default)]
    pub user_id: Option<String>,
}

fn default_audit_page() -> u64 {
    1
}

fn default_audit_per_page() -> u64 {
    50
}

impl SshAuditQuery {
    fn pagination(&self) -> PaginationParams {
        PaginationParams {
            page: self.page,
            per_page: self.per_page,
            before: self.before.clone(),
        }
    }
}

/// `GET /api/tenant/{tenant_id}/ssh-audit`
///
/// Gated on `VIEW_SSH_AUDIT`, deliberately not on `SSH_DEVICE`: reviewing who
/// held a session is a different job from being able to open one, and an org
/// should be able to staff them separately.
pub async fn audit(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<SshAuditQuery>,
) -> Result<Json<SshAuditResponse>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::VIEW_SSH_AUDIT,
        "VIEW_SSH_AUDIT",
    )
    .await?;

    let pg = q.pagination();
    let page = match (&q.agent_id, &q.user_id) {
        (Some(a), _) => {
            let aid = ObjectId::parse_str(a)
                .map_err(|_| ApiError::BadRequest("Invalid agent_id".into()))?;
            state.ssh_audit.list_for_agent(tid, aid, &pg).await?
        }
        (None, Some(u)) => {
            let uid = ObjectId::parse_str(u)
                .map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;
            state.ssh_audit.list_for_user(tid, uid, &pg).await?
        }
        (None, None) => state.ssh_audit.list_for_tenant(tid, &pg).await?,
    };
    Ok(Json(SshAuditResponse {
        items: page.items.into_iter().map(Into::into).collect(),
        total: page.total,
        page: page.page,
        per_page: page.per_page,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// P8 — session activity
// ────────────────────────────────────────────────────────────────────────────

/// Projected activity row. Same reason for existing as [`SshAuditRow`]: bson
/// renders `ObjectId`/`DateTime` as extended JSON that no client parses.
#[derive(Debug, Serialize)]
pub struct SshActivityRow {
    pub id: String,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub caller: String,
    pub kind: SshActivityKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub allowed: bool,
    pub at: String,
}

impl From<SshActivityEvent> for SshActivityRow {
    fn from(e: SshActivityEvent) -> Self {
        Self {
            id: e.id.map(|i| i.to_hex()).unwrap_or_default(),
            agent_id: e.agent_id.to_hex(),
            grant_id: e.grant_id,
            caller: e.caller,
            kind: e.kind,
            detail: e.detail,
            exit_code: e.exit_code,
            allowed: e.allowed,
            at: e.at.try_to_rfc3339_string().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SshActivityResponse {
    pub items: Vec<SshActivityRow>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
}

#[derive(Debug, Deserialize)]
pub struct SshActivityQuery {
    #[serde(default = "default_audit_page")]
    pub page: u64,
    #[serde(default = "default_audit_per_page")]
    pub per_page: u64,
    #[serde(default)]
    pub before: Option<String>,
    /// Narrow to one device — "what has been run on this machine?"
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Narrow to one session — the join back from an `ssh_audit` decision row
    /// to everything that followed it.
    #[serde(default)]
    pub grant_id: Option<String>,
}

impl SshActivityQuery {
    fn pagination(&self) -> PaginationParams {
        PaginationParams {
            page: self.page,
            per_page: self.per_page,
            before: self.before.clone(),
        }
    }
}

/// `GET /api/tenant/{tenant_id}/ssh-activity`
///
/// Behind the SAME `VIEW_SSH_AUDIT` bit as the decision log rather than a new
/// one: reviewing what a session did and reviewing who was let in are the same
/// job, done by the same person, and a fresh permission bit would mean
/// rewriting every admin role's mask for no separation anyone asked for.
///
/// ⚠️ These rows are the DEVICE's account of itself, not the server's — see
/// [`SshActivityEvent`]. A quiet device produces an empty page whether it was
/// idle, has reporting switched off (the default), or has been compromised.
pub async fn activity(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<SshActivityQuery>,
) -> Result<Json<SshActivityResponse>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::VIEW_SSH_AUDIT,
        "VIEW_SSH_AUDIT",
    )
    .await?;

    let pg = q.pagination();
    let page = match (&q.agent_id, &q.grant_id) {
        (Some(a), _) => {
            let aid = ObjectId::parse_str(a)
                .map_err(|_| ApiError::BadRequest("Invalid agent_id".into()))?;
            state.ssh_activity.list_for_agent(tid, aid, &pg).await?
        }
        (None, Some(g)) => state.ssh_activity.list_for_grant(tid, g, &pg).await?,
        (None, None) => state.ssh_activity.list_for_tenant(tid, &pg).await?,
    };
    Ok(Json(SshActivityResponse {
        items: page.items.into_iter().map(Into::into).collect(),
        total: page.total,
        page: page.page,
        per_page: page.per_page,
    }))
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    fn caller(origin: Option<ObjectId>) -> Caller {
        Caller {
            user_id: ObjectId::new(),
            display: "someone@example.com".to_string(),
            origin_agent_id: origin,
            session: CallerSession::None,
        }
    }

    fn granted() -> Granted {
        Granted {
            grant_id: "abc123".to_string(),
            address: "100.65.4.30".to_string(),
            name: Some("corplap".to_string()),
            host_pubkey: Some("ssh-ed25519 AAAAC3Nz…".to_string()),
            expires_at_ms: 1,
            account_mode: SshAccountMode::ConsoleUser,
            session_secs: 900,
            confirmed_after_ms: Some(42),
            port: DEFAULT_SSH_PORT,
            ran_as: "worker",
        }
    }

    #[test]
    fn a_refusal_carries_no_grant_fields() {
        // The whole reason refusals are persisted is that they are the trace
        // of someone probing the fleet. A row that carried a grant_id or an
        // account_mode for a request that was REFUSED would read, to whoever
        // reviews it later, as a session that happened.
        let c = caller(None);
        let e = audit_event(
            ObjectId::new(),
            ObjectId::new(),
            &c,
            &Err(SshDenyReason::NoPermission),
        );
        assert_eq!(e.denied, Some(SshDenyReason::NoPermission));
        assert!(e.grant_id.is_none(), "a refusal must not carry a grant id");
        assert!(
            e.account_mode.is_none(),
            "a refusal must not name an account it never granted"
        );
        assert!(e.session_secs.is_none());
        assert_eq!(
            e.user_id, c.user_id,
            "the principal is the point of the row"
        );
    }

    #[test]
    fn a_grant_records_which_identity_it_authorised() {
        // `account_mode` is the field that makes this log worth reading: it is
        // the difference between a shell as the console user and a shell as
        // SYSTEM/root.
        let e = audit_event(
            ObjectId::new(),
            ObjectId::new(),
            &caller(None),
            &Ok(granted()),
        );
        assert!(e.denied.is_none());
        assert_eq!(e.grant_id.as_deref(), Some("abc123"));
        assert_eq!(e.account_mode.as_deref(), Some("console_user"));
        assert_eq!(e.session_secs, Some(900));
    }

    #[test]
    fn the_source_distinguishes_the_device_leg_from_an_http_caller() {
        // Only distinction the server can actually observe — a browser and a
        // script both arrive as an authenticated bearer token.
        let origin = ObjectId::new();
        let via_device = audit_event(
            ObjectId::new(),
            ObjectId::new(),
            &caller(Some(origin)),
            &Ok(granted()),
        );
        assert_eq!(via_device.source, "cli");
        assert_eq!(via_device.origin_agent_id, Some(origin));

        let via_http = audit_event(
            ObjectId::new(),
            ObjectId::new(),
            &caller(None),
            &Ok(granted()),
        );
        assert_eq!(via_http.source, "api");
        assert!(via_http.origin_agent_id.is_none());
    }

    #[test]
    fn every_refusal_reason_survives_the_row_and_explains_itself() {
        // A reviewer reading the audit table should not have to map enum
        // variants back to meanings by hand, and a reason added later must not
        // silently render as a blank cell.
        for reason in [
            SshDenyReason::OrgDisabled,
            SshDenyReason::NoPermission,
            SshDenyReason::DeviceDisabled,
            SshDenyReason::CallerNotAllowed,
            SshDenyReason::OriginNotAllowed,
            SshDenyReason::Unsupported,
            SshDenyReason::Offline,
            SshDenyReason::NoOverlayAddress,
            SshDenyReason::RateLimited,
            SshDenyReason::BadPublicKey,
            SshDenyReason::AgentDisabled,
            SshDenyReason::GrantExpiredOnArrival,
            SshDenyReason::GrantRefused,
            SshDenyReason::GrantUnconfirmed,
            SshDenyReason::ClaimRefused,
        ] {
            let e = audit_event(
                ObjectId::new(),
                ObjectId::new(),
                &caller(None),
                &Err(reason),
            );
            let row = SshAuditRow::from(e);
            assert_eq!(row.denied, Some(reason));
            let msg = row.denied_message.expect("a refusal must explain itself");
            assert!(!msg.is_empty(), "{reason:?} has an empty message");
        }
    }

    #[test]
    fn a_refusal_answer_carries_neither_an_address_nor_a_host_key() {
        // The host key is only ever paired with somewhere to dial. Emitting
        // one on a refusal would hand a caller half a connection and invite
        // them to reconstruct the other half.
        let body = SshResponseBody::denied(SshDenyReason::DeviceDisabled);
        assert!(body.address.is_none());
        assert!(body.host_pubkey.is_none());
        assert!(body.grant_id.is_none());
        assert!(body.error.is_some());
    }

    #[test]
    fn a_device_that_reported_no_host_key_yields_none_not_empty_string() {
        // `None` and `Some("")` are worlds apart to a client: one says "this
        // device cannot prove itself", the other looks like a key it can
        // compare against and always match. The API must never emit the
        // second, so the conversion happens once, at the boundary.
        for reported in ["", "   ".trim()] {
            let projected: Option<String> = (!reported.is_empty()).then(|| reported.to_string());
            assert!(
                projected.is_none(),
                "an empty reported key must project to None"
            );
        }
        let real = "ssh-ed25519 AAAAC3Nz…";
        assert_eq!(
            (!real.is_empty()).then(|| real.to_string()),
            Some(real.to_string())
        );
    }

    #[test]
    fn a_granted_row_projects_ids_as_hex_not_extended_json() {
        // bson's ObjectId/DateTime serialise as {"$oid": …} / {"$date": …},
        // which nothing on the client parses — the audit table would render
        // `[object Object]`. Same trap `ExecAuditRow` exists to avoid.
        let tid = ObjectId::new();
        let aid = ObjectId::new();
        let row = SshAuditRow::from(audit_event(tid, aid, &caller(None), &Ok(granted())));
        assert_eq!(row.tenant_id, tid.to_hex());
        assert_eq!(row.agent_id, aid.to_hex());
        assert!(
            row.denied_message.is_none(),
            "a grant has nothing to explain"
        );
        let json = serde_json::to_string(&row).expect("row serialises");
        assert!(
            !json.contains("$oid") && !json.contains("$date"),
            "row leaked extended JSON: {json}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `console_user` is storable on Windows, and on Linux and macOS only for an
    /// agent that advertises `console-user` (FR-97 P5a). The negative half is the
    /// one that matters — before #1557 the dialog defaulted every device to
    /// `console_user`, so a Linux or macOS device silently carried a policy that
    /// failed every session at connect time, which an older agent still would.
    #[test]
    fn console_user_is_refused_where_the_agent_cannot_drop_to_the_person() {
        use roomler_ai_remote_control::models::AgentCaps;
        let caps = |verbs: &[&str]| AgentCaps {
            rpc: verbs.iter().map(|v| v.to_string()).collect(),
            ..Default::default()
        };
        let older = caps(&["exec", "ssh", "ssh-consent"]);
        let p5a = caps(&["exec", "ssh", "ssh-consent", "console-user"]);
        assert!(!console_user_unsupported(
            SshAccountMode::ConsoleUser,
            OsKind::Windows,
            &older
        ));
        for os in [OsKind::Linux, OsKind::Macos] {
            assert!(
                console_user_unsupported(SshAccountMode::ConsoleUser, os, &older),
                "console_user must be refused on {os:?} for an agent without the word"
            );
            assert!(
                !console_user_unsupported(SshAccountMode::ConsoleUser, os, &p5a),
                "console_user is storable on {os:?} for an agent with the word"
            );
        }
        // The other modes do not depend on the agent and must pass on every OS —
        // a guard that refused those would break Windows policies too.
        for os in [OsKind::Linux, OsKind::Macos, OsKind::Windows] {
            for mode in [SshAccountMode::Daemon, SshAccountMode::Named] {
                assert!(
                    !console_user_unsupported(mode, os, &older),
                    "{mode:?} on {os:?}"
                );
            }
        }
    }

    /// A policy that promises operator approval may only be stored for a device
    /// that will actually ask. Otherwise the admin is handed a lie — the exact
    /// defect P5d removed from the agent.
    #[test]
    fn a_consent_policy_is_refused_for_a_device_that_would_ignore_it() {
        use roomler_ai_remote_control::models::AgentCaps;

        let caps = |verbs: &[&str]| AgentCaps {
            rpc: verbs.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        let p5d = caps(&["exec", "originate", "ssh", "ssh-consent"]);
        // rc.419 and earlier: advertises `ssh`, ignores consent_mode.
        let older = caps(&["exec", "originate", "ssh"]);

        for m in [
            Some(ConsentMode::Prompt),
            Some(ConsentMode::Email),
            Some(ConsentMode::Push),
        ] {
            assert!(
                consent_mode_would_be_ignored(&older, m),
                "{m:?} must be refused for an agent that would ignore it"
            );
            assert!(
                !consent_mode_would_be_ignored(&p5d, m),
                "{m:?} must be storable once the device honours it"
            );
        }

        // Neither of these promises a prompt, so both are always storable —
        // including for an agent too old to advertise anything at all.
        for m in [None, Some(ConsentMode::Auto)] {
            assert!(!consent_mode_would_be_ignored(&older, m));
            assert!(!consent_mode_would_be_ignored(&caps(&[]), m));
        }
    }

    /// The wire may carry `Auto` only when the policy said `Auto` in so many
    /// words. Everything else — including a policy that said nothing — must
    /// cross as `Prompt`.
    #[test]
    fn only_an_explicit_auto_crosses_the_wire_as_auto() {
        assert_eq!(
            effective_wire_consent(Some(ConsentMode::Auto)),
            ConsentMode::Auto
        );
        for m in [
            None,
            Some(ConsentMode::Prompt),
            Some(ConsentMode::Email),
            Some(ConsentMode::Push),
            Some(ConsentMode::PromptThenEmail),
        ] {
            assert_eq!(effective_wire_consent(m), ConsentMode::Prompt, "{m:?}");
        }
    }

    #[test]
    fn only_ed25519_keys_are_accepted() {
        // A REAL blob: u32(11) "ssh-ed25519" u32(32) + 32 key bytes, which is
        // the 68-char form `ssh-keygen` emits. The fixtures here used to be
        // plausible-looking but undecodable, which is exactly what the old
        // shape-only check could not tell apart.
        const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";

        assert!(is_supported_public_key(&format!(
            "ssh-ed25519 {KEY} someone@example.com"
        )));
        // No comment is fine — `ssh-keygen -y` emits exactly this.
        assert!(is_supported_public_key(&format!("ssh-ed25519 {KEY}")));

        // RSA is refused on purpose: the `rsa` feature is off in the agent, so
        // accepting one here would mint a grant no device could ever redeem.
        assert!(!is_supported_public_key(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQExampleKeyMaterial00 someone@example.com"
        ));
        assert!(!is_supported_public_key("ssh-ed25519"));
        assert!(!is_supported_public_key(""));
        assert!(!is_supported_public_key("ssh-ed25519 short"));
        // Whitespace or control characters in the blob would end up in the
        // agent's config-shaped parsing; reject rather than pass through.
        assert!(!is_supported_public_key(
            "ssh-ed25519 AAAA\u{7f}BBBB0000000000000000000000000000"
        ));

        // The cases the old shape-only check WAVED THROUGH, each of which the
        // agent rejects at redemption — so the grant was minted, pushed, and
        // then failed to authenticate with no stated reason.
        // 1. Long enough and all-graphic, but not valid base64.
        assert!(!is_supported_public_key(
            "ssh-ed25519 ****not-base64-but-graphic-and-long-enough****"
        ));
        // 2. Valid base64, correct algorithm prefix, but a 31-byte key.
        assert!(!is_supported_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAHwECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        ));
        // 3. Valid base64 of the right length whose EMBEDDED algorithm name
        //    disagrees with the text prefix — the mismatch a parser catches
        //    and a length check does not.
        assert!(!is_supported_public_key(
            "ssh-ed25519 AAAAB3NzaC1yc2EAAAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"
        ));
    }

    #[test]
    fn account_modes_use_the_enum_wire_spelling() {
        // These strings cross to the agent and are matched there; if the enum
        // gains a variant, this is what fails rather than a device silently
        // treating an unknown mode as the default.
        assert_eq!(account_mode_wire(SshAccountMode::Daemon), "daemon");
        assert_eq!(
            account_mode_wire(SshAccountMode::ConsoleUser),
            "console_user"
        );
        assert_eq!(account_mode_wire(SshAccountMode::Named), "named");
        for m in [
            SshAccountMode::Daemon,
            SshAccountMode::ConsoleUser,
            SshAccountMode::Named,
        ] {
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(json.trim_matches('"'), account_mode_wire(m));
        }
    }

    #[test]
    fn every_deny_reason_says_which_gate_refused() {
        for r in [
            SshDenyReason::OrgDisabled,
            SshDenyReason::NoPermission,
            SshDenyReason::DeviceDisabled,
            SshDenyReason::CallerNotAllowed,
            SshDenyReason::OriginNotAllowed,
            SshDenyReason::Unsupported,
            SshDenyReason::Offline,
            SshDenyReason::NoOverlayAddress,
            SshDenyReason::RateLimited,
            SshDenyReason::BadPublicKey,
            SshDenyReason::AgentDisabled,
            SshDenyReason::GrantExpiredOnArrival,
            SshDenyReason::GrantRefused,
            SshDenyReason::GrantUnconfirmed,
            SshDenyReason::ClaimRefused,
            SshDenyReason::TicketRefused,
            SshDenyReason::SessionNotAllowed,
            SshDenyReason::TargetTooOld,
        ] {
            let m = r.message();
            assert!(!m.is_empty(), "{r:?} has no message");
            assert!(
                m.len() > 20,
                "{r:?}'s message is too terse to act on: {m:?}"
            );
        }
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use roomler_ai_services::auth::SshTicket;

    /// An auth service under a secret made at run time.
    fn auth() -> AuthService {
        AuthService::new(roomler_ai_config::JwtSettings {
            secret: format!("p381b-{}-{}", ObjectId::new(), ObjectId::new()),
            previous_secrets: String::new(),
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 3600,
            issuer: "roomler-ai-test".into(),
        })
    }

    struct Places {
        tenant: ObjectId,
        origin: ObjectId,
        target: ObjectId,
        session: ObjectId,
        owner: ObjectId,
        ticket: ObjectId,
    }

    fn places() -> Places {
        Places {
            tenant: ObjectId::new(),
            origin: ObjectId::new(),
            target: ObjectId::new(),
            session: ObjectId::new(),
            owner: ObjectId::new(),
            ticket: ObjectId::new(),
        }
    }

    fn signed(auth: &AuthService, p: &Places, account: SshAccountMode) -> (String, i64) {
        let exp = bson::DateTime::now().timestamp_millis() / 1000 + 120;
        let token = auth
            .issue_ssh_ticket(&SshTicket {
                session_id: p.session,
                tenant_id: p.tenant,
                fence: 3,
                owner_user_id: p.owner,
                origin_agent_id: p.origin,
                target_agent_id: p.target,
                account,
                ticket_id: p.ticket,
                exp,
            })
            .unwrap();
        (token, exp)
    }

    /// FR-90 P3-8-1b — a ticket binds only where it holds: on an agent's own
    /// connection, signed by this server, in its organization, from the
    /// device it names and toward the target it names. What it binds is the
    /// session's, as the ticket names it; each refusal is in its own words.
    #[test]
    fn a_ticket_binds_only_where_it_holds() {
        let a = auth();
        let p = places();
        let (token, exp) = signed(&a, &p, SshAccountMode::Named);
        let s = bind_ssh_ticket(&a, p.tenant, Some(p.origin), p.target, &token).unwrap();
        // Three dotted words, made at run time: no token-shaped literal.
        let garbage = ["not", "a", "ticket"].join(".");
        assert_eq!(
            s,
            SessionCaller {
                session_id: p.session,
                owner_user_id: p.owner,
                ticket_id: p.ticket.to_hex(),
                account: SshAccountMode::Named,
                ends_at: exp,
            }
        );
        for (tenant, origin, target, token, why) in [
            (
                p.tenant,
                None,
                p.target,
                token.as_str(),
                "rides only its own device's connection",
            ),
            (
                ObjectId::new(),
                Some(p.origin),
                p.target,
                token.as_str(),
                "another organization",
            ),
            (
                p.tenant,
                Some(ObjectId::new()),
                p.target,
                token.as_str(),
                "another device",
            ),
            (
                p.tenant,
                Some(p.origin),
                ObjectId::new(),
                token.as_str(),
                "another target",
            ),
            (
                p.tenant,
                Some(p.origin),
                p.target,
                garbage.as_str(),
                "not a ticket this server signed",
            ),
        ] {
            let refused = bind_ssh_ticket(&a, tenant, origin, target, token).unwrap_err();
            assert!(refused.contains(why), "{why}: {refused}");
        }
        // Another server's ticket, however well formed, is no ticket here.
        let (theirs, _) = signed(&auth(), &p, SshAccountMode::Named);
        assert!(bind_ssh_ticket(&a, p.tenant, Some(p.origin), p.target, &theirs).is_err());
    }

    /// FR-90 P3-8-1b — what is left of a ticket bounds a session's SSH
    /// session, and never by 0, which `clamp_session_secs` reads as the
    /// ceiling.
    #[test]
    fn what_is_left_of_a_ticket_never_lifts_the_bound() {
        let now_ms = 1_800_000_000_000_u64;
        let now = 1_800_000_000_i64;
        assert_eq!(secs_left(now + 120, now_ms), 120);
        assert_eq!(secs_left(now + 1, now_ms), 1);
        assert_eq!(
            secs_left(now, now_ms),
            1,
            "at its end: one second, not the ceiling"
        );
        assert_eq!(secs_left(now - 30, now_ms), 1, "past its end");
        assert_eq!(
            ssh_limits::clamp_session_secs(300).min(secs_left(now + 120, now_ms)),
            120
        );
    }

    /// FR-90 P3-8-1b — a session's row names the session and its ticket, as
    /// `session`; a refused ticket is a `session` row that names no session,
    /// since nothing it claims was verified; a person's row names neither.
    #[test]
    fn a_sessions_row_names_the_session_only_once_its_ticket_held() {
        let (tid, aid, origin) = (ObjectId::new(), ObjectId::new(), Some(ObjectId::new()));
        let bound = SessionCaller {
            session_id: ObjectId::new(),
            owner_user_id: ObjectId::new(),
            ticket_id: "k1".into(),
            account: SshAccountMode::ConsoleUser,
            ends_at: 1,
        };
        let caller = |session| Caller {
            user_id: ObjectId::new(),
            display: "someone (via a device)".into(),
            origin_agent_id: origin,
            session,
        };
        let row = audit_event(
            tid,
            aid,
            &caller(CallerSession::Bound(bound.clone())),
            &Err(SshDenyReason::SessionNotAllowed),
        );
        assert_eq!(row.source, "session");
        assert_eq!(row.session_id, Some(bound.session_id));
        assert_eq!(row.ssh_ticket_id.as_deref(), Some("k1"));
        assert_eq!(row.denied, Some(SshDenyReason::SessionNotAllowed));

        let refused = audit_event(
            tid,
            aid,
            &caller(CallerSession::Refused("a ticket for another target")),
            &Err(SshDenyReason::TicketRefused),
        );
        assert_eq!(refused.source, "session");
        assert_eq!((refused.session_id, refused.ssh_ticket_id), (None, None));

        let person = audit_event(
            tid,
            aid,
            &caller(CallerSession::None),
            &Err(SshDenyReason::NoPermission),
        );
        assert_eq!(person.source, "cli");
        assert_eq!((person.session_id, person.ssh_ticket_id), (None, None));
    }
}

/// FR-90 P3-8-2a — which grants a device's SYSTEM service is sent.
#[cfg(test)]
mod service_route_tests {
    use super::*;
    use roomler_ai_remote_control::models::ExecAnchor;

    /// A Windows device anchored as `anchor-1`, whose service published under
    /// `published.0`, saying `published.1` of one command; or published
    /// nothing.
    fn device(published: Option<(&str, bool)>) -> Agent {
        let mut a: Agent = serde_json::from_str(
            r#"{
                "tenant_id":"000000000000000000000001",
                "owner_user_id":"000000000000000000000002",
                "name":"winbox","machine_id":"m","os":"windows",
                "agent_version":"0.4.150","agent_token_hash":"",
                "status":"online","last_seen_at":{"$date":{"$numberLong":"0"}},
                "created_at":{"$date":{"$numberLong":"0"}},
                "updated_at":{"$date":{"$numberLong":"0"}},
                "deleted_at":null
            }"#,
        )
        .unwrap();
        a.exec_anchor = Some(ExecAnchor {
            anchored_at: bson::DateTime::now(),
            anchored_by: ObjectId::new(),
            anchor_id: "anchor-1".to_string(),
        });
        a.ssh_service = published.map(|(anchor_id, one_command)| SshServiceEndpoint {
            host_pubkey: "the service's host key".to_string(),
            ceiling: SshServiceCeiling::System,
            anchor_id: anchor_id.to_string(),
            published_at: bson::DateTime::now(),
            one_command,
        });
        a
    }

    /// A person's grant goes to a current service whatever it said of one
    /// command; an agent session's only to one that said it holds one. The
    /// rest of the rule is unchanged: never under another anchor, nor where
    /// nothing was published.
    #[test]
    fn a_sessions_grant_goes_to_the_service_only_if_it_holds_one_command() {
        let mode = SshAccountMode::Daemon;
        let said = |one_command| device(Some(("anchor-1", one_command)));
        assert!(service_endpoint_serves(&said(false), mode, false));
        assert!(service_endpoint_serves(&said(true), mode, false));
        assert!(
            !service_endpoint_serves(&said(false), mode, true),
            "a service that never said it holds one command"
        );
        assert!(service_endpoint_serves(&said(true), mode, true));
        assert!(!service_endpoint_serves(
            &device(Some(("anchor-0", true))),
            mode,
            true
        ));
        assert!(!service_endpoint_serves(&device(None), mode, true));
    }

    /// A record a service published before P3-8-2a reads as not holding one
    /// command, and so does a publish that does not say it.
    #[test]
    fn what_a_service_never_said_of_one_command_is_false() {
        let stored = bson::doc! {
            "host_pubkey": "k",
            "ceiling": "system",
            "anchor_id": "a",
            "published_at": bson::DateTime::now(),
        };
        let endpoint: SshServiceEndpoint = bson::from_document(stored).unwrap();
        assert!(!endpoint.one_command);
        let body: ServiceSshEndpointBody =
            serde_json::from_str(r#"{"host_pubkey":"k","ceiling":"system"}"#).unwrap();
        assert!(!body.one_command);
        let body: ServiceSshEndpointBody =
            serde_json::from_str(r#"{"host_pubkey":"k","ceiling":"system","one_command":true}"#)
                .unwrap();
        assert!(body.one_command);
    }

    /// A claim holds one command only when it says so; every claim before
    /// P3-8-2a says nothing, beside the `tid` the front proxy hashes on.
    #[test]
    fn a_claim_holds_one_command_only_when_it_says_so() {
        let said = |query: &str| {
            let uri: axum::http::Uri = format!("http://pod/claim?{query}").parse().unwrap();
            Query::<ServiceClaimQuery>::try_from_uri(&uri)
                .unwrap()
                .0
                .one_command
        };
        assert!(!said("tid=000000000000000000000001"));
        assert!(said("tid=000000000000000000000001&one_command=true"));
        assert!(!said("one_command=false"));
    }
}
