// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Multi-org — add an ALREADY-ENROLLED device to a second organization from
//! the admin UI, without touching the machine.
//!
//! Field 2026-08-05: the multi-org fleet test could not finish on WINHOST-A (a
//! corp-managed Windows box) purely because every path to a second enrollment
//! ran through a shell on the device. This is that path, remote:
//!
//! ```text
//!  admin (UI, org A)                server                        agent
//!    │  POST …/agent/{id}/join-org    │                             │
//!    │  { target_tenant_id }          │                             │
//!    │ ──────────────────────────────>│ authz A: MANAGE_AGENTS      │
//!    │                                │ authz B: MANAGE_AGENTS      │
//!    │                                │ mint enrollment token (B)   │
//!    │                                │ ── rc:agent.join_org ──────>│
//!    │ <──────────────────────────────│                             │ enroll → [[orgs]] → supervise
//! ```
//!
//! The authorization is the whole design: **the caller must hold
//! MANAGE_AGENTS in BOTH organizations**. Holding it only in the target would
//! let anyone pull a stranger's device into their org; holding it only in the
//! source would let a device's admin push it into an org that never asked for
//! it. Requiring both means the person clicking already administers both
//! sides — the same authority they'd have doing it by hand at the keyboard.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::signaling::ServerMsg;
use meshharbor_services::quota;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};

use crate::FleetState;

/// Enrollment-token lifetime for a pushed join. Deliberately shorter than the
/// interactive `ENROLLMENT_TTL_SECS` (10 min): nobody has to copy this one
/// into a terminal, so it only has to survive the WS hop.
const JOIN_TOKEN_TTL_SECS: u64 = 120;

#[derive(Debug, Deserialize)]
pub struct JoinOrgRequest {
    /// The organization to add the device to.
    pub target_tenant_id: String,
    /// Label for the agent's new `[[orgs]]` entry. Defaults to the target
    /// org's slug, which is what an operator would have typed.
    #[serde(default)]
    pub label: Option<String>,
    /// Overlay participation in the new org: `off` (default) | `netstack` |
    /// `tun`. `tun` also needs the daemon's `overlay_multi_org` opt-in.
    #[serde(default)]
    pub overlay_mode: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JoinOrgResponse {
    pub agent_id: String,
    pub target_tenant_id: String,
    pub label: String,
    /// The push reached a live agent socket (this pod, or another one via the
    /// ctrl lane). `false` never happens today — an offline agent is rejected
    /// upfront — but the field is honest about what was actually delivered.
    pub delivered: bool,
    /// Set when the device already had an enrollment in the target org: the
    /// push still went out (it refreshes the token in place), so this is
    /// informational, not an error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_enrolled: Option<bool>,
    /// Set when a `tun` join lands on a daemon whose TUN is not muxed yet:
    /// the enrollment takes effect immediately, but the org's MESH waits for
    /// the next daemon start. See [`needs_restart_for_tun`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_required: Option<bool>,
}

/// Does a `tun` join on this device have to wait for a daemon restart?
///
/// The agent advertises `multi_org: ["join", "tun"]` once its TUN is muxed;
/// a daemon that started single-org advertises only `join`. Asking such a
/// daemon for a `tun` join is legal and does the right thing — it writes the
/// config and enables the opt-in — but the mesh cannot come up until the
/// process restarts, because the primary org's loop already holds the
/// adapter's (single-session-only) Wintun handle.
///
/// Field 2026-08-07, WINHOST-A: without this, the click reported plain success
/// while the device logged `WintunStartSession failed "Failed to register
/// rings"` on every reconnect. The join was fine; the promise wasn't.
pub fn needs_restart_for_tun(overlay_mode: Option<&str>, caps_multi_org: &[String]) -> bool {
    let wants_tun = overlay_mode.map(str::trim).map(str::to_ascii_lowercase) == Some("tun".into());
    wants_tun && !caps_multi_org.iter().any(|c| c == "tun")
}

/// POST /api/tenant/{tenant_id}/agent/{agent_id}/join-org
pub async fn join_org(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<JoinOrgRequest>,
) -> Result<Json<JoinOrgResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;
    let target = ObjectId::parse_str(&body.target_tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid target_tenant_id".to_string()))?;

    if target == tid {
        return Err(ApiError::BadRequest(
            "The device is already in this organization".to_string(),
        ));
    }

    // BOTH sides. See the module header for why neither alone is enough.
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    require_permission(
        &state,
        target,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    // The device must be OURS (tenant-scoped lookup) — an agent id alone
    // must never address a device in someone else's org — and LIVE: a join
    // token minted for a removed device would be an invitation nothing can
    // consume (#1821).
    let agent = state
        .agents
        .find_live_in_tenant(tid, aid)
        .await
        .map_err(|_| ApiError::NotFound("Device not found in this organization".into()))?;

    // Capability gate: an agent that predates `rc:agent.join_org` drops the
    // unknown variant in its decoder's debug branch, so pushing to one would
    // report success and do nothing. Refuse with the actionable message
    // instead — and never mint a token that cannot be consumed.
    if !agent.capabilities.multi_org.iter().any(|c| c == "join") {
        return Err(ApiError::BadRequest(format!(
            "{} runs agent {} which predates remote org-join. Update the device \
             (or enroll it at the keyboard with `roomler enroll --label …`).",
            agent.name,
            if agent.agent_version.is_empty() {
                "(unknown version)"
            } else {
                &agent.agent_version
            }
        )));
    }

    // The push rides the device's live socket, so it has to have one.
    // Deliberately checked before minting: no token exists unless it can be
    // delivered.
    let online = matches!(
        agent.status,
        meshharbor_remote_control::models::AgentStatus::Online
    );
    if !online {
        return Err(ApiError::BadRequest(format!(
            "{} is offline. It must be connected to join another organization.",
            agent.name
        )));
    }

    // The enroll route would refuse an archived target anyway, but there
    // the failure lands in a daemon log nobody is watching; here it is the
    // click's answer — and no token gets minted for a join that cannot work.
    if state
        .tenants
        .base
        .find_by_id(target)
        .await
        .map(|t| t.is_archived)
        .unwrap_or(false)
    {
        return Err(ApiError::BadRequest(
            "The target organization is archived and accepts no device enrollments".to_string(),
        ));
    }

    // Already enrolled? Not an error — the agent refreshes that org's entry
    // in place — but the response says so, and the UI can be honest.
    let already = state
        .agents
        .find_by_tenant_and_machine(target, &agent.machine_id)
        .await
        .ok()
        .flatten()
        .map(|a| a.deleted_at.is_none())
        .unwrap_or(false);

    // Device-cap pre-flight on the TARGET org. The agent's own enroll POST
    // would hit this anyway, but there the failure lands in a daemon log
    // nobody is watching; here it becomes the click's answer. (Field
    // 2026-08-05: a Free-plan cap silently stopped a join.)
    if !already {
        let tenant = state.tenants.base.find_by_id(target).await?;
        let used = state.agents.count_active_for_tenant(target).await?;
        // FR-32: the decision and its record live in `quota::check`; the
        // wording stays here because it is contextual ("in the target
        // organization"). `MaxDevices` is an established limit, so this
        // refuses regardless of the tenant's `plan_enforcement` mode.
        // FR-102 P4 — through core, which also counts the collision per org.
        if let Err(d) = meshharbor_core::quota::check(&state, &tenant, quota::Limit::MaxDevices, used)
        {
            return Err(ApiError::Forbidden(format!(
                "Device limit reached for the {:?} plan in the target organization \
                 ({} of {} devices used). Upgrade the plan or remove a device first.",
                d.plan, d.used, d.max
            )));
        }
    }

    let label = match &body.label {
        Some(l) if !l.trim().is_empty() => l.trim().to_string(),
        _ => state
            .tenants
            .base
            .find_by_id(target)
            .await
            .map(|t| t.slug)
            .unwrap_or_else(|_| "org".to_string()),
    };

    // Mint against the TARGET tenant, attributed to the acting admin — the
    // agent row it creates is owned by them, exactly as a hand enrollment
    // would be.
    let (token, _jti) =
        state
            .auth
            .issue_enrollment_token(auth.user_id, target, JOIN_TOKEN_TTL_SECS)?;

    let msg = ServerMsg::JoinOrg {
        enrollment_token: token.clone(),
        label: Some(label.clone()),
        overlay_mode: body.overlay_mode.clone(),
    };

    // Local first; the ctrl lane covers an agent homed on another pod. The
    // envelope carries a live (single-use, 2-minute) token over the internal
    // Redis bus, and every pod applies it — hence the tenant re-check inside
    // `send_to_agent_in_tenant`, so a mismatched envelope can't hand another
    // tenant's device a token for an org it was never meant to join.
    let delivered = if state.rc_hub.send_to_agent_in_tenant(aid, tid, msg).is_ok() {
        true
    } else {
        crate::ctrl::publish_rc_ctrl(
            &state,
            "agent_join_org",
            serde_json::json!({
                "agent_id": aid.to_hex(),
                "tenant_id": tid.to_hex(),
                "enrollment_token": token,
                "label": label,
                "overlay_mode": body.overlay_mode,
            }),
        )
        .await;
        // The owning pod applies asynchronously; we can't observe it from
        // here. Report the dispatch, not a delivery we didn't witness.
        false
    };

    let restart_required =
        needs_restart_for_tun(body.overlay_mode.as_deref(), &agent.capabilities.multi_org);

    info!(
        admin = %auth.user_id, agent = %aid, source = %tid, target = %target,
        %label, delivered, already_enrolled = already, restart_required,
        "cross-org device join pushed"
    );
    if !delivered {
        warn!(agent = %aid, "join-org: agent not on this pod; dispatched over the ctrl lane");
    }

    Ok(Json(JoinOrgResponse {
        agent_id: aid.to_hex(),
        target_tenant_id: target.to_hex(),
        label,
        delivered,
        already_enrolled: already.then_some(true),
        restart_required: restart_required.then_some(true),
    }))
}

/// GET /api/tenant/{tenant_id}/agent/{agent_id}/join-targets — the orgs this
/// caller could add the device to: every tenant where they hold
/// MANAGE_AGENTS, minus the device's current org, each flagged with whether
/// the device is already there.
///
/// The UI needs this to render a picker that can't produce a 403.
pub async fn join_targets(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    // LIVE: the picker offers what a join will work for, and a removed device
    // joins nothing.
    let agent = state
        .agents
        .find_live_in_tenant(tid, aid)
        .await
        .map_err(|_| ApiError::NotFound("Device not found in this organization".into()))?;

    let mut items = Vec::new();
    for membership in state.tenants.find_user_tenants(auth.user_id).await? {
        let Some(other) = membership.id else { continue };
        if other == tid {
            continue;
        }
        // An archived org takes no devices (`routes::tenant::archive`), so
        // it never appears in the picker.
        if membership.is_archived {
            continue;
        }
        // Silently skip orgs where this caller can't manage devices — the
        // picker only ever offers what will actually work.
        if require_permission(
            &state,
            other,
            auth.user_id,
            permissions::MANAGE_AGENTS,
            "MANAGE_AGENTS",
        )
        .await
        .is_err()
        {
            continue;
        }
        let already = state
            .agents
            .find_by_tenant_and_machine(other, &agent.machine_id)
            .await
            .ok()
            .flatten()
            .map(|a| a.deleted_at.is_none())
            .unwrap_or(false);
        items.push(serde_json::json!({
            "tenant_id": other.to_hex(),
            "name": membership.name,
            "slug": membership.slug,
            "already_enrolled": already,
        }));
    }

    Ok(Json(serde_json::json!({
        "items": items,
        // The UI greys out the action (with this reason) rather than letting
        // the click fail.
        "supported": agent.capabilities.multi_org.iter().any(|c| c == "join"),
        // Can a `tun` join reach the mesh WITHOUT a daemon restart? The
        // dialog says so before the click rather than after it.
        "mesh_ready": agent.capabilities.multi_org.iter().any(|c| c == "tun"),
        "online": matches!(
            agent.status,
            meshharbor_remote_control::models::AgentStatus::Online
        ),
    })))
}

#[cfg(test)]
mod tests {
    use super::needs_restart_for_tun;

    fn caps(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn only_a_tun_join_onto_an_unmuxed_daemon_needs_a_restart() {
        let single = caps(&["join"]);
        let muxed = caps(&["join", "tun"]);

        // The case that burned WINHOST-A: tun asked of a single-org daemon.
        assert!(needs_restart_for_tun(Some("tun"), &single));
        assert!(
            needs_restart_for_tun(Some(" TUN "), &single),
            "trimmed + case-folded like the agent's own parse"
        );

        // Already muxed — the join is live.
        assert!(!needs_restart_for_tun(Some("tun"), &muxed));

        // Non-mesh joins never touch the adapter.
        for mode in [None, Some("off"), Some("netstack")] {
            assert!(!needs_restart_for_tun(mode, &single), "mode={mode:?}");
        }

        // A pre-multi-org agent can't be asked for `tun` at all (the
        // capability gate rejects it earlier), but if it were, the honest
        // answer is still "restart".
        assert!(needs_restart_for_tun(Some("tun"), &[]));
    }
}
