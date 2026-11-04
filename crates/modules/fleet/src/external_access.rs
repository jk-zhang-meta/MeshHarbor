// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-52 cross-org remote access — the ADMIN surface, in the FLEET module
//! (`docs/fr/FR-52-cross-org-remote-access.md`): the org kill-switch (gate 1),
//! per-device approval (gate 2), the connect code an outsider names a device
//! by (§5), and the decision log.
//!
//! FR-69 put it here rather than in `remote`: this is device MANAGEMENT —
//! an org switch, a per-device policy on the `agents` row, a handle on that
//! row and a decision log — the exact shape of `agent_exec`, which is this
//! crate's. What a CONTROLLER reaches is `remote`'s, and that is where FR-52's
//! session half (the external branch of the `rc:*` authz gate) belongs when
//! P4 lands. Splitting it that way mirrors exec and SSH.
//!
//! **P1 ships no access path.** Nothing here lets anyone in: the session
//! handshake (gates 3–5) lands in P3/P4, and until it does the only thing a
//! connect code resolves to is a device that refuses. What P1 establishes is
//! the policy surface, and — from the first commit — the audit, because a
//! refusal nobody can query is a refusal nobody will notice.
//!
//! ## Permissions — and why there is no `EXTERNAL_ACCESS` bit
//!
//! There is none to take. The UI mirror checks masks with JavaScript's signed
//! 32-bit bitwise ops and `VIEW_SSH_AUDIT` (`1 << 30`) is the ceiling by design
//! (`role.rs`, #888). Approval therefore rides `MANAGE_AGENTS` **and**
//! `REMOTE_CONTROL`: you may open a device to an outsider only if you could
//! control it yourself, which is a coherence rule rather than a stand-in.
//!
//! ⚠️ **This is not the FR-19 shape, and it is weaker.** FR-19 pairs
//! `MANAGE_AGENTS` with `EXEC_DEVICE`, which `DEFAULT_ADMIN` deliberately does
//! NOT carry, so it is a real extra grant. `DEFAULT_ADMIN` **does** carry
//! `REMOTE_CONTROL`, so this pair is no hurdle at all for the seeded `admin`
//! role — it bites only on a custom role built with `MANAGE_AGENTS` and not
//! `REMOTE_CONTROL`. Saying otherwise would overstate the control, so: the
//! hurdle for cross-org access is deliberately NOT here. It is the org switch
//! above it (`MANAGE_TENANT`), the device's own opt-in, and the password the
//! device holds and this server never sees. Gate 2 is an org-side VETO, not
//! the security boundary.
//!
//! Borrowing `EXEC_DEVICE` for this would be defensible — an `EXEC_DEVICE`
//! holder can already `meshharbor exec` its way to setting the device password as
//! root — but it would exclude the natural approver, a fleet admin who holds
//! no root-command grant, in exchange for a hurdle the design does not lean
//! on. A dedicated bit waits on the BigInt migration; FR-52 open decision 5.
//!
//! Clearing an approval needs only `MANAGE_AGENTS`: revocation is not a grant,
//! and the person who can open a door must not be the only one who can shut it.
//!
//! The org switch is `MANAGE_TENANT`, like `exec-settings` and `peer-relay`:
//! whether this org can be reached from outside at all is an org-owner
//! decision, not a fleet-admin one. Reading the settings is `MANAGE_AGENTS`,
//! like every other device-fleet view.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::{
    connect_code,
    models::{
        Agent, AgentStatus, ExternalAccessPolicy, ExternalRcAuditAction, ExternalRcAuditEvent,
        ExternalRcDenyReason, RpcCap,
    },
    permissions::Permissions,
};
use meshharbor_services::dao::base::PaginationParams;
use serde::{Deserialize, Serialize};
use tracing::warn;

use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};

use crate::FleetState;
use crate::agent::fmt_dt;

/// How many times to retry a connect-code mint on a unique-index collision.
///
/// A collision is a 60-bit birthday hit, i.e. it will not happen — the retry
/// exists so that if it somehow does, an admin sees a new code instead of an
/// unexplained 500. Three, because a loop that retries forever on what is
/// actually a bug (a duplicate index on the wrong field, say) is worse than a
/// clean failure.
const CODE_MINT_ATTEMPTS: usize = 3;

// ────────────────────────────────────────────────────────────────────────────
// The approval decision
// ────────────────────────────────────────────────────────────────────────────

/// The whole approval policy as one pure function, so it is testable without a
/// database and every refusal has exactly one place to come from — the shape of
/// `peer_relay::decide_approval`.
///
/// Three rules, each load-bearing:
///
/// 1. Touching device policy at all requires `MANAGE_AGENTS`.
/// 2. ADDING an approval additionally requires `REMOTE_CONTROL`. Re-stating an
///    approval that already stands is not a grant, and neither is clearing one
///    — #600's `check_grant` gates only the bits being ADDED, and the same rule
///    applies here.
/// 3. A device whose agent does not advertise [`RpcCap::ExternalAccess`] cannot
///    be approved. That gate is here, at approval time, rather than only at
///    session time on purpose: such an agent shows the person at the machine
///    the ordinary "someone wants to control this" panel with no hint that the
///    someone is a stranger, so approving it would put a promise on screen that
///    the device does not keep — and consent given under it would not be
///    informed consent.
///
/// ⚠️ Rule 3 is checked against what the device said on its LAST hello, which
/// is all the server ever knows. An offline device that previously advertised
/// the verb is approvable; one that never did is not.
pub fn decide_approval(
    caller_permissions: u64,
    device_supports_external: bool,
    current: &ExternalAccessPolicy,
    requested: &ExternalAccessPolicy,
) -> Result<(), ExternalRcDenyReason> {
    if !permissions::has(caller_permissions, permissions::MANAGE_AGENTS) {
        return Err(ExternalRcDenyReason::NotDeviceAdmin);
    }
    let is_new_grant = requested.approved && !current.approved;
    if is_new_grant && !permissions::has(caller_permissions, permissions::REMOTE_CONTROL) {
        return Err(ExternalRcDenyReason::CannotGrantExternal);
    }
    // Only a grant is blocked by an unsupported device. Clearing one must
    // always work — otherwise a device that downgraded to an older agent could
    // never have its approval taken away.
    if requested.approved && !device_supports_external {
        return Err(ExternalRcDenyReason::DeviceUnsupported);
    }
    Ok(())
}

fn tenant_of(tenant_id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))
}

fn agent_of(agent_id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(agent_id).map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))
}

// ────────────────────────────────────────────────────────────────────────────
// Views
// ────────────────────────────────────────────────────────────────────────────

/// One approved device, as the settings view lists it.
#[derive(Debug, Serialize)]
pub struct ExternalDeviceView {
    pub id: String,
    pub name: String,
    pub status: AgentStatus,
    /// The handle to hand out, in display form (`XXXX-XXXX-XXXX`). `None` when
    /// no code has been minted — an approved device with no code is not
    /// reachable, and that is the most common "why can they not connect?"
    /// answer, so it is on screen rather than inferred.
    pub connect_code: Option<String>,
    /// RFC3339, never a raw `bson::DateTime` — see [`crate::routes::remote_control::fmt_dt`].
    pub connect_code_rotated_at: Option<String>,
    /// The effective ceiling, always resolved — never the raw `Option`. A UI
    /// that rendered "unset" would be showing the admin nothing about what an
    /// outsider may actually do.
    pub max_permissions: String,
    pub expires_at: Option<String>,
    /// Gate 3 as the device last advertised it: whether its agent even
    /// understands cross-org access. An approved device on an old agent is
    /// approved and unreachable, and the grid must be able to say so.
    pub supported: bool,
}

impl From<Agent> for ExternalDeviceView {
    fn from(a: Agent) -> Self {
        let supported = a.capabilities.has_rpc(RpcCap::ExternalAccess);
        let (_, spec) = a.external_access_policy.clone().split();
        Self {
            id: a.id.map(|i| i.to_hex()).unwrap_or_default(),
            name: a.name,
            status: a.status,
            connect_code: a.connect_code.as_deref().map(connect_code::format_grouped),
            connect_code_rotated_at: a.connect_code_rotated_at.map(fmt_dt),
            max_permissions: spec.ceiling().wire_names(),
            expires_at: a.external_access_policy.expires_at.map(fmt_dt),
            supported,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ExternalAccessSettings {
    /// Gate 1. While this is false nothing else in this payload can admit
    /// anyone, and the UI says so rather than showing a list that looks live.
    pub enabled: bool,
    /// Devices approved under gate 2, whether or not they are reachable.
    pub devices: Vec<ExternalDeviceView>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalAccessEnabledBody {
    pub enabled: bool,
}

/// What an admin may set on a device.
///
/// Deliberately NOT the raw [`ExternalAccessPolicy`], on two counts:
///
/// * `max_permissions` crosses as the pipe-separated name form the rest of the
///   `rc:*` surface uses, so a client cannot post a numeric bitfield whose
///   meaning drifts with the flag order; and
/// * ⚠️ `expires_at` crosses as an **RFC3339 string**, not a `bson::DateTime`.
///   A `bson::DateTime` accepts only the extended-JSON `{"$date": …}` shape, so
///   a body carrying what `Date.toISOString()` produces — which is exactly what
///   the dialog's `datetime-local` picker yields — fails to deserialize. The
///   symptom is a 4xx on an optional field with nothing on screen to explain
///   it. Caught by a unit test before it shipped; the outbound half of the same
///   trap (`{"$date": …}` is TRUTHY, so a client presence check passes and the
///   display renders `[object Object]`) is why every view here uses
///   [`fmt_dt`] too.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalAccessPolicyBody {
    pub approved: bool,
    /// `"VIEW | INPUT"`, or absent for the built-in ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_permissions: Option<Permissions>,
    /// RFC3339, e.g. `"2026-09-05T10:00:00Z"`. Absent = stands until cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl ExternalAccessPolicyBody {
    /// Parse into the stored shape, or say which field was wrong.
    ///
    /// A `Result` rather than a lossy `Option`: an unparseable instant that
    /// silently became "no expiry" would store a PERMANENT approval where the
    /// admin asked for a temporary one — the failure direction that matters.
    fn to_policy(&self) -> Result<ExternalAccessPolicy, ApiError> {
        let expires_at = match &self.expires_at {
            None => None,
            Some(s) => Some(DateTime::parse_rfc3339_str(s).map_err(|_| {
                ApiError::BadRequest(format!(
                    "expires_at must be an RFC3339 instant (e.g. 2026-09-05T10:00:00Z), got {s:?}"
                ))
            })?),
        };
        Ok(ExternalAccessPolicy {
            approved: self.approved,
            max_permissions: self.max_permissions,
            expires_at,
        })
    }
}

/// The reverse, for `AgentResponse::external_access_policy`.
///
/// ⚠️ This direction is not cosmetic. The dialog PUTs the whole shape, so a
/// dialog that cannot read the stored policy opens on its closed default and
/// the next save REPLACES the real one — silently dropping a narrowed ceiling
/// or an expiry, which widens an outsider's access rather than narrowing it.
/// Same reasoning as `AgentResponse::exec_policy`, and the same
/// `configured_only` treatment on the way out.
impl From<ExternalAccessPolicy> for ExternalAccessPolicyBody {
    fn from(p: ExternalAccessPolicy) -> Self {
        Self {
            approved: p.approved,
            max_permissions: p.max_permissions,
            // Out as the same RFC3339 string it came in as, so the value the
            // dialog reads back is one it can put straight into the next PUT.
            expires_at: p.expires_at.map(fmt_dt),
        }
    }
}

/// One audit row as the API returns it.
///
/// Exists for one reason: [`ExternalRcAuditEvent`] is a `models::*` struct that
/// owns two `bson::DateTime`s, and returning it straight from a handler
/// serialises them as `{"$date":{"$numberLong":…}}`. That object is TRUTHY, so
/// a client presence check passes and the value renders as `[object Object]`
/// — a failure that can survive several releases before anyone formats it.
#[derive(Debug, Serialize)]
pub struct ExternalRcAuditView {
    pub id: Option<String>,
    pub action: ExternalRcAuditAction,
    pub agent_id: String,
    pub user_id: String,
    pub actor: String,
    pub approved: Option<bool>,
    pub max_permissions: Option<String>,
    pub expires_at: Option<String>,
    pub at: String,
    pub denied: Option<ExternalRcDenyReason>,
    /// FR-52 P3 — `login` rows. Carried explicitly: this view is a hand-built
    /// shape, so a field added to the event does not reach the API until it is
    /// named here — and a login row without its outcome would read as a
    /// verified login to anyone scanning the log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_refused: Option<meshharbor_remote_control::models::ExtauthRefusal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_detail: Option<String>,
    /// FR-52 P4 — `session` rows: the session an admitted login opened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl From<ExternalRcAuditEvent> for ExternalRcAuditView {
    fn from(e: ExternalRcAuditEvent) -> Self {
        // Destructured, not field-accessed, so a field added to the event is a
        // compile error HERE instead of silently missing from every audit read.
        let ExternalRcAuditEvent {
            id,
            tenant_id: _,
            action,
            agent_id,
            user_id,
            actor,
            approved,
            max_permissions,
            expires_at,
            at,
            denied,
            attempt_id,
            login_refused,
            login_detail,
            session_id,
        } = e;
        Self {
            id: id.map(|i| i.to_hex()),
            action,
            agent_id: agent_id.to_hex(),
            user_id: user_id.to_hex(),
            actor,
            approved,
            max_permissions,
            expires_at: expires_at.map(fmt_dt),
            at: fmt_dt(at),
            denied,
            attempt_id,
            login_refused,
            login_detail,
            session_id: session_id.map(|s| s.to_hex()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ConnectCodeResponse {
    /// Display form, `XXXX-XXXX-XXXX`.
    pub connect_code: String,
    pub rotated_at: DateTime,
}

// ────────────────────────────────────────────────────────────────────────────
// Org switch (gate 1)
// ────────────────────────────────────────────────────────────────────────────

/// `GET /api/tenant/{tenant_id}/external-access`
pub async fn get_settings(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<ExternalAccessSettings>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let enabled = state
        .tenants
        .base
        .find_by_id(tid)
        .await?
        .settings
        .external_rc_enabled;
    let devices = state
        .agents
        .list_external_approved(tid)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(Json(ExternalAccessSettings { enabled, devices }))
}

/// `PUT /api/tenant/{tenant_id}/external-access` — gate 1.
///
/// `MANAGE_TENANT`, not `MANAGE_AGENTS`: this decides whether the org can be
/// reached from outside at all.
pub async fn set_enabled(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<ExternalAccessEnabledBody>,
) -> Result<Json<ExternalAccessEnabledBody>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_TENANT,
        "MANAGE_TENANT",
    )
    .await?;
    state
        .tenants
        .base
        .update_by_id(
            tid,
            bson::doc! { "$set": { "settings.external_rc_enabled": body.enabled } },
        )
        .await?;
    // WARN rather than INFO: this is the switch that decides whether strangers
    // can reach this org's machines, and it should be visible in a log an
    // operator skims.
    warn!(
        tenant = %tenant_id, admin = %auth.user_id, enabled = body.enabled,
        "external access: org switch changed"
    );
    Ok(Json(body))
}

// ────────────────────────────────────────────────────────────────────────────
// Per-device approval (gate 2)
// ────────────────────────────────────────────────────────────────────────────

/// `PUT /api/tenant/{tenant_id}/agent/{agent_id}/external-access-policy`
pub async fn set_policy(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<ExternalAccessPolicyBody>,
) -> Result<Json<ExternalAccessPolicyBody>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    let aid = agent_of(&agent_id)?;

    // Membership first: `get_member_permissions` is the membership check too,
    // so a non-member never reaches the policy below.
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;

    // Tenant-scoped, so an agent id from another org is a 404 rather than a
    // cross-tenant read.
    let agent = state.agents.base.find_by_id_in_tenant(tid, aid).await?;

    // Parsed BEFORE the decision, so a malformed instant is a 400 about the
    // field rather than a policy refusal — and so it never leaves a
    // granted-looking audit row behind.
    let requested = body.to_policy()?;
    // An expiry already in the past is a refusal, not a policy: it would store
    // an approval that is closed the instant it is written, which reads on the
    // grid as "approved" and behaves as "denied".
    if let Some(exp) = requested.expires_at
        && exp <= DateTime::now()
    {
        return Err(ApiError::BadRequest(
            "the approval expiry is already in the past".to_string(),
        ));
    }
    let supported = agent.capabilities.has_rpc(RpcCap::ExternalAccess);
    let verdict = decide_approval(perms, supported, &agent.external_access_policy, &requested);

    let (_, spec) = requested.clone().split();
    let event = ExternalRcAuditEvent {
        id: None,
        tenant_id: tid,
        action: ExternalRcAuditAction::Approve,
        agent_id: aid,
        user_id: auth.user_id,
        actor: auth.username.clone(),
        approved: Some(requested.approved),
        // The RESOLVED ceiling, not the raw option: a row saying nothing about
        // what an outsider could do is a row nobody can review.
        max_permissions: Some(spec.ceiling().wire_names()),
        expires_at: requested.expires_at,
        at: DateTime::now(),
        denied: verdict.err(),
        attempt_id: None,
        login_refused: None,
        login_detail: None,
        session_id: None,
    };
    if let Err(e) = state.external_rc_audit.record(event).await {
        // Best-effort, like the other decision logs: an audit insert must
        // never be what stops a legitimate change.
        warn!(%e, "external access: audit write failed");
    }
    if let Err(reason) = verdict {
        return Err(ApiError::Forbidden(reason.message().to_string()));
    }

    state
        .agents
        .update_external_access_policy(tid, aid, &requested)
        .await?;
    warn!(
        tenant = %tenant_id, agent = %agent_id, admin = %auth.user_id,
        approved = requested.approved, ceiling = %spec.ceiling().wire_names(),
        "external access: device approval changed"
    );
    Ok(Json(body))
}

// ────────────────────────────────────────────────────────────────────────────
// Connect code (§5)
// ────────────────────────────────────────────────────────────────────────────

/// `POST /api/tenant/{tenant_id}/agent/{agent_id}/connect-code` — mint or
/// rotate.
///
/// One route for both, because they are the same act: rotation IS the
/// revocation story for a leaked code, and a separate "revoke" that left the
/// device with no code would only mean it has to be minted again before anyone
/// can connect.
///
/// `MANAGE_AGENTS` alone. A code is not a credential — gate 4, the device-held
/// password, is what stops a stranger — and rotating one only ever *narrows*
/// who can reach the device, so it does not carry the `REMOTE_CONTROL`
/// requirement that granting an approval does.
pub async fn rotate_connect_code(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Result<Json<ConnectCodeResponse>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    let aid = agent_of(&agent_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    // Tenant-scoped: a foreign agent id 404s rather than getting a code.
    state.agents.base.find_by_id_in_tenant(tid, aid).await?;

    let mut last_err = None;
    for _ in 0..CODE_MINT_ATTEMPTS {
        let code = connect_code::generate().ok_or_else(|| {
            // The system RNG refused. There is no weaker source to fall back
            // to — an unaddressable device is the safe outcome.
            ApiError::Internal("could not generate a connect code".to_string())
        })?;
        match state.agents.set_connect_code(tid, aid, &code).await {
            Ok(_) => {
                warn!(
                    tenant = %tenant_id, agent = %agent_id, admin = %auth.user_id,
                    "external access: connect code rotated"
                );
                let event = ExternalRcAuditEvent {
                    id: None,
                    tenant_id: tid,
                    action: ExternalRcAuditAction::RotateCode,
                    agent_id: aid,
                    user_id: auth.user_id,
                    actor: auth.username.clone(),
                    // A rotation says nothing about the approval — the two are
                    // independent acts and the row must not imply otherwise.
                    approved: None,
                    max_permissions: None,
                    expires_at: None,
                    at: DateTime::now(),
                    denied: None,
                    attempt_id: None,
                    login_refused: None,
                    login_detail: None,
                    session_id: None,
                };
                if let Err(e) = state.external_rc_audit.record(event).await {
                    warn!(%e, "external access: audit write failed");
                }
                // ⚠️ The code is returned ONCE per rotation in display form.
                // It is readable again from `get_settings`, which is behind
                // `MANAGE_AGENTS` — deliberately not from the ordinary device
                // list, which needs only tenant membership.
                return Ok(Json(ConnectCodeResponse {
                    connect_code: connect_code::format_grouped(&code),
                    rotated_at: DateTime::now(),
                }));
            }
            Err(e) => last_err = Some(e),
        }
    }
    // Every attempt collided. At 60 bits this is not a birthday hit; it is a
    // broken index or a broken RNG, and it should read as an error rather than
    // as a device that mysteriously has no code.
    warn!(
        tenant = %tenant_id, agent = %agent_id, ?last_err,
        "external access: connect code mint failed after {CODE_MINT_ATTEMPTS} attempts"
    );
    Err(ApiError::Internal(
        "could not assign a connect code; please retry".to_string(),
    ))
}

// ────────────────────────────────────────────────────────────────────────────
// Audit
// ────────────────────────────────────────────────────────────────────────────

/// `GET /api/tenant/{tenant_id}/external-rc-audit`
///
/// Behind `VIEW_REMOTE_AUDIT` rather than `MANAGE_AGENTS`: reviewing who
/// opened the fleet to outsiders is a different job from doing it, the same
/// split `VIEW_SSH_AUDIT` makes against `SSH_DEVICE`.
pub async fn audit(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::VIEW_REMOTE_AUDIT,
        "VIEW_REMOTE_AUDIT",
    )
    .await?;
    let page = state
        .external_rc_audit
        .list_for_tenant(tid, &params)
        .await?;
    let items: Vec<ExternalRcAuditView> = page.items.into_iter().map(Into::into).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": page.total,
        "page": page.page,
        "per_page": page.per_page,
        "total_pages": page.total_pages,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMIN: u64 = permissions::MANAGE_AGENTS | permissions::REMOTE_CONTROL;

    fn approved() -> ExternalAccessPolicy {
        ExternalAccessPolicy {
            approved: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_full_admin_may_grant_on_a_supported_device() {
        assert_eq!(
            decide_approval(ADMIN, true, &ExternalAccessPolicy::default(), &approved()),
            Ok(())
        );
    }

    #[test]
    fn without_manage_agents_nothing_is_permitted() {
        // Not even clearing: `MANAGE_AGENTS` is the right to touch device
        // policy at all.
        for requested in [ExternalAccessPolicy::default(), approved()] {
            assert_eq!(
                decide_approval(permissions::REMOTE_CONTROL, true, &approved(), &requested),
                Err(ExternalRcDenyReason::NotDeviceAdmin)
            );
        }
    }

    /// The compound gate: `MANAGE_AGENTS` alone cannot ADD an approval.
    #[test]
    fn granting_needs_remote_control_too() {
        assert_eq!(
            decide_approval(
                permissions::MANAGE_AGENTS,
                true,
                &ExternalAccessPolicy::default(),
                &approved()
            ),
            Err(ExternalRcDenyReason::CannotGrantExternal)
        );
    }

    /// Revocation is not a grant — the person who can open a door must not be
    /// the only one who can shut it.
    #[test]
    fn clearing_needs_only_manage_agents() {
        assert_eq!(
            decide_approval(
                permissions::MANAGE_AGENTS,
                true,
                &approved(),
                &ExternalAccessPolicy::default()
            ),
            Ok(())
        );
    }

    /// Re-stating an approval that already stands adds no bits, so it is not a
    /// grant either (#600's `check_grant` rule).
    #[test]
    fn restating_a_standing_approval_is_not_a_grant() {
        assert_eq!(
            decide_approval(permissions::MANAGE_AGENTS, true, &approved(), &approved()),
            Ok(())
        );
    }

    /// Narrowing the ceiling on a standing approval is not a grant either —
    /// it is the opposite of one.
    #[test]
    fn narrowing_the_ceiling_is_not_a_grant() {
        let narrowed = ExternalAccessPolicy {
            approved: true,
            max_permissions: Some(Permissions::VIEW),
            ..Default::default()
        };
        assert_eq!(
            decide_approval(permissions::MANAGE_AGENTS, true, &approved(), &narrowed),
            Ok(())
        );
    }

    /// A device whose agent cannot say "this controller is from outside your
    /// organization" must not be approvable — otherwise the consent prompt
    /// makes a promise the device does not keep.
    #[test]
    fn an_unsupported_device_cannot_be_approved() {
        assert_eq!(
            decide_approval(ADMIN, false, &ExternalAccessPolicy::default(), &approved()),
            Err(ExternalRcDenyReason::DeviceUnsupported)
        );
    }

    /// ...but it can always be UN-approved. A device that downgraded to an
    /// older agent would otherwise be stuck approved forever.
    #[test]
    fn an_unsupported_device_can_still_be_cleared() {
        assert_eq!(
            decide_approval(
                permissions::MANAGE_AGENTS,
                false,
                &approved(),
                &ExternalAccessPolicy::default()
            ),
            Ok(())
        );
    }

    /// ⚠️ The honest statement of what the compound gate is worth: the seeded
    /// `admin` role carries BOTH bits, so it is no hurdle for a default admin
    /// — unlike FR-19's `MANAGE_AGENTS + EXEC_DEVICE`, where the second bit is
    /// deliberately absent from `DEFAULT_ADMIN`.
    ///
    /// Asserted rather than left implicit, because the module doc makes this
    /// claim and a claim about a permission model that nothing checks is how
    /// the SSH policy's `consent_mode` came to be silently dropped. If a future
    /// change removes `REMOTE_CONTROL` from `DEFAULT_ADMIN`, this test turns
    /// red and the doc gets revisited with it.
    #[test]
    fn the_compound_gate_does_not_restrict_a_default_admin() {
        assert!(permissions::has(
            permissions::DEFAULT_ADMIN,
            permissions::MANAGE_AGENTS
        ));
        assert!(permissions::has(
            permissions::DEFAULT_ADMIN,
            permissions::REMOTE_CONTROL
        ));
        assert_eq!(
            decide_approval(
                permissions::DEFAULT_ADMIN,
                true,
                &ExternalAccessPolicy::default(),
                &approved()
            ),
            Ok(()),
            "a default admin may approve — the hurdle is the org switch, the \
             device's own opt-in and the device-held password, not this"
        );
    }

    /// ⚠️ The body must accept exactly what the dialog sends.
    ///
    /// `<input type="datetime-local">` → `new Date(v).toISOString()` → a plain
    /// `"2026-09-05T10:00:00.000Z"`. Typing this field as `bson::DateTime`
    /// (the obvious move, since that is what gets stored) rejects that string
    /// and answers 4xx on an OPTIONAL field, with nothing on screen to explain
    /// it. This test is why the body carries a `String`.
    #[test]
    fn the_body_accepts_the_iso_instant_a_browser_actually_sends() {
        let body: ExternalAccessPolicyBody =
            serde_json::from_str(r#"{"approved":true,"expires_at":"2026-09-05T10:00:00.000Z"}"#)
                .expect("the dialog's own output must deserialize");
        let policy = body.to_policy().expect("and must parse");
        assert!(policy.approved);
        assert_eq!(
            policy.expires_at.unwrap().timestamp_millis(),
            1_788_602_400_000,
        );
    }

    /// An unparseable instant is an ERROR, never a silent `None`. `None` means
    /// "no expiry", so swallowing the parse failure would store a PERMANENT
    /// approval where the admin asked for a temporary one — the one direction
    /// this must not fail in.
    #[test]
    fn an_unparseable_expiry_is_refused_rather_than_dropped() {
        let body = ExternalAccessPolicyBody {
            approved: true,
            max_permissions: None,
            expires_at: Some("next tuesday".into()),
        };
        let err = body.to_policy().expect_err("must not become 'no expiry'");
        assert!(
            matches!(err, ApiError::BadRequest(ref m) if m.contains("RFC3339")),
            "the refusal must name the format, got {err:?}"
        );
    }

    /// An absent expiry is the standing-approval case and must stay absent.
    #[test]
    fn an_absent_expiry_stays_absent() {
        let body = ExternalAccessPolicyBody {
            approved: true,
            max_permissions: None,
            expires_at: None,
        };
        assert_eq!(body.to_policy().unwrap().expires_at, None);
    }

    /// The round trip a dialog depends on: what it reads back must be something
    /// it can put straight into the next PUT.
    #[test]
    fn the_policy_round_trips_through_the_body_shape() {
        let stored = ExternalAccessPolicy {
            approved: true,
            max_permissions: Some(Permissions::VIEW),
            expires_at: Some(bson::DateTime::from_millis(1_788_602_400_000)),
        };
        let body = ExternalAccessPolicyBody::from(stored.clone());
        assert!(
            body.expires_at.as_deref().is_some_and(|s| s.contains('T')),
            "out as RFC3339, not as an object: {:?}",
            body.expires_at
        );
        assert_eq!(body.to_policy().unwrap(), stored);
    }

    /// `ADMINISTRATOR` passes via the bypass in `permissions::has`, like every
    /// other gate in the codebase — asserted here so a future rewrite of this
    /// function cannot quietly drop the owner.
    #[test]
    fn administrator_passes_by_bypass() {
        assert_eq!(
            decide_approval(
                permissions::ADMINISTRATOR,
                true,
                &ExternalAccessPolicy::default(),
                &approved()
            ),
            Ok(())
        );
    }
}
