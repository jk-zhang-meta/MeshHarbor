// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! REST surface for the remote-control subsystem.
//!
//! Per `docs/remote-control.md` §9.1. Signaling (SDP/ICE) happens over the
//! WebSocket; this module is everything else: agent enrollment, CRUD, session
//! introspection, TURN credential issuance.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, oid::ObjectId};
use roomler_ai_db::models::role::permissions;
use roomler_ai_remote_control::models::{AccessPolicy, AgentStatus, InstallInfo, OsKind};
use roomler_ai_services::dao::base::PaginationParams;
use roomler_ai_services::quota;
use serde::{Deserialize, Serialize};

use roomler_core::{ApiError, extractors::auth::AuthUser};

use crate::FleetState;

const ENROLLMENT_TTL_SECS: u64 = 600; // 10 minutes per §11.1

/// Require a `role::permissions` bit for `user_id` in `tenant_id`. Doubles as
/// the membership check — `get_member_permissions` returns `Forbidden` for a
/// non-member. `owner` always passes via the `ADMINISTRATOR` bypass in `has`.
///
/// `pub(crate)` so the sibling device-management surfaces in the same subsystem
/// (`routes::overlay_route`, `routes::tunnel`) gate their destructive endpoints
/// on the same `MANAGE_AGENTS` bit rather than re-deriving the check.
// FR-69 P3 — the gate itself is `roomler_core::guards::require_permission`
// (the `chat` module's room routes need it too); re-exported so every
// `super::remote_control::require_permission(&state, …)` in this crate reads
// as before — an `&FleetState` argument derefs to `&Core`.
pub(crate) use roomler_core::guards::require_permission;

// ────────────────────────────────────────────────────────────────────────────
// Agent enrollment
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct EnrollmentTokenResponse {
    pub enrollment_token: String,
    pub expires_in: u64,
    pub jti: String,
    /// FR-104 — the token may also anchor the device it enrolls.
    pub anchor: bool,
    /// This credential explicitly approves its enrolled device as an org relay.
    pub relay_server: bool,
}

/// Optional body for `POST …/agent/enroll-token`. The dashboard (and every
/// older client) posts none, which mints the plain single-use token.
#[derive(Debug, Default, Deserialize)]
pub struct EnrollmentTokenRequest {
    /// FR-104 — let this token also anchor the Windows device it enrolls for
    /// SYSTEM exec: the wizard's elevated `roomlerd anchor create`, with the
    /// same pasted token. Default off.
    #[serde(default)]
    pub anchor: bool,
    /// Server enrollment only: requires the same EXEC_DEVICE permission as
    /// approving a relay through the per-device policy API. Default off.
    #[serde(default)]
    pub relay_server: bool,
}

impl EnrollmentTokenRequest {
    /// Read the body leniently. Before FR-104 this route read no body at all,
    /// so every shape an admin's script may post was accepted: nothing,
    /// `curl -d ''` (form-encoded, empty), a JSON content type with an empty
    /// body. They still are, because only a non-empty JSON body is parsed —
    /// axum's `Option<Json<_>>` would answer the last two 415 and 400.
    fn from_body(headers: &axum::http::HeaderMap, body: &[u8]) -> Result<Self, ApiError> {
        let json = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(|essence| {
                let essence = essence.trim().to_ascii_lowercase();
                essence == "application/json" || essence.ends_with("+json")
            })
            .unwrap_or(false);
        if !json || body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        serde_json::from_slice(body)
            .map_err(|e| ApiError::BadRequest(format!("Invalid request body: {e}")))
    }
}

/// POST /api/tenant/{tenant_id}/agent/enroll-token — admin issues an enrollment
/// token that a new agent binary exchanges (once, within 10 min) for a
/// long-lived agent token.
pub async fn issue_enrollment_token(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<EnrollmentTokenResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    let requested = EnrollmentTokenRequest::from_body(&headers, &body)?;
    if requested.relay_server {
        require_permission(
            &state,
            tid,
            auth.user_id,
            permissions::EXEC_DEVICE,
            "EXEC_DEVICE",
        )
        .await?;
    }
    let anchor = requested.anchor;
    let relay_server = requested.relay_server;
    let (token, jti) = state.auth.issue_enrollment_token_with_relay(
        auth.user_id,
        tid,
        ENROLLMENT_TTL_SECS,
        anchor,
        relay_server,
    )?;
    // FR-102 P3 — the issuance on record (the jti, never the token), so the
    // digest can say how many tokens were minted and how many enrolled.
    // Best-effort: a ledger that could not answer must not cost the admin
    // the token they asked for; the enroll's upsert fills the row in later.
    if let Err(e) = state
        .enroll_tokens
        .record_issued(&jti, tid, auth.user_id, DateTime::now())
        .await
    {
        tracing::warn!(tenant = %tid, %jti, error = %e, "fr-102: could not record the issued enrollment token");
    }
    if anchor {
        // The admin's choice, on the record: whoever holds this token can
        // anchor the device it enrolls, and so speak for its SYSTEM service.
        tracing::info!(
            tenant = %tid, admin = %auth.user_id, %jti,
            "fleet-rpc: enrollment token minted that may also anchor the device it enrolls"
        );
    }

    if relay_server {
        tracing::info!(tenant = %tid, admin = %auth.user_id, %jti,
            "fleet: single-use enrollment token carries explicit relay approval");
    }
    Ok(Json(EnrollmentTokenResponse {
        enrollment_token: token,
        expires_in: ENROLLMENT_TTL_SECS,
        jti,
        anchor,
        relay_server,
    }))
}

/// The enroll body. ⚠️ No `deny_unknown_fields`, and none may ever be added:
/// an agent newer than this server sends fields it has never heard of, and
/// an older server must keep enrolling it (FR-102 P3 relies on exactly that
/// in the other direction too — a pre-P3 server ignores `install`).
#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    pub enrollment_token: String,
    pub machine_id: String,
    pub machine_name: String,
    pub os: OsKind,
    pub agent_version: String,
    /// FR-102 P3 — how the device was installed (`{method, scope, run}`).
    /// Additive: absent on every agent from before P3, which records as
    /// `unknown`. Clamped, never refused ([`InstallInfo::clamped`]).
    #[serde(default)]
    pub install: Option<InstallInfo>,
}

#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub tenant_id: String,
    pub agent_token: String,
    /// FR-51 — true when this enrollment arrived on an ephemeral key: the
    /// row will be reaped after its inactivity TTL, and re-enrolling later
    /// creates a NEW device rather than reviving this one.
    pub ephemeral: bool,
}

/// POST /api/agent/enroll — public (no user JWT); authenticates via the
/// enrollment token instead. Creates or rehydrates the Agent row and returns
/// a long-lived agent JWT.
///
/// FR-51 P2 — the SAME route also accepts an ephemeral enrollment KEY
/// (`TokenType::EphemeralEnrollment`); which path runs is decided by the
/// CREDENTIAL's audience, never by anything in the request body (a body that
/// could pick would let a device declare itself permanent and evade the
/// reaper, or schedule a permanent device for silent deletion).
pub async fn enroll_agent(
    State(state): State<FleetState>,
    Json(body): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    let (claims, is_ephemeral) = state
        .auth
        .verify_enrollment_token_any(&body.enrollment_token)?;
    let tid = ObjectId::parse_str(&claims.tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id claim".to_string()))?;
    let admin_uid = ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::BadRequest("Invalid admin user id claim".to_string()))?;

    // A signed delegation cannot outlive its issuer's admission. Check before
    // consuming either a single-use token or an ephemeral enrollment key.
    roomler_core::admission::authorize_user_id(&state.core, admin_uid, None).await?;

    // An archived org accepts no devices — including back into an existing
    // row, which is what makes archiving a throwaway org actually final
    // (`routes::tenant::archive`). Checked before the single-use claim so a
    // refused enrollment does not also burn the token.
    if state
        .tenants
        .base
        .find_by_id(tid)
        .await
        .map(|t| t.is_archived)
        .unwrap_or(false)
    {
        return Err(ApiError::Forbidden(
            "This organization is archived and accepts no device enrollments".to_string(),
        ));
    }

    if is_ephemeral {
        return enroll_agent_ephemeral(&state, tid, admin_uid, &claims.jti, body).await;
    }

    // If a row already exists for (tenant_id, machine_id), rehydrate it —
    // refresh name / os / agent_version, clear `deleted_at` if soft-deleted,
    // and re-issue a token against the same _id. The unique index on
    // (tenant_id, machine_id) covers soft-deleted rows too, so we must look
    // them up *including* tombstones and revive in place rather than create.
    let existing = state
        .agents
        .find_by_tenant_and_machine(tid, &body.machine_id)
        .await?;
    // S5 — plan device cap. Only a NEW row consumes a slot; a known machine
    // rehydrates below regardless of the cap (re-enrolling your existing
    // fleet must never brick). Checked BEFORE the single-use claim on
    // purpose: a token burnt by a rejection the operator can only fix
    // elsewhere (upgrade the plan, remove a device) would fail their retry a
    // second time, for a new and confusing reason.
    if existing.is_none() {
        let tenant = state.tenants.base.find_by_id(tid).await?;
        let used = state.agents.count_active_for_tenant(tid).await?;
        // FR-32: decision + record in `quota::check`. `MaxDevices` is an
        // established limit, so it refuses whatever the tenant's mode says.
        // FR-102 P4 — through core, which also counts the collision per org.
        if let Err(d) = roomler_core::quota::check(&state, &tenant, quota::Limit::MaxDevices, used)
        {
            return Err(ApiError::Forbidden(format!(
                "Device limit reached for the {:?} plan ({} of {} devices used). \
                 Upgrade the plan or remove a device first.",
                d.plan, d.used, d.max
            )));
        }
    }

    // Enrollment tokens are single-use BY DESIGN and were never enforced —
    // field 2026-08-05 replayed one after a cap rejection. Claimed on BOTH
    // branches: a replay against a KNOWN machine still mints a fresh agent
    // JWT, which is the credential worth protecting.
    //
    // The claim fails CLOSED (see `UsedTokenDao::claim`), and the two failures
    // are reported differently on purpose: "already used" sends an operator
    // looking for a replay, so a ledger that merely could not answer must not
    // borrow that phrasing. It gets a 503 the caller can retry — the token is
    // still valid for the rest of its 10 minutes.
    state
        .used_tokens
        .claim(&claims.jti, "agent-enroll")
        .await
        .map_err(|e| match e {
            roomler_ai_services::dao::base::DaoError::Validation(_) => {
                ApiError::Unauthorized("This enrollment token has already been used".into())
            }
            _ => ApiError::ServiceUnavailable(
                "Could not verify this enrollment token is unused; please retry".into(),
            ),
        })?;

    // FR-102 P3 — the request's install claim, clamped to the vocabulary. A
    // known row keeps what it has unless this request says (a re-enroll by
    // an older agent must not downgrade it); a new row records `unknown`
    // when nothing was said.
    let install = body.install.as_ref().map(InstallInfo::clamped);
    let agent = match existing {
        Some(a) => {
            let id =
                a.id.ok_or_else(|| ApiError::Internal("agent missing _id".to_string()))?;
            state
                .agents
                .rehydrate(
                    id,
                    &body.machine_name,
                    body.os,
                    &body.agent_version,
                    install.as_ref(),
                )
                .await?
        }
        None => {
            state
                .agents
                .create(
                    tid,
                    admin_uid,
                    body.machine_name,
                    body.machine_id,
                    body.os,
                    body.agent_version,
                    String::new(), // agent_token_hash unused in JWT-only scheme
                    install,
                )
                .await?
        }
    };

    let agent_id = agent
        .id
        .ok_or_else(|| ApiError::Internal("agent missing _id".to_string()))?;
    // Only the signed, single-use credential grants this policy. The narrow
    // update preserves endpoints and fails closed against removal/generation
    // changes. A failed write can leave an ordinary row and a consumed token;
    // it must NEVER return an apparently successful agent credential.
    if claims.relay_server {
        let granted = state
            .agents
            .grant_relay_server(tid, agent_id, agent.token_gen)
            .await?;
        if !granted {
            return Err(ApiError::ServiceUnavailable(
                "Device changed during relay enrollment; request a fresh enrollment token".into(),
            ));
        }
        tracing::info!(tenant = %tid, agent = %agent_id, admin = %admin_uid,
            jti = %claims.jti, "fleet: signed enrollment approved relay serving");
    }
    // FR-104 — which token enrolled this device, so an `anchor: true` token
    // can anchor exactly this one afterwards. Best-effort: a failure here
    // costs only that second use (the anchor then needs a fresh token).
    if let Err(e) = state.agents.record_enrollment(agent_id, &claims.jti).await {
        tracing::warn!(agent = %agent_id, error = %e, "enroll: could not record the enrolling token");
    }
    // FR-102 P3 — the redemption, on the issuance row (an upsert from the
    // claims, so a token minted before the ledger existed is on record too).
    // Best-effort like the line above: the count must never refuse an enroll.
    if let Err(e) = state
        .enroll_tokens
        .mark_redeemed(
            &claims.jti,
            tid,
            admin_uid,
            DateTime::from_millis(claims.iat.saturating_mul(1000)),
            agent_id,
            DateTime::now(),
        )
        .await
    {
        tracing::warn!(agent = %agent_id, error = %e, "fr-102: could not record the token redemption");
    }
    // FR-103 — at the row's CURRENT generation. A row revived after a removal
    // has a higher one than before, so the token minted here is accepted and
    // every token from before the removal is not.
    let agent_token = state.auth.issue_agent_token(
        agent_id,
        tid,
        agent.token_gen,
        Some(state.settings.rc.agent_token_ttl_secs),
    )?;

    Ok(Json(EnrollResponse {
        agent_id: agent_id.to_hex(),
        tenant_id: tid.to_hex(),
        agent_token,
        ephemeral: false,
    }))
}

/// FR-51 P2 — the ephemeral-key enrollment path. Differs from the standard
/// one in exactly the ways the spec derives:
///
/// * **create-only, never rehydrate** (F1): an ephemeral enrollment supplies
///   a fresh random machine_id per process, and a rehydrate affordance here
///   would let a key-holder TAKE OVER an existing device row by posting its
///   machine_id — so a duplicate is a final 409, not a revival.
/// * the org switch is re-checked on every use, AHEAD of the key's own
///   claim, so flipping it off revokes the whole class immediately and
///   burns no uses;
/// * the device cap runs BEFORE the use-claim, mirroring the single-use
///   path's order for the field-taught reason: a use burnt on a rejection
///   the operator must fix elsewhere would fail their retry a second time.
///   (A use IS burnt on the duplicate-machine_id 409 below — that one is
///   caller error, and claiming after create would let racing enrollments
///   overshoot the ceiling.)
async fn enroll_agent_ephemeral(
    state: &FleetState,
    tid: ObjectId,
    admin_uid: ObjectId,
    jti: &str,
    body: EnrollRequest,
) -> Result<Json<EnrollResponse>, ApiError> {
    // Gate 1 — the class switch (FR-51 §4). Default off; off = every
    // outstanding key stops working, on its next use, burning nothing.
    let tenant = state.tenants.base.find_by_id(tid).await?;
    if !tenant.settings.ephemeral_keys_enabled {
        return Err(ApiError::Forbidden(
            "Ephemeral enrollment keys are disabled for this organization".to_string(),
        ));
    }

    // Device cap — an ephemeral device consumes a slot while it exists
    // (FR-51 F5, the simple reading; the reaper is what gives them back).
    let used = state.agents.count_active_for_tenant(tid).await?;
    // FR-102 P4 — through core, which also counts the collision per org.
    if let Err(d) = roomler_core::quota::check(state, &tenant, quota::Limit::MaxDevices, used) {
        return Err(ApiError::Forbidden(format!(
            "Device limit reached for the {:?} plan ({} of {} devices used). \
             Upgrade the plan or remove a device first.",
            d.plan, d.used, d.max
        )));
    }

    // The atomic use-claim: not revoked, not expired, ceiling not reached,
    // counter bumped — one operation, so racing replicas cannot overshoot
    // and a revocation lands on the very next use.
    let Some(key) = state.enrollment_keys.claim_use(tid, jti).await? else {
        let reason = state
            .enrollment_keys
            .refusal_reason(tid, jti)
            .await
            .unwrap_or(roomler_ai_services::dao::enrollment_key::KeyRefusal::Unknown);
        tracing::warn!(tenant_id = %tid, jti, reason = reason.as_str(),
            "fr-51: ephemeral enrollment key refused");
        return Err(ApiError::Unauthorized(format!(
            "This enrollment key was refused ({})",
            reason.as_str()
        )));
    };
    let key_id = key
        .id
        .ok_or_else(|| ApiError::Internal("enrollment key missing _id".to_string()))?;

    // FR-102 P3 — the same install claim as the standard path records.
    let install = body.install.as_ref().map(InstallInfo::clamped);
    let agent = match state
        .agents
        .create_ephemeral(
            tid,
            admin_uid,
            body.machine_name,
            body.machine_id,
            body.os,
            body.agent_version,
            key_id,
            key.ephemeral_ttl_secs,
            install,
        )
        .await
    {
        Ok(a) => a,
        Err(roomler_ai_services::dao::base::DaoError::DuplicateKey(_)) => {
            return Err(ApiError::Conflict(
                "A device with this machine_id is already enrolled in this organization; \
                 an ephemeral enrollment never revives or replaces an existing device"
                    .to_string(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let agent_id = agent
        .id
        .ok_or_else(|| ApiError::Internal("agent missing _id".to_string()))?;

    // Control 4 — the per-use audit row: the record that outlives the device
    // row (which will hard-delete). Best-effort — the atomic claim above is
    // the enforcement; losing the record is logged, never a refusal.
    if let Err(e) = state
        .enrollment_keys
        .record_use(tid, key_id, agent_id, &agent.machine_id, &agent.name)
        .await
    {
        tracing::warn!(%agent_id, %key_id, %e, "fr-51: enrollment key use-record failed");
    }
    tracing::info!(
        tenant_id = %tid, %agent_id, %key_id, name = %agent.name,
        uses = key.uses, max_uses = key.max_uses,
        "fr-51: ephemeral device enrolled"
    );

    // FR-103 — at the row's generation. An ephemeral row is always new
    // (never rehydrated), so that is 0; reading it keeps the rule in one place.
    let agent_token = state.auth.issue_agent_token(
        agent_id,
        tid,
        agent.token_gen,
        Some(state.settings.rc.agent_token_ttl_secs),
    )?;
    Ok(Json(EnrollResponse {
        agent_id: agent_id.to_hex(),
        tenant_id: tid.to_hex(),
        agent_token,
        ephemeral: true,
    }))
}

/// FR-103 — what `POST /api/agent/self/renew` answers.
#[derive(Debug, Serialize, Deserialize)]
pub struct RenewedAgentToken {
    /// A fresh agent token for the same device, at the row's generation.
    pub agent_token: String,
    /// When it expires, RFC 3339. The device renews again well before then.
    pub expires_at: String,
}

/// POST /api/agent/self/renew — FR-103: a device buys a fresh agent token
/// with the one it holds, so a device that keeps running never drops off on
/// its enrollment anniversary.
///
/// The decision is `AuthAgent`'s, with one difference: the presented token
/// may be up to `RENEWAL_GRACE_SECS` past its `exp`, so a device that slept
/// through its anniversary updates (the release routes are unauthenticated),
/// renews and reconnects by itself. A deleted or quarantined device, or a
/// token from before a removal, is refused as everywhere.
///
/// Idempotent: the old token stays valid until its own `exp` (no rotation,
/// FR-103 §6), so a lost response costs nothing and the device asks again.
/// `rc.token_renewal = false` answers 404, and the device keeps its token.
pub async fn self_renew(
    State(state): State<FleetState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<RenewedAgentToken>, ApiError> {
    if !state.settings.rc.token_renewal {
        return Err(ApiError::NotFound(
            "token renewal is switched off on this server".to_string(),
        ));
    }
    let agent = crate::auth_agent::authenticate_for_renewal(&state, &headers).await?;
    let ttl = state.settings.rc.agent_token_ttl_secs;
    let agent_token = state.auth.issue_agent_token(
        agent.agent_id,
        agent.tenant_id,
        agent.agent.token_gen,
        Some(ttl),
    )?;
    let expires = chrono::Utc::now() + chrono::Duration::seconds(ttl as i64);
    let expires_at = expires.to_rfc3339();
    // The device list's "credential expires" follows the renewal now, not the
    // next connect: the device keeps its socket and presents this token only
    // when it reconnects, which can be weeks away. That connect stamps what it
    // actually presents, so a device that lost this answer is corrected there.
    // Best-effort, like the connect's stamp.
    if let Err(e) = state
        .agents
        .stamp_token_exp(agent.agent_id, expires.timestamp())
        .await
    {
        tracing::warn!(agent_id = %agent.agent_id, %e, "fr-103: could not record the renewed expiry");
    }
    tracing::info!(
        tenant_id = %agent.tenant_id, agent_id = %agent.agent_id,
        token_gen = agent.agent.token_gen, %expires_at,
        "fr-103: agent token renewed"
    );
    Ok(Json(RenewedAgentToken {
        agent_token,
        expires_at,
    }))
}

/// POST /api/agent/self/unenroll — an EPHEMERAL device removes itself
/// (FR-51 P3): the daemon calls this on SIGTERM/SIGINT so a clean stop
/// reaps in seconds instead of on the inactivity deadline.
///
/// Authenticated by the agent's own JWT via [`AuthAgent`], which also
/// enforces that the row still exists — so the second call after a
/// successful first one is a 401, which the agent deliberately treats as
/// "already gone".
///
/// ⚠️ ONLY an ephemeral row may take this path. A permanent device removing
/// itself would let a compromised host erase its own fleet record (and its
/// tombstone is the thing that lets it revive in place); a permanent
/// device's removal stays an admin decision. The refusal is 403, loudly.
pub async fn self_unenroll(
    State(state): State<FleetState>,
    agent: crate::auth_agent::AuthAgent,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !agent.agent.ephemeral {
        return Err(ApiError::Forbidden(
            "Only an ephemeral device may unenroll itself; removal of a permanent \
             device is an admin action"
                .to_string(),
        ));
    }
    // The reason is what keeps the removal's kick from telling a device that
    // is already leaving (#2267).
    let released = crate::removal::remove_agent_device(
        &state,
        &agent.agent,
        crate::removal::SELF_UNENROLL_REASON,
    )
    .await?;
    tracing::info!(
        tenant_id = %agent.tenant_id, agent_id = %agent.agent_id, name = %agent.agent.name,
        overlay_released = released.is_some(),
        "fr-51: ephemeral device unenrolled itself"
    );
    Ok(Json(serde_json::json!({
        "removed": true,
        "overlay_released": released.is_some(),
    })))
}

// ────────────────────────────────────────────────────────────────────────────
// Agent CRUD
// ────────────────────────────────────────────────────────────────────────────

/// Phase A-1 three-state presence (see `to_agent_response`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentPresence {
    /// An rc socket is registered on some pod — Connect will work.
    Online,
    /// Heartbeat trail fresh but no pod claims the socket — amber.
    Stale,
    Offline,
}

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub id: String,
    pub tenant_id: String,
    pub owner_user_id: String,
    pub name: String,
    /// Admin-set friendly label; display-only (the technical `name` is what
    /// the overlay/MagicDNS label derives from). Absent = show `name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Admin-set fleet labels.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub machine_id: String,
    pub os: OsKind,
    pub agent_version: String,
    /// FR-27 — the `roomler-desktop` version installed on the host, as the
    /// device last reported it. Omitted when there is none / it could not be
    /// read / the agent predates the field: the grid must not turn three
    /// different situations into one string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub companion_version: Option<String>,
    /// FR-92 P5b — keep busy as the device last reported it. Omitted when the
    /// device does not say (no keep busy there, an older agent, a supervised
    /// Mac's daemon): unknown, never "off".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_busy: Option<roomler_ai_remote_control::models::KeepBusyBrief>,
    pub status: AgentStatus,
    /// FR-51 — this device enrolled as temporary: the reaper removes it after
    /// its inactivity TTL, and removal is final (hard delete, no tombstone).
    /// The grid badges it so an operator is never surprised by the vanishing.
    pub ephemeral: bool,
    /// FR-51 P4 — the per-device inactivity deadline override, for the badge
    /// tooltip. Absent = the server default applies (and on a permanent
    /// device the field is meaningless and always absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_ttl_secs: Option<u64>,
    /// Three-state truth: `online` | `stale` | `offline` (Phase A-1).
    pub presence: AgentPresence,
    /// Back-compat bool = `presence == online` (a socket is actually
    /// registered; pre-A-1 this also counted heartbeat-only agents,
    /// which is what showed green on dead sockets).
    pub is_online: bool,
    pub last_seen_at: String,
    pub access_policy: AccessPolicy,
    /// Subnet-router CIDRs this agent advertises for the mesh (Phase 2). The
    /// `roomler socks5` mesh longest-prefix-matches a LAN target IP
    /// against these to pick the covering agent, which then dials the real
    /// IP. Admin-managed here; still gated by the tenant's `tunnel_policies`.
    pub routes: Vec<String>,
    /// Subnet CIDRs the agent itself ADVERTISES it can route (from its
    /// `advertise_routes` config, sent on `rc:agent.hello`). Untrusted
    /// suggestions the admin approves into `routes`. Empty for pre-feature agents.
    pub advertised_routes: Vec<String>,
    /// Codec + HW backend availability advertised by the agent in its
    /// most recent rc:agent.hello. Default empty for pre-2A.1 agents
    /// that haven't reconnected since the schema change.
    pub capabilities: roomler_ai_remote_control::models::AgentCaps,
    /// Multi-region relay PoPs: the agent's nearest relay region (derived
    /// from its STUN probe reports). `None` = never probed / all timed out —
    /// the default region serves it.
    pub relay_home: Option<String>,
    /// Fleet-RPC gate 3 as stored (`docs/fleet-rpc.md`), or `None` when this
    /// device's policy is indistinguishable from the untouched default.
    ///
    /// ⚠️ Returning this at all is not cosmetic. The policy dialogs PUT the
    /// WHOLE shape, so a dialog that cannot read the current policy opens on
    /// its closed default and the next save REPLACES the real one — silently
    /// dropping an `allowed_user_ids` restriction, which widens the device
    /// from "these three people" to "anyone holding the bit".
    ///
    /// ⚠️ And `Option`, not "always `Some`", for the mirror-image reason: the
    /// stored model cannot tell a device nobody configured from one explicitly
    /// saved as all-defaults, so `None` is the honest answer for that shape and
    /// leaves the dialog on its own closed default. See [`Self::ssh_policy`],
    /// where the difference has teeth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_policy: Option<crate::agent_exec::ExecPolicyBody>,
    /// FR-94 — an administrator anchored this Windows device for SYSTEM
    /// exec: when, and by whom (a user id). Absent on every unanchored device.
    /// Plain strings, like every id and timestamp here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_anchor: Option<ExecAnchorView>,
    /// FR-103 — when the agent token this device last connected with
    /// expires, so a device nearing its anniversary can be found (and
    /// re-enrolled, if it is too old to renew itself) before it drops.
    /// Absent until the device connects once after FR-103.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<String>,
    /// FR-102 P3 — how the device was installed, as its enroll said
    /// (`{method, scope}`; `method: "unknown"` for an agent from before P3).
    /// Absent on a row created before the install trace existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install: Option<InstallInfo>,
    /// Roomler-SSH gate 3 as stored, with the same replace-on-save warning as
    /// [`Self::exec_policy`] — and this is the one that makes `Option`
    /// load-bearing rather than tidy.
    ///
    /// The MODEL's default `account_mode` is `daemon` (SYSTEM / root); the
    /// DIALOG's is `console_user`, deliberately, so that an admin who turns SSH
    /// on without reading the selector does not get a root shell. Sending the
    /// model default for every unconfigured device would pre-select `daemon` in
    /// that dialog and undo exactly that protection — so a policy equal to the
    /// default is reported as absent instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_policy: Option<roomler_ai_remote_control::models::SshPolicyBody>,
    /// FR-52 gate 2 as stored, with the same replace-on-save warning as
    /// [`Self::exec_policy`]: the dialog PUTs the WHOLE shape, so without
    /// this a save would silently drop a narrowed permission ceiling or an
    /// expiry — and here that widens what an OUTSIDER may do.
    ///
    /// ⚠️ The device's **connect code** is deliberately NOT here. This route
    /// needs only tenant membership, and the code is the address a stranger
    /// dials; handing it to every member is a wider audience than the admin
    /// who is supposed to be handing it out. It is read from
    /// `GET /tenant/{id}/external-access`, behind `MANAGE_AGENTS`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_access_policy: Option<crate::external_access::ExternalAccessPolicyBody>,
    /// Remote config — what an operator has ASKED this device to run, and what
    /// the device SAID it did (`docs/remote-config.md`).
    ///
    /// Absent when nothing has ever been requested. The two halves have to
    /// travel together: a report alone cannot be read (it may be about an
    /// older revision), and a request alone cannot be read either (a pending
    /// change and a refused one look identical without the answer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_config: Option<RemoteConfigView>,
    /// FR-40 — the device's overlay (WireGuard) PUBLIC key as it last joined
    /// with, server-verified. Absent until the device has joined the overlay
    /// on a server that stamps it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_key_epoch: Option<u32>,
    /// FR-40 — the standing rotation order and where it stands. Absent when
    /// no rotation was ever ordered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_rotation: Option<KeyRotationView>,
    /// FR-100 P1a — the public half of the device key this enrollment last
    /// said hello with (a P-256 point, standard base64), and its fingerprint
    /// as a person reads it. Both absent until the device sends a key: an
    /// agent that predates it, or one that could not keep it on disk. A hint
    /// for a browser's first pin, never an authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_auth_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_auth_fingerprint: Option<String>,
}

/// FR-40 — one device's overlay-key rotation as the dashboard reads it:
/// the order, the device's answer (if any) and ONE server-resolved state.
#[derive(Debug, Serialize)]
pub struct KeyRotationView {
    pub request_id: String,
    pub requested_at: String,
    pub requested_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<String>,
    /// P1c — the key the device held when the order was placed; the grid's
    /// current key next to it is the rotation made visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<KeyRotationReportView>,
    pub state: KeyRotationState,
}

#[derive(Debug, Serialize)]
pub struct KeyRotationReportView {
    pub request_id: String,
    pub outcome: roomler_ai_remote_control::models::KeyRotationOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_public_key: Option<String>,
    pub key_epoch: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub reported_at: String,
}

/// Where a rotation order stands. Resolved ONCE, here, from the order, the
/// device's report and the key the device has since JOINED with — because
/// "the device says it rotated" and "the device is on the mesh under the new
/// key" are different facts, and only the second is one the server verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationState {
    /// Ordered while the device was offline; it is ordered again on its next
    /// connect (reconcile-on-connect).
    Queued,
    /// Pushed to a live socket; no answer for THIS order yet.
    Delivered,
    /// The device reported `rotated` and is expected to re-join within
    /// seconds; its last verified join still shows the previous key.
    Rotating,
    /// The device reported `rotated` AND has since joined under the key it
    /// reported. Done.
    Rotated,
    /// The device reported `rotated` long enough ago that it should have
    /// re-joined by now, and its last verified join still shows another key —
    /// read the device log.
    ReportedNotJoined,
    /// The device refused — `report.outcome` says which refusal.
    Refused,
    /// Mint or persist failed on the device; `report.detail` says why. The
    /// device's identity is unchanged.
    Failed,
    /// Queued for a device whose agent predates `key-rotate`: it will not act
    /// on the order until it is updated.
    Unsupported,
}

/// A `rotated` report older than this with no matching join is a problem,
/// not a device that is still reconnecting.
const KEY_ROTATION_REJOIN_GRACE_SECS: i64 = 60;

fn key_rotation_view(
    request: Option<roomler_ai_remote_control::models::KeyRotationRequest>,
    report: Option<roomler_ai_remote_control::models::KeyRotationReport>,
    identity: Option<&roomler_ai_remote_control::models::OverlayIdentity>,
    caps: &roomler_ai_remote_control::models::AgentCaps,
) -> Option<KeyRotationView> {
    let req = request?;
    // Only a report about THIS order counts — an answer to a superseded one
    // says nothing about it (the remote-config revision rule).
    let current = report.as_ref().filter(|r| r.request_id == req.request_id);
    // P1c — the join is the proof. A device that has joined under a key
    // different from the one it held when the order was placed HAS rotated:
    // whatever the report says (a refusal for this order can only be the
    // duplicate-delivery race), and whether a report arrived at all (it rides
    // the dying session and was lost in the second field run).
    let moved = match (req.public_key_before.as_deref(), identity) {
        (Some(before), Some(id)) => {
            id.public_key != before
                && id.joined_at.timestamp_millis() >= req.requested_at.timestamp_millis()
        }
        _ => false,
    };
    let state = if moved {
        KeyRotationState::Rotated
    } else {
        key_rotation_state_from_report(&req, current, identity, caps)
    };
    Some(KeyRotationView {
        request_id: req.request_id,
        requested_at: fmt_dt(req.requested_at),
        requested_by: req.requested_by.to_hex(),
        delivered_at: req.delivered_at.map(fmt_dt),
        public_key_before: req.public_key_before,
        report: report.map(|r| KeyRotationReportView {
            request_id: r.request_id,
            outcome: r.outcome,
            old_public_key: r.old_public_key,
            new_public_key: r.new_public_key,
            key_epoch: r.key_epoch,
            detail: r.detail,
            reported_at: fmt_dt(r.reported_at),
        }),
        state,
    })
}

/// The report-driven half of the resolution (everything short of a verified
/// identity change).
fn key_rotation_state_from_report(
    req: &roomler_ai_remote_control::models::KeyRotationRequest,
    current: Option<&roomler_ai_remote_control::models::KeyRotationReport>,
    identity: Option<&roomler_ai_remote_control::models::OverlayIdentity>,
    caps: &roomler_ai_remote_control::models::AgentCaps,
) -> KeyRotationState {
    use roomler_ai_remote_control::models::{KeyRotationOutcome, RpcCap};

    match current.map(|r| r.outcome) {
        Some(KeyRotationOutcome::Rotated) => {
            let joined_under_new =
                match (current.and_then(|r| r.new_public_key.as_deref()), identity) {
                    (Some(new), Some(id)) => id.public_key == new,
                    _ => false,
                };
            if joined_under_new {
                KeyRotationState::Rotated
            } else {
                let age_secs = current
                    .map(|r| {
                        (DateTime::now().timestamp_millis() - r.reported_at.timestamp_millis())
                            / 1000
                    })
                    .unwrap_or(0);
                if age_secs <= KEY_ROTATION_REJOIN_GRACE_SECS {
                    KeyRotationState::Rotating
                } else {
                    KeyRotationState::ReportedNotJoined
                }
            }
        }
        Some(KeyRotationOutcome::Failed) => KeyRotationState::Failed,
        Some(
            KeyRotationOutcome::Disabled
            | KeyRotationOutcome::RateLimited
            | KeyRotationOutcome::Unsupported,
        ) => KeyRotationState::Refused,
        None if !caps.has_rpc(RpcCap::KeyRotate) => KeyRotationState::Unsupported,
        None if req.delivered_at.is_some() => KeyRotationState::Delivered,
        None => KeyRotationState::Queued,
    }
}

/// The remote-config state of one device, as the dashboard needs to read it.
///
/// Deliberately assembled here rather than serialising the two model fields
/// straight out. Beyond the usual `{"$oid": …}` problem, the honest answer to
/// "did this land?" is a comparison — desired revision vs reported revision vs
/// what the device is even capable of saying — and doing that comparison in
/// one place beats doing it in every client that asks.
#[derive(Debug, Serialize)]
pub struct RemoteConfigView {
    /// The keys under management, as requested.
    pub desired: DesiredConfigView,
    /// The device's last word, if it has said one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ConfigReportView>,
    /// Where this stands, resolved server-side — see [`RemoteConfigState`].
    pub state: RemoteConfigState,
}

/// Where a device's remote config stands. One enum rather than three booleans
/// on the client, because these are mutually exclusive and a client that
/// derived them separately would eventually render two at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteConfigState {
    /// The device confirmed this exact revision, and everything asked for is
    /// in force.
    Applied,
    /// Confirmed, but some keys only take effect after a daemon restart. A
    /// SEPARATE state from `applied` on purpose: reporting them as one would
    /// tell an operator SSH is open while the device still refuses every
    /// session.
    NeedsRestart,
    /// The device refused — see `report.outcome` for which refusal. Both of
    /// them have a concrete next action, which is why they are surfaced rather
    /// than folded into "not applied".
    Refused,
    /// The device tried and failed; `report.detail` says why.
    Failed,
    /// Requested, and we are waiting for the device to say something about
    /// THIS revision. Includes "it has not reconnected yet" — reconcile
    /// happens on connect.
    Pending,
    /// The device's agent understands a pushed config but predates
    /// [`RpcCap::ConfigReport`], so it may well have applied this perfectly
    /// and will never say so. Distinct from `pending` because waiting is
    /// futile here and the fix is to update the device.
    ///
    /// [`RpcCap::ConfigReport`]: roomler_ai_remote_control::models::RpcCap::ConfigReport
    ReportsUnsupported,
    /// The device's agent predates `rc:agent.config` entirely — the push is
    /// not even sent. Nothing will happen until it is updated.
    PushUnsupported,
}

/// [`DesiredConfig`] with hex ids and an RFC3339 timestamp.
///
/// [`DesiredConfig`]: roomler_ai_remote_control::models::DesiredConfig
#[derive(Debug, Serialize)]
pub struct DesiredConfigView {
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_authorized_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_account_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoder_cells_deny: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fps_deny: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl From<roomler_ai_remote_control::models::DesiredConfig> for DesiredConfigView {
    /// The ONE place a `DesiredConfig` becomes client-facing JSON.
    ///
    /// Extracted because it wasn't: the listing projected through this shape
    /// while `set_desired_config` returned the stored model directly, so the
    /// same object came back as `{"$oid": …}` / `{"$date": …}` from the write
    /// and as hex + RFC3339 from the read. The client stores the write's
    /// answer, so its `updated_at` was an object where its own type said
    /// string — measured against prod, 2026-08-24.
    fn from(d: roomler_ai_remote_control::models::DesiredConfig) -> Self {
        Self {
            revision: d.revision,
            exec_enabled: d.exec_enabled,
            ssh_enabled: d.ssh_enabled,
            ssh_authorized_keys: d.ssh_authorized_keys,
            ssh_account_mode: d.ssh_account_mode,
            ssh_port: d.ssh_port,
            encoder_cells_deny: d.encoder_cells_deny,
            fps_deny: d.fps_deny,
            updated_by: d.updated_by.map(|i| i.to_hex()),
            updated_at: d.updated_at.map(fmt_dt),
        }
    }
}

/// [`ConfigReport`] with an RFC3339 timestamp.
///
/// [`ConfigReport`]: roomler_ai_remote_control::models::ConfigReport
#[derive(Debug, Serialize)]
pub struct ConfigReportView {
    pub revision: u64,
    pub outcome: roomler_ai_remote_control::models::ConfigOutcome,
    pub live: Vec<String>,
    pub needs_restart: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub reported_at: String,
}

/// Resolve the desired config + the device's report + its capabilities into
/// the one thing a reader wants: where this stands.
///
/// ⚠️ The revision comparison is the load-bearing part. A report for an OLDER
/// revision is a device that has not caught up — which looks exactly like a
/// refusal if you only read `outcome`, and exactly like success if you only
/// read "there is a report". Both misreadings put a wrong answer on a screen
/// an operator is using to decide whether a device is safe.
fn remote_config_view(
    desired: roomler_ai_remote_control::models::DesiredConfig,
    report: Option<roomler_ai_remote_control::models::ConfigReport>,
    caps: &roomler_ai_remote_control::models::AgentCaps,
) -> Option<RemoteConfigView> {
    use roomler_ai_remote_control::models::{ConfigOutcome, RpcCap};

    if desired.is_empty() {
        return None;
    }
    let current = report.as_ref().filter(|r| r.revision == desired.revision);
    let state = match current.map(|r| r.outcome) {
        Some(ConfigOutcome::Applied | ConfigOutcome::Noop) => {
            // `needs_restart` beats `applied`: the half that is merely written
            // down is the half an operator will otherwise act on wrongly.
            if current.is_some_and(|r| !r.needs_restart.is_empty()) {
                RemoteConfigState::NeedsRestart
            } else {
                RemoteConfigState::Applied
            }
        }
        Some(ConfigOutcome::NotOptedIn | ConfigOutcome::NotPrimary) => RemoteConfigState::Refused,
        Some(ConfigOutcome::Failed) => RemoteConfigState::Failed,
        // No report for THIS revision. Which of the three "no answer" states
        // it is depends on what the device can do, not on how long we waited.
        None if !caps.has_rpc(RpcCap::Config) => RemoteConfigState::PushUnsupported,
        None if !caps.has_rpc(RpcCap::ConfigReport) => RemoteConfigState::ReportsUnsupported,
        None => RemoteConfigState::Pending,
    };
    Some(RemoteConfigView {
        desired: desired.into(),
        report: report.map(|r| ConfigReportView {
            revision: r.revision,
            outcome: r.outcome,
            live: r.live,
            needs_restart: r.needs_restart,
            detail: r.detail,
            reported_at: fmt_dt(r.reported_at),
        }),
        state,
    })
}

/// `None` for a policy that is byte-for-byte the untouched default — see
/// [`AgentResponse::ssh_policy`] for why that distinction has to survive to
/// the client rather than being flattened here.
fn configured_only<T: Default + PartialEq, B: From<T>>(policy: T) -> Option<B> {
    (policy != T::default()).then(|| policy.into())
}

pub async fn list_agents(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let page = state.agents.list_for_tenant(tid, &params).await?;
    let redis_fresh = agent_presence_batch(&state, &page.items).await;
    let items: Vec<AgentResponse> = page
        .items
        .into_iter()
        .map(|a| {
            let fresh = a.id.map(|i| redis_fresh.contains(&i)).unwrap_or(false);
            to_agent_response(&state, a, fresh)
        })
        .collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "total": page.total,
        "page": page.page,
        "per_page": page.per_page,
        "total_pages": page.total_pages,
    })))
}

pub async fn get_agent(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Result<Json<AgentResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    // LIVE: a removed device is a 404 here exactly as it is absent from the
    // listing (#1821 — this GET answered 200 with the whole tombstone).
    let agent = state.agents.find_live_in_tenant(tid, aid).await?;
    let redis_fresh = agent_presence_batch(&state, std::slice::from_ref(&agent)).await;
    let fresh = agent.id.map(|i| redis_fresh.contains(&i)).unwrap_or(false);
    Ok(Json(to_agent_response(&state, agent, fresh)))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAgentRequest {
    pub name: Option<String>,
    /// Friendly display-only label. `Some("")` clears it (JSON has no clean
    /// "unset" distinct from absent through Option once, so empty = clear).
    pub display_name: Option<String>,
    /// Replace the whole tag list. Entries are trimmed, de-duped, capped.
    pub tags: Option<Vec<String>>,
    pub access_policy: Option<AccessPolicy>,
    /// Reassign the device owner (hex user id). `MANAGE_AGENTS` only.
    pub owner_user_id: Option<String>,
    /// Replace the advertised subnet-router CIDRs (mesh Phase 2). Each entry
    /// is validated + canonicalized by `normalize_routes`; an invalid CIDR
    /// fails the whole request with 400. `MANAGE_AGENTS` only.
    pub routes: Option<Vec<String>>,
}

/// Trim / drop-empties / de-dup (order-preserving) / cap a client-supplied
/// tag list. Shared by the agent and tunnel-client update routes.
pub fn normalize_tags(tags: Vec<String>) -> Result<Vec<String>, ApiError> {
    const MAX_TAGS: usize = 16;
    const MAX_TAG_LEN: usize = 40;
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        if t.chars().count() > MAX_TAG_LEN {
            return Err(ApiError::BadRequest(format!(
                "Tag too long (max {MAX_TAG_LEN} chars)"
            )));
        }
        if !out.iter().any(|e| e == t) {
            out.push(t.to_string());
        }
    }
    if out.len() > MAX_TAGS {
        return Err(ApiError::BadRequest(format!(
            "Too many tags (max {MAX_TAGS})"
        )));
    }
    Ok(out)
}

pub async fn update_agent(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<UpdateAgentRequest>,
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

    // LIVE, before anything below writes (#1821): this handler used to go
    // straight to the setters, so a stale page holding a removed device's id
    // edited the tombstone and only the refetch at the end noticed. A removed
    // device is a 404 here, like a bogus id. The setters filter on the live
    // row as well, so a removal between this read and those writes cannot
    // land one on the tombstone either.
    state.agents.find_live_in_tenant(tid, aid).await?;
    // FR-90 P2c-4 — placement reads a device's tags and its owner.
    let placement_inputs = body.owner_user_id.is_some() || body.tags.is_some();

    if let Some(owner) = body.owner_user_id {
        let owner_id = ObjectId::parse_str(&owner)
            .map_err(|_| ApiError::BadRequest("Invalid owner_user_id".to_string()))?;
        state.agents.update_owner(tid, aid, owner_id).await?;
    }
    // Rename outcome for the response: was there a live overlay node, and
    // what label does it carry now? Additive next to `updated` — nothing
    // read the old body, but a shape swap would still be a needless hazard.
    let mut dns_renamed: Option<bool> = None;
    let mut dns_name: Option<String> = None;
    if let Some(name) = body.name {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(ApiError::BadRequest("name must not be empty".to_string()));
        }
        state.agents.rename(tid, aid, &name).await?;
        // Best-effort propagation onto the live overlay node — network's, so
        // through the core hooks (FR-69 D6): peers see the new MagicDNS label
        // immediately (delta re-fan); the device itself re-learns its
        // self-name on its next reconnect.
        match state
            .hooks
            .agent_renamed(tid, aid, &name)
            .await
            .map_err(|e| ApiError::Internal(format!("rename propagation failed: {e}")))?
        {
            roomler_core::RenamePropagation::Propagated(label) => {
                dns_renamed = Some(true);
                dns_name = Some(label);
            }
            roomler_core::RenamePropagation::Failed => dns_renamed = Some(false),
            roomler_core::RenamePropagation::NoLiveNode => {}
        }
    }
    if let Some(display_name) = body.display_name {
        let trimmed = display_name.trim();
        state
            .agents
            .set_display_name(tid, aid, (!trimmed.is_empty()).then_some(trimmed))
            .await?;
    }
    if let Some(tags) = body.tags {
        let normalized = normalize_tags(tags)?;
        state.agents.set_tags(tid, aid, &normalized).await?;
    }
    if let Some(policy) = body.access_policy {
        state.agents.update_access_policy(tid, aid, &policy).await?;
    }
    if let Some(routes) = body.routes {
        let normalized = normalize_routes(routes)?;
        state.agents.update_routes(tid, aid, &normalized).await?;
    }
    // FR-90 P2c-4 — and where the org's sessions are copied is decided again,
    // through the core hooks (hive's). Stored first, decided after: a failure
    // is the caller's to see, and a retry decides again from what is stored.
    if placement_inputs {
        state
            .hooks
            .agent_updated(tid, aid)
            .await
            .map_err(|e| ApiError::Internal(format!("placement was not decided again: {e}")))?;
    }

    // Hand back the refreshed row so the UI can patch without a refetch —
    // additive around the legacy `{"updated": true}`.
    let agent = state.agents.find_live_in_tenant(tid, aid).await?;
    let redis_fresh = agent_presence_batch(&state, std::slice::from_ref(&agent)).await;
    let fresh = agent.id.map(|i| redis_fresh.contains(&i)).unwrap_or(false);
    Ok(Json(serde_json::json!({
        "updated": true,
        "agent": to_agent_response(&state, agent, fresh),
        "dns_renamed": dns_renamed,
        "dns_name": dns_name,
    })))
}

/// DELETE /api/tenant/{tid}/agent/{agent_id} — remove a device from the fleet.
///
/// Cascades to the overlay: the agent's mesh node is evicted (peers get a
/// `removes` delta) and its overlay IP goes back to the tenant's free pool for
/// reuse. The agent binary stays installed on the host and may be enrolled
/// again — but it comes back as a NEW mesh node with a fresh address.
pub async fn delete_agent(
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

    // Read first: gives a real 404 for a bogus agent id (`soft_delete` returns
    // a bool the handler used to discard, so deleting a nonexistent agent
    // reported `{"deleted": true}`), and yields the machine_id the overlay node
    // is keyed by.
    //
    // LIVE (#1821): the row this tombstones is live when it is found, and a
    // REPEAT delete is a 404 — the same answer the listing gives, and the
    // only one that leaves the state alone. Finding the tombstone instead
    // would re-run the whole cascade on it: re-stamp `deleted_at` (the
    // removal time, now lost), re-fire the holders' hooks against a node
    // that was already released, and report `deleted: true` for something
    // somebody else removed earlier.
    let agent = state.agents.find_live_in_tenant(tid, aid).await?;

    // FR-51 — ONE removal sequence, shared with the ephemeral reaper
    // (overlay release before the row delete before the kick; the ordering
    // rationale lives on `remove_agent_device`). An EPHEMERAL row is
    // hard-deleted here too — its tombstone would reserve a random,
    // never-reused machine_id forever — while a permanent row tombstones
    // exactly as before.
    let released = crate::removal::remove_agent_device(&state, &agent, "agent_delete").await?;
    Ok(Json(serde_json::json!({
        "deleted": true,
        "overlay_released": released.is_some(),
        "overlay_ip": released.as_ref().map(|r| r.overlay_ip.clone()),
    })))
}

// ────────────────────────────────────────────────────────────────────────────
// Forced self-update (S1a)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct TriggerUpdateRequest {
    /// Optional release tag to pin (e.g. `agent-v0.3.0-rc.260`); omitted =
    /// latest. Forwarded verbatim to the agent.
    #[serde(default)]
    pub pin: Option<String>,
    /// A pin that is strictly OLDER than what the agent runs is refused with
    /// 409 unless this is set — a deliberate-downgrade escape hatch (crash
    /// rollback, repro of an old build). FR-2: on 2026-08-27 a stale
    /// operator script pinned rc.484 at a fleet already on 0.4.1 and five
    /// hosts downgraded; the server is the one place that always knows both
    /// versions at push time.
    #[serde(default)]
    pub force: bool,
}

/// Order a release tag / bare semver as `(major, minor, patch, pre_rank)` —
/// the same tuple the agent updater's `parse_version` uses (`rc.N` ranks N,
/// a final ranks `u64::MAX`, so `0.3.0-rc.482 < 0.4.0 < 0.4.1`). `None` for
/// anything unparseable — the guard then stays out of the way (it can't
/// claim "downgrade" about an ordering it can't compute; the agent's own
/// verifier still gates what actually installs).
pub(crate) fn release_ord(v: &str) -> Option<(u64, u64, u64, u64)> {
    let s = v
        .trim()
        .trim_start_matches("agent-")
        .trim_start_matches('v');
    let (core, pre) = match s.find('-') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let mut it = core.split('.');
    let major: u64 = it.next()?.parse().ok()?;
    let minor: u64 = it.next()?.parse().ok()?;
    let patch: u64 = it.next()?.parse().ok()?;
    let pre_rank = match pre {
        None => u64::MAX,
        Some(p) => p
            .strip_prefix("rc.")
            .and_then(|n| n.parse().ok())
            .unwrap_or(u64::MAX),
    };
    Some((major, minor, patch, pre_rank))
}

/// FR-2 downgrade guard: `Some(reason)` when `pin` is strictly older than
/// the version the agent reports. Equal is ALLOWED (re-install is a normal
/// recovery move); unknown orderings are allowed (see `release_ord`).
fn pin_downgrade(pin: &str, agent_version: &str) -> Option<String> {
    match (release_ord(pin), release_ord(agent_version)) {
        (Some(p), Some(c)) if p < c => Some(format!(
            "pin {pin} is older than the agent's current {agent_version} — a stale pin \
             would DOWNGRADE this device; pass force=true to do it deliberately"
        )),
        _ => None,
    }
}

#[derive(Debug, Serialize)]
pub struct TriggerUpdateResult {
    pub agent_id: String,
    /// Whether the message reached a live agent WS. `false` = offline (or a
    /// full outbound queue); offline agents pick the release up on their own
    /// periodic check anyway.
    pub delivered: bool,
    /// FR-2: set (with the reason) when the push was NOT sent because the
    /// pin would downgrade this agent and `force` wasn't given. FR-67 P7:
    /// also when the device said it would not act on it (a secondary
    /// enrollment, or auto-update off). Additive — absent on
    /// delivered/offline rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    /// FR-67 P7 — the refusal as a stable code a client branches on:
    /// `pin_downgrade`, `primary_org` or `auto_update_off`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused_code: Option<&'static str>,
}

/// FR-67 P7 — the push this route must not send: the device's hello said it
/// would ignore (a secondary enrollment) or drop (auto-update off) it. A
/// frame sent anyway reached the socket, so it counted as `delivered`, while
/// the device logged `rc:agent.update ignored` and stayed where it was.
fn device_refusal(
    caps: &roomler_ai_remote_control::models::AgentCaps,
) -> Option<(&'static str, String)> {
    caps.update_refusal()
        .map(|r| (r.code(), r.reason().to_string()))
}

/// POST /api/tenant/{tid}/agent/{agent_id}/update — push `rc:agent.update`
/// to one agent. MANAGE_AGENTS. Pre-S1a agents ignore the unknown message
/// (decode-and-drop, same contract as `rc:goodbye`).
pub async fn trigger_agent_update(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    // Body is required (send `{}` for defaults) — plain `Json` keeps us off
    // axum 0.8's `OptionalFromRequest` surface, which the codebase doesn't
    // use anywhere else.
    Json(body): Json<TriggerUpdateRequest>,
) -> Result<Json<TriggerUpdateResult>, ApiError> {
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

    // Tenant-scope the target (404 for a foreign agent id) — LIVE, because an
    // update order for a removed device has nowhere to go (#1821).
    let agent = state.agents.find_live_in_tenant(tid, aid).await?;

    // FR-2: refuse a stale pin that would downgrade, unless forced.
    if let Some(pin) = body.pin.as_deref()
        && !body.force
        && let Some(reason) = pin_downgrade(pin, &agent.agent_version)
    {
        return Err(ApiError::Conflict(reason));
    }
    // FR-67 P7: refuse what the device said it would not act on. `force`
    // does not override this: it overrides OUR downgrade guard, and the
    // device ignores or drops the frame whatever the server sends.
    if let Some((_, reason)) = device_refusal(&agent.capabilities) {
        return Err(ApiError::Conflict(reason));
    }

    let pin = body.pin;
    let delivered = state
        .rc_hub
        .send_to_agent(
            aid,
            roomler_ai_remote_control::signaling::ServerMsg::UpdateNow { pin: pin.clone() },
        )
        .is_ok();
    tracing::info!(
        admin = %auth.user_id, agent = %aid, ?pin, delivered,
        "operator-triggered agent self-update"
    );
    Ok(Json(TriggerUpdateResult {
        agent_id: aid.to_hex(),
        delivered,
        refused: None,
        refused_code: None,
    }))
}

#[derive(Debug, Deserialize, Default)]
pub struct BulkTriggerUpdateRequest {
    /// Explicit targets (hex agent ids). Omitted/empty = every agent in the
    /// tenant.
    #[serde(default)]
    pub agent_ids: Option<Vec<String>>,
    #[serde(default)]
    pub pin: Option<String>,
    /// FR-2: allow pins that downgrade (see `TriggerUpdateRequest::force`).
    /// Bulk refusals are PER-AGENT (`results[].refused`) rather than failing
    /// the whole request — a fleet-wide push must not be all-or-nothing over
    /// one already-updated device.
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Serialize)]
pub struct BulkTriggerUpdateResponse {
    pub results: Vec<TriggerUpdateResult>,
    pub requested: usize,
    pub delivered: usize,
    /// How many targets were skipped, each with its `refused` reason and
    /// `refused_code`: FR-2's downgrade guard (0 when force or no pin), and
    /// FR-67 P7's devices that said they would not act on the push.
    pub refused: usize,
}

/// POST /api/tenant/{tid}/agent/update — push `rc:agent.update` to selected
/// (or all) agents in the tenant. MANAGE_AGENTS. Fleet-side stampede control
/// is the agents' own 5-min install-storm cooldown + the release proxy cache.
pub async fn trigger_agents_update(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<BulkTriggerUpdateRequest>,
) -> Result<Json<BulkTriggerUpdateResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    // (id, running version, the device's own refusal) — the FR-2 guard needs
    // the version per target, FR-67 P7 what the device's hello said.
    type Target = (ObjectId, String, Option<(&'static str, String)>);
    let targets: Vec<Target> = match body.agent_ids {
        Some(ids) if !ids.is_empty() => {
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                let aid = ObjectId::parse_str(&id)
                    .map_err(|_| ApiError::BadRequest(format!("Invalid agent_id: {id}")))?;
                // Tenant-scope every explicit target — LIVE, like the
                // "all devices" arm below, which lists live rows only.
                let a = state.agents.find_live_in_tenant(tid, aid).await?;
                let refusal = device_refusal(&a.capabilities);
                out.push((aid, a.agent_version, refusal));
            }
            out
        }
        _ => {
            let page = state
                .agents
                .list_for_tenant(
                    tid,
                    &PaginationParams {
                        page: 1,
                        per_page: 1000,
                        before: None,
                    },
                )
                .await?;
            page.items
                .into_iter()
                .filter_map(|a| {
                    let refusal = device_refusal(&a.capabilities);
                    a.id.map(|i| (i, a.agent_version, refusal))
                })
                .collect()
        }
    };

    let mut results = Vec::with_capacity(targets.len());
    let mut delivered = 0usize;
    let mut refused = 0usize;
    for (aid, version, device) in &targets {
        // FR-2: skip (never fail the batch) targets a stale pin would
        // downgrade.
        if let Some(pin) = body.pin.as_deref()
            && !body.force
            && let Some(reason) = pin_downgrade(pin, version)
        {
            refused += 1;
            results.push(TriggerUpdateResult {
                agent_id: aid.to_hex(),
                delivered: false,
                refused: Some(reason),
                refused_code: Some("pin_downgrade"),
            });
            continue;
        }
        // FR-67 P7: skip (never fail the batch) a device that said it would
        // ignore or drop the push, and say why, rather than count it delivered.
        if let Some((code, reason)) = device {
            refused += 1;
            results.push(TriggerUpdateResult {
                agent_id: aid.to_hex(),
                delivered: false,
                refused: Some(reason.clone()),
                refused_code: Some(code),
            });
            continue;
        }
        let ok = state
            .rc_hub
            .send_to_agent(
                *aid,
                roomler_ai_remote_control::signaling::ServerMsg::UpdateNow {
                    pin: body.pin.clone(),
                },
            )
            .is_ok();
        if ok {
            delivered += 1;
        }
        results.push(TriggerUpdateResult {
            agent_id: aid.to_hex(),
            delivered: ok,
            refused: None,
            refused_code: None,
        });
    }
    tracing::info!(
        admin = %auth.user_id, tenant = %tid,
        requested = targets.len(), delivered, refused, pin = ?body.pin,
        "operator-triggered bulk agent self-update"
    );
    Ok(Json(BulkTriggerUpdateResponse {
        requested: results.len(),
        delivered,
        refused,
        results,
    }))
}

// Helpers
// ────────────────────────────────────────────────────────────────────────────

/// Batched cross-pod presence read for the listing (Phase A-1): one MGET
/// under a 200 ms budget. Returns the set of agent ids with a FRESH
/// (TTL-enforced) directory record on ANY pod. Redis down / timeout ⇒
/// empty set — `to_agent_response` then degrades to the pre-A-1
/// heartbeat disjunction, never to hard-offline.
pub async fn agent_presence_batch(
    state: &FleetState,
    agents: &[roomler_ai_remote_control::models::Agent],
) -> std::collections::HashSet<ObjectId> {
    let Some(redis) = &state.redis_pubsub else {
        return Default::default();
    };
    let ids: Vec<ObjectId> = agents.iter().filter_map(|a| a.id).collect();
    let hexes: Vec<String> = ids.iter().map(|i| i.to_hex()).collect();
    match tokio::time::timeout(
        std::time::Duration::from_millis(200),
        redis.agent_presence_get_many(&hexes),
    )
    .await
    {
        Ok(Ok(vals)) => ids
            .into_iter()
            .zip(vals)
            .filter_map(|(id, v)| v.map(|_| id))
            .collect(),
        Ok(Err(e)) => {
            tracing::debug!(%e, "agent presence MGET failed; degrading to heartbeat disjunction");
            Default::default()
        }
        Err(_) => {
            tracing::debug!("agent presence MGET timed out; degrading to heartbeat disjunction");
            Default::default()
        }
    }
}

/// Phase A-1 three-state presence, shared by the agent response and the
/// unified device list (`routes/device.rs`) so the derivations can't drift.
/// "online" = an rc socket is REGISTERED somewhere (this pod's hub, or any
/// pod's fresh Redis directory record) — the state in which Connect will
/// actually work. "stale" = the Mongo heartbeat trail is fresh but no pod
/// claims the socket (half-open middlebox leg, directory outage, or a pod
/// that died without cleanup) — visible, amber, Connect disabled. "offline"
/// = neither. With Redis down `redis_fresh` is always false, so the presence
/// degrades to the pre-A-1 heartbeat disjunction (a cross-pod agent shows
/// "stale" instead of "online" — degraded, never lying green on a dead
/// socket ONLY, and never hard-offline). The returned bool is the back-compat
/// `is_online` = the reachable state only (pre-A-1 it also counted
/// heartbeat-only agents, which is what lied green).
pub fn derive_agent_presence(
    state: &FleetState,
    a: &roomler_ai_remote_control::models::Agent,
    redis_fresh: bool,
) -> (AgentPresence, bool) {
    let hub_online =
        a.id.map(|i| state.rc_hub.is_agent_online(i))
            .unwrap_or(false);
    let recently_seen = matches!(
        a.status,
        roomler_ai_remote_control::models::AgentStatus::Online
    ) && {
        let age_ms = bson::DateTime::now().timestamp_millis() - a.last_seen_at.timestamp_millis();
        age_ms < 90_000
    };
    let presence = if hub_online || redis_fresh {
        AgentPresence::Online
    } else if recently_seen {
        AgentPresence::Stale
    } else {
        AgentPresence::Offline
    };
    let is_online = matches!(presence, AgentPresence::Online);
    (presence, is_online)
}

fn to_agent_response(
    state: &FleetState,
    a: roomler_ai_remote_control::models::Agent,
    redis_fresh: bool,
) -> AgentResponse {
    let id = a.id.map(|i| i.to_hex()).unwrap_or_default();
    let (presence, is_online) = derive_agent_presence(state, &a, redis_fresh);
    // Resolved before the struct literal moves `capabilities`: the
    // remote-config state depends on which verbs this device advertises.
    let remote_config = remote_config_view(a.desired_config, a.config_report, &a.capabilities);
    // FR-40 — same rule: resolved before `capabilities` moves.
    let key_rotation = key_rotation_view(
        a.key_rotation,
        a.key_rotation_report,
        a.overlay_identity.as_ref(),
        &a.capabilities,
    );
    let overlay_public_key = a.overlay_identity.as_ref().map(|i| i.public_key.clone());
    let overlay_key_epoch = a.overlay_identity.as_ref().map(|i| i.key_epoch);
    // FR-100 P1a — the socket stores a key only when it is well formed, so
    // the fingerprint exists exactly when the key does. Derived here rather
    // than stored, so it can never disagree with the key.
    let peer_auth_fingerprint =
        roomler_ai_remote_control::signaling::peer_auth_fingerprint(&a.peer_auth_key);
    let peer_auth_key = peer_auth_fingerprint
        .is_some()
        .then(|| a.peer_auth_key.clone());
    AgentResponse {
        presence,
        id,
        tenant_id: a.tenant_id.to_hex(),
        owner_user_id: a.owner_user_id.to_hex(),
        name: a.name,
        display_name: a.display_name,
        tags: a.tags,
        machine_id: a.machine_id,
        os: a.os,
        agent_version: a.agent_version,
        companion_version: a.companion_version,
        keep_busy: a.keep_busy,
        status: a.status,
        ephemeral: a.ephemeral,
        ephemeral_ttl_secs: a.ephemeral_ttl_secs,
        is_online,
        last_seen_at: fmt_dt(a.last_seen_at),
        access_policy: a.access_policy,
        routes: a.routes,
        advertised_routes: a.advertised_routes,
        capabilities: a.capabilities,
        relay_home: a.relay_home,
        exec_policy: configured_only(a.exec_policy),
        exec_anchor: a.exec_anchor.map(|x| ExecAnchorView {
            anchored_at: fmt_dt(x.anchored_at),
            anchored_by: x.anchored_by.to_hex(),
        }),
        token_expires_at: a.token_exp.map(fmt_dt),
        install: a.install,
        ssh_policy: configured_only(a.ssh_policy),
        external_access_policy: configured_only(a.external_access_policy),
        remote_config,
        overlay_public_key,
        overlay_key_epoch,
        key_rotation,
        peer_auth_key,
        peer_auth_fingerprint,
    }
}

/// FR-94 — [`roomler_ai_remote_control::models::ExecAnchor`] as the API shows
/// it.
#[derive(Debug, Serialize)]
pub struct ExecAnchorView {
    pub anchored_at: String,
    pub anchored_by: String,
}

pub fn fmt_dt(dt: DateTime) -> String {
    dt.try_to_rfc3339_string()
        .unwrap_or_else(|_| dt.timestamp_millis().to_string())
}

/// Validate + canonicalize the subnet-route CIDRs an admin assigns to an agent
/// for the mesh subnet-router (Phase 2). Every entry must be valid CIDR
/// notation — IPv4 or IPv6, e.g. `10.66.24.0/24` or a single host
/// `10.66.24.53/32`. Host bits are masked to the network address, blank entries
/// are dropped, and duplicates removed. A bare IP or any unparseable entry
/// fails the whole request with 400 so the admin UI shows a clear error instead
/// of silently storing a route the mesh client would skip. Mirrors the
/// client-side parse in `roomler-cli`'s `mesh.rs` (both use `ipnet::IpNet`).
fn normalize_routes(raw: Vec<String>) -> Result<Vec<String>, ApiError> {
    use std::str::FromStr;
    const MAX_ROUTES: usize = 64;
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for entry in raw {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let net = ipnet::IpNet::from_str(trimmed).map_err(|_| {
            ApiError::BadRequest(format!(
                "Invalid route CIDR '{trimmed}' — use CIDR notation, \
                 e.g. 10.66.24.0/24 or a single host 10.66.24.53/32"
            ))
        })?;
        let canonical = net.trunc().to_string();
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    if out.len() > MAX_ROUTES {
        return Err(ApiError::BadRequest(format!(
            "Too many routes ({}); max {MAX_ROUTES}",
            out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod key_rotation_state_tests {
    use super::{KeyRotationState, key_rotation_view};
    use bson::{DateTime, oid::ObjectId};
    use roomler_ai_remote_control::models::{
        AgentCaps, KeyRotationOutcome, KeyRotationReport, KeyRotationRequest, OverlayIdentity,
    };

    fn caps(with_verb: bool) -> AgentCaps {
        AgentCaps {
            rpc: if with_verb {
                vec!["key-rotate".into()]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }
    fn req(before: Option<&str>, delivered: bool, at: DateTime) -> KeyRotationRequest {
        KeyRotationRequest {
            request_id: "r1".into(),
            requested_by: ObjectId::new(),
            requested_at: at,
            delivered_at: delivered.then_some(at),
            public_key_before: before.map(str::to_string),
        }
    }
    fn ident(key: &str, epoch: u32, at: DateTime) -> OverlayIdentity {
        OverlayIdentity {
            public_key: key.into(),
            key_epoch: epoch,
            joined_at: at,
        }
    }
    fn report(rid: &str, outcome: KeyRotationOutcome, new: Option<&str>) -> KeyRotationReport {
        KeyRotationReport {
            request_id: rid.into(),
            outcome,
            old_public_key: None,
            new_public_key: new.map(str::to_string),
            key_epoch: 1,
            detail: None,
            reported_at: DateTime::now(),
        }
    }
    fn state(
        r: KeyRotationRequest,
        rep: Option<KeyRotationReport>,
        id: Option<&OverlayIdentity>,
        c: &AgentCaps,
    ) -> KeyRotationState {
        key_rotation_view(Some(r), rep, id, c).unwrap().state
    }

    /// The second field run: the device's report was lost on the dying
    /// session, but it joined under a new key — that IS the rotation.
    #[test]
    fn a_verified_identity_change_is_rotated_with_no_report_at_all() {
        let t0 = DateTime::from_millis(1_700_000_000_000);
        let later = DateTime::from_millis(1_700_000_005_000);
        let id = ident("NEW==", 2, later);
        assert_eq!(
            state(req(Some("OLD=="), true, t0), None, Some(&id), &caps(true)),
            KeyRotationState::Rotated
        );
    }

    /// The first field run: the duplicate's refusal must not hide a rotation
    /// the join already proved.
    #[test]
    fn a_verified_identity_change_beats_a_refusal_report() {
        let t0 = DateTime::from_millis(1_700_000_000_000);
        let later = DateTime::from_millis(1_700_000_005_000);
        let id = ident("NEW==", 2, later);
        let refusal = report("r1", KeyRotationOutcome::RateLimited, None);
        assert_eq!(
            state(
                req(Some("OLD=="), true, t0),
                Some(refusal),
                Some(&id),
                &caps(true)
            ),
            KeyRotationState::Rotated
        );
    }

    /// An unchanged key is NOT a rotation, however the join is timed; and a
    /// join that predates the order proves nothing.
    #[test]
    fn an_unchanged_or_stale_identity_falls_back_to_the_report() {
        let t0 = DateTime::from_millis(1_700_000_000_000);
        let later = DateTime::from_millis(1_700_000_005_000);
        let earlier = DateTime::from_millis(1_699_999_000_000);
        let same = ident("OLD==", 1, later);
        assert_eq!(
            state(req(Some("OLD=="), true, t0), None, Some(&same), &caps(true)),
            KeyRotationState::Delivered
        );
        let old_join = ident("NEW==", 2, earlier);
        assert_eq!(
            state(
                req(Some("OLD=="), true, t0),
                None,
                Some(&old_join),
                &caps(true)
            ),
            KeyRotationState::Delivered
        );
        // No snapshot (the device had never joined): report-driven only.
        assert_eq!(
            state(req(None, false, t0), None, Some(&same), &caps(false)),
            KeyRotationState::Unsupported
        );
        assert_eq!(
            state(req(None, false, t0), None, None, &caps(true)),
            KeyRotationState::Queued
        );
    }

    #[test]
    fn a_rotated_report_needs_the_join_to_count_as_done() {
        let t0 = DateTime::from_millis(1_700_000_000_000);
        let rep = report("r1", KeyRotationOutcome::Rotated, Some("NEW=="));
        let joined = ident("NEW==", 2, t0);
        assert_eq!(
            state(
                req(None, true, t0),
                Some(rep.clone()),
                Some(&joined),
                &caps(true)
            ),
            KeyRotationState::Rotated
        );
        // Report just now, identity still old: rotating (grace), not an error.
        let old = ident("OLD==", 1, t0);
        assert_eq!(
            state(req(None, true, t0), Some(rep), Some(&old), &caps(true)),
            KeyRotationState::Rotating
        );
    }
}

#[cfg(test)]
mod remote_config_state_tests {
    use super::{RemoteConfigState, remote_config_view};
    use roomler_ai_remote_control::models::{
        AgentCaps, ConfigOutcome, ConfigReport, DesiredConfig, RpcCap,
    };

    fn caps(verbs: &[RpcCap]) -> AgentCaps {
        AgentCaps {
            rpc: verbs.iter().map(|v| v.wire().to_string()).collect(),
            ..Default::default()
        }
    }
    fn modern() -> AgentCaps {
        caps(&[RpcCap::Config, RpcCap::ConfigReport])
    }
    fn desired(revision: u64) -> DesiredConfig {
        DesiredConfig {
            exec_enabled: Some(true),
            revision,
            ..Default::default()
        }
    }
    fn report(revision: u64, outcome: ConfigOutcome, needs_restart: &[&str]) -> ConfigReport {
        ConfigReport {
            revision,
            outcome,
            live: vec![],
            needs_restart: needs_restart.iter().map(|s| s.to_string()).collect(),
            detail: None,
            reported_at: bson::DateTime::now(),
        }
    }
    fn state(
        d: DesiredConfig,
        r: Option<ConfigReport>,
        c: &AgentCaps,
    ) -> Option<RemoteConfigState> {
        remote_config_view(d, r, c).map(|v| v.state)
    }

    #[test]
    fn nothing_requested_is_not_a_state_at_all() {
        assert!(remote_config_view(DesiredConfig::default(), None, &modern()).is_none());
    }

    /// The comparison this whole view exists for. A device that answered about
    /// revision 3 has said NOTHING about revision 4 — reading its old
    /// `outcome` would show a stale "applied" over a change that has not
    /// landed, which is the most dangerous wrong answer available here.
    #[test]
    fn a_report_about_an_older_revision_is_not_an_answer() {
        assert_eq!(
            state(
                desired(4),
                Some(report(3, ConfigOutcome::Applied, &[])),
                &modern()
            ),
            Some(RemoteConfigState::Pending)
        );
        // …and the stale report is still RETURNED, so a UI can say what the
        // device last confirmed. It just doesn't decide the state.
        let view = remote_config_view(
            desired(4),
            Some(report(3, ConfigOutcome::Applied, &[])),
            &modern(),
        )
        .unwrap();
        assert_eq!(view.report.map(|r| r.revision), Some(3));
    }

    #[test]
    fn applied_and_noop_both_mean_converged() {
        for outcome in [ConfigOutcome::Applied, ConfigOutcome::Noop] {
            assert_eq!(
                state(desired(1), Some(report(1, outcome, &[])), &modern()),
                Some(RemoteConfigState::Applied),
                "{outcome:?}"
            );
        }
    }

    /// `needs_restart` must WIN over `applied`. The keys in that list are
    /// written to disk and not in force; calling the device "applied" would
    /// tell an operator SSH is open while it refuses every session.
    #[test]
    fn a_pending_restart_is_never_reported_as_applied() {
        assert_eq!(
            state(
                desired(1),
                Some(report(1, ConfigOutcome::Applied, &["ssh_enabled"])),
                &modern()
            ),
            Some(RemoteConfigState::NeedsRestart)
        );
    }

    #[test]
    fn both_refusals_are_refusals_and_a_failure_is_not() {
        for outcome in [ConfigOutcome::NotOptedIn, ConfigOutcome::NotPrimary] {
            assert_eq!(
                state(desired(1), Some(report(1, outcome, &[])), &modern()),
                Some(RemoteConfigState::Refused),
                "{outcome:?}"
            );
        }
        assert_eq!(
            state(
                desired(1),
                Some(report(1, ConfigOutcome::Failed, &[])),
                &modern()
            ),
            Some(RemoteConfigState::Failed)
        );
    }

    /// Silence means three different things, and only one of them is worth
    /// waiting through. Collapsing them into "pending" would leave an operator
    /// watching a spinner for an answer that is never coming.
    #[test]
    fn silence_is_disambiguated_by_what_the_device_can_do() {
        // Modern agent, no answer yet — genuinely pending.
        assert_eq!(
            state(desired(1), None, &modern()),
            Some(RemoteConfigState::Pending)
        );
        // rc.457/rc.458-era: applies pushed config, never reports. Waiting is
        // futile; the fix is an update.
        assert_eq!(
            state(desired(1), None, &caps(&[RpcCap::Config])),
            Some(RemoteConfigState::ReportsUnsupported)
        );
        // Predates the push entirely — the server does not even send it.
        assert_eq!(
            state(desired(1), None, &caps(&[RpcCap::Exec])),
            Some(RemoteConfigState::PushUnsupported)
        );
    }

    /// `config` is a PREFIX of `config-report`. A device advertising only
    /// `config` must not be read as report-capable, or every rc.458 device in
    /// the fleet shows "pending" forever.
    #[test]
    fn the_config_prefix_does_not_imply_reporting() {
        let old = caps(&[RpcCap::Config]);
        assert!(old.has_rpc(RpcCap::Config));
        assert!(!old.has_rpc(RpcCap::ConfigReport));
        assert_eq!(
            state(desired(1), None, &old),
            Some(RemoteConfigState::ReportsUnsupported)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_routes;

    #[test]
    fn normalize_routes_canonicalizes_and_dedups() {
        // host bits masked to the network; duplicate collapsed; blanks dropped
        let out = normalize_routes(vec![
            "10.66.24.53/24".to_string(),
            "  ".to_string(),
            "10.66.24.0/24".to_string(),
            "192.168.1.0/24".to_string(),
        ])
        .unwrap();
        assert_eq!(out, vec!["10.66.24.0/24", "192.168.1.0/24"]);
    }

    #[test]
    fn normalize_routes_accepts_host_route_and_ipv6() {
        let out = normalize_routes(vec![
            "10.66.24.53/32".to_string(),
            "2001:db8::/32".to_string(),
        ])
        .unwrap();
        assert_eq!(out, vec!["10.66.24.53/32", "2001:db8::/32"]);
    }

    #[test]
    fn normalize_routes_rejects_bare_ip_and_garbage() {
        // a bare IP (no prefix) is rejected — CIDR notation is required so the
        // stored value always parses on the mesh client side.
        assert!(normalize_routes(vec!["10.66.24.53".to_string()]).is_err());
        assert!(normalize_routes(vec!["not-a-cidr".to_string()]).is_err());
        assert!(normalize_routes(vec!["10.66.24.0/33".to_string()]).is_err());
    }

    #[test]
    fn normalize_routes_empty_is_ok() {
        assert_eq!(normalize_routes(vec![]).unwrap(), Vec::<String>::new());
        assert_eq!(
            normalize_routes(vec!["".to_string(), "   ".to_string()]).unwrap(),
            Vec::<String>::new()
        );
    }
}

#[cfg(test)]
mod fr2_downgrade_guard_tests {
    use super::{pin_downgrade, release_ord};

    #[test]
    fn ordering_matches_the_agent_updater() {
        // rc train < finals; finals order by patch; tags and bare semvers
        // both parse.
        assert!(release_ord("agent-v0.3.0-rc.482") < release_ord("agent-v0.4.0"));
        assert!(release_ord("0.4.0") < release_ord("0.4.1"));
        assert!(release_ord("agent-v0.4.1") < release_ord("v0.4.2"));
        assert!(release_ord("0.3.0-rc.9") < release_ord("0.3.0-rc.100"));
        assert_eq!(release_ord("agent-v0.4.2"), release_ord("0.4.2"));
        assert_eq!(release_ord("not-a-version"), None);
    }

    #[test]
    fn strict_downgrades_are_named_everything_else_passes() {
        // The 2026-08-27 incident shape: rc.484 pinned at a 0.4.1 fleet.
        assert!(pin_downgrade("agent-v0.3.0-rc.484", "0.4.1").is_some());
        assert!(pin_downgrade("agent-v0.4.0", "0.4.1").is_some());
        // Upgrades and re-installs pass.
        assert!(pin_downgrade("agent-v0.4.2", "0.4.1").is_none());
        assert!(pin_downgrade("agent-v0.4.1", "0.4.1").is_none());
        // Unknown orderings stay out of the way — the guard cannot claim
        // "downgrade" about what it cannot compare.
        assert!(pin_downgrade("agent-vNEXT", "0.4.1").is_none());
        assert!(pin_downgrade("agent-v0.4.0", "custom-build").is_none());
    }
}

#[cfg(test)]
mod enrollment_token_request_tests {
    use super::EnrollmentTokenRequest;
    use axum::http::{HeaderMap, HeaderValue, header::CONTENT_TYPE};

    fn read(content_type: Option<&'static str>, body: &str) -> Option<bool> {
        let mut headers = HeaderMap::new();
        if let Some(ct) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(ct));
        }
        EnrollmentTokenRequest::from_body(&headers, body.as_bytes())
            .ok()
            .map(|r| r.anchor)
    }

    /// Every shape a script could post before FR-104 still mints the plain
    /// token — axum's `Option<Json<_>>` refused the middle three.
    #[test]
    fn what_the_route_accepted_before_still_mints_a_plain_token() {
        assert_eq!(read(None, ""), Some(false), "no body");
        assert_eq!(
            read(Some("application/x-www-form-urlencoded"), ""),
            Some(false),
            "curl -d ''"
        );
        assert_eq!(
            read(Some("application/json"), ""),
            Some(false),
            "JSON, empty"
        );
        assert_eq!(
            read(Some("application/json"), " \n"),
            Some(false),
            "JSON, blank"
        );
        assert_eq!(
            read(Some("text/plain"), "{\"anchor\":true}"),
            Some(false),
            "a body that is not declared JSON is ignored, as before"
        );
    }

    #[test]
    fn relay_grant_is_explicit_and_independent_of_anchor() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        for body in ["", "{}", r#"{"anchor":true}"#] {
            assert!(
                !EnrollmentTokenRequest::from_body(&headers, body.as_bytes())
                    .unwrap()
                    .relay_server
            );
        }
        let request =
            EnrollmentTokenRequest::from_body(&headers, br#"{"relay_server":true}"#).unwrap();
        assert!(request.relay_server && !request.anchor);
    }

    #[test]
    fn only_a_json_body_asks_for_an_anchor() {
        assert_eq!(
            read(Some("application/json"), r#"{"anchor":true}"#),
            Some(true)
        );
        assert_eq!(
            read(
                Some("Application/JSON; charset=utf-8"),
                r#"{"anchor":true}"#
            ),
            Some(true)
        );
        assert_eq!(
            read(Some("application/json"), r#"{"anchor":false}"#),
            Some(false)
        );
        assert_eq!(read(Some("application/json"), "{}"), Some(false));
        assert_eq!(read(Some("application/json"), "{not json"), None, "a 400");
    }
}
