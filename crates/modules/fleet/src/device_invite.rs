// SPDX-License-Identifier: AGPL-3.0-only
//! Temporary devices — "invite a device for N hours".
//!
//! A person with `MANAGE_AGENTS` in an organization creates an invitation and
//! reads its 8-digit code to whoever sits at the other machine. That machine
//! redeems the code (`mh join`, or the tray's "Join with an invite code…")
//! WITHOUT any account: the redemption hands it a STANDARD single-use
//! enrollment token minted under the inviter's identity, and the enrollment
//! binds the new device to the invitation. From then on the device is
//! temporary:
//!
//! - only the INVITER (and members holding one of the invitation's extra
//!   roles) may control it or reach it over the mesh, and it may reach nobody:
//!   the overlay ships it only the inviter's devices, and ships it to those
//!   devices with a deny-new-flows ingress rule (replies to their own flows
//!   still pass), whatever the org's ACL posture;
//! - it is removed when the invitation's time is up (the reaper below), when
//!   the inviter revokes the invitation, or when the device leaves itself.
//!
//! What this flow can never do: bind an EXISTING device (a redemption that
//! would rehydrate a known machine is refused at enrollment), hand out a
//! code twice (`open → redeemed` is a compare-and-set), or let anyone guess
//! codes at speed (per-client and server-wide failure budgets). Codes are
//! stored only as peppered hashes; the token itself is never stored.
use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::role::permissions;
use meshharbor_services::dao::native_ssh_authorization::hash_secret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use crate::FleetState;

/// Mongo collection; its indexes are declared in `FleetModule::indexes`.
pub const COLLECTION: &str = "device_invites";
/// The enrollment token a redemption hands out (same as an admin-issued one).
const ENROLLMENT_TTL_SECS: u64 = 600;
pub const MIN_ACCESS_SECS: i64 = 600;
pub const MAX_ACCESS_SECS: i64 = 5 * 365 * 86_400;
const MAX_OPEN_PER_TENANT: u64 = 20;
const CODE_DIGITS: usize = 8;
/// Failed redemptions allowed per client, and server-wide, per window. The
/// server-wide budget is what stops a distributed guesser: 10^8 codes against
/// a few hundred guesses per ten minutes.
const FAIL_WINDOW_SECS: i64 = 600;
const MAX_FAILS_PER_CLIENT: u32 = 10;
const MAX_FAILS_TOTAL: u32 = 300;

pub const STATE_OPEN: &str = "open";
pub const STATE_REDEEMED: &str = "redeemed";
pub const STATE_ENROLLED: &str = "enrolled";
pub const STATE_ENDED: &str = "ended";

/// The removal reason a temporary device's end carries (audit + logs).
pub const REASON_EXPIRED: &str = "temporary_expired";
pub const REASON_REVOKED: &str = "temporary_revoked";
pub const REASON_LEFT: &str = "temporary_left";
pub const REASON_REMOVED: &str = "temporary_removed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInviteRow {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub tenant_id: ObjectId,
    pub inviter_user_id: ObjectId,
    #[serde(default)]
    pub label: String,
    /// Members holding any of these roles may also control / reach the device.
    #[serde(default)]
    pub allow_role_ids: Vec<ObjectId>,
    pub code_hash: String,
    /// `open` → `redeemed` (token minted) → `enrolled` (device bound) →
    /// `ended`; `open`/`redeemed` may also go straight to `ended`.
    pub state: String,
    pub access_until: DateTime,
    pub created_at: DateTime,
    #[serde(default)]
    pub redeemed_at: Option<DateTime>,
    #[serde(default)]
    pub token_jti: Option<String>,
    #[serde(default)]
    pub agent_id: Option<ObjectId>,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub device_os: Option<String>,
    #[serde(default)]
    pub ended_at: Option<DateTime>,
    #[serde(default)]
    pub end_reason: Option<String>,
    /// Who ended it by hand (a revocation); `None` for a deadline, a device
    /// that left, or a device removed by other means.
    #[serde(default)]
    pub ended_by: Option<ObjectId>,
    /// Every extension of the access period, oldest first.
    #[serde(default)]
    pub renewals: Vec<Renewal>,
    /// `true` for an invitation made FROM an already-enrolled device (it never
    /// had a code anyone could redeem).
    #[serde(default)]
    pub converted: bool,
}

/// One extension of an invitation's access period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Renewal {
    pub at: DateTime,
    pub by: ObjectId,
    pub previous_until: DateTime,
    pub until: DateTime,
}

/// What the overlay and the controller gates need to know about a temporary
/// device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporaryGrant {
    pub invite_id: ObjectId,
    pub inviter_user_id: ObjectId,
    pub allow_role_ids: Vec<ObjectId>,
    pub access_until: DateTime,
}

impl TemporaryGrant {
    /// May a member with this identity control / reach the device?
    pub fn allows(&self, user_id: Option<ObjectId>, role_ids: &[ObjectId]) -> bool {
        user_id == Some(self.inviter_user_id)
            || role_ids.iter().any(|r| self.allow_role_ids.contains(r))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    duration_secs: i64,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    allow_role_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redeem {
    code: String,
    device_name: String,
    device_os: String,
}

macro_rules! coll {
    ($state:expr) => {
        $state.core.db.collection::<DeviceInviteRow>(COLLECTION)
    };
}

fn enabled(state: &FleetState) -> Result<(), ApiError> {
    if state.settings.auth.native_device_invite_enabled {
        Ok(())
    } else {
        Err(ApiError::ServiceUnavailable(
            "Temporary device invitations are disabled on this server".into(),
        ))
    }
}

fn storage<T, E>(r: Result<T, E>) -> Result<T, ApiError> {
    // Driver errors can carry query fields (hashes); never echo them.
    r.map_err(|_| ApiError::ServiceUnavailable("Invitation storage unavailable".into()))
}

fn no_store(status: StatusCode, body: Value) -> Response {
    let mut r = (status, Json(body)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// Digits only, separators and spaces ignored. `None` for anything else, so a
/// malformed value never reaches the database.
pub fn normalize_code(raw: &str) -> Option<String> {
    let s: String = raw.chars().filter(|c| !matches!(c, '-' | ' ')).collect();
    (s.len() == CODE_DIGITS && s.bytes().all(|b| b.is_ascii_digit())).then_some(s)
}

/// `1234-5678` — how a code is shown and read aloud.
pub fn display_code(normalized: &str) -> String {
    format!("{}-{}", &normalized[..4], &normalized[4..])
}

fn new_code() -> String {
    // 8 OS-random bytes of a v4 UUID (bytes 6 and 8 carry fixed version and
    // variant bits — skipped) → mod 10^8: the bias of 2^64 mod 10^8 is ~5e-12.
    let raw = *uuid::Uuid::new_v4().as_bytes();
    let mut b = [0u8; 8];
    b.copy_from_slice(&[
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[7], raw[9],
    ]);
    format!(
        "{:0width$}",
        u64::from_le_bytes(b) % 100_000_000,
        width = CODE_DIGITS
    )
}

/// Peppered with the server's JWT secret: a leaked row does not hand out its
/// code by enumerating 10^8 hashes.
fn code_hash(state: &FleetState, normalized: &str) -> String {
    hash_secret(
        "device-invite-code",
        &format!("{}\0{normalized}", state.settings.jwt.secret),
    )
}

fn valid_device_name(s: &str) -> bool {
    let n = s.chars().count();
    (1..=64).contains(&n) && !s.chars().any(char::is_control) && s.trim() == s
}

fn valid_os(s: &str) -> bool {
    matches!(s, "windows" | "macos" | "linux")
}

fn valid_label(s: &str) -> bool {
    s.chars().count() <= 64 && !s.chars().any(char::is_control)
}

// ─── redemption throttle ────────────────────────────────────────────────────

struct FailWindow {
    start_ms: i64,
    total: u32,
    per_client: HashMap<String, u32>,
}

static FAILS: std::sync::LazyLock<Mutex<FailWindow>> = std::sync::LazyLock::new(|| {
    Mutex::new(FailWindow {
        start_ms: 0,
        total: 0,
        per_client: HashMap::new(),
    })
});

fn with_window<T>(now_ms: i64, f: impl FnOnce(&mut FailWindow) -> T) -> T {
    let mut w = FAILS.lock().unwrap_or_else(|e| e.into_inner());
    if now_ms - w.start_ms >= FAIL_WINDOW_SECS * 1000 {
        w.start_ms = now_ms;
        w.total = 0;
        w.per_client.clear();
    }
    f(&mut w)
}

fn throttled(client: &str, now_ms: i64) -> bool {
    with_window(now_ms, |w| {
        w.total >= MAX_FAILS_TOTAL
            || w.per_client.get(client).copied().unwrap_or(0) >= MAX_FAILS_PER_CLIENT
    })
}

fn record_failure(client: &str, now_ms: i64) {
    with_window(now_ms, |w| {
        w.total = w.total.saturating_add(1);
        *w.per_client.entry(client.to_string()).or_insert(0) += 1;
    });
}

// ─── the inviter's routes ───────────────────────────────────────────────────

fn parse_tid(raw: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(raw).map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))
}

fn row_view(r: &DeviceInviteRow) -> Value {
    json!({
        "id": r.id.to_hex(),
        "inviter_user_id": r.inviter_user_id.to_hex(),
        "label": r.label,
        "allow_role_ids": r.allow_role_ids.iter().map(|x| x.to_hex()).collect::<Vec<_>>(),
        "state": r.state,
        "access_until_ms": r.access_until.timestamp_millis(),
        "created_at_ms": r.created_at.timestamp_millis(),
        "agent_id": r.agent_id.map(|a| a.to_hex()),
        "device_name": r.device_name,
        "device_os": r.device_os,
        "redeemed_at_ms": r.redeemed_at.map(|t| t.timestamp_millis()),
        "ended_at_ms": r.ended_at.map(|t| t.timestamp_millis()),
        "end_reason": r.end_reason,
        "ended_by": r.ended_by.map(|x| x.to_hex()),
        "converted": r.converted,
        "renewals": r.renewals.iter().map(|x| json!({
            "at_ms": x.at.timestamp_millis(),
            "by": x.by.to_hex(),
            "previous_until_ms": x.previous_until.timestamp_millis(),
            "until_ms": x.until.timestamp_millis(),
        })).collect::<Vec<_>>(),
    })
}

/// `POST /api/tenant/{tenant_id}/device-invite` — create an invitation. The
/// code is in this response ONLY.
pub async fn create(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<Create>,
) -> Result<Response, ApiError> {
    enabled(&state)?;
    let tid = parse_tid(&tenant_id)?;
    crate::agent::require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    if !(MIN_ACCESS_SECS..=MAX_ACCESS_SECS).contains(&body.duration_secs) {
        return Err(ApiError::BadRequest(format!(
            "The access period must be between {} minutes and {} days",
            MIN_ACCESS_SECS / 60,
            MAX_ACCESS_SECS / 86_400
        )));
    }
    let label = body.label.unwrap_or_default().trim().to_string();
    if !valid_label(&label) {
        return Err(ApiError::BadRequest("Invalid label".into()));
    }
    let mut allow_role_ids = Vec::new();
    for r in &body.allow_role_ids {
        let id =
            ObjectId::parse_str(r).map_err(|_| ApiError::BadRequest("Invalid role id".into()))?;
        if !allow_role_ids.contains(&id) {
            allow_role_ids.push(id);
        }
    }
    if allow_role_ids.len() > 10 {
        return Err(ApiError::BadRequest("At most 10 extra roles".into()));
    }
    if state
        .tenants
        .base
        .find_by_id(tid)
        .await
        .map(|t| t.is_archived)
        .unwrap_or(false)
    {
        return Err(ApiError::Forbidden(
            "This organization is archived and accepts no devices".into(),
        ));
    }
    let c = coll!(state);
    let now = DateTime::now();
    let open = storage(
        c.count_documents(doc! {
            "tenant_id": tid,
            "state": STATE_OPEN,
            "access_until": { "$gt": now },
        })
        .await,
    )?;
    if open >= MAX_OPEN_PER_TENANT {
        return Err(ApiError::Forbidden(
            "Too many open invitations in this organization; revoke one first".into(),
        ));
    }
    let until_ms = now.timestamp_millis() + body.duration_secs * 1000;
    // A code collides with another OPEN code at ~N/10^8; the partial unique
    // index turns that into an insert error, answered by drawing again.
    for _ in 0..3 {
        let code = new_code();
        let row = DeviceInviteRow {
            id: ObjectId::new(),
            tenant_id: tid,
            inviter_user_id: auth.user_id,
            label: label.clone(),
            allow_role_ids: allow_role_ids.clone(),
            code_hash: code_hash(&state, &code),
            state: STATE_OPEN.into(),
            access_until: DateTime::from_millis(until_ms),
            created_at: now,
            redeemed_at: None,
            token_jti: None,
            agent_id: None,
            device_name: None,
            device_os: None,
            ended_at: None,
            end_reason: None,
            ended_by: None,
            renewals: Vec::new(),
            converted: false,
        };
        if c.insert_one(&row).await.is_ok() {
            tracing::info!(invite = %row.id, tenant = %tid, inviter = %auth.user_id,
                until_ms, roles = allow_role_ids.len(), "device-invite: created");
            let shown = display_code(&code);
            let mut v = row_view(&row);
            v["code"] = json!(shown);
            v["join_command"] = json!(format!("mh join {shown}"));
            return Ok(no_store(StatusCode::CREATED, v));
        }
    }
    Err(ApiError::ServiceUnavailable(
        "Could not create the invitation; please retry".into(),
    ))
}

/// `GET /api/tenant/{tenant_id}/device-invite` — the org's invitations
/// (codes are never shown again).
pub async fn list(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    let tid = parse_tid(&tenant_id)?;
    crate::agent::require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    use futures::TryStreamExt;
    let rows: Vec<DeviceInviteRow> = storage(
        storage(
            coll!(state)
                .find(doc! { "tenant_id": tid })
                .sort(doc! { "created_at": -1 })
                .limit(500)
                .await,
        )?
        .try_collect()
        .await,
    )?;
    Ok(Json(
        json!({ "items": rows.iter().map(row_view).collect::<Vec<_>>() }),
    ))
}

/// `DELETE /api/tenant/{tenant_id}/device-invite/{id}` — revoke: the code
/// stops working and a device that joined with it is removed now.
pub async fn revoke(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, invite_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    let tid = parse_tid(&tenant_id)?;
    let iid =
        ObjectId::parse_str(&invite_id).map_err(|_| ApiError::BadRequest("Invalid id".into()))?;
    crate::agent::require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let Some(row) = storage(
        coll!(state)
            .find_one(doc! { "_id": iid, "tenant_id": tid })
            .await,
    )?
    else {
        return Err(ApiError::NotFound("No such invitation".into()));
    };
    let removed = end_invite_by(&state, &row, REASON_REVOKED, Some(auth.user_id)).await?;
    tracing::info!(invite = %iid, tenant = %tid, user = %auth.user_id, removed,
        "device-invite: revoked");
    Ok(Json(json!({ "ended": true, "device_removed": removed })))
}

/// End an invitation: remove its device first (the ONE removal sequence),
/// then mark the row ended. Returns whether a device was removed. A removal
/// that fails leaves the row as it was, so the reaper retries it.
pub async fn end_invite(
    state: &FleetState,
    row: &DeviceInviteRow,
    reason: &str,
) -> Result<bool, ApiError> {
    end_invite_by(state, row, reason, None).await
}

/// [`end_invite`], recording who ended it by hand.
pub async fn end_invite_by(
    state: &FleetState,
    row: &DeviceInviteRow,
    reason: &str,
    by: Option<ObjectId>,
) -> Result<bool, ApiError> {
    if row.state == STATE_ENDED {
        return Ok(false);
    }
    let mut removed = false;
    if let Some(aid) = row.agent_id
        && let Ok(agent) = state.agents.base.find_by_id(aid).await
        && agent.deleted_at.is_none()
    {
        crate::removal::remove_agent_device(state, &agent, reason).await?;
        removed = true;
    }
    let now = DateTime::now();
    storage(
        coll!(state)
            .update_one(
                doc! { "_id": row.id, "state": { "$ne": STATE_ENDED } },
                doc! { "$set": {
                    "state": STATE_ENDED,
                    "ended_at": now,
                    "end_reason": reason,
                    "ended_by": by,
                } },
            )
            .await,
    )?;
    Ok(removed)
}

// ─── the device's redemption ────────────────────────────────────────────────

/// `POST /api/native/device-invite/redeem` — anonymous; the code is the
/// credential. Answers a single-use enrollment token for the inviter's org.
pub async fn redeem(
    State(state): State<FleetState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Redeem>,
) -> Result<Response, ApiError> {
    enabled(&state)?;
    if !valid_device_name(&body.device_name) || !valid_os(&body.device_os) {
        return Err(ApiError::BadRequest("Invalid device".into()));
    }
    let client = meshharbor_core::client_ip::ConnectionOrigin::capture(
        &headers,
        Some(peer),
        &state.settings.app.business_trusted_proxy_cidrs,
        state.settings.app.rate_limit_trusted_hops,
    )
    .client_ip()
    .ok_or_else(|| ApiError::Forbidden("Invitation refused".into()))?;
    let client_key = hash_secret("device-invite-client", &client.to_string());
    let now = DateTime::now();
    let now_ms = now.timestamp_millis();
    if throttled(&client_key, now_ms) {
        let mut r = no_store(
            StatusCode::TOO_MANY_REQUESTS,
            json!({ "error": "slow_down" }),
        );
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("600"));
        return Ok(r);
    }
    let invalid = || {
        no_store(
            StatusCode::NOT_FOUND,
            json!({ "error": "invalid_code", "message": "This invite code is not valid (it may have expired or been used)" }),
        )
    };
    let Some(code) = normalize_code(&body.code) else {
        record_failure(&client_key, now_ms);
        return Ok(invalid());
    };
    // The one-time step: whoever wins this compare-and-set owns the code.
    let won = storage(
        coll!(state)
            .find_one_and_update(
                doc! {
                    "code_hash": code_hash(&state, &code),
                    "state": STATE_OPEN,
                    "access_until": { "$gt": now },
                },
                doc! { "$set": {
                    "state": STATE_REDEEMED,
                    "redeemed_at": now,
                    "device_name": &body.device_name,
                    "device_os": &body.device_os,
                } },
            )
            .await,
    )?;
    let Some(row) = won else {
        record_failure(&client_key, now_ms);
        tracing::info!("device-invite: redemption with an unknown or spent code refused");
        return Ok(invalid());
    };
    // The inviter must still be allowed to add devices at the moment the
    // credential is minted (a revocation since the invitation wins).
    if let Err(e) = crate::agent::require_permission(
        &state,
        row.tenant_id,
        row.inviter_user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await
    {
        let _ = end_invite(&state, &row, REASON_REVOKED).await;
        return Err(e);
    }
    let (token, jti) = state
        .auth
        .issue_enrollment_token_with_relay(
            row.inviter_user_id,
            row.tenant_id,
            ENROLLMENT_TTL_SECS,
            false,
            false,
        )
        .map_err(|_| ApiError::ServiceUnavailable("Could not mint an enrollment token".into()))?;
    // Fail closed: an enrollment that cannot be recognised as temporary would
    // produce an ordinary, fully visible device.
    storage(
        coll!(state)
            .update_one(
                doc! { "_id": row.id, "state": STATE_REDEEMED },
                doc! { "$set": { "token_jti": &jti } },
            )
            .await,
    )?;
    if let Err(e) = state
        .enroll_tokens
        .record_issued(&jti, row.tenant_id, row.inviter_user_id, DateTime::now())
        .await
    {
        tracing::warn!(invite = %row.id, %jti, error = %e, "device-invite: could not record the issued enrollment token");
    }
    let inviter = inviter_display(&state, row.inviter_user_id).await;
    tracing::info!(invite = %row.id, tenant = %row.tenant_id, device = %body.device_name,
        os = %body.device_os, %jti, "device-invite: redeemed for a single-use enrollment token");
    Ok(no_store(
        StatusCode::OK,
        json!({
            "enrollment_token": token,
            "expires_in": ENROLLMENT_TTL_SECS,
            "tenant_id": row.tenant_id.to_hex(),
            "access_until_ms": row.access_until.timestamp_millis(),
            "inviter": inviter,
        }),
    ))
}

async fn inviter_display(state: &FleetState, uid: ObjectId) -> String {
    let users = state.core.db.collection::<bson::Document>("users");
    match users.find_one(doc! { "_id": uid }).await {
        Ok(Some(u)) => u
            .get_str("display_name")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| u.get_str("username").ok())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

// ─── enrollment binding and lookups ─────────────────────────────────────────

/// The invitation whose redemption minted the token with this `jti`, if any.
/// `Err` = the store could not answer; the enrollment must then refuse.
pub async fn redeemed_for_jti(
    state: &FleetState,
    jti: &str,
) -> Result<Option<DeviceInviteRow>, ApiError> {
    storage(
        coll!(state)
            .find_one(doc! { "token_jti": jti, "state": STATE_REDEEMED })
            .await,
    )
}

/// Bind the freshly enrolled device to its invitation (`redeemed →
/// enrolled`). `Ok(false)` = the invitation was revoked meanwhile.
pub async fn bind(
    state: &FleetState,
    invite_id: ObjectId,
    agent_id: ObjectId,
) -> Result<bool, ApiError> {
    let r = storage(
        coll!(state)
            .update_one(
                doc! { "_id": invite_id, "state": STATE_REDEEMED },
                doc! { "$set": { "state": STATE_ENROLLED, "agent_id": agent_id } },
            )
            .await,
    )?;
    Ok(r.modified_count == 1)
}

/// Is this device temporary, and on whose invitation? `Err` = the store could
/// not answer — every caller fails CLOSED on it.
pub async fn grant_for_agent(
    state: &FleetState,
    agent_id: ObjectId,
) -> Result<Option<TemporaryGrant>, ApiError> {
    let row = storage(
        coll!(state)
            .find_one(doc! { "agent_id": agent_id, "state": STATE_ENROLLED })
            .await,
    )?;
    Ok(row.map(|r| TemporaryGrant {
        invite_id: r.id,
        inviter_user_id: r.inviter_user_id,
        allow_role_ids: r.allow_role_ids,
        access_until: r.access_until,
    }))
}

pub const REASON_MADE_PERMANENT: &str = "temporary_made_permanent";

/// The device stays, as an ordinary one: end its invitation WITHOUT the
/// removal (the network module unmarks its node and re-fans).
pub async fn end_keeping_device(
    state: &FleetState,
    invite_id: ObjectId,
    by: ObjectId,
) -> Result<bool, ApiError> {
    let now = DateTime::now();
    let r = storage(
        coll!(state)
            .update_one(
                doc! { "_id": invite_id, "state": STATE_ENROLLED },
                doc! { "$set": {
                    "state": STATE_ENDED,
                    "ended_at": now,
                    "end_reason": REASON_MADE_PERMANENT,
                    "ended_by": by,
                } },
            )
            .await,
    )?;
    Ok(r.modified_count == 1)
}

/// The device left by itself (`self/unenroll`): end its invitation.
pub async fn mark_left(state: &FleetState, invite_id: ObjectId) {
    let now = DateTime::now();
    if let Err(e) = coll!(state)
        .update_one(
            doc! { "_id": invite_id, "state": { "$ne": STATE_ENDED } },
            doc! { "$set": {
                "state": STATE_ENDED,
                "ended_at": now,
                "end_reason": REASON_LEFT,
            } },
        )
        .await
    {
        tracing::warn!(invite = %invite_id, error = %e, "device-invite: could not mark the invitation left");
    }
}

// ─── renewal, conversion, the device's own view ─────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Renew {
    duration_secs: i64,
}

/// `POST /api/tenant/{tenant_id}/device-invite/{id}/renew` — extend the access
/// period by `duration_secs`, counted from the current deadline (or from now,
/// for one already past). A joined device keeps its place.
pub async fn renew(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, invite_id)): Path<(String, String)>,
    Json(body): Json<Renew>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    let tid = parse_tid(&tenant_id)?;
    let iid =
        ObjectId::parse_str(&invite_id).map_err(|_| ApiError::BadRequest("Invalid id".into()))?;
    crate::agent::require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    if !(MIN_ACCESS_SECS..=MAX_ACCESS_SECS).contains(&body.duration_secs) {
        return Err(ApiError::BadRequest("Invalid extension".into()));
    }
    let c = coll!(state);
    let Some(row) = storage(c.find_one(doc! { "_id": iid, "tenant_id": tid }).await)? else {
        return Err(ApiError::NotFound("No such invitation".into()));
    };
    if row.state == STATE_ENDED {
        return Err(ApiError::Conflict(
            "This invitation has ended; create a new one".into(),
        ));
    }
    let now = DateTime::now().timestamp_millis();
    let from = row.access_until.timestamp_millis().max(now);
    let until = (from + body.duration_secs * 1000).min(now + MAX_ACCESS_SECS * 1000);
    let renewal = Renewal {
        at: DateTime::now(),
        by: auth.user_id,
        previous_until: row.access_until,
        until: DateTime::from_millis(until),
    };
    let r = storage(
        c.update_one(
            // The deadline we extended from: a concurrent renewal or the
            // reaper ending it makes this a no-op, answered as a conflict.
            doc! { "_id": iid, "state": { "$ne": STATE_ENDED }, "access_until": row.access_until },
            doc! {
                "$set": { "access_until": DateTime::from_millis(until) },
                "$push": { "renewals": storage(bson::to_bson(&renewal))? },
            },
        )
        .await,
    )?;
    if r.modified_count != 1 {
        return Err(ApiError::Conflict(
            "The invitation changed meanwhile; reload and retry".into(),
        ));
    }
    tracing::info!(invite = %iid, tenant = %tid, user = %auth.user_id, until_ms = until,
        "device-invite: renewed");
    let fresh = storage(c.find_one(doc! { "_id": iid }).await)?
        .ok_or_else(|| ApiError::NotFound("No such invitation".into()))?;
    Ok(Json(row_view(&fresh)))
}

/// Make an ALREADY-ENROLLED device temporary: an invitation row bound to it,
/// with no redeemable code. The caller (the network module, which owns the
/// device's overlay node) marks the node and re-fans the netmaps.
pub async fn create_bound(
    state: &FleetState,
    tenant_id: ObjectId,
    by: ObjectId,
    agent: &meshharbor_remote_control::models::Agent,
    duration_secs: i64,
    allow_role_ids: Vec<ObjectId>,
) -> Result<DeviceInviteRow, ApiError> {
    if !(MIN_ACCESS_SECS..=MAX_ACCESS_SECS).contains(&duration_secs) {
        return Err(ApiError::BadRequest("Invalid access period".into()));
    }
    let agent_id = agent
        .id
        .ok_or_else(|| ApiError::Internal("agent missing _id".into()))?;
    if grant_for_agent(state, agent_id).await?.is_some() {
        return Err(ApiError::Conflict(
            "This device is already temporary".into(),
        ));
    }
    let now = DateTime::now();
    let row = DeviceInviteRow {
        id: ObjectId::new(),
        tenant_id,
        inviter_user_id: by,
        label: String::new(),
        allow_role_ids,
        // Not a code anyone can type: a hash of nothing anyone holds.
        code_hash: hash_secret("device-invite-converted", &uuid::Uuid::new_v4().to_string()),
        state: STATE_ENROLLED.into(),
        access_until: DateTime::from_millis(now.timestamp_millis() + duration_secs * 1000),
        created_at: now,
        redeemed_at: Some(now),
        token_jti: None,
        agent_id: Some(agent_id),
        device_name: Some(agent.name.clone()),
        device_os: Some(format!("{:?}", agent.os).to_lowercase()),
        ended_at: None,
        end_reason: None,
        ended_by: None,
        renewals: Vec::new(),
        converted: true,
    };
    storage(coll!(state).insert_one(&row).await)?;
    tracing::info!(invite = %row.id, tenant = %tenant_id, agent = %agent_id, by = %by,
        "device-invite: existing device made temporary");
    Ok(row)
}

/// `GET /api/agent/self/temporary` — the device's own view: is it temporary,
/// until when, on whose invitation. The tray shows it; a renewal reaches the
/// device through it.
pub async fn self_view(
    State(state): State<FleetState>,
    agent: crate::auth_agent::AuthAgent,
) -> Result<Json<Value>, ApiError> {
    if !state.settings.auth.native_device_invite_enabled {
        return Ok(Json(json!({ "temporary": false })));
    }
    match grant_for_agent(&state, agent.agent_id).await? {
        None => Ok(Json(json!({ "temporary": false }))),
        Some(g) => Ok(Json(json!({
            "temporary": true,
            "access_until_ms": g.access_until.timestamp_millis(),
            "inviter": inviter_display(&state, g.inviter_user_id).await,
        }))),
    }
}

// ─── the reaper ─────────────────────────────────────────────────────────────

/// One cycle: every invitation whose time is up ends, and its device is
/// removed; an enrolled invitation whose device was removed by other means
/// (an admin delete) ends too. Pub so tests can drive it.
pub async fn reap_once(state: &FleetState) -> anyhow::Result<usize> {
    use futures::TryStreamExt;
    let now = DateTime::now();
    let due: Vec<DeviceInviteRow> = coll!(state)
        .find(doc! {
            "state": { "$ne": STATE_ENDED },
            "$or": [
                { "access_until": { "$lte": now } },
                { "state": STATE_ENROLLED },
            ],
        })
        .limit(500)
        .await?
        .try_collect()
        .await?;
    let mut ended = 0;
    for row in due {
        let expired = row.access_until <= now;
        let reason = if expired {
            REASON_EXPIRED
        } else {
            // Enrolled and still in time: end it only if its device is gone.
            let Some(aid) = row.agent_id else { continue };
            match state.agents.base.find_by_id(aid).await {
                Ok(a) if a.deleted_at.is_none() => continue,
                Ok(_) | Err(meshharbor_services::dao::base::DaoError::NotFound) => REASON_REMOVED,
                Err(_) => continue,
            }
        };
        match end_invite(state, &row, reason).await {
            Ok(removed) => {
                ended += 1;
                tracing::info!(invite = %row.id, tenant = %row.tenant_id, agent = ?row.agent_id,
                    reason, device_removed = removed, "device-invite: ended");
            }
            Err(e) => {
                tracing::warn!(invite = %row.id, error = ?e, "device-invite: could not end; retrying next cycle");
            }
        }
    }
    Ok(ended)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_eight_digits_and_normalize_leniently() {
        for _ in 0..500 {
            let c = new_code();
            assert_eq!(c.len(), CODE_DIGITS);
            assert!(c.bytes().all(|b| b.is_ascii_digit()));
            let shown = display_code(&c);
            assert_eq!(normalize_code(&shown).as_deref(), Some(c.as_str()));
            assert_eq!(
                normalize_code(&shown.replace('-', " ")).as_deref(),
                Some(c.as_str())
            );
        }
        for bad in [
            "",
            "1234567",
            "123456789",
            "1234-567a",
            "{\"$ne\":1}",
            "１２３４５６７８",
        ] {
            assert_eq!(normalize_code(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_grant_admits_the_inviter_and_its_roles_only() {
        let inviter = ObjectId::new();
        let role = ObjectId::new();
        let g = TemporaryGrant {
            invite_id: ObjectId::new(),
            inviter_user_id: inviter,
            allow_role_ids: vec![role],
            access_until: DateTime::now(),
        };
        assert!(g.allows(Some(inviter), &[]));
        assert!(g.allows(Some(ObjectId::new()), &[role]));
        assert!(!g.allows(Some(ObjectId::new()), &[ObjectId::new()]));
        assert!(!g.allows(None, &[]));
    }

    #[test]
    fn the_redemption_budget_closes_per_client_and_server_wide() {
        let t0 = 10_000_000_000_000;
        let me = "client-a";
        for _ in 0..MAX_FAILS_PER_CLIENT {
            assert!(!throttled(me, t0));
            record_failure(me, t0);
        }
        assert!(throttled(me, t0), "one client's budget");
        assert!(
            !throttled("client-b", t0),
            "another client still has its own"
        );
        assert!(
            !throttled(me, t0 + FAIL_WINDOW_SECS * 1000),
            "a new window reopens"
        );
    }
}
