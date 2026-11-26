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
//! What this flow can never do: bind an EXISTING ordinary device (a redemption
//! that would rehydrate a known machine is refused at enrollment), hand out a
//! code twice (`open → redeemed` is a compare-and-set), or let anyone guess
//! codes at speed (per-client and server-wide failure budgets). Codes are
//! stored only as peppered hashes; the token itself is never stored.
//!
//! One device may hold SEVERAL invitations at once. Within one organization
//! they are grants on the device's ONE enrollment there (a second code is
//! redeemed with that enrollment's own credential and attaches to it); across
//! organizations each is a separate enrollment the device holds side by side.
//! The device's access is the union of its live grants, each ending on its
//! own; the device is removed from an organization when its last grant there
//! ends. Every redemption hands the device a private proof of that invitation,
//! which it keeps: when the same machine is (or later becomes) a device of its
//! own owner's organization, it presents the proofs from there, and that
//! organization's admins see which invitations their device accepted. A
//! self-reported machine id never links anything.
use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::models::{ConsentMode, DeviceAccessFeature, DeviceAccessFeatures};
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
/// Ended by an admin of the organization that owns the device (the proof link).
pub const REASON_OWNER_ENDED: &str = "temporary_ended_by_owner";
/// At most this many proofs in one link call.
const MAX_PROOFS: usize = 200;

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
    /// The accepting host's ceiling; absent is the legacy invitation, not an
    /// instruction to turn on any previously disabled service.
    #[serde(default)]
    pub features: Option<DeviceAccessFeatures>,
    #[serde(default)]
    pub features_revision: u32,
    #[serde(default)]
    pub revocation_pending: bool,
    /// Local close completed, but authoritative network activation is not yet
    /// confirmed. Persisted independently so a DB failure cannot erase retry state.
    #[serde(default)]
    pub activation_pending: bool,
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
    /// `true` when the code was redeemed by a device ALREADY temporary in this
    /// organization: the grant attached to its existing enrollment.
    #[serde(default)]
    pub attached: bool,
    /// Hash of the proof the redeeming device holds (see the module docs).
    #[serde(default)]
    pub device_proof_hash: Option<String>,
    /// The device's OWN organizations, proven by the device (`self/link`).
    #[serde(default)]
    pub hosts: Vec<HostLink>,
    /// Ended, but whether its device stays (other grants) or goes (none
    /// left) is not settled yet; the reaper retries until it is. While set,
    /// a device with no live grant left admits nobody.
    #[serde(default)]
    pub removal_pending: bool,
    /// FR-139 — when `true`, the invited device inherits `Agent.gpu_server = true`
    /// upon enrollment/attachment and appears in authorized GPU fleet views.
    #[serde(default)]
    pub gpu_server: bool,
}

/// An organization the invited machine belongs to by its own enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostLink {
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    pub linked_at: DateTime,
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
    pub ssh_port: Option<u16>,
    pub rdp_port: Option<u16>,
    pub feature_grants: Vec<meshharbor_remote_control::models::DeviceFeatureGrant>,
    /// The oldest live invitation (or, while the device's end is being
    /// settled, the one that ended last).
    pub invite_id: ObjectId,
    /// That invitation's inviter — [`NOBODY`] while the end is being settled.
    pub inviter_user_id: ObjectId,
    /// The inviters of the device's other live invitations.
    pub also_inviter_user_ids: Vec<ObjectId>,
    /// The union of every live invitation's extra roles.
    pub allow_role_ids: Vec<ObjectId>,
    /// The latest deadline among them.
    pub access_until: DateTime,
}

/// No user has the all-zero id: a grant naming it admits nobody.
pub const NOBODY: ObjectId = ObjectId::from_bytes([0; 12]);

impl TemporaryGrant {
    /// May a member with this identity control / reach the device?
    pub fn allows(&self, user_id: Option<ObjectId>, role_ids: &[ObjectId]) -> bool {
        user_id.is_some_and(|u| {
            u != NOBODY && (u == self.inviter_user_id || self.also_inviter_user_ids.contains(&u))
        }) || role_ids.iter().any(|r| self.allow_role_ids.contains(r))
    }

    /// The union of a device's live invitations, oldest first; `None` for none.
    pub fn of(rows: &[DeviceInviteRow]) -> Option<Self> {
        let first = rows.first()?;
        let mut g = TemporaryGrant {
            ssh_port: None,
            rdp_port: None,
            feature_grants: Vec::new(),
            invite_id: first.id,
            inviter_user_id: first.inviter_user_id,
            also_inviter_user_ids: Vec::new(),
            allow_role_ids: Vec::new(),
            access_until: first.access_until,
        };
        for r in rows {
            g.feature_grants
                .push(meshharbor_remote_control::models::DeviceFeatureGrant {
                    access_until_ms: Some(r.access_until.timestamp_millis().max(0) as u64),
                    inviter_user_id: r.inviter_user_id,
                    allow_role_ids: r.allow_role_ids.clone(),
                    features: if rows.iter().any(|row| row.revocation_pending) {
                        Some(DeviceAccessFeatures::none())
                    } else {
                        r.features
                    },
                });
            if r.inviter_user_id != g.inviter_user_id
                && !g.also_inviter_user_ids.contains(&r.inviter_user_id)
            {
                g.also_inviter_user_ids.push(r.inviter_user_id);
            }
            for role in &r.allow_role_ids {
                if !g.allow_role_ids.contains(role) {
                    g.allow_role_ids.push(*role);
                }
            }
            if r.access_until > g.access_until {
                g.access_until = r.access_until;
            }
        }
        Some(g)
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
    #[serde(default)]
    gpu_server: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redeem {
    code: String,
    device_name: String,
    device_os: String,
    /// The device's own agent credential IN THE INVITATION'S ORGANIZATION,
    /// when it already holds one there (a temporary device taking a second
    /// invitation from the same organization): the grant attaches to it.
    #[serde(default)]
    attach_token: Option<String>,
    #[serde(default)]
    features: Option<DeviceAccessFeatures>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    code: String,
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
        "features": r.features,
        "features_revision": r.features_revision,
        "revocation_pending": r.revocation_pending || r.activation_pending,
        "activation_pending": r.activation_pending,
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
        "attached": r.attached,
        "gpu_server": r.gpu_server,
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
            features: None,
            features_revision: 0,
            revocation_pending: false,
            activation_pending: false,
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
            attached: false,
            device_proof_hash: None,
            hosts: Vec::new(),
            removal_pending: false,
            gpu_server: body.gpu_server,
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

/// End an invitation (the reaper's, the device's own and the inviter's end).
/// Returns whether its device was removed — it is when this was its last
/// live grant in the organization; with others left it stays, admitting only
/// what they admit. See [`end_invite_by`].
pub async fn end_invite(
    state: &FleetState,
    row: &DeviceInviteRow,
    reason: &str,
) -> Result<bool, ApiError> {
    end_invite_by(state, row, reason, None).await
}

/// [`end_invite`], recording who ended it by hand.
///
/// The row ends FIRST, flagged `removal_pending`, and only then is the
/// device's fate settled from what is left ([`settle_device`]). Two grants
/// ending at once therefore cannot both see the other as still live and leave
/// a device with none (each settles after its own end, so the last one sees
/// zero). While the flag is set, a device with no live grant admits nobody
/// ([`grant_for_agent`]); a settle that fails keeps the flag, and the reaper
/// retries it.
pub async fn end_invite_by(
    state: &FleetState,
    row: &DeviceInviteRow,
    reason: &str,
    by: Option<ObjectId>,
) -> Result<bool, ApiError> {
    if row.state == STATE_ENDED {
        return Ok(false);
    }
    let mut end_filter = doc! { "_id": row.id, "state": { "$ne": STATE_ENDED } };
    if reason == REASON_EXPIRED {
        end_filter.insert("revocation_pending", doc! { "$ne": true });
        end_filter.insert("activation_pending", doc! { "$ne": true });
    }
    let now = DateTime::now();
    let r = storage(
        coll!(state)
            .update_one(
                end_filter,
                doc! { "$set": {
                    "state": STATE_ENDED,
                    "ended_at": now,
                    "end_reason": reason,
                    "ended_by": by,
                    "removal_pending": row.agent_id.is_some(),
                } },
            )
            .await,
    )?;
    if r.modified_count != 1 {
        return Ok(false); // ended meanwhile, by someone else
    }
    match row.agent_id {
        Some(aid) => settle_device(state, row.tenant_id, aid, reason).await,
        None => Ok(false),
    }
}

/// After a grant ended: the device goes if no live grant is left, else the
/// organization's netmaps are fanned again so the ended inviter's devices
/// lose it. Clears `removal_pending` only once that happened.
pub async fn settle_device(
    state: &FleetState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    reason: &str,
) -> Result<bool, ApiError> {
    let live = storage(
        coll!(state)
            .count_documents(doc! { "agent_id": agent_id, "state": STATE_ENROLLED })
            .await,
    )?;
    let mut removed = false;
    if live > 0 {
        state
            .hooks
            .agent_access_changed(tenant_id, agent_id)
            .await
            .map_err(|e| ApiError::ServiceUnavailable(format!("netmaps not refreshed: {e}")))?;
    } else if let Ok(agent) = state.agents.base.find_by_id(agent_id).await
        && agent.deleted_at.is_none()
    {
        crate::removal::remove_agent_device(state, &agent, reason).await?;
        removed = true;
    }
    storage(
        coll!(state)
            .update_many(
                doc! { "agent_id": agent_id, "removal_pending": true },
                doc! { "$set": { "removal_pending": false } },
            )
            .await,
    )?;
    Ok(removed)
}

// ─── the device's redemption ────────────────────────────────────────────────

/// The redemption's client key and throttle answer, shared by preview and
/// redeem (both spend the same failure budget).
fn client_key(
    state: &FleetState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    let client = meshharbor_core::client_ip::ConnectionOrigin::capture(
        headers,
        Some(peer),
        &state.settings.app.business_trusted_proxy_cidrs,
        state.settings.app.rate_limit_trusted_hops,
    )
    .client_ip()
    .ok_or_else(|| ApiError::Forbidden("Invitation refused".into()))?;
    Ok(hash_secret("device-invite-client", &client.to_string()))
}

fn slow_down() -> Response {
    let mut r = no_store(
        StatusCode::TOO_MANY_REQUESTS,
        json!({ "error": "slow_down" }),
    );
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("600"));
    r
}

fn invalid_code() -> Response {
    no_store(
        StatusCode::NOT_FOUND,
        json!({ "error": "invalid_code", "message": "This invite code is not valid (it may have expired or been used)" }),
    )
}

/// The open, in-time invitation a code names, or `None` (a failure is
/// recorded against the client).
async fn open_for_code(
    state: &FleetState,
    raw: &str,
    client: &str,
    now: DateTime,
) -> Result<Option<(String, DeviceInviteRow)>, ApiError> {
    let now_ms = now.timestamp_millis();
    let Some(code) = normalize_code(raw) else {
        record_failure(client, now_ms);
        return Ok(None);
    };
    let row = storage(
        coll!(state)
            .find_one(doc! {
                "code_hash": code_hash(state, &code),
                "state": STATE_OPEN,
                "access_until": { "$gt": now },
            })
            .await,
    )?;
    if row.is_none() {
        record_failure(client, now_ms);
        tracing::info!("device-invite: an unknown or spent code was presented");
    }
    Ok(row.map(|r| (code, r)))
}

async fn org_display(state: &FleetState, tid: ObjectId) -> String {
    state
        .tenants
        .base
        .find_by_id(tid)
        .await
        .map(|t| t.name)
        .unwrap_or_default()
}

/// A fresh proof for the redeeming device, and the hash the row keeps.
fn new_proof() -> (String, String) {
    let proof = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let h = hash_secret("device-invite-proof", &proof);
    (proof, h)
}

/// `POST /api/native/device-invite/preview` — anonymous, like the redemption:
/// who invites, from which organization, until when. Spends nothing; the
/// device shows it and asks before it redeems.
pub async fn preview(
    State(state): State<FleetState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Preview>,
) -> Result<Response, ApiError> {
    enabled(&state)?;
    let client = client_key(&state, peer, &headers)?;
    let now = DateTime::now();
    if throttled(&client, now.timestamp_millis()) {
        return Ok(slow_down());
    }
    let Some((_, row)) = open_for_code(&state, &body.code, &client, now).await? else {
        return Ok(invalid_code());
    };
    Ok(no_store(
        StatusCode::OK,
        json!({
            "tenant_id": row.tenant_id.to_hex(),
            "org": org_display(&state, row.tenant_id).await,
            "inviter": inviter_display(&state, row.inviter_user_id).await,
            "access_until_ms": row.access_until.timestamp_millis(),
            "features_supported": true,
        }),
    ))
}

/// `POST /api/native/device-invite/redeem` — anonymous; the code is the
/// credential. Answers a single-use enrollment token for the inviter's org —
/// or, when the device proves it is already temporary there
/// (`attach_token`), attaches the grant to that enrollment.
pub async fn redeem(
    State(state): State<FleetState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Redeem>,
) -> Result<Response, ApiError> {
    if body.features.is_some_and(|f| !f.valid()) {
        return Err(ApiError::BadRequest(
            "Desktop control and clipboard require desktop view".into(),
        ));
    }
    enabled(&state)?;
    if !valid_device_name(&body.device_name) || !valid_os(&body.device_os) {
        return Err(ApiError::BadRequest("Invalid device".into()));
    }
    let client = client_key(&state, peer, &headers)?;
    let now = DateTime::now();
    if throttled(&client, now.timestamp_millis()) {
        return Ok(slow_down());
    }
    let Some((code, found)) = open_for_code(&state, &body.code, &client, now).await? else {
        return Ok(invalid_code());
    };
    // The device's existing enrollment in this organization, proven by its
    // own credential. Checked BEFORE the code is spent: a device that is an
    // ordinary member there keeps its code for someone else.
    let attach_to = match body.attach_token.as_deref().filter(|t| !t.is_empty()) {
        None => None,
        Some(t) => {
            let claims = state
                .auth
                .verify_agent_token(t)
                .map_err(|_| ApiError::Unauthorized("Device credential refused".into()))?;
            let (aid, tid, agent) = crate::auth_agent::accepted_agent(
                &state,
                &claims.sub,
                &claims.tenant_id,
                Some(claims.generation),
            )
            .await?;
            if tid != found.tenant_id {
                return Err(ApiError::BadRequest(
                    "That credential is for another organization".into(),
                ));
            }
            if grant_for_agent(&state, aid).await?.is_none() {
                return Ok(no_store(
                    StatusCode::CONFLICT,
                    json!({ "error": "already_member", "message": "This device is already a regular device in that organization" }),
                ));
            }
            Some((aid, agent))
        }
    };
    let (proof, proof_hash) = new_proof();
    // The one-time step: whoever wins this compare-and-set owns the code.
    let mut set = doc! {
        "state": if attach_to.is_some() { STATE_ENROLLED } else { STATE_REDEEMED },
        "redeemed_at": now,
        "device_name": &body.device_name,
        "device_os": &body.device_os,
        "device_proof_hash": &proof_hash,
        "features": bson::to_bson(&body.features).map_err(|_| ApiError::Internal("Invalid features".into()))?,
        "features_revision": 0_i64,
    };
    if let Some((aid, agent)) = &attach_to {
        set.insert("agent_id", *aid);
        set.insert("attached", true);
        set.insert("device_name", agent.name.clone());
    }
    let won = storage(
        coll!(state)
            .find_one_and_update(
                doc! {
                    "_id": found.id,
                    "code_hash": code_hash(&state, &code),
                    "state": STATE_OPEN,
                    "access_until": { "$gt": now },
                },
                doc! { "$set": set },
            )
            .await,
    )?;
    let Some(row) = won else {
        record_failure(&client, now.timestamp_millis());
        return Ok(invalid_code());
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
        let mut ended = row.clone();
        ended.agent_id = attach_to.as_ref().map(|(a, _)| *a);
        let _ = end_invite(&state, &ended, REASON_REVOKED).await;
        return Err(e);
    }
    let inviter = inviter_display(&state, row.inviter_user_id).await;
    let org = org_display(&state, row.tenant_id).await;
    if let Some((aid, _)) = attach_to {
        // FR-139 — if this invite carries `gpu_server = true`, mark the
        // attached device as a GPU server so it shows up in GPU fleet views.
        if row.gpu_server
            && let Err(e) = state.agents.set_gpu_server(row.tenant_id, aid, true).await
        {
            tracing::warn!(invite = %row.id, agent = %aid, error = %e,
                "device-invite: failed to stamp gpu_server on attached device");
        }
        // The new inviter's devices learn of it on the re-fan; the live gates
        // already admit them. A failed re-fan only delays that visibility.
        if let Err(e) = state.hooks.agent_updated(row.tenant_id, aid).await {
            tracing::warn!(invite = %row.id, agent = %aid, error = %e,
                "device-invite: attached, but the netmaps were not refreshed");
        }
        tracing::info!(invite = %row.id, tenant = %row.tenant_id, agent = %aid,
            "device-invite: redeemed onto the device's existing enrollment");
        return Ok(no_store(
            StatusCode::OK,
            json!({
                "attached": true,
                "features": body.features,
                "features_revision": 0,
                "agent_id": aid.to_hex(),
                "invite_id": row.id.to_hex(),
                "device_proof": proof,
                "tenant_id": row.tenant_id.to_hex(),
                "access_until_ms": row.access_until.timestamp_millis(),
                "inviter": inviter,
                "org": org,
                "gpu_server": row.gpu_server,
            }),
        ));
    }
    let (token, jti) = state
        .auth
        .issue_enrollment_token_with_options(
            row.inviter_user_id,
            row.tenant_id,
            ENROLLMENT_TTL_SECS,
            false,
            false,
            row.gpu_server,
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
    tracing::info!(invite = %row.id, tenant = %row.tenant_id, device = %body.device_name,
        os = %body.device_os, %jti, "device-invite: redeemed for a single-use enrollment token");
    Ok(no_store(
        StatusCode::OK,
        json!({
            "enrollment_token": token,
            "features": body.features,
            "features_revision": 0,
            "expires_in": ENROLLMENT_TTL_SECS,
            "invite_id": row.id.to_hex(),
            "device_proof": proof,
            "tenant_id": row.tenant_id.to_hex(),
            "access_until_ms": row.access_until.timestamp_millis(),
            "inviter": inviter,
            "org": org,
            "gpu_server": row.gpu_server,
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

/// The device's live invitations, oldest first.
pub async fn live_for_agent(
    state: &FleetState,
    agent_id: ObjectId,
) -> Result<Vec<DeviceInviteRow>, ApiError> {
    use futures::TryStreamExt;
    storage(
        storage(
            coll!(state)
                .find(doc! { "agent_id": agent_id, "state": STATE_ENROLLED, "access_until": { "$gt": DateTime::now() } })
                .sort(doc! { "created_at": 1 })
                .limit(100)
                .await,
        )?
        .try_collect()
        .await,
    )
}

/// Is this device temporary, and on whose invitations (their union)? `Err` =
/// the store could not answer — every caller fails CLOSED on it. A device
/// whose last grant ended but whose removal is not settled yet is still
/// temporary, admitting nobody.
pub async fn grant_for_agent(
    state: &FleetState,
    agent_id: ObjectId,
) -> Result<Option<TemporaryGrant>, ApiError> {
    let rows = live_for_agent(state, agent_id).await?;
    if let Some(mut g) = TemporaryGrant::of(&rows) {
        let agent = state.agents.base.find_by_id(agent_id).await?;
        // The grant API routes the embedded worker to 2222 (service uses its reserved port).
        g.ssh_port = Some(2222);
        g.rdp_port = if agent.capabilities.rdp_available == Some(true) {
            agent.capabilities.rdp_port.filter(|port| *port != 0)
        } else {
            None
        };
        return Ok(Some(g));
    }
    let pending = storage(
        coll!(state)
            .find_one(doc! { "agent_id": agent_id, "$or": [{ "removal_pending": true }, { "state": STATE_ENROLLED }] })
            .await,
    )?;
    Ok(pending.map(|r| TemporaryGrant {
        ssh_port: None,
        rdp_port: None,
        feature_grants: Vec::new(),
        invite_id: r.id,
        inviter_user_id: NOBODY,
        also_inviter_user_ids: Vec::new(),
        allow_role_ids: Vec::new(),
        access_until: r.access_until,
    }))
}

/// All `agent_id`s in `tenant_id` currently bound to an enrolled or
/// pending-removal temporary invitation.
pub async fn temporary_agent_ids_in_tenant(
    state: &FleetState,
    tenant_id: ObjectId,
) -> Result<std::collections::HashSet<ObjectId>, ApiError> {
    use futures::TryStreamExt;
    let raw = state.core.db.collection::<bson::Document>(COLLECTION);
    let mut cursor = storage(
        raw.find(doc! {
            "tenant_id": tenant_id,
            "agent_id": { "$ne": null },
            "$or": [{ "state": STATE_ENROLLED }, { "removal_pending": true }],
        })
        .projection(doc! { "agent_id": 1 })
        .await,
    )?;
    let mut out = std::collections::HashSet::new();
    while let Some(d) = storage(cursor.try_next().await)? {
        let aid = d.get_object_id("agent_id").map_err(|e| {
            tracing::error!(%e, "device invite: malformed agent_id in temporary lookup");
            ApiError::Internal("temporary-device lookup failed".to_string())
        })?;
        out.insert(aid);
    }
    Ok(out)
}

/// The host's ceiling for THIS caller. Never union another inviter's rights.
/// None means an ordinary device with no selected access profile. Legacy
/// invitations retain their old service gates; they do not enable services.
pub async fn features_for_caller(
    state: &FleetState,
    agent_id: ObjectId,
    user_id: ObjectId,
) -> Result<Option<DeviceAccessFeatures>, ApiError> {
    if host_revocation_pending(state, agent_id).await? {
        return Ok(Some(DeviceAccessFeatures::none()));
    }
    let rows = live_for_agent(state, agent_id).await?;
    if rows.is_empty() {
        if grant_for_agent(state, agent_id).await?.is_some() {
            return Ok(Some(DeviceAccessFeatures::none()));
        }
        let raw = storage(
            state
                .core
                .db
                .collection::<bson::Document>("agents")
                .find_one(doc! { "_id": agent_id })
                .await,
        )?;
        if let Some(raw) = raw
            && let Ok(owner) = raw.get_object_id("personal_access_owner_id")
        {
            return Ok(Some(
                if owner == user_id && raw.get_object_id("owner_user_id").ok() == Some(owner) {
                    DeviceAccessFeatures::all()
                } else {
                    DeviceAccessFeatures::none()
                },
            ));
        }
        return Ok(None);
    }
    let roles = state
        .tenants
        .member_role_ids(rows[0].tenant_id, user_id)
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Could not verify invitation roles".into()))?;
    Ok(Some(selected_for_caller(&rows, user_id, &roles)))
}

fn selected_for_caller(
    rows: &[DeviceInviteRow],
    user: ObjectId,
    roles: &[ObjectId],
) -> DeviceAccessFeatures {
    let mut selected = DeviceAccessFeatures::none();
    if rows
        .iter()
        .any(|row| row.revocation_pending || row.activation_pending)
    {
        return selected;
    }
    for row in rows.iter().filter(|r| {
        r.inviter_user_id == user || roles.iter().any(|id| r.allow_role_ids.contains(id))
    }) {
        let f = row.features.unwrap_or_else(DeviceAccessFeatures::all);
        selected.desktop_view |= f.desktop_view;
        selected.desktop_control |= f.desktop_control;
        selected.clipboard |= f.clipboard;
        selected.files |= f.files;
        selected.ssh |= f.ssh;
        selected.exec |= f.exec;
        selected.rdp |= f.rdp;
        selected.network |= f.network;
    }
    selected
}

/// An accepted, live invitation already consents to its assigned capabilities.
/// This only fills an unset policy; callers must still enforce all feature,
/// identity, organization and local-agent gates. Ordinary devices stay attended.
pub async fn invite_consent_mode(
    state: &FleetState,
    agent_id: ObjectId,
    user: ObjectId,
    configured: Option<ConsentMode>,
) -> Result<ConsentMode, ApiError> {
    if let Some(mode) = configured {
        return Ok(mode);
    }
    if host_revocation_pending(state, agent_id).await? {
        return Ok(ConsentMode::Prompt);
    }
    let rows = live_for_agent(state, agent_id).await?;
    if rows.is_empty() {
        return Ok(ConsentMode::Prompt);
    }
    let roles = state
        .tenants
        .member_role_ids(rows[0].tenant_id, user)
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Could not verify invitation roles".into()))?;
    Ok(
        if selected_for_caller(&rows, user, &roles) != DeviceAccessFeatures::none() {
            ConsentMode::Auto
        } else {
            ConsentMode::Prompt
        },
    )
}

pub async fn allows_feature(
    state: &FleetState,
    agent_id: ObjectId,
    user: ObjectId,
    feature: DeviceAccessFeature,
) -> Result<bool, ApiError> {
    Ok(features_for_caller(state, agent_id, user)
        .await?
        .is_none_or(|f| f.allows(feature)))
}

/// Proof-linked enrollments share a physical host. Freeze the whole family
/// until close/ack, including its primary service and other invitations.
/// One bounded connected component over target and verified host identities.
/// The same closure drives freeze, epoch fencing, and every refan.
async fn host_family(
    state: &FleetState,
    agent_id: ObjectId,
) -> Result<(Vec<(ObjectId, ObjectId)>, Vec<DeviceInviteRow>), ApiError> {
    use futures::TryStreamExt;
    let agent = match state.agents.base.find_by_id(agent_id).await {
        Ok(agent) => agent,
        Err(meshharbor_services::dao::base::DaoError::NotFound) => {
            return Ok((Vec::new(), Vec::new()));
        }
        Err(e) => return Err(e.into()),
    };
    let mut identities = vec![(agent_id, agent.tenant_id)];
    loop {
        let mut scopes = Vec::new();
        for (id, tid) in &identities {
            scopes.push(doc! { "agent_id": id, "tenant_id": tid });
            scopes.push(doc! { "hosts": { "$elemMatch": { "agent_id": id, "tenant_id": tid } } });
        }
        let rows: Vec<DeviceInviteRow> = storage(
            storage(
                coll!(state)
                    .find(doc! { "$or": scopes })
                    .sort(doc! { "_id": 1 })
                    .limit(101)
                    .await,
            )?
            .try_collect()
            .await,
        )?;
        if rows.len() > 100 {
            return Err(ApiError::ServiceUnavailable(
                "Host proof component exceeds verification bound".into(),
            ));
        }
        let before = identities.len();
        for row in &rows {
            if let Some(id) = row.agent_id
                && !identities.contains(&(id, row.tenant_id))
            {
                identities.push((id, row.tenant_id));
            }
            for host in &row.hosts {
                if !identities.contains(&(host.agent_id, host.tenant_id)) {
                    identities.push((host.agent_id, host.tenant_id));
                }
            }
        }
        if identities.len() > 100 {
            return Err(ApiError::ServiceUnavailable(
                "Host proof component exceeds verification bound".into(),
            ));
        }
        if identities.len() == before {
            return Ok((identities, rows));
        }
    }
}

async fn host_scopes(
    state: &FleetState,
    agent_id: ObjectId,
) -> Result<Vec<bson::Document>, ApiError> {
    let (identities, _) = host_family(state, agent_id).await?;
    let mut scopes = Vec::new();
    for (id, tid) in identities {
        scopes.push(doc! { "agent_id": id, "tenant_id": tid });
        scopes.push(doc! { "hosts": { "$elemMatch": { "agent_id": id, "tenant_id": tid } } });
    }
    Ok(scopes)
}

async fn host_change_exists(
    state: &FleetState,
    agent_id: ObjectId,
    since: Option<DateTime>,
) -> Result<bool, ApiError> {
    let scopes = host_scopes(state, agent_id).await?;
    if scopes.is_empty() {
        return Ok(false);
    }
    let change = match since {
        Some(at) => {
            doc! { "$or": [{ "revocation_pending": true }, {"activation_pending": true}, { "features_updated_at": { "$gte": at } }] }
        }
        None => doc! { "$or": [{"revocation_pending":true},{"activation_pending":true}] },
    };
    Ok(storage(
        coll!(state)
            .find_one(doc! { "$and": [{ "$or": scopes }, change] })
            .await,
    )?
    .is_some())
}

/// Opaque revision fence, independent of clocks on different API pods.
pub async fn authorization_epoch(
    state: &FleetState,
    agent_id: ObjectId,
) -> Result<String, ApiError> {
    use futures::TryStreamExt;
    let scopes = host_scopes(state, agent_id).await?;
    if scopes.is_empty() {
        return Err(ApiError::NotFound("No such device".into()));
    }
    let rows: Vec<DeviceInviteRow> = storage(
        storage(
            coll!(state)
                .find(doc! { "$or": scopes })
                .sort(doc! { "_id": 1 })
                .limit(101)
                .await,
        )?
        .try_collect()
        .await,
    )?;
    if rows.len() > 100 {
        return Err(ApiError::ServiceUnavailable(
            "Host proof family exceeds epoch bound".into(),
        ));
    }
    let now = DateTime::now();
    let snapshot: Vec<_> = rows.iter().map(|row| json!({
        "id": row.id.to_hex(), "revision": row.features_revision, "pending": row.revocation_pending, "activation_pending": row.activation_pending,
        "active": row.state == STATE_ENROLLED && row.access_until > now,
        "hosts": row.hosts.iter().map(|host| (host.agent_id.to_hex(), host.tenant_id.to_hex())).collect::<Vec<_>>()
    })).collect();
    Ok(hash_secret(
        "device-access-epoch",
        &serde_json::to_string(&snapshot)
            .map_err(|_| ApiError::Internal("Could not encode authorization epoch".into()))?,
    ))
}

pub async fn stamp_service_epoch(
    state: &FleetState,
    collection: &str,
    id_field: &str,
    id: &str,
    epoch: &str,
) -> Result<(), ApiError> {
    let mut filter = doc! {};
    filter.insert(id_field, id);
    let result = storage(
        state
            .core
            .db
            .collection::<bson::Document>(collection)
            .update_one(filter, doc! { "$set": { "device_access_epoch": epoch } })
            .await,
    )?;
    if result.matched_count != 1 {
        return Err(ApiError::Conflict("Service request disappeared".into()));
    }
    Ok(())
}

pub async fn stored_service_epoch_current(
    state: &FleetState,
    agent_id: ObjectId,
    collection: &str,
    id_field: &str,
    id: &str,
) -> Result<bool, ApiError> {
    if host_revocation_pending(state, agent_id).await? {
        return Ok(false);
    }
    let mut filter = doc! { "agent_id": agent_id };
    filter.insert(id_field, id);
    let row = storage(
        state
            .core
            .db
            .collection::<bson::Document>(collection)
            .find_one(filter)
            .await,
    )?;
    let Some(row) = row else {
        return Ok(false);
    };
    if let Ok(epoch) = row.get_str("device_access_epoch") {
        return Ok(epoch == authorization_epoch(state, agent_id).await?);
    }
    // Backward-compatible ordinary requests may predate epochs. Once a host
    // selection changed, no unversioned request may pass, irrespective of clocks.
    let scopes = host_scopes(state, agent_id).await?;
    if scopes.is_empty() {
        return Ok(false);
    }
    Ok(storage(coll!(state).find_one(doc! { "$and": [{ "$or": scopes }, { "features_updated_at": { "$exists": true } }] }).await)?.is_none())
}

pub async fn host_revocation_pending(
    state: &FleetState,
    agent_id: ObjectId,
) -> Result<bool, ApiError> {
    host_change_exists(state, agent_id, None).await
}

/// Network projection can install only the newly selected (already closed)
/// profile during activation. Application grants remain frozen by BOTH phases.
pub async fn host_network_revocation_pending(
    state: &FleetState,
    agent_id: ObjectId,
) -> Result<bool, ApiError> {
    let scopes = host_scopes(state, agent_id).await?;
    if scopes.is_empty() {
        return Ok(false);
    }
    Ok(storage(
        coll!(state)
            .find_one(doc! {"$and":[{"$or":scopes},{"revocation_pending":true}]})
            .await,
    )?
    .is_some())
}

/// Reject work authorized before any proof-linked host capability change,
/// including inserts racing cancellation and service claims on another pod.
pub async fn service_request_is_current(
    state: &FleetState,
    agent_id: ObjectId,
    authorized_at: DateTime,
) -> Result<bool, ApiError> {
    Ok(!host_change_exists(state, agent_id, Some(authorized_at)).await?)
}

/// Re-fan all proof-linked enrollments before acknowledging a selection/ack.
pub async fn refan_host_family(state: &FleetState, agent_id: ObjectId) -> Result<(), ApiError> {
    let (identities, _) = host_family(state, agent_id).await?;
    for (id, tid) in identities {
        match state.agents.find_live_in_tenant(tid, id).await {
            Err(meshharbor_services::dao::base::DaoError::NotFound) => continue,
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        {
            state
                .hooks
                .agent_access_changed(tid, id)
                .await
                .map_err(|_| {
                    ApiError::ServiceUnavailable(
                        "Capabilities saved but host-family network refresh failed".into(),
                    )
                })?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureRevision {
    expected_revision: u32,
}

/// An anchored SYSTEM service validates a local close request with its own
/// credential. A worker/user-supplied URL or invitation is never authority.
pub async fn service_features_pending(
    State(state): State<FleetState>,
    service: crate::auth_agent::AuthAgentService,
    Path(invite_id): Path<String>,
    Query(query): Query<FeatureRevision>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    let id = ObjectId::parse_str(&invite_id)
        .map_err(|_| ApiError::NotFound("No pending host capability change".into()))?;
    let found = storage(
        coll!(state)
            .find_one(doc! {
                "_id": id, "$or": [
                    { "agent_id": service.agent_id, "tenant_id": service.tenant_id },
                    { "hosts": { "$elemMatch": { "agent_id": service.agent_id, "tenant_id": service.tenant_id } } }
                ],
                "features_revision": i64::from(query.expected_revision),
                "$and": [{"$or":[{"revocation_pending":true},{"activation_pending":true}]}],
            })
            .await,
    )?;
    let row =
        found.ok_or_else(|| ApiError::NotFound("No pending host capability change".into()))?;
    Ok(Json(
        json!({ "invite_id": invite_id, "features_revision": query.expected_revision,
        "revocation_pending": true, "agent_id": row.agent_id.map(|id| id.to_hex()), "tenant_id": row.tenant_id.to_hex(),
        "host_agent_id": service.agent_id.to_hex(), "host_tenant_id": service.tenant_id.to_hex() }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectFeatures {
    features: DeviceAccessFeatures,
    expected_revision: u32,
}

/// Only the bound device may change its accepted ceiling; not the inviter or
/// an organization administrator. Revision fences two stale settings pages.
pub async fn self_features(
    State(state): State<FleetState>,
    agent: crate::auth_agent::AuthAgent,
    Path(invite_id): Path<String>,
    Json(body): Json<SelectFeatures>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    enabled(&state)?;
    if !body.features.valid() || body.expected_revision == u32::MAX {
        return Err(ApiError::BadRequest(
            "Invalid feature selection or revision".into(),
        ));
    }
    let id = ObjectId::parse_str(&invite_id)
        .map_err(|_| ApiError::BadRequest("Invalid invitation id".into()))?;
    let now = DateTime::now();
    let mut filter = doc! { "_id": id, "agent_id": agent.agent_id, "tenant_id": agent.tenant_id,
    "state": STATE_ENROLLED, "access_until": { "$gt": now } };
    if body.expected_revision == 0 {
        filter.insert(
            "$or",
            vec![
                doc! { "features_revision": 0_i64 },
                doc! { "features_revision": { "$exists": false } },
            ],
        );
    } else {
        filter.insert("features_revision", i64::from(body.expected_revision));
    }
    let changed = storage(coll!(state).update_one(filter, doc! { "$set": {
        "features": bson::to_bson(&body.features).map_err(|_| ApiError::Internal("Invalid features".into()))?,
        "features_revision": i64::from(body.expected_revision) + 1,
        "revocation_pending": true, "activation_pending": false,
        "features_updated_at": now,
    }}).await)?;
    if changed.modified_count != 1 {
        return Err(ApiError::Conflict(
            "Invitation changed or is not held by this device; reload".into(),
        ));
    }
    // Cancel stored unconsumed work; a concurrent insert is fenced again at
    // the service claim by its pre-authorization timestamp.
    for collection in ["exec_pending", "ssh_pending"] {
        storage(state.core.db.collection::<bson::Document>(collection).update_many(
            doc! { "agent_id": agent.agent_id, "tenant_id": agent.tenant_id, "state": "pending" },
            doc! { "$set": { "state": "cancelled" } },
        ).await)?;
    }
    // Existing desktop/file scopes must not retain an obsolete ceiling.
    state.rc_hub.end_agent_sessions(agent.agent_id);
    refan_host_family(&state, agent.agent_id).await?;
    // New authorization is restricted now; do not claim that old SSH/exec
    // processes have ended without a device-side close acknowledgement.
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "invite_id": invite_id, "features": body.features,
            "features_revision": body.expected_revision + 1,
            "revocation_pending": true,
            "message": "New authorization updated; termination of existing sessions is not yet confirmed"
        })),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeFeatures {
    expected_revision: u32,
    closed: bool,
}

/// The authenticated host acknowledges its completed local close barrier.
/// Expiry cannot restore an invitation: it only permits finishing cleanup.
pub async fn self_features_ack(
    State(state): State<FleetState>,
    host: crate::auth_agent::AuthAgent,
    Path(invite_id): Path<String>,
    Json(body): Json<AcknowledgeFeatures>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    if !body.closed {
        return Err(ApiError::BadRequest(
            "Existing sessions must be confirmed closed".into(),
        ));
    }
    let id = ObjectId::parse_str(&invite_id)
        .map_err(|_| ApiError::NotFound("No matching host capability change".into()))?;
    let authority = doc! { "_id": id, "$or": [
        { "agent_id": host.agent_id, "tenant_id": host.tenant_id },
        { "hosts": { "$elemMatch": { "agent_id": host.agent_id, "tenant_id": host.tenant_id } } }
    ] };
    let row = storage(coll!(state).find_one(authority.clone()).await)?
        .ok_or_else(|| ApiError::NotFound("No matching host capability change".into()))?;
    if row.features_revision != body.expected_revision {
        return Err(ApiError::Conflict(
            "Capability revision changed; close the current revision first".into(),
        ));
    }
    let target = row
        .agent_id
        .ok_or_else(|| ApiError::Conflict("Invitation is not enrolled".into()))?;
    // Complete a strict frozen-map pass before lifting the persisted barrier.
    // Retry reads authoritative storage, never a stale success cached in memory.
    refan_host_family(&state, target).await?;
    if row.revocation_pending {
        let mut filter = authority.clone();
        filter.insert("features_revision", i64::from(body.expected_revision));
        filter.insert("revocation_pending", true);
        let staged = storage(coll!(state).update_one(filter, doc! {"$set": {
            "revocation_pending":false,"activation_pending":true,
            "revocation_closed_revision": i64::from(body.expected_revision)
        }, "$unset":{"revocation_acked_revision":"","revocation_acked_at":"","revocation_acked_by_agent":""}}).await)?;
        if staged.modified_count != 1 {
            return Err(ApiError::Conflict(
                "Capability revision changed during close acknowledgement".into(),
            ));
        }
    } else if !row.activation_pending {
        let mut acked = authority.clone();
        acked.insert("features_revision", i64::from(body.expected_revision));
        acked.insert("revocation_pending", false);
        acked.insert("activation_pending", doc! {"$ne":true});
        acked.insert(
            "revocation_acked_revision",
            i64::from(body.expected_revision),
        );
        if storage(
            state
                .core
                .db
                .collection::<bson::Document>(COLLECTION)
                .find_one(acked)
                .await,
        )?
        .is_none()
        {
            return Err(ApiError::Conflict(
                "Capability revision changed or was never acknowledged".into(),
            ));
        }
    }
    if row.revocation_pending || row.activation_pending {
        // Failure at any read/fan/publication leaves activation_pending durable.
        // No compensation write is required to preserve the retry barrier.
        refan_host_family(&state, target).await?;
        let mut finish = authority.clone();
        finish.insert("features_revision", i64::from(body.expected_revision));
        finish.insert("revocation_pending", false);
        finish.insert("activation_pending", true);
        finish.insert(
            "revocation_closed_revision",
            i64::from(body.expected_revision),
        );
        let committed = storage(coll!(state).update_one(finish,doc! {"$set": {
            "activation_pending":false,"revocation_acked_revision":i64::from(body.expected_revision),
            "revocation_acked_at":DateTime::now(),"revocation_acked_by_agent":host.agent_id
        }}).await)?;
        if committed.modified_count != 1 {
            return Err(ApiError::Conflict(
                "Capability revision changed during activation".into(),
            ));
        }
    }
    if row.access_until <= DateTime::now() && row.state != STATE_ENDED {
        end_invite_by(&state, &row, REASON_EXPIRED, None).await?;
        // A reaper may have won the end CAS after ACK; await settlement here
        // too so enrollment_removed describes this response, not a future task.
        settle_device(&state, row.tenant_id, target, REASON_EXPIRED).await?;
    }
    let enrollment_removed = match state.agents.base.find_by_id(target).await {
        Ok(agent) => agent.deleted_at.is_some(),
        Err(meshharbor_services::dao::base::DaoError::NotFound) => true,
        Err(e) => return Err(e.into()),
    };
    Ok(Json(
        json!({ "invite_id": invite_id, "features_revision": body.expected_revision,
        "revocation_pending": false, "enrollment_removed": enrollment_removed }),
    ))
}

pub const REASON_MADE_PERMANENT: &str = "temporary_made_permanent";

/// The device stays, as an ordinary one: end EVERY live invitation of it
/// WITHOUT the removal (the network module unmarks its node and re-fans).
/// Returns how many ended.
pub async fn end_keeping_device(
    state: &FleetState,
    agent_id: ObjectId,
    by: ObjectId,
) -> Result<u64, ApiError> {
    // An inviter/admin cannot erase a host-selected ceiling by converting
    // the enrollment. The host can leave and personally sign in instead.
    if storage(
        coll!(state)
            .find_one(doc! {
                "agent_id": agent_id, "state": STATE_ENROLLED,
                "features": { "$ne": bson::Bson::Null, "$exists": true },
            })
            .await,
    )?
    .is_some()
    {
        return Err(ApiError::Forbidden("A host-selected device must leave its invitation and sign in personally before becoming permanent".into()));
    }
    let now = DateTime::now();
    let r = storage(
        coll!(state)
            .update_many(
                doc! { "agent_id": agent_id, "state": STATE_ENROLLED },
                doc! { "$set": {
                    "state": STATE_ENDED,
                    "ended_at": now,
                    "end_reason": REASON_MADE_PERMANENT,
                    "ended_by": by,
                } },
            )
            .await,
    )?;
    Ok(r.modified_count)
}

/// The device left by itself (`self/unenroll`, already removed): end every
/// invitation it held.
pub async fn mark_left(state: &FleetState, agent_id: ObjectId) {
    let now = DateTime::now();
    if let Err(e) = coll!(state)
        .update_many(
            doc! { "agent_id": agent_id, "state": { "$ne": STATE_ENDED } },
            doc! { "$set": {
                "state": STATE_ENDED,
                "ended_at": now,
                "end_reason": REASON_LEFT,
            } },
        )
        .await
    {
        tracing::warn!(agent = %agent_id, error = %e, "device-invite: could not mark the invitations left");
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
    if storage(state.core.db.collection::<bson::Document>("agents").find_one(doc! {
        "_id": agent_id, "personal_access_owner_id": { "$exists": true, "$ne": bson::Bson::Null }
    }).await)?.is_some() {
        return Err(ApiError::Forbidden("A personal device must accept invitations on the host; an administrator cannot convert its owner-only profile".into()));
    }
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
        features: None,
        features_revision: 0,
        revocation_pending: false,
        activation_pending: false,
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
        attached: false,
        device_proof_hash: None,
        hosts: Vec::new(),
        removal_pending: false,
        gpu_server: agent.gpu_server,
    };
    storage(coll!(state).insert_one(&row).await)?;
    tracing::info!(invite = %row.id, tenant = %tenant_id, agent = %agent_id, by = %by,
        "device-invite: existing device made temporary");
    Ok(row)
}

/// `GET /api/agent/self/temporary` — the device's own view: is it temporary,
/// until when, on whose invitations. The tray shows it; a renewal reaches the
/// device through it. `access_until_ms` / `inviter` are the latest deadline and
/// the first inviter (what a pre-multi-invitation device reads).
pub async fn self_view(
    State(state): State<FleetState>,
    agent: crate::auth_agent::AuthAgent,
) -> Result<Json<Value>, ApiError> {
    if !state.settings.auth.native_device_invite_enabled {
        return Ok(Json(json!({ "temporary": false })));
    }
    use futures::TryStreamExt;
    // Expired pending rows are cleanup authority only, never access grants.
    let rows: Vec<DeviceInviteRow> = storage(
        storage(
            coll!(state)
                .find(doc! {
                    "agent_id": agent.agent_id, "$or": [
                        { "state": STATE_ENROLLED, "access_until": { "$gt": DateTime::now() } },
                        { "revocation_pending": true }, { "activation_pending": true }
                    ]
                })
                .sort(doc! { "created_at": 1 })
                .limit(100)
                .await,
        )?
        .try_collect()
        .await,
    )?;

    // No live grant but an end still settling: still temporary (the device
    // keeps its marker, so the removal that follows is a planned end).
    let Some(g) = (match TemporaryGrant::of(&rows) {
        Some(g) => Some(g),
        None => grant_for_agent(&state, agent.agent_id).await?,
    }) else {
        return Ok(Json(json!({ "temporary": false })));
    };
    let org = org_display(&state, agent.tenant_id).await;
    let mut grants = Vec::new();
    for r in &rows {
        grants.push(json!({
            "invite_id": r.id.to_hex(),
            "features": r.features,
            "features_revision": r.features_revision,
        "revocation_pending": r.revocation_pending || r.activation_pending,
        "activation_pending": r.activation_pending,
            "inviter": inviter_display(&state, r.inviter_user_id).await,
            "org": org,
            "access_until_ms": r.access_until.timestamp_millis(),
        }));
    }
    Ok(Json(json!({
        "temporary": true,
        "access_until_ms": g.access_until.timestamp_millis(),
        "inviter": inviter_display(&state, g.inviter_user_id).await,
        "org": org,
        "grants": grants,
    })))
}

/// `POST /api/agent/self/temporary/{invite_id}/leave` — the person at the
/// machine ends ONE invitation. The device stays while others are live.
pub async fn self_leave(
    State(state): State<FleetState>,
    agent: crate::auth_agent::AuthAgent,
    Path(invite_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    let iid =
        ObjectId::parse_str(&invite_id).map_err(|_| ApiError::BadRequest("Invalid id".into()))?;
    let Some(row) = storage(
        coll!(state)
            .find_one(doc! { "_id": iid, "agent_id": agent.agent_id, "state": STATE_ENROLLED })
            .await,
    )?
    else {
        return Err(ApiError::NotFound(
            "No such invitation on this device".into(),
        ));
    };
    let removed = end_invite(&state, &row, REASON_LEFT).await?;
    tracing::info!(invite = %iid, agent = %agent.agent_id, removed, "device-invite: the device left one invitation");
    Ok(Json(json!({ "ended": true, "device_removed": removed })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofItem {
    invite_id: String,
    proof: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    proofs: Vec<ProofItem>,
}

/// `POST /api/agent/self/link` — an ORDINARY device presents the proofs of
/// the invitations its machine accepted (now or in the past): its own
/// organization's admins may then see them. Only a proof links; idempotent.
pub async fn self_link(
    State(state): State<FleetState>,
    agent: crate::auth_agent::AuthAgent,
    Json(body): Json<Link>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    if body.proofs.len() > MAX_PROOFS {
        return Err(ApiError::BadRequest("Too many proofs".into()));
    }
    if agent.agent.ephemeral || grant_for_agent(&state, agent.agent_id).await?.is_some() {
        return Err(ApiError::Forbidden(
            "Only a device of its own organization links invitations".into(),
        ));
    }
    let mut linked = 0u64;
    let link = storage(bson::to_bson(&HostLink {
        tenant_id: agent.tenant_id,
        agent_id: agent.agent_id,
        linked_at: DateTime::now(),
    }))?;
    for p in &body.proofs {
        let Ok(iid) = ObjectId::parse_str(&p.invite_id) else {
            continue;
        };
        if p.proof.len() != 64 {
            continue;
        }
        let r = storage(
            coll!(state)
                .update_one(
                    doc! {
                        "_id": iid,
                        "device_proof_hash": hash_secret("device-invite-proof", &p.proof),
                        "hosts.agent_id": { "$ne": agent.agent_id },
                    },
                    doc! { "$push": { "hosts": link.clone() } },
                )
                .await,
        )?;
        linked += r.modified_count;
    }
    if linked > 0 {
        tracing::info!(agent = %agent.agent_id, tenant = %agent.tenant_id, linked,
            "device-invite: the device linked the invitations its machine accepted");
    }
    // A newly proven primary host can already have open overlay sessions.
    // Reconcile pending deny-all marks even on an idempotent link retry.
    if !body.proofs.is_empty() {
        refan_host_family(&state, agent.agent_id).await?;
    }
    Ok(Json(json!({ "linked": linked })))
}

// ─── the device owner's view ────────────────────────────────────────────────

fn host_view(
    r: &DeviceInviteRow,
    tid: ObjectId,
    inviter: String,
    org: String,
    names: &HashMap<ObjectId, String>,
) -> Value {
    let host = r.hosts.iter().find(|h| h.tenant_id == tid);
    json!({
        "id": r.id.to_hex(),
        "features": r.features,
        "features_revision": r.features_revision,
        "revocation_pending": r.revocation_pending || r.activation_pending,
        "activation_pending": r.activation_pending,
        "host_agent_id": host.map(|h| h.agent_id.to_hex()),
        "host_device_name": host.and_then(|h| names.get(&h.agent_id).cloned()),
        "inviter": inviter,
        "org": org,
        "state": r.state,
        "access_until_ms": r.access_until.timestamp_millis(),
        "created_at_ms": r.created_at.timestamp_millis(),
        "redeemed_at_ms": r.redeemed_at.map(|t| t.timestamp_millis()),
        "ended_at_ms": r.ended_at.map(|t| t.timestamp_millis()),
        "end_reason": r.end_reason,
        "renewals": r.renewals.iter().map(|x| json!({
            "at_ms": x.at.timestamp_millis(),
            "previous_until_ms": x.previous_until.timestamp_millis(),
            "until_ms": x.until.timestamp_millis(),
        })).collect::<Vec<_>>(),
    })
}

/// `GET /api/tenant/{tenant_id}/device-grants` — the invitations this
/// organization's devices accepted from elsewhere (as their machines proved),
/// current and past. Never shows the inviter's private label or ids.
pub async fn host_list(
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
                .find(doc! { "hosts.tenant_id": tid })
                .sort(doc! { "created_at": -1 })
                .limit(500)
                .await,
        )?
        .try_collect()
        .await,
    )?;
    let mut people: HashMap<ObjectId, String> = HashMap::new();
    let mut orgs: HashMap<ObjectId, String> = HashMap::new();
    let mut names: HashMap<ObjectId, String> = HashMap::new();
    let mut items = Vec::new();
    for r in &rows {
        if let std::collections::hash_map::Entry::Vacant(e) = people.entry(r.inviter_user_id) {
            e.insert(inviter_display(&state, r.inviter_user_id).await);
        }
        if let std::collections::hash_map::Entry::Vacant(e) = orgs.entry(r.tenant_id) {
            e.insert(org_display(&state, r.tenant_id).await);
        }
        if let Some(h) = r.hosts.iter().find(|h| h.tenant_id == tid)
            && !names.contains_key(&h.agent_id)
            && let Ok(a) = state.agents.base.find_by_id(h.agent_id).await
        {
            names.insert(h.agent_id, a.name);
        }
        items.push(host_view(
            r,
            tid,
            people[&r.inviter_user_id].clone(),
            orgs[&r.tenant_id].clone(),
            &names,
        ));
    }
    Ok(Json(json!({ "items": items })))
}

/// `DELETE /api/tenant/{tenant_id}/device-grants/{id}` — the device's owner
/// ends an invitation its machine accepted. The owner's word wins.
pub async fn host_end(
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
            .find_one(doc! { "_id": iid, "hosts.tenant_id": tid })
            .await,
    )?
    else {
        return Err(ApiError::NotFound("No such invitation".into()));
    };
    let removed = end_invite_by(&state, &row, REASON_OWNER_ENDED, Some(auth.user_id)).await?;
    tracing::info!(invite = %iid, host_tenant = %tid, user = %auth.user_id, removed,
        "device-invite: ended by the device's owner");
    Ok(Json(json!({ "ended": true, "device_removed": removed })))
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
        // Keep the host's cleanup credential until its recorded close/ack
        // finishes. Authorization already fails closed at the expired deadline.
        if expired && (row.revocation_pending || row.activation_pending) {
            continue;
        }

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
    // Ends whose device was not settled (a failed removal or re-fan).
    let pending: Vec<DeviceInviteRow> = coll!(state)
        .find(doc! { "state": STATE_ENDED, "removal_pending": true })
        .limit(100)
        .await?
        .try_collect()
        .await?;
    for row in pending {
        let Some(aid) = row.agent_id else { continue };
        let reason = row
            .end_reason
            .clone()
            .unwrap_or_else(|| REASON_REMOVED.into());
        if let Err(e) = settle_device(state, row.tenant_id, aid, &reason).await {
            tracing::warn!(invite = %row.id, error = ?e, "device-invite: device still not settled; retrying next cycle");
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
            ssh_port: None,
            rdp_port: None,
            feature_grants: Vec::new(),
            invite_id: ObjectId::new(),
            inviter_user_id: inviter,
            also_inviter_user_ids: Vec::new(),
            allow_role_ids: vec![role],
            access_until: DateTime::now(),
        };
        assert!(g.allows(Some(inviter), &[]));
        assert!(g.allows(Some(ObjectId::new()), &[role]));
        assert!(!g.allows(Some(ObjectId::new()), &[ObjectId::new()]));
        assert!(!g.allows(None, &[]));
    }

    fn row(inviter: ObjectId, roles: Vec<ObjectId>, until_ms: i64) -> DeviceInviteRow {
        DeviceInviteRow {
            id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            inviter_user_id: inviter,
            label: String::new(),
            allow_role_ids: roles,
            features: None,
            features_revision: 0,
            revocation_pending: false,
            activation_pending: false,
            code_hash: String::new(),
            state: STATE_ENROLLED.into(),
            access_until: DateTime::from_millis(until_ms),
            created_at: DateTime::now(),
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
            attached: false,
            device_proof_hash: None,
            hosts: Vec::new(),
            removal_pending: false,
            gpu_server: false,
        }
    }

    #[test]
    fn capability_union_never_borrows_another_inviters_features() {
        let alice = ObjectId::new();
        let bob = ObjectId::new();
        let role = ObjectId::new();
        let mut a = row(alice, vec![], i64::MAX);
        let mut b = row(bob, vec![role], i64::MAX);
        a.features = Some(DeviceAccessFeatures {
            ssh: true,
            ..DeviceAccessFeatures::none()
        });
        b.features = Some(DeviceAccessFeatures {
            exec: true,
            ..DeviceAccessFeatures::none()
        });
        let rows = vec![a, b];
        let f = selected_for_caller(&rows, alice, &[]);
        assert!(f.ssh && !f.exec && !f.network);
        let f = selected_for_caller(&rows, bob, &[]);
        assert!(!f.ssh && f.exec);
        let f = selected_for_caller(&rows, ObjectId::new(), &[role]);
        assert!(!f.ssh && f.exec);
        assert_eq!(
            selected_for_caller(&rows, ObjectId::new(), &[]),
            DeviceAccessFeatures::none()
        );
        let grants = TemporaryGrant::of(&rows).unwrap().feature_grants;
        assert_eq!(grants[0].inviter_user_id, alice);
        assert_eq!(grants[1].features, rows[1].features);
    }

    #[test]
    fn several_invitations_admit_the_union_and_keep_the_latest_deadline() {
        let (a, b, role) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let g = TemporaryGrant::of(&[
            row(a, vec![], 1_000),
            row(b, vec![role], 5_000),
            row(a, vec![], 2_000),
        ])
        .unwrap();
        assert_eq!(g.inviter_user_id, a);
        assert_eq!(g.also_inviter_user_ids, vec![b]);
        assert_eq!(g.access_until.timestamp_millis(), 5_000);
        assert!(g.allows(Some(a), &[]) && g.allows(Some(b), &[]));
        assert!(g.allows(Some(ObjectId::new()), &[role]));
        assert!(!g.allows(Some(ObjectId::new()), &[]));
        assert!(TemporaryGrant::of(&[]).is_none());
    }

    #[test]
    fn a_settling_device_admits_nobody() {
        let g = TemporaryGrant {
            ssh_port: None,
            rdp_port: None,
            feature_grants: Vec::new(),
            invite_id: ObjectId::new(),
            inviter_user_id: NOBODY,
            also_inviter_user_ids: Vec::new(),
            allow_role_ids: Vec::new(),
            access_until: DateTime::now(),
        };
        assert!(!g.allows(Some(NOBODY), &[]));
        assert!(!g.allows(Some(ObjectId::new()), &[ObjectId::new()]));
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
