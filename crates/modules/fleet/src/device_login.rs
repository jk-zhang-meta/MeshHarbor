// SPDX-License-Identifier: AGPL-3.0-only
//! Device login — the `mh login` flow (RFC 8628 device authorization with a
//! PKCE binding).
//!
//! 1. A device that is not enrolled yet starts a request (anonymous). It gets
//!    a high-entropy `device_code` it never shows, and a human `user_code` it
//!    shows next to a link to the approval page.
//! 2. A signed-in person opens that page, sees what the device claims to be
//!    and where the request came from, picks one of their organizations, and
//!    approves or denies.
//! 3. The device polls `exchange` with its `device_code` and the PKCE
//!    verifier. On approval it receives a STANDARD single-use enrollment
//!    token, minted exactly as `POST /tenant/{id}/agent/enroll-token` mints
//!    one: under the APPROVER's identity, after the same `MANAGE_AGENTS`
//!    check. Enrollment itself then runs through the unchanged
//!    `/api/agent/enroll`.
//!
//! What this flow can never do: approve on the device's word (approval needs
//! a session plus `MANAGE_AGENTS` in the chosen org), hand the token to
//! anyone but the holder of both the device code and the verifier, or hand
//! it out twice (`approved → consumed` is a compare-and-set). Codes are
//! stored only as hashes; the token itself is never stored.
use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::role::permissions;
use meshharbor_services::dao::native_ssh_authorization::{
    code_challenge, hash_secret, random_code,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::{IpAddr, SocketAddr};

use crate::FleetState;

/// Mongo collection; its indexes are declared in `FleetModule::indexes`.
pub const COLLECTION: &str = "device_login_requests";
/// How long a request may wait for its approval and exchange.
pub const REQUEST_TTL_SECS: i64 = 600;
/// The enrollment token handed out on exchange (same lifetime as an
/// admin-issued one).
const ENROLLMENT_TTL_SECS: u64 = 600;
const MAX_PENDING_PER_CLIENT: u64 = 5;
const MAX_PENDING_TOTAL: u64 = 1000;
/// A device polls every `INTERVAL_SECS`; a poller that never stops is denied.
const MAX_POLLS: i32 = 400;
const INTERVAL_SECS: u64 = 2;
/// RFC 8628 §6.1 — consonants only: no vowels (no words), no 0/O/1/I.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 10;

fn default_purpose() -> String {
    "enrollment".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Enrollment,
    UserSession,
    EnrollmentAndUserSession,
}

impl Purpose {
    fn parse(raw: Option<&str>) -> Option<Self> {
        match raw.unwrap_or("enrollment") {
            "enrollment" => Some(Self::Enrollment),
            "user_session" => Some(Self::UserSession),
            "enrollment_and_user_session" => Some(Self::EnrollmentAndUserSession),
            _ => None,
        }
    }
    fn wire(self) -> &'static str {
        match self {
            Self::Enrollment => "enrollment",
            Self::UserSession => "user_session",
            Self::EnrollmentAndUserSession => "enrollment_and_user_session",
        }
    }
    fn needs_enrollment(self) -> bool {
        self != Self::UserSession
    }
    fn needs_user_session(self) -> bool {
        self != Self::Enrollment
    }
    fn scopes(self) -> &'static [&'static str] {
        match self {
            Self::Enrollment => &["enrollment"],
            Self::UserSession => &["user_session"],
            Self::EnrollmentAndUserSession => &["enrollment", "user_session"],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLoginRow {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    #[serde(default = "default_purpose")]
    pub purpose: String,
    pub user_code_hash: String,
    pub device_code_hash: String,
    pub code_challenge: String,
    pub device_name: String,
    pub device_os: String,
    pub client_hash: String,
    /// What the approval page shows of the requester's address (last octet
    /// or the low 80 bits masked) — enough to tell "my home" from "abroad".
    pub client_display: String,
    /// `pending` → `approved` | `denied` → (`approved` only) `consumed`.
    pub state: String,
    pub tenant_id: Option<ObjectId>,
    pub approved_by: Option<ObjectId>,
    /// Server-recorded provenance of the enrollment credential. Never supplied
    /// by an enrollment request or inferred from its self-reported machine id.
    #[serde(default)]
    pub enrollment_jti: Option<String>,
    pub polls: i32,
    pub created_at: DateTime,
    pub expires_at: DateTime,
    pub decided_at: Option<DateTime>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    device_name: String,
    device_os: String,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    purpose: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    user_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    user_code: String,
    approve: bool,
    tenant_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    device_code: String,
    code_verifier: String,
}

macro_rules! coll {
    ($state:expr) => {
        $state.core.db.collection::<DeviceLoginRow>(COLLECTION)
    };
}

fn enabled(state: &FleetState) -> Result<(), ApiError> {
    if state.settings.auth.native_device_login_enabled {
        Ok(())
    } else {
        Err(ApiError::ServiceUnavailable(
            "Device login is disabled on this server".into(),
        ))
    }
}

fn storage<T, E>(r: Result<T, E>) -> Result<T, ApiError> {
    // Driver errors can carry query fields (hashes); never echo them.
    r.map_err(|_| ApiError::ServiceUnavailable("Device login storage unavailable".into()))
}

fn response(status: StatusCode, body: Value) -> Response {
    let mut r = (status, Json(body)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

/// RFC 8628 §3.5 error shape: HTTP 400 with a machine-readable `error`.
fn oauth_error(code: &'static str) -> Response {
    response(StatusCode::BAD_REQUEST, json!({ "error": code }))
}

/// Normalize what a person typed or a link carried: case-insensitive, the
/// separator and spaces optional. Returns `None` for anything that is not a
/// well-formed code, so a malformed value never reaches the database.
pub fn normalize_user_code(raw: &str) -> Option<String> {
    let s: String = raw
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (s.len() == USER_CODE_LEN && s.bytes().all(|b| USER_CODE_ALPHABET.contains(&b))).then_some(s)
}

fn new_user_code() -> String {
    // 16 OS-random bytes (v4 UUID; 122 of its bits are random, and the two
    // fixed nibbles sit at bytes 6 and 8 — skipped). `% 20` over a byte has a
    // bias of 16/256 on the first 16 letters: ~43 bits instead of 43.2.
    let raw = *uuid::Uuid::new_v4().as_bytes();
    let bytes: Vec<u8> = raw
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 6 && *i != 8)
        .map(|(_, b)| *b)
        .collect();
    let mut out = String::with_capacity(USER_CODE_LEN + 1);
    for i in 0..USER_CODE_LEN {
        if i == USER_CODE_LEN / 2 {
            out.push('-');
        }
        out.push(USER_CODE_ALPHABET[usize::from(bytes[i]) % USER_CODE_ALPHABET.len()] as char);
    }
    out
}

/// PKCE S256: `BASE64URL(SHA256(verifier)) == challenge`.
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    code_challenge(verifier) == challenge
}

/// 43 base64url characters = a 32-byte S256 digest.
fn valid_challenge(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_device_name(s: &str) -> bool {
    let n = s.chars().count();
    (1..=64).contains(&n) && !s.chars().any(char::is_control) && s.trim() == s
}

fn valid_os(s: &str) -> bool {
    matches!(s, "windows" | "macos" | "linux")
}

fn mask_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.x", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// Approval is a cookie-authenticated POST: refuse it from any origin that is
/// not this deployment's own front end (wildcard CORS is never authority).
fn trusted_origin(state: &FleetState, headers: &HeaderMap) -> bool {
    let origins: Vec<String> = state
        .settings
        .app
        .cors_origins
        .iter()
        .filter(|s| s.as_str() != "*")
        .cloned()
        .collect();
    let Some(raw) = headers.get(header::ORIGIN).and_then(|s| s.to_str().ok()) else {
        return false;
    };
    let Ok(uri) = raw.parse::<Uri>() else {
        return false;
    };
    if !matches!(uri.scheme_str(), Some("https" | "http"))
        || uri.authority().is_none_or(|a| a.as_str().contains('@'))
        || uri.query().is_some()
        || uri.path() != "/"
    {
        return false;
    }
    meshharbor_core::origin::is_trusted(
        &meshharbor_core::origin::origin_policy(&origins, &state.settings.app.frontend_url),
        raw,
    )
}

/// The approval page's base URL, or `None` when `frontend_url` is unusable.
fn frontend_base(state: &FleetState) -> Option<String> {
    let frontend = state.settings.app.frontend_url.trim_end_matches('/');
    let uri = frontend.parse::<Uri>().ok()?;
    (matches!(uri.scheme_str(), Some("http" | "https"))
        && uri.authority().is_some_and(|a| !a.as_str().contains('@'))
        && uri.query().is_none()
        && !frontend.contains('#'))
    .then(|| frontend.to_string())
}

/// `POST /api/native/device-login` — anonymous. The device's claims (name,
/// OS) are only displayed, never trusted for anything.
pub async fn start(
    State(state): State<FleetState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Start>,
) -> Result<Response, ApiError> {
    enabled(&state)?;
    let Some(purpose) = Purpose::parse(body.purpose.as_deref()) else {
        return Err(ApiError::BadRequest("Invalid device login purpose".into()));
    };
    if !valid_device_name(&body.device_name)
        || !valid_os(&body.device_os)
        || body.code_challenge_method != "S256"
        || !valid_challenge(&body.code_challenge)
    {
        return Err(ApiError::BadRequest("Invalid device login request".into()));
    }
    let frontend = frontend_base(&state).ok_or_else(|| {
        ApiError::ServiceUnavailable("Device login approval URL unavailable".into())
    })?;
    let client = meshharbor_core::client_ip::ConnectionOrigin::capture(
        &headers,
        Some(peer),
        &state.settings.app.business_trusted_proxy_cidrs,
        state.settings.app.rate_limit_trusted_hops,
    )
    .client_ip()
    .ok_or_else(|| ApiError::Forbidden("Device login refused".into()))?;
    let client_hash = hash_secret("device-login-client", &client.to_string());

    let c = coll!(state);
    let now = DateTime::now();
    // Reclaim explicit expiry even before Mongo's TTL monitor runs, so the
    // pending counts below measure only live requests.
    storage(c.delete_many(doc! { "expires_at": { "$lte": now } }).await)?;
    let mine = storage(
        c.count_documents(doc! { "client_hash": &client_hash, "state": "pending" })
            .await,
    )?;
    let total = storage(c.count_documents(doc! { "state": "pending" }).await)?;
    if mine >= MAX_PENDING_PER_CLIENT || total >= MAX_PENDING_TOTAL {
        let mut r = response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({ "error": "slow_down" }),
        );
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("300"));
        return Ok(r);
    }

    let device_code = random_code();
    let user_code = new_user_code();
    let normalized = normalize_user_code(&user_code).expect("generated codes are well-formed");
    let row = DeviceLoginRow {
        id: ObjectId::new(),
        purpose: purpose.wire().into(),
        user_code_hash: hash_secret("device-login-user", &normalized),
        device_code_hash: hash_secret("device-login-device", &device_code),
        code_challenge: body.code_challenge,
        device_name: body.device_name,
        device_os: body.device_os,
        client_hash,
        client_display: mask_ip(client),
        state: "pending".into(),
        tenant_id: None,
        approved_by: None,
        enrollment_jti: None,
        polls: 0,
        created_at: now,
        expires_at: DateTime::from_millis(now.timestamp_millis() + REQUEST_TTL_SECS * 1000),
        decided_at: None,
    };
    // A user-code collision is a unique-index error: astronomically rare at
    // 20^10, and answered like any storage failure (the device just retries).
    storage(c.insert_one(&row).await)?;
    tracing::info!(
        request = %row.id, device = %row.device_name, os = %row.device_os,
        client = %row.client_display, "device-login: request started"
    );
    Ok(response(
        StatusCode::CREATED,
        json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": format!("{frontend}/device-login"),
            "verification_uri_complete": format!("{frontend}/device-login?code={user_code}"),
            "expires_in": REQUEST_TTL_SECS,
            "interval": INTERVAL_SECS,
        }),
    ))
}

async fn pending_by_user_code(
    state: &FleetState,
    raw: &str,
) -> Result<Option<DeviceLoginRow>, ApiError> {
    let Some(code) = normalize_user_code(raw) else {
        return Ok(None);
    };
    storage(
        coll!(state)
            .find_one(doc! {
                "user_code_hash": hash_secret("device-login-user", &code),
                "state": "pending",
                "expires_at": { "$gt": DateTime::now() },
            })
            .await,
    )
}

/// `POST /api/native/device-login/preview` — what the approval page shows.
pub async fn preview(
    State(state): State<FleetState>,
    _auth: AuthUser,
    headers: HeaderMap,
    Json(body): Json<Preview>,
) -> Result<Response, ApiError> {
    enabled(&state)?;
    if !trusted_origin(&state, &headers) {
        return Err(ApiError::Forbidden("Device login refused".into()));
    }
    let Some(row) = pending_by_user_code(&state, &body.user_code).await? else {
        return Err(ApiError::NotFound(
            "No pending device login with that code (it may have expired)".into(),
        ));
    };
    let purpose = Purpose::parse(Some(&row.purpose))
        .ok_or_else(|| ApiError::BadRequest("Invalid device login purpose".into()))?;
    Ok(response(
        StatusCode::OK,
        json!({
            "purpose": purpose.wire(),
            "requested_scopes": purpose.scopes(),
            "device": { "name": row.device_name, "os": row.device_os },
            "client": row.client_display,
            "personal_device": purpose.needs_enrollment(),
            "requested_at_ms": row.created_at.timestamp_millis(),
            "expires_at_ms": row.expires_at.timestamp_millis(),
        }),
    ))
}

/// `POST /api/native/device-login/decision` — approve into one organization
/// (needs `MANAGE_AGENTS` when enrollment is requested), authorize a GUI user
/// session (needs a verified non-placeholder email when `user_session` is
/// requested), or deny.
pub async fn decide(
    State(state): State<FleetState>,
    auth: AuthUser,
    headers: HeaderMap,
    Json(body): Json<Decision>,
) -> Result<Response, ApiError> {
    enabled(&state)?;
    if !trusted_origin(&state, &headers) {
        return Err(ApiError::Forbidden("Device login refused".into()));
    }
    let Some(pending) = pending_by_user_code(&state, &body.user_code).await? else {
        return Err(ApiError::NotFound(
            "No pending device login with that code (it may have expired)".into(),
        ));
    };
    let purpose = Purpose::parse(Some(&pending.purpose))
        .ok_or_else(|| ApiError::BadRequest("Invalid device login purpose".into()))?;
    let tenant = if body.approve {
        if purpose.needs_user_session() {
            let user = state.users.base.find_by_id(auth.user_id).await?;
            meshharbor_core::admission::require_user(
                &state.core,
                &user,
                Some(auth.claims.approval_revision),
            )?;
            if !meshharbor_core::admission::has_verified_account_email(&user)
                || user.security_revision().is_none()
            {
                return Err(ApiError::Forbidden(
                    "A verified account email is required to authorize native sign-in".into(),
                ));
            }
        }
        if purpose.needs_enrollment() {
            let tid = body
                .tenant_id
                .as_deref()
                .and_then(|t| ObjectId::parse_str(t).ok())
                .ok_or_else(|| ApiError::BadRequest("Choose an organization".into()))?;
            crate::agent::require_permission(
                &state,
                tid,
                auth.user_id,
                permissions::MANAGE_AGENTS,
                "MANAGE_AGENTS",
            )
            .await?;
            Some(tid)
        } else {
            None
        }
    } else {
        None
    };
    let now = DateTime::now();
    let next = if body.approve { "approved" } else { "denied" };
    let updated = storage(
        coll!(state)
            .find_one_and_update(
                doc! {
                    "_id": pending.id,
                    "state": "pending",
                    "expires_at": { "$gt": now },
                },
                doc! { "$set": {
                    "state": next,
                    "tenant_id": tenant,
                    "approved_by": body.approve.then_some(auth.user_id),
                    "decided_at": now,
                } },
            )
            .await,
    )?;
    let Some(row) = updated else {
        return Err(ApiError::NotFound(
            "No pending device login with that code (it may have expired)".into(),
        ));
    };
    tracing::info!(
        request = %row.id, device = %row.device_name, client = %row.client_display,
        user = %auth.user_id, tenant = ?tenant, purpose = %row.purpose, decision = next,
        "device-login: decided"
    );
    Ok(response(StatusCode::OK, json!({ "status": next })))
}

/// `POST /api/native/device-login/exchange` — the device's poll. Anonymous;
/// authenticated by the device code AND the PKCE verifier together.
pub async fn exchange(
    State(state): State<FleetState>,
    Json(body): Json<Exchange>,
) -> Result<Response, ApiError> {
    enabled(&state)?;
    if body.device_code.len() != 43 || !(43..=128).contains(&body.code_verifier.len()) {
        return Ok(oauth_error("invalid_request"));
    }
    let c = coll!(state);
    let now = DateTime::now();
    let key = hash_secret("device-login-device", &body.device_code);
    let Some(row) = storage(c.find_one(doc! { "device_code_hash": &key }).await)? else {
        return Ok(oauth_error("expired_token"));
    };
    if row.expires_at <= now {
        return Ok(oauth_error("expired_token"));
    }
    match row.state.as_str() {
        "pending" => {
            let polls = row.polls + 1;
            let set = if polls > MAX_POLLS {
                doc! { "$set": { "state": "denied", "decided_at": now }, "$inc": { "polls": 1 } }
            } else {
                doc! { "$inc": { "polls": 1 } }
            };
            storage(
                c.update_one(doc! { "_id": row.id, "state": "pending" }, set)
                    .await,
            )?;
            return Ok(oauth_error(if polls > MAX_POLLS {
                "access_denied"
            } else {
                "authorization_pending"
            }));
        }
        "denied" => return Ok(oauth_error("access_denied")),
        "approved" => {}
        // `consumed`, or anything unknown: the request is spent.
        _ => return Ok(oauth_error("expired_token")),
    }
    if !pkce_matches(&body.code_verifier, &row.code_challenge) {
        tracing::warn!(request = %row.id, "device-login: exchange with a wrong verifier refused");
        return Ok(oauth_error("access_denied"));
    }
    let Some(purpose) = Purpose::parse(Some(&row.purpose)) else {
        return Ok(oauth_error("access_denied"));
    };
    let Some(approver) = row.approved_by else {
        return Ok(oauth_error("access_denied"));
    };
    if purpose.needs_enrollment() && row.tenant_id.is_none() {
        return Ok(oauth_error("access_denied"));
    }
    // The one-time step: whoever wins this compare-and-set gets the grant.
    let won = storage(
        c.update_one(
            doc! { "_id": row.id, "state": "approved" },
            doc! { "$set": { "state": "consumed", "decided_at": now } },
        )
        .await,
    )?;
    if won.modified_count != 1 {
        return Ok(oauth_error("expired_token"));
    }

    let user = state.users.base.find_by_id(approver).await?;
    if user.deleted_at.is_some() {
        return Err(ApiError::Unauthorized("Account unavailable".into()));
    }
    meshharbor_core::admission::require_user(&state.core, &user, None)?;

    let mut out = serde_json::Map::new();
    if purpose.needs_enrollment() {
        let tenant = row
            .tenant_id
            .ok_or_else(|| ApiError::Forbidden("Missing enrollment organization".into()))?;
        crate::agent::require_permission(
            &state,
            tenant,
            approver,
            permissions::MANAGE_AGENTS,
            "MANAGE_AGENTS",
        )
        .await?;
        // Personal device login mints `anchor = true` so Windows personal
        // promotion can also anchor the SYSTEM service (`exec-system` +
        // `ssh-system`) with the same single-approval enrollment token.
        let (token, jti) = state
            .auth
            .issue_enrollment_token_with_relay(approver, tenant, ENROLLMENT_TTL_SECS, true, false)
            .map_err(|_| {
                ApiError::ServiceUnavailable("Could not mint an enrollment token".into())
            })?;
        let stamped = storage(
            c.update_one(
                doc! { "_id": row.id, "state": "consumed" },
                doc! { "$set": { "enrollment_jti": &jti, "expires_at": DateTime::from_millis(DateTime::now().timestamp_millis() + (ENROLLMENT_TTL_SECS as i64) * 1000) } },
            )
            .await,
        )?;
        if stamped.modified_count != 1 {
            return Err(ApiError::ServiceUnavailable(
                "Could not bind personal device approval".into(),
            ));
        }
        if let Err(e) = state
            .enroll_tokens
            .record_issued(&jti, tenant, approver, DateTime::now())
            .await
        {
            tracing::warn!(%tenant, %jti, error = %e, "device-login: could not record the issued enrollment token");
        }
        out.insert("enrollment_token".into(), json!(token));
        out.insert("expires_in".into(), json!(ENROLLMENT_TTL_SECS));
        out.insert("tenant_id".into(), json!(tenant.to_hex()));
    }

    if purpose.needs_user_session() {
        if !meshharbor_core::admission::has_verified_account_email(&user) {
            return Err(ApiError::Forbidden(
                "A verified account email is required to authorize native sign-in".into(),
            ));
        }
        let sec_rev = user.security_revision().ok_or_else(|| {
            ApiError::Forbidden("Account security revision unavailable".into())
        })?;
        let prefix = meshharbor_core::admission::normalized_frontend_prefix(
            &state.settings.app.frontend_url,
        )
        .ok_or_else(|| {
            ApiError::ServiceUnavailable("Account frontend origin unavailable".into())
        })?;
        let sid = ObjectId::new();
        let issued_at = DateTime::now();
        let expires_at = DateTime::from_millis(
            issued_at.timestamp_millis()
                + (state.settings.jwt.refresh_token_ttl_secs as i64) * 1000,
        );
        meshharbor_services::dao::native_session::create_session(
            &state.core.db,
            &meshharbor_services::dao::native_session::NativeUserSession {
                id: sid,
                user_id: approver,
                security_revision: sec_rev,
                approval_revision: user.account_approval.revision,
                trusted_frontend_origin_prefix: prefix,
                created_at: issued_at,
                expires_at,
                revoked_at: None,
            },
        )
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Could not create native session".into()))?;
        let sid_hex = sid.to_hex();
        let tokens = state
            .auth
            .generate_tokens_with_native_sid(
                approver,
                &user.email,
                &user.username,
                user.account_approval.revision,
                Some(&sid_hex),
            )
            .map_err(|_| ApiError::ServiceUnavailable("Could not mint native session".into()))?;
        out.insert(
            "native_session".into(),
            json!({
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token,
                "expires_in": tokens.expires_in,
                "user": {
                    "id": approver.to_hex(),
                    "email": user.email,
                    "email_verified": true,
                },
            }),
        );
    }

    tracing::info!(
        request = %row.id, device = %row.device_name, approver = %approver,
        purpose = purpose.wire(), "device-login: exchanged"
    );
    Ok(response(StatusCode::OK, Value::Object(out)))
}

pub async fn is_personal_enrollment(
    state: &FleetState,
    jti: &str,
    tenant: ObjectId,
    owner: ObjectId,
) -> Result<bool, ApiError> {
    Ok(storage(
        coll!(state)
            .find_one(doc! {
                "enrollment_jti": jti, "state": "consumed", "tenant_id": tenant,
                "approved_by": owner, "expires_at": { "$gt": DateTime::now() },
            })
            .await,
    )?
    .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_are_well_formed_and_normalize_leniently() {
        for _ in 0..200 {
            let c = new_user_code();
            assert_eq!(c.len(), USER_CODE_LEN + 1);
            assert_eq!(c.as_bytes()[USER_CODE_LEN / 2], b'-');
            let n = normalize_user_code(&c).expect("a generated code normalizes");
            assert_eq!(
                normalize_user_code(&c.to_lowercase()).as_deref(),
                Some(n.as_str())
            );
            assert_eq!(
                normalize_user_code(&c.replace('-', " ")).as_deref(),
                Some(n.as_str())
            );
        }
        // Vowels, digits, wrong length, injection-shaped input: never a code.
        for bad in [
            "",
            "AEIOU-AEIOU",
            "BCDFG-HJKL1",
            "BCDFG-HJKL",
            "BCDFG-HJKLMN",
            "{\"$ne\":1}",
        ] {
            assert_eq!(normalize_user_code(bad), None, "{bad}");
        }
    }

    #[test]
    fn pkce_s256_matches_only_its_own_verifier() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        // RFC 7636 appendix B test vector.
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_matches(verifier, challenge));
        assert!(!pkce_matches(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl",
            challenge
        ));
    }

    #[test]
    fn claims_are_bounded_and_the_requester_is_masked() {
        assert!(valid_device_name("wsl-debian"));
        assert!(!valid_device_name(""));
        assert!(!valid_device_name(" padded"));
        assert!(!valid_device_name("line\nbreak"));
        assert!(!valid_device_name(&"x".repeat(65)));
        assert!(valid_os("linux") && valid_os("windows") && valid_os("macos"));
        assert!(!valid_os("Linux") && !valid_os("plan9"));
        assert_eq!(mask_ip("203.0.113.77".parse().unwrap()), "203.0.113.x");
        assert_eq!(
            mask_ip("2001:db8:1:2::5".parse().unwrap()),
            "2001:db8:1::/48"
        );
    }
}
