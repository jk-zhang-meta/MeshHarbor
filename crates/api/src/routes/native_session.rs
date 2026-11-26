// SPDX-License-Identifier: AGPL-3.0-only
//! Native GUI session revocation and single-use loopback-to-browser SSO handoff.
use axum::{
    Form, Json,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_core::ApiError;
use meshharbor_services::{
    dao::native_session::{self, NativeHandoffTicket},
    dao::native_ssh_authorization::random_code,
};
use serde::{Deserialize, Serialize};

use crate::{routes::auth::UserResponse, state::AppState};

const HANDOFF_TTL_SECS: u64 = 60;

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/session/revoke", post(revoke))
        .route("/handoff", post(handoff_issue))
        .route("/handoff/consume", post(handoff_consume))
        .route("/handoff/complete", post(handoff_complete))
        .layer(DefaultBodyLimit::max(4096))
}

fn ensure_enabled(state: &AppState) -> Result<(), ApiError> {
    if state.settings.auth.native_device_login_enabled {
        Ok(())
    } else {
        Err(ApiError::ServiceUnavailable(
            "Device login is disabled on this server".into(),
        ))
    }
}

fn no_store_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    h.insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    h
}

fn parse_strict_oid(raw: &str, label: &str) -> Result<ObjectId, ApiError> {
    if raw.len() != 24 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(format!("Invalid {label}")));
    }
    ObjectId::parse_str(raw).map_err(|_| ApiError::BadRequest(format!("Invalid {label}")))
}

pub fn validate_loopback_form_origin(raw: &str) -> Result<String, ApiError> {
    let Some(port_str) = raw.strip_prefix("http://127.0.0.1:") else {
        return Err(ApiError::BadRequest(
            "Invalid loopback handoff origin".into(),
        ));
    };
    if port_str.is_empty()
        || port_str.starts_with('0')
        || !port_str.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ApiError::BadRequest(
            "Invalid loopback handoff port".into(),
        ));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid loopback handoff port".into()))?;
    if port == 0 {
        return Err(ApiError::BadRequest(
            "Invalid loopback handoff port".into(),
        ));
    }
    let url = reqwest::Url::parse(raw)
        .map_err(|_| ApiError::BadRequest("Invalid loopback handoff origin".into()))?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port() != Some(port)
        || url.path() != "/"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ApiError::BadRequest(
            "Invalid loopback handoff origin".into(),
        ));
    }
    Ok(format!("http://127.0.0.1:{port}"))
}

fn require_frontend_origin(frontend_url: &str, headers: &HeaderMap) -> Result<(), ApiError> {
    let raw = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Forbidden("Trusted frontend origin required".into()))?;
    if raw.is_empty() || raw == "null" || raw != raw.trim() || raw.ends_with('/') {
        return Err(ApiError::Forbidden("Untrusted origin".into()));
    }
    let (expected, _) = meshharbor_core::admission::parse_trusted_frontend_url(frontend_url)
        .ok_or_else(|| ApiError::ServiceUnavailable("Invalid configured frontend URL".into()))?;
    let got = reqwest::Url::parse(raw).map_err(|_| ApiError::Forbidden("Untrusted origin".into()))?;
    if got.path() != "/"
        || !got.username().is_empty()
        || got.password().is_some()
        || got.query().is_some()
        || got.fragment().is_some()
        || got.scheme() != expected.scheme()
        || !got
            .host_str()
            .zip(expected.host_str())
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
        || got.port_or_known_default() != expected.port_or_known_default()
    {
        return Err(ApiError::Forbidden("Untrusted origin".into()));
    }
    Ok(())
}

async fn bearer_native_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(ObjectId, ObjectId), ApiError> {
    let raw_auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization bearer token".into()))?;
    let token = raw_auth
        .strip_prefix("Bearer ")
        .filter(|t| !t.is_empty() && !t.bytes().any(|b| b.is_ascii_whitespace()))
        .ok_or_else(|| ApiError::Unauthorized("Invalid Authorization bearer token".into()))?;
    let claims = state.auth.verify_access_token(token)?;
    let user_id = ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::Unauthorized("Invalid user ID".into()))?;
    let sid_raw = claims.native_sid.as_deref().ok_or_else(|| {
        ApiError::Forbidden("Explicit native user session credential required".into())
    })?;
    let sid = ObjectId::parse_str(sid_raw)
        .map_err(|_| ApiError::Unauthorized("Invalid native session".into()))?;
    meshharbor_core::admission::authorize_claims(&state.core, &claims).await?;
    Ok((user_id, sid))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(_body): Json<RevokeRequest>,
) -> Result<Response, ApiError> {
    let (user_id, sid) = bearer_native_session(&state, &headers).await?;
    let revoked = native_session::revoke_session(&state.db, sid, user_id)
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Session storage unavailable".into()))?;
    if !revoked {
        return Err(ApiError::Unauthorized("Native session unavailable".into()));
    }
    Ok((StatusCode::NO_CONTENT, no_store_headers()).into_response())
}

fn default_purpose() -> String {
    "remote".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffIssueRequest {
    #[serde(default = "default_purpose")]
    pub purpose: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub share_id: Option<String>,
    pub form_origin: String,
}

#[derive(Serialize)]
pub struct HandoffIssueResponse {
    pub ticket: String,
    pub post_url: String,
    pub expires_in: u64,
}

#[derive(Debug, Clone)]
enum TargetSpec {
    Remote {
        tenant_id: ObjectId,
        agent_id: ObjectId,
    },
    DeviceShareRemote {
        share_id: ObjectId,
        bound_device: Option<(ObjectId, ObjectId)>,
    },
    MyDevices,
    DeviceSharesSent,
    DeviceSharesReceived,
    Dashboard,
}

#[derive(Debug, Clone)]
struct VerifiedTarget {
    purpose: &'static str,
    tenant_id: Option<ObjectId>,
    agent_id: Option<ObjectId>,
    share_id: Option<ObjectId>,
}

#[derive(Serialize)]
pub struct HandoffTargetResponse {
    pub purpose: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_id: Option<String>,
}

impl VerifiedTarget {
    fn into_wire(self) -> HandoffTargetResponse {
        match self.purpose {
            "remote" => HandoffTargetResponse {
                purpose: "remote",
                tenant_id: self.tenant_id.map(|id| id.to_hex()),
                agent_id: self.agent_id.map(|id| id.to_hex()),
                share_id: None,
            },
            "device_share_remote" => HandoffTargetResponse {
                purpose: "device_share_remote",
                tenant_id: None,
                agent_id: None,
                share_id: self.share_id.map(|id| id.to_hex()),
            },
            other => HandoffTargetResponse {
                purpose: other,
                tenant_id: None,
                agent_id: None,
                share_id: None,
            },
        }
    }
}

impl TargetSpec {
    fn from_request(req: &HandoffIssueRequest) -> Result<Self, ApiError> {
        match req.purpose.as_str() {
            "remote" => {
                if req.share_id.is_some() {
                    return Err(ApiError::BadRequest(
                        "remote handoff cannot include share_id".into(),
                    ));
                }
                let tid = parse_strict_oid(
                    req.tenant_id
                        .as_deref()
                        .ok_or_else(|| ApiError::BadRequest("tenant_id required".into()))?,
                    "tenant_id",
                )?;
                let aid = parse_strict_oid(
                    req.agent_id
                        .as_deref()
                        .ok_or_else(|| ApiError::BadRequest("agent_id required".into()))?,
                    "agent_id",
                )?;
                Ok(Self::Remote {
                    tenant_id: tid,
                    agent_id: aid,
                })
            }
            "device_share_remote" => {
                if req.tenant_id.is_some() || req.agent_id.is_some() {
                    return Err(ApiError::BadRequest(
                        "device_share_remote handoff accepts only share_id".into(),
                    ));
                }
                let sid = parse_strict_oid(
                    req.share_id
                        .as_deref()
                        .ok_or_else(|| ApiError::BadRequest("share_id required".into()))?,
                    "share_id",
                )?;
                Ok(Self::DeviceShareRemote {
                    share_id: sid,
                    bound_device: None,
                })
            }
            "my_devices" | "device_shares_sent" | "device_shares_received" | "dashboard" => {
                if req.tenant_id.is_some() || req.agent_id.is_some() || req.share_id.is_some() {
                    return Err(ApiError::BadRequest(
                        "Target purpose does not accept device or share IDs".into(),
                    ));
                }
                Ok(match req.purpose.as_str() {
                    "my_devices" => Self::MyDevices,
                    "device_shares_sent" => Self::DeviceSharesSent,
                    "device_shares_received" => Self::DeviceSharesReceived,
                    _ => Self::Dashboard,
                })
            }
            _ => Err(ApiError::BadRequest("Unsupported handoff purpose".into())),
        }
    }

    fn from_row(row: &NativeHandoffTicket) -> Result<Self, ApiError> {
        match row.purpose.as_str() {
            "remote" => {
                let (Some(tenant_id), Some(agent_id), None) =
                    (row.tenant_id, row.agent_id, row.share_id)
                else {
                    return Err(ApiError::Forbidden("Corrupt handoff target".into()));
                };
                Ok(Self::Remote {
                    tenant_id,
                    agent_id,
                })
            }
            "device_share_remote" => {
                let (Some(tenant_id), Some(agent_id), Some(share_id)) =
                    (row.tenant_id, row.agent_id, row.share_id)
                else {
                    return Err(ApiError::Forbidden("Corrupt handoff target".into()));
                };
                Ok(Self::DeviceShareRemote {
                    share_id,
                    bound_device: Some((tenant_id, agent_id)),
                })
            }
            "my_devices" | "device_shares_sent" | "device_shares_received" | "dashboard" => {
                if row.tenant_id.is_some() || row.agent_id.is_some() || row.share_id.is_some() {
                    return Err(ApiError::Forbidden("Corrupt handoff target".into()));
                }
                Ok(match row.purpose.as_str() {
                    "my_devices" => Self::MyDevices,
                    "device_shares_sent" => Self::DeviceSharesSent,
                    "device_shares_received" => Self::DeviceSharesReceived,
                    _ => Self::Dashboard,
                })
            }
            _ => Err(ApiError::Forbidden("Unsupported handoff target".into())),
        }
    }
}

async fn verify_target(
    state: &AppState,
    user_id: ObjectId,
    spec: &TargetSpec,
) -> Result<VerifiedTarget, ApiError> {
    match *spec {
        TargetSpec::Remote {
            tenant_id,
            agent_id,
        } => verify_remote_target(state, user_id, tenant_id, agent_id).await,
        TargetSpec::DeviceShareRemote {
            share_id,
            bound_device,
        } => verify_share_remote_target(state, user_id, share_id, bound_device).await,
        TargetSpec::MyDevices => {
            ensure_fleet_mounted(state)?;
            Ok(VerifiedTarget {
                purpose: "my_devices",
                tenant_id: None,
                agent_id: None,
                share_id: None,
            })
        }
        TargetSpec::DeviceSharesSent => {
            ensure_fleet_mounted(state)?;
            Ok(VerifiedTarget {
                purpose: "device_shares_sent",
                tenant_id: None,
                agent_id: None,
                share_id: None,
            })
        }
        TargetSpec::DeviceSharesReceived => {
            ensure_fleet_mounted(state)?;
            Ok(VerifiedTarget {
                purpose: "device_shares_received",
                tenant_id: None,
                agent_id: None,
                share_id: None,
            })
        }
        TargetSpec::Dashboard => Ok(VerifiedTarget {
            purpose: "dashboard",
            tenant_id: None,
            agent_id: None,
            share_id: None,
        }),
    }
}

fn ensure_fleet_mounted(state: &AppState) -> Result<(), ApiError> {
    #[cfg(feature = "fleet")]
    {
        if state.modules.fleet.is_some() {
            return Ok(());
        }
    }
    #[cfg(not(feature = "fleet"))]
    let _ = state;
    Err(ApiError::ServiceUnavailable(
        "Fleet module is not enabled".into(),
    ))
}

#[cfg(feature = "remote")]
async fn verify_remote_target(
    state: &AppState,
    user_id: ObjectId,
    tenant_id: ObjectId,
    agent_id: ObjectId,
) -> Result<VerifiedTarget, ApiError> {
    use meshharbor_remote_control::{
        models::AgentStatus, permissions::Permissions, signaling::ClientMsg,
    };

    let (Some(fleet), Some(remote)) = (&state.modules.fleet, &state.modules.remote) else {
        return Err(ApiError::ServiceUnavailable(
            "Remote control module is not enabled".into(),
        ));
    };
    let agent = fleet
        .agents
        .base
        .find_by_id(agent_id)
        .await
        .map_err(|_| ApiError::Forbidden("Device access denied".into()))?;
    if agent.deleted_at.is_some()
        || agent.tenant_id != tenant_id
        || agent.status == AgentStatus::Quarantined
    {
        return Err(ApiError::Forbidden("Device access denied".into()));
    }
    let tenant = state
        .tenants
        .base
        .find_by_id(tenant_id)
        .await
        .map_err(|_| ApiError::Forbidden("Organization access denied".into()))?;
    if tenant.deleted_at.is_some() || tenant.is_archived {
        return Err(ApiError::Forbidden("Organization is unavailable".into()));
    }
    let msg = ClientMsg::SessionRequest {
        two_factor_code: None,
        agent_id,
        share_grant_id: None,
        permissions: Permissions::VIEW,
        browser_caps: Vec::new(),
        preferred_transport: None,
        chroma_pref: None,
        chunk_framing: None,
        audio_enabled: false,
        override_reason: None,
        local_relay: None,
        initial_resolution: None,
        replaces: None,
        continues_from: None,
    };
    let raw = serde_json::to_string(&msg)
        .map_err(|_| ApiError::Internal("Failed to encode PDP request".into()))?;
    meshharbor_mod_remote::controller::resolve_session_authz(remote, user_id, &raw)
        .await
        .map_err(ApiError::Forbidden)?;
    Ok(VerifiedTarget {
        purpose: "remote",
        tenant_id: Some(tenant_id),
        agent_id: Some(agent_id),
        share_id: None,
    })
}

#[cfg(not(feature = "remote"))]
async fn verify_remote_target(
    _state: &AppState,
    _user_id: ObjectId,
    _tenant_id: ObjectId,
    _agent_id: ObjectId,
) -> Result<VerifiedTarget, ApiError> {
    Err(ApiError::ServiceUnavailable(
        "Remote control module is not enabled".into(),
    ))
}

#[cfg(feature = "remote")]
async fn verify_share_remote_target(
    state: &AppState,
    user_id: ObjectId,
    share_id: ObjectId,
    bound_device: Option<(ObjectId, ObjectId)>,
) -> Result<VerifiedTarget, ApiError> {
    use meshharbor_db::models::DeviceShareOperation;
    use meshharbor_remote_control::{
        models::AgentStatus, permissions::Permissions, signaling::ClientMsg,
    };

    let Some(remote) = &state.modules.remote else {
        return Err(ApiError::ServiceUnavailable(
            "Remote control module is not enabled".into(),
        ));
    };
    let access = meshharbor_core::device_share::authorize_grant(
        &state.core,
        user_id,
        share_id,
        DeviceShareOperation::DesktopView,
    )
    .await?;
    let tenant_id = access.agent.tenant_id;
    let agent_id = access.grant.device_id;
    if access.agent.deleted_at.is_some() || access.agent.status == AgentStatus::Quarantined {
        return Err(ApiError::Forbidden("Shared device unavailable".into()));
    }
    if let Some((expected_tid, expected_aid)) = bound_device
        && (tenant_id != expected_tid || agent_id != expected_aid)
    {
        return Err(ApiError::Forbidden(
            "Shared device binding changed since handoff was issued".into(),
        ));
    }
    let tenant = state
        .tenants
        .base
        .find_by_id(tenant_id)
        .await
        .map_err(|_| ApiError::Forbidden("Organization access denied".into()))?;
    if tenant.deleted_at.is_some() || tenant.is_archived {
        return Err(ApiError::Forbidden("Organization is unavailable".into()));
    }
    let msg = ClientMsg::SessionRequest {
        two_factor_code: None,
        agent_id,
        share_grant_id: Some(share_id),
        permissions: Permissions::VIEW,
        browser_caps: Vec::new(),
        preferred_transport: None,
        chroma_pref: None,
        chunk_framing: None,
        audio_enabled: false,
        override_reason: None,
        local_relay: None,
        initial_resolution: None,
        replaces: None,
        continues_from: None,
    };
    let raw = serde_json::to_string(&msg)
        .map_err(|_| ApiError::Internal("Failed to encode share PDP request".into()))?;
    meshharbor_mod_remote::controller::resolve_session_authz(remote, user_id, &raw)
        .await
        .map_err(ApiError::Forbidden)?;
    Ok(VerifiedTarget {
        purpose: "device_share_remote",
        tenant_id: Some(tenant_id),
        agent_id: Some(agent_id),
        share_id: Some(share_id),
    })
}

#[cfg(not(feature = "remote"))]
async fn verify_share_remote_target(
    _state: &AppState,
    _user_id: ObjectId,
    _share_id: ObjectId,
    _bound_device: Option<(ObjectId, ObjectId)>,
) -> Result<VerifiedTarget, ApiError> {
    Err(ApiError::ServiceUnavailable(
        "Remote control module is not enabled".into(),
    ))
}

pub async fn handoff_issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HandoffIssueRequest>,
) -> Result<Response, ApiError> {
    ensure_enabled(&state)?;
    let (user_id, native_sid) = bearer_native_session(&state, &headers).await?;
    let form_origin = validate_loopback_form_origin(&req.form_origin)?;
    let spec = TargetSpec::from_request(&req)?;
    let verified = verify_target(&state, user_id, &spec).await?;
    let frontend_base =
        meshharbor_core::admission::normalized_frontend_prefix(&state.settings.app.frontend_url)
            .ok_or_else(|| {
                ApiError::ServiceUnavailable("Invalid configured frontend URL".into())
            })?;

    let ticket = random_code();
    let now_ms = DateTime::now().timestamp_millis();
    let row = NativeHandoffTicket {
        id: ObjectId::new(),
        ticket_hash: native_session::hash_ticket(&ticket),
        native_sid,
        user_id,
        form_origin,
        purpose: verified.purpose.to_owned(),
        tenant_id: verified.tenant_id,
        agent_id: verified.agent_id,
        share_id: verified.share_id,
        created_at: DateTime::from_millis(now_ms),
        expires_at: DateTime::from_millis(now_ms + (HANDOFF_TTL_SECS as i64) * 1000),
        consumed_at: None,
    };
    native_session::issue_handoff(&state.db, &row)
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Handoff storage unavailable".into()))?;

    let body = HandoffIssueResponse {
        ticket,
        post_url: format!("{frontend_base}/api/native/handoff/consume"),
        expires_in: HANDOFF_TTL_SECS,
    };
    Ok((StatusCode::OK, no_store_headers(), Json(body)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeForm {
    pub ticket: String,
}

pub async fn handoff_consume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConsumeForm>,
) -> Result<Response, ApiError> {
    ensure_enabled(&state)?;
    let raw_origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Forbidden("Loopback handoff Origin required".into()))?;
    let form_origin = validate_loopback_form_origin(raw_origin)
        .map_err(|_| ApiError::Forbidden("Untrusted handoff Origin".into()))?;
    if form.ticket.is_empty()
        || form.ticket.len() > 128
        || !form.ticket.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(ApiError::Unauthorized("Invalid handoff ticket".into()));
    }

    let now = DateTime::now();
    let row = native_session::consume_handoff(&state.db, &form.ticket, &form_origin, now)
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Handoff storage unavailable".into()))?
        .ok_or_else(|| ApiError::Unauthorized("Invalid or expired handoff ticket".into()))?;

    let user = state.users.base.find_by_id(row.user_id).await?;
    let sid_hex = row.native_sid.to_hex();
    let tokens = state.auth.generate_tokens_with_native_sid(
        row.user_id,
        &user.email,
        &user.username,
        user.account_approval.revision,
        Some(&sid_hex),
    )?;
    let claims = state.auth.verify_access_token(&tokens.access_token)?;
    meshharbor_core::admission::authorize_claims(&state.core, &claims).await?;

    let spec = TargetSpec::from_row(&row)?;
    verify_target(&state, row.user_id, &spec).await?;

    let frontend_base =
        meshharbor_core::admission::normalized_frontend_prefix(&state.settings.app.frontend_url)
            .ok_or_else(|| {
                ApiError::ServiceUnavailable("Invalid configured frontend URL".into())
            })?;
    let location = format!(
        "{frontend_base}/native-session-complete?handoff_id={}",
        row.id.to_hex()
    );

    let mut resp_headers = no_store_headers();
    resp_headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&location)
            .map_err(|_| ApiError::Internal("Invalid redirect location".into()))?,
    );
    let access_cookie = format!(
        "access_token={}; HttpOnly; Path=/; SameSite=Lax; Max-Age={}{}",
        tokens.access_token,
        tokens.expires_in,
        crate::routes::auth::secure_attr(&state.core)
    );
    resp_headers.append(header::SET_COOKIE, access_cookie.parse().unwrap());
    resp_headers.append(
        header::SET_COOKIE,
        crate::routes::auth::refresh_cookie(&state.core, &tokens.refresh_token)
            .parse()
            .unwrap(),
    );
    Ok((StatusCode::SEE_OTHER, resp_headers).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteRequest {
    pub handoff_id: String,
}

#[derive(Serialize)]
pub struct CompleteResponse {
    pub user: UserResponse,
    pub target: HandoffTargetResponse,
}

pub async fn handoff_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CompleteRequest>,
) -> Result<Response, ApiError> {
    ensure_enabled(&state)?;
    require_frontend_origin(&state.settings.app.frontend_url, &headers)?;
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(ApiError::Forbidden(
            "Browser session cookie required; bearer override not permitted".into(),
        ));
    }
    let token = crate::cookies::get(&headers, "access_token")
        .ok_or_else(|| ApiError::Unauthorized("Missing session cookie".into()))?;
    let claims = state.auth.verify_access_token(&token)?;
    meshharbor_core::admission::authorize_claims(&state.core, &claims).await?;

    let caller_user_id = ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::Unauthorized("Invalid user ID".into()))?;
    let caller_sid = claims
        .native_sid
        .as_deref()
        .and_then(|s| ObjectId::parse_str(s).ok())
        .ok_or_else(|| ApiError::Forbidden("Native session cookie required".into()))?;

    let handoff_id = parse_strict_oid(&req.handoff_id, "handoff_id")?;
    let row = native_session::find_consumed_handoff(&state.db, handoff_id, DateTime::now())
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Handoff storage unavailable".into()))?
        .ok_or_else(|| ApiError::Unauthorized("Handoff receipt unavailable or expired".into()))?;

    if row.user_id != caller_user_id || row.native_sid != caller_sid {
        return Err(ApiError::Forbidden(
            "Handoff receipt does not belong to this browser session".into(),
        ));
    }

    let spec = TargetSpec::from_row(&row)?;
    let verified = verify_target(&state, caller_user_id, &spec).await?;
    let user = state.users.base.find_by_id(caller_user_id).await?;
    let is_platform_admin = state.platform_admins.contains(&caller_user_id);

    let body = CompleteResponse {
        user: UserResponse::of(user, is_platform_admin),
        target: verified.into_wire(),
    };
    Ok((StatusCode::OK, no_store_headers(), Json(body)).into_response())
}
