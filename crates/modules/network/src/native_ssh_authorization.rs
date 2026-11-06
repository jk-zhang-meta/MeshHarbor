// SPDX-License-Identifier: AGPL-3.0-only
//! Browser approval and one-time exchange only. No account tokens or SSH transport.
use crate::{NetworkState, shared_ssh::authorization_policy};
use axum::{
    Json,
    extract::{ConnectInfo, FromRef, FromRequestParts, Path},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header, request::Parts},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::{NativeSshAuthorization, NativeSshBinding, NativeSshScope};
use meshharbor_remote_control::models::ssh_limits;
use meshharbor_services::dao::{
    base::DaoResult,
    native_ssh_authorization::{NativeSshAuthorizationDao, Poll, hash_secret, random_code},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{future::Future, net::SocketAddr, time::Duration};

/// Reject before later extractors can query account or authorization state.
/// Explicit enablement is for isolated testing until revocation fencing exists.
pub struct EnabledAuthorization(NetworkState);

impl<S> FromRequestParts<S> for EnabledAuthorization
where
    NetworkState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = NetworkState::from_ref(state);
        if !state.settings.auth.native_share_ssh_authorization_enabled {
            return Err(ApiError::ServiceUnavailable(
                "Native SSH authorization is disabled".into(),
            ));
        }
        Ok(Self(state))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    share_grant_id: String,
    public_key: String,
    code_challenge: String,
    code_challenge_method: String,
    session_secs: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    user_code: String,
    approve: bool,
    expected_scope_revision: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    user_code: String,
}

/// Capture only server-owned display and authorization inputs. Comparing these
/// values binds consent. Tenant SSH/archive writes have a monotonic revision;
/// other dependencies still use value snapshots without full ABA protection.
async fn authorized_scope(
    state: &NetworkState,
    row: &NativeSshAuthorization,
    recipient_id: ObjectId,
    approval_revision: u32,
) -> Result<NativeSshScope, ApiError> {
    if row.session_secs == 0 || row.session_secs > ssh_limits::MAX_SESSION_SECS {
        return Err(refused());
    }
    let access = authorization_policy(state, recipient_id, row.share_grant_id)
        .await
        .map_err(|_| refused())?;
    let recipient = state
        .core
        .users
        .base
        .find_by_id(recipient_id)
        .await
        .map_err(|_| refused())?;
    meshharbor_core::device_share::require_recipient(&recipient).map_err(|_| refused())?;
    meshharbor_core::admission::require_user(&state.core, &recipient, Some(approval_revision))
        .map_err(|_| refused())?;
    let owner = state
        .core
        .users
        .base
        .find_by_id(access.grant.owner_user_id)
        .await
        .map_err(|_| refused())?;
    meshharbor_core::admission::require_user(&state.core, &owner, None).map_err(|_| refused())?;
    let recipient_security_rev = recipient.security_revision().ok_or_else(refused)?;
    let owner_security_rev = owner.security_revision().ok_or_else(refused)?;
    let tenant = state
        .tenants
        .base
        .find_by_id(access.grant.tenant_id)
        .await
        .map_err(|_| refused())?;
    let tenant_security_rev = tenant.security_revision().ok_or_else(refused)?;
    let membership = storage(
        state
            .tenants
            .members
            .find_one(doc! {
                "tenant_id": access.grant.tenant_id, "user_id": access.grant.owner_user_id,
            })
            .await,
    )?
    .ok_or_else(refused)?;
    let owner_membership_id = membership.id.ok_or_else(refused)?;
    let owner_membership_security_rev = membership.security_revision().ok_or_else(refused)?;
    let device_security_rev = access.agent.access_policy_revision().ok_or_else(refused)?;
    let device_token_gen = i64::from(access.agent.token_gen);
    if owner.deleted_at.is_some()
        || !owner.is_verified
        || recipient.is_mfa_enabled
        || tenant.settings.mfa_required
        || !tenant.settings.remote_ssh_enabled
        || tenant.deleted_at.is_some()
        || tenant.is_archived
    {
        return Err(refused());
    }
    let request_expires_at = row.expires_at.min(access.grant.expires_at);
    if request_expires_at <= DateTime::now() {
        return Err(refused());
    }
    let os = serde_json::to_value(access.agent.os).map_err(|_| refused())?;
    let security = doc! {
        "recipient_security_rev": recipient_security_rev,
        "recipient_approval": bson::to_document(&recipient.account_approval).map_err(|_| refused())?,
        "recipient_verified": recipient.is_verified, "recipient_mfa": recipient.is_mfa_enabled,
        "recipient_deleted_at": recipient.deleted_at,
        "owner_security_rev": owner_security_rev,
        "owner_approval": bson::to_document(&owner.account_approval).map_err(|_| refused())?,
        "owner_verified": owner.is_verified, "owner_mfa": owner.is_mfa_enabled,
        "owner_deleted_at": owner.deleted_at,
        "owner_membership_id": owner_membership_id,
        "owner_membership_security_rev": owner_membership_security_rev,
        "owner_joined_at": membership.joined_at,
        "owner_role_ids": membership.role_ids,
        "device_security_rev": device_security_rev,
        "device_token_gen": device_token_gen,
        "tenant_owner_id": tenant.owner_id, "tenant_security_rev": tenant_security_rev,
        "tenant_ssh_enabled": tenant.settings.remote_ssh_enabled,
        "tenant_mfa_required": tenant.settings.mfa_required, "tenant_archived": tenant.is_archived,
        "tenant_deleted_at": tenant.deleted_at,
        "access_policy": bson::to_document(&access.agent.access_policy).map_err(|_| refused())?,
        "share_permissions": bson::to_document(&access.grant.permissions).map_err(|_| refused())?,
        "share_tcp_ports": bson::to_bson(&access.grant.tcp_ports).map_err(|_| refused())?,
        "account_approval_enabled": state.settings.auth.account_approval.enabled,
        "bootstrap_owner_id": state.settings.auth.account_approval.owner_user_id.clone(),
        "max_session_secs": ssh_limits::MAX_SESSION_SECS as i64,
    };
    Ok(NativeSshScope {
        device_id: access.grant.device_id,
        tenant_id: access.grant.tenant_id,
        owner_user_id: access.grant.owner_user_id,
        recipient_user_id: recipient_id,
        approval_revision: recipient.account_approval.revision,
        share_revision: access.grant.revision,
        ssh_account: access.grant.ssh_account.ok_or_else(refused)?,
        ssh_policy: bson::to_document(&access.agent.ssh_policy).map_err(|_| refused())?,
        binding: Some(NativeSshBinding {
            authorization_id: row.authorization_id,
            share_grant_id: row.share_grant_id,
            public_key: row.public_key.clone(),
            code_challenge: row.code_challenge.clone(),
            recipient_username: recipient.username,
            recipient_display_name: recipient.display_name,
            device_name: access.agent.name,
            device_os: os.as_str().ok_or_else(refused)?.to_owned(),
            request_expires_at,
            share_expires_at: access.grant.expires_at,
            session_secs: row.session_secs,
            security,
        }),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    device_code: String,
    code_verifier: String,
}

fn storage<T>(value: DaoResult<T>) -> Result<T, ApiError> {
    // Driver errors can contain query fields. Never put proof material or
    // private authorization records into a response/log through Display.
    value.map_err(|_| {
        ApiError::ServiceUnavailable("Native SSH authorization storage unavailable".into())
    })
}

fn refused() -> ApiError {
    ApiError::Forbidden("Native SSH authorization refused".into())
}

async fn bounded(
    work: impl Future<Output = Result<Response, ApiError>>,
) -> Result<Response, ApiError> {
    tokio::time::timeout(Duration::from_secs(3), work)
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Native SSH authorization timed out".into()))?
}

fn response(status: StatusCode, body: Value) -> Response {
    let mut result = (status, Json(body)).into_response();
    result
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    result
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    result
}

fn limited() -> Response {
    let mut result = response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({"error":"authorization_rate_limited"}),
    );
    result
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("300"));
    result
}

/// Wildcard CORS is never approval authority. Missing/null/malformed Origin
/// is refused even when the account cookie itself is valid.
fn trusted_origin(state: &NetworkState, headers: &HeaderMap) -> bool {
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

pub async fn start(
    EnabledAuthorization(state): EnabledAuthorization,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Start>,
) -> Result<Response, ApiError> {
    bounded(async {
        let share = ObjectId::parse_str(&body.share_grant_id)
            .map_err(|_| ApiError::BadRequest("Invalid native SSH request".into()))?;
        if body.share_grant_id.len() != 24
            || body.public_key.len() > 1024
            || !crate::routes::agent_ssh::is_supported_public_key(&body.public_key)
            || body.code_challenge_method != "S256"
            || body.code_challenge.len() != 43
            || !URL_SAFE_NO_PAD
                .decode(&body.code_challenge)
                .is_ok_and(|b| b.len() == 32)
            || body.session_secs == 0
            || body.session_secs > ssh_limits::MAX_SESSION_SECS
        {
            return Err(ApiError::BadRequest("Invalid native SSH request".into()));
        }
        let origin = meshharbor_core::client_ip::ConnectionOrigin::capture(
            &headers,
            Some(peer),
            &state.settings.app.business_trusted_proxy_cidrs,
            state.settings.app.rate_limit_trusted_hops,
        );
        let client = origin.client_ip().ok_or_else(refused)?;
        let frontend = state.settings.app.frontend_url.trim_end_matches('/');
        let uri = frontend.parse::<Uri>().map_err(|_| {
            ApiError::ServiceUnavailable("Native SSH approval URL unavailable".into())
        })?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || uri.query().is_some()
            || frontend.contains('#')
        {
            return Err(ApiError::ServiceUnavailable(
                "Native SSH approval URL unavailable".into(),
            ));
        }
        let device_code = random_code();
        // Separate high-entropy human approval code; never a URL capability.
        let user_code = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 9]>());
        let id = ObjectId::new();
        let now = DateTime::now();
        let row = NativeSshAuthorization {
            id: None,
            authorization_id: id,
            client_hash: hash_secret("client", &client.to_string()),
            client_slot: 0,
            share_hash: None,
            share_slot: None,
            share_grant_id: share,
            public_key: body.public_key,
            code_challenge: body.code_challenge,
            user_code_hash: hash_secret("user", &user_code),
            device_code_hash: hash_secret("device", &device_code),
            session_secs: body.session_secs,
            state: "pending".into(),
            polls: 0,
            scope: None,
            preview_scope: None,
            preview_revision_hash: None,
            grant_hash: None,
            grant_expires_at: None,
            created_at: now,
            expires_at: DateTime::from_millis(
                now.timestamp_millis() + NativeSshAuthorization::REQUEST_TTL_SECS * 1000,
            ),
        };
        if !storage(
            NativeSshAuthorizationDao::new(&state.core.db)
                .reserve(&row)
                .await,
        )? {
            return Ok(limited());
        }
        // Deliberately no share lookup here: known/unknown, expired, foreign
        // and disabled shares produce the same anonymous response shape.
        Ok(response(
            StatusCode::CREATED,
            json!({
                "authorization_id":id.to_hex(), "user_code":user_code, "device_code":device_code,
                "verification_uri":format!("{frontend}/native/share-ssh/approve"),
                "expires_in":NativeSshAuthorization::REQUEST_TTL_SECS, "interval":1,
            }),
        ))
    })
    .await
}

pub async fn preview(
    EnabledAuthorization(state): EnabledAuthorization,
    auth: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Preview>,
) -> Result<Response, ApiError> {
    bounded(async {
        if !trusted_origin(&state, &headers) || id.len() != 24 || body.user_code.len() != 12 {
            return Err(refused());
        }
        let id = ObjectId::parse_str(id).map_err(|_| refused())?;
        let dao = NativeSshAuthorizationDao::new(&state.core.db);
        let row = storage(dao.pending(id, &body.user_code).await)?.ok_or_else(refused)?;
        let scope = authorized_scope(&state, &row, auth.user_id, auth.claims.approval_revision).await?;
        if !state.ssh_rate_limiter.check_bounded(auth.user_id, scope.device_id, 20) {
            return Ok(limited());
        }
        let revision = random_code();
        if !storage(dao.preview(&row, &body.user_code, &scope, &revision).await)? {
            return Err(refused());
        }
        let binding = scope.binding.as_ref().ok_or_else(refused)?;
        Ok(response(StatusCode::OK, json!({
            "authorization_id": row.authorization_id.to_hex(),
            "recipient": {"id":scope.recipient_user_id.to_hex(),
                "username":binding.recipient_username, "display_name":binding.recipient_display_name},
            "device": {"id":scope.device_id.to_hex(), "name":binding.device_name, "os":binding.device_os},
            "ssh_account":scope.ssh_account, "request_expires_at_ms":binding.request_expires_at.timestamp_millis(),
            "session_secs":binding.session_secs, "scope_revision":revision,
        })))
    }).await
}

pub async fn decide(
    EnabledAuthorization(state): EnabledAuthorization,
    auth: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Decision>,
) -> Result<Response, ApiError> {
    bounded(async {
        if !trusted_origin(&state, &headers) || id.len() != 24 || body.user_code.len() != 12 {
            return Err(refused());
        }
        let revision = body
            .expected_scope_revision
            .as_deref()
            .ok_or_else(refused)?;
        if revision.len() != 43
            || !revision
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(refused());
        }
        let id = ObjectId::parse_str(id).map_err(|_| refused())?;
        let dao = NativeSshAuthorizationDao::new(&state.core.db);
        let row = storage(dao.pending(id, &body.user_code).await)?.ok_or_else(refused)?;
        let shown = row.preview_scope.as_ref().ok_or_else(refused)?;
        if shown.binding.is_none()
            || shown.recipient_user_id != auth.user_id
            || shown
                != &authorized_scope(&state, &row, auth.user_id, auth.claims.approval_revision)
                    .await?
        {
            return Err(refused());
        }
        if !state
            .ssh_rate_limiter
            .check_bounded(auth.user_id, shown.device_id, 20)
        {
            return Ok(limited());
        }
        if !storage(
            dao.decide(&row, &body.user_code, revision, body.approve)
                .await,
        )? {
            return Err(refused());
        }
        Ok(response(
            StatusCode::OK,
            json!({"status":if body.approve {"approved"} else {"denied"}}),
        ))
    })
    .await
}

pub async fn exchange(
    EnabledAuthorization(state): EnabledAuthorization,
    Json(body): Json<Exchange>,
) -> Result<Response, ApiError> {
    bounded(async {
        if body.device_code.len() != 43 || !(43..=128).contains(&body.code_verifier.len())
            || !body.code_verifier.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(ApiError::Unauthorized("Invalid native SSH proof".into()));
        }
        let dao = NativeSshAuthorizationDao::new(&state.core.db);
        let row = match storage(dao.poll(&body.device_code, &body.code_verifier).await)? {
            Poll::Found(row) => row,
            Poll::Limited => return Ok(limited()),
            Poll::Invalid => return Err(ApiError::Unauthorized("Invalid native SSH proof".into())),
        };
        match row.state.as_str() {
            "pending" => return Ok(response(StatusCode::CONFLICT, json!({"error":"authorization_pending"}))),
            "approved" => {},
            _ => return Err(refused()),
        }
        let scope = row.scope.as_ref().ok_or_else(refused)?;
        let binding = scope.binding.as_ref().ok_or_else(refused)?;
        if scope != &authorized_scope(&state, &row, scope.recipient_user_id, scope.approval_revision).await? {
            return Err(refused());
        }
        let now = DateTime::now().timestamp_millis();
        let expires_at = (now + NativeSshAuthorization::GRANT_TTL_SECS * 1000)
            .min(binding.request_expires_at.timestamp_millis()).min(binding.share_expires_at.timestamp_millis());
        if expires_at <= now { return Err(refused()); }
        let grant = format!("mhssh_{}", random_code());
        if !storage(dao.exchange(&row, &grant, DateTime::from_millis(expires_at)).await)? {
            return Err(refused());
        }
        Ok(response(StatusCode::OK, json!({
            "grant":grant, "expires_in":(expires_at-now)/1000,
            "scope":{"operation":"ssh", "share_grant_id":binding.share_grant_id.to_hex(),
                "device_id":scope.device_id.to_hex(), "recipient_user_id":scope.recipient_user_id.to_hex(),
                "public_key":binding.public_key, "session_secs":binding.session_secs},
        })))
    }).await
}
