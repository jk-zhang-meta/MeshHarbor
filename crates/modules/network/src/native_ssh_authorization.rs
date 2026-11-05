// SPDX-License-Identifier: AGPL-3.0-only
//! Browser approval and one-time exchange only. No account tokens or SSH transport.
use crate::{NetworkState, shared_ssh::authorization_policy};
use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bson::{DateTime, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::{NativeSshAuthorization, NativeSshScope};
use meshharbor_remote_control::models::ssh_limits;
use meshharbor_services::dao::{
    base::DaoResult,
    native_ssh_authorization::{NativeSshAuthorizationDao, Poll, hash_secret, random_code},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{future::Future, net::SocketAddr, time::Duration};

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
    State(state): State<NetworkState>,
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

pub async fn decide(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Decision>,
) -> Result<Response, ApiError> {
    bounded(async {
        if !trusted_origin(&state, &headers) || id.len() != 24 || body.user_code.len() != 12 {
            return Err(refused());
        }
        let id = ObjectId::parse_str(id).map_err(|_| refused())?;
        let dao = NativeSshAuthorizationDao::new(&state.core.db);
        let row = storage(dao.pending(id, &body.user_code).await)?.ok_or_else(refused)?;
        // This is the first share read: identity comes from the real browser
        // session, never a recipient supplied by the anonymous request.
        let access = authorization_policy(&state, auth.user_id, row.share_grant_id)
            .await
            .map_err(|_| refused())?;
        if !state
            .ssh_rate_limiter
            .check_bounded(auth.user_id, access.grant.device_id, 20)
        {
            return Ok(limited());
        }
        let scope = NativeSshScope {
            device_id: access.grant.device_id,
            tenant_id: access.grant.tenant_id,
            owner_user_id: access.grant.owner_user_id,
            recipient_user_id: auth.user_id,
            approval_revision: auth.claims.approval_revision,
            share_revision: access.grant.revision,
            ssh_account: access.grant.ssh_account.ok_or_else(refused)?,
            ssh_policy: bson::to_document(&access.agent.ssh_policy).map_err(|_| refused())?,
        };
        if !storage(
            dao.decide(id, &body.user_code, body.approve.then_some(&scope))
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
    State(state): State<NetworkState>,
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
        meshharbor_core::admission::authorize_user_id(&state.core, scope.recipient_user_id, Some(scope.approval_revision)).await?;
        let access = authorization_policy(&state, scope.recipient_user_id, row.share_grant_id).await.map_err(|_| refused())?;
        if access.grant.revision != scope.share_revision || access.grant.device_id != scope.device_id
            || access.grant.tenant_id != scope.tenant_id || access.grant.owner_user_id != scope.owner_user_id
            || access.grant.ssh_account.as_deref() != Some(scope.ssh_account.as_str())
            || bson::to_document(&access.agent.ssh_policy).map_err(|_| refused())? != scope.ssh_policy
        {
            return Err(refused());
        }
        let now = DateTime::now().timestamp_millis();
        let expires_at = (now + NativeSshAuthorization::GRANT_TTL_SECS * 1000)
            .min(row.expires_at.timestamp_millis()).min(access.grant.expires_at.timestamp_millis());
        if expires_at <= now { return Err(refused()); }
        let grant = format!("mhssh_{}", random_code());
        if !storage(dao.exchange(&row, &grant, DateTime::from_millis(expires_at)).await)? {
            return Err(refused());
        }
        Ok(response(StatusCode::OK, json!({
            "grant":grant, "expires_in":(expires_at-now)/1000,
            "scope":{"operation":"ssh", "share_grant_id":row.share_grant_id.to_hex(),
                "device_id":scope.device_id.to_hex(), "recipient_user_id":scope.recipient_user_id.to_hex(),
                "public_key":row.public_key, "session_secs":row.session_secs},
        })))
    }).await
}
