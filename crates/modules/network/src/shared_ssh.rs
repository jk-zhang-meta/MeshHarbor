// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit recipient-only embedded SSH bridge. Not a tenant/overlay principal:
//! original tunnel tenant guards remain untouched and this route never calls
//! overlay join, enrolls a tunnel-client, registers DNS, or forwards a host/port.
use crate::NetworkState;
use axum::{
    Json,
    extract::{
        Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, header::AUTHORIZATION},
    response::Response,
};
use bson::oid::ObjectId;
use meshharbor_core::{
    AgentCtx, ApiError, device_share::authorize_grant, extractors::auth::AuthUser,
};
use meshharbor_db::models::DeviceShareOperation;
use meshharbor_remote_control::{
    models::{ConsentMode, OsKind, RpcCap, SshAccountMode, SshMode, SshPolicy, ssh_limits},
    signaling::{ClientMsg, CloseReason, ServerMsg, SharedSessionLease, SharedSshSetup},
};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, mpsc};

#[derive(Clone)]
pub(crate) enum SessionAuthority {
    Account(meshharbor_services::auth::Claims),
    NativeGrant {
        row: Box<meshharbor_db::models::NativeSshAuthorization>,
        expires_at_ms: i64,
    },
}

enum SessionAuth {
    Account(AuthUser),
    NativeGrant {
        user_id: ObjectId,
        row: Box<meshharbor_db::models::NativeSshAuthorization>,
    },
}

#[derive(Clone)]
pub(crate) struct SharedSshSession {
    pub id: ObjectId,
    pub device: ObjectId,
    pub recipient: ObjectId,
    pub grant: ObjectId,
    pub revision: u32,
    pub authority: SessionAuthority,
    pub lease: SharedSessionLease,
    pub policy: SshPolicy,
    pub outbound: mpsc::Sender<ServerMsg>,
    pub last_challenge: Arc<AtomicU64>,
    pub prepared: Arc<Mutex<Option<tokio::sync::oneshot::Sender<bool>>>>,
    pub revocation_audited: Arc<AtomicBool>,
}
#[derive(Serialize)]
pub struct SharedSshDevice {
    pub id: String,
    pub name: String,
    pub host_pubkey: String,
}
#[derive(Deserialize)]
pub struct ConnectQuery {
    pub public_key: String,
    #[serde(default)]
    pub session_secs: u64,
}
fn deny(message: &str) -> ApiError {
    ApiError::Forbidden(message.into())
}
/// The account a shared session becomes: the share's own, re-validated on every read.
fn shared_account(grant: &meshharbor_db::models::DeviceShareGrant) -> Option<String> {
    grant
        .ssh_account
        .clone()
        .filter(|a| meshharbor_db::models::device_share::valid_share_account(a))
}
/// Role membership is NOT inferred. An explicit approved-recipient SSH grant is
/// this route's authority; all target/org/local SSH policies still restrict it.
pub(crate) async fn authorization_policy(
    state: &NetworkState,
    user: ObjectId,
    grant: ObjectId,
) -> Result<meshharbor_core::device_share::SharedDeviceAccess, ApiError> {
    tokio::time::timeout(Duration::from_secs(3),async {
        let access=authorize_grant(&state.core,user,grant,DeviceShareOperation::Ssh).await?;
        let a=&access.agent;
        let tenant=state.tenants.base.find_by_id(a.tenant_id).await?;
        if !tenant.settings.remote_ssh_enabled {return Err(deny("The organization has disabled embedded SSH"));}
        // The share's own account, never the device policy's (often the daemon's root). A row
        // without one predates the choice and is refused rather than silently inheriting root.
        if shared_account(&access.grant).is_none() {return Err(deny("This SSH share names no device account; ask the owner to share it again"));}
        if a.os==OsKind::Windows {return Err(deny("SSH sharing is available for Linux and macOS devices"));}
        let (gates,_)=a.ssh_policy.clone().split();
        if crate::routes::agent_ssh::routes_ssh_via_service(state,a,SshAccountMode::Named,false) {return Err(deny("This device policy requires its SYSTEM-service SSH bridge, which sharing does not yet support"));}
        if gates.mode!=SshMode::On || !gates.allows_caller(&user,&[]) {return Err(deny("The device's SSH policy does not permit this recipient"));}
        // A role-only allowlist does not turn an external recipient into a member.
        let p=&a.access_policy;
        if (!p.allowed_user_ids.is_empty()||!p.allowed_role_ids.is_empty())&&!p.allowed_user_ids.contains(&user) {return Err(deny("The device access allowlist does not permit this recipient"));}
        Ok(access)
    }).await.map_err(|_|deny("Shared SSH policy lookup timed out"))?
}

/// Opening the bridge retains every live transport/agent enforcement gate.
async fn pdp(
    state: &NetworkState,
    user: ObjectId,
    grant: ObjectId,
) -> Result<meshharbor_core::device_share::SharedDeviceAccess, ApiError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let access = authorization_policy(state, user, grant).await?;
        let a = &access.agent;
        if !state.fleet.rc_hub.is_agent_online(access.grant.device_id)
            || state.fleet.rc_hub.agent_org(access.grant.device_id) != Some(a.tenant_id)
        {
            return Err(deny(
                "Shared SSH requires this device on this server; no cross-pod fallback",
            ));
        }
        for cap in [
            RpcCap::Ssh,
            RpcCap::SshConsent,
            RpcCap::SharedSessionLease,
            RpcCap::SharedSshStream,
        ] {
            if !a.capabilities.has_rpc(cap) {
                return Err(deny("This agent cannot enforce scoped shared embedded SSH"));
            }
        }
        if a.ssh_host_pubkey.is_empty() {
            return Err(deny("Device has not published an SSH host key"));
        }
        Ok(access)
    })
    .await
    .map_err(|_| deny("Shared SSH policy lookup timed out"))?
}

async fn verify_account_token(state: &NetworkState, token: &str) -> Result<AuthUser, ApiError> {
    let claims = state.core.auth.verify_access_token(token)?;
    meshharbor_core::admission::authorize_claims(&state.core, &claims).await?;
    let user_id = ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::Unauthorized("Invalid user ID in token".into()))?;
    Ok(AuthUser {
        user_id,
        email: claims.email.clone(),
        username: claims.username.clone(),
        claims,
    })
}

async fn verify_account_headers(
    state: &NetworkState,
    headers: &HeaderMap,
) -> Result<AuthUser, ApiError> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
        .or_else(|| meshharbor_core::cookies::get(headers, "access_token"))
        .ok_or_else(|| ApiError::Unauthorized("No token provided".into()))?;
    verify_account_token(state, &token).await
}

pub async fn metadata(
    State(state): State<NetworkState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SharedSshDevice>, ApiError> {
    if let Some(bearer) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        && crate::native_ssh_authorization::is_native_grant_bearer(bearer)
    {
        if !state.settings.auth.native_share_ssh_authorization_enabled {
            return Err(ApiError::ServiceUnavailable(
                "Native SSH authorization is disabled".into(),
            ));
        }
        let id =
            ObjectId::parse_str(id).map_err(|_| ApiError::BadRequest("Invalid share ID".into()))?;
        let (_, scope) =
            crate::native_ssh_authorization::verify_exchanged_grant(&state, id, bearer).await?;
        let a = pdp(&state, scope.recipient_user_id, id).await?;
        return Ok(Json(SharedSshDevice {
            id: a.grant.device_id.to_hex(),
            name: a.agent.name,
            host_pubkey: a.agent.ssh_host_pubkey,
        }));
    }
    let auth = verify_account_headers(&state, &headers).await?;
    let id =
        ObjectId::parse_str(id).map_err(|_| ApiError::BadRequest("Invalid share ID".into()))?;
    let a = pdp(&state, auth.user_id, id).await?;
    Ok(Json(SharedSshDevice {
        id: a.grant.device_id.to_hex(),
        name: a.agent.name,
        host_pubkey: a.agent.ssh_host_pubkey,
    }))
}
pub async fn connect(
    State(state): State<NetworkState>,
    Path(id): Path<String>,
    Query(q): Query<ConnectQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    // Native CLI endpoint: require an explicit Authorization header. A browser
    // cannot silently spend an ambient session cookie through a foreign origin.
    let Some(bearer) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return Err(ApiError::Unauthorized(
            "Shared SSH WebSocket requires an explicit access bearer".into(),
        ));
    };
    if crate::native_ssh_authorization::is_native_grant_bearer(bearer) {
        if !state.settings.auth.native_share_ssh_authorization_enabled {
            return Err(ApiError::ServiceUnavailable(
                "Native SSH authorization is disabled".into(),
            ));
        }
        let Ok(id) = ObjectId::parse_str(id) else {
            crate::native_ssh_authorization::record_audit(
                &state,
                meshharbor_db::models::NativeSshAuditEvent {
                    id: None,
                    authorization_id: None,
                    share_grant_id: None,
                    tenant_id: None,
                    device_id: None,
                    owner_user_id: None,
                    recipient_user_id: None,
                    grant_id: None,
                    public_key_fingerprint: None,
                    session_id: None,
                    ssh_account: None,
                    session_secs: Some(q.session_secs),
                    stage: "dispatch".into(),
                    outcome: "refused".into(),
                    reason: Some("invalid_share_grant_id".into()),
                    at: bson::DateTime::now(),
                },
            )
            .await;
            return Err(ApiError::BadRequest("Invalid share ID".into()));
        };
        if q.public_key.len() > 1024
            || !crate::routes::agent_ssh::is_supported_public_key(&q.public_key)
        {
            let existing =
                meshharbor_services::dao::native_ssh_authorization::NativeSshAuthorizationDao::new(
                    &state.core.db,
                )
                .by_grant_hash(bearer)
                .await
                .ok()
                .flatten();
            let event = if let Some(existing) = existing.as_ref() {
                crate::native_ssh_authorization::audit_from_row(
                    existing,
                    existing.scope.as_ref(),
                    "dispatch",
                    "refused",
                    Some("invalid_public_key"),
                )
            } else {
                meshharbor_db::models::NativeSshAuditEvent {
                    id: None,
                    authorization_id: None,
                    share_grant_id: Some(id),
                    tenant_id: None,
                    device_id: None,
                    owner_user_id: None,
                    recipient_user_id: None,
                    grant_id: None,
                    public_key_fingerprint: None,
                    session_id: None,
                    ssh_account: None,
                    session_secs: Some(q.session_secs),
                    stage: "dispatch".into(),
                    outcome: "refused".into(),
                    reason: Some("invalid_public_key".into()),
                    at: bson::DateTime::now(),
                }
            };
            crate::native_ssh_authorization::record_audit(&state, event).await;
            return Err(ApiError::BadRequest(
                "A valid Ed25519 ephemeral public key is required".into(),
            ));
        }
        let (row, scope) = crate::native_ssh_authorization::verify_exchanged_grant_for_dispatch(
            &state, id, bearer,
        )
        .await?;
        if row.public_key != q.public_key {
            crate::native_ssh_authorization::record_audit(
                &state,
                crate::native_ssh_authorization::audit_from_row(
                    &row,
                    Some(&scope),
                    "dispatch",
                    "refused",
                    Some("public_key_mismatch"),
                ),
            )
            .await;
            return Err(deny("Native SSH authorization refused"));
        }
        if q.session_secs > row.session_secs {
            crate::native_ssh_authorization::record_audit(
                &state,
                crate::native_ssh_authorization::audit_from_row(
                    &row,
                    Some(&scope),
                    "dispatch",
                    "refused",
                    Some("session_secs_exceeds_grant"),
                ),
            )
            .await;
            return Err(deny("Native SSH authorization refused"));
        }
        let access = match pdp(&state, scope.recipient_user_id, id).await {
            Ok(access) => access,
            Err(e) => {
                crate::native_ssh_authorization::record_audit(
                    &state,
                    crate::native_ssh_authorization::audit_from_row(
                        &row,
                        Some(&scope),
                        "dispatch",
                        "refused",
                        Some("pdp_or_agent_unavailable"),
                    ),
                )
                .await;
                return Err(e);
            }
        };
        let Ok(slot) = state.shared_ssh_slots.clone().try_acquire_owned() else {
            crate::native_ssh_authorization::record_audit(
                &state,
                crate::native_ssh_authorization::audit_from_row(
                    &row,
                    Some(&scope),
                    "dispatch",
                    "refused",
                    Some("session_slot_limit_reached"),
                ),
            )
            .await;
            return Err(deny("Shared SSH session capacity reached"));
        };
        if !state.ssh_rate_limiter.check_bounded(
            scope.recipient_user_id,
            access.grant.device_id,
            ssh_limits::RATE_LIMIT_PER_MINUTE,
        ) {
            crate::native_ssh_authorization::record_audit(
                &state,
                crate::native_ssh_authorization::audit_from_row(
                    &row,
                    Some(&scope),
                    "dispatch",
                    "refused",
                    Some("rate_limited"),
                ),
            )
            .await;
            return Err(deny("Shared SSH request rate exceeded"));
        }
        crate::native_ssh_authorization::consume_exchanged_grant(&state, &row, bearer).await?;
        let sid = ObjectId::new();
        let mut consumed_audit = crate::native_ssh_authorization::audit_from_row(
            &row,
            Some(&scope),
            "dispatch",
            "consumed",
            None,
        );
        consumed_audit.session_id = Some(sid);
        crate::native_ssh_authorization::record_audit(&state, consumed_audit).await;
        let auth = SessionAuth::NativeGrant {
            user_id: scope.recipient_user_id,
            row: Box::new(row),
        };
        return Ok(ws
            .max_message_size(64 * 1024)
            .on_upgrade(move |socket| run(state, socket, auth, id, q, slot, sid)));
    }
    let auth = verify_account_token(&state, bearer).await?;
    let id =
        ObjectId::parse_str(id).map_err(|_| ApiError::BadRequest("Invalid share ID".into()))?;
    let access = pdp(&state, auth.user_id, id).await?;
    if q.public_key.len() > 1024
        || !crate::routes::agent_ssh::is_supported_public_key(&q.public_key)
    {
        return Err(ApiError::BadRequest(
            "A valid Ed25519 ephemeral public key is required".into(),
        ));
    }
    let slot = state
        .shared_ssh_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| deny("Shared SSH session capacity reached"))?;
    if !state.ssh_rate_limiter.check_bounded(
        auth.user_id,
        access.grant.device_id,
        ssh_limits::RATE_LIMIT_PER_MINUTE,
    ) {
        return Err(deny("Shared SSH request rate exceeded"));
    }
    let auth = SessionAuth::Account(auth);
    let sid = ObjectId::new();
    Ok(ws
        .max_message_size(64 * 1024)
        .on_upgrade(move |socket| run(state, socket, auth, id, q, slot, sid)))
}
async fn audit_live_revocation_once(
    state: &NetworkState,
    s: &SharedSshSession,
    row: &meshharbor_db::models::NativeSshAuthorization,
    expires_at_ms: i64,
) {
    if !s.revocation_audited.swap(true, Ordering::SeqCst) {
        let reason = crate::native_ssh_authorization::classify_live_revocation_reason(
            state,
            row,
            expires_at_ms,
        )
        .await;
        let mut event = crate::native_ssh_authorization::audit_from_row(
            row,
            row.scope.as_ref(),
            "revocation_terminate",
            "terminated",
            Some(reason),
        );
        event.session_id = Some(s.id);
        crate::native_ssh_authorization::record_audit(state, event).await;
    }
}
async fn valid(state: &NetworkState, s: &SharedSshSession) -> bool {
    match &s.authority {
        SessionAuthority::Account(claims) => {
            if (bson::DateTime::now().timestamp_millis() / 1000) >= claims.exp
                || meshharbor_core::admission::authorize_claims(&state.core, claims)
                    .await
                    .is_err()
            {
                return false;
            }
        }
        SessionAuthority::NativeGrant { row, expires_at_ms } => {
            if bson::DateTime::now().timestamp_millis() >= *expires_at_ms
                || !crate::native_ssh_authorization::live_session_scope_valid(state, row).await
            {
                audit_live_revocation_once(state, s, row, *expires_at_ms).await;
                return false;
            }
        }
    }
    let pdp_ok = pdp(state, s.recipient, s.grant).await.is_ok_and(|a| {
        a.grant.revision == s.revision
            && a.grant.device_id == s.device
            && a.agent.ssh_policy == s.policy
    });
    if !pdp_ok && let SessionAuthority::NativeGrant { row, expires_at_ms } = &s.authority {
        audit_live_revocation_once(state, s, row, *expires_at_ms).await;
    }
    pdp_ok
}
fn terminate(state: &NetworkState, sid: ObjectId, s: &SharedSshSession) {
    state.shared_ssh_sessions.remove(&sid);
    state.tunnel_clients_by_session.remove(&sid);
    if let Some(mut set) = state.tunnel_sessions_by_target_agent.get_mut(&s.device) {
        set.remove(&sid);
    }
    let msg = ServerMsg::TunnelTerminate {
        session_id: sid,
        reason: CloseReason::IoError,
    };
    let _ = s.outbound.try_send(msg.clone());
    let _ = state.fleet.rc_hub.send_to_agent(s.device, msg);
}
/// The authenticated agent must confirm this exact prepared stream; no user ACK.
pub(crate) async fn prepared(state: &NetworkState, ctx: &AgentCtx, sid: ObjectId, accepted: bool) {
    let Some(s) = state.shared_ssh_sessions.get(&sid).map(|e| e.clone()) else {
        return;
    };
    if s.device != ctx.agent_id {
        return;
    }
    if let Some(tx) = s.prepared.lock().await.take() {
        let _ = tx.send(accepted);
    }
}
/// Every echo requires a new full PDP read and the original policy revision.
pub(crate) async fn renew(
    state: &NetworkState,
    ctx: &AgentCtx,
    sid: ObjectId,
    grant: ObjectId,
    epoch: String,
    challenge: u64,
) {
    let Some(s) = state.shared_ssh_sessions.get(&sid).map(|e| e.clone()) else {
        return;
    };
    if s.device != ctx.agent_id
        || s.grant != grant
        || s.lease.lease_epoch != epoch
        || challenge == 0
        || !state
            .ssh_shared_lease_limiter
            .check_bounded(ctx.agent_id, sid, 40)
    {
        return;
    }
    if s.last_challenge.fetch_max(challenge, Ordering::SeqCst) >= challenge {
        return;
    }
    if !valid(state, &s).await {
        terminate(state, sid, &s);
        return;
    }
    if !state.shared_ssh_sessions.contains_key(&sid) {
        return;
    }
    let _ = ctx.tx.try_send(ServerMsg::SharedSshLeaseRenewal {
        session_id: sid,
        grant_id: grant,
        lease_epoch: epoch,
        challenge_id: challenge,
    });
}
async fn run(
    state: NetworkState,
    mut socket: WebSocket,
    auth: SessionAuth,
    grant: ObjectId,
    q: ConnectQuery,
    _slot: tokio::sync::OwnedSemaphorePermit,
    sid: ObjectId,
) {
    let user = match &auth {
        SessionAuth::Account(auth) => auth.user_id,
        SessionAuth::NativeGrant { user_id, .. } => *user_id,
    };
    let Ok(access) = pdp(&state, user, grant).await else {
        return;
    };
    let secs_left = ((access.grant.expires_at.timestamp_millis()
        - bson::DateTime::now().timestamp_millis())
        / 1000)
        .max(0) as u64;
    if secs_left == 0 {
        return;
    }
    let session_secs = match &auth {
        SessionAuth::Account(_) => ssh_limits::clamp_session_secs(q.session_secs).min(secs_left),
        SessionAuth::NativeGrant { row, .. } => {
            if !crate::native_ssh_authorization::live_session_scope_valid(&state, row).await {
                return;
            }
            let requested = if q.session_secs == 0 {
                row.session_secs
            } else {
                q.session_secs.min(row.session_secs)
            };
            ssh_limits::clamp_session_secs(requested)
                .min(row.session_secs)
                .min(secs_left)
        }
    };
    if session_secs == 0 {
        return;
    }
    let authority = match auth {
        SessionAuth::Account(auth) => SessionAuthority::Account(auth.claims),
        SessionAuth::NativeGrant { row, .. } => {
            let expires_at_ms = (bson::DateTime::now().timestamp_millis()
                + (session_secs as i64) * 1000)
                .min(access.grant.expires_at.timestamp_millis());
            SessionAuthority::NativeGrant { row, expires_at_ms }
        }
    };
    let (out, mut rx) = mpsc::channel(64);
    let (prepared_tx, prepared_rx) = tokio::sync::oneshot::channel();
    let lease = SharedSessionLease {
        grant_id: grant,
        lease_epoch: uuid::Uuid::new_v4().to_string(),
        // An SSH stream carries its account in `SharedSshSetup`, not here.
        account: None,
    };
    let s = SharedSshSession {
        id: sid,
        authority,
        device: access.grant.device_id,
        recipient: user,
        grant,
        revision: access.grant.revision,
        lease: lease.clone(),
        policy: access.agent.ssh_policy.clone(),
        outbound: out.clone(),
        last_challenge: Arc::new(AtomicU64::new(0)),
        prepared: Arc::new(Mutex::new(Some(prepared_tx))),
        revocation_audited: Arc::new(AtomicBool::new(false)),
    };
    state.shared_ssh_sessions.insert(sid, s.clone());
    struct Cleanup {
        state: NetworkState,
        sid: ObjectId,
        scope: SharedSshSession,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            terminate(&self.state, self.sid, &self.scope);
        }
    }
    let _cleanup = Cleanup {
        state: state.clone(),
        sid,
        scope: s.clone(),
    };
    state.tunnel_clients_by_session.insert(sid, out.clone());
    state
        .tunnel_sessions_by_target_agent
        .entry(s.device)
        .or_default()
        .insert(sid);
    let (_, spec) = access.agent.ssh_policy.split();
    let Some(account) = shared_account(&access.grant) else {
        return;
    };
    let caller = match &s.authority {
        SessionAuthority::Account(_) => format!("approved recipient {user} / share {grant}"),
        SessionAuthority::NativeGrant { row, .. } => {
            format!(
                "approved recipient {user} / share {grant} / auth {}",
                row.authorization_id
            )
        }
    };
    let setup = SharedSshSetup {
        device_id: s.device,
        owner_user_id: access.grant.owner_user_id,
        recipient_user_id: user,
        shared_lease: lease.clone(),
        ssh_grant_id: ObjectId::new().to_hex(),
        public_key: q.public_key,
        caller,
        account_mode: SshAccountMode::Named,
        account: Some(account),
        consent_mode: Some(if spec.consent_mode == Some(ConsentMode::Auto) {
            ConsentMode::Auto
        } else {
            ConsentMode::Prompt
        }),
        expires_at_ms: (bson::DateTime::now().timestamp_millis().max(0) as u64)
            + ssh_limits::GRANT_TTL_SECS * 1000,
        session_secs,
    };
    let audit = meshharbor_remote_control::models::SshAuditEvent {
        id: None,
        tenant_id: access.agent.tenant_id,
        agent_id: s.device,
        user_id: user,
        origin_agent_id: None,
        grant_id: Some(setup.ssh_grant_id.clone()),
        source: "device_share".into(),
        session_id: Some(sid),
        ssh_ticket_id: None,
        caller: setup.caller.clone(),
        account_mode: Some(setup.account_mode.wire().into()),
        session_secs: Some(session_secs),
        at: bson::DateTime::now(),
        denied: None,
        ran_as: Some("embedded_shared_stream".into()),
    };
    if state
        .fleet
        .rc_hub
        .send_to_agent(
            s.device,
            ServerMsg::SharedSshSetup {
                session_id: sid,
                setup,
            },
        )
        .is_err()
    {
        if let SessionAuthority::NativeGrant { row, .. } = &s.authority {
            let mut event = crate::native_ssh_authorization::audit_from_row(
                row,
                row.scope.as_ref(),
                "dispatch",
                "refused",
                Some("agent_offline_after_consume"),
            );
            event.session_id = Some(sid);
            crate::native_ssh_authorization::record_audit(&state, event).await;
        }
        return;
    }
    if !matches!(
        tokio::time::timeout(Duration::from_secs(5), prepared_rx).await,
        Ok(Ok(true))
    ) {
        if let SessionAuthority::NativeGrant { row, .. } = &s.authority {
            let mut event = crate::native_ssh_authorization::audit_from_row(
                row,
                row.scope.as_ref(),
                "dispatch",
                "refused",
                Some("agent_rejected_setup_after_consume"),
            );
            event.session_id = Some(sid);
            crate::native_ssh_authorization::record_audit(&state, event).await;
        }
        return;
    }
    let _ = state.ssh_audit.record(audit).await;
    let mut opened = false;
    let mut flow = None;
    let mut offered = false;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=tick.tick()=> {if !valid(&state,&s).await {break;}}
            msg=rx.recv()=> {let Some(msg)=msg else {break;};let ended=matches!(msg,ServerMsg::TunnelTerminate {..}|ServerMsg::TcpClosed {..});if !matches!(tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Text(serde_json::to_string(&msg).unwrap_or_default().into()))).await,Ok(Ok(())))||ended{break;}}
            incoming=socket.recv()=> {
                let Some(Ok(msg))=incoming else {break;};
                let Message::Text(text)=msg else {if matches!(msg,Message::Close(_)){break;}else{continue;}};
                let Ok(msg)=serde_json::from_str::<ClientMsg>(&text) else {break;};
                // Fresh authority before every data-plane mutation, not after it.
                if !valid(&state,&s).await {break;}
                match msg {
                    ClientMsg::TunnelHello {..}=>{},
                    ClientMsg::TunnelOpen {agent_id,transport,net_grant,derp_pubkey,open_nonce} if !opened && agent_id==s.device && transport=="webrtc-dc-v1" && net_grant.is_none() && derp_pubkey.is_none()=> {
                        opened=true;
                        let ice=meshharbor_remote_control::turn_creds::ice_servers_for(&meshharbor_remote_control::turn_creds::charged(&sid.to_hex(),&access.agent.tenant_id.to_hex()),state.turn_map.cfg_for(None));
                        let m=ServerMsg::TunnelOpened {session_id:sid,transport:"webrtc-dc-v1".into(),dc_pool_size:8,sctp_rwnd_bytes:8*1024*1024,ice_servers:ice,quic_auth_token:None,open_nonce,net_grant_id:None};
                        if out.try_send(m).is_err(){break;}
                    }
                    ClientMsg::TunnelSdpOffer {session_id,sdp} if opened && !offered && session_id==sid=> {
                        offered=true;
                        if state.fleet.rc_hub.send_to_agent(s.device,ServerMsg::TunnelSdpOffer {session_id:sid,sdp,shared_lease:Some(lease.clone())}).is_err(){break;}
                    }
                    ClientMsg::TunnelIce {session_id,candidate} if offered && session_id==sid=> {if state.fleet.rc_hub.send_to_agent(s.device,ServerMsg::TunnelIce {session_id:sid,candidate}).is_err(){break;}}
                    ClientMsg::SharedSshConnect {session_id,flow_id} if offered && flow.is_none() && session_id==sid=> {flow=Some(flow_id);if state.fleet.rc_hub.send_to_agent(s.device,ServerMsg::SharedSshForward {session_id:sid,flow_id}).is_err(){break;}}
                    ClientMsg::TcpHalfClose {session_id,flow_id,direction} if flow==Some(flow_id) && session_id==sid=> {let _=state.fleet.rc_hub.send_to_agent(s.device,ServerMsg::TcpHalfClose {session_id:sid,flow_id,direction});}
                    ClientMsg::TcpClosed {session_id,..}|ClientMsg::TunnelTerminate {session_id,..} if session_id==sid=>break,
                    // No overlay join, device/netmap registration, UDP, arbitrary TCP,
                    // second flow, cross-account onward share, or SSH lease from user.
                    _=>break,
                }
            }
        }
    }
}

/// Existing ordinary tunnel relays stay unchanged; every shared reply first
/// proves it came from this session's authenticated target, never merely a SID.
pub(crate) fn agent_frame_allowed(state: &NetworkState, ctx: &AgentCtx, msg: &ClientMsg) -> bool {
    let sid = match msg {
        ClientMsg::TcpForwardAccept { session_id, .. }
        | ClientMsg::TcpForwardReject { session_id, .. }
        | ClientMsg::TcpHalfClose { session_id, .. }
        | ClientMsg::TcpClosed { session_id, .. }
        | ClientMsg::TunnelSdpAnswer { session_id, .. }
        | ClientMsg::TunnelIce { session_id, .. }
        | ClientMsg::TunnelTerminate { session_id, .. } => Some(*session_id),
        _ => None,
    };
    sid.and_then(|sid| {
        state
            .shared_ssh_sessions
            .get(&sid)
            .map(|s| s.device == ctx.agent_id)
    })
    .unwrap_or(true)
}
