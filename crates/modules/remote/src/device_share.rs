// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit share-bound remote sessions; existing org paths remain independent.
use crate::{RemoteState, controller::SessionAuthz};
use axum::{
    Json,
    extract::{Path, State},
};
use bson::{DateTime, oid::ObjectId};
use roomler_ai_db::models::{DeviceShareGrant, DeviceShareOperation};
use roomler_ai_remote_control::{
    models::{ConsentMode, EndReason},
    permissions::Permissions,
    signaling::ClientMsg,
};
use roomler_ai_services::dao::device_share::DeviceShareDao;
use roomler_core::{
    ApiError,
    device_share::{SharedDeviceAccess, authorize_grant},
    extractors::auth::AuthUser,
};
use serde::Serialize;

#[derive(Clone)]
pub(crate) struct ShareScope {
    pub grant_id: ObjectId,
    pub revision: u32,
    pub recipient: ObjectId,
    pub device: ObjectId,
    pub asked: Permissions,
    pub consent_mode: ConsentMode,
}
pub(crate) fn requested_operation(asked: Permissions) -> Result<DeviceShareOperation, String> {
    let supported = Permissions::VIEW | Permissions::INPUT | Permissions::FILES;
    if asked.is_empty()
        || !(asked - supported).is_empty()
        || (asked.contains(Permissions::INPUT) && !asked.contains(Permissions::VIEW))
    {
        return Err(
            "Shared sessions support only explicit desktop view/control and bidirectional files"
                .into(),
        );
    }
    if asked.contains(Permissions::VIEW) {
        Ok(DeviceShareOperation::DesktopView)
    } else {
        Ok(DeviceShareOperation::FilesWrite)
    }
}
fn within_grant(g: &DeviceShareGrant, asked: Permissions) -> bool {
    (!asked.contains(Permissions::VIEW) || g.permissions.desktop_view)
        && (!asked.contains(Permissions::INPUT) || g.permissions.desktop_control)
        && (!asked.contains(Permissions::FILES)
            || (g.permissions.files_read && g.permissions.files_write))
}
pub(crate) async fn scope_for_request(
    state: &RemoteState,
    user: ObjectId,
    msg: &ClientMsg,
) -> Result<Option<(ShareScope, SharedDeviceAccess)>, String> {
    let ClientMsg::SessionRequest {
        agent_id,
        permissions,
        share_grant_id: Some(grant_id),
        override_reason,
        local_relay,
        audio_enabled,
        ..
    } = msg
    else {
        return Ok(None);
    };
    if local_relay.is_some()
        || override_reason
            .as_ref()
            .is_some_and(|v| !v.trim().is_empty())
        || *audio_enabled
    {
        return Err(
            "A device share cannot request break-glass, audio, overlay relay, or transit".into(),
        );
    }
    let op = requested_operation(*permissions)?;
    let access = authorize_grant(&state.core, user, *grant_id, op)
        .await
        .map_err(|e| e.to_string())?;
    if access.grant.device_id != *agent_id || !within_grant(&access.grant, *permissions) {
        return Err("Share does not permit this device and requested services".into());
    }
    // Do not send an unscoped share through the legacy cross-pod relay.
    if !state.fleet.rc_hub.is_agent_online(*agent_id)
        || state.fleet.rc_hub.agent_org(*agent_id) != Some(access.agent.tenant_id)
    {
        return Err(
            "Shared sessions require the device on this server; cross-pod sharing is not supported"
                .into(),
        );
    }
    if !access
        .agent
        .capabilities
        .has_rpc(roomler_ai_remote_control::models::RpcCap::SharedSessionLease)
    {
        return Err(
            "Shared sessions require an agent enforcing the short shared-session lease".into(),
        );
    }
    let policy = &access.agent.access_policy;
    if (!policy.allowed_user_ids.is_empty() || !policy.allowed_role_ids.is_empty())
        && !policy.allowed_user_ids.contains(&user)
    {
        return Err("The device's own access allowlist does not permit this recipient".into());
    }
    Ok(Some((
        ShareScope {
            grant_id: *grant_id,
            revision: access.grant.revision,
            recipient: user,
            device: *agent_id,
            asked: *permissions,
            consent_mode: policy.effective_consent_mode(),
        },
        access,
    )))
}
pub(crate) async fn session_authz(
    state: &RemoteState,
    user: ObjectId,
    msg: &ClientMsg,
) -> Result<SessionAuthz, String> {
    let Some((_, access)) = scope_for_request(state, user, msg).await? else {
        return Err("Missing explicit device share".into());
    };
    let tenant = state
        .tenants
        .base
        .find_by_id(access.agent.tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let secs = (access.grant.expires_at.timestamp_millis() - DateTime::now().timestamp_millis())
        .max(0) as u64
        / 1000;
    if secs == 0 {
        return Err("Share expires too soon to start a session".into());
    }
    let max_secs = tenant
        .settings
        .rc_limits
        .max_secs
        .map(u64::from)
        .unwrap_or(secs)
        .min(secs);
    let cap = if state.settings.rc.org_session_cap && state.plans_sold {
        crate::controller::org_session_cap_of(&tenant)
    } else {
        None
    };
    Ok(SessionAuthz {
        mode: access.agent.access_policy.effective_consent_mode(),
        override_reason: None,
        input_mode: access.agent.access_policy.input_mode,
        tenant_name: Some(tenant.name.clone()),
        may_record: false,
        rc_overlay: false,
        session_policy: roomler_ai_mod_fleet::hub::OrgPolicy::Read(crate::session_policy::wire(
            &tenant.settings.rc_session,
        )),
        max_duration: Some(std::time::Duration::from_secs(max_secs)),
        idle_secs: roomler_ai_remote_control::models::stricter_idle_limit(
            tenant.settings.rc_limits.idle_secs,
            access.agent.access_policy.idle_limit_secs(),
        ),
        lock_on_end: access.agent.access_policy.lock_on_end_ask(),
        org_session_cap: cap,
    })
}
/// Re-read all mutable sharing gates, not only the ledger row. Whole check is bounded.
pub(crate) async fn live_scope_valid(
    state: &RemoteState,
    scope: &ShareScope,
    effective: Permissions,
) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let op = requested_operation(scope.asked).map_err(ApiError::Forbidden)?;
        let a = authorize_grant(&state.core, scope.recipient, scope.grant_id, op).await?;
        let policy = &a.agent.access_policy;
        if !a
            .agent
            .capabilities
            .has_rpc(roomler_ai_remote_control::models::RpcCap::SharedSessionLease)
            || a.grant.revision != scope.revision
            || !within_grant(&a.grant, scope.asked)
            || policy.effective_consent_mode() != scope.consent_mode
            || ((!policy.allowed_user_ids.is_empty() || !policy.allowed_role_ids.is_empty())
                && !policy.allowed_user_ids.contains(&scope.recipient))
        {
            return Err(ApiError::Forbidden("Shared device policy changed".into()));
        }
        let tenant = state.tenants.base.find_by_id(a.agent.tenant_id).await?;
        use roomler_ai_db::models::RcFeaturePolicy;
        if effective.contains(Permissions::FILES)
            && (tenant.settings.rc_session.files == RcFeaturePolicy::Off
                || (tenant.settings.rc_session.files == RcFeaturePolicy::Ask
                    && scope.consent_mode == ConsentMode::Auto))
        {
            return Err(ApiError::Forbidden(
                "Organization no longer permits these file transfers".into(),
            ));
        }
        Ok::<(), ApiError>(())
    })
    .await
    .is_ok_and(|r| r.is_ok())
}
/// Exact session ID returned by Hub creation, never a user/device snapshot scan.
/// A storage outage also terminates; expiry and account/device/owner changes are live.
pub(crate) fn watch_session(state: RemoteState, session: ObjectId, scope: ShareScope) {
    if !state
        .fleet
        .rc_hub
        .claim_device_share_watch(session, scope.grant_id)
    {
        return;
    }
    state.shared_scopes.insert(session, scope.clone());
    tokio::spawn(async move {
        struct Remove {
            state: RemoteState,
            session: ObjectId,
        }
        impl Drop for Remove {
            fn drop(&mut self) {
                self.state.shared_scopes.remove(&self.session);
            }
        }
        let _remove = Remove {
            state: state.clone(),
            session,
        };
        loop {
            let Some((agent, user, effective)) = state.fleet.rc_hub.session_grant(session) else {
                return;
            };
            if agent != scope.device
                || user != scope.recipient
                || !(effective - scope.asked).is_empty()
            {
                let _ = state
                    .fleet
                    .rc_hub
                    .terminate(session, EndReason::AdminTerminated);
                return;
            }
            let valid = live_scope_valid(&state, &scope, effective).await;
            if !valid {
                let _ = state
                    .fleet
                    .rc_hub
                    .terminate(session, EndReason::AdminTerminated);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}
#[derive(Serialize)]
pub struct SharedRemoteDevice {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
    /// Public key for this exact device; used by the existing end-to-end answer verifier.
    pub peer_auth_key: String,
    pub os: roomler_ai_remote_control::models::OsKind,
    pub capabilities: roomler_ai_remote_control::models::AgentCaps,
    pub permissions: roomler_ai_db::models::DeviceSharePermissions,
    pub share_grant_id: String,
    pub expires_at_ms: i64,
}
/// A recipient sees ONLY this explicitly shared device, never the owner's fleet/tenant.
pub async fn device(
    State(state): State<RemoteState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<SharedRemoteDevice>, ApiError> {
    let id =
        ObjectId::parse_str(id).map_err(|_| ApiError::BadRequest("Invalid share ID".into()))?;
    let g = DeviceShareDao::new(&state.db).base.find_by_id(id).await?;
    if g.recipient_user_id != auth.user_id {
        return Err(ApiError::NotFound("Share not found".into()));
    }
    let op = if g.permissions.desktop_view {
        DeviceShareOperation::DesktopView
    } else if g.permissions.files_read && g.permissions.files_write {
        DeviceShareOperation::FilesWrite
    } else {
        return Err(ApiError::Forbidden(
            "This share has no supported desktop or bidirectional-file capability".into(),
        ));
    };
    let a = authorize_grant(&state.core, auth.user_id, id, op).await?;
    Ok(Json(SharedRemoteDevice {
        id: a.grant.device_id.to_hex(),
        name: a.agent.name,
        display_name: a.agent.display_name,
        peer_auth_key: a.agent.peer_auth_key,
        os: a.agent.os,
        capabilities: a.agent.capabilities,
        permissions: a.grant.permissions,
        share_grant_id: id.to_hex(),
        expires_at_ms: a.grant.expires_at.timestamp_millis(),
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_share_remote_ceiling_refuses_extra_services_and_read_only_files() {
        for p in [
            Permissions::CLIPBOARD,
            Permissions::AUDIO,
            Permissions::RECORD,
            Permissions::PRIVACY,
            Permissions::INPUT,
        ] {
            assert!(requested_operation(p).is_err())
        }
        let now = DateTime::now();
        let mut g = DeviceShareGrant {
            id: None,
            device_id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            owner_user_id: ObjectId::new(),
            recipient_user_id: ObjectId::new(),
            permissions: Default::default(),
            tcp_ports: vec![],
            created_at: now,
            expires_at: now,
            revoked_at: None,
            revision: 0,
        };
        g.permissions.files_read = true;
        assert!(!within_grant(&g, Permissions::FILES));
        g.permissions.files_write = true;
        assert!(within_grant(&g, Permissions::FILES));
        assert!(!within_grant(&g, Permissions::VIEW));
    }
}

/// Authenticated agent only. No heartbeat, cached approval, or user frame renews authority.
pub(crate) async fn renew_lease(
    state: &RemoteState,
    ctx: &roomler_core::AgentCtx,
    session: ObjectId,
    grant: ObjectId,
    epoch: String,
    challenge_id: u64,
) {
    if epoch.len() != 36 || challenge_id == 0 {
        return;
    }
    let Some(scope) = state.shared_scopes.get(&session).map(|e| e.clone()) else {
        return;
    };
    let hub = &state.fleet.rc_hub;
    let Some(lease) = hub.shared_lease(session) else {
        return;
    };
    let Some((agent, user, effective)) = hub.session_grant(session) else {
        return;
    };
    if agent != ctx.agent_id
        || agent != scope.device
        || user != scope.recipient
        || grant != scope.grant_id
        || lease.grant_id != grant
        || lease.lease_epoch != epoch
        || !(effective - scope.asked).is_empty()
        || !state
            .shared_lease_limiter
            .check_bounded(ctx.agent_id, session, 40)
    {
        return;
    }
    if !live_scope_valid(state, &scope, effective).await {
        let _ = hub.terminate(session, EndReason::AdminTerminated);
        return;
    }
    // The check may have yielded to a revoke/termination: never revive a removed session.
    if hub.shared_lease(session).as_ref() != Some(&lease) {
        return;
    }
    let _ = ctx.tx.try_send(
        roomler_ai_remote_control::signaling::ServerMsg::SharedLeaseRenewal {
            session_id: session,
            grant_id: grant,
            lease_epoch: epoch,
            challenge_id,
        },
    );
}
