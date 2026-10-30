// SPDX-License-Identifier: AGPL-3.0-only
//! Private central-owner view/approval of business device-use authority.
//!
//! A tenant administrator, tag or relay toggle must not turn a client into an
//! unrestricted server. Reuse the configured account-review owner, and load the
//! actual current device row rather than accept identity fields from JSON.
use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use roomler_ai_config::AccountApprovalSettings;
use roomler_core::{
    ApiError,
    business_authority::{
        AuthenticatedDevice, DeviceAuthorityView, DeviceKind, DeviceUseRole, RoleApproval,
        approve_device_role, get_device_authority,
    },
    extractors::auth::AuthUser,
};
use serde::Deserialize;

use crate::NetworkState;

fn require_review_owner(
    policy: &AccountApprovalSettings,
    user_id: ObjectId,
) -> Result<(), ApiError> {
    let owner = roomler_core::admission::owner_id(policy)?
        .ok_or_else(|| ApiError::NotFound("Central role approval is not configured".into()))?;
    if owner != user_id {
        return Err(ApiError::Forbidden(
            "Only the configured account-review owner may manage business roles".into(),
        ));
    }
    Ok(())
}

async fn current_device(
    state: &NetworkState,
    kind: &str,
    tenant: &str,
    device: &str,
) -> Result<AuthenticatedDevice, ApiError> {
    let tid = ObjectId::parse_str(tenant)
        .map_err(|_| ApiError::BadRequest("Invalid tenant ID".into()))?;
    let id = ObjectId::parse_str(device)
        .map_err(|_| ApiError::BadRequest("Invalid device ID".into()))?;
    match kind {
        "agent" => {
            let row = state.fleet.agents.find_live_in_tenant(tid, id).await?;
            AuthenticatedDevice::from_agent(&row)
        }
        "tunnel-client" => {
            let row = state.tunnel_clients.find_live_in_tenant(tid, id).await?;
            AuthenticatedDevice::from_tunnel_client(&row)
        }
        _ => Err(ApiError::BadRequest("Unknown device kind".into())),
    }
}

/// GET /api/admin/business-authority/{kind}/{tenant_id}/{device_id}.
/// The private observation is never added to the ordinary device-list model.
pub async fn get(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((kind, tenant, device)): Path<(String, String, String)>,
) -> Result<Json<DeviceAuthorityView>, ApiError> {
    require_review_owner(&state.settings.auth.account_approval, auth.user_id)?;
    let identity = current_device(&state, &kind, &tenant, &device).await?;
    Ok(Json(get_device_authority(&state.core, &identity).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub role: DeviceUseRole,
    pub reason: String,
}

/// PUT the same private path. `unknown` explicitly revokes business-use role.
/// No body-supplied machine, generation, tenant or current geography is trusted.
pub async fn approve(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((kind, tenant, device)): Path<(String, String, String)>,
    Json(body): Json<ApprovalRequest>,
) -> Result<Json<RoleApproval>, ApiError> {
    require_review_owner(&state.settings.auth.account_approval, auth.user_id)?;
    let identity = current_device(&state, &kind, &tenant, &device).await?;
    let approval =
        approve_device_role(&state.core, &auth, &identity, body.role, &body.reason).await?;
    // MeshHarbor `auto` + Item #96: any role change fences in-flight mints,
    // re-fans the tenant's overlay netmaps, rebuilds the DERP allow table, and
    // revokes sessions/grants the new role no longer permits.
    let tenant_id = approval.identity.tenant_id;
    let device_id = approval.identity.device_id;
    state.org_relay.invalidate_eligibility();
    if approval.identity.kind == DeviceKind::Agent && approval.role != DeviceUseRole::Server {
        crate::org_relay::revoke_where(&state, "role_revoked", |s| {
            s.implicit && s.relay_agent_id == device_id
        })
        .await;
    }
    if approval.role == DeviceUseRole::Unknown
        && crate::business_isolation::mode(&state) == crate::business_isolation::Mode::Enforce
        && crate::business_isolation::unknown_role_mode(&state)
            == crate::business_isolation::Mode::Enforce
    {
        crate::org_relay::revoke_where(&state, "role_revoked", |s| {
            s.tenant_id == tenant_id && s.involves_device(approval.identity.kind, device_id)
        })
        .await;
    }
    crate::tunnel::reconcile_tunnel_sessions(&state, tenant_id).await;
    crate::managed_forward::reconcile_tenant_forwards(&state, tenant_id).await;
    if let Ok(Some(net)) = state.overlay_networks.find_for_tenant(tenant_id).await
        && let Some(network_id) = net.id
    {
        if let Ok(nodes) = state
            .overlay_nodes
            .list_active_in_network(tenant_id, network_id)
            .await
        {
            for node in &nodes {
                crate::overlay::refan_node(&state, node).await;
            }
        }
        crate::derp_acl::rebuild(&state, tenant_id, network_id).await;
    }
    crate::org_relay::recheck_zones(&state, device_id, "role_changed").await;
    crate::org_relay::reconcile_acl(&state, tenant_id).await;
    Ok(Json(approval))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_configured_central_owner_can_approve() {
        let owner = ObjectId::new();
        let policy = AccountApprovalSettings {
            enabled: true,
            owner_user_id: Some(owner.to_hex()),
        };
        assert!(require_review_owner(&policy, owner).is_ok());
        // No tenant or platform role is an input capable of widening this.
        assert!(require_review_owner(&policy, ObjectId::new()).is_err());
    }

    #[test]
    fn disabled_or_invalid_central_owner_does_not_enable_role_assignment() {
        assert!(
            require_review_owner(&AccountApprovalSettings::default(), ObjectId::new()).is_err()
        );
        let invalid = AccountApprovalSettings {
            enabled: true,
            owner_user_id: Some("not-an-object-id".into()),
        };
        assert!(require_review_owner(&invalid, ObjectId::new()).is_err());
    }

    #[test]
    fn role_request_cannot_override_identity_or_region() {
        for extra in [
            "tenant_id",
            "device_id",
            "machine_id",
            "token_gen",
            "zone",
            "source_ip",
            "approved_by",
        ] {
            let mut value =
                serde_json::json!({"role":"server", "reason":"explicit central review"});
            value[extra] = serde_json::json!("forged");
            assert!(
                serde_json::from_value::<ApprovalRequest>(value).is_err(),
                "{extra}"
            );
        }
        assert!(
            serde_json::from_value::<ApprovalRequest>(serde_json::json!({"role":"server"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<ApprovalRequest>(
                serde_json::json!({"reason":"missing explicit role"})
            )
            .is_err()
        );
    }
}
