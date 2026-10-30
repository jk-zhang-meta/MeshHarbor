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
    let device_kind = approval.identity.kind;
    let new_role = approval.role;
    state.org_relay.invalidate_eligibility();
    let key = (tenant_id, device_kind, device_id);
    let slot = device_reconcile_slot(tenant_id, device_kind, device_id);
    let my_gen = slot.generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;
    let st = state.clone();
    // Spawn the post-approval reconcile on the runtime so an HTTP caller that
    // disconnects mid-request cannot cancel revocation/re-fan, and schedule
    // capped-backoff retries if any step hits a transient storage read error.
    let reconcile_handle = tokio::spawn(async move {
        let ok = {
            let _guard = slot.lock.lock().await;
            if slot.generation.load(std::sync::atomic::Ordering::Acquire) != my_gen {
                drop(_guard);
                cleanup_device_reconcile_slot(key, slot);
                return;
            }
            apply_immediate_in_memory_revocations(&st, tenant_id, device_kind, device_id, new_role)
                .await;
            run_role_change_reconcile(&st, tenant_id, device_id).await
        };
        if !ok && slot.generation.load(std::sync::atomic::Ordering::Acquire) == my_gen {
            let retry_state = st;
            let retry_slot = slot;
            tokio::spawn(async move {
                for delay_ms in [200u64, 500, 1000]
                    .into_iter()
                    .chain(std::iter::repeat(2000u64))
                {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    if retry_slot.generation.load(std::sync::atomic::Ordering::Acquire) != my_gen {
                        cleanup_device_reconcile_slot(key, retry_slot);
                        return;
                    }
                    let done = {
                        let _guard = retry_slot.lock.lock().await;
                        if retry_slot.generation.load(std::sync::atomic::Ordering::Acquire)
                            != my_gen
                        {
                            drop(_guard);
                            cleanup_device_reconcile_slot(key, retry_slot);
                            return;
                        }
                        run_role_change_reconcile(&retry_state, tenant_id, device_id).await
                    };
                    if done {
                        tracing::info!(
                            %tenant_id,
                            %device_id,
                            "business authority: post-approval reconcile succeeded on retry"
                        );
                        cleanup_device_reconcile_slot(key, retry_slot);
                        return;
                    }
                }
            });
        } else {
            cleanup_device_reconcile_slot(key, slot);
        }
    });
    let _ = reconcile_handle.await;
    Ok(Json(approval))
}

struct DeviceReconcileSlot {
    generation: std::sync::atomic::AtomicU64,
    lock: tokio::sync::Mutex<()>,
}

static DEVICE_RECONCILE_SLOTS: std::sync::LazyLock<
    dashmap::DashMap<(ObjectId, DeviceKind, ObjectId), std::sync::Arc<DeviceReconcileSlot>>,
> = std::sync::LazyLock::new(dashmap::DashMap::new);

fn device_reconcile_slot(
    tenant_id: ObjectId,
    device_kind: DeviceKind,
    device_id: ObjectId,
) -> std::sync::Arc<DeviceReconcileSlot> {
    DEVICE_RECONCILE_SLOTS
        .entry((tenant_id, device_kind, device_id))
        .or_insert_with(|| {
            std::sync::Arc::new(DeviceReconcileSlot {
                generation: std::sync::atomic::AtomicU64::new(0),
                lock: tokio::sync::Mutex::new(()),
            })
        })
        .clone()
}

fn cleanup_device_reconcile_slot(
    key: (ObjectId, DeviceKind, ObjectId),
    slot: std::sync::Arc<DeviceReconcileSlot>,
) {
    drop(slot);
    DEVICE_RECONCILE_SLOTS.remove_if(&key, |_, existing| {
        std::sync::Arc::strong_count(existing) == 1
    });
}

async fn apply_immediate_in_memory_revocations(
    state: &NetworkState,
    tenant_id: ObjectId,
    device_kind: DeviceKind,
    device_id: ObjectId,
    new_role: DeviceUseRole,
) {
    state.org_relay.invalidate_eligibility();
    if device_kind == DeviceKind::Agent && new_role != DeviceUseRole::Server {
        crate::org_relay::revoke_where(state, "role_revoked", |s| {
            s.implicit && s.relay_agent_id == device_id
        })
        .await;
    }
    if new_role == DeviceUseRole::Unknown
        && crate::business_isolation::mode(state) == crate::business_isolation::Mode::Enforce
        && crate::business_isolation::unknown_role_mode(state)
            == crate::business_isolation::Mode::Enforce
    {
        crate::org_relay::revoke_where(state, "role_revoked", |s| {
            s.tenant_id == tenant_id && s.involves_device(device_kind, device_id)
        })
        .await;
    }
}

async fn run_role_change_reconcile(
    state: &NetworkState,
    tenant_id: ObjectId,
    device_id: ObjectId,
) -> bool {
    state.org_relay.invalidate_eligibility();
    let mut ok = true;
    // 1. Fast security-critical gates first (relay zones/ACL, DERP allow table,
    //    center-brokered tunnel sessions, managed forwards).
    if !crate::org_relay::recheck_zones(state, device_id, "role_changed").await {
        ok = false;
    }
    if !crate::org_relay::reconcile_acl(state, tenant_id).await {
        ok = false;
    }
    let network_opt = match state.overlay_networks.find_for_tenant(tenant_id).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(%tenant_id, %e, "business authority: overlay network lookup failed during reconcile");
            ok = false;
            None
        }
    };
    if let Some(ref net) = network_opt
        && let Some(network_id) = net.id
        && !crate::derp_acl::rebuild(state, tenant_id, network_id).await
    {
        ok = false;
    }
    if !crate::tunnel::reconcile_tunnel_sessions(state, tenant_id).await {
        ok = false;
    }
    if !crate::managed_forward::reconcile_tenant_forwards(state, tenant_id).await {
        ok = false;
    }
    // 2. O(N^2) overlay netmap re-fan across active nodes.
    if let Some(net) = network_opt
        && let Some(network_id) = net.id
    {
        match state
            .overlay_nodes
            .list_active_in_network(tenant_id, network_id)
            .await
        {
            Ok(nodes) => {
                for node in &nodes {
                    if !crate::overlay::refan_node(state, node).await {
                        ok = false;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(%tenant_id, %e, "business authority: active node list failed during reconcile");
                ok = false;
            }
        }
    }
    ok
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
