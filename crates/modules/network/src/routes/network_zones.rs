// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Logical Network Zones & per-device Zone Assignment endpoints:
//! - `GET /api/tenant/{tenant_id}/network-zones`
//! - `PUT /api/tenant/{tenant_id}/network-zones`
//! - `PUT /api/tenant/{tenant_id}/agent/{agent_id}/zone-assignment`

use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::models::{
    DeviceZoneResolution, NetworkZone, normalize_zone_slug, validate_and_normalize_network_zones,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::NetworkState;
use crate::network_zones::TenantZoneSnapshot;

#[derive(Debug, Serialize)]
pub struct NetworkZonesResponse {
    pub revision: u64,
    pub zones: Vec<NetworkZone>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetNetworkZonesBody {
    pub zones: Vec<NetworkZone>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneAssignmentBody {
    #[serde(default)]
    pub pinned_zone_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ZoneAssignmentResponse {
    pub agent_id: String,
    pub pinned_zone_id: Option<String>,
    pub country_code: Option<String>,
    pub effective_zone_id: Option<String>,
    pub effective_zone_name: Option<String>,
}

/// `GET /api/tenant/{tenant_id}/network-zones`
///
/// Any authenticated member of `tenant_id` may read the admin-defined zone
/// catalog for per-device Zone Assignment selection; `gateway_relay_ids` are
/// included only for callers holding `ADMINISTRATOR`.
pub async fn get_zones(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<NetworkZonesResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    let is_admin = permissions::has(perms, permissions::ADMINISTRATOR);

    let (revision, mut zones) = match state.overlay_networks.find_for_tenant(tid).await? {
        Some(net) => (net.zone_revision, net.zones),
        None => (0, Vec::new()),
    };
    if !is_admin {
        for z in &mut zones {
            z.gateway_relay_ids.clear();
        }
    }
    Ok(Json(NetworkZonesResponse { revision, zones }))
}

/// `PUT /api/tenant/{tenant_id}/network-zones` (`ADMINISTRATOR` only)
pub async fn set_zones(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<SetNetworkZonesBody>,
) -> Result<Json<NetworkZonesResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::ADMINISTRATOR,
        "ADMINISTRATOR",
    )
    .await?;

    let normalized =
        validate_and_normalize_network_zones(body.zones).map_err(ApiError::BadRequest)?;
    let active_agents = state.fleet.agents.list_all_active_for_tenant(tid).await?;

    let approved_relays: HashSet<ObjectId> = active_agents
        .iter()
        .filter(|a| a.peer_relay_policy.serve)
        .filter_map(|a| a.id)
        .collect();
    for z in &normalized {
        for gw_hex in &z.gateway_relay_ids {
            let gw_id = ObjectId::parse_str(gw_hex).map_err(|_| {
                ApiError::BadRequest(format!(
                    "Zone '{}' has invalid gateway_relay_id '{}'",
                    z.id, gw_hex
                ))
            })?;
            if !approved_relays.contains(&gw_id) {
                return Err(ApiError::BadRequest(format!(
                    "Zone '{}' references gateway_relay_id '{}' which is not an active approved relay (serve=true) in this tenant",
                    z.id, gw_hex
                )));
            }
        }
    }

    let kept_zone_ids: HashSet<&str> = normalized.iter().map(|z| z.id.as_str()).collect();
    for a in &active_agents {
        if let Some(pinned) = a.pinned_zone_id.as_deref()
            && !kept_zone_ids.contains(pinned)
        {
            return Err(ApiError::BadRequest(format!(
                "Cannot delete zone '{pinned}' while active device '{}' is pinned to it",
                a.id.map(|id| id.to_hex()).unwrap_or_default()
            )));
        }
    }

    let _ = state.overlay_networks.get_or_create(tid).await?;
    let updated_net = state
        .overlay_networks
        .set_network_zones(tid, &normalized)
        .await?;

    state.org_relay.bump_eligibility_generation();
    let snapshot = TenantZoneSnapshot::load_consistent(&state, tid).await;
    snapshot.sync_hub_policies_for_tenant(&state, tid).await;
    snapshot
        .sync_relay_backbone_endpoints_at_current_revision(&state, tid, None)
        .await;
    crate::org_relay::recheck_tenant_zones(&state, tid, "network_zones_updated").await;
    crate::overlay::on_tenant_zones_changed(&state, tid).await;

    info!(
        tenant = %tid,
        actor = %auth.user_id,
        revision = updated_net.zone_revision,
        zone_count = updated_net.zones.len(),
        "network zones updated"
    );

    Ok(Json(NetworkZonesResponse {
        revision: updated_net.zone_revision,
        zones: updated_net.zones,
    }))
}

/// `PUT /api/tenant/{tenant_id}/agent/{agent_id}/zone-assignment`
pub async fn set_zone_assignment(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<ZoneAssignmentBody>,
) -> Result<Json<ZoneAssignmentResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;

    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    let agent = state.fleet.agents.find_live_in_tenant(tid, aid).await?;
    if !permissions::has(perms, permissions::MANAGE_AGENTS) && agent.owner_user_id != auth.user_id {
        return Err(ApiError::Forbidden(
            "Missing MANAGE_AGENTS permission".to_string(),
        ));
    }

    let normalized_pin = match body.pinned_zone_id {
        None => None,
        Some(raw) => {
            let slug = normalize_zone_slug(&raw).map_err(ApiError::BadRequest)?;
            let exists = state
                .overlay_networks
                .find_for_tenant(tid)
                .await?
                .is_some_and(|net| net.zones.iter().any(|z| z.id == slug));
            if !exists {
                return Err(ApiError::BadRequest(format!(
                    "Zone '{slug}' does not exist in this tenant"
                )));
            }
            Some(slug)
        }
    };

    let _ = state.overlay_networks.get_or_create(tid).await?;
    let updated = state
        .fleet
        .agents
        .update_pinned_zone_id(tid, aid, normalized_pin.as_deref())
        .await?;
    if !updated {
        return Err(ApiError::NotFound("Agent not found".to_string()));
    }
    let _ = state.overlay_networks.bump_zone_revision(tid).await?;

    state.org_relay.bump_eligibility_generation();
    let snapshot = TenantZoneSnapshot::load_consistent(&state, tid).await;
    snapshot.sync_hub_policy_for_agent(&state, tid, aid).await;
    if agent.peer_relay_policy.serve {
        snapshot
            .sync_relay_backbone_endpoints_at_current_revision(&state, tid, None)
            .await;
    }
    crate::org_relay::recheck_zones(&state, aid, "zone_assignment").await;
    crate::overlay::on_agent_policy_changed(&state, tid, aid, "zone_policy").await;

    let fresh_agent = state.fleet.agents.find_live_in_tenant(tid, aid).await.ok();
    let country_code = fresh_agent
        .as_ref()
        .and_then(|f| meshharbor_mod_fleet::socket::agent_effective_country(&state.fleet, f));
    let (effective_zone_id, effective_zone_name) = if !snapshot.read_failed && !snapshot.superseded
    {
        match snapshot.resolve_agent(aid) {
            DeviceZoneResolution::Resolved(z) => (Some(z.id.clone()), Some(z.name.clone())),
            _ => (None, None),
        }
    } else if let (Ok(Some(net)), Some(fresh)) = (
        state.overlay_networks.find_for_tenant(tid).await,
        fresh_agent.as_ref(),
    ) {
        match meshharbor_remote_control::models::resolve_device_zone(
            &net.zones,
            fresh.pinned_zone_id.as_deref(),
            country_code.as_deref(),
        ) {
            DeviceZoneResolution::Resolved(z) => (Some(z.id.clone()), Some(z.name.clone())),
            _ => (None, None),
        }
    } else {
        (None, None)
    };

    info!(
        tenant = %tid,
        agent = %aid,
        actor = %auth.user_id,
        pinned_zone_id = ?normalized_pin,
        effective_zone_id = ?effective_zone_id,
        "agent zone assignment updated"
    );

    Ok(Json(ZoneAssignmentResponse {
        agent_id: aid.to_hex(),
        pinned_zone_id: normalized_pin,
        country_code,
        effective_zone_id,
        effective_zone_name,
    }))
}
