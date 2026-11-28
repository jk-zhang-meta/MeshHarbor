// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Logical Network Zones & per-device Zone Assignment endpoints:
//! - `GET /api/tenant/{tenant_id}/network-zones`
//! - `PUT /api/tenant/{tenant_id}/network-zones`
//! - `GET /api/tenant/{tenant_id}/network-zones/backbone`
//! - `PUT /api/tenant/{tenant_id}/agent/{agent_id}/zone-assignment`

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_core::{
    ApiError, extractors::auth::AuthUser, guards::require_permission,
    user_analytics::canonical_public_ip,
};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::models::{
    CrossZoneMode, DeviceZoneResolution, NetworkZone, OsKind, first_zone_without_gateway,
    normalize_zone_slug, validate_and_normalize_network_zones,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_source: Option<meshharbor_remote_control::models::ZoneSource>,
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
    // FR-134 — every zone reaches the centre and other zones through its gateways, so a zone
    // with no gateway is refused at save.
    if let Some(z) = first_zone_without_gateway(&normalized) {
        return Err(ApiError::BadRequest(format!(
            "Zone '{}' must name at least one gateway router",
            z.id
        )));
    }
    let active_agents = state.fleet.agents.list_all_active_for_tenant(tid).await?;

    let active_ids: HashSet<ObjectId> = active_agents.iter().filter_map(|a| a.id).collect();
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
            // FR-134 — the centre zone names the centre's own active host device without
            // requiring relay/entry serving (`peer_relay_policy.serve = false`), so saving
            // zones never requires toggling `serve` on/off on a shared centre host. Every
            // non-centre zone still requires an active approved relay (`serve = true`).
            if z.is_centre {
                if !active_ids.contains(&gw_id) {
                    return Err(ApiError::BadRequest(format!(
                        "Centre zone '{}' references gateway_relay_id '{}' which is not an active device in this tenant",
                        z.id, gw_hex
                    )));
                }
            } else if !approved_relays.contains(&gw_id) {
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
    // FR-134 — live push updated management paths and gateway entry keys/revocations.
    meshharbor_mod_fleet::management_path::sync_tenant_management_paths(&state.fleet, tid).await;

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
    // FR-124 — `MANAGE_AGENTS` only, never the device's owner: a zone is the
    // admin's boundary, and an owner who could move their own device out of a
    // strict zone would walk around it. Checked before the device is looked
    // up, so a refusal says nothing about which ids exist.
    if !permissions::has(perms, permissions::MANAGE_AGENTS) {
        return Err(ApiError::Forbidden(
            "Missing MANAGE_AGENTS permission".to_string(),
        ));
    }
    let agent = state.fleet.agents.find_live_in_tenant(tid, aid).await?;

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
    // FR-134 — live push updated management path for the moved device (and tenant if gateway).
    meshharbor_mod_fleet::management_path::sync_tenant_management_paths(&state.fleet, tid).await;

    let fresh_agent = state.fleet.agents.find_live_in_tenant(tid, aid).await.ok();
    let country_code = fresh_agent
        .as_ref()
        .and_then(|f| meshharbor_mod_fleet::socket::agent_effective_country(&state.fleet, f));
    let (effective_zone_id, effective_zone_name, zone_source) = if !snapshot.read_failed
        && !snapshot.superseded
    {
        let (res, src) = snapshot.resolve_agent_with_source(aid);
        match res {
            DeviceZoneResolution::Resolved(z) => (Some(z.id.clone()), Some(z.name.clone()), src),
            _ => (None, None, src),
        }
    } else if let (Ok(Some(net)), Some(fresh)) = (
        state.overlay_networks.find_for_tenant(tid).await,
        fresh_agent.as_ref(),
    ) {
        let (res, src) = meshharbor_mod_fleet::socket::resolve_agent_zone_with_source(
            &state.fleet,
            &net.zones,
            fresh,
            None,
        );
        match res {
            DeviceZoneResolution::Resolved(z) => (Some(z.id.clone()), Some(z.name.clone()), src),
            _ => (None, None, src),
        }
    } else {
        (None, None, None)
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
        zone_source,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// FR-137: Read-only Zone Backbone view (`GET /network-zones/backbone`)
// ────────────────────────────────────────────────────────────────────────────

const BACKBONE_MESH_FRESH_SECS: i64 = 180;

#[derive(Debug, Serialize)]
pub struct BackboneZoneView {
    pub id: String,
    pub name: String,
    pub is_centre: bool,
    pub is_default: bool,
    pub cross_zone_mode: CrossZoneMode,
    pub auto_countries: Vec<String>,
    pub gateway_relay_ids: Vec<String>,
    pub device_count: usize,
}

#[derive(Debug, Serialize)]
pub struct BackboneGatewayView {
    pub agent_id: String,
    pub name: String,
    pub online: bool,
    pub os: OsKind,
    pub agent_version: String,
    pub last_seen_at: String,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub relay_home: Option<String>,
    pub public_ip: Option<String>,
    pub zone_ids: Vec<String>,
    pub is_centre: bool,
    pub serving_relay: bool,
    pub entry_listening: bool,
    pub entry_port: Option<u16>,
    pub entry_device_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackboneLinkEndView {
    pub node: String,
    pub carrier: String,
    pub relay: Option<String>,
    pub rtt_ms: Option<i64>,
    pub stalled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackboneLinkView {
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub carrier: String,
    pub rtt_ms: Option<i64>,
    pub stalled: bool,
    pub reports: u8,
    pub cross_zone: bool,
    pub ends: Vec<BackboneLinkEndView>,
}

#[derive(Debug, Serialize)]
pub struct ZoneBackboneResponse {
    pub revision: u64,
    pub zones: Vec<BackboneZoneView>,
    pub gateways: Vec<BackboneGatewayView>,
    pub links: Vec<BackboneLinkView>,
}

/// Pessimistic carrier ranking matching `GET /api/tenant/{tid}/stats/mesh`.
fn carrier_rank(c: &str) -> u8 {
    match c {
        "direct" => 0,
        "relay" => 1,
        "derp" => 2,
        "tunnel" => 3,
        "blocked" => 4,
        _ => 5,
    }
}

#[derive(Debug, Clone)]
struct RawMeshLink {
    node: String,
    carrier: String,
    relay: Option<String>,
    rtt_ms: Option<i64>,
    stalled: bool,
}

fn bson_as_i64(v: Option<&Bson>) -> Option<i64> {
    match v {
        Some(Bson::Int64(n)) => Some(*n),
        Some(Bson::Int32(n)) => Some(i64::from(*n)),
        _ => None,
    }
}

fn gateways_are_cross_zone(zones_a: &[String], zones_b: &[String]) -> bool {
    !zones_a.iter().any(|z| zones_b.contains(z)) || zones_a != zones_b
}

fn merge_backbone_links(
    snapshots: &[(String, Vec<RawMeshLink>)],
    node_of_agent: &HashMap<String, String>,
    agent_of_node: &HashMap<String, String>,
    gateway_zones: &HashMap<String, Vec<String>>,
) -> Vec<BackboneLinkView> {
    #[derive(Default)]
    struct Edge {
        carrier: String,
        rtt_ms: Option<i64>,
        stalled: bool,
        reports: u8,
        ends: Vec<BackboneLinkEndView>,
    }

    let mut edges: HashMap<(String, String), Edge> = HashMap::new();
    for (from_agent, links) in snapshots {
        if !node_of_agent.contains_key(from_agent) || !gateway_zones.contains_key(from_agent) {
            continue;
        }
        for l in links {
            let Some(to_agent) = agent_of_node.get(&l.node) else {
                continue;
            };
            if to_agent == from_agent || !gateway_zones.contains_key(to_agent) {
                continue;
            }
            let key = if from_agent.as_str() <= to_agent.as_str() {
                (from_agent.clone(), to_agent.clone())
            } else {
                (to_agent.clone(), from_agent.clone())
            };
            let e = edges.entry(key).or_default();
            e.reports = e.reports.saturating_add(1);
            e.stalled |= l.stalled;
            e.ends.push(BackboneLinkEndView {
                node: from_agent.clone(),
                carrier: l.carrier.clone(),
                relay: l.relay.clone(),
                rtt_ms: l.rtt_ms,
                stalled: l.stalled,
            });
            if e.carrier.is_empty() || carrier_rank(&l.carrier) > carrier_rank(&e.carrier) {
                e.carrier = l.carrier.clone();
            }
            e.rtt_ms = match (e.rtt_ms, l.rtt_ms) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
    }

    let mut out: Vec<BackboneLinkView> = edges
        .into_iter()
        .map(|((a, b), mut e)| {
            e.ends.sort_by(|x, y| x.node.cmp(&y.node));
            let cross_zone = match (gateway_zones.get(&a), gateway_zones.get(&b)) {
                (Some(za), Some(zb)) => gateways_are_cross_zone(za, zb),
                _ => true,
            };
            BackboneLinkView {
                from_agent_id: a,
                to_agent_id: b,
                carrier: e.carrier,
                rtt_ms: e.rtt_ms,
                stalled: e.stalled,
                reports: e.reports,
                cross_zone,
                ends: e.ends,
            }
        })
        .collect();
    out.sort_by(|x, y| {
        x.from_agent_id
            .cmp(&y.from_agent_id)
            .then_with(|| x.to_agent_id.cmp(&y.to_agent_id))
    });
    out
}

/// `GET /api/tenant/{tenant_id}/network-zones/backbone` (`MANAGE_AGENTS`)
///
/// FR-137 — read-only Zone Backbone topology assembled strictly from data the
/// server already holds: configured `OverlayNetwork.zones` (including `is_centre`),
/// active approved gateway relays with live management-entry listener state and
/// connected device counts, and live gateway↔gateway connections from `stats_mesh`.
pub async fn get_backbone(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<ZoneBackboneResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    let (revision, raw_zones) = match state.overlay_networks.find_for_tenant(tid).await? {
        Some(net) => (net.zone_revision, net.zones),
        None => (0, Vec::new()),
    };

    if raw_zones.is_empty() {
        return Ok(Json(ZoneBackboneResponse {
            revision,
            zones: Vec::new(),
            gateways: Vec::new(),
            links: Vec::new(),
        }));
    }

    let active_agents = state.fleet.agents.list_all_active_for_tenant(tid).await?;

    // Resolve each active device into its effective zone for per-zone device counts.
    let mut zone_device_counts: HashMap<String, usize> = HashMap::new();
    let mut agents_by_id: HashMap<ObjectId, &meshharbor_remote_control::models::Agent> =
        HashMap::with_capacity(active_agents.len());
    for a in &active_agents {
        if let Some(aid) = a.id {
            agents_by_id.insert(aid, a);
        }
        if let DeviceZoneResolution::Resolved(z) =
            meshharbor_mod_fleet::socket::resolve_agent_zone_with_source(
                &state.fleet,
                &raw_zones,
                a,
                None,
            )
            .0
        {
            *zone_device_counts.entry(z.id.clone()).or_insert(0) += 1;
        }
    }

    // Collect every zone each gateway is assigned to (preserving zone order).
    let mut gw_zone_ids: HashMap<ObjectId, Vec<String>> = HashMap::new();
    let mut gw_is_centre: HashMap<ObjectId, bool> = HashMap::new();
    for z in &raw_zones {
        for gw_hex in &z.gateway_relay_ids {
            let Ok(gw_id) = ObjectId::parse_str(gw_hex) else {
                continue;
            };
            let entry = gw_zone_ids.entry(gw_id).or_default();
            if !entry.contains(&z.id) {
                entry.push(z.id.clone());
            }
            if z.is_centre {
                gw_is_centre.insert(gw_id, true);
            }
        }
    }

    let zones: Vec<BackboneZoneView> = raw_zones
        .into_iter()
        .map(|z| {
            let device_count = zone_device_counts.get(&z.id).copied().unwrap_or(0);
            BackboneZoneView {
                id: z.id,
                name: z.name,
                is_centre: z.is_centre,
                is_default: z.is_default,
                cross_zone_mode: z.cross_zone_mode,
                auto_countries: z.auto_countries,
                gateway_relay_ids: z.gateway_relay_ids,
                device_count,
            }
        })
        .collect();

    let entry_counts = state.fleet.rc_hub.management_entry_device_counts(tid);
    let mut gateway_oids: Vec<ObjectId> = Vec::new();
    let mut gateway_zones_hex: HashMap<String, Vec<String>> = HashMap::new();
    let mut gateways: Vec<BackboneGatewayView> = Vec::new();

    for (gw_id, zone_ids) in gw_zone_ids {
        let Some(a) = agents_by_id.get(&gw_id).copied() else {
            continue;
        };
        // FR-137 — include every active device named in any zone's `gateway_relay_ids`,
        // even when `peer_relay_policy.serve == false` (e.g. a centre-zone host whose
        // central reporting role is separate from relay/entry forwarding).
        let serving_relay = a.peer_relay_policy.serve;
        let aid_hex = gw_id.to_hex();
        gateway_oids.push(gw_id);
        gateway_zones_hex.insert(aid_hex.clone(), zone_ids.clone());

        let online = state.fleet.rc_hub.is_agent_online(gw_id);
        let entry_port = if online && serving_relay {
            state.fleet.rc_hub.agent_management_entry_port(gw_id)
        } else {
            None
        };
        let entry_listening = entry_port.is_some();
        let entry_device_count = if serving_relay {
            entry_counts.get(&gw_id).copied().unwrap_or(0)
        } else {
            0
        };

        let effective_cc = meshharbor_mod_fleet::socket::agent_effective_country(&state.fleet, a);
        let egress_ip = a
            .public_ip
            .as_deref()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .and_then(canonical_public_ip)
            .or_else(|| state.fleet.rc_hub.agent_live_public_ip(gw_id));
        let public_ip = egress_ip.map(|ip| ip.to_string());
        let geo = meshharbor_mod_fleet::socket::lookup_display_location(
            &state.core.geoip,
            a.physical_public_ip.as_deref(),
            a.physical_seen_at.map(|dt| dt.timestamp_millis()),
            egress_ip,
            DateTime::now().timestamp_millis(),
        );

        let display_name = a
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let name = display_name.unwrap_or(&a.name).to_string();

        gateways.push(BackboneGatewayView {
            agent_id: aid_hex,
            name,
            online,
            os: a.os,
            agent_version: a.agent_version.clone(),
            last_seen_at: meshharbor_mod_fleet::agent::fmt_dt(a.last_seen_at),
            country_code: geo.country_code.or(effective_cc),
            country: geo.country,
            region: geo.region,
            city: geo.city,
            relay_home: a.relay_home.clone(),
            public_ip,
            zone_ids,
            is_centre: gw_is_centre.get(&gw_id).copied().unwrap_or(false),
            serving_relay,
            entry_listening,
            entry_port,
            entry_device_count,
        });
    }

    gateways.sort_by(|a, b| {
        b.is_centre
            .cmp(&a.is_centre)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.agent_id.cmp(&b.agent_id))
    });

    if gateway_oids.is_empty() {
        return Ok(Json(ZoneBackboneResponse {
            revision,
            zones,
            gateways,
            links: Vec::new(),
        }));
    }

    // Map gateway agent_id <-> live overlay_nodes._id.
    let mut node_of_agent: HashMap<String, String> = HashMap::new();
    let mut agent_of_node: HashMap<String, String> = HashMap::new();
    let node_cursor = state
        .core
        .db
        .collection::<Document>("overlay_nodes")
        .find(doc! {
            "tenant_id": tid,
            "deleted_at": Bson::Null,
            "node_ref.kind": "agent",
            "node_ref.id": { "$in": &gateway_oids },
        })
        .await
        .map_err(|e| ApiError::Internal(format!("backbone overlay_nodes query failed: {e}")))?;
    let node_docs: Vec<Document> = node_cursor
        .try_collect()
        .await
        .map_err(|e| ApiError::Internal(format!("backbone overlay_nodes read failed: {e}")))?;
    for doc in node_docs {
        let Ok(node_oid) = doc.get_object_id("_id") else {
            continue;
        };
        let Ok(node_ref) = doc.get_document("node_ref") else {
            continue;
        };
        let Ok(agent_oid) = node_ref.get_object_id("id") else {
            continue;
        };
        let n_hex = node_oid.to_hex();
        let a_hex = agent_oid.to_hex();
        node_of_agent.insert(a_hex.clone(), n_hex.clone());
        agent_of_node.insert(n_hex, a_hex);
    }

    let fresh_floor =
        DateTime::from_millis(DateTime::now().timestamp_millis() - BACKBONE_MESH_FRESH_SECS * 1000);
    let snap_cursor = state
        .core
        .db
        .collection::<Document>(meshharbor_services::dao::stats::STATS_MESH)
        .find(doc! {
            "tenant_id": tid,
            "ts": { "$gte": fresh_floor },
            "agent_id": { "$in": &gateway_oids },
        })
        .await
        .map_err(|e| ApiError::Internal(format!("backbone stats_mesh query failed: {e}")))?;
    let snap_docs: Vec<Document> = snap_cursor
        .try_collect()
        .await
        .map_err(|e| ApiError::Internal(format!("backbone stats_mesh read failed: {e}")))?;

    let mut snapshots: Vec<(String, Vec<RawMeshLink>)> = Vec::with_capacity(snap_docs.len());
    for doc in snap_docs {
        let Ok(agent_oid) = doc.get_object_id("agent_id") else {
            continue;
        };
        let Ok(raw_links) = doc.get_array("links") else {
            continue;
        };
        let mut parsed = Vec::with_capacity(raw_links.len());
        for item in raw_links {
            let Some(ldoc) = item.as_document() else {
                continue;
            };
            let (Ok(node), Ok(carrier)) = (ldoc.get_str("node"), ldoc.get_str("carrier")) else {
                continue;
            };
            parsed.push(RawMeshLink {
                node: node.to_string(),
                carrier: carrier.to_string(),
                relay: ldoc.get_str("relay").ok().map(str::to_string),
                rtt_ms: bson_as_i64(ldoc.get("rtt_ms")),
                stalled: ldoc.get_bool("stalled").unwrap_or(false),
            });
        }
        snapshots.push((agent_oid.to_hex(), parsed));
    }

    let links = merge_backbone_links(
        &snapshots,
        &node_of_agent,
        &agent_of_node,
        &gateway_zones_hex,
    );

    Ok(Json(ZoneBackboneResponse {
        revision,
        zones,
        gateways,
        links,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_backbone_links_pessimistically_merges_gateway_pairs_and_ignores_non_gateways() {
        let mut node_of_agent = HashMap::new();
        let mut agent_of_node = HashMap::new();
        for (a, n) in [("gw-a", "node-a"), ("gw-b", "node-b"), ("gw-c", "node-c")] {
            node_of_agent.insert(a.to_string(), n.to_string());
            agent_of_node.insert(n.to_string(), a.to_string());
        }
        let mut gw_zones = HashMap::new();
        gw_zones.insert("gw-a".to_string(), vec!["cn".to_string()]);
        gw_zones.insert("gw-b".to_string(), vec!["centre".to_string()]);
        gw_zones.insert("gw-c".to_string(), vec!["cn".to_string()]);

        let snapshots = vec![
            (
                "gw-a".to_string(),
                vec![
                    RawMeshLink {
                        node: "node-b".to_string(),
                        carrier: "direct".to_string(),
                        relay: None,
                        rtt_ms: Some(32),
                        stalled: false,
                    },
                    RawMeshLink {
                        node: "node-c".to_string(),
                        carrier: "direct".to_string(),
                        relay: None,
                        rtt_ms: Some(4),
                        stalled: false,
                    },
                    // Non-gateway peer must be ignored.
                    RawMeshLink {
                        node: "node-client".to_string(),
                        carrier: "direct".to_string(),
                        relay: None,
                        rtt_ms: Some(2),
                        stalled: false,
                    },
                ],
            ),
            (
                "gw-b".to_string(),
                vec![RawMeshLink {
                    node: "node-a".to_string(),
                    carrier: "relay".to_string(),
                    relay: Some("org_relay".to_string()),
                    rtt_ms: Some(41),
                    stalled: true,
                }],
            ),
        ];

        let links = merge_backbone_links(&snapshots, &node_of_agent, &agent_of_node, &gw_zones);
        assert_eq!(links.len(), 2);

        let ab = &links[0];
        assert_eq!(ab.from_agent_id, "gw-a");
        assert_eq!(ab.to_agent_id, "gw-b");
        assert_eq!(ab.carrier, "relay");
        assert_eq!(ab.rtt_ms, Some(32));
        assert!(ab.stalled);
        assert_eq!(ab.reports, 2);
        assert!(ab.cross_zone);
        assert_eq!(ab.ends.len(), 2);
        assert_eq!(ab.ends[0].node, "gw-a");
        assert_eq!(ab.ends[1].node, "gw-b");
        assert_eq!(ab.ends[1].relay.as_deref(), Some("org_relay"));

        let ac = &links[1];
        assert_eq!(ac.from_agent_id, "gw-a");
        assert_eq!(ac.to_agent_id, "gw-c");
        assert!(!ac.cross_zone);
        assert_eq!(ac.reports, 1);
    }
}
