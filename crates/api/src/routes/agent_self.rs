// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D5a — a device's own view of its org, for the desktop companion.
//!
//! The companion reaches only its local daemon, and the daemon holds an AGENT
//! token — never a user's — so the admin listing (`/tenant/{tid}/device`) and
//! the org mesh (`/tenant/{tid}/stats/mesh`) are out of its reach. These two
//! routes answer the same questions FOR ONE DEVICE, with the same grid logic
//! (`device::parse_query` / `apply_query`) and the same graph
//! (`stats::build_mesh`), over a set that is never the org's inventory:
//!
//! **visible = self ∪ what this device's overlay netmap already carries.**
//!
//! That is not a policy of this file. The set is computed by the join path's
//! own shaping ([`meshharbor_mod_network::overlay::shape_full_netmap`]), so
//! `off` / `warn` list every live node and `enforce` lists exactly what the
//! netmap would ship — a peer the ACL withholds from the netmap is absent here
//! too, by construction rather than by a second rule that could drift. Only
//! node ids and the `reachable` flag are read off the shaped peers; keys and
//! endpoints never leave the engine.
//!
//! Host-owned, not a module's: the rows need fleet (required) and the overlay
//! needs network (optional — a `remote` profile has no mesh, and its devices
//! see themselves). `docs/modular-monolith.md` §4 is the lesson behind that.
//!
//! ⚠️ The order of reads is load-bearing. The tenant's network is resolved
//! with `find_for_tenant` and the device's LIVE node with `current_node`
//! BEFORE any ACL read, because `load_acl` goes through `get_or_create`, and
//! a GET must never allocate a network row (or, under P2b, carve a block that
//! is quarantined forever once freed). A device without a live node gets
//! `overlay: "no_node"` and sees itself alone; the shaping never runs.
//!
//! Read-only: `debug!` only, no audit rows.

use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use meshharbor_core::ApiError;
use meshharbor_core::client_ip::{ConnectionOrigin, PeerAddr};
use meshharbor_mod_fleet::agent::{AgentPresence, agent_presence_batch, derive_agent_presence};
use meshharbor_remote_control::models::{
    DeviceZoneResolution, NodeRef, OverlayAclMode, OverlayNode, ProbeHysteresisDecision,
    VisibleDeviceRow, VisibleDevicesPage, ZoneSource, auto_zone_for_country,
};
use serde::{Deserialize, Serialize};

use crate::extractors::auth_agent::HostAuthAgent;
#[cfg(feature = "network")]
use crate::routes::device::client_row;
use crate::routes::device::{DeviceListQuery, DeviceRow, agent_row, apply_query, parse_query};
use crate::routes::stats::{BuiltMesh, build_mesh, disabled_payload, to_payload};
use crate::state::AppState;

/// The overlay nodes THIS device may see, and why the set is what it is.
struct Visibility {
    /// `ok` · `no_node` · `no_network` · `unavailable` — see
    /// [`VisibleDevicesPage::overlay`].
    overlay: &'static str,
    /// The ACL posture the shaping ran under (`unknown` without the module).
    acl_mode: &'static str,
    self_node_id: Option<String>,
    self_temporary: bool,
    /// The visible node rows, each with the netmap's `reachable` verdict —
    /// the caller's own node included. `None` = the caller alone.
    nodes: Option<Vec<(OverlayNode, bool)>>,
    /// All active nodes in the tenant's overlay network (read-only), used to
    /// attach overlay metadata for permanent account inventory even when the
    /// caller has no live node yet or ACL/isolation withholds data-plane reachability.
    all_network_nodes: Vec<OverlayNode>,
    zones: Vec<meshharbor_remote_control::models::NetworkZone>,
}

impl Visibility {
    fn self_only(overlay: &'static str, acl_mode: &'static str) -> Self {
        Self {
            overlay,
            acl_mode,
            self_node_id: None,
            self_temporary: false,
            nodes: None,
            all_network_nodes: Vec::new(),
            zones: Vec::new(),
        }
    }

    /// `node id (hex) → reachable` for every visible node.
    fn reachable_by_node(&self) -> HashMap<String, bool> {
        self.nodes
            .iter()
            .flatten()
            .filter_map(|(n, up)| Some((n.id?.to_hex(), *up)))
            .collect()
    }
}

fn acl_mode_str(mode: OverlayAclMode) -> &'static str {
    match mode {
        OverlayAclMode::Off => "off",
        OverlayAclMode::Warn => "warn",
        OverlayAclMode::Enforce => "enforce",
    }
}

fn presence_str(p: AgentPresence) -> &'static str {
    match p {
        AgentPresence::Online => "online",
        AgentPresence::Stale => "stale",
        AgentPresence::Offline => "offline",
    }
}

/// Resolve the caller's visible set — the join-time shaping, over the
/// device's live node, after the two read-only lookups the module docs
/// insist on.
#[cfg(feature = "network")]
async fn visibility(state: &AppState, agent: &HostAuthAgent) -> Result<Visibility, ApiError> {
    use meshharbor_mod_network::overlay::{
        NodeIdentity, current_node, reachability, shape_full_netmap,
    };

    let Some(network) = state.modules.network.as_ref() else {
        return Ok(Visibility::self_only("unavailable", "unknown"));
    };
    // ⚠️ `find_for_tenant`, never `get_or_create` (module docs).
    let Some(net) = network
        .overlay_networks
        .find_for_tenant(agent.tenant_id)
        .await?
    else {
        // A tenant that has never joined the mesh has the posture the row
        // would be created with: the DAO's default, `off`.
        return Ok(Visibility::self_only("no_network", "off"));
    };
    let stored_mode = acl_mode_str(net.acl_mode);
    let zones = net.zones;
    let Some(network_id) = net.id else {
        return Ok(Visibility {
            zones,
            ..Visibility::self_only("no_network", stored_mode)
        });
    };
    let all = network
        .overlay_nodes
        .list_active_in_network(agent.tenant_id, network_id)
        .await?;
    // The device's own LIVE node — a released (tombstoned) node is gone for
    // good; the device comes back with a fresh lease when it rejoins.
    let Some(self_node) = current_node(network, NodeIdentity::Agent(agent.agent_id)).await else {
        return Ok(Visibility {
            overlay: "no_node",
            acl_mode: stored_mode,
            self_node_id: None,
            self_temporary: false,
            nodes: None,
            all_network_nodes: all,
            zones,
        });
    };
    let Some(self_id) = self_node.id else {
        return Ok(Visibility {
            overlay: "no_node",
            acl_mode: stored_mode,
            self_node_id: None,
            self_temporary: self_node.temporary.is_some(),
            nodes: None,
            all_network_nodes: all,
            zones,
        });
    };
    let self_temporary = self_node.temporary.is_some();

    let reach = reachability(network, &all).await;
    let shaped = shape_full_netmap(network, &self_node, &all, &reach).await;
    // Only the id and the presence verdict leave the shaped peers.
    let visible: HashMap<bson::oid::ObjectId, bool> = shaped
        .peers
        .iter()
        .map(|p| (p.node_id, p.reachable))
        .collect();
    let self_reachable = reach.get(&self_id).copied().unwrap_or(true);
    let all_network_nodes = all.clone();
    let mut nodes: Vec<(OverlayNode, bool)> = all
        .into_iter()
        .filter_map(|n| {
            let id = n.id?;
            if id == self_id {
                Some((n, self_reachable))
            } else {
                visible.get(&id).map(|up| (n, *up))
            }
        })
        .collect();
    if !nodes.iter().any(|(n, _)| n.id == Some(self_id)) {
        nodes.push((self_node, self_reachable));
    }
    Ok(Visibility {
        overlay: "ok",
        acl_mode: acl_mode_str(shaped.acl.mode),
        self_node_id: Some(self_id.to_hex()),
        self_temporary,
        nodes: Some(nodes),
        all_network_nodes,
        zones,
    })
}

/// A build without the network module has no mesh: every device sees itself,
/// while still resolving any persisted Logical Network Zones on the tenant.
#[cfg(not(feature = "network"))]
async fn visibility(state: &AppState, agent: &HostAuthAgent) -> Result<Visibility, ApiError> {
    let zones = meshharbor_services::dao::overlay_network::OverlayNetworkDao::new(&state.core.db)
        .find_for_tenant(agent.tenant_id)
        .await?
        .map(|n| n.zones)
        .unwrap_or_default();
    Ok(Visibility {
        zones,
        ..Visibility::self_only("unavailable", "unknown")
    })
}

/// GET /api/agent/self/devices — the devices this device may see (itself
/// included), with the admin's display names; searched, sorted and paged on
/// the server with the admin grid's own query contract (`page`, `per_page`,
/// `q`, `sort`, `dir`, `kind`; an unknown `sort` is a 400).
///
/// Fields the device must not see are BLANKED before the query runs, so `q`
/// cannot be used as an oracle on them (`q=<machine_id>` matches nothing),
/// and the wire type has no slot for them at all.
pub async fn devices(
    State(state): State<AppState>,
    agent: HostAuthAgent,
    Query(params): Query<DeviceListQuery>,
) -> Result<Json<VisibleDevicesPage>, ApiError> {
    let query = parse_query(&params)?;
    let Some(fleet) = state.modules.fleet.as_ref() else {
        return Err(ApiError::ServiceUnavailable(
            "the fleet module is not mounted on this server".to_string(),
        ));
    };
    let tid = agent.tenant_id;
    let self_hex = agent.agent_id.to_hex();

    let vis = visibility(&state, &agent).await?;
    let reach_by_node = vis.reachable_by_node();

    // Always consult existing temporary-invitation records regardless of
    // `native_device_invite_enabled` (disabling new invitations must never
    // upgrade an already-enrolled guest to permanent inventory access), and
    // propagate any DB lookup error (`?`) so failures fail closed.
    let temporary_agents =
        meshharbor_mod_fleet::device_invite::temporary_agent_ids_in_tenant(fleet, tid).await?;
    let temporary_caller = vis.self_temporary
        || temporary_agents.contains(&agent.agent_id)
        || meshharbor_mod_fleet::device_invite::grant_for_agent(fleet, agent.agent_id)
            .await?
            .is_some();
    // Permanent account devices see 100% of active non-temporary permanent
    // devices in `/api/agent/self/devices` regardless of `acl_mode` or
    // `business_isolation` (`reachable: bool` continues to reflect actual
    // shaped netmap reachability, and `/api/agent/self/mesh` remains strictly
    // shaped). Temporary invited guests remain strictly isolated.
    let full_account_inventory = !temporary_caller;

    // Nodes are attached from the shaped set; for a permanent account device,
    // also attach non-temporary active nodes so all permanent inventory rows
    // surface accurate overlay IPs / MagicDNS names while `reachable` stays
    // `false` for peers withheld from the shaped netmap.
    let mut node_by_agent = HashMap::new();
    let mut node_by_client = HashMap::new();
    for (n, _) in vis.nodes.iter().flatten() {
        match &n.node_ref {
            NodeRef::Agent { agent_id } => {
                node_by_agent.insert(*agent_id, n);
            }
            NodeRef::TunnelClient { tunnel_client_id } => {
                node_by_client.insert(*tunnel_client_id, n);
            }
        }
    }
    if full_account_inventory {
        for n in &vis.all_network_nodes {
            if n.temporary.is_some() {
                continue;
            }
            match &n.node_ref {
                NodeRef::Agent { agent_id } if !temporary_agents.contains(agent_id) => {
                    node_by_agent.entry(*agent_id).or_insert(n);
                }
                NodeRef::TunnelClient { tunnel_client_id } => {
                    node_by_client.entry(*tunnel_client_id).or_insert(n);
                }
                _ => {}
            }
        }
    }
    // One read of the tenant: its MagicDNS domain for the rows, and (FR-133)
    // its name for a permanent device, which may say whose device it is when
    // a person from another org signs in on it. Never for a temporary guest.
    let tenant = state.tenants.base.find_by_id(tid).await.ok();
    let org_name = tenant
        .as_ref()
        .filter(|_| !temporary_caller)
        .map(|t| t.name.clone());
    let dns_domain = if node_by_agent.is_empty() && node_by_client.is_empty() {
        None
    } else {
        tenant.and_then(|t| t.settings.magic_dns_domain)
    };

    let agents = fleet.agents.list_all_active_for_tenant(tid).await?;
    let fresh = agent_presence_batch(fleet, &agents).await;
    let mut rows: Vec<DeviceRow> = Vec::with_capacity(agents.len());
    for a in agents {
        let aid = a.id;
        let is_temp_peer = aid.is_some_and(|id| temporary_agents.contains(&id));
        let redis_fresh = aid.map(|i| fresh.contains(&i)).unwrap_or(false);
        let (presence, is_online) = derive_agent_presence(fleet, &a, redis_fresh);
        let node = aid.and_then(|i| node_by_agent.get(&i).copied());
        let row = agent_row(
            fleet,
            &vis.zones,
            a,
            presence,
            is_online,
            node,
            dns_domain.as_deref(),
        );
        let in_netmap = row
            .overlay_node_id
            .as_deref()
            .is_some_and(|id| reach_by_node.contains_key(id));
        if row.id == self_hex || in_netmap || (full_account_inventory && !is_temp_peer) {
            rows.push(row);
        }
    }
    // Tunnel clients exist only as overlay nodes from a device's point of
    // view: listed when the module is here and one of them is visible (or part
    // of permanent account inventory).
    #[cfg(feature = "network")]
    {
        if should_query_tunnel_clients(full_account_inventory, !node_by_client.is_empty())
            && let Some(network) = state.modules.network.as_ref()
        {
            for c in network
                .tunnel_clients
                .list_all_active_for_tenant(tid)
                .await?
            {
                let node = c.id.and_then(|i| node_by_client.get(&i).copied());
                let row = client_row(&state.core.geoip, &vis.zones, c, node, dns_domain.as_deref());
                let in_netmap = row
                    .overlay_node_id
                    .as_deref()
                    .is_some_and(|id| reach_by_node.contains_key(id));
                if should_include_tunnel_client(in_netmap, full_account_inventory) {
                    rows.push(row);
                }
            }
        }
    }

    // Blank what the device must not see BEFORE the search runs.
    // Blank public_ip, geo, and zone fields ONLY when the calling agent is a temporary guest device.
    for r in &mut rows {
        r.machine_id.clear();
        r.owner_user_id.clear();
        r.overlay_public_key = None;
        r.overlay_key_epoch = None;
        if temporary_caller {
            r.public_ip = None;
            r.physical_public_ip = None;
            r.physical_seen_at = None;
            r.country_code = None;
            r.country = None;
            r.region = None;
            r.city = None;
            r.lat = None;
            r.lon = None;
            r.accuracy_radius_km = None;
            r.geo_level = None;
            r.pinned_zone_id = None;
            r.effective_zone_id = None;
            r.effective_zone_name = None;
            r.zone_source = None;
            r.default_route_vpn = false;
        }
    }

    let page = apply_query(rows, &query);
    let visible = reach_by_node.len();
    tracing::debug!(
        tenant_id = %tid, agent_id = %self_hex, overlay = vis.overlay, acl_mode = vis.acl_mode,
        visible, total = page.total,
        "agent self: device listing"
    );

    let items = page
        .items
        .into_iter()
        .map(|r| {
            let reachable = r
                .overlay_node_id
                .as_deref()
                .and_then(|id| reach_by_node.get(id).copied())
                .unwrap_or(false);
            VisibleDeviceRow {
                is_self: r.id == self_hex,
                kind: r.kind.to_string(),
                id: r.id,
                name: r.name,
                display_name: r.display_name,
                os: r.os,
                version: r.version,
                presence: presence_str(r.presence).to_string(),
                is_online: r.is_online,
                last_seen_at: r.last_seen_at,
                overlay_ip: r.overlay_ip,
                overlay_node_id: r.overlay_node_id,
                magic_dns_name: r.magic_dns_name,
                magic_dns_fqdn: r.magic_dns_fqdn,
                tags: r.tags,
                reachable,
                ephemeral: r.ephemeral,
                rdp_available: r.rdp_available,
                rdp_port: r.rdp_port,
                rdp_cert_sha256: r.rdp_cert_sha256,
                rdp_mesh_reachable: r.rdp_mesh_reachable,
                public_ip: r.public_ip,
                physical_public_ip: r.physical_public_ip,
                physical_seen_at: r.physical_seen_at,
                country_code: r.country_code,
                country: r.country,
                region: r.region,
                city: r.city,
                lat: r.lat,
                lon: r.lon,
                accuracy_radius_km: r.accuracy_radius_km,
                geo_level: r.geo_level,
                pinned_zone_id: r.pinned_zone_id,
                effective_zone_id: r.effective_zone_id,
                effective_zone_name: r.effective_zone_name,
                zone_source: r.zone_source,
                default_route_vpn: r.default_route_vpn,
            }
        })
        .collect();
    Ok(Json(VisibleDevicesPage {
        items,
        total: page.total,
        page: page.page,
        per_page: page.per_page,
        total_pages: page.total_pages,
        overlay: vis.overlay.to_string(),
        acl_mode: vis.acl_mode.to_string(),
        self_node_id: vis.self_node_id,
        org_name,
    }))
}

/// GET /api/agent/self/mesh — the org mesh graph restricted to the caller's
/// visible set: nodes it may see, the agents backing them, and edges whose
/// BOTH ends it may see (an edge to a withheld node would name it). Each node
/// carries a server-computed `label` (the companion has no agent list to join
/// against) and the payload names the caller's `self_node_id`, plus the same
/// `overlay` / `acl_mode` the listing reports so an empty graph can explain
/// itself. `{"enabled": false}` when stats are off, like every stats route.
pub async fn mesh(
    State(state): State<AppState>,
    agent: HostAuthAgent,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let vis = visibility(&state, &agent).await?;
    let visible: HashSet<String> = vis.reachable_by_node().into_keys().collect();
    // No node ⇒ nothing to draw; the org's graph is not read at all.
    let built = if visible.is_empty() {
        BuiltMesh::default()
    } else {
        build_mesh(&state.core, agent.tenant_id).await?
    };
    tracing::debug!(
        tenant_id = %agent.tenant_id, agent_id = %agent.agent_id,
        overlay = vis.overlay, acl_mode = vis.acl_mode, visible = visible.len(),
        total = built.nodes.len(),
        "agent self: mesh"
    );
    let mut payload = to_payload(built, Some(&visible), vis.self_node_id.as_deref());
    payload["overlay"] = serde_json::Value::String(vis.overlay.to_string());
    payload["acl_mode"] = serde_json::Value::String(vis.acl_mode.to_string());
    Ok(Json(payload))
}

#[derive(Debug, Default, Deserialize)]
pub struct EgressProbeQuery {
    /// FR-134 — management-entry attestation token when the probe traverses a gateway entry.
    #[serde(default)]
    pub entry: Option<String>,
}

/// Compact response from `POST /api/agent/self/egress-probe` (FR-138).
#[derive(Debug, Serialize)]
pub struct EgressProbeResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_public_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_public_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_source: Option<ZoneSource>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub hysteresis_held: bool,
}

/// POST /api/agent/self/egress-probe (FR-138) — physical-path egress observation.
///
/// The daemon binds a short-lived HTTPS socket to a physical non-VPN uplink and posts here with
/// its agent bearer token. The server observes the connection's `canonical_public_ip` (honouring
/// FR-134 attested management-entry origins); the device never states an IP in the request body.
pub async fn egress_probe(
    State(state): State<AppState>,
    agent: HostAuthAgent,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Query(query): Query<EgressProbeQuery>,
) -> Result<Json<EgressProbeResponse>, ApiError> {
    let Some(fleet) = state.modules.fleet.as_ref() else {
        return Err(ApiError::ServiceUnavailable(
            "the fleet module is not mounted on this server".to_string(),
        ));
    };
    let tid = agent.tenant_id;
    let aid = agent.agent_id;

    let raw_origin = ConnectionOrigin::capture(
        &headers,
        peer,
        &state.settings.app.business_trusted_proxy_cidrs,
        state.settings.app.rate_limit_trusted_hops,
    );
    let (origin, _entry_id) = meshharbor_mod_fleet::management_path::resolve_origin(
        fleet,
        tid,
        aid,
        query.entry.as_deref(),
        raw_origin,
    )
    .await;
    let observed_ip = origin.observed_public_ip();

    let mut row = fleet.agents.find_live_in_tenant(tid, aid).await?;
    let net_dao = meshharbor_services::dao::overlay_network::OverlayNetworkDao::new(&state.core.db);
    let zones = net_dao
        .find_for_tenant(tid)
        .await?
        .map(|n| n.zones)
        .unwrap_or_default();

    let now = bson::DateTime::now();
    let now_ms = now.timestamp_millis();

    let (before_res, before_source) =
        meshharbor_mod_fleet::socket::resolve_agent_zone_with_source(fleet, &zones, &row, None);
    let before_zone_id = match before_res {
        DeviceZoneResolution::Resolved(z) => Some(z.id.clone()),
        _ => None,
    };

    let probe_country = observed_ip
        .and_then(|ip| state.core.geoip.security_lookup(ip).country_code)
        .map(|c| c.to_ascii_uppercase());
    let probe_zone_id = probe_country
        .as_deref()
        .and_then(|cc| auto_zone_for_country(&zones, Some(cc)))
        .map(|z| z.id.clone());
    let ws_country = meshharbor_mod_fleet::socket::agent_effective_country(fleet, &row);
    let conn_id = fleet
        .rc_hub
        .agent_live_conn_id(aid)
        .unwrap_or_else(|| "__disconnected__".to_string());

    let mut hysteresis_held = false;
    if let Some(ip) = observed_ip {
        // A device currently sitting on an unverified VPN fallback (no clean
        // history yet) has no trusted zone to protect with hysteresis: its
        // first verified physical-path probe commits immediately.
        let decision = if row.pinned_zone_id.is_some()
            || zones.is_empty()
            || matches!(
                before_source,
                Some(meshharbor_remote_control::models::ZoneSource::AutoEgressFallback)
            ) {
            ProbeHysteresisDecision::Commit
        } else {
            fleet.rc_hub.evaluate_probe_hysteresis(
                aid,
                &conn_id,
                before_zone_id.as_deref(),
                probe_country.as_deref(),
                probe_zone_id.as_deref(),
                ws_country.as_deref(),
                row.capabilities.default_route_vpn,
                now_ms,
            )
        };
        match decision {
            ProbeHysteresisDecision::Commit => {
                let ip_str = ip.to_string();
                fleet
                    .agents
                    .update_physical_egress(aid, &ip_str, now, probe_zone_id.as_deref())
                    .await?;
                row.physical_public_ip = Some(ip_str);
                row.physical_seen_at = Some(now);
                if let Some(ref pz) = probe_zone_id {
                    row.last_clean_zone_id = Some(pz.clone());
                }
            }
            ProbeHysteresisDecision::Hold => {
                hysteresis_held = true;
            }
        }
    }

    let (after_res, zone_source) =
        meshharbor_mod_fleet::socket::resolve_agent_zone_with_source(fleet, &zones, &row, None);
    let (zone_id, zone_name) = match after_res {
        DeviceZoneResolution::Resolved(z) => (Some(z.id.clone()), Some(z.name.clone())),
        _ => (None, None),
    };

    if before_zone_id != zone_id && !zones.is_empty() {
        let _ = net_dao.bump_zone_revision(tid).await;
        #[cfg(feature = "network")]
        if let Some(network) = state.modules.network.as_ref() {
            network.org_relay.bump_eligibility_generation();
            let snapshot =
                meshharbor_mod_network::network_zones::TenantZoneSnapshot::load_consistent(
                    network, tid,
                )
                .await;
            snapshot.sync_hub_policy_for_agent(network, tid, aid).await;
            if row.peer_relay_policy.serve {
                snapshot
                    .sync_relay_backbone_endpoints_at_current_revision(network, tid, None)
                    .await;
            }
            meshharbor_mod_network::org_relay::recheck_zones(network, aid, "egress_probe").await;
            meshharbor_mod_network::overlay::on_agent_policy_changed(
                network,
                tid,
                aid,
                "zone_policy",
            )
            .await;
        }
        meshharbor_mod_fleet::management_path::sync_tenant_management_paths(fleet, tid).await;
    }

    let physical_public_ip = row
        .physical_public_ip
        .as_deref()
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .and_then(meshharbor_core::user_analytics::canonical_public_ip)
        .map(|ip| ip.to_string());
    let current_public_ip = fleet
        .rc_hub
        .agent_live_public_ip(aid)
        .or_else(|| {
            row.public_ip
                .as_deref()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .and_then(meshharbor_core::user_analytics::canonical_public_ip)
        })
        .map(|ip| ip.to_string());

    tracing::debug!(
        tenant_id = %tid,
        agent_id = %aid,
        observed = observed_ip.is_some(),
        hysteresis_held,
        zone_id = ?zone_id,
        zone_source = ?zone_source,
        "agent self: egress probe"
    );

    Ok(Json(EgressProbeResponse {
        ok: true,
        physical_public_ip,
        current_public_ip,
        zone_id,
        zone_name,
        zone_source,
        hysteresis_held,
    }))
}

#[cfg(any(feature = "network", test))]
fn should_query_tunnel_clients(full_account_inventory: bool, has_client_nodes: bool) -> bool {
    full_account_inventory || has_client_nodes
}

#[cfg(any(feature = "network", test))]
fn should_include_tunnel_client(in_netmap: bool, full_account_inventory: bool) -> bool {
    in_netmap || full_account_inventory
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_inventory_includes_nodeless_tunnel_clients_while_guest_requires_netmap() {
        // Permanent caller (`full_account_inventory == true`) queries and includes
        // active tunnel clients even when `node_by_client` is empty and `in_netmap == false`.
        assert!(should_query_tunnel_clients(true, false));
        assert!(should_include_tunnel_client(false, true));
        assert!(should_include_tunnel_client(true, true));

        // Temporary guest (`full_account_inventory == false`) skips querying when no
        // client nodes exist and includes ONLY shaped `in_netmap` tunnel clients.
        assert!(!should_query_tunnel_clients(false, false));
        assert!(should_query_tunnel_clients(false, true));
        assert!(!should_include_tunnel_client(false, false));
        assert!(should_include_tunnel_client(true, false));
    }
}
