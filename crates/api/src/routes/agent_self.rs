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
};
use meshharbor_core::ApiError;
use meshharbor_mod_fleet::agent::{AgentPresence, agent_presence_batch, derive_agent_presence};
use meshharbor_remote_control::models::{
    NodeRef, OverlayAclMode, OverlayNode, VisibleDeviceRow, VisibleDevicesPage,
};

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
    /// The visible node rows, each with the netmap's `reachable` verdict —
    /// the caller's own node included. `None` = the caller alone.
    nodes: Option<Vec<(OverlayNode, bool)>>,
}

impl Visibility {
    fn self_only(overlay: &'static str, acl_mode: &'static str) -> Self {
        Self {
            overlay,
            acl_mode,
            self_node_id: None,
            nodes: None,
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
    let Some(network_id) = net.id else {
        return Ok(Visibility::self_only("no_network", stored_mode));
    };
    // The device's own LIVE node — a released (tombstoned) node is gone for
    // good; the device comes back with a fresh lease when it rejoins.
    let Some(self_node) = current_node(network, NodeIdentity::Agent(agent.agent_id)).await else {
        return Ok(Visibility::self_only("no_node", stored_mode));
    };
    let Some(self_id) = self_node.id else {
        return Ok(Visibility::self_only("no_node", stored_mode));
    };

    let all = network
        .overlay_nodes
        .list_active_in_network(agent.tenant_id, network_id)
        .await?;
    let reach = reachability(network, &all).await;
    let shaped = shape_full_netmap(network, &self_node, &all, &reach).await;
    // Only the id and the presence verdict leave the shaped peers.
    let visible: HashMap<bson::oid::ObjectId, bool> = shaped
        .peers
        .iter()
        .map(|p| (p.node_id, p.reachable))
        .collect();
    let self_reachable = reach.get(&self_id).copied().unwrap_or(true);
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
        nodes: Some(nodes),
    })
}

/// A build without the network module has no mesh: every device sees itself.
#[cfg(not(feature = "network"))]
async fn visibility(_state: &AppState, _agent: &HostAuthAgent) -> Result<Visibility, ApiError> {
    Ok(Visibility::self_only("unavailable", "unknown"))
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

    // Nodes are attached to rows ONLY from the visible set; a peer the netmap
    // withholds gets no overlay columns and — below — no row.
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
    let dns_domain = if node_by_agent.is_empty() && node_by_client.is_empty() {
        None
    } else {
        state
            .tenants
            .base
            .find_by_id(tid)
            .await
            .ok()
            .and_then(|t| t.settings.magic_dns_domain)
    };

    let agents = fleet.agents.list_all_active_for_tenant(tid).await?;
    let fresh = agent_presence_batch(fleet, &agents).await;
    let mut rows: Vec<DeviceRow> = Vec::with_capacity(agents.len());
    for a in agents {
        let redis_fresh = a.id.map(|i| fresh.contains(&i)).unwrap_or(false);
        let (presence, is_online) = derive_agent_presence(fleet, &a, redis_fresh);
        let node = a.id.and_then(|i| node_by_agent.get(&i).copied());
        rows.push(agent_row(
            a,
            presence,
            is_online,
            node,
            dns_domain.as_deref(),
        ));
    }
    // Tunnel clients exist only as overlay nodes from a device's point of
    // view: listed when the module is here and one of them is visible.
    #[cfg(feature = "network")]
    {
        if !node_by_client.is_empty()
            && let Some(network) = state.modules.network.as_ref()
        {
            for c in network
                .tunnel_clients
                .list_all_active_for_tenant(tid)
                .await?
            {
                let node = c.id.and_then(|i| node_by_client.get(&i).copied());
                rows.push(client_row(c, node, dns_domain.as_deref()));
            }
        }
    }

    // The visibility rule, applied to rows: the caller itself, or a device
    // whose overlay node the netmap carries.
    rows.retain(|r| {
        r.id == self_hex
            || r.overlay_node_id
                .as_deref()
                .is_some_and(|id| reach_by_node.contains_key(id))
    });
    // Blank what the device must not see BEFORE the search runs.
    for r in &mut rows {
        r.machine_id.clear();
        r.owner_user_id.clear();
        r.overlay_public_key = None;
        r.overlay_key_epoch = None;
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
