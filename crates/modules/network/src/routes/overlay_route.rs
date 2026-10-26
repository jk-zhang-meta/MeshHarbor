// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Admin CRUD for overlay subnet-route approval (Phase 1 subnet router).
//!
//! A node advertises subnet CIDRs on join (`OverlayNode.advertised_routes`);
//! NOTHING is distributed to peers until an admin approves a subset here
//! (`approved_routes`). Mirrors the tunnel-policy admin surface. On change we
//! re-fan the node's netmap entry so peers pick up the routes immediately
//! instead of waiting for the next join.

use roomler_ai_services::quota;
use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{doc, oid::ObjectId};
use roomler_ai_db::models::role::permissions;
use roomler_ai_remote_control::models::{
    AgentStatus, DEFAULT_ROUTE_V4, NodeRef, OsKind, OverlayNode,
};
use serde::{Deserialize, Serialize};

use roomler_core::guards::require_permission;
use roomler_core::{ApiError, extractors::auth::AuthUser};

use crate::NetworkState;

#[derive(Debug, Serialize)]
pub struct OverlayNodeResponse {
    pub id: String,
    pub name: String,
    pub overlay_ip: String,
    /// `"agent"` | `"tunnel_client"`.
    pub kind: &'static str,
    /// CIDRs the node claims it can route (from its config).
    pub advertised_routes: Vec<String>,
    /// Admin-approved subset actually distributed to peers.
    pub approved_routes: Vec<String>,
    /// P5 — admin has designated this node as an exit node.
    pub is_exit_node: bool,
    /// P5 — the node advertised `0.0.0.0/0`, so it's ELIGIBLE to be toggled
    /// on as an exit node (the toggle is gated on this).
    pub can_be_exit_node: bool,
    pub online: bool,
    /// The backing agent / tunnel-client is still enrolled, so evicting this
    /// node from the mesh does NOT keep it out — the device rejoins on its next
    /// connect and takes a NEW overlay address. `false` means the device is
    /// gone and the eviction is permanent. The admin UI branches its confirm
    /// copy on this, so it must not be guessed.
    pub will_rejoin: bool,
    pub last_seen_at: String,
    /// Backing device id (2026-08-04): the FK the unified Devices page joins
    /// on — the wire previously carried NO key linking a node to its agent /
    /// tunnel-client row (name is a lossy, de-duplicated DNS label).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_client_id: Option<String>,
    /// FR-97 P0b — the backing agent's OS (`linux` | `macos` | `windows`), so
    /// an admin approving an exit or a subnet router sees what the device is.
    /// Display only: what a device can serve is what IT says
    /// (`route_offer_withheld`), never inferred from its OS. `None` for a
    /// tunnel client, or when the agent row could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsKind>,
    /// FR-97 P0b — the device's own reason for offering no `/0` and no subnet
    /// route although it was configured to (it cannot forward or NAT for the
    /// overlay). Such a node advertises nothing, so without this it would not
    /// appear among the routes at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_offer_withheld: Option<String>,
}

impl OverlayNodeResponse {
    fn from_node(n: OverlayNode, will_rejoin: bool, os: Option<OsKind>) -> Self {
        let route_offer_withheld = n.route_offer_withheld.clone();
        let can_be_exit_node = n.advertised_routes.iter().any(|r| r == DEFAULT_ROUTE_V4);
        let (agent_id, tunnel_client_id) = match &n.node_ref {
            NodeRef::Agent { agent_id } => (Some(agent_id.to_hex()), None),
            NodeRef::TunnelClient { tunnel_client_id } => (None, Some(tunnel_client_id.to_hex())),
        };
        Self {
            id: n.id.map(|i| i.to_hex()).unwrap_or_default(),
            name: n.name,
            overlay_ip: n.overlay_ip,
            kind: match n.node_ref {
                NodeRef::Agent { .. } => "agent",
                NodeRef::TunnelClient { .. } => "tunnel_client",
            },
            agent_id,
            tunnel_client_id,
            online: matches!(n.status, AgentStatus::Online),
            will_rejoin,
            // Surface only the SUBNET routes in the per-CIDR grid — the `/0`
            // default is managed by the exit-node toggle, not a checkbox.
            advertised_routes: n
                .advertised_routes
                .into_iter()
                .filter(|r| r != DEFAULT_ROUTE_V4)
                .collect(),
            approved_routes: n
                .approved_routes
                .into_iter()
                .filter(|r| r != DEFAULT_ROUTE_V4)
                .collect(),
            is_exit_node: n.is_exit_node,
            can_be_exit_node,
            last_seen_at: n.last_seen_at.try_to_rfc3339_string().unwrap_or_default(),
            os,
            route_offer_withheld,
        }
    }
}

impl From<OverlayNode> for OverlayNodeResponse {
    /// `will_rejoin: true` — the single-node responses (route approval, exit-node
    /// toggle) act on a node that is live by construction, and removal now
    /// cascades from the device to its node, so a live node cannot outlive its
    /// backing agent / tunnel-client. Only the LIST endpoint resolves this for
    /// real, because pre-cascade fleets can still hold nodes whose device was
    /// deleted before the release feature existed. No `os`: the handlers that
    /// answer with ONE node use [`single_node_response`], which reads it.
    fn from(n: OverlayNode) -> Self {
        Self::from_node(n, true, None)
    }
}

/// FR-97 P0b — a single-node response WITH its backing agent's OS. The admin
/// UI replaces the row it acted on with this response, so a response without
/// the OS would drop the row's OS chip on every toggle. Tenant-scoped read.
async fn single_node_response(state: &NetworkState, n: OverlayNode) -> OverlayNodeResponse {
    let os = match n.node_ref {
        NodeRef::Agent { agent_id } => state
            .fleet
            .agents
            .base
            .find_one(doc! { "_id": agent_id, "tenant_id": n.tenant_id })
            .await
            .ok()
            .flatten()
            .map(|a| a.os),
        NodeRef::TunnelClient { .. } => None,
    };
    OverlayNodeResponse::from_node(n, true, os)
}

/// Resolve `will_rejoin` for a batch of nodes in two queries: a node rejoins iff
/// its backing agent / tunnel-client row is still live.
async fn resolve_will_rejoin(
    state: &NetworkState,
    tenant_id: ObjectId,
    nodes: &[OverlayNode],
) -> (HashSet<ObjectId>, HashMap<ObjectId, OsKind>) {
    let mut agent_ids = Vec::new();
    let mut client_ids = Vec::new();
    for n in nodes {
        match n.node_ref {
            NodeRef::Agent { agent_id } => agent_ids.push(agent_id),
            NodeRef::TunnelClient { tunnel_client_id } => client_ids.push(tunnel_client_id),
        }
    }
    let mut live = HashSet::new();
    // FR-97 P0b — each live agent's OS, from the same query.
    let mut os = HashMap::new();
    if !agent_ids.is_empty()
        && let Ok(rows) = state
            .fleet
            .agents
            .base
            .find_many(
                doc! { "_id": { "$in": &agent_ids }, "tenant_id": tenant_id, "deleted_at": null },
                None,
            )
            .await
    {
        for a in rows {
            if let Some(id) = a.id {
                live.insert(id);
                os.insert(id, a.os);
            }
        }
    }
    if !client_ids.is_empty()
        && let Ok(rows) = state
            .tunnel_clients
            .base
            .find_many(
                doc! { "_id": { "$in": &client_ids }, "tenant_id": tenant_id, "deleted_at": null },
                None,
            )
            .await
    {
        live.extend(rows.into_iter().filter_map(|c| c.id));
    }
    (live, os)
}

/// The id of whatever device backs this node — the key `resolve_will_rejoin`
/// returns liveness under.
fn backing_device_id(n: &OverlayNode) -> ObjectId {
    match n.node_ref {
        NodeRef::Agent { agent_id } => agent_id,
        NodeRef::TunnelClient { tunnel_client_id } => tunnel_client_id,
    }
}

#[derive(Debug, Deserialize)]
pub struct SetApprovedRoutesRequest {
    pub approved_routes: Vec<String>,
}

/// GET /api/tenant/{tenant_id}/overlay-node — list the tenant's overlay nodes
/// with their advertised + approved subnet routes (the subnet-router admin view).
pub async fn list_overlay_nodes(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let network = state.overlay_networks.get_or_create(tid).await?;
    let Some(network_id) = network.id else {
        return Ok(Json(serde_json::json!({ "items": [] })));
    };
    let nodes = state
        .overlay_nodes
        .list_active_in_network(tid, network_id)
        .await?;
    let (live_devices, os_by_agent) = resolve_will_rejoin(&state, tid, &nodes).await;
    let items: Vec<OverlayNodeResponse> = nodes
        .into_iter()
        .map(|n| {
            let will_rejoin = live_devices.contains(&backing_device_id(&n));
            let os = match n.node_ref {
                NodeRef::Agent { agent_id } => os_by_agent.get(&agent_id).copied(),
                NodeRef::TunnelClient { .. } => None,
            };
            OverlayNodeResponse::from_node(n, will_rejoin, os)
        })
        .collect();
    Ok(Json(serde_json::json!({ "items": items })))
}

/// PUT /api/tenant/{tenant_id}/overlay-node/{node_id}/approved-routes — set the
/// admin-approved subset of a node's advertised routes. Only routes the node
/// actually advertised may be approved; the change is re-fanned to peers.
pub async fn set_approved_routes(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, node_id)): Path<(String, String)>,
    Json(body): Json<SetApprovedRoutesRequest>,
) -> Result<Json<OverlayNodeResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let nid = ObjectId::parse_str(&node_id)
        .map_err(|_| ApiError::BadRequest("Invalid node_id".to_string()))?;
    // Distributing a subnet route (or an exit node's /0) exposes a whole
    // network to the mesh, and overlay traffic bypasses the tunnel ACL — so
    // this is an agent-management action, not something bare tenant
    // membership should authorise.
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let network = state.overlay_networks.get_or_create(tid).await?;
    let network_id = network
        .id
        .ok_or_else(|| ApiError::Internal("overlay network missing _id".into()))?;

    // Scope the lookup to the tenant's network — tenant-safe by construction.
    // Keep the full live list: the duplicate-claim guard below needs the
    // OTHER nodes' approvals.
    let nodes = state
        .overlay_nodes
        .list_active_in_network(tid, network_id)
        .await?;
    let node = nodes
        .iter()
        .find(|n| n.id == Some(nid))
        .cloned()
        .ok_or_else(|| ApiError::NotFound("overlay node not found".into()))?;

    // Only routes the node advertised may be approved (dedup, preserve order).
    // P5: the `0.0.0.0/0` default route is REJECTED here — it may only be
    // approved via the exit-node toggle (`set_exit_node`), so a mis-clicked
    // checkbox can never route a client's whole internet through this node.
    let mut approved: Vec<String> = Vec::new();
    for r in &body.approved_routes {
        if r == DEFAULT_ROUTE_V4 {
            return Err(ApiError::BadRequest(
                "the default route 0.0.0.0/0 is managed by the exit-node toggle, \
                 not per-CIDR approval"
                    .into(),
            ));
        }
        if let Some(why) = route_problem(r) {
            return Err(ApiError::BadRequest(format!("route {r} {why}")));
        }
        if !node.advertised_routes.contains(r) {
            return Err(ApiError::BadRequest(format!(
                "route {r} is not advertised by this node"
            )));
        }
        if !approved.contains(r) {
            approved.push(r.clone());
        }
    }
    // One LIVE subnet router per CIDR (the `wg_key_taken_by_other` pattern).
    // Approving the same route on a second node turns every client's routing
    // into a tie-break between the claimants — and the field incident behind
    // this guard (2026-08-25) was exactly that: a stale approval left on a
    // superseded router's row made clients loop corp traffic through a host
    // with no working uplink, nondeterministically per restart. The 409 names
    // the current holder so the operator revokes there first. Exact-string
    // match, same as the advertised-routes check above — approvals are stored
    // and compared as literal CIDR strings on this whole surface. Exit-node
    // `/0`s are exempt by construction: they are rejected from `approved`
    // above (plural exit nodes are by design — clients CHOOSE their exit).
    // Not only an equal CIDR: an OVERLAPPING one (10.0.0.0/16 against
    // 10.0.1.0/24) splits one site between two routers by longest prefix,
    // the same confusion with a quieter signature.
    for r in &approved {
        if let Some((holder, held)) = nodes.iter().filter(|n| n.id != Some(nid)).find_map(|n| {
            n.approved_routes
                .iter()
                .find(|a| a.as_str() != DEFAULT_ROUTE_V4 && cidrs_overlap(a, r))
                .map(|a| (n, a))
        }) {
            return Err(ApiError::Conflict(format!(
                "route {r} overlaps {held}, already approved on live node \"{}\" ({}) — \
                 revoke it there first (one live subnet router per network)",
                holder.name,
                holder.id.map(|i| i.to_hex()).unwrap_or_default(),
            )));
        }
    }
    // Preserve an existing exit-node `/0` approval across a subnet-route edit
    // (the grid never carries `/0`, so a naive replace would drop it).
    if node.is_exit_node {
        approved.push(DEFAULT_ROUTE_V4.to_string());
    }

    let updated = state
        .overlay_nodes
        .set_approved_routes(nid, &approved)
        .await?;
    // Push the change to peers now, not on their next join.
    crate::overlay::refan_node(&state, &updated).await;
    Ok(Json(single_node_response(&state, updated).await))
}

/// Why `r` can never be a subnet route, or `None`. A subnet route names a
/// real site network: canonical (no host bits, so two spellings of one
/// network cannot dodge the one-router rule), not a default-route half (that
/// is the exit-node toggle), and not an address space that is never a site:
/// loopback, link-local, multicast, reserved, "this network", or the
/// overlay's own `100.64.0.0/10`, where a route would capture peers' traffic.
fn route_problem(r: &str) -> Option<String> {
    let Ok(net) = r.parse::<ipnet::IpNet>() else {
        return Some("is not a CIDR (a bare address needs a prefix, e.g. 10.0.0.5/32)".into());
    };
    if net != net.trunc() {
        return Some(format!("has host bits set; the network is {}", net.trunc()));
    }
    if net.prefix_len() <= 1 {
        return Some("is (half of) a default route; use the exit-node toggle".into());
    }
    let never: &[&str] = match net {
        ipnet::IpNet::V4(_) => &[
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "100.64.0.0/10",
        ],
        ipnet::IpNet::V6(_) => &["::/127", "fe80::/10", "ff00::/8"],
    };
    never
        .iter()
        .find(|s| cidrs_overlap(s, r))
        .map(|s| format!("overlaps {s}, which is never a site network"))
}

/// Whether two CIDRs share any address. Unparseable input overlaps nothing
/// (it is refused before it gets here).
fn cidrs_overlap(a: &str, b: &str) -> bool {
    match (a.parse::<ipnet::IpNet>(), b.parse::<ipnet::IpNet>()) {
        (Ok(a), Ok(b)) => a.contains(&b.network()) || b.contains(&a.network()),
        _ => false,
    }
}

#[derive(Debug, Deserialize)]
pub struct SetExitNodeRequest {
    pub enabled: bool,
}

/// PUT /api/tenant/{tenant_id}/overlay-node/{node_id}/exit-node — designate (or
/// un-designate) a node as an exit node (P5). Enabling requires the node to have
/// advertised `0.0.0.0/0`; it sets `is_exit_node` and adds `/0` to the node's
/// `approved_routes` (the data-plane signal). Re-fanned to peers immediately.
pub async fn set_exit_node(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, node_id)): Path<(String, String)>,
    Json(body): Json<SetExitNodeRequest>,
) -> Result<Json<OverlayNodeResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let nid = ObjectId::parse_str(&node_id)
        .map_err(|_| ApiError::BadRequest("Invalid node_id".to_string()))?;
    // Distributing a subnet route (or an exit node's /0) exposes a whole
    // network to the mesh, and overlay traffic bypasses the tunnel ACL — so
    // this is an agent-management action, not something bare tenant
    // membership should authorise.
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    // FR-32 P1a — `exit_nodes` is advertised per plan and was enforced nowhere.
    // ⚠ Only ENABLING is gated. Turning an exit node OFF must always be
    // allowed: a plan downgrade would otherwise trap the tenant with an exit
    // they cannot withdraw, which is worse than the feature being free.
    if body.enabled {
        let tenant = state.tenants.base.find_by_id(tid).await?;
        // FR-102 P4 — through core, which also counts the collision per org.
        if let Err(d) =
            roomler_core::quota::require_feature(&state, &tenant, quota::Limit::ExitNodes)
        {
            return Err(ApiError::Forbidden(d.message()));
        }
    }

    let network = state.overlay_networks.get_or_create(tid).await?;
    let network_id = network
        .id
        .ok_or_else(|| ApiError::Internal("overlay network missing _id".into()))?;
    let nodes = state
        .overlay_nodes
        .list_active_in_network(tid, network_id)
        .await?;
    let node = nodes
        .into_iter()
        .find(|n| n.id == Some(nid))
        .ok_or_else(|| ApiError::NotFound("overlay node not found".into()))?;

    // Gate: can only become an exit node if it actually advertised `0.0.0.0/0`.
    if body.enabled && !node.advertised_routes.iter().any(|r| r == DEFAULT_ROUTE_V4) {
        return Err(ApiError::BadRequest(
            "node has not advertised 0.0.0.0/0 — enable exit-node mode in its \
             config first (overlay_exit_node_enabled), then re-join"
                .into(),
        ));
    }

    let updated = state.overlay_nodes.set_exit_node(nid, body.enabled).await?;
    crate::overlay::refan_node(&state, &updated).await;
    Ok(Json(single_node_response(&state, updated).await))
}

#[derive(Debug, Serialize)]
pub struct EvictOverlayNodeResponse {
    pub released: bool,
    pub node_id: String,
    pub name: String,
    /// The address returned to the tenant's pool.
    pub overlay_ip: String,
    /// `false` when the host number could not be recycled (CIDR drift, or the
    /// pool is at its cap). The node is still evicted; the address just leaks.
    pub host_recycled: bool,
}

/// DELETE /api/tenant/{tenant_id}/overlay-node/{node_id} — evict a node from the
/// overlay mesh and release its address back to the tenant's pool.
///
/// This is "force a new lease", NOT "ban": it does not touch the backing agent /
/// tunnel-client, so a still-enrolled device rejoins on its next connect and is
/// handed a DIFFERENT overlay IP (and reappears as a new node id — its MagicDNS
/// name comes back unchanged, since the tombstone no longer holds it). To remove
/// a device for good, delete the agent or tunnel client. There is deliberately
/// no per-machine overlay denylist today.
pub async fn evict_overlay_node(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, node_id)): Path<(String, String)>,
) -> Result<Json<EvictOverlayNodeResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let nid = ObjectId::parse_str(&node_id)
        .map_err(|_| ApiError::BadRequest("Invalid node_id".to_string()))?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    let network = state.overlay_networks.get_or_create(tid).await?;
    let network_id = network
        .id
        .ok_or_else(|| ApiError::Internal("overlay network missing _id".into()))?;
    // Scope the lookup to the tenant's network — cross-tenant-safe by
    // construction, and an already-released node is simply absent (404).
    let nodes = state
        .overlay_nodes
        .list_active_in_network(tid, network_id)
        .await?;
    let node = nodes
        .into_iter()
        .find(|n| n.id == Some(nid))
        .ok_or_else(|| ApiError::NotFound("overlay node not found".into()))?;

    let released = crate::overlay::release_overlay_node(&state, &node, "admin_evict")
        .await
        .ok_or_else(|| ApiError::NotFound("overlay node not found".into()))?;

    tracing::info!(admin = %auth.user_id, tenant = %tid, node = %nid,
        overlay_ip = %released.overlay_ip, "admin evicted an overlay node");

    Ok(Json(EvictOverlayNodeResponse {
        released: true,
        node_id: released.node_id.to_hex(),
        name: released.name,
        overlay_ip: released.overlay_ip,
        host_recycled: released.host_recycled,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 2 MagicDNS — tenant DNS settings
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct MagicDnsResponse {
    /// Overlay DNS suffix (`None` = MagicDNS off).
    pub magic_dns_domain: Option<String>,
    /// Upstream nameservers for non-overlay queries.
    pub magic_dns_nameservers: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SetMagicDnsRequest {
    #[serde(default)]
    pub magic_dns_domain: Option<String>,
    #[serde(default)]
    pub magic_dns_nameservers: Vec<String>,
}

/// GET /api/tenant/{tenant_id}/magic-dns — the tenant's current MagicDNS config.
pub async fn get_magic_dns(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<MagicDnsResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let tenant = state.tenants.base.find_by_id(tid).await?;
    Ok(Json(MagicDnsResponse {
        magic_dns_domain: tenant.settings.magic_dns_domain,
        magic_dns_nameservers: tenant.settings.magic_dns_nameservers,
    }))
}

/// PUT /api/tenant/{tenant_id}/magic-dns — set the MagicDNS domain + upstreams.
/// An empty domain disables MagicDNS.
pub async fn set_magic_dns(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<SetMagicDnsRequest>,
) -> Result<Json<MagicDnsResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    // Normalize: blank domain → None (off); lowercase, strip surrounding dots.
    let domain = body
        .magic_dns_domain
        .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty());

    // FR-32 P1a — `magic_dns` is advertised per plan and was enforced nowhere.
    // ⚠ Only SETTING a domain is gated; clearing it (`None` = off) must always
    // be allowed, for the same reason as the exit-node gate above — a downgrade
    // must never leave a tenant unable to switch the feature off.
    if domain.is_some() {
        let tenant = state.tenants.base.find_by_id(tid).await?;
        // FR-102 P4 — through core, which also counts the collision per org.
        if let Err(d) =
            roomler_core::quota::require_feature(&state, &tenant, quota::Limit::MagicDns)
        {
            return Err(ApiError::Forbidden(d.message()));
        }
    }

    if let Some(d) = &domain
        && !d
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(ApiError::BadRequest(
            "magic_dns_domain has invalid characters".to_string(),
        ));
    }
    // W2 — reserved-name guard for zones under the product domain: the
    // agent resolver is AUTHORITATIVE for its zone (in-zone miss =
    // NXDOMAIN, never forwarded), so a tenant zone named after fleet
    // infrastructure would shadow it org-wide from EVERY member host — a
    // zone `coturn.roomler.ai` NXDOMAINs the relay fleet itself. Only
    // `*.roomler.ai` is guarded; foreign apex domains are the operator's
    // own business.
    if let Some(d) = &domain
        && let Some(label) = d.strip_suffix(".roomler.ai").map(|p| {
            // The rightmost remaining label is the [org] slot directly
            // under roomler.ai (e.g. "grox" from "grox.roomler.ai").
            p.rsplit('.').next().unwrap_or(p).to_string()
        })
    {
        const RESERVED: &[&str] = &[
            "api", "argocd", "grafana", "mail", "registry", "staging", "www",
        ];
        let shadowed = RESERVED.contains(&label.as_str())
            || label.starts_with("coturn")
            || label.starts_with("derp");
        if shadowed {
            return Err(ApiError::BadRequest(format!(
                "magic_dns_domain '{label}.roomler.ai' would shadow reserved \
                 infrastructure names for every org member; pick another name"
            )));
        }
    }
    let nameservers: Vec<String> = body
        .magic_dns_nameservers
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let tenant = state
        .tenants
        .set_magic_dns(tid, domain, nameservers)
        .await?;
    Ok(Json(MagicDnsResponse {
        magic_dns_domain: tenant.settings.magic_dns_domain,
        magic_dns_nameservers: tenant.settings.magic_dns_nameservers,
    }))
}

#[cfg(test)]
mod route_rule_tests {
    use super::*;

    #[test]
    fn only_a_canonical_site_network_can_be_a_subnet_route() {
        for ok in [
            "10.0.0.0/24",
            "192.168.1.0/24",
            "172.16.0.0/12",
            "10.0.0.5/32",
            "fd00:1::/64",
        ] {
            assert_eq!(route_problem(ok), None, "{ok}");
        }
        for bad in [
            "10.0.0.5/24",
            "10.0.0.5",
            "0.0.0.0/1",
            "128.0.0.0/1",
            "127.0.0.0/8",
            "169.254.1.0/24",
            "224.0.0.0/8",
            "100.64.0.0/10",
            "100.65.0.0/22",
            "100.0.0.0/8",
            "0.0.0.0/8",
            "fe80::/64",
            "ff02::/16",
        ] {
            assert!(route_problem(bad).is_some(), "{bad} must be refused");
        }
    }

    #[test]
    fn overlap_is_any_shared_address() {
        assert!(cidrs_overlap("10.0.0.0/16", "10.0.1.0/24"));
        assert!(cidrs_overlap("10.0.1.0/24", "10.0.0.0/16"));
        assert!(cidrs_overlap("10.0.1.0/24", "10.0.1.0/24"));
        assert!(!cidrs_overlap("10.0.1.0/24", "10.0.2.0/24"));
        assert!(!cidrs_overlap("10.0.0.0/8", "fd00::/8"));
    }
}
