// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Multi-org P2b — tenant-block addressing: status + the renumber migration.
//!
//! Every tenant shares `100.64.0.0/10` today, each network's host cursor
//! seeded at 1. Tenant A's `100.64.0.7` and tenant B's `100.64.0.7` are
//! therefore the SAME address — fine while a daemon carries exactly one org,
//! fatal the moment one host is enrolled in two (one interface, one routing
//! table, two claimants for the same /32).
//!
//! Blocks carve each tenant a disjoint slice out of the `/10`. New networks
//! get one at creation (gated by `overlay.blocks_enabled`); existing ones move
//! via the renumber endpoint here, which is deliberately explicit and
//! staged-per-tenant because it must:
//!
//! 1. refuse to run over a fleet below the P2a forward-compat floor (an older
//!    daemon purges its OWN on-link route at boot — host-wide mesh blackhole),
//! 2. rewrite every live node's address in one pass, and
//! 3. CYCLE every agent's WS, because a node's `self_ip` is bound once when
//!    its overlay session establishes.
//!
//! `dry_run` (the default) runs 1 and 2's planner and returns the full
//! before/after mapping without writing anything.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{doc, oid::ObjectId};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::models::{
    NodeRef, OVERLAY_BLOCK_MAX_PREFIX, OVERLAY_BLOCK_MIN_PREFIX, OverlayNetwork, OverlayNode,
    cidr_max_host, overlay_host, overlay_ip,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

use meshharbor_core::guards::require_permission;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::NetworkState;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct BlockStatusResponse {
    /// The range the tenant's overlay currently leases from.
    pub cidr: String,
    /// `true` while the tenant is still on the shared legacy `/10`.
    pub legacy: bool,
    /// Highest host ordinal the current range can lease.
    pub capacity: u32,
    /// Live nodes in the network.
    pub nodes: u32,
    /// IPAM cursor — how far the tenant has walked into its range.
    pub next_host: u32,
    /// Registry rows for this tenant, newest block first (the assigned one
    /// plus its quarantined predecessors).
    pub blocks: Vec<BlockRow>,
    /// Are new networks being carved on this deployment?
    pub carving_enabled: bool,
    /// Minimum device version a renumber requires.
    pub version_floor: String,
    /// Devices below the floor right now — a renumber refuses while non-empty.
    pub below_floor: Vec<DeviceVersion>,
    /// Fleet-wide slot accounting for the whole block space. Quarantined
    /// blocks are never re-issued, so `burned` only grows; reporting it is
    /// what turns "4032 slots is plenty" from a belief into something an
    /// operator can check (docs/multi-org.md §12).
    pub headroom: meshharbor_services::dao::overlay_block::BlockHeadroom,
}

#[derive(Debug, Serialize)]
pub struct BlockRow {
    pub cidr: String,
    pub slot: u32,
    pub slots: u32,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub released_reason: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DeviceVersion {
    pub name: String,
    pub kind: &'static str,
    /// The reported version, or `""` when the device has never checked in
    /// with one (treated as below the floor — fail closed).
    pub version: String,
    pub online: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct RenumberRequest {
    /// Plan only. Defaults to TRUE: a renumber is disruptive, so the
    /// destructive form must be asked for explicitly.
    #[serde(default = "default_true")]
    pub dry_run: bool,
    /// Block width to carve, `/16` … `/22`. Defaults to the deployment's
    /// `overlay.block_prefix`.
    #[serde(default)]
    pub prefix: Option<u8>,
    /// Cycle every agent's WS after the write so the fleet re-binds
    /// immediately. Default true; `false` leaves nodes on their old
    /// addresses until they reconnect on their own.
    #[serde(default = "default_true")]
    pub cycle: bool,
    /// Run even though devices sit below the version floor. Their mesh will
    /// black-hole at their next daemon start until they update.
    #[serde(default)]
    pub force: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct RenumberResponse {
    pub dry_run: bool,
    pub applied: bool,
    pub old_cidr: String,
    pub new_cidr: String,
    pub next_host: u32,
    /// Per-node old → new mapping.
    pub moves: Vec<NodeMove>,
    /// Nodes whose current address doesn't parse under the OLD cidr (leased
    /// under a since-changed range). They are re-based like the rest — listed
    /// separately because their ordinal could not be preserved.
    pub reseated: Vec<String>,
    /// Devices below the version floor (empty unless `force`).
    pub below_floor: Vec<DeviceVersion>,
    /// Agents whose WS this pod published a cycle for.
    pub cycled: Vec<String>,
    /// Nodes that must reconnect on their own for the new address to bind
    /// (tunnel clients — the server has no cycle primitive for them).
    pub reconnect_required: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct NodeMove {
    pub node_id: String,
    pub name: String,
    pub kind: &'static str,
    pub old_ip: String,
    pub new_ip: String,
    /// The ordinal was carried over rather than compacted.
    pub ordinal_preserved: bool,
}

// ---------------------------------------------------------------------------
// Pure planning (unit-tested below; no DB, no state)
// ---------------------------------------------------------------------------

/// One node's identity as far as the planner cares.
#[derive(Debug, Clone)]
pub struct PlanNode {
    pub id: ObjectId,
    pub name: String,
    pub kind: &'static str,
    pub ip: String,
}

#[derive(Debug)]
pub struct RenumberPlan {
    pub moves: Vec<NodeMove>,
    pub reseated: Vec<String>,
    pub next_host: u32,
}

/// Map every live node from `old_cidr` into `new_cidr`.
///
/// Ordinals are PRESERVED where they fit (`100.64.0.7` → `100.65.0.7`), which
/// keeps hand-written notes, `known_hosts` entries and dashboards readable
/// across the migration. An ordinal that doesn't fit the new block — or that
/// can't be recovered from the address at all — is COMPACTED onto the lowest
/// free one. Preservation runs as a first pass over the whole set so a
/// compacted node can never steal an ordinal a later node would have kept.
pub fn plan_renumber(
    nodes: &[PlanNode],
    old_cidr: &str,
    new_cidr: &str,
) -> Result<RenumberPlan, String> {
    let max_host = cidr_max_host(new_cidr)
        .ok_or_else(|| format!("{new_cidr} cannot lease any host addresses"))?;
    if nodes.len() as u64 > max_host as u64 {
        return Err(format!(
            "{} live nodes do not fit in {new_cidr} (capacity {max_host}); \
             renumber with a wider prefix",
            nodes.len()
        ));
    }

    // Pass 1 — who keeps their ordinal. Sorted by id so the plan is
    // deterministic (a dry-run must predict what the apply will do).
    let mut ordered: Vec<&PlanNode> = nodes.iter().collect();
    ordered.sort_by_key(|n| n.id);

    let mut taken: HashSet<u32> = HashSet::new();
    let mut keep: HashMap<ObjectId, u32> = HashMap::new();
    for n in &ordered {
        if let Some(h) = overlay_host(old_cidr, &n.ip)
            && h >= 1
            && h <= max_host
            && taken.insert(h)
        {
            keep.insert(n.id, h);
        }
    }

    // Pass 2 — everyone else takes the lowest free ordinal.
    let mut moves = Vec::with_capacity(ordered.len());
    let mut reseated = Vec::new();
    let mut cursor = 1u32;
    let mut highest = 0u32;
    for n in ordered {
        let (host, preserved) = match keep.get(&n.id) {
            Some(h) => (*h, true),
            None => {
                while cursor <= max_host && !taken.insert(cursor) {
                    cursor += 1;
                }
                if cursor > max_host {
                    return Err(format!("{new_cidr} exhausted while compacting"));
                }
                reseated.push(n.name.clone());
                (cursor, false)
            }
        };
        highest = highest.max(host);
        let new_ip = overlay_ip(new_cidr, host)
            .ok_or_else(|| format!("host {host} does not render inside {new_cidr}"))?;
        moves.push(NodeMove {
            node_id: n.id.to_hex(),
            name: n.name.clone(),
            kind: n.kind,
            old_ip: n.ip.clone(),
            new_ip,
            ordinal_preserved: preserved,
        });
    }

    Ok(RenumberPlan {
        moves,
        reseated,
        // The cursor resumes above the highest ordinal actually placed — the
        // gaps below it are recovered by the free pool, not by the cursor.
        next_host: highest.saturating_add(1).max(1),
    })
}

/// Parse a `MAJOR.MINOR.PATCH[-rc.N]` version into a comparable tuple.
/// A release (no `-rc`) sorts ABOVE every rc of the same version, which is
/// the usual semver pre-release rule.
fn parse_version(v: &str) -> Option<(u32, u32, u32, u32)> {
    let v = v.trim();
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    let rc = match pre {
        // `rc.238` / `rc238` — the fleet has only ever used the dotted form,
        // but tolerate both rather than mis-sorting a stray tag.
        Some(p) => {
            let digits: String = p.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                0
            } else {
                digits.parse().unwrap_or(0)
            }
        }
        // No pre-release ⇒ final, sorts above every rc.
        None => u32::MAX,
    };
    Some((major, minor, patch, rc))
}

/// Is `version` at or above `floor`?
///
/// An unparseable or EMPTY version fails closed (`false`): a device that has
/// never reported one is exactly the device most likely to be running
/// something ancient, and the cost of guessing wrong is a blackholed mesh.
pub fn version_meets_floor(version: &str, floor: &str) -> bool {
    let Some(f) = parse_version(floor) else {
        // A malformed FLOOR must not block every migration — treat the gate
        // as unconfigured rather than universally failing.
        return true;
    };
    parse_version(version).is_some_and(|v| v >= f)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /api/tenant/{tenant_id}/overlay-block — the tenant's address-block
/// posture: current range, usage, registry trail and fleet readiness.
pub async fn get_block(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<BlockStatusResponse>, ApiError> {
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

    let network = state.overlay_networks.get_or_create(tid).await?;
    let network_id = network
        .id
        .ok_or_else(|| ApiError::Internal("overlay network missing _id".into()))?;
    let nodes = state
        .overlay_nodes
        .list_active_in_network(tid, network_id)
        .await?;
    let versions = resolve_versions(&state, tid, &nodes).await;
    let floor = state.settings.overlay.block_version_floor.clone();
    let below_floor = versions
        .into_iter()
        .filter(|d| !version_meets_floor(&d.version, &floor))
        .collect();

    let blocks = state
        .overlay_networks
        .blocks()
        .list_for_tenant(tid)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|b| BlockRow {
            cidr: b.cidr,
            slot: b.slot,
            slots: b.slots,
            state: match b.state {
                meshharbor_remote_control::models::OverlayBlockState::Assigned => "assigned",
                meshharbor_remote_control::models::OverlayBlockState::Quarantined => "quarantined",
                meshharbor_remote_control::models::OverlayBlockState::Reclaimed => "reclaimed",
            }
            .to_string(),
            released_reason: b.released_reason,
        })
        .collect();

    Ok(Json(BlockStatusResponse {
        legacy: network.cidr == OverlayNetwork::DEFAULT_CIDR,
        capacity: network.max_host(),
        nodes: nodes.len() as u32,
        next_host: network.next_host,
        cidr: network.cidr,
        blocks,
        carving_enabled: state.overlay_networks.block_prefix().is_some(),
        version_floor: floor,
        below_floor,
        headroom: state.overlay_networks.blocks().headroom().await?,
    }))
}

/// Authorize a block operation on `tid`: a **platform operator**, or a tenant
/// admin holding `MANAGE_AGENTS`.
///
/// FR-47 — the platform arm was added because the routes around this one
/// already had it and this one did not, which made the block toolkit
/// unusable as a set: `POST /api/admin/overlay-block/reclaim` and
/// `…/reconcile-hosts` are platform-operator, so an operator could reclaim
/// ranges fleet-wide and return leaked ordinals, but could not migrate the
/// one tenant those operations exist to serve without first being made a
/// member of it.
///
/// ⚠️ This is **consistency, not escalation**, and the reasoning matters
/// before anyone widens it further. A platform operator already governs the
/// GLOBAL block registry through `reclaim` — a strictly more powerful
/// capability than renumbering a single tenant, since a mis-reclaimed range
/// can be re-issued to a *different* org. Granting the smaller power to the
/// same list closes a gap rather than opening one. It is emphatically not a
/// licence to route ordinary tenant operations through `platform_admins`.
///
/// The platform path is logged at WARN with the tenant it acted on: an
/// operator reaching into an org they are not a member of should leave a
/// trace, and a renumber is disruptive enough to want one.
async fn require_block_operator(
    state: &NetworkState,
    tid: ObjectId,
    user_id: ObjectId,
    op: &str,
) -> Result<(), ApiError> {
    if state.platform_admins.contains(&user_id) {
        warn!(
            admin = %user_id, tenant = %tid, %op,
            "overlay blocks: platform operator acting on a tenant"
        );
        return Ok(());
    }
    require_permission(
        state,
        tid,
        user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await
}

/// POST /api/tenant/{tenant_id}/overlay-block/renumber — plan (default) or
/// perform the tenant's migration onto its own block.
pub async fn renumber(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<RenumberRequest>,
) -> Result<Json<RenumberResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    require_block_operator(&state, tid, auth.user_id, "renumber").await?;

    let prefix = body.prefix.unwrap_or(state.settings.overlay.block_prefix);
    if !(OVERLAY_BLOCK_MIN_PREFIX..=OVERLAY_BLOCK_MAX_PREFIX).contains(&prefix) {
        return Err(ApiError::BadRequest(format!(
            "block prefix must be between /{OVERLAY_BLOCK_MIN_PREFIX} and \
             /{OVERLAY_BLOCK_MAX_PREFIX} (got /{prefix})"
        )));
    }

    let network = state.overlay_networks.get_or_create(tid).await?;
    let network_id = network
        .id
        .ok_or_else(|| ApiError::Internal("overlay network missing _id".into()))?;
    let nodes = state
        .overlay_nodes
        .list_active_in_network(tid, network_id)
        .await?;

    // --- Gate 1: the fleet version floor -----------------------------------
    let floor = state.settings.overlay.block_version_floor.clone();
    let below_floor: Vec<DeviceVersion> = resolve_versions(&state, tid, &nodes)
        .await
        .into_iter()
        .filter(|d| !version_meets_floor(&d.version, &floor))
        .collect();
    if !below_floor.is_empty() && !body.force && !body.dry_run {
        return Err(ApiError::BadRequest(format!(
            "{} device(s) are below the {floor} floor for tenant-block addressing \
             ({}). Their daemon purges its own on-link route at boot, which \
             black-holes that host's mesh. Update them, or re-send with \
             force=true to accept the breakage.",
            below_floor.len(),
            below_floor
                .iter()
                .map(|d| format!(
                    "{} @ {}",
                    d.name,
                    if d.version.is_empty() {
                        "unknown"
                    } else {
                        &d.version
                    }
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    // --- Plan --------------------------------------------------------------
    // Dry runs must not consume a block, so the plan is rendered against the
    // range the allocator WOULD hand out. The apply path re-allocates for
    // real — the two can differ if another tenant migrates in between, which
    // is why the response always echoes the cidr it actually used.
    let plan_nodes: Vec<PlanNode> = nodes
        .iter()
        .filter_map(|n| {
            Some(PlanNode {
                id: n.id?,
                name: n.name.clone(),
                kind: node_kind(n),
                ip: n.overlay_ip.clone(),
            })
        })
        .collect();

    let mut warnings = Vec::new();
    if body.dry_run {
        let preview = state
            .overlay_networks
            .blocks()
            .preview_next_cidr(prefix)
            .await
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
        let plan =
            plan_renumber(&plan_nodes, &network.cidr, &preview).map_err(ApiError::BadRequest)?;
        if !below_floor.is_empty() {
            warnings.push(format!(
                "{} device(s) below the {floor} floor — the apply will refuse \
                 unless force=true",
                below_floor.len()
            ));
        }
        warnings.push(
            "preview only: the block is allocated by the apply, so the actual \
             range can differ if another tenant migrates first"
                .to_string(),
        );
        return Ok(Json(RenumberResponse {
            dry_run: true,
            applied: false,
            old_cidr: network.cidr,
            new_cidr: preview,
            next_host: plan.next_host,
            moves: plan.moves,
            reseated: plan.reseated,
            below_floor,
            cycled: Vec::new(),
            reconnect_required: Vec::new(),
            warnings,
        }));
    }

    // --- Apply -------------------------------------------------------------
    // Quarantine BEFORE allocating: the registry's partial-unique index
    // allows one assigned block per network, and a block that is retired but
    // whose replacement failed is harmless (its slots simply stay out of
    // circulation) — whereas the reverse order cannot even be attempted.
    let old_block = state
        .overlay_networks
        .blocks()
        .find_assigned_for_network(network_id)
        .await?;
    if let Some(b) = &old_block
        && let Some(bid) = b.id
    {
        state
            .overlay_networks
            .blocks()
            .quarantine(bid, "renumber")
            .await?;
    }
    let block = state
        .overlay_networks
        .blocks()
        .allocate(tid, network_id, prefix, 0)
        .await?;
    let plan =
        plan_renumber(&plan_nodes, &network.cidr, &block.cidr).map_err(ApiError::BadRequest)?;

    // Node rows first, then the network. A crash between them leaves nodes on
    // the new addresses with the network still describing the old range: the
    // next join re-reads both and the operator can simply re-run the
    // renumber, whereas the reverse order would hand a joiner an address
    // inside a range whose live rows still sit outside it.
    for m in &plan.moves {
        let Ok(nid) = ObjectId::parse_str(&m.node_id) else {
            continue;
        };
        if let Err(e) = state
            .overlay_nodes
            .set_overlay_ip(nid, network_id, &m.new_ip)
            .await
        {
            warn!(%tid, node = %m.node_id, %e, "renumber: node address write failed");
            warnings.push(format!("{}: address write failed ({e})", m.name));
        }
    }
    state
        .overlay_networks
        .apply_renumber(network_id, &block.cidr, plan.next_host)
        .await?;
    info!(
        tenant = %tid, old = %network.cidr, new = %block.cidr, nodes = plan.moves.len(),
        "overlay renumber applied"
    );

    // --- Cycle -------------------------------------------------------------
    // A node's self_ip is bound once, when its overlay session establishes,
    // so the fleet keeps its OLD addresses until each socket re-establishes.
    let mut cycled = Vec::new();
    let mut reconnect_required = Vec::new();
    for n in &nodes {
        match n.node_ref {
            NodeRef::Agent { agent_id } => {
                if body.cycle {
                    // Local first (the common single-pod case), then the ctrl
                    // lane for whichever pod actually holds the socket.
                    state.fleet.rc_hub.cycle_agent_ws(agent_id);
                    meshharbor_mod_fleet::ctrl::publish_rc_ctrl(
                        &state,
                        "overlay_cycle",
                        serde_json::json!({ "agent_id": agent_id.to_hex() }),
                    )
                    .await;
                    cycled.push(n.name.clone());
                }
            }
            // The server has no cycle primitive for tunnel-client sockets
            // (they are not hub-registered), so those nodes pick the new
            // address up on their next reconnect.
            NodeRef::TunnelClient { .. } => reconnect_required.push(n.name.clone()),
        }
    }
    if !body.cycle {
        warnings.push(
            "cycle=false: nodes keep their OLD self_ip until they reconnect on \
             their own — peers will already have installed the new addresses"
                .to_string(),
        );
    }
    if !reconnect_required.is_empty() {
        warnings.push(format!(
            "{} tunnel-client node(s) must reconnect for the new address to bind",
            reconnect_required.len()
        ));
    }
    if !below_floor.is_empty() {
        warnings.push(format!(
            "forced over {} device(s) below the {floor} floor",
            below_floor.len()
        ));
    }

    Ok(Json(RenumberResponse {
        dry_run: false,
        applied: true,
        old_cidr: network.cidr,
        new_cidr: block.cidr,
        next_host: plan.next_host,
        moves: plan.moves,
        reseated: plan.reseated,
        below_floor,
        cycled,
        reconnect_required,
        warnings,
    }))
}

fn node_kind(n: &OverlayNode) -> &'static str {
    match n.node_ref {
        NodeRef::Agent { .. } => "agent",
        NodeRef::TunnelClient { .. } => "tunnel_client",
    }
}

/// Resolve each node's backing device version in two queries. A node whose
/// device row is gone is skipped: it can't rejoin, so it can't be broken by
/// the migration.
async fn resolve_versions(
    state: &NetworkState,
    tenant_id: ObjectId,
    nodes: &[OverlayNode],
) -> Vec<DeviceVersion> {
    let mut agent_ids = Vec::new();
    let mut client_ids = Vec::new();
    for n in nodes {
        match n.node_ref {
            NodeRef::Agent { agent_id } => agent_ids.push(agent_id),
            NodeRef::TunnelClient { tunnel_client_id } => client_ids.push(tunnel_client_id),
        }
    }
    let mut out = Vec::new();
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
        out.extend(rows.into_iter().map(|a| DeviceVersion {
            name: a.name,
            kind: "agent",
            version: a.agent_version,
            online: matches!(
                a.status,
                meshharbor_remote_control::models::AgentStatus::Online
            ),
        }));
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
        out.extend(rows.into_iter().map(|c| DeviceVersion {
            name: c.name,
            kind: "tunnel_client",
            version: c.client_version,
            online: matches!(
                c.status,
                meshharbor_remote_control::models::AgentStatus::Online
            ),
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u8, ip: &str) -> PlanNode {
        let mut raw = [0u8; 12];
        raw[11] = id;
        PlanNode {
            id: ObjectId::from_bytes(raw),
            name: format!("node-{id}"),
            kind: "agent",
            ip: ip.to_string(),
        }
    }

    #[test]
    fn ordinals_survive_the_move_when_they_fit() {
        let nodes = vec![
            node(1, "100.64.0.1"),
            node(2, "100.64.0.7"),
            node(3, "100.64.1.0"), // ordinal 256
        ];
        let plan = plan_renumber(&nodes, "100.64.0.0/10", "100.65.0.0/22").expect("plans");
        let ips: Vec<&str> = plan.moves.iter().map(|m| m.new_ip.as_str()).collect();
        assert_eq!(ips, vec!["100.65.0.1", "100.65.0.7", "100.65.1.0"]);
        assert!(plan.moves.iter().all(|m| m.ordinal_preserved));
        assert!(plan.reseated.is_empty());
        // The cursor resumes above the HIGHEST placed ordinal, not the count.
        assert_eq!(plan.next_host, 257);
    }

    #[test]
    fn ordinals_past_the_block_are_compacted() {
        let nodes = vec![
            node(1, "100.64.0.5"),  // fits
            node(2, "100.64.10.0"), // ordinal 2560 — past a /22
            node(3, "100.64.20.0"), // ordinal 5120 — past a /22
        ];
        let plan = plan_renumber(&nodes, "100.64.0.0/10", "100.65.0.0/22").expect("plans");
        assert_eq!(plan.moves[0].new_ip, "100.65.0.5");
        assert!(plan.moves[0].ordinal_preserved);
        // Compacted onto the lowest free ordinals — and NOT onto 5, which the
        // first node kept.
        assert_eq!(plan.moves[1].new_ip, "100.65.0.1");
        assert_eq!(plan.moves[2].new_ip, "100.65.0.2");
        assert!(!plan.moves[1].ordinal_preserved);
        assert_eq!(plan.reseated, vec!["node-2", "node-3"]);
    }

    /// The ordering trap: a node that must be compacted must never be handed
    /// an ordinal that a LATER node in the list is entitled to keep.
    #[test]
    fn compaction_never_steals_a_preserved_ordinal() {
        let nodes = vec![
            node(1, "100.64.99.0"), // compacted — sorts FIRST by id
            node(2, "100.64.0.1"),  // keeps ordinal 1
            node(3, "100.64.0.2"),  // keeps ordinal 2
        ];
        let plan = plan_renumber(&nodes, "100.64.0.0/10", "100.65.0.0/22").expect("plans");
        assert_eq!(
            plan.moves[0].new_ip, "100.65.0.3",
            "took the first FREE one"
        );
        assert_eq!(plan.moves[1].new_ip, "100.65.0.1");
        assert_eq!(plan.moves[2].new_ip, "100.65.0.2");
    }

    #[test]
    fn an_unparseable_address_is_reseated_not_dropped() {
        let nodes = vec![node(1, "10.9.9.9"), node(2, "100.64.0.4")];
        let plan = plan_renumber(&nodes, "100.64.0.0/10", "100.65.0.0/22").expect("plans");
        assert_eq!(plan.moves.len(), 2);
        assert_eq!(plan.moves[0].new_ip, "100.65.0.1");
        assert!(!plan.moves[0].ordinal_preserved);
        assert_eq!(plan.moves[1].new_ip, "100.65.0.4");
        assert_eq!(plan.reseated, vec!["node-1"]);
    }

    #[test]
    fn a_block_that_cannot_hold_the_fleet_is_refused() {
        // /22 leases 1022; ask it to hold 1023.
        let nodes: Vec<PlanNode> = (0..1023)
            .map(|i| PlanNode {
                id: ObjectId::from_bytes([
                    (i / 256) as u8,
                    (i % 256) as u8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]),
                name: format!("n{i}"),
                kind: "agent",
                ip: format!("100.64.{}.{}", i / 256, i % 256),
            })
            .collect();
        let err = plan_renumber(&nodes, "100.64.0.0/10", "100.65.0.0/22").unwrap_err();
        assert!(err.contains("do not fit"), "{err}");
        // …and a /20 takes them.
        assert!(plan_renumber(&nodes, "100.64.0.0/10", "100.65.0.0/20").is_ok());
    }

    #[test]
    fn plans_are_deterministic() {
        let nodes = vec![
            node(3, "100.64.7.7"),
            node(1, "100.64.0.1"),
            node(2, "10.0.0.1"),
        ];
        let a = plan_renumber(&nodes, "100.64.0.0/10", "100.65.0.0/22").expect("plans");
        let mut shuffled = nodes.clone();
        shuffled.reverse();
        let b = plan_renumber(&shuffled, "100.64.0.0/10", "100.65.0.0/22").expect("plans");
        assert_eq!(a.moves, b.moves, "input order must not change the plan");
    }

    #[test]
    fn version_floor_compares_rc_numbers_numerically() {
        let floor = "0.3.0-rc.301";
        assert!(version_meets_floor("0.3.0-rc.301", floor));
        assert!(version_meets_floor("0.3.0-rc.306", floor));
        // The trap a string compare falls into: "rc.99" > "rc.301" lexically.
        assert!(!version_meets_floor("0.3.0-rc.99", floor));
        assert!(!version_meets_floor("0.3.0-rc.300", floor));
        assert!(!version_meets_floor("0.2.9-rc.999", floor));
        assert!(version_meets_floor("0.4.0-rc.1", floor));
        // A final release outranks every rc of the same version.
        assert!(version_meets_floor("0.3.0", floor));
    }

    #[test]
    fn an_unknown_version_fails_closed() {
        let floor = "0.3.0-rc.301";
        assert!(!version_meets_floor("", floor));
        assert!(!version_meets_floor("dev", floor));
        assert!(!version_meets_floor("0.3", floor));
        // …but a broken FLOOR must not block every migration.
        assert!(version_meets_floor("0.1.0", "not-a-version"));
    }
}

// ── Reclaim (platform operator) ─────────────────────────────────────────

/// Default quarantine age before a range may be re-issued.
///
/// The risk quarantine protects against is a device that missed a renumber
/// and still believes it holds an address in the old range. Every agent
/// reconnects on a cadence of minutes and re-reads its netmap; a month is
/// several orders of magnitude past that, and covers a laptop that spent a
/// holiday in a drawer.
const DEFAULT_RECLAIM_MIN_AGE_DAYS: i64 = 30;

#[derive(Debug, Deserialize)]
pub struct ReclaimRequest {
    /// Plan only (the default). Nothing is reclaimed unless this is `false`.
    #[serde(default = "default_true")]
    pub dry_run: bool,
    /// Override the quarantine age requirement, in days.
    #[serde(default)]
    pub min_age_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ReclaimCandidate {
    pub cidr: String,
    pub slot: u32,
    pub slots: u32,
    pub tenant_id: String,
    pub quarantined_days: i64,
    /// Absent when the block is reclaimable; otherwise why it was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReclaimResponse {
    pub dry_run: bool,
    pub min_age_days: i64,
    /// Blocks reclaimed (or that would be, on a dry run).
    pub reclaimed: Vec<ReclaimCandidate>,
    /// Quarantined blocks that are NOT eligible, each with its reason.
    pub skipped: Vec<ReclaimCandidate>,
    pub headroom: meshharbor_services::dao::overlay_block::BlockHeadroom,
}

/// POST /api/admin/overlay-block/reclaim — return quarantined ranges to the
/// allocator. Platform operator only; dry-run by default.
///
/// Quarantine is permanent on purpose: a device that missed a renumber may
/// still believe it holds an address in the old range, and handing that
/// range to a different tenant is how two tenants end up sharing addresses.
/// With 4032 slots the cost of never re-issuing is nothing, so this exists
/// for the deployment that churns tenants hard enough to matter — and it is
/// deliberately unable to cause harm in the meantime, because a reclaimed
/// range is the allocator's EXHAUSTION FALLBACK, not its default. Normal
/// allocation stays strictly monotonic-upward.
///
/// Two conditions, both required:
/// * the block has been quarantined for at least `min_age_days`;
/// * no live overlay node anywhere holds an address inside it.
pub async fn reclaim(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Json(body): Json<ReclaimRequest>,
) -> Result<Json<ReclaimResponse>, ApiError> {
    if !state.platform_admins.contains(&auth.user_id) {
        return Err(ApiError::NotFound("Not found".to_string()));
    }
    let min_age_days = body.min_age_days.unwrap_or(DEFAULT_RECLAIM_MIN_AGE_DAYS);

    // Every live address in the fleet, once. The registry is global, so the
    // occupancy question is too.
    let live_ips = state.overlay_nodes.all_live_overlay_ips().await?;

    let now = bson::DateTime::now().timestamp_millis();
    let mut reclaimed = Vec::new();
    let mut skipped = Vec::new();

    for b in state
        .overlay_networks
        .blocks()
        .list_quarantined()
        .await
        .unwrap_or_default()
    {
        let released = b.released_at.map(|d| d.timestamp_millis());
        let days = released.map(|r| (now - r) / 86_400_000).unwrap_or(0);
        let mut row = ReclaimCandidate {
            cidr: b.cidr.clone(),
            slot: b.slot,
            slots: b.slots,
            tenant_id: b.tenant_id.to_hex(),
            quarantined_days: days,
            blocked_by: None,
        };

        // No `released_at` means an older row that predates the stamp; treat
        // it as too young rather than guessing it is ancient.
        if released.is_none() {
            row.blocked_by = Some("no released_at stamp; age unknown".into());
            skipped.push(row);
            continue;
        }
        if days < min_age_days {
            row.blocked_by = Some(format!("quarantined {days}d, needs {min_age_days}d"));
            skipped.push(row);
            continue;
        }
        if let Some(ip) = live_ips.iter().find(|ip| cidr_contains(&b.cidr, ip)) {
            row.blocked_by = Some(format!("a live node still holds {ip}"));
            skipped.push(row);
            continue;
        }

        if !body.dry_run
            && let Some(id) = b.id
        {
            let ok = state
                .overlay_networks
                .blocks()
                .reclaim(id, "operator reclaim")
                .await
                .unwrap_or(false);
            if !ok {
                row.blocked_by = Some("state changed under us; not reclaimed".into());
                skipped.push(row);
                continue;
            }
        }
        reclaimed.push(row);
    }

    if !body.dry_run && !reclaimed.is_empty() {
        tracing::warn!(
            admin = %auth.user_id, count = reclaimed.len(), min_age_days,
            "overlay blocks: operator reclaimed quarantined ranges"
        );
    }

    Ok(Json(ReclaimResponse {
        dry_run: body.dry_run,
        min_age_days,
        reclaimed,
        skipped,
        headroom: state.overlay_networks.blocks().headroom().await?,
    }))
}

/// Is `ip` inside `cidr`? IPv4 only — overlay v6 is derived from the v4
/// address, so v4 containment already answers for both.
fn cidr_contains(cidr: &str, ip: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    let (Ok(base), Ok(ip)) = (
        base.parse::<std::net::Ipv4Addr>(),
        ip.parse::<std::net::Ipv4Addr>(),
    ) else {
        return false;
    };
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = !0u32 << (32 - u32::from(prefix));
    (u32::from(base) & mask) == (u32::from(ip) & mask)
}

// ---------------------------------------------------------------------------
// FR-47 P3 — host-ordinal reconciliation
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct ReconcileHostsRequest {
    /// Plan only (the default). Nothing is released unless this is `false`.
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct ReconcileHostsResponse {
    pub dry_run: bool,
    pub cidr: String,
    /// The IPAM cursor: ordinals `1..next_host` have been issued at some point.
    pub next_host: u32,
    /// Ordinals a live node currently holds.
    pub live: u32,
    /// Ordinals already sitting in the recycle pool.
    pub pooled: u32,
    /// Issued ordinals held by nothing and pooled by nothing — the leak.
    pub orphaned: Vec<u32>,
    /// Orphans actually returned to the pool (empty on a dry run).
    pub released: Vec<u32>,
    /// Orphans `release_host` declined, with the count. A refusal is not an
    /// error: the guards exist precisely so this path cannot corrupt the pool.
    pub refused: usize,
}

/// Issued ordinals that belong to no live node and are not already pooled.
///
/// Pure so it can be tested: the range is half-open (`next_host` is the NEXT
/// one to hand out, never itself issued) and host 0 is the network address,
/// which the allocator never leases. Both bounds are off-by-one bait, and a
/// mistake at either end is destructive here rather than merely wrong — an
/// over-eager orphan list would release an ordinal a live node is using and
/// hand two devices the same address.
fn orphaned_ordinals(
    next_host: u32,
    live: &std::collections::HashSet<u32>,
    pooled: &std::collections::HashSet<u32>,
) -> Vec<u32> {
    (1..next_host)
        .filter(|h| !live.contains(h) && !pooled.contains(h))
        .collect()
}

/// POST /api/tenant/{tenant_id}/overlay-block/reconcile-hosts — return leaked
/// host ordinals to the tenant's recycle pool. Platform operator only;
/// dry-run by default.
///
/// The leak is real and measurable: on production 2026-08-31 the oldest carved
/// network had issued 35 ordinals, of which 17 were held by live nodes and 1
/// sat in `free_hosts` — the other ~17 belonged to no document at all. They
/// were released before the recycle pool existed, so there was nothing to
/// return them to, and no eviction path can reach them because they are not
/// attached to a row anyone can delete.
///
/// ⚠️ Every orphan goes back through [`OverlayNetworkDao::release_host`] and
/// never by writing `free_hosts` directly. That is the whole design of this
/// route. `release_host` carries three guards — `$addToSet` against a double
/// release, `next_host > host` against an ordinal the cursor never issued, and
/// the `MAX_FREE_HOSTS` size cap — and a reconcile that bypassed them to
/// "fix" bookkeeping could hand two live nodes the same address, which is
/// strictly worse than the leak it set out to repair.
///
/// ⚠️ Running this twice, a month apart, answers a question nothing else can:
/// whether the leak is purely historical (pre-2026-07-29 releases) or whether
/// a live path is still dropping ordinals.
pub async fn reconcile_hosts(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<ReconcileHostsRequest>,
) -> Result<Json<ReconcileHostsResponse>, ApiError> {
    if !state.platform_admins.contains(&auth.user_id) {
        return Err(ApiError::NotFound("Not found".to_string()));
    }
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("bad tenant id".to_string()))?;
    let network = state.overlay_networks.get_or_create(tid).await?;
    let network_id = network
        .id
        .ok_or_else(|| ApiError::Internal("overlay network has no id".to_string()))?;

    // Ordinals a live node holds. A node whose address does not invert under
    // the CURRENT cidr is skipped rather than guessed at: it was leased under
    // a since-changed range, and inventing an ordinal for it could release one
    // that a different node legitimately holds.
    let nodes = state
        .overlay_nodes
        .list_active_in_network(tid, network_id)
        .await?;
    let live: std::collections::HashSet<u32> = nodes
        .iter()
        .filter_map(|n| overlay_host(&network.cidr, &n.overlay_ip))
        .collect();
    let pooled: std::collections::HashSet<u32> = network.free_hosts.iter().copied().collect();

    let orphaned = orphaned_ordinals(network.next_host, &live, &pooled);

    let mut released = Vec::new();
    let mut refused = 0usize;
    if !body.dry_run {
        for h in &orphaned {
            match state.overlay_networks.release_host(network_id, *h).await {
                Ok(true) => released.push(*h),
                // Declined by a guard, or the pool is full. Neither is an
                // error — the ordinal simply stays leaked, exactly as before.
                Ok(false) => refused += 1,
                Err(e) => {
                    tracing::warn!(%network_id, host = h, %e, "reconcile-hosts: release failed");
                    refused += 1;
                }
            }
        }
        tracing::warn!(
            admin = %auth.user_id, %tenant_id, cidr = %network.cidr,
            released = released.len(), refused,
            "overlay ipam: operator reconciled leaked host ordinals"
        );
    }

    Ok(Json(ReconcileHostsResponse {
        dry_run: body.dry_run,
        cidr: network.cidr,
        next_host: network.next_host,
        live: live.len() as u32,
        pooled: pooled.len() as u32,
        orphaned,
        released,
        refused,
    }))
}

#[cfg(test)]
mod reclaim_tests {
    use super::cidr_contains;

    #[test]
    fn containment_decides_whether_a_range_is_still_occupied() {
        assert!(cidr_contains("100.65.0.0/22", "100.65.0.5"));
        assert!(cidr_contains("100.65.0.0/22", "100.65.3.255"));
        // Just outside the /22 — the next block's first address.
        assert!(!cidr_contains("100.65.0.0/22", "100.65.4.0"));
        assert!(!cidr_contains("100.65.0.0/22", "100.64.0.28"));
        // The legacy range contains every carved block, which is why a
        // legacy tenant's nodes block reclaiming anything nested in it.
        assert!(cidr_contains("100.64.0.0/10", "100.65.0.5"));
        // Junk must never read as "contained" — that would let a reclaim
        // proceed against a range something still occupies.
        assert!(!cidr_contains("not-a-cidr", "100.65.0.5"));
        assert!(!cidr_contains("100.65.0.0/22", "::1"));
        assert!(!cidr_contains("100.65.0.0/99", "100.65.0.5"));
    }
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;

    fn set(v: &[u32]) -> HashSet<u32> {
        v.iter().copied().collect()
    }

    /// The production shape this route was written for: the oldest carved
    /// network had issued 35 ordinals, 17 held by live nodes and 1 pooled.
    #[test]
    fn orphans_are_the_issued_ordinals_nothing_holds() {
        let live = set(&[1, 2, 3]);
        let pooled = set(&[5]);
        // Issued 1..=6 (cursor at 7): 4 and 6 belong to nothing.
        assert_eq!(orphaned_ordinals(7, &live, &pooled), vec![4, 6]);
    }

    /// Both bounds are off-by-one bait, and being wrong here releases an
    /// address a live node is using.
    #[test]
    fn the_cursor_itself_was_never_issued_and_host_zero_is_the_network() {
        let empty = set(&[]);
        // Cursor at 3 ⇒ only 1 and 2 were ever handed out. 3 must NOT appear.
        assert_eq!(orphaned_ordinals(3, &empty, &empty), vec![1, 2]);
        // A virgin network has issued nothing at all.
        assert!(orphaned_ordinals(1, &empty, &empty).is_empty());
        assert!(orphaned_ordinals(0, &empty, &empty).is_empty());
        // Host 0 is the network address and is never a candidate.
        assert!(!orphaned_ordinals(9, &empty, &empty).contains(&0));
    }

    /// A fully-accounted network reports no work, which is what a SECOND run
    /// a month later should say if the leak really was historical.
    #[test]
    fn a_reconciled_network_has_nothing_left_to_reclaim() {
        let live = set(&[1, 3]);
        let pooled = set(&[2, 4]);
        assert!(orphaned_ordinals(5, &live, &pooled).is_empty());
    }
}

// ---------------------------------------------------------------------------
// FR-54 — orphaned overlay networks (a tenant that vanished)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct OrphanRequest {
    /// Plan only (the default). Nothing is released unless this is `false`.
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct OrphanNode {
    pub name: String,
    pub overlay_ip: String,
    pub kind: &'static str,
    /// The backing agent's reported version, when there is still an agent row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OrphanNetwork {
    pub tenant_id: String,
    pub cidr: String,
    pub network_id: String,
    /// Live nodes still attached to a network whose org no longer exists.
    pub nodes: Vec<OrphanNode>,
    /// The newest `updated_at` across those nodes — how stale this is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_node_write: Option<String>,
    /// Nodes actually released (empty on a dry run).
    pub released: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct OrphanResponse {
    pub dry_run: bool,
    /// Networks scanned.
    pub networks: u32,
    /// Networks whose tenant row does not exist.
    pub orphans: Vec<OrphanNetwork>,
}

/// POST /api/admin/overlay-network/orphans — find overlay networks whose
/// organization no longer exists. Platform operator only; dry-run by default.
///
/// FR-54. Found on production 2026-08-31 during the FR-47 audit: a tenant row
/// was gone while its network, 2 nodes and 2 agents lived on — holding
/// `100.64.0.1` and `.2`, the same addresses a LIVE org's first two devices
/// held. The collision FR-47 opened on was caused by an orphan nobody could
/// see. Nothing in the system notices this today.
///
/// ⚠️ There is no tenant-delete code path — `roles` and `rooms` have deletes,
/// the tenant DAO has only `set_archived` — so an orphan means somebody edited
/// MongoDB by hand. This route exists to make that DETECTABLE, not supported:
/// it deliberately does not offer to delete a tenant.
///
/// ⚠️ An ARCHIVED org is not an orphan. Its tenant row exists, it is simply
/// retired, and offering to release a live org's mesh because someone archived
/// it would be a far worse bug than the one this fixes. The test asserts it.
///
/// Applying releases each node through
/// [`crate::overlay::release_overlay_node`] — never by deleting rows —
/// because that path tombstones under a CAS, pools the host ordinal, and fans
/// `netmap_delta{removes}` to peers. Bypassing it to tidy up would be the same
/// class of act that created the mess.
pub async fn orphans(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Json(body): Json<OrphanRequest>,
) -> Result<Json<OrphanResponse>, ApiError> {
    if !state.platform_admins.contains(&auth.user_id) {
        return Err(ApiError::NotFound("Not found".to_string()));
    }

    let networks = state.overlay_networks.base.find_many(doc! {}, None).await?;
    let scanned = networks.len() as u32;
    let mut orphans = Vec::new();

    for net in networks {
        let Some(network_id) = net.id else { continue };
        // The ONLY test for an orphan: does the tenant row exist? Archived
        // tenants have a row and are deliberately not orphans.
        if state.tenants.base.find_by_id(net.tenant_id).await.is_ok() {
            continue;
        }

        let nodes = state
            .overlay_nodes
            .list_active_in_network(net.tenant_id, network_id)
            .await
            .unwrap_or_default();

        let mut rows = Vec::new();
        let mut newest: Option<bson::DateTime> = None;
        for n in &nodes {
            let agent_version = match &n.node_ref {
                NodeRef::Agent { agent_id } => state
                    .fleet
                    .agents
                    .base
                    .find_by_id(*agent_id)
                    .await
                    .ok()
                    .map(|a| a.agent_version),
                _ => None,
            };
            rows.push(OrphanNode {
                name: n.name.clone(),
                overlay_ip: n.overlay_ip.clone(),
                kind: match n.node_ref {
                    NodeRef::Agent { .. } => "agent",
                    _ => "tunnel-client",
                },
                agent_version,
            });
            newest = Some(newest.map_or(n.updated_at, |c| c.max(n.updated_at)));
        }

        let mut released = Vec::new();
        if !body.dry_run {
            for n in &nodes {
                if crate::overlay::release_overlay_node(
                    &state,
                    n,
                    "orphaned network: the tenant row no longer exists (FR-54)",
                )
                .await
                .is_some()
                {
                    released.push(n.name.clone());
                }
            }
            warn!(
                admin = %auth.user_id, tenant = %net.tenant_id, cidr = %net.cidr,
                released = released.len(),
                "overlay: operator released an orphaned network's nodes"
            );
        }

        orphans.push(OrphanNetwork {
            tenant_id: net.tenant_id.to_hex(),
            cidr: net.cidr.clone(),
            network_id: network_id.to_hex(),
            nodes: rows,
            last_node_write: newest.map(|d| d.try_to_rfc3339_string().unwrap_or_default()),
            released,
        });
    }

    Ok(Json(OrphanResponse {
        dry_run: body.dry_run,
        networks: scanned,
        orphans,
    }))
}
