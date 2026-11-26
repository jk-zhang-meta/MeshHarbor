// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — HTTP routes for GPU fleet, history, users, alert rules, and bot channels.

use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, doc, oid::ObjectId};
use futures::TryStreamExt as _;
use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::gpu::{
    GpuFreshness, GpuHostStatus, GpuInventory, GpuProc, GpuSample, GpuState, HostLoad, ProcsState,
    classify_gpu_state, compute_freshness,
};
use meshharbor_remote_control::models::{Agent, RpcCap};
use serde::{Deserialize, Serialize};

use super::alerts::{GpuAlertRule, RULES_COLLECTION};
use super::bots::{
    BotAlertItem, BotKind, ChannelView, GpuAlertChannel, resolve_and_validate_public, send_once,
    validate_channel_url,
};
use super::{GpuSnapshotDoc, history, load_rule, load_snapshots};
use crate::FleetState;

fn ensure_enabled(state: &FleetState) -> Result<(), ApiError> {
    if state.gpu.settings.enabled {
        Ok(())
    } else {
        Err(ApiError::NotFound("GPU monitoring is disabled".to_string()))
    }
}

fn parse_oid(raw: &str, label: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(raw).map_err(|_| ApiError::BadRequest(format!("Invalid {label}")))
}

// ─── Mark / unmark GPU server ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SetGpuServerBody {
    pub gpu_server: bool,
}

#[derive(Debug, Serialize)]
pub struct SetGpuServerResponse {
    pub agent_id: String,
    pub gpu_server: bool,
}

/// `PUT /api/tenant/{tenant_id}/agent/{agent_id}/gpu-server` — mark or unmark
/// a permanent OR invited/temporary device as a GPU server (`MANAGE_AGENTS`).
pub async fn set_gpu_server(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<SetGpuServerBody>,
) -> Result<Json<SetGpuServerResponse>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    let aid = parse_oid(&agent_id, "agent_id")?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    let agent = state.agents.find_live_in_tenant(tid, aid).await?;
    state
        .agents
        .set_gpu_server(tid, aid, body.gpu_server)
        .await?;
    state.gpu.on_gpu_server_toggled(
        &state.rc_hub,
        aid,
        body.gpu_server,
        agent.capabilities.has_rpc(RpcCap::Gpu),
    );
    tracing::info!(
        tenant = %tid,
        admin = %auth.user_id,
        agent = %aid,
        gpu_server = body.gpu_server,
        "fr-139: gpu_server mark updated"
    );
    Ok(Json(SetGpuServerResponse {
        agent_id: aid.to_hex(),
        gpu_server: body.gpu_server,
    }))
}

// ─── Fleet response shapes (shared with `/api/agent/self/gpu/fleet`) ────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuCardFleetView {
    pub uuid: String,
    pub idx: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: GpuState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used_mb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub util_pct: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temp_c: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power_w: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power_limit_w: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fan_pct: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sm_clock_mhz: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttle: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_uncorrected: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remapped_rows: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xid_errors: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mig: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lost: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pci_bus: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_since: Option<i64>,
    pub procs_state: ProcsState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub procs: Option<Vec<GpuProc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuHostFleetView {
    pub agent_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub os: String,
    /// `"org"` | `"invited"` | `"shared"` — tells the UI/CLI whether this host
    /// is an org device, a temporary invited GPU server, or a shared device.
    pub source: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
    pub is_online: bool,
    pub freshness: GpuFreshness,
    pub status: GpuHostStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at_ms: Option<i64>,
    pub interval_ms: u32,
    pub free_count: usize,
    pub busy_count: usize,
    pub held_idle_count: usize,
    pub total_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostLoad>,
    pub gpus: Vec<GpuCardFleetView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory: Option<GpuInventory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuFleetResponse {
    pub hosts: Vec<GpuHostFleetView>,
    pub summary: GpuFleetSummary,
    pub server_time_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuFleetSummary {
    pub hosts_total: usize,
    pub hosts_online: usize,
    pub gpus_total: usize,
    pub gpus_free: usize,
    pub gpus_busy: usize,
    pub gpus_held_idle: usize,
    pub gpus_fault: usize,
}

#[derive(Debug, Deserialize, Default)]
pub struct FleetQuery {
    #[serde(default)]
    pub live: Option<String>,
    #[serde(default)]
    pub hosts: Option<String>,
}

fn parse_live(raw: Option<&str>) -> bool {
    matches!(
        raw.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes")
    )
}

fn parse_host_filter(raw: Option<&str>) -> HashSet<String> {
    raw.unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn matches_host_filter(agent: &Agent, filter: &HashSet<String>) -> bool {
    if filter.is_empty() {
        return true;
    }
    if let Some(id) = agent.id
        && filter.contains(&id.to_hex().to_ascii_lowercase())
    {
        return true;
    }
    if filter.contains(&agent.name.to_ascii_lowercase()) {
        return true;
    }
    if let Some(dn) = agent.display_name.as_deref()
        && filter.contains(&dn.to_ascii_lowercase())
    {
        return true;
    }
    false
}

/// Project a list of `(Agent, source, read_only)` into a [`GpuFleetResponse`],
/// optionally granting live leases and waiting up to `wait_ms` for fresh reports.
pub async fn build_fleet_response(
    state: &FleetState,
    entries: Vec<(Agent, &'static str, bool)>,
    live: bool,
    wait_ms: u32,
    include_inventory: bool,
) -> GpuFleetResponse {
    let agents_only: Vec<Agent> = entries.iter().map(|(a, _, _)| a.clone()).collect();
    let fresh_presence = crate::agent::agent_presence_batch(state, &agents_only).await;

    if live {
        let lease_targets: Vec<(ObjectId, bool)> = entries
            .iter()
            .filter_map(|(a, _, _)| a.id.map(|id| (id, a.capabilities.has_rpc(RpcCap::Gpu))))
            .collect();
        state.gpu.request_live_leases(&state.rc_hub, &lease_targets);

        if wait_ms > 0 {
            let online_targets: Vec<ObjectId> = lease_targets
                .iter()
                .filter(|(id, sup)| *sup && state.rc_hub.is_agent_online(*id))
                .map(|(id, _)| *id)
                .collect();
            state.gpu.wait_for_fresh(&online_targets, wait_ms).await;
        }
    }

    let ids: Vec<ObjectId> = entries.iter().filter_map(|(a, _, _)| a.id).collect();
    let snapshots = load_snapshots(&state.core.db, &ids).await;

    let now_ms = chrono::Utc::now().timestamp_millis();
    let now_s = now_ms / 1000;
    let thresholds = state.gpu.thresholds();

    let mut hosts = Vec::with_capacity(entries.len());
    let mut sum = GpuFleetSummary {
        hosts_total: 0,
        hosts_online: 0,
        gpus_total: 0,
        gpus_free: 0,
        gpus_busy: 0,
        gpus_held_idle: 0,
        gpus_fault: 0,
    };

    for (agent, source, read_only) in entries {
        let Some(aid) = agent.id else { continue };
        let redis_fresh = fresh_presence.contains(&aid);
        let (_, is_online) = crate::agent::derive_agent_presence(state, &agent, redis_fresh);
        let snap = snapshots.get(&aid);
        let view = project_host_view(
            &agent,
            source,
            read_only,
            is_online,
            snap,
            now_s,
            thresholds,
            include_inventory,
        );
        sum.hosts_total += 1;
        if view.is_online {
            sum.hosts_online += 1;
        }
        sum.gpus_total += view.total_count;
        sum.gpus_free += view.free_count;
        sum.gpus_busy += view.busy_count;
        sum.gpus_held_idle += view.held_idle_count;
        let has_fault = !matches!(
            view.status,
            GpuHostStatus::Ok | GpuHostStatus::NoGpu | GpuHostStatus::Limited
        ) || view
            .gpus
            .iter()
            .any(|g| g.lost || g.xid_errors.as_ref().is_some_and(|x| !x.is_empty()));
        if has_fault {
            sum.gpus_fault += 1;
        }
        hosts.push(view);
    }

    hosts.sort_by(|a, b| a.name.cmp(&b.name));
    GpuFleetResponse {
        hosts,
        summary: sum,
        server_time_ms: now_ms,
    }
}

#[allow(clippy::too_many_arguments)]
fn project_host_view(
    agent: &Agent,
    source: &'static str,
    read_only: bool,
    is_online: bool,
    snap: Option<&GpuSnapshotDoc>,
    now_s: i64,
    thresholds: meshharbor_remote_control::gpu::GpuStateThresholds,
    include_inventory: bool,
) -> GpuHostFleetView {
    let interval_ms = snap.map(|s| s.report.interval_ms).unwrap_or(30_000);
    let recv_s = snap.map(|s| s.received_at.timestamp_millis() / 1000);
    let freshness = compute_freshness(is_online, recv_s, now_s, interval_ms);

    let (status, backend, driver_version, host, gpus) = match snap {
        Some(s) => {
            let cards: Vec<GpuCardFleetView> = s
                .report
                .gpus
                .iter()
                .map(|g| card_from_sample(s.report.status, g, now_s, thresholds))
                .collect();
            (
                s.report.status,
                s.report.backend.clone(),
                s.report.driver_version.clone(),
                Some(s.report.host.clone()),
                cards,
            )
        }
        None => {
            let inv = agent.gpu_inventory.as_ref();
            let cards: Vec<GpuCardFleetView> = inv
                .map(|i| {
                    i.gpus
                        .iter()
                        .map(|g| GpuCardFleetView {
                            uuid: g.uuid.clone(),
                            idx: g.idx,
                            name: Some(g.name.clone()),
                            state: GpuState::Unknown,
                            mem_used_mb: None,
                            mem_total_mb: g.mem_total_mb,
                            util_pct: None,
                            temp_c: None,
                            power_w: None,
                            power_limit_w: g.power_limit_w,
                            fan_pct: None,
                            sm_clock_mhz: None,
                            throttle: None,
                            ecc_uncorrected: None,
                            remapped_rows: None,
                            xid_errors: None,
                            mig: g.mig,
                            lost: false,
                            unified: g.unified,
                            pci_bus: g.pci_bus.clone(),
                            idle_since: None,
                            procs_state: ProcsState::Unknown,
                            procs: None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            (
                inv.map(|i| i.status).unwrap_or(GpuHostStatus::Unknown),
                inv.and_then(|i| i.backend.clone()),
                inv.and_then(|i| i.driver_version.clone()),
                None,
                cards,
            )
        }
    };

    let free_count = gpus.iter().filter(|g| g.state == GpuState::Free).count();
    let busy_count = gpus
        .iter()
        .filter(|g| matches!(g.state, GpuState::Busy | GpuState::Unattributed))
        .count();
    let held_idle_count = gpus
        .iter()
        .filter(|g| g.state == GpuState::HeldIdle)
        .count();
    let total_count = gpus.len();

    GpuHostFleetView {
        agent_id: agent.id.map(|i| i.to_hex()).unwrap_or_default(),
        name: agent.name.clone(),
        display_name: agent.display_name.clone(),
        os: format!("{:?}", agent.os).to_ascii_lowercase(),
        source: source.to_string(),
        read_only,
        is_online,
        freshness,
        status,
        backend,
        driver_version,
        received_at_ms: snap.map(|s| s.received_at.timestamp_millis()),
        interval_ms,
        free_count,
        busy_count,
        held_idle_count,
        total_count,
        host,
        gpus,
        inventory: include_inventory.then(|| agent.gpu_inventory.clone()).flatten(),
    }
}

fn card_from_sample(
    host_status: GpuHostStatus,
    g: &GpuSample,
    now_s: i64,
    thresholds: meshharbor_remote_control::gpu::GpuStateThresholds,
) -> GpuCardFleetView {
    GpuCardFleetView {
        uuid: g.uuid.clone(),
        idx: g.idx,
        name: g.name.clone(),
        state: classify_gpu_state(host_status, g, now_s, thresholds),
        mem_used_mb: g.mem_used_mb,
        mem_total_mb: g.mem_total_mb,
        util_pct: g.util_pct,
        temp_c: g.temp_c,
        power_w: g.power_w,
        power_limit_w: g.power_limit_w,
        fan_pct: g.fan_pct,
        sm_clock_mhz: g.sm_clock_mhz,
        throttle: g.throttle.clone(),
        ecc_uncorrected: g.ecc_uncorrected,
        remapped_rows: g.remapped_rows,
        xid_errors: g.xid_errors.clone(),
        mig: g.mig,
        lost: g.lost,
        unified: g.unified,
        pci_bus: g.pci_bus.clone(),
        idle_since: g.idle_since,
        procs_state: g.procs_state,
        procs: g.procs.clone(),
    }
}

/// Collect all GPU servers visible to `user_id` inside `tid`:
/// - Org's marked permanent GPU servers (`source = "org"`)
/// - Org's marked temporary/invited GPU servers authorized for `user_id` (`source = "invited"`)
/// - Active received `DeviceShareGrant` GPU servers for `user_id` (`source = "shared"`, `read_only = true`)
async fn visible_tenant_and_shared_gpu_agents(
    state: &FleetState,
    tid: ObjectId,
    user_id: ObjectId,
) -> Result<Vec<(Agent, &'static str, bool)>, ApiError> {
    let perms = state.tenants.get_member_permissions(tid, user_id).await?;
    let is_admin = permissions::has(perms, permissions::MANAGE_AGENTS);
    let member_roles: Vec<ObjectId> = state
        .tenants
        .member_role_ids(tid, user_id)
        .await
        .unwrap_or_default();

    let org_gpu_agents = state.agents.list_gpu_servers_in_tenant(tid).await?;
    let temp_ids = crate::device_invite::temporary_agent_ids_in_tenant(state, tid).await?;

    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut entries: Vec<(Agent, &'static str, bool)> = Vec::new();

    for agent in org_gpu_agents {
        let Some(aid) = agent.id else { continue };
        if temp_ids.contains(&aid) {
            let allowed = if is_admin {
                true
            } else {
                crate::device_invite::grant_for_agent(state, aid)
                    .await?
                    .is_some_and(|g| g.allows(Some(user_id), &member_roles))
            };
            if allowed && seen.insert(aid) {
                entries.push((agent, "invited", false));
            }
        } else if seen.insert(aid) {
            entries.push((agent, "org", false));
        }
    }

    // Active received DeviceShareGrants pointing to live `gpu_server = true` devices.
    if meshharbor_core::device_share::require_enabled(&state.core).is_ok() {
        let now = DateTime::now();
        if let Ok(mut cur) = state
            .core
            .db
            .collection::<bson::Document>("device_shares")
            .find(doc! {
                "recipient_user_id": user_id,
                "revoked_at": null,
                "expires_at": { "$gt": now },
            })
            .await
        {
            let mut shared_ids: Vec<ObjectId> = Vec::new();
            while let Ok(Some(d)) = cur.try_next().await {
                if let Ok(did) = d.get_object_id("device_id")
                    && !seen.contains(&did)
                {
                    shared_ids.push(did);
                }
            }
            if !shared_ids.is_empty()
                && let Ok(shared_agents) = state.agents.base.find_by_ids(&shared_ids).await
            {
                for a in shared_agents {
                    if a.deleted_at.is_none()
                        && a.gpu_server
                        && let Some(aid) = a.id
                        && seen.insert(aid)
                    {
                        entries.push((a, "shared", true));
                    }
                }
            }
        }
    }

    Ok(entries)
}

/// `GET /api/tenant/{tenant_id}/gpu/fleet?live=0|1&hosts=`
pub async fn get_fleet(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(query): Query<FleetQuery>,
) -> Result<Json<GpuFleetResponse>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    let filter = parse_host_filter(query.hosts.as_deref());
    let live = parse_live(query.live.as_deref());

    let entries: Vec<_> = visible_tenant_and_shared_gpu_agents(&state, tid, auth.user_id)
        .await?
        .into_iter()
        .filter(|(a, _, _)| matches_host_filter(a, &filter))
        .collect();

    Ok(Json(build_fleet_response(&state, entries, live, 0, false).await))
}

/// `GET /api/tenant/{tenant_id}/gpu/fleet/{agent_id}` — one GPU host in full + inventory.
pub async fn get_fleet_host(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Query(query): Query<FleetQuery>,
) -> Result<Json<GpuHostFleetView>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    let aid = parse_oid(&agent_id, "agent_id")?;
    let live = parse_live(query.live.as_deref());

    let visible = visible_tenant_and_shared_gpu_agents(&state, tid, auth.user_id).await?;
    let found = visible
        .into_iter()
        .find(|(a, _, _)| a.id == Some(aid))
        .ok_or_else(|| ApiError::NotFound("GPU server not found".to_string()))?;

    let mut resp = build_fleet_response(&state, vec![found], live, 0, true).await;
    resp.hosts
        .pop()
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("GPU server not found".to_string()))
}

// ─── History & Per-user GPU·h ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub agent_id: String,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub range: Option<String>,
}

/// `GET /api/tenant/{tenant_id}/gpu/history?agent_id=&uuid=&range=1h|24h|7d|30d`
pub async fn get_history(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    let aid = parse_oid(&query.agent_id, "agent_id")?;
    let range = query.range.as_deref().unwrap_or("24h");

    // Verify caller can see this GPU server (org, authorized invite, or active share).
    let visible = visible_tenant_and_shared_gpu_agents(&state, tid, auth.user_id).await?;
    let (target_agent, _, _) = visible
        .into_iter()
        .find(|(a, _, _)| a.id == Some(aid))
        .ok_or_else(|| ApiError::NotFound("GPU server not found".to_string()))?;

    let points = history::query_history(
        &state.core.db,
        target_agent.tenant_id,
        aid,
        query.uuid.as_deref(),
        range,
    )
    .await
    .map_err(|e| ApiError::Internal(format!("GPU history query failed: {e}")))?;

    Ok(Json(serde_json::json!({
        "agent_id": aid.to_hex(),
        "uuid": query.uuid,
        "range": range,
        "points": points,
    })))
}

#[derive(Debug, Deserialize, Default)]
pub struct UsersQuery {
    #[serde(default)]
    pub range: Option<String>,
}

/// `GET /api/tenant/{tenant_id}/gpu/users?range=24h|7d|30d`
pub async fn get_users(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(query): Query<UsersQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    let range = query.range.as_deref().unwrap_or("24h");

    let entries = visible_tenant_and_shared_gpu_agents(&state, tid, auth.user_id).await?;
    let mut visible_map: HashMap<ObjectId, String> = HashMap::new();
    for (a, _, _) in &entries {
        if let Some(id) = a.id {
            visible_map.insert(
                id,
                a.display_name
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| a.name.clone()),
            );
        }
    }
    let ids: Vec<ObjectId> = visible_map.keys().copied().collect();
    let snaps = load_snapshots(&state.core.db, &ids).await;
    let live_reports: HashMap<ObjectId, meshharbor_remote_control::gpu::GpuReport> = snaps
        .into_iter()
        .map(|(k, v)| (k, v.report))
        .collect();

    let users = history::query_users(&state.core.db, tid, &visible_map, range, &live_reports)
        .await
        .map_err(|e| ApiError::Internal(format!("GPU users query failed: {e}")))?;

    Ok(Json(serde_json::json!({
        "range": range,
        "users": users,
    })))
}

// ─── Alert rules (owner's own) ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PutAlertRulesBody {
    pub enabled: bool,
    #[serde(default)]
    pub free_gpus_min: Option<u16>,
    #[serde(default)]
    pub free_min_mem_gb: Option<u32>,
    #[serde(default = "default_true")]
    pub held_idle_alert: bool,
    #[serde(default = "default_true")]
    pub fault_alert: bool,
    #[serde(default = "default_true")]
    pub machine_alert: bool,
    #[serde(default)]
    pub lang: Option<String>,
}

fn default_true() -> bool {
    true
}

/// `GET /api/tenant/{tenant_id}/gpu/alert-rules`
pub async fn get_alert_rules(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<GpuAlertRule>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    Ok(Json(load_rule(&state.core.db, tid, auth.user_id).await))
}

/// `PUT /api/tenant/{tenant_id}/gpu/alert-rules`
pub async fn put_alert_rules(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<PutAlertRulesBody>,
) -> Result<Json<GpuAlertRule>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let lang = match body.lang.as_deref().map(str::trim) {
        Some("zh") => "zh".to_string(),
        _ => "en".to_string(),
    };
    let rule = GpuAlertRule {
        id: None,
        tenant_id: tid,
        user_id: auth.user_id,
        enabled: body.enabled,
        free_gpus_min: body.free_gpus_min,
        free_min_mem_gb: body.free_min_mem_gb,
        held_idle_alert: body.held_idle_alert,
        fault_alert: body.fault_alert,
        machine_alert: body.machine_alert,
        lang,
        updated_at: DateTime::now(),
    };
    state
        .core
        .db
        .collection::<GpuAlertRule>(RULES_COLLECTION)
        .replace_one(
            doc! { "tenant_id": tid, "user_id": auth.user_id },
            &rule,
        )
        .upsert(true)
        .await
        .map_err(|e| ApiError::Internal(format!("saving GPU alert rules failed: {e}")))?;
    Ok(Json(rule))
}

// ─── Bot channels (owner's own, masked credentials) ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateChannelBody {
    pub kind: BotKind,
    pub label: String,
    pub webhook_url: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_true")]
    pub include_users: bool,
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct PatchChannelBody {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub include_users: Option<bool>,
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// `GET /api/tenant/{tenant_id}/gpu/channels`
pub async fn list_channels(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let rows: Vec<GpuAlertChannel> = state
        .core
        .db
        .collection::<GpuAlertChannel>(super::bots::COLLECTION)
        .find(doc! { "tenant_id": tid, "user_id": auth.user_id })
        .sort(doc! { "created_at": -1 })
        .await
        .map_err(|e| ApiError::Internal(format!("listing GPU channels failed: {e}")))?
        .try_collect()
        .await
        .map_err(|e| ApiError::Internal(format!("reading GPU channels failed: {e}")))?;

    let items: Vec<ChannelView> = rows.into_iter().map(ChannelView::from).collect();
    Ok(Json(serde_json::json!({ "items": items })))
}

/// `POST /api/tenant/{tenant_id}/gpu/channels`
pub async fn create_channel(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<CreateChannelBody>,
) -> Result<Json<ChannelView>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let label = body.label.trim().to_string();
    if label.is_empty() || label.chars().count() > 64 {
        return Err(ApiError::BadRequest(
            "Channel label must be 1..=64 characters".to_string(),
        ));
    }
    let parsed_url =
        validate_channel_url(body.kind, &body.webhook_url).map_err(ApiError::BadRequest)?;
    resolve_and_validate_public(&parsed_url)
        .await
        .map_err(ApiError::BadRequest)?;

    let lang = match body.lang.as_deref().map(str::trim) {
        Some("zh") => "zh".to_string(),
        _ => "en".to_string(),
    };
    let now = DateTime::now();
    let ch = GpuAlertChannel {
        id: Some(ObjectId::new()),
        tenant_id: tid,
        user_id: auth.user_id,
        kind: body.kind,
        label,
        webhook_url: parsed_url.to_string(),
        secret: body
            .secret
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        include_users: body.include_users,
        lang,
        enabled: body.enabled,
        last_error: None,
        last_sent_at: None,
        created_at: now,
        updated_at: now,
    };
    state
        .core
        .db
        .collection::<GpuAlertChannel>(super::bots::COLLECTION)
        .insert_one(&ch)
        .await
        .map_err(|e| ApiError::Internal(format!("creating GPU channel failed: {e}")))?;

    Ok(Json(ChannelView::from(ch)))
}

/// `PATCH /api/tenant/{tenant_id}/gpu/channels/{channel_id}`
pub async fn patch_channel(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, channel_id)): Path<(String, String)>,
    Json(body): Json<PatchChannelBody>,
) -> Result<Json<ChannelView>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    let cid = parse_oid(&channel_id, "channel_id")?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let coll = state
        .core
        .db
        .collection::<GpuAlertChannel>(super::bots::COLLECTION);
    let mut existing = coll
        .find_one(doc! { "_id": cid, "tenant_id": tid, "user_id": auth.user_id })
        .await
        .map_err(|e| ApiError::Internal(format!("loading GPU channel failed: {e}")))?
        .ok_or_else(|| ApiError::NotFound("Alert channel not found".to_string()))?;

    if let Some(lbl) = body.label {
        let lbl = lbl.trim().to_string();
        if lbl.is_empty() || lbl.chars().count() > 64 {
            return Err(ApiError::BadRequest(
                "Channel label must be 1..=64 characters".to_string(),
            ));
        }
        existing.label = lbl;
    }
    if let Some(raw_url) = body.webhook_url {
        let parsed = validate_channel_url(existing.kind, &raw_url).map_err(ApiError::BadRequest)?;
        resolve_and_validate_public(&parsed)
            .await
            .map_err(ApiError::BadRequest)?;
        existing.webhook_url = parsed.to_string();
    }
    if let Some(sec) = body.secret {
        let s = sec.trim().to_string();
        existing.secret = (!s.is_empty()).then_some(s);
    }
    if let Some(inc) = body.include_users {
        existing.include_users = inc;
    }
    if let Some(lang) = body.lang {
        existing.lang = if lang.trim() == "zh" {
            "zh".to_string()
        } else {
            "en".to_string()
        };
    }
    if let Some(en) = body.enabled {
        existing.enabled = en;
    }
    existing.updated_at = DateTime::now();

    coll.replace_one(
        doc! { "_id": cid, "tenant_id": tid, "user_id": auth.user_id },
        &existing,
    )
    .await
    .map_err(|e| ApiError::Internal(format!("updating GPU channel failed: {e}")))?;

    Ok(Json(ChannelView::from(existing)))
}

/// `DELETE /api/tenant/{tenant_id}/gpu/channels/{channel_id}`
pub async fn delete_channel(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, channel_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_enabled(&state)?;
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    let cid = parse_oid(&channel_id, "channel_id")?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let res = state
        .core
        .db
        .collection::<GpuAlertChannel>(super::bots::COLLECTION)
        .delete_one(doc! { "_id": cid, "tenant_id": tid, "user_id": auth.user_id })
        .await
        .map_err(|e| ApiError::Internal(format!("deleting GPU channel failed: {e}")))?;
    if res.deleted_count == 0 {
        return Err(ApiError::NotFound("Alert channel not found".to_string()));
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// `POST /api/tenant/{tenant_id}/gpu/channels/{channel_id}/test`
pub async fn test_channel(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, channel_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_enabled(&state)?;
    if !state.gpu.settings.bots {
        return Err(ApiError::Forbidden(
            "GPU bot delivery is disabled on this server".to_string(),
        ));
    }
    let tid = parse_oid(&tenant_id, "tenant_id")?;
    let cid = parse_oid(&channel_id, "channel_id")?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let ch = state
        .core
        .db
        .collection::<GpuAlertChannel>(super::bots::COLLECTION)
        .find_one(doc! { "_id": cid, "tenant_id": tid, "user_id": auth.user_id })
        .await
        .map_err(|e| ApiError::Internal(format!("loading GPU channel failed: {e}")))?
        .ok_or_else(|| ApiError::NotFound("Alert channel not found".to_string()))?;

    let item = BotAlertItem {
        severity: "info".into(),
        title_en: "MeshHarbor GPU alert test".into(),
        title_zh: "MeshHarbor GPU 告警测试".into(),
        body_en: "This is a test alert from MeshHarbor GPU Servers.".into(),
        body_zh: "这是一条来自 MeshHarbor GPU 服务器的测试告警。".into(),
        users_summary: None,
        link: "/gpu".into(),
    };
    send_once(&ch, &[item])
        .await
        .map_err(ApiError::BadRequest)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
