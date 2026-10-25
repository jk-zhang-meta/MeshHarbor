// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor #19 — the admin read of the node network inventory
//! (`crate::net_inventory`). Viewing needs `MANAGE_AGENTS` in the tenant,
//! like the overlay ACL it sits beside; nothing here changes a node. A row is
//! reported state as the node READ it, with the server's freshness verdict,
//! never evidence that a path works.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{DateTime, oid::ObjectId};
use roomler_ai_db::models::role::permissions;
use roomler_ai_remote_control::net_inventory::{NetInventory, Section, SectionState};
use roomler_core::guards::require_permission;
use roomler_core::{ApiError, extractors::auth::AuthUser};
use serde::Serialize;

use crate::NetworkState;
use crate::net_inventory::{self, FRESH_FOR, InventoryRow};

async fn gate(
    state: &NetworkState,
    tenant_id: &str,
    auth: &AuthUser,
) -> Result<ObjectId, ApiError> {
    let tid = ObjectId::parse_str(tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    require_permission(
        state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    Ok(tid)
}

#[derive(Serialize)]
pub struct SectionSummary {
    pub state: SectionState,
    pub total: u32,
    pub reported: usize,
}

fn summary<T>(s: &Section<T>) -> SectionSummary {
    SectionSummary {
        state: s.state,
        total: s.total,
        reported: s.items.len(),
    }
}

#[derive(Serialize)]
pub struct InventorySummary {
    pub agent_id: String,
    pub received_at: String,
    /// The server's verdict: received within the freshness window.
    pub fresh: bool,
    pub stale_after_secs: u64,
    pub observed_at_ms: i64,
    pub os: String,
    pub namespaces: String,
    pub interfaces: SectionSummary,
    pub routes: SectionSummary,
    pub rules: SectionSummary,
    pub listeners: SectionSummary,
    pub firewall_chains: SectionSummary,
    pub firewall_rules: SectionSummary,
}

impl InventorySummary {
    fn of(r: &InventoryRow, now: DateTime) -> Self {
        let i = &r.inventory;
        InventorySummary {
            agent_id: r.agent_id.to_hex(),
            received_at: r.received_at.try_to_rfc3339_string().unwrap_or_default(),
            fresh: r.fresh(now),
            stale_after_secs: FRESH_FOR.as_secs(),
            observed_at_ms: r.observed_at_ms,
            os: i.os.clone(),
            namespaces: i.namespaces.clone(),
            interfaces: summary(&i.interfaces),
            routes: summary(&i.routes),
            rules: summary(&i.rules),
            listeners: summary(&i.listeners),
            firewall_chains: summary(&i.firewall_chains),
            firewall_rules: summary(&i.firewall_rules),
        }
    }
}

#[derive(Serialize)]
pub struct InventoryListResponse {
    pub items: Vec<InventorySummary>,
}

pub async fn list(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<InventoryListResponse>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let rows = net_inventory::list(&state, tid)
        .await
        .map_err(|e| ApiError::Internal(format!("net inventory: {e}")))?;
    let now = DateTime::now();
    Ok(Json(InventoryListResponse {
        items: rows.iter().map(|r| InventorySummary::of(r, now)).collect(),
    }))
}

#[derive(Serialize)]
pub struct InventoryDetailResponse {
    #[serde(flatten)]
    pub summary: InventorySummary,
    pub inventory: NetInventory,
}

pub async fn get(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Result<Json<InventoryDetailResponse>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;
    let row = net_inventory::get(&state, tid, aid)
        .await
        .map_err(|e| ApiError::Internal(format!("net inventory: {e}")))?
        .ok_or_else(|| ApiError::NotFound("no inventory for this agent".to_string()))?;
    Ok(Json(InventoryDetailResponse {
        summary: InventorySummary::of(&row, DateTime::now()),
        inventory: row.inventory,
    }))
}
