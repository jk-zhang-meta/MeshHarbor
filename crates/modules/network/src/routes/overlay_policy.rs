// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Admin CRUD for the overlay L3 ACL.
//!
//! Mirrors the tunnel-policy admin surface (`routes/tunnel.rs`) but drives a
//! different enforcement point: these rows shape the NETMAP each node receives
//! — which peers it sees and which of their approved routes it may install —
//! rather than gating individual tunnel flows.
//!
//! The tenant-wide posture lives on `OverlayNetwork.acl_mode`
//! (`off` → `warn` → `enforce`) and is edited through
//! `PUT /overlay-acl/mode`. It defaults to `off`, so adding policies is
//! inert until an admin deliberately turns enforcement on — the feature can
//! never black-hole a live mesh by merely being deployed.
//!
//! Everything here requires `MANAGE_AGENTS`: overlay traffic bypasses the
//! tunnel ACL entirely, so an overlay grant is at least as powerful as an
//! agent-management action.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::oid::ObjectId;
use roomler_ai_db::models::role::permissions;
use roomler_ai_remote_control::models::{
    OverlayAclMode, OverlayPolicy, OverlayRule, OverlaySelector, OverlayTarget,
};
use roomler_ai_services::dao::base::PaginationParams;
use serde::{Deserialize, Serialize};

use roomler_core::guards::require_permission;
use roomler_core::{ApiError, extractors::auth::AuthUser};

use crate::NetworkState;

#[derive(Debug, Serialize)]
pub struct OverlayPolicyResponse {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub enabled: bool,
    pub sources: Vec<OverlaySelector>,
    pub via: Vec<OverlayTarget>,
    pub destinations: Vec<OverlayRule>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<OverlayPolicy> for OverlayPolicyResponse {
    fn from(p: OverlayPolicy) -> Self {
        Self {
            id: p.id.map(|i| i.to_hex()).unwrap_or_default(),
            tenant_id: p.tenant_id.to_hex(),
            name: p.name,
            enabled: p.enabled,
            sources: p.sources,
            via: p.via,
            destinations: p.destinations,
            created_at: p.created_at.try_to_rfc3339_string().unwrap_or_default(),
            updated_at: p.updated_at.try_to_rfc3339_string().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OverlayPolicyListResponse {
    pub items: Vec<OverlayPolicyResponse>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    /// The tenant's current posture, so the UI can render the mode selector
    /// and the "rules are not being enforced yet" banner from one round-trip.
    pub mode: OverlayAclMode,
}

#[derive(Debug, Deserialize)]
pub struct UpsertOverlayPolicyRequest {
    pub name: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub sources: Vec<OverlaySelector>,
    pub via: Vec<OverlayTarget>,
    pub destinations: Vec<OverlayRule>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct SetAclModeRequest {
    pub mode: OverlayAclMode,
}

#[derive(Debug, Serialize)]
pub struct AclModeResponse {
    pub mode: OverlayAclMode,
}

/// Reject rules that can never match, so an admin never authors a silent
/// no-op. Every CIDR must parse, and the port range must be sane.
fn validate(body: &UpsertOverlayPolicyRequest) -> Result<(), ApiError> {
    if body.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    if body.sources.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one source is required".into(),
        ));
    }
    if body.via.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one via node is required".into(),
        ));
    }
    if body.destinations.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one destination is required".into(),
        ));
    }
    for d in &body.destinations {
        if d.cidr.trim().parse::<ipnet::IpNet>().is_err() {
            return Err(ApiError::BadRequest(format!(
                "destination '{}' is not a valid CIDR (a bare address needs a prefix, e.g. 10.0.0.5/32)",
                d.cidr
            )));
        }
        if d.port_range.low == 0 || d.port_range.high < d.port_range.low {
            return Err(ApiError::BadRequest(format!(
                "destination '{}' has an invalid port range",
                d.cidr
            )));
        }
    }
    Ok(())
}

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

pub async fn list(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<OverlayPolicyListResponse>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let page = state.overlay_policies.list_for_tenant(tid, &params).await?;
    let mode = state.overlay_networks.get_or_create(tid).await?.acl_mode;
    Ok(Json(OverlayPolicyListResponse {
        items: page.items.into_iter().map(Into::into).collect(),
        total: page.total,
        page: page.page,
        per_page: page.per_page,
        mode,
    }))
}

pub async fn create(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<UpsertOverlayPolicyRequest>,
) -> Result<Json<OverlayPolicyResponse>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    validate(&body)?;
    let created = state
        .overlay_policies
        .create(
            tid,
            body.name.trim().to_string(),
            body.enabled,
            body.sources,
            body.via,
            body.destinations,
        )
        .await?;
    crate::overlay::publish_and_refan_tenant_authority(&state, tid, true, "policy_create").await;
    Ok(Json(created.into()))
}

pub async fn get(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, policy_id)): Path<(String, String)>,
) -> Result<Json<OverlayPolicyResponse>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let pid = ObjectId::parse_str(&policy_id)
        .map_err(|_| ApiError::BadRequest("Invalid policy_id".to_string()))?;
    // LIVE: a deleted policy is a 404 here exactly as it is absent from the
    // listing and from the netmap compiler's set (#1829).
    Ok(Json(
        state
            .overlay_policies
            .find_live_in_tenant(tid, pid)
            .await?
            .into(),
    ))
}

/// A deleted policy is a 404 (#1829): the lookup is live, the write under it
/// is live-scoped on its own, and the tenant is re-fanned only when a row
/// actually changed — before this, a `PUT` on a tombstone wrote `enabled:
/// true` onto it, re-fanned every node for an edit the compiler could not
/// see, and then served the edited tombstone back.
pub async fn update(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, policy_id)): Path<(String, String)>,
    Json(body): Json<UpsertOverlayPolicyRequest>,
) -> Result<Json<OverlayPolicyResponse>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let pid = ObjectId::parse_str(&policy_id)
        .map_err(|_| ApiError::BadRequest("Invalid policy_id".to_string()))?;
    // Resolve the target LIVE before touching it — a removed policy is a 404
    // whatever the body says, like a bogus or foreign id.
    state.overlay_policies.find_live_in_tenant(tid, pid).await?;
    validate(&body)?;
    let changed = state
        .overlay_policies
        .update(
            tid,
            pid,
            Some(body.name.trim().to_string()),
            Some(body.enabled),
            Some(body.sources),
            Some(body.via),
            Some(body.destinations),
        )
        .await?;
    if changed {
        crate::overlay::publish_and_refan_tenant_authority(&state, tid, true, "policy_update")
            .await;
    }
    // The refetch is live too: a removal that raced the write is a 404, not
    // a 200 carrying the tombstone.
    Ok(Json(
        state
            .overlay_policies
            .find_live_in_tenant(tid, pid)
            .await?
            .into(),
    ))
}

/// Soft-delete. A repeat `DELETE` (or a bogus / foreign id) is a 404, the
/// same answer the tunnel-policy sibling gives and the one that leaves the
/// state alone (#1829): the write is live-scoped, so a tombstone matches
/// nothing — before this it re-stamped the removal time, answered
/// `deleted: true` and re-fanned the tenant for a removal someone else did.
pub async fn delete(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, policy_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let pid = ObjectId::parse_str(&policy_id)
        .map_err(|_| ApiError::BadRequest("Invalid policy_id".to_string()))?;
    let removed = state.overlay_policies.soft_delete(tid, pid).await?;
    if !removed {
        return Err(ApiError::NotFound("Overlay policy not found".into()));
    }
    crate::overlay::publish_and_refan_tenant_authority(&state, tid, true, "policy_delete").await;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

pub async fn get_mode(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<AclModeResponse>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let mode = state.overlay_networks.get_or_create(tid).await?.acl_mode;
    Ok(Json(AclModeResponse { mode }))
}

pub async fn set_mode(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<SetAclModeRequest>,
) -> Result<Json<AclModeResponse>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    state.overlay_networks.set_acl_mode(tid, body.mode).await?;
    crate::overlay::publish_and_refan_tenant_authority(&state, tid, false, "acl_mode").await;
    Ok(Json(AclModeResponse { mode: body.mode }))
}
