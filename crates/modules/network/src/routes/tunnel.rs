// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! REST surface for the `roomler` subsystem.
//!
//! Mirrors `crates/api/src/routes/remote_control.rs` for the
//! enrollment flow. The tunnel client (a laptop running
//! `roomler`) is enrolled in the same two-step shape as a
//! remote-control agent: admin issues a single-use `TunnelEnrollment`
//! token, then the operator runs `roomler enroll` which
//! exchanges it for a long-lived `TunnelClient` token.
//!
//! Signalling, forwarding, audit + policy CRUD land in T2.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use bson::oid::ObjectId;
use roomler_ai_db::models::role::permissions;
use roomler_ai_remote_control::models::{
    AgentStatus, DestinationRule, NodeRef, OsKind, PolicySubject, PolicyTarget,
};
use roomler_ai_services::dao::base::PaginationParams;
use roomler_ai_services::quota;
use serde::{Deserialize, Serialize};

use roomler_core::guards::require_permission;
use roomler_core::{ApiError, extractors::auth::AuthUser};

use crate::NetworkState;

/// 10 minutes — same TTL as the agent enrollment token (see plan
/// §"Security model"; matches `ENROLLMENT_TTL_SECS` in
/// `routes/remote_control.rs`).
const TUNNEL_ENROLLMENT_TTL_SECS: u64 = 600;

// ────────────────────────────────────────────────────────────────────────────
// Tunnel-client enrollment
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TunnelEnrollmentTokenResponse {
    pub enrollment_token: String,
    pub expires_in: u64,
    pub jti: String,
}

/// POST /api/tenant/{tenant_id}/tunnel-client/enroll-token —
/// admin/member issues a single-use token the operator pastes into
/// `roomler enroll`. Mirrors `issue_enrollment_token` for
/// agents.
pub async fn issue_tunnel_enrollment_token(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<TunnelEnrollmentTokenResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let (token, jti) =
        state
            .auth
            .issue_tunnel_enrollment_token(auth.user_id, tid, TUNNEL_ENROLLMENT_TTL_SECS)?;

    Ok(Json(TunnelEnrollmentTokenResponse {
        enrollment_token: token,
        expires_in: TUNNEL_ENROLLMENT_TTL_SECS,
        jti,
    }))
}

#[derive(Debug, Deserialize)]
pub struct TunnelEnrollRequest {
    pub enrollment_token: String,
    pub machine_id: String,
    pub machine_name: String,
    pub os: OsKind,
    pub client_version: String,
}

#[derive(Debug, Serialize)]
pub struct TunnelEnrollResponse {
    pub tunnel_client_id: String,
    pub tenant_id: String,
    pub tunnel_client_token: String,
}

/// POST /api/tunnel-client/enroll — public (no user JWT);
/// authenticates via the tunnel-enrollment token and returns a
/// long-lived TunnelClient JWT. Rehydrates an existing
/// `(tenant_id, machine_id)` row if one is found (covers soft-deleted
/// tombstones too — see [`TunnelClientDao::find_by_tenant_and_machine`]).
///
/// `owner_user_id` is taken from the enrollment claim's `sub` — the
/// admin who issued the token. v1 limitation: this records the
/// admin's identity rather than the operator's. v1.1 can extend the
/// enrollment request with an operator user-id once we have the
/// admin-UI flow to enter it.
pub async fn enroll_tunnel_client(
    State(state): State<NetworkState>,
    Json(body): Json<TunnelEnrollRequest>,
) -> Result<Json<TunnelEnrollResponse>, ApiError> {
    let claims = state
        .auth
        .verify_tunnel_enrollment_token(&body.enrollment_token)?;
    let tid = ObjectId::parse_str(&claims.tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id claim".to_string()))?;
    let admin_uid = ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::BadRequest("Invalid admin user id claim".to_string()))?;

    let existing = state
        .tunnel_clients
        .find_by_tenant_and_machine(tid, &body.machine_id)
        .await?;
    let client = match existing {
        Some(c) => {
            let id =
                c.id.ok_or_else(|| ApiError::Internal("tunnel client missing _id".to_string()))?;
            state
                .tunnel_clients
                .rehydrate(id, &body.machine_name, body.os, &body.client_version)
                .await?
        }
        None => {
            // S5 — plan tunnel-client cap. Mirrors the device cap in
            // `enroll_agent`: only NEW rows consume a slot.
            let tenant = state.tenants.base.find_by_id(tid).await?;
            let used = state.tunnel_clients.count_active_for_tenant(tid).await?;
            // FR-32: decision + record in `quota::check`. `MaxTunnelClients` is
            // an established limit, so it refuses whatever the mode says.
            // FR-102 P4 — through core, which also counts the collision per org.
            if let Err(d) =
                roomler_core::quota::check(&state, &tenant, quota::Limit::MaxTunnelClients, used)
            {
                return Err(ApiError::Forbidden(format!(
                    "Tunnel-client limit reached for the {:?} plan ({} of {} used). \
                     Upgrade the plan or remove a tunnel client first.",
                    d.plan, d.used, d.max
                )));
            }
            state
                .tunnel_clients
                .create(
                    tid,
                    admin_uid,
                    body.machine_name,
                    body.machine_id,
                    body.os,
                    body.client_version,
                )
                .await?
        }
    };

    let client_id = client
        .id
        .ok_or_else(|| ApiError::Internal("tunnel client missing _id".to_string()))?;
    // FR-103 — at the row's CURRENT generation, so a client revived after a
    // removal gets a token that is accepted, and its old ones are not.
    let tunnel_client_token = state.auth.issue_tunnel_client_token(
        client_id,
        tid,
        admin_uid,
        client.token_gen,
        Some(state.fleet.settings.rc.agent_token_ttl_secs),
    )?;

    Ok(Json(TunnelEnrollResponse {
        tunnel_client_id: client_id.to_hex(),
        tenant_id: tid.to_hex(),
        tunnel_client_token,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// Tunnel-client agent roster (SOCKS mesh routing)
// ────────────────────────────────────────────────────────────────────────────

/// One agent in the tenant, for the SOCKS mesh's name → agent-id routing
/// and (Phase 2) subnet-router CIDR → agent-id routing.
#[derive(Debug, Serialize)]
pub struct TunnelAgentInfo {
    pub agent_id: String,
    pub name: String,
    pub online: bool,
    /// Subnet-router CIDRs this agent is a gateway for. The mesh
    /// longest-prefix-matches a LAN-IP target against these.
    pub routes: Vec<String>,
}

/// GET /api/tunnel-client/agents — the tenant's agent roster, so
/// `roomler socks5` (mesh mode) can route a CONNECT by friendly agent
/// name instead of the raw 24-hex id. Authenticated by the caller's TunnelClient
/// JWT (`Authorization: Bearer <token>`) and scoped to that token's tenant.
pub async fn list_tenant_agents(
    State(state): State<NetworkState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<TunnelAgentInfo>>, ApiError> {
    let token = bearer_token(&headers)
        .ok_or_else(|| ApiError::Unauthorized("missing tunnel-client bearer token".to_string()))?;
    let claims = state
        .auth
        .verify_tunnel_client_token(token)
        .map_err(|_| ApiError::Unauthorized("invalid tunnel-client token".to_string()))?;
    // FR-103 — the row is the revocation list here too. This route used to
    // trust a valid signature alone, so a removed or quarantined client kept
    // reading the org's roster for the rest of its token's year.
    let client =
        accepted_tunnel_client(&state, &claims.sub, &claims.tenant_id, claims.generation).await?;
    let tid = client.tenant_id;

    // Tenants have tens of agents; one large page covers them.
    let params = PaginationParams {
        per_page: 500,
        ..Default::default()
    };
    let Some(client_id) = client.id else {
        return Err(ApiError::Internal("tunnel client missing id".to_string()));
    };
    let client_ref = roomler_ai_remote_control::models::NodeRef::TunnelClient {
        tunnel_client_id: client_id,
    };
    let page = state.fleet.agents.list_for_tenant(tid, &params).await?;
    let mut agents = Vec::with_capacity(page.items.len());
    for a in page.items {
        let Some(agent_id) = a.id else { continue };
        let agent_ref = roomler_ai_remote_control::models::NodeRef::Agent { agent_id };
        if crate::business_isolation::refuses_parties(
            &state,
            (tid, &client_ref),
            (tid, &agent_ref),
            "tunnel_roster",
        )
        .await
        {
            continue;
        }
        let online = state.fleet.rc_hub.is_agent_online(agent_id);
        agents.push(TunnelAgentInfo {
            agent_id: agent_id.to_hex(),
            name: a.name,
            online,
            routes: a.routes,
        });
    }
    Ok(Json(agents))
}

/// FR-103 — the tunnel-client twin of fleet's `accepted_agent`: the row the
/// claims name, refused if it is deleted or quarantined (the same rule the
/// tunnel-client socket applies at connect) or if the token predates the
/// client's removal (`generation_refusal`). A lookup FAILURE is a 500, never
/// a 401: a database wobble must not tell a healthy client its credential is
/// dead. `NotFound` is the authoritative "no such client".
async fn accepted_tunnel_client(
    state: &NetworkState,
    sub: &str,
    tenant: &str,
    generation: u32,
) -> Result<roomler_ai_remote_control::models::TunnelClient, ApiError> {
    let client_id = ObjectId::parse_str(sub)
        .map_err(|_| ApiError::Unauthorized("invalid tunnel-client id in claims".to_string()))?;
    let tenant_id = ObjectId::parse_str(tenant)
        .map_err(|_| ApiError::Unauthorized("invalid tenant_id in claims".to_string()))?;
    let client = state
        .tunnel_clients
        .find_any_in_tenant(tenant_id, client_id)
        .await
        .map_err(|e| match e {
            roomler_ai_services::dao::base::DaoError::NotFound => {
                ApiError::Unauthorized("no such tunnel client".to_string())
            }
            other => ApiError::Internal(format!("tunnel-client lookup: {other}")),
        })?;
    if client.deleted_at.is_some()
        || matches!(
            client.status,
            roomler_ai_remote_control::models::AgentStatus::Quarantined
        )
    {
        return Err(ApiError::Unauthorized(
            "tunnel client has been deleted or quarantined".to_string(),
        ));
    }
    if let Some(reason) = roomler_ai_mod_fleet::auth_agent::generation_refusal(
        generation,
        client.token_gen,
        state.fleet.settings.rc.token_generation_check,
    ) {
        return Err(ApiError::Unauthorized(reason.to_string()));
    }
    Ok(client)
}

/// FR-103 — what `POST /api/tunnel-client/renew` answers.
#[derive(Debug, Serialize, Deserialize)]
pub struct RenewedTunnelClientToken {
    pub tunnel_client_token: String,
    /// RFC 3339.
    pub expires_at: String,
}

/// POST /api/tunnel-client/renew — FR-103: a `roomler` client buys a fresh
/// token with the one it holds, up to `RENEWAL_GRACE_SECS` past its `exp`.
/// The row is checked as on every tunnel-client route, and the new token keeps
/// the same owner. Idempotent; `rc.token_renewal = false` answers 404.
pub async fn renew_tunnel_client(
    State(state): State<NetworkState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<RenewedTunnelClientToken>, ApiError> {
    if !state.fleet.settings.rc.token_renewal {
        return Err(ApiError::NotFound(
            "token renewal is switched off on this server".to_string(),
        ));
    }
    let token = bearer_token(&headers)
        .ok_or_else(|| ApiError::Unauthorized("missing tunnel-client bearer token".to_string()))?;
    let claims = state
        .auth
        .verify_tunnel_client_token_for_renewal(token)
        .map_err(|e| ApiError::Unauthorized(e.to_string()))?;
    let owner = ObjectId::parse_str(&claims.owner_user_id)
        .map_err(|_| ApiError::Unauthorized("invalid owner in claims".to_string()))?;
    let client =
        accepted_tunnel_client(&state, &claims.sub, &claims.tenant_id, claims.generation).await?;
    let client_id = client
        .id
        .ok_or_else(|| ApiError::Internal("tunnel client missing _id".to_string()))?;
    let ttl = state.fleet.settings.rc.agent_token_ttl_secs;
    let tunnel_client_token = state.auth.issue_tunnel_client_token(
        client_id,
        client.tenant_id,
        owner,
        client.token_gen,
        Some(ttl),
    )?;
    let expires_at = bson::DateTime::from_millis(
        bson::DateTime::now()
            .timestamp_millis()
            .saturating_add((ttl as i64).saturating_mul(1000)),
    )
    .try_to_rfc3339_string()
    .unwrap_or_default();
    tracing::info!(
        tenant_id = %client.tenant_id, %client_id, token_gen = client.token_gen, %expires_at,
        "fr-103: tunnel-client token renewed"
    );
    Ok(Json(RenewedTunnelClientToken {
        tunnel_client_token,
        expires_at,
    }))
}

/// Extract the `Bearer <token>` value from the `Authorization` header.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

// ────────────────────────────────────────────────────────────────────────────
// Tunnel-client listing (admin UI)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TunnelClientResponse {
    pub id: String,
    pub tenant_id: String,
    pub owner_user_id: String,
    pub name: String,
    /// Admin-set friendly label; display-only (see `AgentResponse`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Admin-set fleet labels.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub machine_id: String,
    pub os: OsKind,
    pub client_version: String,
    pub status: AgentStatus,
    pub last_seen_at: String,
}

fn to_tunnel_client_response(
    c: roomler_ai_remote_control::models::TunnelClient,
) -> TunnelClientResponse {
    TunnelClientResponse {
        id: c.id.map(|i| i.to_hex()).unwrap_or_default(),
        tenant_id: c.tenant_id.to_hex(),
        owner_user_id: c.owner_user_id.to_hex(),
        name: c.name,
        display_name: c.display_name,
        tags: c.tags,
        machine_id: c.machine_id,
        os: c.os,
        client_version: c.client_version,
        status: c.status,
        last_seen_at: c.last_seen_at.try_to_rfc3339_string().unwrap_or_default(),
    }
}

/// GET /api/tenant/{tenant_id}/tunnel-client — paginated list of
/// enrolled tunnel clients for the tenant. Mirrors `list_agents`.
/// T2 extends with the WS-live `is_online` derivation.
pub async fn list_tunnel_clients(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let page = state.tunnel_clients.list_for_tenant(tid, &params).await?;
    let items: Vec<TunnelClientResponse> = page
        .items
        .into_iter()
        .map(to_tunnel_client_response)
        .collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "total": page.total,
        "page": page.page,
        "per_page": page.per_page,
        "total_pages": page.total_pages,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UpdateTunnelClientRequest {
    pub name: Option<String>,
    /// `Some("")` clears (same convention as the agent route).
    pub display_name: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// PUT /api/tenant/{tenant_id}/tunnel-client/{client_id} — rename / relabel a
/// tunnel client SERVER-side. This is the only in-place rename there is: a
/// client-side rename derives a fresh machine_id and enrolls a brand-new row.
/// Mirrors `remote_control::update_agent` incl. the overlay/MagicDNS
/// propagation and the additive response envelope. `MANAGE_AGENTS`.
pub async fn update_tunnel_client(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, client_id)): Path<(String, String)>,
    Json(body): Json<UpdateTunnelClientRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let cid = ObjectId::parse_str(&client_id)
        .map_err(|_| ApiError::BadRequest("Invalid client_id".to_string()))?;

    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    // Tenant-scope the target first, LIVE — a bogus, foreign or REMOVED id
    // 404s (#1829). The setters below are live-scoped on their own too; this
    // read is what makes a stale page's edit of a removed client a clean 404
    // rather than a silent no-op.
    state.tunnel_clients.find_live_in_tenant(tid, cid).await?;

    let mut dns_renamed: Option<bool> = None;
    let mut dns_name: Option<String> = None;
    if let Some(name) = body.name {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(ApiError::BadRequest("name must not be empty".to_string()));
        }
        state.tunnel_clients.rename(tid, cid, &name).await?;
        if let Some(node) = state
            .overlay_nodes
            .find_live_by_tunnel_client(tid, cid)
            .await?
        {
            match crate::overlay::propagate_node_rename(&state, &node, &name).await {
                Some(label) => {
                    dns_renamed = Some(true);
                    dns_name = Some(label);
                }
                None => dns_renamed = Some(false),
            }
        }
    }
    if let Some(display_name) = body.display_name {
        let trimmed = display_name.trim();
        state
            .tunnel_clients
            .set_display_name(tid, cid, (!trimmed.is_empty()).then_some(trimmed))
            .await?;
    }
    if let Some(tags) = body.tags {
        let normalized = roomler_ai_mod_fleet::agent::normalize_tags(tags)?;
        state.tunnel_clients.set_tags(tid, cid, &normalized).await?;
    }

    let client = state.tunnel_clients.find_live_in_tenant(tid, cid).await?;
    Ok(Json(serde_json::json!({
        "updated": true,
        "client": to_tunnel_client_response(client),
        "dns_renamed": dns_renamed,
        "dns_name": dns_name,
    })))
}

/// DELETE /api/tenant/{tenant_id}/tunnel-client/{client_id} — remove a tunnel
/// client from the fleet.
///
/// The mirror of `remote_control::delete_agent`: evicts the client's overlay
/// node (peers get a `removes` delta, its address returns to the tenant pool)
/// and soft-deletes the client row. Revocation of a LIVE connection rides the
/// existing 60 s `spawn_revocation_check` sweep in `ws::tunnel`, which closes
/// the socket once it sees `deleted_at`.
///
/// Gated on `MANAGE_AGENTS` — the device-management bit; there is no separate
/// tunnel-client permission and minting one would mean a role migration.
pub async fn delete_tunnel_client(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let cid = ObjectId::parse_str(&client_id)
        .map_err(|_| ApiError::BadRequest("Invalid client_id".to_string()))?;

    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    // Read first, LIVE — tenant-scopes the target and 404s a bogus id, and
    // makes a REPEAT delete a 404 too (#1829): re-finding the tombstone would
    // re-run the release on an already-released node, re-stamp `deleted_at`
    // (the removal time, lost) and report `deleted: true` for a removal
    // someone else did. 404 is the one answer that leaves the state alone.
    let client = state.tunnel_clients.find_live_in_tenant(tid, cid).await?;

    let released = crate::overlay::release_overlay_node_for(
        &state,
        tid,
        &client.machine_id,
        &NodeRef::TunnelClient {
            tunnel_client_id: cid,
        },
        "tunnel_client_delete",
    )
    .await;

    state.tunnel_clients.soft_delete(tid, cid).await?;

    Ok(Json(serde_json::json!({
        "deleted": true,
        "overlay_released": released.is_some(),
        "overlay_ip": released.as_ref().map(|r| r.overlay_ip.clone()),
    })))
}

// ────────────────────────────────────────────────────────────────────────────
// Tunnel policy CRUD (admin UI)
// ────────────────────────────────────────────────────────────────────────────

/// Wire shape for create + update. `subjects`, `targets`, and
/// `allowlist` re-use the BSON serde representation of the
/// `roomler_ai_remote_control::models` types — adjacently-tagged
/// (`{kind: "...", id: "..."}` / `{kind: "...", value: "..."}`).
#[derive(Debug, Deserialize)]
pub struct TunnelPolicyCreateRequest {
    pub name: String,
    pub subjects: Vec<PolicySubject>,
    pub targets: Vec<PolicyTarget>,
    pub allowlist: Vec<DestinationRule>,
    #[serde(default)]
    pub max_concurrent_flows: Option<u32>,
    #[serde(default)]
    pub max_bytes_per_session: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct TunnelPolicyUpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subjects: Option<Vec<PolicySubject>>,
    #[serde(default)]
    pub targets: Option<Vec<PolicyTarget>>,
    #[serde(default)]
    pub allowlist: Option<Vec<DestinationRule>>,
    /// `Some(None)` clears the ceiling; `Some(Some(v))` sets it;
    /// absent leaves it unchanged. Two-level Option matches the
    /// DAO's three-way intent. JSON wire: `null` to clear,
    /// integer to set, omit field to leave alone.
    #[serde(default, deserialize_with = "deserialize_clearable_u32")]
    pub max_concurrent_flows: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_clearable_u64")]
    pub max_bytes_per_session: Option<Option<u64>>,
}

fn deserialize_clearable_u32<'de, D>(de: D) -> Result<Option<Option<u32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: Option<u32> = Option::deserialize(de)?;
    Ok(Some(v))
}

fn deserialize_clearable_u64<'de, D>(de: D) -> Result<Option<Option<u64>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: Option<u64> = Option::deserialize(de)?;
    Ok(Some(v))
}

#[derive(Debug, Serialize)]
pub struct TunnelPolicyResponse {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub subjects: Vec<PolicySubject>,
    pub targets: Vec<PolicyTarget>,
    pub allowlist: Vec<DestinationRule>,
    pub max_concurrent_flows: Option<u32>,
    pub max_bytes_per_session: Option<u64>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<roomler_ai_remote_control::models::TunnelPolicy> for TunnelPolicyResponse {
    fn from(p: roomler_ai_remote_control::models::TunnelPolicy) -> Self {
        Self {
            id: p.id.map(|i| i.to_hex()).unwrap_or_default(),
            tenant_id: p.tenant_id.to_hex(),
            name: p.name,
            subjects: p.subjects,
            targets: p.targets,
            allowlist: p.allowlist,
            max_concurrent_flows: p.max_concurrent_flows,
            max_bytes_per_session: p.max_bytes_per_session,
            created_at: p.created_at.try_to_rfc3339_string().unwrap_or_default(),
            updated_at: p.updated_at.try_to_rfc3339_string().unwrap_or_default(),
        }
    }
}

/// Reject empty / malformed inputs before they reach the DAO. Surface
/// a clean 400 rather than relying on Mongo to bounce malformed BSON.
fn validate_policy_input(
    name: &str,
    subjects: &[PolicySubject],
    targets: &[PolicyTarget],
    allowlist: &[DestinationRule],
) -> Result<(), ApiError> {
    if name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".into()));
    }
    if subjects.is_empty() {
        return Err(ApiError::BadRequest(
            "subjects must contain at least one entry (use AllUsers for catch-all)".into(),
        ));
    }
    if targets.is_empty() {
        return Err(ApiError::BadRequest(
            "targets must contain at least one entry (use AllAgents for catch-all)".into(),
        ));
    }
    if allowlist.is_empty() {
        return Err(ApiError::BadRequest(
            "allowlist must contain at least one DestinationRule".into(),
        ));
    }
    for r in allowlist {
        if r.port_range.low == 0 || r.port_range.high < r.port_range.low {
            return Err(ApiError::BadRequest(format!(
                "invalid port_range: low={}, high={}",
                r.port_range.low, r.port_range.high
            )));
        }
    }
    Ok(())
}

/// POST /api/tenant/{tenant_id}/tunnel-policy — create a new policy.
pub async fn create_tunnel_policy(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<TunnelPolicyCreateRequest>,
) -> Result<(StatusCode, Json<TunnelPolicyResponse>), ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    validate_policy_input(&body.name, &body.subjects, &body.targets, &body.allowlist)?;

    let policy = state
        .tunnel_policies
        .create(
            tid,
            body.name,
            body.subjects,
            body.targets,
            body.allowlist,
            body.max_concurrent_flows,
            body.max_bytes_per_session,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(policy.into())))
}

/// GET /api/tenant/{tenant_id}/tunnel-policy — paginated list of live
/// policies for the tenant. Soft-deleted rows are excluded.
pub async fn list_tunnel_policies(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let page = state.tunnel_policies.list_for_tenant(tid, &params).await?;
    let items: Vec<TunnelPolicyResponse> = page.items.into_iter().map(Into::into).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": page.total,
        "page": page.page,
        "per_page": page.per_page,
        "total_pages": page.total_pages,
    })))
}

/// GET /api/tenant/{tenant_id}/tunnel-policy/{policy_id} — fetch one.
pub async fn get_tunnel_policy(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, policy_id)): Path<(String, String)>,
) -> Result<Json<TunnelPolicyResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let pid = ObjectId::parse_str(&policy_id)
        .map_err(|_| ApiError::BadRequest("Invalid policy_id".to_string()))?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    // LIVE: a deleted policy is a 404 here exactly as it is absent from the
    // listing and from the gate's compile set (#1829).
    let policy = state.tunnel_policies.find_live_in_tenant(tid, pid).await?;
    Ok(Json(policy.into()))
}

/// PUT /api/tenant/{tenant_id}/tunnel-policy/{policy_id} — partial
/// update. Any field omitted from the body stays unchanged.
///
/// A deleted policy is a 404 (#1829): the lookup below is live, and the
/// write underneath it is live-scoped on its own, so neither a stale page nor
/// a caller that skips the read can edit a tombstone back into service.
pub async fn update_tunnel_policy(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, policy_id)): Path<(String, String)>,
    Json(body): Json<TunnelPolicyUpdateRequest>,
) -> Result<Json<TunnelPolicyResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let pid = ObjectId::parse_str(&policy_id)
        .map_err(|_| ApiError::BadRequest("Invalid policy_id".to_string()))?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    // Resolve the target LIVE before touching it — a removed policy is a 404
    // whatever the body says, like a bogus or foreign id.
    state.tunnel_policies.find_live_in_tenant(tid, pid).await?;
    // Validate only the fields that ARE being updated.
    if let Some(n) = &body.name
        && n.trim().is_empty()
    {
        return Err(ApiError::BadRequest("name must not be empty".into()));
    }
    if let Some(s) = &body.subjects
        && s.is_empty()
    {
        return Err(ApiError::BadRequest(
            "subjects must contain at least one entry".into(),
        ));
    }
    if let Some(t) = &body.targets
        && t.is_empty()
    {
        return Err(ApiError::BadRequest(
            "targets must contain at least one entry".into(),
        ));
    }
    if let Some(a) = &body.allowlist {
        if a.is_empty() {
            return Err(ApiError::BadRequest(
                "allowlist must contain at least one DestinationRule".into(),
            ));
        }
        for r in a {
            if r.port_range.low == 0 || r.port_range.high < r.port_range.low {
                return Err(ApiError::BadRequest(format!(
                    "invalid port_range: low={}, high={}",
                    r.port_range.low, r.port_range.high
                )));
            }
        }
    }
    let changed = state
        .tunnel_policies
        .update(
            tid,
            pid,
            body.name,
            body.subjects,
            body.targets,
            body.allowlist,
            body.max_concurrent_flows,
            body.max_bytes_per_session,
        )
        .await?;
    if !changed {
        // The live-scoped write matched nothing: the policy was removed
        // between the lookup above and here.
        return Err(ApiError::NotFound("Tunnel policy not found".into()));
    }
    let policy = state.tunnel_policies.find_live_in_tenant(tid, pid).await?;
    Ok(Json(policy.into()))
}

/// DELETE /api/tenant/{tenant_id}/tunnel-policy/{policy_id} —
/// soft-delete. Existing flows on live sessions are not killed; new
/// `TcpForwardRequest`s using only this policy will start being
/// denied at the next policy fetch (every request — there's no
/// cache, see `list_active_for_tenant`).
pub async fn delete_tunnel_policy(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, policy_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let pid = ObjectId::parse_str(&policy_id)
        .map_err(|_| ApiError::BadRequest("Invalid policy_id".to_string()))?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let deleted = state.tunnel_policies.soft_delete(tid, pid).await?;
    if !deleted {
        return Err(ApiError::NotFound("Tunnel policy not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}
