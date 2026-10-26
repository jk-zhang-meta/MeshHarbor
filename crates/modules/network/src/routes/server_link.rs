// SPDX-License-Identifier: AGPL-3.0-only
//! MeshHarbor — the server topology: which servers connect to which.
//!
//! Two devices whose central role is Server are connected exactly when an
//! ENABLED link names them, whatever their business zones; with no link (or a
//! disabled one) they do not see each other, even inside one zone. Every other
//! pair keeps the zone rule (`business_isolation`). The rule applies under
//! `app.business_isolation = enforce`; `warn` logs what it would cut, so links
//! can be put in place before the switch.
//!
//! - `GET    /tenant/{tid}/server-link`        the servers and the links
//! - `PUT    /tenant/{tid}/server-link`        `{a, b, enabled}`: add, enable or disable
//! - `DELETE /tenant/{tid}/server-link/{a}/{b}` remove
//!
//! Editing requires `ADMINISTRATOR`: a link can join the two business zones.
//! Every edit re-fans both servers, rebuilds the DERP allow table and ends the
//! sessions the change no longer allows.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use roomler_ai_db::models::role::permissions;
use roomler_ai_remote_control::models::ServerLink;
use serde::{Deserialize, Serialize};

use roomler_core::guards::require_permission;
use roomler_core::{ApiError, extractors::auth::AuthUser};

use crate::NetworkState;

#[derive(Debug, Serialize)]
pub struct ServerView {
    pub agent_id: String,
    pub name: String,
    pub online: bool,
}

#[derive(Debug, Serialize)]
pub struct LinkView {
    pub a: String,
    pub b: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct TopologyResponse {
    /// The devices whose central role is Server now.
    pub servers: Vec<ServerView>,
    pub links: Vec<LinkView>,
}

#[derive(Debug, Deserialize)]
pub struct SetLinkRequest {
    pub a: String,
    pub b: String,
    pub enabled: bool,
}

fn oid(s: &str, what: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(s).map_err(|_| ApiError::BadRequest(format!("Invalid {what}")))
}

async fn gate(
    state: &NetworkState,
    tenant_id: &str,
    auth: &AuthUser,
    perm: u64,
    name: &str,
) -> Result<ObjectId, ApiError> {
    let tid = oid(tenant_id, "tenant_id")?;
    require_permission(state, tid, auth.user_id, perm, name).await?;
    Ok(tid)
}

pub async fn list(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<TopologyResponse>, ApiError> {
    let tid = gate(
        &state,
        &tenant_id,
        &auth,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let servers = roomler_core::business_authority::current_server_agents(&state.core, tid)
        .await?
        .into_iter()
        .filter_map(|a| {
            let id = a.id?;
            Some(ServerView {
                agent_id: id.to_hex(),
                name: a.name,
                online: state.fleet.rc_hub.is_agent_online(id),
            })
        })
        .collect();
    let links = state
        .overlay_networks
        .get_or_create(tid)
        .await?
        .server_links
        .into_iter()
        .map(|l| LinkView {
            a: l.a.to_hex(),
            b: l.b.to_hex(),
            enabled: l.enabled,
        })
        .collect();
    Ok(Json(TopologyResponse { servers, links }))
}

pub async fn set(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<SetLinkRequest>,
) -> Result<Json<LinkView>, ApiError> {
    let tid = gate(
        &state,
        &tenant_id,
        &auth,
        permissions::ADMINISTRATOR,
        "ADMINISTRATOR",
    )
    .await?;
    let (a, b) = (oid(&body.a, "a")?, oid(&body.b, "b")?);
    if a == b {
        return Err(ApiError::BadRequest(
            "a link joins two different servers".into(),
        ));
    }
    let servers: Vec<ObjectId> =
        roomler_core::business_authority::current_server_agents(&state.core, tid)
            .await?
            .into_iter()
            .filter_map(|s| s.id)
            .collect();
    for x in [a, b] {
        if !servers.contains(&x) {
            return Err(ApiError::BadRequest(format!(
                "{} is not a server of this tenant (its central role must be Server)",
                x.to_hex()
            )));
        }
    }
    let net = state.overlay_networks.get_or_create(tid).await?;
    let pair = ServerLink::ordered(a, b);
    let exists = net.server_links.iter().any(|l| (l.a, l.b) == pair);
    if !exists && net.server_links.len() >= ServerLink::MAX_PER_TENANT {
        return Err(ApiError::BadRequest(format!(
            "at most {} server links per tenant",
            ServerLink::MAX_PER_TENANT
        )));
    }
    state
        .overlay_networks
        .set_server_link(tid, a, b, Some(body.enabled))
        .await?;
    apply(&state, tid, [a, b]).await;
    Ok(Json(LinkView {
        a: pair.0.to_hex(),
        b: pair.1.to_hex(),
        enabled: body.enabled,
    }))
}

pub async fn delete(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, a, b)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = gate(
        &state,
        &tenant_id,
        &auth,
        permissions::ADMINISTRATOR,
        "ADMINISTRATOR",
    )
    .await?;
    let (a, b) = (oid(&a, "a")?, oid(&b, "b")?);
    state
        .overlay_networks
        .set_server_link(tid, a, b, None)
        .await?;
    apply(&state, tid, [a, b]).await;
    Ok(Json(serde_json::json!({ "removed": true })))
}

/// Make an edit take effect now: both servers re-fanned (every peer's view of
/// them, and theirs of every peer), the DERP allow table rebuilt, and the
/// sessions either takes part in re-judged.
async fn apply(state: &NetworkState, tenant_id: ObjectId, agents: [ObjectId; 2]) {
    let Ok(network) = state.overlay_networks.get_or_create(tenant_id).await else {
        return;
    };
    let Some(network_id) = network.id else { return };
    for agent_id in agents {
        if let Ok(agent) = state
            .fleet
            .agents
            .find_live_in_tenant(tenant_id, agent_id)
            .await
            && let Ok(Some(node)) = state
                .overlay_nodes
                .find_live_by_tenant_and_machine(tenant_id, &agent.machine_id)
                .await
        {
            crate::overlay::refan_node(state, &node).await;
        }
    }
    crate::derp_acl::rebuild(state, tenant_id, network_id).await;
    for agent_id in agents {
        crate::org_relay::recheck_zones(state, agent_id, "server_link_changed").await;
    }
}
