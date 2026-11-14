// SPDX-License-Identifier: AGPL-3.0-only
//! Make an already-enrolled device temporary (`fleet::device_invite`): bind
//! an invitation to it, mark its overlay node, and re-fan the org's netmaps so
//! every device that may no longer see it gets an explicit remove.
use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use meshharbor_core::guards::require_permission;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::role::permissions;
use meshharbor_mod_fleet::device_invite;
use meshharbor_remote_control::models::TemporaryMark;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::NetworkState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MakeTemporary {
    duration_secs: i64,
    #[serde(default)]
    allow_role_ids: Vec<String>,
}

/// `POST /api/tenant/{tenant_id}/agent/{agent_id}/temporary`
pub async fn make_temporary(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<MakeTemporary>,
) -> Result<Json<Value>, ApiError> {
    if !state.settings.auth.native_device_invite_enabled {
        return Err(ApiError::ServiceUnavailable(
            "Temporary devices are disabled on this server".into(),
        ));
    }
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".into()))?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let mut roles = Vec::new();
    for r in &body.allow_role_ids {
        roles.push(
            ObjectId::parse_str(r).map_err(|_| ApiError::BadRequest("Invalid role id".into()))?,
        );
    }
    let agent = state
        .fleet
        .agents
        .base
        .find_by_id(aid)
        .await
        .map_err(|_| ApiError::NotFound("No such device".into()))?;
    if agent.tenant_id != tid || agent.deleted_at.is_some() {
        return Err(ApiError::NotFound("No such device".into()));
    }
    if agent.ephemeral {
        return Err(ApiError::Conflict(
            "An ephemeral device cannot be made temporary".into(),
        ));
    }
    let row = device_invite::create_bound(
        &state.fleet,
        tid,
        auth.user_id,
        &agent,
        body.duration_secs,
        roles,
    )
    .await?;
    let mark = TemporaryMark {
        invite_id: row.id,
        inviter_user_id: row.inviter_user_id,
        allow_role_ids: row.allow_role_ids.clone(),
    };
    let node = match state.overlay_nodes.find_live_by_agent(tid, aid).await {
        Ok(n) => n,
        Err(_) => {
            let _ = device_invite::end_invite(&state.fleet, &row, "temporary_unbound").await;
            return Err(ApiError::ServiceUnavailable(
                "Overlay storage unavailable".into(),
            ));
        }
    };
    let marked = match &node {
        Some(n) => {
            let Some(nid) = n.id else {
                return Err(ApiError::Internal("node missing _id".into()));
            };
            if state
                .overlay_nodes
                .set_temporary(nid, Some(&mark))
                .await
                .is_err()
            {
                // The device must not stay half-converted: a grant with an
                // unmarked node would refuse its rejoin forever.
                let _ = device_invite::end_invite(&state.fleet, &row, "temporary_unbound").await;
                return Err(ApiError::ServiceUnavailable(
                    "Could not mark the device".into(),
                ));
            }
            true
        }
        // Not on the overlay yet: its node is born marked at its first join.
        None => false,
    };
    if marked {
        crate::overlay::refan_tenant_authority_local(&state, tid, "temporary_device").await;
    }
    tracing::info!(tenant = %tid, agent = %aid, invite = %row.id, by = %auth.user_id, marked,
        "temporary: existing device made temporary");
    Ok(Json(json!({
        "invite_id": row.id.to_hex(),
        "access_until_ms": row.access_until.timestamp_millis(),
        "overlay_marked": marked,
    })))
}

/// `DELETE /api/tenant/{tenant_id}/agent/{agent_id}/temporary` — make a
/// temporary device an ordinary one again (it stays enrolled). The
/// invitation ends first, so its gates open before the node is unmarked; a
/// node left marked is refused at its next join until this is retried.
pub async fn make_permanent(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    if !state.settings.auth.native_device_invite_enabled {
        return Err(ApiError::ServiceUnavailable(
            "Temporary devices are disabled on this server".into(),
        ));
    }
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".into()))?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let agent = state
        .fleet
        .agents
        .base
        .find_by_id(aid)
        .await
        .map_err(|_| ApiError::NotFound("No such device".into()))?;
    if agent.tenant_id != tid || agent.deleted_at.is_some() {
        return Err(ApiError::NotFound("No such device".into()));
    }
    let Some(grant) = device_invite::grant_for_agent(&state.fleet, aid).await? else {
        return Err(ApiError::Conflict("This device is not temporary".into()));
    };
    if !device_invite::end_keeping_device(&state.fleet, grant.invite_id, auth.user_id).await? {
        return Err(ApiError::Conflict(
            "The invitation changed meanwhile; retry".into(),
        ));
    }
    let node = state
        .overlay_nodes
        .find_live_by_agent(tid, aid)
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Overlay storage unavailable".into()))?;
    if let Some(nid) = node.and_then(|n| n.id) {
        state
            .overlay_nodes
            .set_temporary(nid, None)
            .await
            .map_err(|_| ApiError::ServiceUnavailable("Could not unmark the device".into()))?;
        crate::overlay::refan_tenant_authority_local(&state, tid, "temporary_device").await;
    }
    tracing::info!(tenant = %tid, agent = %aid, invite = %grant.invite_id, by = %auth.user_id,
        "temporary: device made permanent");
    Ok(Json(json!({ "permanent": true })))
}
