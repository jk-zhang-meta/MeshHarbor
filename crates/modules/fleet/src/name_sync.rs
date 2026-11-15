//! Durable device-name intent. Delivery is a hint; only the current host's
//! exact-revision persisted ACK can turn an intent into a synced observation.
use crate::{FleetState, auth_agent::AuthAgent};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bson::oid::ObjectId;
use meshharbor_core::ApiError;
use meshharbor_remote_control::{
    models::{Agent, RpcCap},
    signaling::ServerMsg,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize)]
pub struct NameSyncView {
    pub revision: String,
    pub acked_revision: Option<String>,
    pub event_seq: String,
    pub state: &'static str,
    pub scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn view(a: &Agent) -> NameSyncView {
    let revision = a.name_sync.as_ref().map_or(0, |s| s.revision);
    let report = a.name_sync.as_ref();
    let alias = a.capabilities.has_rpc(RpcCap::OrganizationNameAlias);
    let capable = a.capabilities.has_rpc(RpcCap::DeviceNameSync) && !alias;
    let state = if alias {
        "unsupported"
    } else if report.is_none() {
        "unverified"
    } else if !capable {
        "unsupported"
    } else if report.and_then(|s| s.acked_revision) == Some(revision) {
        "synced"
    } else if report.and_then(|s| s.error.as_ref()).is_some() {
        "failed"
    } else {
        "pending"
    };
    NameSyncView {
        revision: revision.to_string(),
        acked_revision: report.and_then(|s| s.acked_revision).map(|r| r.to_string()),
        event_seq: report.map_or(0, |s| s.event_seq).to_string(),
        state,
        scope: if alias {
            "organization_alias"
        } else {
            "device"
        },
        error: report.and_then(|s| s.error.clone()),
    }
}

pub fn valid_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "name must contain 1..64 UTF-8 bytes and no control characters".into(),
        ));
    }
    Ok(name.to_owned())
}

fn revision(s: &str) -> Result<i64, ApiError> {
    let r = s
        .parse::<i64>()
        .map_err(|_| ApiError::BadRequest("invalid name revision".into()))?;
    if r < 0 || r.to_string() != s {
        return Err(ApiError::BadRequest("invalid name revision".into()));
    }
    Ok(r)
}

fn canonical(a: &Agent) -> serde_json::Value {
    json!({"agent_id":a.id.unwrap().to_hex(),"tenant_id":a.tenant_id.to_hex(),"name":a.name,
        "revision":a.name_sync.as_ref().map_or(0,|s|s.revision).to_string()})
}

pub async fn get_self(auth: AuthAgent) -> Json<serde_json::Value> {
    Json(canonical(&auth.agent))
}

#[derive(Deserialize)]
pub struct Proposal {
    pub name: String,
    pub expected_revision: String,
}

pub async fn propose(
    State(state): State<FleetState>,
    auth: AuthAgent,
    Json(body): Json<Proposal>,
) -> Result<Response, ApiError> {
    if !auth.agent.capabilities.has_rpc(RpcCap::DeviceNameSync)
        || auth
            .agent
            .capabilities
            .has_rpc(RpcCap::OrganizationNameAlias)
    {
        return Err(ApiError::Forbidden(
            "only a name-sync capable primary enrollment can propose a device name".into(),
        ));
    }
    let name = valid_name(&body.name)?;
    let expected = revision(&body.expected_revision)?;
    let Some(a) = state
        .agents
        .rename_if_revision(
            auth.tenant_id,
            auth.agent_id,
            &name,
            Some((expected, auth.agent.token_gen)),
        )
        .await?
    else {
        let current = state
            .agents
            .find_live_in_tenant(auth.tenant_id, auth.agent_id)
            .await?;
        let mut body = canonical(&current);
        body["error"] = json!("name_revision_conflict");
        return Ok((StatusCode::CONFLICT, Json(body)).into_response());
    };
    after_change(&state, &a).await;
    Ok(Json(canonical(&a)).into_response())
}

pub async fn broadcast(state: &FleetState, a: &Agent) {
    let Ok(members) = state.tenants.member_user_ids(a.tenant_id).await else {
        return;
    };
    let event = json!({"type":"device:name","data":{"tenant_id":a.tenant_id.to_hex(),"agent_id":a.id.unwrap().to_hex(),"name":a.name,"name_sync":view(a)}});
    meshharbor_core::ws::dispatcher::broadcast_with_redis(
        &state.ws_storage,
        &state.redis_pubsub,
        &members,
        &event,
    )
    .await;
}

pub async fn push(state: &FleetState, a: &Agent) {
    if !a.capabilities.has_rpc(RpcCap::DeviceNameSync)
        || a.capabilities.has_rpc(RpcCap::OrganizationNameAlias)
    {
        return;
    }
    let msg = ServerMsg::DeviceNameSync {
        agent_id: a.id.unwrap().to_hex(),
        tenant_id: a.tenant_id.to_hex(),
        name: a.name.clone(),
        revision: a.name_sync.as_ref().map_or(0, |s| s.revision).to_string(),
    };
    let _ = state
        .rc_hub
        .send_to_agent_in_tenant(a.id.unwrap(), a.tenant_id, msg.clone());
    crate::ctrl::publish_rc_ctrl(
        &state.core,
        "device_name_sync",
        json!({"tenant_id":a.tenant_id.to_hex(),"agent_id":a.id.unwrap().to_hex(),"message":msg}),
    )
    .await;
}

pub async fn after_change(state: &FleetState, a: &Agent) {
    // Canonical storage is already committed. A transport/projection failure
    // cannot pretend that it was not; retry/reconnect reconciles from the row.
    if let Err(error) = state
        .hooks
        .agent_renamed(a.tenant_id, a.id.unwrap(), &a.name)
        .await
    {
        tracing::warn!(%error,"name DNS propagation pending");
    }
    push(state, a).await;
    broadcast(state, a).await;
}

pub async fn reconcile(state: &FleetState, tenant: ObjectId, agent: ObjectId) {
    if let Ok(a) = state.agents.find_live_in_tenant(tenant, agent).await {
        // DNS projection can fail after canonical storage and even after the
        // device ACK. The hook revision gate skips already completed writes.
        if let Err(error) = state.hooks.agent_renamed(tenant, agent, &a.name).await {
            tracing::warn!(%error, "name DNS reconciliation pending");
        }
        if matches!(view(&a).state, "pending" | "unverified") {
            push(state, &a).await;
        }
    }
}

pub async fn acknowledge(
    state: &FleetState,
    tenant: ObjectId,
    agent: ObjectId,
    conn: &str,
    revision_text: &str,
    name: &str,
    applied: bool,
    detail: Option<String>,
) {
    let Ok(rev) = revision(revision_text) else {
        return;
    };
    let error = if applied {
        None
    } else {
        Some(
            detail
                .unwrap_or_else(|| "device did not persist name".into())
                .chars()
                .take(256)
                .collect(),
        )
    };
    match state
        .agents
        .acknowledge_name(tenant, agent, conn, rev, name, applied, error)
        .await
    {
        Ok(Some(a)) => broadcast(state, &a).await,
        Ok(None) => {}
        Err(error) => tracing::warn!(%error,"name ACK was not durably recorded"),
    }
}
