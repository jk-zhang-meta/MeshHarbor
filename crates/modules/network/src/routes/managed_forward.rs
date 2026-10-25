// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor #20 slice 1 — the managed forward intent API
//! (`crate::managed_forward`). `MANAGE_AGENTS` in the tenant for every verb,
//! viewing included: a forward exposes a listener. Create and update run the
//! dry-run plan and store nothing unless it passes (422 with the plan
//! otherwise); an update or delete names the revision it read (409 when
//! stale). Nothing is applied to a node yet: every forward reads
//! `applied: not_applied`, `verified: unverified`.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use bson::{DateTime, doc, oid::ObjectId};
use roomler_ai_db::models::role::permissions;
use roomler_core::guards::require_permission;
use roomler_core::{ApiError, extractors::auth::AuthUser};
use serde::{Deserialize, Serialize};

use crate::NetworkState;
use crate::managed_forward::{self, COLLECTION, Desired, ForwardSpec, ManagedForward, Plan};

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

fn parse_id(id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(id).map_err(|_| ApiError::BadRequest("Invalid id".to_string()))
}

/// The four layers v039 keeps apart. `applied` is the ingress agent's own
/// ack for THIS revision: `applied` (listening), `failed` (with `error`),
/// `pending` (pushed or awaiting a capable agent), or `not_applied` for a
/// disabled forward. `verified` (a scoped probe) is a later slice.
#[derive(Serialize)]
pub struct Status {
    pub desired: Desired,
    pub applied: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub verified: &'static str,
}

#[derive(Serialize)]
pub struct ForwardView {
    pub id: String,
    pub revision: u64,
    pub spec: ForwardSpec,
    pub status: Status,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&ManagedForward> for ForwardView {
    fn from(f: &ManagedForward) -> Self {
        ForwardView {
            id: f.id.to_hex(),
            revision: f.revision,
            spec: f.spec.clone(),
            status: {
                let current = f.applied.as_ref().filter(|a| a.revision == f.revision);
                Status {
                    desired: f.spec.desired,
                    applied: match (f.spec.desired, current) {
                        (Desired::Disabled, _) => "not_applied",
                        (_, Some(a)) if a.listening => "applied",
                        (_, Some(_)) => "failed",
                        (_, None) => "pending",
                    },
                    error: current.and_then(|a| a.error.clone()),
                    verified: "unverified",
                }
            },
            created_at: f.created_at.try_to_rfc3339_string().unwrap_or_default(),
            updated_at: f.updated_at.try_to_rfc3339_string().unwrap_or_default(),
        }
    }
}

#[derive(Serialize)]
pub struct MutationResponse {
    pub forward: Option<ForwardView>,
    pub plan: Plan,
}

/// v039's verified layer, from the ingress node's own report: `verified`
/// when a fresh inventory received AFTER the ack shows a listener on the
/// forward's bind address and port, `drift` when that inventory lacks it,
/// `unverified` otherwise (no ack, no newer fresh inventory).
fn verify(
    view: &mut ForwardView,
    f: &ManagedForward,
    inv: Option<&crate::net_inventory::InventoryRow>,
) {
    let Some(a) = f
        .applied
        .as_ref()
        .filter(|a| a.revision == f.revision && a.listening)
    else {
        return;
    };
    let Some(row) = inv.filter(|r| r.fresh(DateTime::now()) && r.received_at > a.at) else {
        return;
    };
    let bind: Option<std::net::IpAddr> = f.spec.bind_addr.parse().ok();
    let seen = row.inventory.listeners.items.iter().any(|l| {
        l.proto == f.spec.proto
            && l.port == f.spec.port
            && l.addr
                .parse::<std::net::IpAddr>()
                .is_ok_and(|x| x.is_unspecified() || Some(x) == bind)
    });
    view.status.verified = if seen { "verified" } else { "drift" };
}

async fn view_of(state: &NetworkState, tid: ObjectId, f: &ManagedForward) -> ForwardView {
    let mut v: ForwardView = f.into();
    if let Ok(agent) = ObjectId::parse_str(&f.spec.ingress_agent_id) {
        let inv = crate::net_inventory::get(state, tid, agent)
            .await
            .ok()
            .flatten();
        verify(&mut v, f, inv.as_ref());
    }
    v
}

#[derive(Serialize)]
pub struct ListResponse {
    pub items: Vec<ForwardView>,
}

/// Re-send the ingress agent its whole set, off the request path.
fn push_ingress(state: &NetworkState, tid: ObjectId, agent: &str) {
    if let Ok(agent) = ObjectId::parse_str(agent) {
        let state = state.clone();
        tokio::spawn(async move { managed_forward::push_to(&state, tid, agent).await });
    }
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(format!("managed forward: {e}"))
}

/// POST /plan — the dry run alone; nothing is stored.
pub async fn plan(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(spec): Json<ForwardSpec>,
) -> Result<Json<Plan>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    Ok(Json(managed_forward::plan(&state, tid, &spec, None).await))
}

pub async fn list(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<ListResponse>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let rows = managed_forward::list(&state, tid).await.map_err(internal)?;
    // One inventory read per tenant, not per forward.
    let invs = crate::net_inventory::list(&state, tid)
        .await
        .unwrap_or_default();
    let items = rows
        .iter()
        .map(|f| {
            let mut v: ForwardView = f.into();
            let inv = invs
                .iter()
                .find(|r| r.agent_id.to_hex() == f.spec.ingress_agent_id);
            verify(&mut v, f, inv);
            v
        })
        .collect();
    Ok(Json(ListResponse { items }))
}

pub async fn get(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, id)): Path<(String, String)>,
) -> Result<Json<ForwardView>, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let f = managed_forward::get(&state, tid, parse_id(&id)?)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::NotFound("Managed forward not found".to_string()))?;
    Ok(Json(view_of(&state, tid, &f).await))
}

pub async fn create(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(spec): Json<ForwardSpec>,
) -> Result<(StatusCode, Json<MutationResponse>), ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let plan = managed_forward::plan(&state, tid, &spec, None).await;
    if !plan.ok {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(MutationResponse {
                forward: None,
                plan,
            }),
        ));
    }
    let now = DateTime::now();
    let f = ManagedForward {
        id: ObjectId::new(),
        tenant_id: tid,
        revision: 1,
        spec,
        created_by: auth.user_id,
        created_at: now,
        updated_at: now,
        deleted_at: None,
        applied: None,
    };
    state
        .core
        .db
        .collection::<ManagedForward>(COLLECTION)
        .insert_one(&f)
        .await
        .map_err(internal)?;
    managed_forward::audit(&state, tid, f.id, auth.user_id, "create", 1, Some(&plan)).await;
    push_ingress(&state, tid, &f.spec.ingress_agent_id);
    Ok((
        StatusCode::CREATED,
        Json(MutationResponse {
            forward: Some((&f).into()),
            plan,
        }),
    ))
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    pub expected_revision: u64,
    pub spec: ForwardSpec,
}

pub async fn update(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, id)): Path<(String, String)>,
    Json(body): Json<UpdateRequest>,
) -> Result<(StatusCode, Json<MutationResponse>), ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let id = parse_id(&id)?;
    let cur = managed_forward::get(&state, tid, id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::NotFound("Managed forward not found".to_string()))?;
    if cur.revision != body.expected_revision {
        return Err(ApiError::Conflict(format!(
            "stale revision: {} is current",
            cur.revision
        )));
    }
    let plan = managed_forward::plan(&state, tid, &body.spec, Some(id)).await;
    if !plan.ok {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(MutationResponse {
                forward: None,
                plan,
            }),
        ));
    }
    let next = cur.revision + 1;
    let spec = bson::to_bson(&body.spec).map_err(internal)?;
    // Conditional on the revision read, so two racing editors cannot both win.
    let res = state
        .core
        .db
        .collection::<ManagedForward>(COLLECTION)
        .update_one(
            doc! { "_id": id, "tenant_id": tid, "revision": cur.revision as i64, "deleted_at": null },
            doc! { "$set": { "spec": spec, "revision": next as i64, "updated_at": DateTime::now() } },
        )
        .await
        .map_err(internal)?;
    if res.matched_count == 0 {
        return Err(ApiError::Conflict("stale revision".to_string()));
    }
    managed_forward::audit(&state, tid, id, auth.user_id, "update", next, Some(&plan)).await;
    push_ingress(&state, tid, &cur.spec.ingress_agent_id);
    if body.spec.ingress_agent_id != cur.spec.ingress_agent_id {
        push_ingress(&state, tid, &body.spec.ingress_agent_id);
    }
    let f = managed_forward::get(&state, tid, id)
        .await
        .map_err(internal)?
        .ok_or_else(|| internal("vanished"))?;
    Ok((
        StatusCode::OK,
        Json(MutationResponse {
            forward: Some((&f).into()),
            plan,
        }),
    ))
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    pub expected_revision: u64,
}

pub async fn delete(
    State(state): State<NetworkState>,
    auth: AuthUser,
    Path((tenant_id, id)): Path<(String, String)>,
    Query(q): Query<DeleteQuery>,
) -> Result<StatusCode, ApiError> {
    let tid = gate(&state, &tenant_id, &auth).await?;
    let id = parse_id(&id)?;
    let res = state
        .core
        .db
        .collection::<ManagedForward>(COLLECTION)
        .update_one(
            doc! { "_id": id, "tenant_id": tid, "revision": q.expected_revision as i64, "deleted_at": null },
            doc! { "$set": { "deleted_at": DateTime::now() } },
        )
        .await
        .map_err(internal)?;
    if res.matched_count == 0 {
        return match managed_forward::get(&state, tid, id)
            .await
            .map_err(internal)?
        {
            Some(f) => Err(ApiError::Conflict(format!(
                "stale revision: {} is current",
                f.revision
            ))),
            None => Err(ApiError::NotFound("Managed forward not found".to_string())),
        };
    }
    managed_forward::audit(
        &state,
        tid,
        id,
        auth.user_id,
        "delete",
        q.expected_revision,
        None,
    )
    .await;
    if let Ok(Some(f)) = state
        .core
        .db
        .collection::<ManagedForward>(COLLECTION)
        .find_one(doc! { "_id": id, "tenant_id": tid })
        .await
    {
        push_ingress(&state, tid, &f.spec.ingress_agent_id);
    }
    Ok(StatusCode::NO_CONTENT)
}
