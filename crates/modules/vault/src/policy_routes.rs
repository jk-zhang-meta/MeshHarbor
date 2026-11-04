// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-2 — the routes over roles and policies, and `simulate`.
//!
//! | Route | Does |
//! |---|---|
//! | `GET …/vault/schema` | the Cedar schema policies are checked against, the actions, modes and OSes |
//! | `GET`/`POST …/vault/role` | the organization's vault roles; declare one |
//! | `DELETE …/vault/role/{name}` | tombstone a role no live policy names |
//! | `GET`/`POST …/vault/policy` | the guardrails and the organization's policies; add one |
//! | `GET`/`PUT`/`DELETE …/vault/policy/{id}` | one policy; replace it from the revision read; tombstone it |
//! | `POST …/vault/simulate` | decide a request as the vault would, and say which policies decided it |
//!
//! All for the organization's `ADMINISTRATOR`s, as in P3-1, and every write
//! recorded as `policy:write` before it is acted on. A policy is checked
//! before it is kept ([`crate::policy::check_policy`]): one Cedar statement,
//! valid against the schema, naming only this organization. `simulate`
//! decides nothing for real and records nothing.

use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use bson::{DateTime, Document, doc, oid::ObjectId};
use meshharbor_remote_control::{models::SshAccountMode, vault::canonical_net_host};
use meshharbor_services::dao::base::DaoError;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::VaultState;
use crate::dao::{MAX_POLICIES, MAX_ROLES, is_name_taken};
use crate::model::{VaultPolicy, VaultRole};
use crate::policy::{
    self, ACTION_ASSUME, ACTION_CONNECT, ACTION_LIST, ACTION_NET_FORWARD, ACTION_NET_SOCKS,
    ACTION_SSH_RUN, ACTION_USE, ACTIONS, Ask as Request, DeviceFacts, GUARDRAILS, MODES, NodeFacts,
    OSES, OrgNames, SecretFacts, SessionFacts, Verdict,
};
use crate::routes::{
    Ask, check_description, decide, live_secret, member_tenant, org_slug, record_allow, rfc3339,
};
use crate::rrn::{check_tag, secret_rrn};

/// The longest simulated TTL, in seconds (a day): `ttl_s` is a lease's.
pub const MAX_TTL_S: i64 = 86_400;

/// What a policy may name of the organization: its RRN prefix, its vault
/// roles, its roomler roles.
async fn org_names(state: &VaultState, tid: ObjectId) -> Result<OrgNames, ApiError> {
    let slug = org_slug(state, tid).await?;
    let roles = state
        .roles
        .list_live(tid)
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect();
    let groups = org_groups(state, tid).await?.into_iter().collect();
    Ok(OrgNames {
        secret_prefix: secret_rrn(&slug, ""),
        roles,
        groups,
    })
}

/// The organization's roomler roles, by name: every Cedar `Group` a policy
/// may name of it.
pub(crate) async fn org_groups(state: &VaultState, tid: ObjectId) -> Result<Vec<String>, DaoError> {
    Ok(state
        .tenants
        .roles
        .find_many(doc! { "tenant_id": tid }, None)
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect())
}

/// P3-7 — a node a simulated request names: a live device of this
/// organization, its facts read from its row; and (P3-8) the account its SSH
/// policy maps, which `ssh:run` reads.
async fn live_node(
    state: &VaultState,
    tid: ObjectId,
    raw: &str,
) -> Result<(NodeFacts, SshAccountMode), ApiError> {
    let id = ObjectId::parse_str(raw)
        .map_err(|_| ApiError::BadRequest("resource.node_id is not a device id".into()))?;
    let agent = match state.agents.find_live_in_tenant(tid, id).await {
        Ok(agent) => agent,
        Err(DaoError::NotFound) => {
            return Err(ApiError::BadRequest(
                "resource.node_id is not a device of this organization".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let node = NodeFacts::new(
        id,
        crate::lease::os_name(agent.os),
        &agent.tags,
        agent.owner_user_id,
    )
    .map_err(ApiError::BadRequest)?;
    Ok((node, agent.ssh_policy.account_mode))
}

/// Check a policy's text for this organization, its named users included.
async fn check_for_org(
    state: &VaultState,
    tid: ObjectId,
    text: &str,
) -> Result<policy::CheckedPolicy, ApiError> {
    let names = org_names(state, tid).await?;
    let checked = policy::check_policy(text, &names).map_err(ApiError::BadRequest)?;
    for user in &checked.users {
        if !state.tenants.is_member(tid, *user).await? {
            return Err(ApiError::BadRequest(format!(
                "User::\"{}\" is not a member of this organization",
                user.to_hex()
            )));
        }
    }
    // P3-7 — an exit named by id is a live device of THIS organization: a
    // policy that named another's would permit nothing here, and would say
    // that it exists.
    for node in &checked.nodes {
        match state.agents.find_live_in_tenant(tid, *node).await {
            Ok(_) => {}
            Err(DaoError::NotFound) => {
                return Err(ApiError::BadRequest(format!(
                    "Node::\"{}\" is not a device of this organization",
                    node.to_hex()
                )));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(checked)
}

/// The roomler roles (Cedar `Group`s) a member holds, by name. Empty for
/// someone who is not a member: no `Group` policy names them.
pub(crate) async fn groups_of_member(
    state: &VaultState,
    tid: ObjectId,
    user: ObjectId,
) -> Result<Vec<String>, DaoError> {
    let ids = state.tenants.member_role_ids(tid, user).await?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    Ok(state
        .tenants
        .roles
        .find_many(doc! { "tenant_id": tid, "_id": { "$in": ids } }, None)
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect())
}

/// The organization's whole set, guardrails first. ⚠️ An Err here is a
/// set that did not build — every caller DENIES on it.
pub(crate) async fn org_set(
    state: &VaultState,
    tid: ObjectId,
) -> Result<(cedar_policy::PolicySet, Vec<VaultPolicy>), String> {
    let stored = state
        .policies
        .list_live(tid)
        .await
        .map_err(|e| format!("the policies could not be read: {e}"))?;
    let set = policy::policy_set(
        stored
            .iter()
            .map(|p| (policy::stored_id(p.id.unwrap_or_default()), p.text.as_str())),
    )?;
    Ok((set, stored))
}

fn parse_user(raw: &str, what: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(raw).map_err(|_| ApiError::BadRequest(format!("{what} is not a user id")))
}

// ─── views ──────────────────────────────────────────────────────────────────

#[derive(Serialize, Debug)]
pub struct RoleView {
    pub name: String,
    pub description: String,
    pub created_by: String,
    pub created_at: String,
}

impl RoleView {
    fn of(r: &VaultRole) -> Self {
        Self {
            name: r.name.clone(),
            description: r.description.clone(),
            created_by: r.created_by.to_hex(),
            created_at: rfc3339(r.created_at),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct PolicyView {
    /// `policy:<id>` for a stored policy, `guardrail:<name>` for a guardrail
    /// — the id a decision names.
    pub id: String,
    pub name: String,
    pub description: String,
    pub text: String,
    pub effect: String,
    /// A guardrail: in every set, never edited or removed.
    pub guardrail: bool,
    pub rev: Option<i64>,
    pub updated_by: Option<String>,
    pub updated_at: Option<String>,
}

impl PolicyView {
    fn of(p: &VaultPolicy) -> Self {
        Self {
            id: policy::stored_id(p.id.unwrap_or_default()),
            name: p.name.clone(),
            description: p.description.clone(),
            text: p.text.clone(),
            effect: p.effect.clone(),
            guardrail: false,
            rev: Some(p.rev),
            updated_by: Some(p.updated_by.to_hex()),
            updated_at: Some(rfc3339(p.updated_at)),
        }
    }

    fn guardrails() -> impl Iterator<Item = Self> {
        GUARDRAILS.iter().map(|g| Self {
            id: g.id.into(),
            name: g.id.trim_start_matches("guardrail:").into(),
            description: g.why.into(),
            text: g.text.into(),
            effect: "forbid".into(),
            guardrail: true,
            rev: None,
            updated_by: None,
            updated_at: None,
        })
    }
}

// ─── schema ─────────────────────────────────────────────────────────────────

/// `GET /api/tenant/{tenant_id}/vault/schema` — what a policy is written
/// against: the Cedar schema, and the actions, modes and OSes it names.
pub async fn schema(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    admin_only(&state, tid, &auth).await?;
    let slug = org_slug(&state, tid).await?;
    Ok(Json(json!({
        "schema": policy::SCHEMA_SRC,
        "actions": ACTIONS,
        "modes": MODES,
        "oses": OSES,
        "secret_prefix": secret_rrn(&slug, ""),
    })))
}

/// An administrator, or a 403 — for the reads that are not decisions about
/// a secret (and so are not recorded).
async fn admin_only(state: &VaultState, tid: ObjectId, auth: &AuthUser) -> Result<(), ApiError> {
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    if meshharbor_db::models::role::permissions::has(
        perms,
        meshharbor_db::models::role::permissions::ADMINISTRATOR,
    ) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "only the organization's administrators reach its vault".into(),
        ))
    }
}

// ─── roles ──────────────────────────────────────────────────────────────────

/// `GET /api/tenant/{tenant_id}/vault/role` — the vault roles.
pub async fn list_roles(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<RoleView>>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    admin_only(&state, tid, &auth).await?;
    Ok(Json(
        state
            .roles
            .list_live(tid)
            .await?
            .iter()
            .map(RoleView::of)
            .collect(),
    ))
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CreateRole {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// `POST /api/tenant/{tenant_id}/vault/role` — declare a role. Nothing is
/// allowed to it until a policy says so.
pub async fn create_role(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<CreateRole>,
) -> Result<(StatusCode, Json<RoleView>), ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let ask = Ask::new("policy:write", "role_create").target(format!("role:{}", body.name));
    decide(&state, tid, &auth, &ask).await?;
    let name = check_tag(&body.name)
        .map_err(|why| ApiError::BadRequest(why.replacen("tag", "role", 1)))?;
    check_description(&body.description)?;
    if state.roles.count_live(tid).await? >= MAX_ROLES as u64 {
        return Err(ApiError::BadRequest(format!(
            "an organization keeps at most {MAX_ROLES} vault roles"
        )));
    }
    record_allow(&state, tid, &auth, &ask).await?;
    let role = VaultRole {
        id: None,
        tenant_id: tid,
        name: name.to_string(),
        description: body.description.clone(),
        created_by: auth.user_id,
        created_at: DateTime::now(),
        deleted_at: None,
    };
    match state.roles.create(&role).await {
        Ok(_) => Ok((StatusCode::CREATED, Json(RoleView::of(&role)))),
        Err(e) if is_name_taken(&e) => Err(ApiError::Conflict(format!(
            "the vault role {name} already exists"
        ))),
        Err(e) => Err(e.into()),
    }
}

/// The live policies that name `Role::"<name>"`, read from each parsed
/// policy ([`policy::names_role`]).
fn policies_naming_role<'a>(policies: &'a [VaultPolicy], name: &str) -> Vec<&'a VaultPolicy> {
    policies
        .iter()
        .filter(|p| policy::names_role(&p.text, name))
        .collect()
}

/// `DELETE /api/tenant/{tenant_id}/vault/role/{name}` — tombstone a role.
/// ⚠️ Refused while a live policy names it: a role re-created under the
/// same name would inherit every policy that still did.
pub async fn delete_role(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, name)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let ask = Ask::new("policy:write", "role_delete").target(format!("role:{name}"));
    decide(&state, tid, &auth, &ask).await?;
    let stored = state.policies.list_live(tid).await?;
    let naming = policies_naming_role(&stored, &name);
    if !naming.is_empty() {
        let names: Vec<&str> = naming.iter().map(|p| p.name.as_str()).collect();
        return Err(ApiError::Conflict(format!(
            "policies name this role: {} — change or delete them first",
            names.join(", ")
        )));
    }
    if !state
        .roles
        .list_live(tid)
        .await?
        .iter()
        .any(|r| r.name == name)
    {
        return Err(ApiError::NotFound("no such vault role".into()));
    }
    record_allow(&state, tid, &auth, &ask).await?;
    if !state.roles.tombstone(tid, &name).await? {
        return Err(ApiError::NotFound("no such vault role".into()));
    }
    Ok(Json(json!({ "deleted": true })))
}

// ─── policies ───────────────────────────────────────────────────────────────

/// `GET /api/tenant/{tenant_id}/vault/policy` — the guardrails, then the
/// organization's policies, oldest first.
pub async fn list_policies(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<PolicyView>>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    admin_only(&state, tid, &auth).await?;
    let stored = state.policies.list_live(tid).await?;
    Ok(Json(
        PolicyView::guardrails()
            .chain(stored.iter().map(PolicyView::of))
            .collect(),
    ))
}

fn parse_policy_id(raw: &str) -> Result<ObjectId, ApiError> {
    let hex = raw.strip_prefix("policy:").unwrap_or(raw);
    ObjectId::parse_str(hex).map_err(|_| ApiError::BadRequest("Invalid policy id".into()))
}

async fn live_policy(
    state: &VaultState,
    tid: ObjectId,
    id: ObjectId,
) -> Result<VaultPolicy, ApiError> {
    match state.policies.get_live(tid, id).await {
        Ok(p) => Ok(p),
        Err(DaoError::NotFound) => Err(ApiError::NotFound("no such policy".into())),
        Err(e) => Err(e.into()),
    }
}

/// `GET /api/tenant/{tenant_id}/vault/policy/{id}` — one policy.
pub async fn get_policy(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, id)): Path<(String, String)>,
) -> Result<Json<PolicyView>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    admin_only(&state, tid, &auth).await?;
    if let Some(g) = PolicyView::guardrails().find(|g| g.id == id) {
        return Ok(Json(g));
    }
    let id = parse_policy_id(&id)?;
    Ok(Json(PolicyView::of(&live_policy(&state, tid, id).await?)))
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct WritePolicy {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub text: String,
    /// On a replace: the revision the writer read.
    #[serde(default)]
    pub rev: Option<i64>,
}

fn check_policy_name(name: &str) -> Result<&str, ApiError> {
    check_tag(name).map_err(|why| ApiError::BadRequest(why.replacen("tag", "policy name", 1)))
}

/// `POST /api/tenant/{tenant_id}/vault/policy` — add a policy, checked
/// first.
pub async fn create_policy(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<WritePolicy>,
) -> Result<(StatusCode, Json<PolicyView>), ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let ask = Ask::new("policy:write", "policy_create").target(format!("policy:{}", body.name));
    decide(&state, tid, &auth, &ask).await?;
    if body.rev.is_some() {
        return Err(ApiError::BadRequest("a new policy has no revision".into()));
    }
    let name = check_policy_name(&body.name)?;
    check_description(&body.description)?;
    let checked = check_for_org(&state, tid, &body.text).await?;
    if state.policies.count_live(tid).await? >= MAX_POLICIES as u64 {
        return Err(ApiError::BadRequest(format!(
            "an organization keeps at most {MAX_POLICIES} policies"
        )));
    }
    record_allow(&state, tid, &auth, &ask).await?;
    let now = DateTime::now();
    let mut row = VaultPolicy {
        id: None,
        tenant_id: tid,
        name: name.to_string(),
        description: body.description.clone(),
        text: body.text.clone(),
        effect: checked.effect.into(),
        rev: 1,
        created_by: auth.user_id,
        updated_by: auth.user_id,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    };
    match state.policies.create(&row).await {
        Ok(id) => row.id = Some(id),
        Err(e) if is_name_taken(&e) => {
            return Err(ApiError::Conflict(format!(
                "a policy named {name} already exists"
            )));
        }
        Err(e) => return Err(e.into()),
    }
    Ok((StatusCode::CREATED, Json(PolicyView::of(&row))))
}

/// `PUT /api/tenant/{tenant_id}/vault/policy/{id}` — replace a policy, from
/// the revision the writer read (`rev`); a guardrail is never replaced.
pub async fn replace_policy(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, id)): Path<(String, String)>,
    Json(body): Json<WritePolicy>,
) -> Result<Json<PolicyView>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let ask = Ask::new("policy:write", "policy_update").target(id.clone());
    decide(&state, tid, &auth, &ask).await?;
    if id.starts_with("guardrail:") {
        return Err(ApiError::BadRequest("a guardrail is never edited".into()));
    }
    let oid = parse_policy_id(&id)?;
    let Some(rev) = body.rev else {
        return Err(ApiError::BadRequest(
            "rev — the revision you read — is required".into(),
        ));
    };
    let name = check_policy_name(&body.name)?;
    check_description(&body.description)?;
    let checked = check_for_org(&state, tid, &body.text).await?;
    live_policy(&state, tid, oid).await?;
    record_allow(&state, tid, &auth, &ask).await?;
    let mut set = Document::new();
    set.insert("name", name);
    set.insert("description", body.description.clone());
    set.insert("text", body.text.clone());
    set.insert("effect", checked.effect);
    set.insert("updated_by", auth.user_id);
    match state.policies.replace(tid, oid, rev, set).await {
        Ok(Some(p)) => Ok(Json(PolicyView::of(&p))),
        Ok(None) => Err(ApiError::Conflict(
            "the policy changed since you read it — read it again".into(),
        )),
        Err(e) if is_name_taken(&e) => Err(ApiError::Conflict(format!(
            "a policy named {name} already exists"
        ))),
        Err(e) => Err(e.into()),
    }
}

/// `DELETE /api/tenant/{tenant_id}/vault/policy/{id}` — tombstone a policy;
/// a guardrail is never removed.
pub async fn delete_policy(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let ask = Ask::new("policy:write", "policy_delete").target(id.clone());
    decide(&state, tid, &auth, &ask).await?;
    if id.starts_with("guardrail:") {
        return Err(ApiError::BadRequest("a guardrail is never removed".into()));
    }
    let oid = parse_policy_id(&id)?;
    live_policy(&state, tid, oid).await?;
    record_allow(&state, tid, &auth, &ask).await?;
    if !state.policies.tombstone(tid, oid).await? {
        return Err(ApiError::NotFound("no such policy".into()));
    }
    Ok(Json(json!({ "deleted": true })))
}

// ─── simulate ───────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SimDevice {
    pub os: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub owner_id: String,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct SimPrincipal {
    /// `role:assume`: the person asking.
    #[serde(default)]
    pub user_id: Option<String>,
    /// `secret:use`: the session's role (none: a session that assumed none),
    /// its owner and playbook.
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub playbook: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct SimResource {
    /// `role:assume`: the role.
    #[serde(default)]
    pub role: Option<String>,
    /// `secret:use`: the secret.
    #[serde(default)]
    pub secret_id: Option<String>,
    /// P3-7 — `net:socks`, `net:forward`: the device the flows exit through,
    /// read from its row.
    #[serde(default)]
    pub node_id: Option<String>,
}

/// `POST …/vault/simulate`.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Simulate {
    pub action: String,
    #[serde(default)]
    pub principal: SimPrincipal,
    #[serde(default)]
    pub resource: SimResource,
    pub device: SimDevice,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub ttl_s: Option<i64>,
    #[serde(default)]
    pub approver_id: Option<String>,
    /// P3-7 — `net:forward`: the destination, through the node.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// P3-8 — `ssh:run`: the account to decide for, as if the node's SSH
    /// policy mapped it (an `SshAccountMode` word); the one it maps when
    /// absent.
    #[serde(default)]
    pub account: Option<String>,
    /// Policies to decide WITH, as if added: checked like a write.
    #[serde(default)]
    pub with: Vec<String>,
    /// Stored policies (`policy:<id>`) to decide WITHOUT, as if deleted. A
    /// guardrail cannot be left out.
    #[serde(default)]
    pub without: Vec<String>,
}

/// One policy that decided a simulated request.
#[derive(Serialize, Debug)]
pub struct Determining {
    pub id: String,
    pub name: Option<String>,
    pub guardrail: bool,
}

/// `POST /api/tenant/{tenant_id}/vault/simulate` — decide a request as the
/// vault would, with the organization's set (and `with` / `without` for a
/// change not yet made), and say which policies decided it. Decides nothing
/// for real, records nothing.
pub async fn simulate(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<Simulate>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    admin_only(&state, tid, &auth).await?;

    let owner = parse_user(&body.device.owner_id, "device.owner_id")?;
    let device = DeviceFacts::new(&body.device.os, &body.device.tags, owner)
        .map_err(ApiError::BadRequest)?;
    let roles: BTreeSet<String> = state
        .roles
        .list_live(tid)
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect();
    let known_role = |r: &str| -> Result<String, ApiError> {
        if roles.contains(r) {
            Ok(r.to_string())
        } else {
            Err(ApiError::BadRequest(format!(
                "{r} is not one of this organization's vault roles"
            )))
        }
    };

    let ask = match body.action.as_str() {
        ACTION_ASSUME => {
            let Some(raw) = &body.principal.user_id else {
                return Err(ApiError::BadRequest("principal.user_id is required".into()));
            };
            let user = parse_user(raw, "principal.user_id")?;
            if !state.tenants.is_member(tid, user).await? {
                return Err(ApiError::BadRequest(
                    "principal.user_id is not a member of this organization".into(),
                ));
            }
            let Some(role) = &body.resource.role else {
                return Err(ApiError::BadRequest("resource.role is required".into()));
            };
            Request::AssumeRole {
                user,
                groups: groups_of_member(&state, tid, user).await?,
                role: known_role(role)?,
                device,
            }
        }
        ACTION_USE => {
            let Some(raw) = &body.principal.owner_id else {
                return Err(ApiError::BadRequest(
                    "principal.owner_id is required".into(),
                ));
            };
            let session_owner = parse_user(raw, "principal.owner_id")?;
            let role = match &body.principal.role {
                Some(r) => Some(known_role(r)?),
                None => None,
            };
            let Some(raw) = &body.resource.secret_id else {
                return Err(ApiError::BadRequest(
                    "resource.secret_id is required".into(),
                ));
            };
            let sid = crate::routes::parse_secret_id(raw)?;
            let secret = live_secret(&state, tid, sid).await?;
            let mode = body.mode.clone().unwrap_or_default();
            if !MODES.contains(&mode.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "mode must be one of {}",
                    MODES.join(", ")
                )));
            }
            let ttl_s = body.ttl_s.unwrap_or(900);
            if !(1..=MAX_TTL_S).contains(&ttl_s) {
                return Err(ApiError::BadRequest(format!(
                    "ttl_s must be 1 to {MAX_TTL_S}"
                )));
            }
            let approver = sim_approver(&state, tid, body.approver_id.as_deref()).await?;
            let slug = org_slug(&state, tid).await?;
            Request::UseSecret {
                session: SessionFacts {
                    id: "simulated".into(),
                    owner: session_owner,
                    role,
                    playbook: body.principal.playbook.clone(),
                },
                secret: SecretFacts {
                    prefix: secret_rrn(&slug, ""),
                    path: secret.path.clone(),
                    kind: secret.kind.clone(),
                    tags: secret.tags.clone(),
                    exec_allow: secret.exec_allow.clone(),
                    audiences: secret.audiences.clone(),
                },
                mode,
                audience: body.audience.clone().unwrap_or_default(),
                ttl_s,
                device,
                approver,
            }
        }
        // P3-4b — whether a session in a role, on that device, may list or
        // describe that secret.
        ACTION_LIST => {
            let Some(raw) = &body.principal.owner_id else {
                return Err(ApiError::BadRequest(
                    "principal.owner_id is required".into(),
                ));
            };
            let session_owner = parse_user(raw, "principal.owner_id")?;
            let role = match &body.principal.role {
                Some(r) => Some(known_role(r)?),
                None => None,
            };
            let Some(raw) = &body.resource.secret_id else {
                return Err(ApiError::BadRequest(
                    "resource.secret_id is required".into(),
                ));
            };
            let sid = crate::routes::parse_secret_id(raw)?;
            let secret = live_secret(&state, tid, sid).await?;
            let slug = org_slug(&state, tid).await?;
            Request::ListSecret {
                session: SessionFacts {
                    id: "simulated".into(),
                    owner: session_owner,
                    role,
                    playbook: body.principal.playbook.clone(),
                },
                secret: SecretFacts {
                    prefix: secret_rrn(&slug, ""),
                    path: secret.path.clone(),
                    kind: secret.kind.clone(),
                    tags: secret.tags.clone(),
                    exec_allow: secret.exec_allow.clone(),
                    audiences: secret.audiences.clone(),
                },
                device,
            }
        }
        // P3-7 — whether a session in a role, on that device, may open a
        // SOCKS5 listener, or a forward to one destination, through a node;
        // P3-8 — or run a command on it, as the account its SSH policy maps
        // (or the one the simulation names).
        ACTION_NET_SOCKS | ACTION_NET_FORWARD | ACTION_SSH_RUN => {
            let Some(raw) = &body.principal.owner_id else {
                return Err(ApiError::BadRequest(
                    "principal.owner_id is required".into(),
                ));
            };
            let session_owner = parse_user(raw, "principal.owner_id")?;
            let role = match &body.principal.role {
                Some(r) => Some(known_role(r)?),
                None => None,
            };
            let Some(raw) = &body.resource.node_id else {
                return Err(ApiError::BadRequest("resource.node_id is required".into()));
            };
            let (node, mapped) = live_node(&state, tid, raw).await?;
            let session = SessionFacts {
                id: "simulated".into(),
                owner: session_owner,
                role,
                playbook: body.principal.playbook.clone(),
            };
            if body.action == ACTION_NET_SOCKS {
                Request::NetSocks {
                    session,
                    node,
                    device,
                }
            } else if body.action == ACTION_SSH_RUN {
                let account = match body.account.as_deref() {
                    None => mapped,
                    Some(word) => SshAccountMode::from_wire(word).ok_or_else(|| {
                        ApiError::BadRequest(format!(
                            "account must be daemon, console_user or named — {word} is not one"
                        ))
                    })?,
                };
                Request::SshRun {
                    session,
                    node,
                    account: account.wire().to_string(),
                    device,
                }
            } else {
                let (Some(host), Some(port)) = (&body.host, body.port) else {
                    return Err(ApiError::BadRequest(
                        "net:forward needs host and port".into(),
                    ));
                };
                // P3-7-1b — decided as the vault decides a session's request:
                // the host in its one spelling, and a port.
                let Some(host) = canonical_net_host(host).filter(|_| port != 0) else {
                    return Err(ApiError::BadRequest(
                        "net:forward needs a host a forward can name (a DNS name or an address, \
                         no port) and a port other than 0"
                            .into(),
                    ));
                };
                Request::NetForward {
                    session,
                    node,
                    host,
                    port,
                    device,
                }
            }
        }
        // P3-9-1 — whether a person, the device's owner, may use that secret
        // through an endpoint toward that upstream. `approver_id` asks what
        // a yes would change, which no real request can get yet (decision
        // 24).
        ACTION_CONNECT => {
            let Some(raw) = &body.principal.user_id else {
                return Err(ApiError::BadRequest("principal.user_id is required".into()));
            };
            let user = parse_user(raw, "principal.user_id")?;
            if user != owner {
                return Err(ApiError::BadRequest(
                    "secret:connect acts as the device's owner: principal.user_id must be \
                     device.owner_id"
                        .into(),
                ));
            }
            if !state.tenants.is_member(tid, user).await? {
                return Err(ApiError::BadRequest(
                    "principal.user_id is not a member of this organization".into(),
                ));
            }
            if body.mode.is_some() {
                return Err(ApiError::BadRequest(
                    "secret:connect has no mode: a person's endpoint is always a proxy".into(),
                ));
            }
            let Some(raw) = &body.resource.secret_id else {
                return Err(ApiError::BadRequest(
                    "resource.secret_id is required".into(),
                ));
            };
            let sid = crate::routes::parse_secret_id(raw)?;
            let secret = live_secret(&state, tid, sid).await?;
            let ttl_s = body.ttl_s.unwrap_or(900);
            if !(1..=MAX_TTL_S).contains(&ttl_s) {
                return Err(ApiError::BadRequest(format!(
                    "ttl_s must be 1 to {MAX_TTL_S}"
                )));
            }
            let approver = sim_approver(&state, tid, body.approver_id.as_deref()).await?;
            let slug = org_slug(&state, tid).await?;
            Request::ConnectSecret {
                user,
                groups: groups_of_member(&state, tid, user).await?,
                secret: SecretFacts {
                    prefix: secret_rrn(&slug, ""),
                    path: secret.path.clone(),
                    kind: secret.kind.clone(),
                    tags: secret.tags.clone(),
                    exec_allow: secret.exec_allow.clone(),
                    audiences: secret.audiences.clone(),
                },
                audience: body.audience.clone().unwrap_or_default(),
                ttl_s,
                device,
                approver,
            }
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "action must be one of {} — {other} is not decided by the vault's policies",
                ACTIONS.join(", ")
            )));
        }
    };

    let (texts, stored) = set_as_changed(&state, tid, &body.with, &body.without).await?;
    let verdict = match policy::policy_set(texts.iter().map(|(id, t)| (id.clone(), t.as_str()))) {
        Ok(set) => policy::decide(&set, &ask),
        Err(why) => Verdict::deny(why),
    };
    let name_of = |id: &str| -> Option<String> {
        stored
            .iter()
            .find(|p| policy::stored_id(p.id.unwrap_or_default()) == id)
            .map(|p| p.name.clone())
    };
    let determining: Vec<Determining> = verdict
        .determining
        .iter()
        .map(|id| Determining {
            id: id.clone(),
            name: name_of(id),
            guardrail: id.starts_with("guardrail:"),
        })
        .collect();
    Ok(Json(json!({
        "decision": if verdict.allow { "allow" } else { "deny" },
        "determining": determining,
        "errors": verdict.errors,
    })))
}

/// P3-4e — a simulated approver, in the groups they hold, as a lease decides
/// them.
async fn sim_approver(
    state: &VaultState,
    tid: ObjectId,
    raw: Option<&str>,
) -> Result<Option<policy::Approver>, ApiError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let id = parse_user(raw, "approver_id")?;
    Ok(Some(policy::Approver {
        id,
        groups: groups_of_member(state, tid, id).await?,
    }))
}

/// The organization's set as it would be: its stored policies less
/// `without` (never a guardrail; only its own), plus `with`, each checked as
/// a write would check it. The texts under their policy ids, and the stored
/// rows (for their names).
async fn set_as_changed(
    state: &VaultState,
    tid: ObjectId,
    with: &[String],
    without: &[String],
) -> Result<(Vec<(String, String)>, Vec<VaultPolicy>), ApiError> {
    let stored = state.policies.list_live(tid).await?;
    for id in without {
        if id.starts_with("guardrail:") {
            return Err(ApiError::BadRequest(
                "a guardrail cannot be left out".into(),
            ));
        }
        if !stored
            .iter()
            .any(|p| policy::stored_id(p.id.unwrap_or_default()) == *id)
        {
            return Err(ApiError::BadRequest(format!(
                "{id} is not one of this organization's policies"
            )));
        }
    }
    let mut texts: Vec<(String, String)> = stored
        .iter()
        .map(|p| (policy::stored_id(p.id.unwrap_or_default()), p.text.clone()))
        .filter(|(id, _)| !without.contains(id))
        .collect();
    for (i, text) in with.iter().enumerate() {
        check_for_org(state, tid, text).await?;
        texts.push((format!("with:{i}"), text.clone()));
    }
    Ok((texts, stored))
}

/// The most recorded decisions one replay decides again, and the most
/// flips it lists (it counts them all).
pub const MAX_REPLAY: i64 = 5_000;
pub const MAX_FLIPS: usize = 200;

/// `POST …/vault/simulate/replay`.
#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Replay {
    #[serde(default)]
    pub with: Vec<String>,
    #[serde(default)]
    pub without: Vec<String>,
    /// How far back, 1 to 7 days; 7 by default (design §8.4).
    #[serde(default)]
    pub days: Option<u32>,
}

/// `POST /api/tenant/{tenant_id}/vault/simulate/replay` — the last days'
/// recorded Cedar decisions (each with the request it decided: the groups,
/// the device, the mode, as they were then) decided again under the set as
/// it would be with `with` and without `without`; answers the ones that
/// would come out the other way. Decides nothing for real, records nothing.
pub async fn replay(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<Replay>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    admin_only(&state, tid, &auth).await?;
    let days = body.days.unwrap_or(7);
    if !(1..=7).contains(&days) {
        return Err(ApiError::BadRequest("days must be 1 to 7".into()));
    }
    let (texts, _) = set_as_changed(&state, tid, &body.with, &body.without).await?;
    let set = policy::policy_set(texts.iter().map(|(id, t)| (id.clone(), t.as_str())))
        .map_err(|why| ApiError::BadRequest(format!("the changed set does not build: {why}")))?;
    let since = DateTime::from_millis(
        DateTime::now().timestamp_millis() - i64::from(days) * 24 * 60 * 60 * 1000,
    );
    let rows = state.audit.decisions_since(tid, since, MAX_REPLAY).await?;
    let (mut replayed, mut unreadable, mut flipped) = (0usize, 0usize, 0usize);
    let mut flips = Vec::new();
    for row in &rows {
        let Some(ask) = row.request.as_ref().and_then(Request::from_doc) else {
            unreadable += 1;
            continue;
        };
        replayed += 1;
        let was = row.decision == "allow";
        let now = policy::decide(&set, &ask);
        if now.allow != was {
            flipped += 1;
            if flips.len() < MAX_FLIPS {
                flips.push(json!({
                    "at": rfc3339(row.at),
                    "action": row.action,
                    "op": row.op,
                    "user_id": row.user_id.to_hex(),
                    "target": row.target,
                    "session_id": row.session_id.map(|i| i.to_hex()),
                    "device_id": row.device_id.map(|i| i.to_hex()),
                    "was": if was { "allow" } else { "deny" },
                    "now": if now.allow { "allow" } else { "deny" },
                    "determining": now.determining,
                }));
            }
        }
    }
    Ok(Json(json!({
        "days": days,
        "replayed": replayed,
        "unreadable": unreadable,
        "flipped": flipped,
        "flips": flips,
        "truncated": rows.len() as i64 >= MAX_REPLAY,
    })))
}

/// The organization's set and a decision against it — what P3-2b's
/// `role:assume` and P3-3's leases call. ⚠️ A set that does not build is a
/// DENY, never an allow.
pub async fn decide_for_org(state: &VaultState, tid: ObjectId, ask: &Request) -> Verdict {
    match org_set(state, tid).await {
        Ok((set, _)) => policy::decide(&set, ask),
        Err(why) => Verdict::deny(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, text: &str) -> VaultPolicy {
        let now = DateTime::now();
        VaultPolicy {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            name: name.into(),
            description: String::new(),
            text: text.into(),
            effect: "permit".into(),
            rev: 1,
            created_by: ObjectId::new(),
            updated_by: ObjectId::new(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    #[test]
    fn a_role_is_named_however_the_policy_spells_it() {
        let ps = [
            row(
                "a",
                r#"permit (principal in Roomler::Role::"dev", action, resource);"#,
            ),
            row(
                "b",
                "permit (principal in Roomler :: Role :: \"dev\", action, resource);",
            ),
            row(
                "c",
                r#"permit (principal in Roomler::Role::"developer", action, resource);"#,
            ),
            row(
                "d",
                r#"permit (principal, action, resource) when { principal in Roomler::Role::"d\u{65}v" };"#,
            ),
            row("e", "not cedar at all"),
        ];
        let names: Vec<&str> = policies_naming_role(&ps, "dev")
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["a", "b", "d", "e"],
            "\"developer\" is not \"dev\"; an escape still names it; a text that does not parse might"
        );
    }

    #[test]
    fn the_guardrails_are_listed_first_and_marked() {
        let g: Vec<PolicyView> = PolicyView::guardrails().collect();
        assert_eq!(g.len(), GUARDRAILS.len());
        assert!(
            g.iter()
                .all(|p| p.guardrail && p.effect == "forbid" && p.rev.is_none())
        );
    }
}
