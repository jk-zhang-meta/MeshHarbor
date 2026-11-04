// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use bson::oid::ObjectId;
use meshharbor_services::quota;
use serde::{Deserialize, Serialize};

use crate::{
    core_state::Core,
    error::ApiError,
    extractors::auth::{AuthUser, OptionalAuthUser},
};
use meshharbor_db::models::role::permissions;
use meshharbor_services::dao::{base::PaginationParams, invite::CreateInviteParams};

// ─── Response types ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct InviteInfoResponse {
    pub code: String,
    /// Routes are id-based — without this the invite page's "Go to
    /// {tenant}" button had nothing to link to (it built `/tenant/` → 404).
    pub tenant_id: String,
    pub tenant_name: String,
    pub tenant_slug: String,
    pub inviter_name: String,
    pub is_valid: bool,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_member: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct InviteResponse {
    pub id: String,
    pub code: String,
    pub tenant_id: String,
    pub inviter_id: String,
    pub target_email: Option<String>,
    pub max_uses: Option<u32>,
    pub use_count: u32,
    pub status: String,
    pub assign_role_ids: Vec<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
    /// True only when THIS request dispatched an invite email — targeted
    /// invite + a configured email backend. Always serialized (a skipped
    /// false would be indistinguishable from an old server), so the UI can
    /// stop claiming "sent" for invites that only ever existed as links.
    /// List responses report false: the flag describes the create, not the row.
    pub email_sent: bool,
}

#[derive(Debug, Serialize)]
pub struct AcceptInviteResponse {
    pub tenant_id: String,
    pub tenant_name: String,
    pub tenant_slug: String,
}

// ─── Request types ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateInviteRequest {
    pub target_email: Option<String>,
    pub max_uses: Option<u32>,
    pub expires_in_hours: Option<u64>,
    #[serde(default)]
    pub assign_role_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    /// Exactly one of `user_id` / `email` (FR-11 added the email form: the
    /// members page adds a known account directly, no invite round-trip).
    #[serde(default)]
    pub user_id: Option<String>,
    /// Resolved via the users collection's unique, PROVEN email reservation
    /// — only a verified account can hold an address, so adding by email is
    /// adding a verified account. Unknown address → 404 pointing at Invites.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub role_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchCreateInviteRequest {
    pub invites: Vec<CreateInviteRequest>,
}

#[derive(Debug, Serialize)]
pub struct BatchInviteResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite: Option<InviteResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BatchCreateInviteResponse {
    pub results: Vec<BatchInviteResult>,
    pub created: usize,
    pub failed: usize,
}

// ─── Public handlers ────────────────────────────────────────────

/// GET /api/invite/{code} — public invite info
pub async fn get_invite_info(
    State(state): State<Core>,
    optional_auth: OptionalAuthUser,
    Path(code): Path<String>,
) -> Result<Json<InviteInfoResponse>, ApiError> {
    let invite = state
        .invites
        .find_by_code(&code)
        .await
        .map_err(|_| ApiError::NotFound("Invite not found".to_string()))?;

    let is_valid = state.invites.validate(&invite).is_ok();

    let tenant = state.tenants.base.find_by_id(invite.tenant_id).await?;
    let inviter = state.users.base.find_by_id(invite.inviter_id).await?;

    let already_member = if let Some(auth) = &optional_auth.0 {
        Some(
            state
                .tenants
                .is_member(invite.tenant_id, auth.user_id)
                .await?,
        )
    } else {
        None
    };

    let status = format!("{:?}", invite.status).to_lowercase();

    Ok(Json(InviteInfoResponse {
        code: invite.code,
        tenant_id: invite.tenant_id.to_hex(),
        tenant_name: tenant.name,
        tenant_slug: tenant.slug,
        inviter_name: inviter.display_name,
        is_valid,
        status,
        already_member,
    }))
}

/// POST /api/invite/{code}/accept — accept invite (requires auth)
pub async fn accept_invite(
    State(state): State<Core>,
    auth: AuthUser,
    Path(code): Path<String>,
) -> Result<Json<AcceptInviteResponse>, ApiError> {
    let invite = state.invites.find_by_code(&code).await?;

    // Validate the invite is still usable
    state
        .invites
        .validate(&invite)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Check target_email constraint
    if let Some(ref target_email) = invite.target_email
        && target_email != &auth.email
    {
        return Err(ApiError::Forbidden(
            "This invite is for a different email address".to_string(),
        ));
    }

    // Check not already a member
    if state
        .tenants
        .is_member(invite.tenant_id, auth.user_id)
        .await?
    {
        return Err(ApiError::Conflict(
            "Already a member of this tenant".to_string(),
        ));
    }

    // FR-32 P1b — plan `max_members` cap on the redemption path too. ⚠ Both
    // paths must gate or neither does: `add_member` is the admin route, this is
    // the one an invitee walks, and leaving this open would make the cap a
    // formality any tenant could route around by sending invite links.
    {
        let tenant = state.tenants.base.find_by_id(invite.tenant_id).await?;
        let used = state.tenants.count_members(invite.tenant_id).await?;
        // FR-102 P4 — through core, which also counts the collision per org.
        if let Err(d) =
            meshharbor_core::quota::check(&state, &tenant, quota::Limit::MaxMembers, used)
        {
            return Err(ApiError::Forbidden(d.message()));
        }
    }

    // Determine roles to assign (default to "member" role if none specified)
    let role_ids = if invite.assign_role_ids.is_empty() {
        let member_role = state
            .tenants
            .get_role_by_name(invite.tenant_id, "member")
            .await?;
        vec![member_role.id.unwrap()]
    } else {
        invite.assign_role_ids.clone()
    };

    // Add the user to the tenant
    state
        .tenants
        .add_member(
            invite.tenant_id,
            auth.user_id,
            role_ids,
            Some(invite.inviter_id),
        )
        .await?;

    // Atomically increment the use count
    state
        .invites
        .increment_use_count(invite.id.unwrap())
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let tenant = state.tenants.base.find_by_id(invite.tenant_id).await?;

    Ok(Json(AcceptInviteResponse {
        tenant_id: tenant.id.unwrap().to_hex(),
        tenant_name: tenant.name,
        tenant_slug: tenant.slug,
    }))
}

// ─── Tenant-scoped handlers (require INVITE_MEMBERS) ───────────

/// FR-11 invite-grid params. Flat (never `#[serde(flatten)]` behind axum
/// `Query`); all optional/defaulted — a parameterless request behaves as
/// before.
#[derive(Debug, Deserialize)]
pub struct InviteListQuery {
    #[serde(default = "invite_default_page")]
    pub page: u64,
    #[serde(default = "invite_default_per_page")]
    pub per_page: u64,
    /// Case-insensitive substring over code/target_email.
    pub q: Option<String>,
    /// Exact status filter: active | expired | revoked | exhausted.
    pub status: Option<String>,
    /// `created_at` (default, desc) | `target_email` | `status`. Unknown → 400.
    pub sort: Option<String>,
    /// `asc` | `desc`.
    pub dir: Option<String>,
}
fn invite_default_page() -> u64 {
    1
}
fn invite_default_per_page() -> u64 {
    25
}

/// GET /api/tenant/{tenant_id}/invite — list tenant invites
pub async fn list_invites(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<InviteListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_oid(&tenant_id)?;
    require_invite_permission(&state, tid, auth.user_id).await?;

    let sort = params.sort.as_deref();
    if let Some(k) = sort
        && !matches!(k, "created_at" | "target_email" | "status")
    {
        return Err(ApiError::BadRequest(format!("Unknown sort key: {k}")));
    }
    if let Some(s) = params.status.as_deref()
        && !matches!(s, "active" | "expired" | "revoked" | "exhausted")
    {
        return Err(ApiError::BadRequest(format!("Unknown status: {s}")));
    }
    let desc = match params.dir.as_deref() {
        None | Some("asc") => false,
        Some("desc") => true,
        Some(other) => {
            return Err(ApiError::BadRequest(format!("Unknown dir: {other}")));
        }
    };
    let page_params = PaginationParams {
        page: params.page.max(1),
        per_page: params.per_page.clamp(1, 100),
        before: None,
    };
    let result = state
        .invites
        .list_by_tenant(
            tid,
            &page_params,
            params.q.as_deref(),
            params.status.as_deref(),
            sort,
            desc,
        )
        .await?;

    let items: Vec<InviteResponse> = result.items.into_iter().map(invite_to_response).collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "total": result.total,
        "page": result.page,
        "per_page": result.per_page,
        "total_pages": result.total_pages,
    })))
}

/// POST /api/tenant/{tenant_id}/invite — create invite
pub async fn create_invite(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<InviteResponse>), ApiError> {
    let tid = parse_oid(&tenant_id)?;
    let held = require_invite_permission(&state, tid, auth.user_id).await?;

    let assign_role_ids: Vec<ObjectId> = body
        .assign_role_ids
        .iter()
        .map(|s| parse_oid(s))
        .collect::<Result<Vec<_>, _>>()?;

    // An invite is a DEFERRED grant — whatever it carries lands on whoever
    // redeems it. Gate it where the intent is written, because at redemption
    // the actor is the invitee, who is granting themselves nothing.
    super::role::check_grant_roles(&state, tid, held, &assign_role_ids).await?;

    let expires_in_hours = body.expires_in_hours.or(Some(168)); // default 7 days

    let target_email = body.target_email.clone();

    let invite = state
        .invites
        .create(
            tid,
            auth.user_id,
            CreateInviteParams {
                target_email: body.target_email,
                max_uses: body.max_uses,
                expires_in_hours,
                assign_role_ids,
            },
        )
        .await?;

    let email_sent = if target_email.is_some() {
        let ctx = invite_email_ctx(&state, auth.user_id, tid).await;
        spawn_invite_email(&state, &ctx, &invite)
    } else {
        false
    };

    let mut resp = invite_to_response(invite);
    resp.email_sent = email_sent;
    Ok((StatusCode::CREATED, Json(resp)))
}

/// POST /api/tenant/{tenant_id}/invite/batch — create multiple invites
pub async fn batch_create_invite(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<BatchCreateInviteRequest>,
) -> Result<(StatusCode, Json<BatchCreateInviteResponse>), ApiError> {
    let tid = parse_oid(&tenant_id)?;
    let held = require_invite_permission(&state, tid, auth.user_id).await?;

    if body.invites.is_empty() {
        return Err(ApiError::BadRequest("No invites provided".to_string()));
    }
    if body.invites.len() > 50 {
        return Err(ApiError::BadRequest(
            "Maximum 50 invites per batch".to_string(),
        ));
    }

    let mut results: Vec<BatchInviteResult> = Vec::with_capacity(body.invites.len());
    // Inviter/tenant display strings are per-REQUEST, not per-item — resolved
    // lazily on the first targeted invite so a link-only batch costs nothing.
    let mut email_ctx: Option<InviteEmailCtx> = None;

    for item in body.invites {
        let assign_role_ids: Result<Vec<ObjectId>, _> =
            item.assign_role_ids.iter().map(|s| parse_oid(s)).collect();

        match assign_role_ids {
            Ok(role_ids) => {
                // Same deferred-grant rule as the single-invite route. Reported
                // per item rather than aborting the batch, matching how this
                // endpoint already reports a bad role id.
                if let Err(e) = super::role::check_grant_roles(&state, tid, held, &role_ids).await {
                    results.push(BatchInviteResult {
                        invite: None,
                        error: Some(e.to_string()),
                        target_email: item.target_email,
                    });
                    continue;
                }
                let expires_in_hours = item.expires_in_hours.or(Some(168));
                match state
                    .invites
                    .create(
                        tid,
                        auth.user_id,
                        CreateInviteParams {
                            target_email: item.target_email.clone(),
                            max_uses: item.max_uses,
                            expires_in_hours,
                            assign_role_ids: role_ids,
                        },
                    )
                    .await
                {
                    Ok(invite) => {
                        let email_sent = if invite.target_email.is_some() {
                            if email_ctx.is_none() {
                                email_ctx = Some(invite_email_ctx(&state, auth.user_id, tid).await);
                            }
                            spawn_invite_email(&state, email_ctx.as_ref().unwrap(), &invite)
                        } else {
                            false
                        };
                        let mut resp = invite_to_response(invite);
                        resp.email_sent = email_sent;
                        results.push(BatchInviteResult {
                            invite: Some(resp),
                            error: None,
                            target_email: item.target_email,
                        })
                    }
                    Err(e) => results.push(BatchInviteResult {
                        invite: None,
                        error: Some(e.to_string()),
                        target_email: item.target_email,
                    }),
                }
            }
            Err(e) => results.push(BatchInviteResult {
                invite: None,
                error: Some(e.to_string()),
                target_email: item.target_email,
            }),
        }
    }

    let created = results.iter().filter(|r| r.invite.is_some()).count();
    let failed = results.iter().filter(|r| r.error.is_some()).count();

    Ok((
        StatusCode::CREATED,
        Json(BatchCreateInviteResponse {
            results,
            created,
            failed,
        }),
    ))
}

/// DELETE /api/tenant/{tenant_id}/invite/{invite_id} — revoke invite
pub async fn revoke_invite(
    State(state): State<Core>,
    auth: AuthUser,
    Path((tenant_id, invite_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_oid(&tenant_id)?;
    let iid = parse_oid(&invite_id)?;
    require_invite_permission(&state, tid, auth.user_id).await?;

    state.invites.revoke(iid, tid).await?;

    Ok(Json(serde_json::json!({ "revoked": true })))
}

/// POST /api/tenant/{tenant_id}/member — direct add member
pub async fn add_member(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let tid = parse_oid(&tenant_id)?;
    let held = require_invite_permission(&state, tid, auth.user_id).await?;

    let user_id = match (&body.user_id, &body.email) {
        (Some(uid), None) => parse_oid(uid)?,
        (None, Some(email)) => {
            // Normalized like the auth flows normalize at signup, so the
            // lookup matches how the reservation was written.
            let email = email.trim().to_lowercase();
            let user = state.users.find_by_email(&email).await.map_err(|_| {
                ApiError::NotFound(
                    "No account with that email address — use Invites to bring them in".to_string(),
                )
            })?;
            user.id
                .ok_or_else(|| ApiError::Internal("user missing _id".to_string()))?
        }
        _ => {
            return Err(ApiError::BadRequest(
                "Provide exactly one of user_id or email".to_string(),
            ));
        }
    };

    // Check not already a member
    if state.tenants.is_member(tid, user_id).await? {
        return Err(ApiError::Conflict("User is already a member".to_string()));
    }

    // FR-32 P1b — plan `max_members` cap. Checked AFTER the already-a-member
    // test, so only a NEW seat consumes one; mirrors the device cap's "only NEW
    // rows consume a slot". Established since FR-115 D2
    // (`Limit::is_established`): refused in every `plan_enforcement` mode,
    // `warn` included.
    {
        let tenant = state.tenants.base.find_by_id(tid).await?;
        let used = state.tenants.count_members(tid).await?;
        // FR-102 P4 — through core, which also counts the collision per org.
        if let Err(d) =
            meshharbor_core::quota::check(&state, &tenant, quota::Limit::MaxMembers, used)
        {
            return Err(ApiError::Forbidden(d.message()));
        }
    }

    let role_ids: Vec<ObjectId> = if body.role_ids.is_empty() {
        let member_role = state.tenants.get_role_by_name(tid, "member").await?;
        vec![member_role.id.unwrap()]
    } else {
        body.role_ids
            .iter()
            .map(|s| parse_oid(s))
            .collect::<Result<Vec<_>, _>>()?
    };

    // Adding a member WITH roles is a grant, and this route is behind
    // `INVITE_MEMBERS` — a much weaker bit than `MANAGE_ROLES`. Without this
    // check the role guard is trivially bypassed: invite a fresh account
    // carrying the `owner` role and log in as it.
    super::role::check_grant_roles(&state, tid, held, &role_ids).await?;

    let member = state
        .tenants
        .add_member(tid, user_id, role_ids, Some(auth.user_id))
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": member.id.unwrap().to_hex(),
            "user_id": member.user_id.to_hex(),
            "tenant_id": member.tenant_id.to_hex(),
        })),
    ))
}

// ─── Helpers ────────────────────────────────────────────────────

/// Display strings the invite email needs, resolved once per request — the
/// batch route reuses one lookup across up to 50 sends.
struct InviteEmailCtx {
    inviter_name: String,
    tenant_name: String,
}

async fn invite_email_ctx(state: &Core, inviter_id: ObjectId, tid: ObjectId) -> InviteEmailCtx {
    let inviter_name = state
        .users
        .base
        .find_by_id(inviter_id)
        .await
        .ok()
        .map(|u| u.display_name)
        .unwrap_or_default();
    let tenant_name = state
        .tenants
        .base
        .find_by_id(tid)
        .await
        .ok()
        .map(|t| t.name)
        .unwrap_or_default();
    InviteEmailCtx {
        inviter_name,
        tenant_name,
    }
}

/// Fire-and-forget invite email. Returns whether a send was actually
/// dispatched. Shared by the single and batch create routes so the two can't
/// drift again — the batch route shipped for months sending nothing while its
/// dialog said "N invites sent".
fn spawn_invite_email(
    state: &Core,
    ctx: &InviteEmailCtx,
    invite: &meshharbor_db::models::Invite,
) -> bool {
    let Some(email_addr) = invite.target_email.clone() else {
        return false;
    };
    let Some(email_svc) = state.email.clone() else {
        // A targeted invite with no email backend used to vanish silently —
        // the id (never the code: the code IS the access grant) gives the
        // operator something to grep for.
        tracing::warn!(
            invite_id = %invite.id.map(|i| i.to_hex()).unwrap_or_default(),
            "invite targets an email address but no email backend is configured — nothing sent"
        );
        return false;
    };
    // The link must land on the SPA origin — every other user-facing mail
    // builds from frontend_url (oauth.base_url is the API origin in dev).
    let invite_url = format!("{}/invite/{}", state.settings.app.frontend_url, invite.code);
    let inviter_name = ctx.inviter_name.clone();
    let tenant_name = ctx.tenant_name.clone();
    tokio::spawn(async move {
        if let Err(e) = email_svc
            .send_invite(&email_addr, &inviter_name, &tenant_name, &invite_url)
            .await
        {
            tracing::warn!(%e, "Failed to send invite email");
        }
    });
    true
}

fn parse_oid(s: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(s).map_err(|_| ApiError::BadRequest(format!("Invalid ObjectId: {}", s)))
}

/// Returns the caller's own combined mask, so the callers can pass it to
/// `role::check_grant_roles` without a second lookup.
async fn require_invite_permission(
    state: &Core,
    tenant_id: ObjectId,
    user_id: ObjectId,
) -> Result<u64, ApiError> {
    let perms = state
        .tenants
        .get_member_permissions(tenant_id, user_id)
        .await?;
    if !permissions::has(perms, permissions::INVITE_MEMBERS) {
        return Err(ApiError::Forbidden(
            "Missing INVITE_MEMBERS permission".to_string(),
        ));
    }
    Ok(perms)
}

fn invite_to_response(invite: meshharbor_db::models::Invite) -> InviteResponse {
    InviteResponse {
        id: invite.id.unwrap().to_hex(),
        code: invite.code,
        tenant_id: invite.tenant_id.to_hex(),
        inviter_id: invite.inviter_id.to_hex(),
        target_email: invite.target_email,
        max_uses: invite.max_uses,
        use_count: invite.use_count,
        status: format!("{:?}", invite.status).to_lowercase(),
        assign_role_ids: invite
            .assign_role_ids
            .iter()
            .map(|id| id.to_hex())
            .collect(),
        expires_at: invite
            .expires_at
            .map(|d| d.try_to_rfc3339_string().unwrap_or_default()),
        created_at: invite
            .created_at
            .try_to_rfc3339_string()
            .unwrap_or_default(),
        email_sent: false,
    }
}
