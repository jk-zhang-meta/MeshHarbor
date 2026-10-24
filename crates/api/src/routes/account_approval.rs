// SPDX-License-Identifier: AGPL-3.0-only
//! Optional central account review, deliberately independent of tenant membership.
use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{Document, doc, oid::ObjectId};
use roomler_ai_db::models::{AccountApprovalState, User};
use roomler_ai_services::dao::base::PaginationParams;
use roomler_core::{ApiError, Core, extractors::auth::AuthUser};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct ApprovalStatus {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub state: AccountApprovalState,
    pub revision: u32,
    pub email_verified: bool,
}
impl From<User> for ApprovalStatus {
    fn from(u: User) -> Self {
        Self {
            user_id: u.id.map(|id| id.to_hex()).unwrap_or_default(),
            username: u.username,
            email: u.email,
            state: u.account_approval.state,
            revision: u.account_approval.revision,
            email_verified: u.is_verified,
        }
    }
}

/// Password proof reveals only the caller's own state and never grants app access.
/// This endpoint is mounted behind the existing credential brute-force limiter.
pub async fn status(
    State(core): State<Core>,
    Json(body): Json<super::auth::LoginRequest>,
) -> Result<Json<ApprovalStatus>, ApiError> {
    if !core.settings.auth.account_approval.enabled {
        return Err(ApiError::NotFound("Account approval not enabled".into()));
    }
    let user = super::auth::password_identity(&core, &body).await?;
    Ok(Json(user.into()))
}

fn require_owner(core: &Core, auth: &AuthUser) -> Result<ObjectId, ApiError> {
    let owner = roomler_core::admission::owner_id(&core.settings.auth.account_approval)?
        .ok_or_else(|| ApiError::NotFound("Account approval not enabled".into()))?;
    if owner != auth.user_id {
        return Err(ApiError::Forbidden(
            "Only the configured approval owner may review accounts".into(),
        ));
    }
    Ok(owner)
}

#[derive(Serialize)]
pub struct ApprovalAccess {
    pub enabled: bool,
    pub is_owner: bool,
}

/// Discover the caller's central-review capability without exposing the owner
/// identity or any other account. Tenant/platform-admin roles do not confer it.
pub async fn access(
    State(core): State<Core>,
    auth: AuthUser,
) -> Result<Json<ApprovalAccess>, ApiError> {
    let policy = &core.settings.auth.account_approval;
    let owner = roomler_core::admission::owner_id(policy)?;
    Ok(Json(ApprovalAccess {
        enabled: policy.enabled,
        is_owner: owner == Some(auth.user_id),
    }))
}

#[derive(Deserialize, Default)]
pub struct ApprovalListQuery {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
    pub state: Option<AccountApprovalState>,
}
impl ApprovalListQuery {
    fn pagination(&self) -> Result<PaginationParams, ApiError> {
        let page = self.page.unwrap_or(1).max(1);
        let per_page = self.per_page.unwrap_or(25).clamp(1, 100);
        // MongoDB skip is signed. Check before DAO multiplication, including
        // debug builds, and never wrap a requested page back to earlier users.
        if (page - 1)
            .checked_mul(per_page)
            .is_none_or(|skip| skip > i64::MAX as u64)
        {
            return Err(ApiError::BadRequest("Page is out of range".into()));
        }
        Ok(PaginationParams {
            page,
            per_page,
            before: None,
        })
    }
}

fn queue_filter(state: Option<AccountApprovalState>, owner: ObjectId) -> Document {
    // The bootstrap owner's persisted state may remain pending. It is not a
    // reviewable row and must not appear as a pending request in the console.
    let mut filter = doc! { "deleted_at": null, "_id": { "$ne": owner } };
    match state {
        None => {
            filter.insert(
                "$or",
                bson::bson!([
                    { "account_approval.state": { "$in": ["pending", "legacy_unreviewed"] } },
                    { "account_approval.state": { "$exists": false } }
                ]),
            );
        }
        Some(AccountApprovalState::LegacyUnreviewed) => {
            filter.insert(
                "$or",
                bson::bson!([
                    { "account_approval.state": "legacy_unreviewed" },
                    { "account_approval.state": { "$exists": false } }
                ]),
            );
        }
        Some(state) => {
            // Exhaustive mapping: a new state cannot silently broaden a query.
            let value = match state {
                AccountApprovalState::Pending => "pending",
                AccountApprovalState::Approved => "approved",
                AccountApprovalState::Rejected => "rejected",
                AccountApprovalState::Suspended => "suspended",
                AccountApprovalState::LegacyUnreviewed => unreachable!(),
            };
            filter.insert("account_approval.state", value);
        }
    }
    filter
}

#[derive(Serialize)]
pub struct ApprovalQueue {
    pub items: Vec<ApprovalStatus>,
    pub total: u64,
    pub page: u64,
}

pub async fn list(
    State(core): State<Core>,
    auth: AuthUser,
    Query(query): Query<ApprovalListQuery>,
) -> Result<Json<ApprovalQueue>, ApiError> {
    let owner = require_owner(&core, &auth)?;
    let page = query.pagination()?;
    let result = core
        .users
        .base
        .find_paginated(
            queue_filter(query.state, owner),
            Some(doc! { "created_at": 1 }),
            &page,
        )
        .await?;
    Ok(Json(ApprovalQueue {
        items: result.items.into_iter().map(Into::into).collect(),
        total: result.total,
        page: result.page,
    }))
}

#[derive(Deserialize)]
pub struct ReviewRequest {
    pub state: AccountApprovalState,
    pub expected_revision: u32,
}
fn reviewable(state: AccountApprovalState) -> bool {
    matches!(
        state,
        AccountApprovalState::Approved
            | AccountApprovalState::Rejected
            | AccountApprovalState::Suspended
    )
}

pub async fn review(
    State(core): State<Core>,
    auth: AuthUser,
    Path(user_id): Path<String>,
    Json(body): Json<ReviewRequest>,
) -> Result<Json<ApprovalStatus>, ApiError> {
    let owner = require_owner(&core, &auth)?;
    let id = ObjectId::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user ID".into()))?;
    if id == owner {
        return Err(ApiError::BadRequest(
            "The bootstrap owner is managed by deployment configuration".into(),
        ));
    }
    if !reviewable(body.state) {
        return Err(ApiError::BadRequest(
            "Review must approve, reject, or suspend".into(),
        ));
    }
    if !core
        .users
        .review_account_approval(id, body.expected_revision, body.state, owner)
        .await?
    {
        return Err(ApiError::Conflict(
            "Account missing, deleted, or review revision changed".into(),
        ));
    }
    // User JWTs are invalidated by the new revision on their next admission check.
    // Existing direct data-plane sessions require explicit network revocation work.
    tracing::info!(reviewer = %owner, user_id = %id, state = ?body.state, "Account admission reviewed");
    Ok(Json(core.users.base.find_by_id(id).await?.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_query_parses_real_urlencoded_pagination() {
        let uri = axum::http::Uri::from_static("/?state=approved&page=1&per_page=25");
        let Query(query) = Query::<ApprovalListQuery>::try_from_uri(&uri).expect("valid UI query");
        assert_eq!(query.pagination().unwrap().page, 1);
        assert_eq!(query.pagination().unwrap().per_page, 25);
        assert_eq!(query.state, Some(AccountApprovalState::Approved));
    }
    #[test]
    fn approval_query_defaults_clamps_and_rejects_overflow() {
        for (url, page, size) in [
            ("/", 1, 25),
            ("/?page=0&per_page=0", 1, 1),
            ("/?per_page=101", 1, 100),
        ] {
            let uri: axum::http::Uri = url.parse().unwrap();
            let Query(query) = Query::<ApprovalListQuery>::try_from_uri(&uri).unwrap();
            let p = query.pagination().unwrap();
            assert_eq!((p.page, p.per_page), (page, size));
        }
        let uri = axum::http::Uri::from_static("/?page=18446744073709551615&per_page=100");
        let Query(query) = Query::<ApprovalListQuery>::try_from_uri(&uri).unwrap();
        assert!(query.pagination().is_err());
        for url in ["/?state=owner", "/?page=-1", "/?per_page=wrong"] {
            let uri: axum::http::Uri = url.parse().unwrap();
            assert!(Query::<ApprovalListQuery>::try_from_uri(&uri).is_err());
        }
    }
    #[test]
    fn review_queue_defaults_to_pending_and_legacy_excluding_owner_and_deleted() {
        let owner = ObjectId::new();
        let filter = queue_filter(None, owner);
        assert_eq!(
            filter
                .get_document("_id")
                .unwrap()
                .get_object_id("$ne")
                .unwrap(),
            owner
        );
        assert_eq!(filter.get("deleted_at"), Some(&bson::Bson::Null));
        assert_eq!(filter.get_array("$or").unwrap().len(), 2);
    }

    #[test]
    fn explicit_review_tabs_never_include_other_states() {
        for (state, label) in [
            (AccountApprovalState::Pending, "pending"),
            (AccountApprovalState::Approved, "approved"),
            (AccountApprovalState::Rejected, "rejected"),
            (AccountApprovalState::Suspended, "suspended"),
        ] {
            let filter = queue_filter(Some(state), ObjectId::new());
            assert_eq!(filter.get_str("account_approval.state").unwrap(), label);
            assert!(!filter.contains_key("$or"));
            assert_eq!(filter.get("deleted_at"), Some(&bson::Bson::Null));
        }
    }

    #[test]
    fn legacy_review_tab_includes_documents_without_approval_state() {
        let filter = queue_filter(
            Some(AccountApprovalState::LegacyUnreviewed),
            ObjectId::new(),
        );
        assert_eq!(
            filter.get_array("$or").unwrap(),
            &vec![
                bson::bson!({ "account_approval.state": "legacy_unreviewed" }),
                bson::bson!({ "account_approval.state": { "$exists": false } }),
            ]
        );
    }
    #[test]
    fn account_approval_review_rejects_pending_or_legacy_as_decisions() {
        assert!(!reviewable(AccountApprovalState::Pending));
        assert!(!reviewable(AccountApprovalState::LegacyUnreviewed));
        for state in [
            AccountApprovalState::Approved,
            AccountApprovalState::Rejected,
            AccountApprovalState::Suspended,
        ] {
            assert!(reviewable(state));
        }
    }
}
