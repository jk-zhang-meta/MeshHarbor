// SPDX-License-Identifier: AGPL-3.0-only
//! Optional deployment-wide account admission. Tenant roles cannot approve users.
use crate::{ApiError, Core};
use bson::oid::ObjectId;
use roomler_ai_config::AccountApprovalSettings;
use roomler_ai_db::models::{AccountApprovalState, User};
use roomler_ai_services::auth::Claims;

pub fn owner_id(policy: &AccountApprovalSettings) -> Result<Option<ObjectId>, ApiError> {
    if !policy.enabled {
        return Ok(None);
    }
    policy
        .owner_user_id
        .as_deref()
        .and_then(|id| ObjectId::parse_str(id).ok())
        .map(Some)
        .ok_or_else(|| {
            ApiError::ServiceUnavailable(
                "Account approval enabled without a valid explicit owner_user_id".into(),
            )
        })
}

/// Pure rule shared by HTTP, login and the WebSocket upgrade integration.
pub fn verdict(
    policy: &AccountApprovalSettings,
    user_id: ObjectId,
    state: AccountApprovalState,
    deleted: bool,
    revision: u32,
    presented_revision: Option<u32>,
) -> Result<(), ApiError> {
    let Some(owner) = owner_id(policy)? else {
        return Ok(());
    };
    if deleted {
        return Err(ApiError::Forbidden("Account unavailable".into()));
    }
    let bootstrap_owner = user_id == owner
        && matches!(
            state,
            AccountApprovalState::Pending | AccountApprovalState::LegacyUnreviewed
        );
    if state != AccountApprovalState::Approved && !bootstrap_owner {
        return Err(ApiError::Forbidden(format!(
            "Account approval required: {state:?}"
        )));
    }
    if presented_revision.is_some_and(|v| v != revision) {
        return Err(ApiError::Unauthorized(
            "Account session revoked; sign in again".into(),
        ));
    }
    Ok(())
}

pub fn require_user(core: &Core, user: &User, revision: Option<u32>) -> Result<(), ApiError> {
    let id = user
        .id
        .ok_or_else(|| ApiError::Unauthorized("Account missing identity".into()))?;
    verdict(
        &core.settings.auth.account_approval,
        id,
        user.account_approval.state,
        user.deleted_at.is_some(),
        user.account_approval.revision,
        revision,
    )
}

/// Existing disabled deployments perform no extra query. Enabled mode fails closed
/// on missing rows/storage errors instead of trusting a formerly issued JWT.
pub async fn authorize_claims(core: &Core, claims: &Claims) -> Result<(), ApiError> {
    if !core.settings.auth.account_approval.enabled {
        return Ok(());
    }
    let id = ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::Unauthorized("Invalid user ID".into()))?;
    authorize_user_id(core, id, Some(claims.approval_revision)).await
}

/// Live account gate for delegated credentials. No tenant-wide assumption:
/// devices are governed by their current owner, enrollment by its issuer.
pub async fn authorize_user_id(
    core: &Core,
    id: ObjectId,
    revision: Option<u32>,
) -> Result<(), ApiError> {
    if !core.settings.auth.account_approval.enabled {
        return Ok(());
    }
    let user = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        core.users.base.find_by_id(id),
    )
    .await
    .map_err(|_| ApiError::ServiceUnavailable("Account admission lookup timed out".into()))??;
    require_user(core, &user, revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_approval_disabled_preserves_legacy_behavior() {
        assert!(
            verdict(
                &AccountApprovalSettings::default(),
                ObjectId::new(),
                AccountApprovalState::LegacyUnreviewed,
                true,
                9,
                Some(0)
            )
            .is_ok()
        );
    }
    #[test]
    fn account_approval_is_owner_only_and_fail_closed() {
        let owner = ObjectId::new();
        let p = AccountApprovalSettings {
            enabled: true,
            owner_user_id: Some(owner.to_hex()),
        };
        for state in [
            AccountApprovalState::Pending,
            AccountApprovalState::Rejected,
            AccountApprovalState::Suspended,
            AccountApprovalState::LegacyUnreviewed,
        ] {
            assert!(verdict(&p, ObjectId::new(), state, false, 0, None).is_err());
        }
        assert!(verdict(&p, owner, AccountApprovalState::Pending, false, 0, None).is_ok());
        for state in [
            AccountApprovalState::Rejected,
            AccountApprovalState::Suspended,
        ] {
            assert!(verdict(&p, owner, state, false, 0, None).is_err());
        }
        assert!(verdict(&p, owner, AccountApprovalState::Approved, true, 0, None).is_err());
        assert!(
            verdict(
                &AccountApprovalSettings {
                    enabled: true,
                    owner_user_id: None
                },
                owner,
                AccountApprovalState::Approved,
                false,
                0,
                None
            )
            .is_err()
        );
    }
    #[test]
    fn account_approval_rejects_stale_tokens_after_review() {
        let p = AccountApprovalSettings {
            enabled: true,
            owner_user_id: Some(ObjectId::new().to_hex()),
        };
        let id = ObjectId::new();
        assert!(verdict(&p, id, AccountApprovalState::Approved, false, 2, Some(1)).is_err());
        assert!(verdict(&p, id, AccountApprovalState::Approved, false, 2, Some(2)).is_ok());
    }
}
