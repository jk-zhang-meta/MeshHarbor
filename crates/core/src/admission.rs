// SPDX-License-Identifier: AGPL-3.0-only
//! Optional deployment-wide account admission. Tenant roles cannot approve users.
use crate::{ApiError, Core};
use bson::oid::ObjectId;
use meshharbor_config::AccountApprovalSettings;
use meshharbor_db::models::{AccountApprovalState, User};
use meshharbor_services::auth::Claims;

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
    )?;
    if user.deleted_at.is_some() {
        return Err(ApiError::Unauthorized("Account unavailable".into()));
    }
    if revision.is_some_and(|v| v != user.account_approval.revision) {
        return Err(ApiError::Unauthorized(
            "Account session revoked; sign in again".into(),
        ));
    }
    Ok(())
}

pub fn has_verified_account_email(user: &User) -> bool {
    if user.deleted_at.is_some() || !user.is_verified {
        return false;
    }
    let Some((local, domain)) = user.email.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.eq_ignore_ascii_case("invalid")
        && !domain.to_ascii_lowercase().ends_with(".invalid")
        && !user
            .email
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
}

pub fn parse_trusted_frontend_url(raw: &str) -> Option<(reqwest::Url, Vec<String>)> {
    let trimmed = raw.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(trimmed).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().contains('%')
        || url.path().contains("//")
    {
        return None;
    }
    let segs = url
        .path()
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    Some((url, segs))
}

pub fn normalized_frontend_prefix(raw: &str) -> Option<String> {
    let (mut url, segs) = parse_trusted_frontend_url(raw)?;
    let path = if segs.is_empty() {
        String::new()
    } else {
        format!("/{}", segs.join("/"))
    };
    url.set_path(&path);
    Some(url.to_string().trim_end_matches('/').to_owned())
}

pub fn same_trusted_frontend_prefix(stored: &str, configured: &str) -> bool {
    let (Some((a, a_segs)), Some((b, b_segs))) = (
        parse_trusted_frontend_url(stored),
        parse_trusted_frontend_url(configured),
    ) else {
        return false;
    };
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
        && a_segs == b_segs
}

/// Credential rotation and native session revocation apply even when optional
/// account approval is disabled. Missing rows/storage errors fail closed.
pub async fn authorize_claims(core: &Core, claims: &Claims) -> Result<(), ApiError> {
    let id = ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::Unauthorized("Invalid user ID".into()))?;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let user = match core.users.base.find_by_id(id).await {
            Ok(u) => u,
            Err(meshharbor_services::dao::base::DaoError::NotFound) => {
                return Err(ApiError::Unauthorized("Account unavailable".into()));
            }
            Err(meshharbor_services::dao::base::DaoError::Mongo(_)) => {
                return Err(ApiError::ServiceUnavailable("Account lookup failed".into()));
            }
            Err(other) => return Err(other.into()),
        };
        require_user(core, &user, Some(claims.approval_revision))?;
        if let Some(ref sid_raw) = claims.native_sid {
            if !has_verified_account_email(&user) {
                return Err(ApiError::Unauthorized(
                    "Verified account email required".into(),
                ));
            }
            let Some(sec_rev) = user.security_revision() else {
                return Err(ApiError::Unauthorized(
                    "Account security revision unavailable".into(),
                ));
            };
            let sid = ObjectId::parse_str(sid_raw)
                .map_err(|_| ApiError::Unauthorized("Invalid native session".into()))?;
            let row = meshharbor_services::dao::native_session::find_session(&core.db, sid)
                .await
                .map_err(|_| ApiError::ServiceUnavailable("Session lookup failed".into()))?
                .ok_or_else(|| ApiError::Unauthorized("Native session revoked".into()))?;
            if row.user_id != id
                || row.revoked_at.is_some()
                || row.expires_at <= bson::DateTime::now()
                || row.security_revision != sec_rev
                || row.approval_revision != user.account_approval.revision
                || !same_trusted_frontend_prefix(
                    &row.trusted_frontend_origin_prefix,
                    &core.settings.app.frontend_url,
                )
            {
                return Err(ApiError::Unauthorized("Native session revoked".into()));
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| ApiError::ServiceUnavailable("Account lookup timed out".into()))?
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
