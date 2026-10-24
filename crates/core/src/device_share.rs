// SPDX-License-Identifier: AGPL-3.0-only
//! Additive sharing PDP. NEVER substitutes a share for org membership or relay eligibility.
//! Callers retain device consent, service enablement, org kill switches and OS permissions.
use crate::{ApiError, Core};
use bson::{DateTime, oid::ObjectId};
use roomler_ai_db::models::{AccountApprovalState, DeviceShareGrant, DeviceShareOperation, User};
use roomler_ai_remote_control::models::{Agent, AgentStatus};
use roomler_ai_services::dao::{agent::AgentDao, device_share::DeviceShareDao};

pub fn require_enabled(core: &Core) -> Result<(), ApiError> {
    if !core.settings.auth.account_approval.enabled {
        return Err(ApiError::ServiceUnavailable(
            "Device sharing requires central account approval".into(),
        ));
    }
    crate::admission::owner_id(&core.settings.auth.account_approval)?;
    Ok(())
}
pub fn require_recipient(user: &User) -> Result<(), ApiError> {
    if user.deleted_at.is_some()
        || !user.is_verified
        || user.account_approval.state != AccountApprovalState::Approved
    {
        return Err(ApiError::Forbidden(
            "Device sharing requires an explicitly approved, verified recipient".into(),
        ));
    }
    Ok(())
}
/// Lookup bounds the WHOLE operation, so unavailable storage fails closed promptly.
pub async fn authorize(
    core: &Core,
    recipient: ObjectId,
    device: ObjectId,
    operation: DeviceShareOperation,
) -> Result<SharedDeviceAccess, ApiError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        authorize_inner(core, recipient, device, None, operation),
    )
    .await
    .map_err(|_| ApiError::ServiceUnavailable("Device share authorization timed out".into()))?
}
/// Grant-ID variant prevents a check of one grant from borrowing another grant's rights.
pub async fn authorize_grant(
    core: &Core,
    recipient: ObjectId,
    grant_id: ObjectId,
    operation: DeviceShareOperation,
) -> Result<SharedDeviceAccess, ApiError> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let grant = DeviceShareDao::new(&core.db)
            .base
            .find_by_id(grant_id)
            .await?;
        if grant.recipient_user_id != recipient {
            // Match the missing-row DAO response without revealing grant existence.
            return Err(ApiError::NotFound("Resource not found".into()));
        }
        authorize_inner(core, recipient, grant.device_id, Some(grant_id), operation).await
    })
    .await
    .map_err(|_| ApiError::ServiceUnavailable("Device share authorization timed out".into()))?
}
pub struct SharedDeviceAccess {
    pub grant: DeviceShareGrant,
    pub agent: Agent,
}
async fn authorize_inner(
    core: &Core,
    recipient: ObjectId,
    device: ObjectId,
    grant_id: Option<ObjectId>,
    operation: DeviceShareOperation,
) -> Result<SharedDeviceAccess, ApiError> {
    require_enabled(core)?;
    let user = core.users.base.find_by_id(recipient).await?;
    require_recipient(&user)?;
    let agent = AgentDao::new(&core.db).base.find_by_id(device).await?;
    if agent.deleted_at.is_some() || agent.status == AgentStatus::Quarantined {
        return Err(ApiError::Forbidden("Shared device unavailable".into()));
    }
    let tenant = core.tenants.base.find_by_id(agent.tenant_id).await?;
    // This native shared-SSH path has no MFA challenge/proof. Reject required
    // MFA rather than treating an ordinary access JWT as second-factor proof.
    // Reached by metadata, WS upgrade and live lease PDP, including legacy files.
    if operation == DeviceShareOperation::Ssh
        && (user.is_mfa_enabled || tenant.settings.mfa_required)
    {
        return Err(ApiError::Forbidden(
            "Native shared SSH cannot satisfy required MFA".into(),
        ));
    }
    if tenant.deleted_at.is_some() || tenant.is_archived {
        return Err(ApiError::Forbidden(
            "Shared device organization unavailable".into(),
        ));
    }
    if !core
        .tenants
        .is_member(agent.tenant_id, agent.owner_user_id)
        .await?
    {
        return Err(ApiError::Forbidden(
            "Device owner no longer belongs to its organization".into(),
        ));
    }
    let owner = core.users.base.find_by_id(agent.owner_user_id).await?;
    crate::admission::require_user(core, &owner, None)?;
    if !owner.is_verified {
        return Err(ApiError::Forbidden("Device owner unavailable".into()));
    }
    let now = DateTime::now();
    for grant in DeviceShareDao::new(&core.db)
        .active_for(recipient, device, now)
        .await?
    {
        if grant_id.is_none_or(|id| grant.id == Some(id))
            && grant.owner_user_id == agent.owner_user_id
            && grant.tenant_id == agent.tenant_id
            && grant.live_at(now)
            && grant.allows(operation)
        {
            return Ok(SharedDeviceAccess { grant, agent });
        }
    }
    Err(ApiError::Forbidden(
        "No active device share permits this operation".into(),
    ))
}
