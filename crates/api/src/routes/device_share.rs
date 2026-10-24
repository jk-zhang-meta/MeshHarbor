// SPDX-License-Identifier: AGPL-3.0-only
//! Single-device share management, not a tenant invitation or service session.
use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, doc, oid::ObjectId};
use roomler_ai_db::models::{DeviceShareGrant, DeviceShareOperation, DeviceSharePermissions};
use roomler_ai_remote_control::models::AgentStatus;
use roomler_ai_services::dao::{
    agent::AgentDao, base::PaginationParams, device_share::DeviceShareDao,
};
use roomler_core::{ApiError, Core, extractors::auth::AuthUser};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateShare {
    pub device_id: String,
    pub recipient_user_id: String,
    pub permissions: DeviceSharePermissions,
    #[serde(default)]
    pub tcp_ports: Vec<u16>,
    pub expires_in_secs: u64,
}
#[derive(Serialize)]
pub struct ShareView {
    pub id: String,
    pub device_id: String,
    pub owner_user_id: String,
    pub recipient_user_id: String,
    pub permissions: DeviceSharePermissions,
    pub tcp_ports: Vec<u16>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub revision: u32,
}
impl From<DeviceShareGrant> for ShareView {
    fn from(g: DeviceShareGrant) -> Self {
        Self {
            id: g.id.map(|i| i.to_hex()).unwrap_or_default(),
            device_id: g.device_id.to_hex(),
            owner_user_id: g.owner_user_id.to_hex(),
            recipient_user_id: g.recipient_user_id.to_hex(),
            permissions: g.permissions,
            tcp_ports: g.tcp_ports,
            created_at_ms: g.created_at.timestamp_millis(),
            expires_at_ms: g.expires_at.timestamp_millis(),
            revoked_at_ms: g.revoked_at.map(|d| d.timestamp_millis()),
            revision: g.revision,
        }
    }
}
fn oid(id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(id).map_err(|_| ApiError::BadRequest("Invalid object ID".into()))
}
fn validate(body: &mut CreateShare) -> Result<(), ApiError> {
    if body.expires_in_secs == 0 || body.expires_in_secs > DeviceShareGrant::MAX_LIFETIME_SECS {
        return Err(ApiError::BadRequest(
            "Share lifetime must be 1 second to 30 days".into(),
        ));
    }
    if !body.permissions.valid() {
        return Err(ApiError::BadRequest(
            "Desktop control requires view; file write requires read".into(),
        ));
    }
    if body.tcp_ports.len() > DeviceShareGrant::MAX_TCP_PORTS || body.tcp_ports.contains(&0) {
        return Err(ApiError::BadRequest(
            "At most 32 nonzero TCP ports are allowed".into(),
        ));
    }
    body.tcp_ports.sort_unstable();
    body.tcp_ports.dedup();
    if !body.permissions.any() && body.tcp_ports.is_empty() {
        return Err(ApiError::BadRequest(
            "At least one explicit service or TCP port is required".into(),
        ));
    }
    Ok(())
}
pub async fn create(
    State(core): State<Core>,
    auth: AuthUser,
    Json(mut body): Json<CreateShare>,
) -> Result<Json<ShareView>, ApiError> {
    roomler_core::device_share::require_enabled(&core)?;
    validate(&mut body)?;
    let device = oid(&body.device_id)?;
    let recipient = oid(&body.recipient_user_id)?;
    if recipient == auth.user_id {
        return Err(ApiError::BadRequest(
            "A share must name another account".into(),
        ));
    }
    let agent = AgentDao::new(&core.db).base.find_by_id(device).await?;
    // Only actual ownership, never MANAGE_AGENTS, org admin, or platform admin.
    if agent.owner_user_id != auth.user_id
        || agent.deleted_at.is_some()
        || agent.status == AgentStatus::Quarantined
    {
        return Err(ApiError::Forbidden(
            "Only the active device owner may share it".into(),
        ));
    }
    let owner = core.users.base.find_by_id(auth.user_id).await?;
    roomler_core::admission::require_user(&core, &owner, None)?;
    if !owner.is_verified {
        return Err(ApiError::Forbidden("Device owner must verify email".into()));
    }
    let user = core.users.base.find_by_id(recipient).await?;
    roomler_core::device_share::require_recipient(&user)?;
    let tenant = core.tenants.base.find_by_id(agent.tenant_id).await?;
    if tenant.deleted_at.is_some() || tenant.is_archived {
        return Err(ApiError::Forbidden(
            "Device organization unavailable".into(),
        ));
    }
    if !core
        .tenants
        .is_member(agent.tenant_id, auth.user_id)
        .await?
    {
        return Err(ApiError::Forbidden(
            "Device owner no longer belongs to its organization".into(),
        ));
    }
    let now = DateTime::now();
    let grant = DeviceShareGrant {
        id: None,
        device_id: device,
        tenant_id: agent.tenant_id,
        owner_user_id: auth.user_id,
        recipient_user_id: recipient,
        permissions: body.permissions,
        tcp_ports: body.tcp_ports,
        created_at: now,
        expires_at: DateTime::from_millis(
            now.timestamp_millis() + body.expires_in_secs as i64 * 1000,
        ),
        revoked_at: None,
        revision: 0,
    };
    let dao = DeviceShareDao::new(&core.db);
    let id = dao.base.insert_one(&grant).await?;
    Ok(Json(dao.base.find_by_id(id).await?.into()))
}
#[derive(Deserialize, Default)]
pub struct ShareListQuery {
    pub direction: Option<String>,
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}
#[derive(Serialize)]
pub struct SharePage {
    pub items: Vec<ShareView>,
    pub page: u64,
    pub total: u64,
}
pub async fn list(
    State(core): State<Core>,
    auth: AuthUser,
    Query(query): Query<ShareListQuery>,
) -> Result<Json<SharePage>, ApiError> {
    roomler_core::device_share::require_enabled(&core)?;
    let field = match query.direction.as_deref().unwrap_or("received") {
        "received" => "recipient_user_id",
        "sent" => "owner_user_id",
        _ => {
            return Err(ApiError::BadRequest(
                "direction must be received or sent".into(),
            ));
        }
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(25).clamp(1, 100);
    if (page - 1)
        .checked_mul(per_page)
        .is_none_or(|n| n > i64::MAX as u64)
    {
        return Err(ApiError::BadRequest("Page out of range".into()));
    }
    let mut filter = bson::Document::new();
    filter.insert(field, auth.user_id);
    let result = DeviceShareDao::new(&core.db)
        .base
        .find_paginated(
            filter,
            Some(doc! {"created_at":-1,"_id":-1}),
            &PaginationParams {
                page,
                per_page,
                before: None,
            },
        )
        .await?;
    Ok(Json(SharePage {
        items: result.items.into_iter().map(Into::into).collect(),
        page,
        total: result.total,
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeShare {
    pub expected_revision: u32,
}
pub async fn revoke(
    State(core): State<Core>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<RevokeShare>,
) -> Result<Json<ShareView>, ApiError> {
    // Revocation remains available to the original grantor even after ownership moves.
    if body.expected_revision == u32::MAX {
        return Err(ApiError::BadRequest("Share revision out of range".into()));
    }
    let dao = DeviceShareDao::new(&core.db);
    let id = oid(&id)?;
    let grant = dao.base.find_by_id(id).await?;
    if grant.owner_user_id != auth.user_id {
        return Err(ApiError::NotFound("Share not found".into()));
    }
    let revised = dao
        .revoke(id, auth.user_id, body.expected_revision, DateTime::now())
        .await?
        .ok_or_else(|| ApiError::Conflict("Share changed; reload before reviewing".into()))?;
    Ok(Json(revised.into()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckShare {
    pub operation: String,
    pub port: Option<u16>,
}
impl CheckShare {
    fn operation(&self) -> Result<DeviceShareOperation, ApiError> {
        match (self.operation.as_str(), self.port) {
            ("ssh", None) => Ok(DeviceShareOperation::Ssh),
            ("desktop_view", None) => Ok(DeviceShareOperation::DesktopView),
            ("desktop_control", None) => Ok(DeviceShareOperation::DesktopControl),
            ("files_read", None) => Ok(DeviceShareOperation::FilesRead),
            ("files_write", None) => Ok(DeviceShareOperation::FilesWrite),
            ("tcp_connect", Some(port)) if port != 0 => Ok(DeviceShareOperation::TcpConnect(port)),
            _ => Err(ApiError::BadRequest(
                "Unknown operation or invalid port".into(),
            )),
        }
    }
}
#[derive(Serialize)]
pub struct ShareCheck {
    pub authorized: bool,
    pub device_id: String,
    pub grant_revision: u32,
}
/// Tests/clients can inspect the CURRENT decision. No bearer capability is minted.
/// Real service entry points must still call the PDP themselves, not trust this response.
pub async fn check(
    State(core): State<Core>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<CheckShare>,
) -> Result<Json<ShareCheck>, ApiError> {
    let grant_id = oid(&id)?;
    let access = roomler_core::device_share::authorize_grant(
        &core,
        auth.user_id,
        grant_id,
        body.operation()?,
    )
    .await?;
    Ok(Json(ShareCheck {
        authorized: true,
        device_id: access.grant.device_id.to_hex(),
        grant_revision: access.grant.revision,
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn body() -> CreateShare {
        CreateShare {
            device_id: ObjectId::new().to_hex(),
            recipient_user_id: ObjectId::new().to_hex(),
            permissions: DeviceSharePermissions {
                ssh: true,
                ..Default::default()
            },
            tcp_ports: vec![22, 22],
            expires_in_secs: 60,
        }
    }
    #[test]
    fn device_share_request_bounds_are_explicit() {
        let mut b = body();
        validate(&mut b).unwrap();
        assert_eq!(b.tcp_ports, vec![22]);
        b.tcp_ports = vec![0];
        assert!(validate(&mut b).is_err());
        b = body();
        b.expires_in_secs = DeviceShareGrant::MAX_LIFETIME_SECS + 1;
        assert!(validate(&mut b).is_err());
        assert!(serde_json::from_value::<CreateShare>(serde_json::json!({"device_id":"x","recipient_user_id":"y","permissions":{"ssh":true},"expires_in_secs":60,"tenant_id":"injected"})).is_err());
    }
}
