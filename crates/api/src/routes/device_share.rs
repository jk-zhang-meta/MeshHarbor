// SPDX-License-Identifier: AGPL-3.0-only
//! Single-device share management, not a tenant invitation or service session.
use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, doc, oid::ObjectId};
use roomler_ai_db::models::{
    DeviceShareGrant, DeviceShareOperation, DeviceSharePermissions, User,
    device_share::valid_share_account,
};
use roomler_ai_remote_control::models::{AgentStatus, OsKind};
use roomler_ai_services::dao::{
    agent::AgentDao,
    base::{DaoError, PaginationParams},
    device_share::DeviceShareDao,
};
use roomler_core::{ApiError, Core, extractors::auth::AuthUser};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateShare {
    pub device_id: String,
    /// The recipient's account id. Leave it empty and name them by [`Self::recipient`] instead;
    /// exactly one of the two must be given.
    #[serde(default)]
    pub recipient_user_id: String,
    /// The recipient's exact username, or their email address, resolved here so a person
    /// never has to know an account id to share a device.
    #[serde(default)]
    pub recipient: Option<String>,
    pub permissions: DeviceSharePermissions,
    #[serde(default)]
    pub tcp_ports: Vec<u16>,
    pub expires_in_secs: u64,
    /// The device account an SSH share runs as. Required with `permissions.ssh`, refused without.
    #[serde(default)]
    pub ssh_account: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_account: Option<String>,
    /// Display names, resolved when the record is read; absent once the row is gone. The ids
    /// above stay the identity — a name is only what a person reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_username: Option<String>,
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
            ssh_account: g.ssh_account,
            device_name: None,
            owner_username: None,
            recipient_username: None,
        }
    }
}
/// Attach device and account names to share records in two batched reads.
async fn named(core: &Core, grants: Vec<DeviceShareGrant>) -> Result<Vec<ShareView>, ApiError> {
    let devices: Vec<ObjectId> = grants
        .iter()
        .map(|g| g.device_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let people: Vec<ObjectId> = grants
        .iter()
        .flat_map(|g| [g.owner_user_id, g.recipient_user_id])
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let device_names: HashMap<ObjectId, String> = if devices.is_empty() {
        HashMap::new()
    } else {
        AgentDao::new(&core.db)
            .base
            .find_by_ids(&devices)
            .await?
            .into_iter()
            .filter_map(|a| a.id.map(|id| (id, a.name)))
            .collect()
    };
    let usernames: HashMap<ObjectId, String> = if people.is_empty() {
        HashMap::new()
    } else {
        core.users
            .base
            .find_by_ids(&people)
            .await?
            .into_iter()
            .filter_map(|u| u.id.map(|id| (id, u.username)))
            .collect()
    };
    Ok(grants
        .into_iter()
        .map(|g| {
            let (device, owner, recipient) = (g.device_id, g.owner_user_id, g.recipient_user_id);
            let mut view = ShareView::from(g);
            view.device_name = device_names.get(&device).cloned();
            view.owner_username = usernames.get(&owner).cloned();
            view.recipient_username = usernames.get(&recipient).cloned();
            view
        })
        .collect())
}
/// One refusal for every reason a NAMED recipient cannot be used — no account, not approved,
/// not verified, deleted — so the share form cannot be used to learn which usernames or
/// addresses hold an account, or what state it is in. A storage failure is still a 500.
const NO_SUCH_RECIPIENT: &str = "No approved, verified account matches that username or email";
async fn named_recipient(core: &Core, login: &str) -> Result<User, ApiError> {
    let login = login.trim();
    let refuse = || ApiError::BadRequest(NO_SUCH_RECIPIENT.into());
    if login.is_empty() || login.len() > 320 {
        return Err(refuse());
    }
    let lookup = |candidate: String| async move {
        if candidate.contains('@') {
            core.users.find_by_email(&candidate).await
        } else {
            core.users.find_by_username(&candidate).await
        }
    };
    let found = match lookup(login.to_string()).await {
        // Addresses are stored as typed at registration; a differently-cased entry falls back
        // to the lowercase form most accounts were created with.
        Err(DaoError::NotFound) if login.contains('@') && login != login.to_lowercase() => {
            lookup(login.to_lowercase()).await
        }
        other => other,
    };
    let user = match found {
        Ok(user) => user,
        Err(DaoError::NotFound) => return Err(refuse()),
        Err(e) => return Err(e.into()),
    };
    roomler_core::device_share::require_recipient(&user).map_err(|_| refuse())?;
    Ok(user)
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
    body.ssh_account = body
        .ssh_account
        .take()
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty());
    match (&body.ssh_account, body.permissions.ssh) {
        (None, true) => {
            return Err(ApiError::BadRequest(
                "Choose the device account this SSH share runs as".into(),
            ));
        }
        (Some(_), false) => {
            return Err(ApiError::BadRequest(
                "A device account is chosen only for an SSH share".into(),
            ));
        }
        // The device refuses to become uid 0 by name (`exec.rs`), so a root share could
        // never connect: root rights come from an administrator account instead.
        (Some(a), true) if a == "root" => {
            return Err(ApiError::BadRequest(
                "root cannot be shared directly; create an administrator account for the recipient"
                    .into(),
            ));
        }
        (Some(a), true) if !valid_share_account(a) => {
            return Err(ApiError::BadRequest(
                "The device account must be a Linux/macOS user name (lowercase letters, digits, _ and -)"
                    .into(),
            ));
        }
        _ => {}
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
    let named_login = match (body.recipient_user_id.is_empty(), body.recipient.as_deref()) {
        (false, None) => None,
        (true, Some(login)) => Some(login.to_string()),
        _ => {
            return Err(ApiError::BadRequest(
                "Name the recipient by exactly one of recipient_user_id or recipient".into(),
            ));
        }
    };
    let by_id = if named_login.is_none() {
        let recipient = oid(&body.recipient_user_id)?;
        if recipient == auth.user_id {
            return Err(ApiError::BadRequest(
                "A share must name another account".into(),
            ));
        }
        Some(recipient)
    } else {
        None
    };
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
    // A chosen account is a Unix account: Windows cannot become one without its password.
    if body.permissions.ssh && agent.os == OsKind::Windows {
        return Err(ApiError::BadRequest(
            "SSH sharing is available for Linux and macOS devices".into(),
        ));
    }
    let owner = core.users.base.find_by_id(auth.user_id).await?;
    roomler_core::admission::require_user(&core, &owner, None)?;
    if !owner.is_verified {
        return Err(ApiError::Forbidden("Device owner must verify email".into()));
    }
    let recipient = match (by_id, named_login) {
        (Some(id), _) => {
            let user = core.users.base.find_by_id(id).await?;
            roomler_core::device_share::require_recipient(&user)?;
            id
        }
        (None, Some(login)) => {
            let user = named_recipient(&core, &login).await?;
            let id = user
                .id
                .ok_or_else(|| ApiError::Internal("recipient row without an id".into()))?;
            if id == auth.user_id {
                return Err(ApiError::BadRequest(
                    "A share must name another account".into(),
                ));
            }
            id
        }
        (None, None) => unreachable!("one recipient form was required above"),
    };
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
        ssh_account: body.ssh_account,
    };
    let dao = DeviceShareDao::new(&core.db);
    let id = dao.base.insert_one(&grant).await?;
    let stored = dao.base.find_by_id(id).await?;
    Ok(Json(named(&core, vec![stored]).await?.remove(0)))
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
        items: named(&core, result.items).await?,
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
            recipient: None,
            permissions: DeviceSharePermissions {
                ssh: true,
                ..Default::default()
            },
            tcp_ports: vec![22, 22],
            expires_in_secs: 60,
            ssh_account: Some("alice".into()),
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
