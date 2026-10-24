// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit single-device sharing. This document is not tenant membership or a network route.
use bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceSharePermissions {
    #[serde(default)]
    pub ssh: bool,
    #[serde(default)]
    pub desktop_view: bool,
    #[serde(default)]
    pub desktop_control: bool,
    #[serde(default)]
    pub files_read: bool,
    #[serde(default)]
    pub files_write: bool,
}
impl DeviceSharePermissions {
    pub fn any(&self) -> bool {
        self.ssh || self.desktop_view || self.desktop_control || self.files_read || self.files_write
    }
    pub fn valid(&self) -> bool {
        (!self.desktop_control || self.desktop_view) && (!self.files_write || self.files_read)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceShareGrant {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub device_id: ObjectId,
    /// The tenant is a snapshot to detect moves, NEVER a membership entitlement.
    pub tenant_id: ObjectId,
    pub owner_user_id: ObjectId,
    pub recipient_user_id: ObjectId,
    pub permissions: DeviceSharePermissions,
    /// Exact ports on this device only; no CIDR, UDP, subnet, exit, or onward hop.
    pub tcp_ports: Vec<u16>,
    pub created_at: DateTime,
    pub expires_at: DateTime,
    pub revoked_at: Option<DateTime>,
    pub revision: u32,
}
impl DeviceShareGrant {
    pub const COLLECTION: &'static str = "device_share_grants";
    pub const MAX_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
    pub const MAX_TCP_PORTS: usize = 32;
    pub fn live_at(&self, now: DateTime) -> bool {
        self.revoked_at.is_none() && self.created_at <= now && now < self.expires_at
    }
    pub fn allows(&self, operation: DeviceShareOperation) -> bool {
        match operation {
            DeviceShareOperation::Ssh => self.permissions.ssh,
            DeviceShareOperation::DesktopView => self.permissions.desktop_view,
            DeviceShareOperation::DesktopControl => {
                self.permissions.desktop_view && self.permissions.desktop_control
            }
            DeviceShareOperation::FilesRead => self.permissions.files_read,
            DeviceShareOperation::FilesWrite => {
                self.permissions.files_read && self.permissions.files_write
            }
            DeviceShareOperation::TcpConnect(port) => port != 0 && self.tcp_ports.contains(&port),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceShareOperation {
    Ssh,
    DesktopView,
    DesktopControl,
    FilesRead,
    FilesWrite,
    TcpConnect(u16),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_share_permissions_never_imply_another_service() {
        let now = DateTime::from_millis(1000);
        let mut g = DeviceShareGrant {
            id: None,
            device_id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            owner_user_id: ObjectId::new(),
            recipient_user_id: ObjectId::new(),
            permissions: DeviceSharePermissions {
                ssh: true,
                ..Default::default()
            },
            tcp_ports: vec![22],
            created_at: now,
            expires_at: DateTime::from_millis(2000),
            revoked_at: None,
            revision: 0,
        };
        assert!(g.allows(DeviceShareOperation::Ssh));
        assert!(g.allows(DeviceShareOperation::TcpConnect(22)));
        assert!(!g.allows(DeviceShareOperation::TcpConnect(23)));
        assert!(!g.allows(DeviceShareOperation::TcpConnect(0)));
        assert!(!g.allows(DeviceShareOperation::FilesRead));
        assert!(!g.allows(DeviceShareOperation::DesktopView));
        assert!(g.live_at(now));
        assert!(!g.live_at(g.expires_at));
        g.revoked_at = Some(now);
        assert!(!g.live_at(now));
    }
    #[test]
    fn device_share_wire_cannot_request_tenant_exit_or_reshare() {
        for field in ["tenant_member", "subnet", "exit_node", "reshare", "transit"] {
            let value = serde_json::json!({(field):true});
            assert!(serde_json::from_value::<DeviceSharePermissions>(value).is_err());
        }
        assert!(
            !DeviceSharePermissions {
                desktop_control: true,
                ..Default::default()
            }
            .valid()
        );
        assert!(
            !DeviceSharePermissions {
                files_write: true,
                ..Default::default()
            }
            .valid()
        );
    }
}
