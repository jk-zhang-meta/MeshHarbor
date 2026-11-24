// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub user_id: ObjectId,
    pub notification_type: NotificationType,
    pub title: String,
    pub body: String,
    pub link: Option<String>,
    pub source: NotificationSource,
    #[serde(default)]
    pub is_read: bool,
    pub read_at: Option<DateTime>,
    pub created_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    Message,
    Mention,
    Reaction,
    Invite,
    Call,
    TaskComplete,
    /// A remote-control session is awaiting the device owner's approval
    /// (Phase 4 owner-consent). `link` points at the in-app consent page.
    ConsentRequest,
    /// FR-90 P1a-2 — an agent session's tool call is waiting for a driver.
    /// `link` points at the session's room; nothing in it says which tool or
    /// what it would do.
    ApprovalRequest,
    /// FR-133 — one of the organization's devices was moved to another
    /// organization by a person signed in at it. Sent to the org's device
    /// admins; it names the device and nothing of the other organization.
    DeviceMoved,
    /// A type this build does not know — a newer server's — read as itself
    /// rather than refused, so one new kind of notification cannot fail a
    /// user's whole list on an older pod mid-roll.
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSource {
    pub entity_type: String,
    pub entity_id: ObjectId,
    pub actor_id: Option<ObjectId>,
}

impl Notification {
    pub const COLLECTION: &'static str = "notifications";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored spelling of the newest kind, and a kind from a newer
    /// server read as `Other` — through BSON, which is how a list is read.
    #[test]
    fn a_notification_kind_this_build_does_not_know_is_read_not_refused() {
        assert_eq!(
            bson::to_bson(&NotificationType::ApprovalRequest).unwrap(),
            bson::Bson::String("approval_request".into())
        );
        assert_eq!(
            bson::to_bson(&NotificationType::DeviceMoved).unwrap(),
            bson::Bson::String("device_moved".into())
        );
        let doc = bson::doc! { "t": "quorum_reached" };
        #[derive(Deserialize)]
        struct T {
            t: NotificationType,
        }
        let t: T = bson::from_document(doc).unwrap();
        assert!(matches!(t.t, NotificationType::Other));
    }
}
