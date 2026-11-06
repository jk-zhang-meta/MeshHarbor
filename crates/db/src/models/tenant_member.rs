// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{Bson, DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

use super::tenant::NotificationLevel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMember {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub user_id: ObjectId,
    /// Preserve raw BSON so corrupt counters cannot block membership/role
    /// administration or change during a full-document round trip. Native
    /// authorization must use `security_revision`, never coerce this raw value.
    #[serde(
        default,
        deserialize_with = "deserialize_security_rev",
        skip_serializing_if = "Option::is_none"
    )]
    pub security_rev: Option<Bson>,
    pub nickname: Option<String>,
    #[serde(default)]
    pub role_ids: Vec<ObjectId>,
    pub joined_at: DateTime,
    #[serde(default)]
    pub is_pending: bool,
    #[serde(default)]
    pub is_muted: bool,
    pub notification_override: Option<NotificationLevel>,
    pub invited_by: Option<ObjectId>,
    pub last_seen_at: Option<DateTime>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

fn deserialize_security_rev<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Bson>, D::Error> {
    // Missing fields take serde's default; explicit null must remain present.
    Bson::deserialize(deserializer).map(Some)
}

impl TenantMember {
    pub const COLLECTION: &'static str = "tenant_members";

    /// Missing, non-Int64, non-positive, and exhausted (`i64::MAX`) counters
    /// return `None` and refuse native shared-SSH authority.
    pub fn security_revision(&self) -> Option<i64> {
        match self.security_rev.as_ref() {
            Some(Bson::Int64(revision)) if *revision > 0 && *revision < i64::MAX => Some(*revision),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member() -> TenantMember {
        let now = DateTime::now();
        TenantMember {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            user_id: ObjectId::new(),
            security_rev: Some(1_i64.into()),
            nickname: None,
            role_ids: vec![ObjectId::new()],
            joined_at: now,
            is_pending: false,
            is_muted: false,
            notification_override: None,
            invited_by: None,
            last_seen_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn legacy_security_revision_is_unknown_without_a_read_default() {
        let mut document = bson::to_document(&member()).unwrap();
        assert_eq!(document.get_i64("security_rev").unwrap(), 1);
        document.remove("security_rev");
        let legacy: TenantMember = bson::from_document(document).unwrap();
        assert_eq!(legacy.security_rev, None);
        assert_eq!(legacy.security_revision(), None);
        assert!(
            !bson::to_document(&legacy)
                .unwrap()
                .contains_key("security_rev")
        );
    }

    #[test]
    fn invalid_security_revisions_round_trip_losslessly_without_authority() {
        for raw in [
            Bson::Null,
            Bson::Boolean(true),
            Bson::String("invalid".into()),
            Bson::Double(1.0),
            Bson::Double(1.5),
            Bson::Int32(1),
            Bson::Int64(0),
            Bson::Int64(-1),
            Bson::Int64(i64::MAX),
            Bson::Array(vec![Bson::Int64(1)]),
            Bson::Document(bson::doc! {"value": 1_i64}),
        ] {
            let mut document = bson::to_document(&member()).unwrap();
            document.insert("security_rev", raw.clone());
            let parsed: TenantMember = bson::from_document(document.clone()).unwrap();
            assert_eq!(parsed.security_rev.as_ref(), Some(&raw));
            assert_eq!(parsed.security_revision(), None);
            assert_eq!(bson::to_document(&parsed).unwrap(), document);
        }
        for valid in [1_i64, i64::MAX - 1] {
            let mut m = member();
            m.security_rev = Some(Bson::Int64(valid));
            assert_eq!(m.security_revision(), Some(valid));
        }
    }
}
