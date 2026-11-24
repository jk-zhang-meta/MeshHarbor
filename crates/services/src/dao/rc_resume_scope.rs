// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 — `rc_resume_scope`: the orgs and devices a platform admin lets keep
//! a live remote session through the loss of the device's control socket
//! (spec §4.1, D4). One row per target, `{kind: all | org | device, id, note,
//! by, at}`, unique `(kind, id)`; `all` has no id.
//!
//! Owned by the `fleet` module, which carries its index set and its route
//! (`/api/admin/rc-resume-scope`): the agent hub that reads the scope when a
//! device registers is fleet's, and `remote` reaches fleet, never the other
//! way round.
//!
//! The scope says which devices a window is announced to; the window itself is
//! `rc.session_resume_secs`, the ceiling and the fleet-wide off, and nothing
//! reads the scope while it is 0. An id that names no org or device is kept
//! and matches nothing. No TTL: an operator's list, as `growth_exclusions` is.

use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use mongodb::{Collection, Database};
use serde::{Deserialize, Serialize};

use super::base::DaoResult;

pub const RC_RESUME_SCOPE: &str = "rc_resume_scope";

/// What a scope entry names. Stored as the snake_case variant; a wire value
/// outside the three is a 400 at the route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeScopeKind {
    /// Every device: what the scope reads once the fleet is staged (P4).
    All,
    /// Every device of one org.
    Org,
    /// One device.
    Device,
}

impl ResumeScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ResumeScopeKind::All => "all",
            ResumeScopeKind::Org => "org",
            ResumeScopeKind::Device => "device",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "all" => Some(ResumeScopeKind::All),
            "org" => Some(ResumeScopeKind::Org),
            "device" => Some(ResumeScopeKind::Device),
            _ => None,
        }
    }
}

/// One scope entry, as stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResumeScopeEntry {
    pub kind: ResumeScopeKind,
    /// The org (`org`) or the device (`device`); none for `all`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// Why the entry is there, in the admin's words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The platform admin who added it: an id, never an address.
    pub by: ObjectId,
    /// When it was added. A save that keeps the entry keeps this.
    pub at: DateTime,
}

impl ResumeScopeEntry {
    /// The entry's place in the unique `(kind, id)` index.
    pub fn target(&self) -> Document {
        doc! {
            "kind": self.kind.as_str(),
            "id": self.id.map_or(Bson::Null, Bson::ObjectId),
        }
    }

    pub fn same_target(&self, other: &Self) -> bool {
        self.kind == other.kind && self.id == other.id
    }
}

pub struct RcResumeScopeDao {
    raw: Collection<Document>,
}

impl RcResumeScopeDao {
    pub fn new(db: &Database) -> Self {
        Self {
            raw: db.collection(RC_RESUME_SCOPE),
        }
    }

    /// Every entry this build can read: `all` first, then the orgs, then the
    /// devices, each by id. A row a newer build wrote in a shape this one
    /// does not know is left out with a warning rather than failing the list.
    pub async fn list(&self) -> DaoResult<Vec<ResumeScopeEntry>> {
        let docs: Vec<Document> = self.raw.find(doc! {}).await?.try_collect().await?;
        let mut rows: Vec<ResumeScopeEntry> = Vec::with_capacity(docs.len());
        for d in docs {
            match bson::from_document::<ResumeScopeEntry>(d) {
                Ok(row) => rows.push(row),
                Err(e) => {
                    tracing::warn!(%e, "rc resume scope: an entry this build cannot read is left out")
                }
            }
        }
        rows.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.id.cmp(&b.id)));
        Ok(rows)
    }

    /// Make the list `entries` (validated and folded by the caller): an entry
    /// it no longer holds is deleted, one it keeps keeps its `by` and `at`
    /// and takes the new note, and a new one is added. An entry that stays is
    /// never absent in between, so a device whose cover did not change never
    /// reads uncovered during a save. Not transactional: a save that fails
    /// half way is finished by saving the same list again.
    pub async fn replace(&self, entries: &[ResumeScopeEntry]) -> DaoResult<()> {
        let keep: Vec<Document> = entries.iter().map(ResumeScopeEntry::target).collect();
        let dropped = if keep.is_empty() {
            doc! {}
        } else {
            doc! { "$nor": keep }
        };
        self.raw.delete_many(dropped).await?;
        for e in entries {
            let note = e.note.clone().map_or(Bson::Null, Bson::String);
            self.raw
                .update_one(
                    e.target(),
                    doc! {
                        "$set": { "note": note },
                        "$setOnInsert": { "by": e.by, "at": e.at },
                    },
                )
                .upsert(true)
                .await?;
        }
        Ok(())
    }

    /// Is the device `agent_id`, of the org `tenant_id`, in the scope: `all`,
    /// its org, or itself? One lookup on the `(kind, id)` index that reads no
    /// entry back, so an entry of a kind a newer build wrote cannot fail it.
    /// The read the hub makes at a device's registration from FR-130 P1b on;
    /// nothing calls it before.
    pub async fn covers(&self, tenant_id: ObjectId, agent_id: ObjectId) -> DaoResult<bool> {
        let hit = self
            .raw
            .find_one(doc! { "$or": [
                { "kind": ResumeScopeKind::All.as_str() },
                { "kind": ResumeScopeKind::Org.as_str(), "id": tenant_id },
                { "kind": ResumeScopeKind::Device.as_str(), "id": agent_id },
            ]})
            .projection(doc! { "_id": 1 })
            .await?;
        Ok(hit.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_parse_only_their_own_spelling() {
        for k in [
            ResumeScopeKind::All,
            ResumeScopeKind::Org,
            ResumeScopeKind::Device,
        ] {
            assert_eq!(ResumeScopeKind::parse(k.as_str()), Some(k));
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
        }
        for bad in ["", "All", "tenant", "devices", "agent", " org"] {
            assert_eq!(ResumeScopeKind::parse(bad), None, "{bad:?}");
        }
        assert!(ResumeScopeKind::All < ResumeScopeKind::Org);
        assert!(ResumeScopeKind::Org < ResumeScopeKind::Device);
    }

    /// `all` is stored with no id and the index keys it as null, so the
    /// list holds one at most; a note left out is not written.
    #[test]
    fn an_entry_stores_what_it_names_and_nothing_else() {
        let by = ObjectId::new();
        let at = DateTime::from_millis(1_762_700_000_000);
        let all = ResumeScopeEntry {
            kind: ResumeScopeKind::All,
            id: None,
            note: None,
            by,
            at,
        };
        let d = bson::to_document(&all).unwrap();
        assert_eq!(d.get_str("kind").unwrap(), "all");
        assert!(!d.contains_key("id") && !d.contains_key("note"), "{d}");
        assert_eq!(all.target(), doc! { "kind": "all", "id": Bson::Null });

        let dev = ObjectId::new();
        let device = ResumeScopeEntry {
            kind: ResumeScopeKind::Device,
            id: Some(dev),
            note: Some("P3: a lab guest".into()),
            by,
            at,
        };
        let d = bson::to_document(&device).unwrap();
        let back: ResumeScopeEntry = bson::from_document(d).unwrap();
        assert_eq!(back, device);
        assert_eq!(device.target(), doc! { "kind": "device", "id": dev });
        assert!(!device.same_target(&all));
        assert!(device.same_target(&ResumeScopeEntry {
            note: None,
            ..device.clone()
        }));

        // `$set: {note: null}` on a kept entry reads back as no note.
        let mut stored = bson::to_document(&device).unwrap();
        stored.insert("note", Bson::Null);
        stored.insert("_id", ObjectId::new());
        let back: ResumeScopeEntry = bson::from_document(stored).unwrap();
        assert_eq!(back.note, None);
    }
}
