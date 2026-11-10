// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2g-2 — a purge, the server's half: `DELETE …/hive/session/{sid}`.
//!
//! Deleting a session writes a purge (`hive_purges`, [`HivePurge`]) naming
//! every device that held the session, and makes the record that purge's
//! tombstone (design §4.4). Each device is sent `rc:hive.purge` (its half is
//! P2g-1): at once if it is connected here, else first thing on its next
//! connection, until it answers with both parts closed. The purge is complete
//! once no device's part is pending, and the tombstone then goes.
//!
//! # Its gates, in order
//!
//! 1. membership, and the replicaset's switch (`hive.replicaset`): off, the
//!    route is not there, and a purge already issued waits;
//! 2. the session, the caller's own — 404 otherwise (decision 12). One the
//!    caller purged already is answered with that purge;
//! 3. `HIVE_RUN` — `no_permission` (decision 12);
//! 4. no promotion in flight — `in_progress`: a move would leave a copy on
//!    a device the purge could not name.
//!
//! From 3 on, a refusal is a 200 carrying the reason, and is audited
//! (`purge`).
//!
//! # The order of the writes, and why
//!
//! No write here spans two collections at once, so the purge is written
//! FIRST, and the tombstone names it: a purge is sent only while its
//! session's tombstone names it, or once the record is gone ([`delivered`]).
//! A purge whose tombstone never landed (a lost race, a crash between the
//! two writes) is never sent, and the session is still there to purge again.
//! One whose tombstone landed is sent until every device has answered.
//!
//! The tombstone's compare-and-set also asserts that the record names no
//! device the purge does not ([`crate::dao::AgentSessionDao::tombstone`]):
//! a placement that added a member after the read makes it fail, and the
//! purge is made again from the record as it is now.
//!
//! # Which devices
//!
//! Every device the record names ([`devices_of`]): where the session runs,
//! every member of its replicaset whatever its state (one that refused a
//! later join may hold an earlier copy), where it ran before (an earlier
//! host keeps its workplace: the account's state directory and refs), and a
//! promotion's two ends. Two are closed at once ([`PurgeClosed`]): a removed
//! device, which can never be asked; and a member that, by its own word,
//! holds nothing ([`holds_nothing`]). A secondary organization's enrollment
//! is one: it ignores every Hive frame, a purge included, so waiting on it
//! would never end.
//!
//! ⚠️ A device's answer is its CLAIM, as `ssh_activity` is: a compromised
//! device can say `done` and keep the copy. The purge records what each
//! device said, and the audit what the server decided.

use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{Bson, DateTime, doc, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::{
    error::Error as HubError,
    hive::{HiveJoinRefusal, HivePurgePart, hive_limits},
    signaling::ServerMsg,
};
use meshharbor_services::dao::base::{BaseDao, DaoError, DaoResult};
use mongodb::Database;
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::HiveState;
use crate::agent_socket::clamp_words;
use crate::model::{
    AgentSession, HiveAuditEvent, HivePurge, MemberState, MemberTip, PurgeClosed, PurgeEntry,
    PurgeEntryState, PurgeView, PurgedMark, SessionStatus, on_chain,
};
use crate::placement::MemberRole;
use crate::routes::{member_tenant, parse_oid};

/// The server's word on an entry it could not send its purge to: the
/// device's connection does not purge (a build before P2g-1, or one without
/// Hive). The purge waits for a connection that does.
pub(crate) const UNSUPPORTED: &str = "device_unsupported";

/// How many times a purge is made again from the record as it is now, when
/// the record changed between its read and its tombstone.
const ISSUE_ATTEMPTS: usize = 3;

/// `hive_purges`.
pub struct PurgeDao {
    pub base: BaseDao<HivePurge>,
}

impl PurgeDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, HivePurge::COLLECTION),
        }
    }

    pub async fn insert(&self, p: &HivePurge) -> DaoResult<()> {
        self.base.insert_one(p).await.map(|_| ())
    }

    pub async fn find(&self, id: ObjectId) -> DaoResult<Option<HivePurge>> {
        self.base.find_one(doc! { "_id": id }).await
    }

    /// A purge whose tombstone never landed goes again. Never a completed
    /// one.
    pub async fn delete_unfinished(&self, id: ObjectId) -> DaoResult<bool> {
        Ok(self
            .base
            .hard_delete(doc! { "_id": id, "done_at": Bson::Null })
            .await?
            > 0)
    }

    /// The owner's latest completed purge of a session whose record is gone:
    /// of the whole session, never a leaving member's (P2g-4b).
    pub async fn completed_of(
        &self,
        tenant_id: ObjectId,
        session_id: ObjectId,
        owner_id: ObjectId,
    ) -> DaoResult<Option<HivePurge>> {
        Ok(self
            .base
            .find_many(
                doc! {
                    "tenant_id": tenant_id,
                    "session_id": session_id,
                    "owner_id": owner_id,
                    "done_at": { "$type": "date" },
                    // P2g-4b — the session's own purge, never a leaving
                    // member's: absent on every whole-session purge.
                    "member": Bson::Null,
                },
                Some(doc! { "done_at": -1 }),
            )
            .await?
            .into_iter()
            .next())
    }

    /// The purges still waiting on `device_id`'s answer, oldest first.
    pub async fn pending_for(
        &self,
        tenant_id: ObjectId,
        device_id: ObjectId,
    ) -> DaoResult<Vec<HivePurge>> {
        self.base
            .find_many(
                doc! {
                    "tenant_id": tenant_id,
                    "done_at": Bson::Null,
                    "devices": { "$elemMatch": {
                        "device_id": device_id,
                        "state": PurgeEntryState::Pending.as_str(),
                    } },
                },
                Some(doc! { "at": 1 }),
            )
            .await
    }

    /// The server could not send `device_id` its purge, and says why on its
    /// entry: only a pending one, and only when it said something else.
    pub async fn note(&self, id: ObjectId, device_id: ObjectId, word: &str) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! {
                    "_id": id,
                    "done_at": Bson::Null,
                    "devices": { "$elemMatch": {
                        "device_id": device_id,
                        "state": PurgeEntryState::Pending.as_str(),
                        "detail": { "$ne": word },
                    } },
                },
                doc! { "$set": { "devices.$.detail": word } },
            )
            .await
    }

    /// A device answered: its words, on its own entry of the purge, while
    /// that entry is pending. `done` when both parts closed; a part that
    /// failed keeps it pending, its detail saying why. `false` = no pending
    /// entry of this device in this purge of this session: a replay, an
    /// answer for a purge it was never sent, or another device's.
    #[allow(clippy::too_many_arguments)]
    pub async fn answer(
        &self,
        id: ObjectId,
        tenant_id: ObjectId,
        session_id: ObjectId,
        device_id: ObjectId,
        store: HivePurgePart,
        account: HivePurgePart,
        detail: Option<String>,
    ) -> DaoResult<bool> {
        let state = if store.closed() && account.closed() {
            PurgeEntryState::Done
        } else {
            PurgeEntryState::Pending
        };
        let mut set = doc! {
            "devices.$.state": state.as_str(),
            "devices.$.store": store.as_str(),
            "devices.$.account": account.as_str(),
            "devices.$.answered_at": DateTime::now(),
        };
        let update = match detail {
            Some(d) => {
                set.insert("devices.$.detail", d);
                doc! { "$set": set }
            }
            None => doc! { "$set": set, "$unset": { "devices.$.detail": "" } },
        };
        self.base
            .update_one(
                doc! {
                    "_id": id,
                    "tenant_id": tenant_id,
                    "session_id": session_id,
                    "done_at": Bson::Null,
                    "devices": { "$elemMatch": {
                        "device_id": device_id,
                        "state": PurgeEntryState::Pending.as_str(),
                    } },
                },
                update,
            )
            .await
    }

    /// FR-90 P2g-4a — `device_id` was removed: its pending part of each
    /// unfinished purge of `tenant_id` closes `device_removed`, as it would
    /// at the issue of one after its removal. The purges it had a part in.
    pub async fn close_removed(
        &self,
        tenant_id: ObjectId,
        device_id: ObjectId,
    ) -> DaoResult<Vec<ObjectId>> {
        let filter = doc! {
            "tenant_id": tenant_id,
            "done_at": Bson::Null,
            "devices": { "$elemMatch": {
                "device_id": device_id,
                "state": PurgeEntryState::Pending.as_str(),
            } },
        };
        let ids: Vec<ObjectId> = self
            .base
            .find_many(filter.clone(), None)
            .await?
            .into_iter()
            .map(|p| p.id)
            .collect();
        if ids.is_empty() {
            return Ok(ids);
        }
        self.base
            .collection()
            .update_many(
                filter,
                doc! { "$set": {
                    "devices.$[e].state": PurgeEntryState::Closed.as_str(),
                    "devices.$[e].closed": PurgeClosed::DeviceRemoved.as_str(),
                    "devices.$[e].answered_at": DateTime::now(),
                } },
            )
            .array_filters(vec![doc! {
                "e.device_id": device_id,
                "e.state": PurgeEntryState::Pending.as_str(),
            }])
            .await?;
        Ok(ids)
    }

    /// The purge completes: once, and only while no device's part is
    /// pending. The purge as it now stands; `None` = not complete, or
    /// completed already.
    pub async fn complete(&self, id: ObjectId) -> DaoResult<Option<HivePurge>> {
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                doc! {
                    "_id": id,
                    "done_at": Bson::Null,
                    "devices.state": { "$ne": PurgeEntryState::Pending.as_str() },
                },
                doc! { "$set": { "done_at": DateTime::now() } },
            )
            .return_document(mongodb::options::ReturnDocument::After)
            .await?)
    }
}

/// Why the SERVER refused a purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeDenyReason {
    NoPermission,
    InProgress,
}

impl PurgeDenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoPermission => "no_permission",
            Self::InProgress => "in_progress",
        }
    }

    /// What the person is told — each names its own next step.
    pub const fn message(self) -> &'static str {
        match self {
            Self::NoPermission => {
                "your role does not include \"Run agent sessions\" (HIVE_RUN); \
                 an owner can grant it"
            }
            Self::InProgress => {
                "the session is being moved to another device; purge it once the move is \
                 done or has failed, as its room says"
            }
        }
    }
}

/// What the purge routes answer.
#[derive(Debug, Serialize)]
pub struct PurgeResponse {
    /// `purging` (its devices are being told; it completes once each has
    /// answered), `purged` (each answered, or none could be asked), or
    /// `refused` (`reason` says which gate).
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purge: Option<PurgeView>,
    /// Sessions forked from this one: each holds its conversation up to its
    /// fork, and this purge leaves them (spec §3b, Fork).
    #[serde(skip_serializing_if = "is_zero")]
    pub forks: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl PurgeResponse {
    fn of(p: &HivePurge, forks: u64) -> Self {
        Self {
            outcome: if p.done_at.is_some() {
                "purged"
            } else {
                "purging"
            },
            reason: None,
            message: (forks > 0).then(|| {
                format!(
                    "{forks} session(s) forked from this one keep its conversation up to their \
                     fork: purging this one does not purge them"
                )
            }),
            purge: Some(PurgeView::from(p)),
            forks,
        }
    }

    fn refused(reason: PurgeDenyReason) -> Self {
        Self {
            outcome: "refused",
            reason: Some(reason.as_str().to_string()),
            message: Some(reason.message().to_string()),
            purge: None,
            forks: 0,
        }
    }
}

/// FR-90 P2g-2 — every device `s` names, once each, where it runs first:
/// the devices a purge of it reaches.
pub(crate) fn devices_of(s: &AgentSession) -> Vec<ObjectId> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut add = |d: ObjectId| {
        if seen.insert(d) {
            out.push(d);
        }
    };
    add(s.location.device_id);
    if let Some(r) = &s.replicaset {
        for m in &r.members {
            add(m.device_id);
        }
    }
    for m in &s.path_map {
        add(m.from.device_id);
        add(m.to.device_id);
    }
    if let Some(m) = &s.moved {
        add(m.from.device_id);
    }
    if let Some(p) = &s.promotion {
        add(p.to);
        add(p.from.device_id);
    }
    if let Some(f) = &s.from_terminal {
        add(f.device_id);
    }
    out
}

/// FR-90 P2g-2 — whether `device`, by its own word, holds nothing of `s`:
/// the record names it ONLY as a member that refused its join as a secondary
/// organization's enrollment, or because it had purged the session already.
/// Any other role (it ran the session, or ran it before) holds a workplace
/// at least.
pub(crate) fn holds_nothing(s: &AgentSession, device: ObjectId) -> bool {
    let ran_it = s.location.device_id == device
        || s.path_map
            .iter()
            .any(|m| m.from.device_id == device || m.to.device_id == device)
        || s.moved.as_ref().is_some_and(|m| m.from.device_id == device)
        || s.promotion
            .as_ref()
            .is_some_and(|p| p.to == device || p.from.device_id == device)
        || s.from_terminal
            .as_ref()
            .is_some_and(|f| f.device_id == device);
    if ran_it {
        return false;
    }
    let nothing = [
        HiveJoinRefusal::SecondaryOrg.as_str(),
        HiveJoinRefusal::Purged.as_str(),
    ];
    let mut rows = s
        .replicaset
        .iter()
        .flat_map(|r| r.members.iter())
        .filter(|m| m.device_id == device)
        .peekable();
    rows.peek().is_some()
        && rows.all(|m| {
            m.state == MemberState::Refused
                && m.refusal.as_deref().is_some_and(|w| nothing.contains(&w))
        })
}

/// Each device `s` names, as a purge's entry: closed when it was removed (no
/// live row in the org) or holds nothing, else pending. A device row that
/// could not be read fails the purge before anything is written.
async fn entries_for(state: &HiveState, s: &AgentSession) -> Result<Vec<PurgeEntry>, ApiError> {
    let mut out = Vec::new();
    for d in devices_of(s) {
        let entry = match state.fleet.agents.find_live_in_tenant(s.tenant_id, d).await {
            Err(DaoError::NotFound) => PurgeEntry::closed(d, PurgeClosed::DeviceRemoved),
            Err(e) => return Err(e.into()),
            Ok(_) if holds_nothing(s, d) => PurgeEntry::closed(d, PurgeClosed::HoldsNothing),
            Ok(_) => PurgeEntry::pending(d),
        };
        out.push(entry);
    }
    Ok(out)
}

/// What issuing a purge came to.
pub(crate) enum Issued {
    /// It took: the purge, and the record as it stood before.
    Took(Box<HivePurge>, Box<AgentSession>),
    /// Another asking purged it first.
    Already,
    Refused(PurgeDenyReason),
    /// P2g-3 — a retention purge of a session that runs again: kept.
    Live,
}

/// Why a purge was issued, as the purge and its audit name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PurgeReason {
    /// Its owner deleted the session (P2g-2).
    Owner,
    /// Its organization's `retention_days` no longer keep it (P2g-3,
    /// [`crate::retention`]).
    Retention,
    /// P2g-4b — a member that leaves, once `min` holds without it: its copy
    /// alone ([`settle_leaving`]).
    Leaving,
}

impl PurgeReason {
    /// The spelling on the purge and in the audit. Locked by test.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Retention => "retention",
            Self::Leaving => "leaving",
        }
    }

    /// Retention purges only a session that is over: a live one renews by
    /// its own activity, and is its owner's to purge.
    const fn only_ended(self) -> bool {
        matches!(self, Self::Retention)
    }
}

/// Write the purge, then make the record its tombstone; should the record
/// change between its read and the tombstone, the purge goes and is made
/// again from the record as it is now.
pub(crate) async fn issue(
    state: &HiveState,
    mut s: AgentSession,
    by: ObjectId,
    why: PurgeReason,
) -> Result<Issued, ApiError> {
    let sid =
        s.id.ok_or_else(|| ApiError::Internal("a session record without an id".into()))?;
    for _ in 0..ISSUE_ATTEMPTS {
        let entries = entries_for(state, &s).await?;
        let ids: Vec<ObjectId> = entries.iter().map(|e| e.device_id).collect();
        let at = DateTime::now();
        let p = HivePurge {
            id: ObjectId::new(),
            tenant_id: s.tenant_id,
            session_id: sid,
            owner_id: s.owner_id,
            by,
            reason: why.as_str().to_string(),
            room_id: s.room_id,
            devices: entries,
            at,
            done_at: None,
            member: None,
        };
        state.purges.insert(&p).await?;
        let mark = PurgedMark {
            purge_id: p.id,
            by,
            at,
        };
        let took = state
            .sessions
            .tombstone(s.tenant_id, s.owner_id, sid, &mark, &ids, why.only_ended())
            .await;
        match took {
            Ok(Some(before)) => return Ok(Issued::Took(Box::new(p), Box::new(before))),
            Ok(None) => {}
            Err(e) => {
                unissue(state, p.id).await;
                return Err(e.into());
            }
        }
        // The record changed first, and this purge never took.
        unissue(state, p.id).await;
        match state
            .sessions
            .find_owned(s.tenant_id, s.owner_id, sid)
            .await
        {
            Ok(now)
                if now
                    .promotion
                    .as_ref()
                    .is_some_and(|p| p.in_flight(DateTime::now())) =>
            {
                return Ok(Issued::Refused(PurgeDenyReason::InProgress));
            }
            // P2g-3 — it runs again (made a managed one meanwhile): retention
            // keeps it.
            Ok(now) if why.only_ended() && !now.status.is_terminal() => {
                return Ok(Issued::Live);
            }
            Ok(now) => s = now,
            Err(DaoError::NotFound) => return Ok(Issued::Already),
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::Conflict(
        "the session kept changing while it was purged; try again".into(),
    ))
}

/// A purge that never took goes. Should that fail, it stays and is never
/// sent: no tombstone names it ([`delivered`]).
async fn unissue(state: &HiveState, id: ObjectId) {
    if let Err(e) = state.purges.delete_unfinished(id).await {
        warn!(purge = %id, %e, "hive: a purge that never took was not deleted — it is never sent");
    }
}

/// One server decision about a purge, for `hive_audit`.
async fn audit(
    state: &HiveState,
    p: &HivePurge,
    user_id: ObjectId,
    outcome: &str,
    reason: Option<&str>,
) {
    let ev = HiveAuditEvent {
        id: None,
        tenant_id: p.tenant_id,
        user_id,
        target_id: None,
        device_id: p.devices.first().map(|d| d.device_id),
        session_id: Some(p.session_id),
        action: "purge".to_string(),
        outcome: outcome.to_string(),
        reason: reason.map(str::to_string),
        sessions: None,
        at: DateTime::now(),
    };
    if let Err(e) = state.audit.record(ev).await {
        warn!(%e, "hive: audit write failed");
    }
}

/// A refused purge: audited, and answered with the reason.
async fn refuse(
    state: &HiveState,
    s: &AgentSession,
    user_id: ObjectId,
    reason: PurgeDenyReason,
) -> Json<PurgeResponse> {
    info!(
        tenant = %s.tenant_id, user = %user_id, session = ?s.id,
        reason = reason.as_str(), "hive: a purge refused"
    );
    let ev = HiveAuditEvent {
        id: None,
        tenant_id: s.tenant_id,
        user_id,
        target_id: None,
        device_id: Some(s.location.device_id),
        session_id: s.id,
        action: "purge".to_string(),
        outcome: "refused".to_string(),
        reason: Some(reason.as_str().to_string()),
        sessions: None,
        at: DateTime::now(),
    };
    if let Err(e) = state.audit.record(ev).await {
        warn!(%e, "hive: audit write failed");
    }
    Json(PurgeResponse::refused(reason))
}

/// The purge of a session the caller owns: the one its tombstone names, or,
/// with the record gone, the latest one that completed. `None` = never
/// purged: a live session, or no session of theirs.
async fn purge_of(
    state: &HiveState,
    tid: ObjectId,
    owner: ObjectId,
    sid: ObjectId,
) -> Result<Option<HivePurge>, ApiError> {
    Ok(
        match state.sessions.find_owned_any(tid, owner, sid).await? {
            Some(s) => match s.purged {
                Some(m) => state.purges.find(m.purge_id).await?,
                None => None,
            },
            None => state.purges.completed_of(tid, sid, owner).await?,
        },
    )
}

/// `DELETE /api/tenant/{tenant_id}/hive/session/{session_id}` — the owner
/// purges their session from every device that held it.
pub async fn purge(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, session_id)): Path<(String, String)>,
) -> Result<Json<PurgeResponse>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    if !state.replicaset {
        return Err(ApiError::NotFound(
            "purging sessions is off on this server".into(),
        ));
    }
    let sid = parse_oid(&session_id, "session_id")?;
    // The owner's alone: anyone else's read of the id is a 404. One purged
    // already answers the asking with its purge.
    let s = match state.sessions.find_owned(tid, auth.user_id, sid).await {
        Ok(s) => s,
        Err(DaoError::NotFound) => {
            return match purge_of(&state, tid, auth.user_id, sid).await? {
                Some(p) => Ok(Json(PurgeResponse::of(&p, 0))),
                None => Err(DaoError::NotFound.into()),
            };
        }
        Err(e) => return Err(e.into()),
    };
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    if !permissions::has(perms, permissions::HIVE_RUN) {
        return Ok(refuse(&state, &s, auth.user_id, PurgeDenyReason::NoPermission).await);
    }
    if s.promotion
        .as_ref()
        .is_some_and(|p| p.in_flight(DateTime::now()))
    {
        return Ok(refuse(&state, &s, auth.user_id, PurgeDenyReason::InProgress).await);
    }
    let read = s.clone();
    let (p, before) = match issue(&state, s, auth.user_id, PurgeReason::Owner).await? {
        Issued::Took(p, before) => (*p, *before),
        Issued::Refused(reason) => return Ok(refuse(&state, &read, auth.user_id, reason).await),
        // A purge of its owner's is never of an ended session only.
        Issued::Already | Issued::Live => {
            return match purge_of(&state, tid, auth.user_id, sid).await? {
                Some(p) => Ok(Json(PurgeResponse::of(&p, 0))),
                None => Err(DaoError::NotFound.into()),
            };
        }
    };
    carry_out(&state, &p, &before, auth.user_id).await;
    let forks = match state.sessions.forks_of(tid, sid).await {
        Ok(n) => n,
        Err(e) => {
            warn!(session = %sid, %e, "hive: the purged session's forks were not counted");
            0
        }
    };
    let now = state.purges.find(p.id).await?.unwrap_or(p);
    Ok(Json(PurgeResponse::of(&now, forks)))
}

/// `GET /api/tenant/{tenant_id}/hive/session/{session_id}/purge` — how the
/// owner's purge of their session stands: each device and what it said.
pub async fn get_purge(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, session_id)): Path<(String, String)>,
) -> Result<Json<PurgeView>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    if !state.replicaset {
        return Err(ApiError::NotFound(
            "purging sessions is off on this server".into(),
        ));
    }
    let sid = parse_oid(&session_id, "session_id")?;
    match purge_of(&state, tid, auth.user_id, sid).await? {
        Some(p) => Ok(Json(PurgeView::from(&p))),
        None => Err(DaoError::NotFound.into()),
    }
}

/// What follows a purge that took, whoever issued it: the server's own data
/// of the session, the audit, each device told, and the purge's completion
/// should no device's part be pending.
pub(crate) async fn carry_out(
    state: &HiveState,
    p: &HivePurge,
    before: &AgentSession,
    user: ObjectId,
) {
    info!(
        tenant = %p.tenant_id, session = %p.session_id, purge = %p.id, user = %user,
        reason = %p.reason, devices = p.devices.len(), "hive: a session purged — its devices are told"
    );
    // What the server holds of it goes now: nothing on a device needs it.
    drop_server_side(state, before).await;
    // The owner's own purge needs no word; another names why.
    let why = (p.reason != PurgeReason::Owner.as_str()).then_some(p.reason.as_str());
    audit(state, p, user, "issued", why).await;
    let mut elsewhere = Vec::new();
    for d in p
        .devices
        .iter()
        .filter(|d| d.state == PurgeEntryState::Pending)
    {
        if send(state, p, d.device_id).await == Sent::NotHere {
            elsewhere.push(d.device_id);
        }
    }
    // P2g-3b — a device whose socket is on another pod: the pod that holds
    // it pushes the purge there. One that is online nowhere is told at its
    // next connection, as before.
    if !elsewhere.is_empty() {
        tell_other_pods(state, p, &elsewhere).await;
    }
    if p.complete() {
        finish(state, p.id).await;
    }
}

/// The session's room, its core memory snapshot and its approvals: the
/// server's own, needed by no device. Best effort: the room is deleted again
/// when the purge completes.
async fn drop_server_side(state: &HiveState, s: &AgentSession) {
    let Some(sid) = s.id else { return };
    if let Some(room) = s.room_id {
        drop_room(state, s.tenant_id, room).await;
    }
    if let Err(e) = state.brain.drop_snapshot(sid).await {
        warn!(session = %sid, %e, "hive: a purged session's core memory snapshot was not deleted");
    }
    if let Err(e) = state.approvals.delete_for_session(sid).await {
        warn!(session = %sid, %e, "hive: a purged session's approvals were not deleted");
    }
}

async fn drop_room(state: &HiveState, tenant_id: ObjectId, room: ObjectId) {
    if let Err(e) = state
        .chat
        .delete_bound_room(tenant_id, room, crate::room::MODULE)
        .await
    {
        warn!(room = %room, %e, "hive: a purged session's room was not deleted");
    }
}

/// What [`send`] did with a device's purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    /// Pushed to the device's connection on this pod.
    Here,
    /// Its connection on this pod does not purge: its entry says so.
    Unsupported,
    /// The device is not connected to this pod.
    NotHere,
}

/// Send `device` its purge, when this server can: a connection that does not
/// purge gets nothing, and its entry says so.
async fn send(state: &HiveState, p: &HivePurge, device: ObjectId) -> Sent {
    let msg = ServerMsg::HivePurge {
        purge_id: p.id,
        session_id: p.session_id,
        // P2k-3 — a leaving member's purge is of its copy alone.
        leaving: p.member.is_some(),
    };
    match state.fleet.rc_hub.push_hive_purge(device, p.tenant_id, msg) {
        Ok(()) => {
            info!(purge = %p.id, session = %p.session_id, device = %device, "hive: purge sent");
            Sent::Here
        }
        Err(HubError::ExecUnsupported(_)) => {
            debug!(purge = %p.id, device = %device, "hive: the device's agent does not purge — it waits for one that does");
            if let Err(e) = state.purges.note(p.id, device, UNSUPPORTED).await {
                warn!(purge = %p.id, %e, "hive: a purge's undeliverable entry was not noted");
            }
            Sent::Unsupported
        }
        // Not connected here: on another pod, or told on its next connection.
        Err(e) => {
            debug!(purge = %p.id, device = %device, %e, "hive: purge not sent from this pod");
            Sent::NotHere
        }
    }
}

/// P2g-3b — `devices` are not connected to this pod: publish the purge on the
/// cluster's control channel, and the pod that holds each one's socket pushes
/// it there (fleet's `hive_purge`, `ctrl.rs`). Sent only once its tombstone
/// names it, as every delivery is ([`delivered`]): this runs right after the
/// purge took. No Redis, one pod: nothing to publish to, and the device is
/// told at its next connection.
async fn tell_other_pods(state: &HiveState, p: &HivePurge, devices: &[ObjectId]) {
    let agent_ids: Vec<String> = devices.iter().map(|d| d.to_hex()).collect();
    meshharbor_mod_fleet::ctrl::publish_rc_ctrl(
        &state.core,
        "hive_purge",
        serde_json::json!({
            "tenant_id": p.tenant_id.to_hex(),
            "purge_id": p.id.to_hex(),
            "session_id": p.session_id.to_hex(),
            "agent_ids": agent_ids,
            // P2k-3 — so the pod that holds the socket says it too.
            "leaving": p.member.is_some(),
        }),
    )
    .await;
    debug!(purge = %p.id, devices = devices.len(), "hive: purge published for the devices on other pods");
}

/// Which of `purges` may be sent: each while its session's tombstone names
/// it, or once the record is gone. One no tombstone names never took. P2g-4b
/// — a leaving member's while its row names it: one placement took the
/// member back before it was named never took either.
async fn delivered(
    state: &HiveState,
    tenant_id: ObjectId,
    purges: Vec<HivePurge>,
) -> DaoResult<Vec<HivePurge>> {
    let ids: Vec<ObjectId> = purges.iter().map(|p| p.session_id).collect();
    let records: HashMap<ObjectId, AgentSession> = state
        .sessions
        .find_many_in_tenant(tenant_id, &ids)
        .await?
        .into_iter()
        .filter_map(|s| Some((s.id?, s)))
        .collect();
    Ok(purges
        .into_iter()
        .filter(|p| match (records.get(&p.session_id), p.member) {
            (None, _) => true,
            (Some(s), None) => s.purged.as_ref().map(|m| m.purge_id) == Some(p.id),
            // P2g-4b — a leaving member's: while its row names this purge,
            // or once the whole session is being purged.
            (Some(s), Some(device)) => s.purged.is_some() || names_purge(s, device, p.id),
        })
        .collect())
}

/// FR-90 P2g-4b — whether `s`'s row of `device` names the purge `purge_id`.
fn names_purge(s: &AgentSession, device: ObjectId, purge_id: ObjectId) -> bool {
    s.replicaset.as_ref().is_some_and(|r| {
        r.members
            .iter()
            .any(|m| m.device_id == device && m.purging == Some(purge_id))
    })
}

/// A device connected: every purge still waiting on it, first, before
/// anything else it is sent. `conn` is that connection's sender in the hub,
/// read as `reconcile_on_connect` reads it: a connection a newer one
/// displaced decides nothing.
pub(crate) async fn reconcile_purges(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    conn: &mpsc::Sender<ServerMsg>,
) {
    let Some(purges) = state
        .fleet
        .rc_hub
        .agent_supports_hive_purge_on(device_id, conn)
    else {
        return;
    };
    let pending = match state.purges.pending_for(tenant_id, device_id).await {
        Ok(p) if p.is_empty() => return,
        Ok(p) => p,
        Err(e) => {
            warn!(device = %device_id, %e, "hive: the device's purges were not read — they go at its next connection");
            return;
        }
    };
    let pending = match delivered(state, tenant_id, pending).await {
        Ok(p) => p,
        Err(e) => {
            warn!(device = %device_id, %e, "hive: the device's purges' sessions were not read — they go at its next connection");
            return;
        }
    };
    for p in &pending {
        if purges {
            // On this connection, so here or nowhere.
            let _ = send(state, p, device_id).await;
        } else if let Err(e) = state.purges.note(p.id, device_id, UNSUPPORTED).await {
            warn!(purge = %p.id, %e, "hive: a purge's undeliverable entry was not noted");
        }
    }
}

/// `rc:hive.purge_ack` from `device_id`'s socket: its words on its own entry,
/// never another device's; and once no part of the purge is pending, it
/// completes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn on_ack(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    purge_id: ObjectId,
    session_id: ObjectId,
    store: HivePurgePart,
    account: HivePurgePart,
    detail: Option<String>,
) {
    let detail = clamp_words(detail, hive_limits::MAX_DETAIL_LEN);
    match state
        .purges
        .answer(
            purge_id, tenant_id, session_id, device_id, store, account, detail,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return debug!(
                purge = %purge_id, device = %device_id,
                "hive: a purge answer for no pending entry of this device — a replay, or another's"
            );
        }
        Err(e) => return warn!(purge = %purge_id, %e, "hive: a purge answer was not recorded"),
    }
    info!(
        purge = %purge_id, session = %session_id, device = %device_id,
        store = store.as_str(), account = account.as_str(), "hive: the device answered its purge"
    );
    if store.closed() && account.closed() {
        finish(state, purge_id).await;
    }
}

/// FR-90 P2g-4a — `device_id` is being removed from `tenant_id`, its socket
/// still up (hive leads `HOOK_ORDER`): it is told to purge every session it
/// holds (`rc:hive.purge_all`), on this pod or on the one that holds its
/// socket, before the kick that follows; only a connection advertising
/// `hive-purge-all`. Best effort: nothing answers, its credentials go next,
/// and one offline now, or of a build before it, keeps what it held (until
/// P7). Then its pending part of each unfinished purge closes
/// `device_removed`, and a purge that was waiting on it alone completes.
pub(crate) async fn device_removed(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
) -> DaoResult<()> {
    let purge_id = ObjectId::new();
    match state
        .fleet
        .rc_hub
        .push_hive_purge_all(device_id, tenant_id, purge_id)
    {
        Ok(()) => {
            info!(purge = %purge_id, device = %device_id, "hive: a removed device is told to purge what it holds")
        }
        Err(HubError::ExecUnsupported(_)) => {
            debug!(device = %device_id, "hive: a removed device's agent does not purge at its removal — its disk keeps what it held")
        }
        // Not connected here: the pod that holds its socket tells it. The
        // kick is published after this, on the same channel.
        Err(_) => {
            meshharbor_mod_fleet::ctrl::publish_rc_ctrl(
                &state.core,
                "hive_purge_all",
                serde_json::json!({
                    "tenant_id": tenant_id.to_hex(),
                    "agent_id": device_id.to_hex(),
                    "purge_id": purge_id.to_hex(),
                }),
            )
            .await;
        }
    }
    for id in state.purges.close_removed(tenant_id, device_id).await? {
        finish(state, id).await;
    }
    Ok(())
}

/// FR-90 P2g-4b — whether `s` holds its `min` copies without `device`: its
/// primary, while the session is live, and each member that took its copy
/// and holds at least as much of the session as `device`'s copy does
/// (`joined`, with a tip, by [`on_chain`]). A member that leaves is never one
/// of them.
///
/// P2k-2 (F1) — "as much as", not "a tip": a member says `seq` 0 at its floor
/// the moment it joins, which is how the server learns it did, so a tip alone
/// counted a replacement that held nothing yet, and the leaving member's whole
/// copy went before its replacement held one event (the field run,
/// 2026-10-16). A copy stands in for the one that goes only once it holds
/// what that one holds; the next tip looks again.
pub(crate) fn holds_without(s: &AgentSession, device: ObjectId) -> bool {
    let Some(r) = s.replicaset.as_ref() else {
        return false;
    };
    let primary = s.location.device_id;
    let holds = |t: &MemberTip| on_chain(&s.fences, t.fence, t.seq);
    // What the copy that goes holds: nothing, without a tip.
    let goes = r
        .members
        .iter()
        .find(|m| m.device_id == device)
        .and_then(|m| m.tip.as_ref())
        .map_or(0, holds);
    let members = r
        .members
        .iter()
        .filter(|m| {
            m.device_id != device
                && m.device_id != primary
                && m.role != MemberRole::Primary.as_str()
                && m.state == MemberState::Joined
                && m.tip.as_ref().is_some_and(|t| holds(t) >= goes)
        })
        .count();
    let live = SessionStatus::LIVE.contains(&s.status) && primary != device;
    members + usize::from(live) >= usize::try_from(r.min).unwrap_or(usize::MAX)
}

/// FR-90 P2g-4b — each member of `s` that leaves, purged once `min` holds
/// without it: its copy alone, which makes no tombstone and leaves the
/// session as it is. Make-before-break: never while the copies elsewhere
/// fall short, never one placement took back, never one a fork is being
/// made from while that fork may still need it, and with the replicaset's
/// switch off, a promotion in flight, or the session over or purged, none.
/// `gone` is a device being removed: its part closes at once (P2g-4a told
/// it to purge everything). How many purges took.
pub(crate) async fn settle_leaving(
    state: &HiveState,
    s: &AgentSession,
    gone: Option<ObjectId>,
) -> usize {
    let (Some(sid), Some(r)) = (s.id, s.replicaset.as_ref()) else {
        return 0;
    };
    if !state.replicaset
        || s.purged.is_some()
        || !SessionStatus::LIVE.contains(&s.status)
        || s.promotion
            .as_ref()
            .is_some_and(|p| p.in_flight(DateTime::now()))
    {
        return 0;
    }
    let leaving: Vec<(ObjectId, Option<ObjectId>)> = r
        .members
        .iter()
        .filter(|m| {
            m.state == MemberState::Leaving
                && m.purging.is_none()
                && m.role != MemberRole::Primary.as_str()
        })
        .map(|m| (m.device_id, m.forking))
        .collect();
    let mut took = 0;
    for (device, forking) in leaving {
        // A fork is being made from its copy (P2f-3c): the fork's first start
        // puts it in place from that copy, so it stays while that start is
        // out. (A device being removed has every session on it ended first,
        // the fork among them: `hooks::agent_removed`.)
        if let Some(fork) = forking
            && fork_needs_copy(state, fork).await
        {
            continue;
        }
        if !holds_without(s, device) {
            continue;
        }
        let removed = Some(device) == gone;
        match issue_leaving(state, s, sid, device, removed, forking).await {
            Ok(true) => took += 1,
            Ok(false) => {}
            Err(e) => {
                warn!(session = %sid, device = %device, %e, "hive: a leaving member's purge was not issued — the next tip or placement tries again")
            }
        }
    }
    took
}

/// One leaving member's purge: written first, then named on its row in one
/// compare-and-set, as a session's purge is written ahead of its tombstone
/// (P2g-2), so one whose row never took (placement took the member back,
/// another purge took it, or a fork is now being made from its copy) is
/// deleted and never sent. `forking` = the fork its row names, as read.
/// `true` = it took.
async fn issue_leaving(
    state: &HiveState,
    s: &AgentSession,
    sid: ObjectId,
    device: ObjectId,
    removed: bool,
    forking: Option<ObjectId>,
) -> DaoResult<bool> {
    let entry = if removed {
        PurgeEntry::closed(device, PurgeClosed::DeviceRemoved)
    } else {
        match state
            .fleet
            .agents
            .find_live_in_tenant(s.tenant_id, device)
            .await
        {
            Err(DaoError::NotFound) => PurgeEntry::closed(device, PurgeClosed::DeviceRemoved),
            Err(e) => return Err(e),
            Ok(_) if holds_nothing(s, device) => {
                PurgeEntry::closed(device, PurgeClosed::HoldsNothing)
            }
            Ok(_) => PurgeEntry::pending(device),
        }
    };
    let p = HivePurge {
        id: ObjectId::new(),
        tenant_id: s.tenant_id,
        session_id: sid,
        owner_id: s.owner_id,
        by: s.owner_id,
        reason: PurgeReason::Leaving.as_str().to_string(),
        room_id: None,
        devices: vec![entry],
        at: DateTime::now(),
        done_at: None,
        member: Some(device),
    };
    state.purges.insert(&p).await?;
    match state
        .sessions
        .mark_purging(sid, device, p.id, forking)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            unissue(state, p.id).await;
            return Ok(false);
        }
        Err(e) => {
            unissue(state, p.id).await;
            return Err(e);
        }
    }
    info!(
        session = %sid, device = %device, purge = %p.id,
        "hive: a member that leaves is purged — min holds without it"
    );
    audit(
        state,
        &p,
        p.by,
        "issued",
        Some(PurgeReason::Leaving.as_str()),
    )
    .await;
    if p.complete() {
        finish(state, p.id).await;
    } else if send(state, &p, device).await == Sent::NotHere {
        tell_other_pods(state, &p, &[device]).await;
    }
    Ok(true)
}

/// FR-90 P2g-4b — each member of `session` that leaves, purged once it may
/// go: looked at when a member's tip lands, which may make `min` hold, and
/// when a fork made from a leaving member's copy has had its first start
/// answered, or the server is done trying to make it.
pub(crate) async fn settle_session(state: &HiveState, session: ObjectId) {
    if !state.replicaset {
        return;
    }
    match state.sessions.with_leaving(session).await {
        Ok(Some(s)) => {
            settle_leaving(state, &s, None).await;
        }
        Ok(None) => {}
        Err(e) => {
            debug!(session = %session, %e, "hive: a session's leaving members were not read — the next tip tries again")
        }
    }
}

/// FR-90 P2g-4b — whether the fork `fork`, made from a leaving member's copy
/// (P2f-3c), may still need that copy: its first start is still out (not
/// answered, and no run of it reported, since the copy is put in place
/// before the launch), or its record is still to be made, which it is
/// moments after its move ends (one not made within a start's redelivery
/// window never will be). Unread, it may: a copy is never purged on a guess.
async fn fork_needs_copy(state: &HiveState, fork: ObjectId) -> bool {
    match state.sessions.find(fork).await {
        Ok(Some(f)) => first_start_out(&f),
        Ok(None) => may_yet_be_made(fork, DateTime::now()),
        Err(e) => {
            debug!(fork = %fork, %e, "hive: a fork's record was not read — the copy it is made from is kept");
            true
        }
    }
}

/// A fork's first start, not yet answered and no run of it reported: the
/// device has yet to put it in place from the copy. A purged fork is made
/// nowhere, and a later start is made from the fork's own copy.
fn first_start_out(f: &AgentSession) -> bool {
    f.status == SessionStatus::Starting
        && f.accepted_at.is_none()
        && f.fence <= 1
        && f.purged.is_none()
}

/// A fork with no record yet, `fork` its id as the move's end named it: the
/// record is made moments after, and one not made within a start's
/// redelivery window never will be.
fn may_yet_be_made(fork: ObjectId, now: DateTime) -> bool {
    let age_ms = now
        .timestamp_millis()
        .saturating_sub(fork.timestamp().timestamp_millis());
    age_ms < hive_limits::START_REDELIVERY_WINDOW_SECS * 1000
}

/// The purge completes once no device's part is pending, and only once:
/// the tombstone goes, the room is deleted again (should its first delete
/// have failed), and the audit says so. P2g-4b — a leaving member's: its row
/// goes instead, and the session stays as it is.
async fn finish(state: &HiveState, purge_id: ObjectId) {
    let p = match state.purges.complete(purge_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return,
        Err(e) => {
            return warn!(purge = %purge_id, %e, "hive: a purge's completion was not recorded");
        }
    };
    // P2g-4b — a leaving member's: its row goes, and the session stays.
    if let Some(device) = p.member {
        match state
            .sessions
            .drop_purged_member(p.session_id, device, p.id)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                warn!(purge = %p.id, session = %p.session_id, device = %device, %e, "hive: a completed leaving purge's member row was not dropped")
            }
        }
        audit(
            state,
            &p,
            p.by,
            "complete",
            Some(PurgeReason::Leaving.as_str()),
        )
        .await;
        info!(purge = %p.id, session = %p.session_id, device = %device, "hive: a leaving member's purge is complete");
        return;
    }
    match state.sessions.delete_tombstone(p.session_id, p.id).await {
        Ok(_) => {}
        Err(e) => {
            warn!(purge = %p.id, session = %p.session_id, %e, "hive: a completed purge's tombstone was not deleted")
        }
    }
    if let Some(room) = p.room_id {
        drop_room(state, p.tenant_id, room).await;
    }
    audit(state, &p, p.by, "complete", None).await;
    info!(purge = %p.id, session = %p.session_id, "hive: a purge is complete");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        FromTerminal, HarnessRef, MovedStart, PathMove, Promotion, PromotionState, ReplicaMember,
        Replicaset, SessionLocation, SessionOrigin, SessionStatus,
    };

    fn place(device_id: ObjectId) -> SessionLocation {
        SessionLocation {
            device_id,
            device_name: String::new(),
            folder: "/src".into(),
            account: None,
        }
    }

    fn member(device_id: ObjectId, state: MemberState, refusal: Option<&str>) -> ReplicaMember {
        ReplicaMember {
            device_id,
            role: "owner".into(),
            state,
            refusal: refusal.map(str::to_string),
            answered_at: None,
            tip: None,
            purging: None,
            forking: None,
        }
    }

    fn session(primary: ObjectId) -> AgentSession {
        let now = DateTime::now();
        AgentSession {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            owner_id: ObjectId::new(),
            drivers: Vec::new(),
            title: "t".into(),
            room_id: None,
            last_turn: None,
            harness: HarnessRef {
                id: "claude-code".into(),
                session: "u".into(),
            },
            location: place(primary),
            status: SessionStatus::Idle,
            fence: 3,
            accepted_at: Some(now),
            refusal: None,
            end_reason: None,
            detail: None,
            created_at: now,
            updated_at: now,
            ended_at: None,
            brain_rev: None,
            vault_role: None,
            origin: SessionOrigin::Started,
            replicaset: None,
            promotion: None,
            fences: Vec::new(),
            moved: None,
            parent: None,
            from_terminal: None,
            path_map: Vec::new(),
            purged: None,
        }
    }

    /// Every device the record names, where it runs first, once each: its
    /// members whatever their state, where it ran before, the start's move,
    /// a promotion's two ends, and the device that adopted it.
    #[test]
    fn a_purge_reaches_every_device_the_record_names_once() {
        let [a, b, c, d, e, f, g, h]: [ObjectId; 8] = std::array::from_fn(|_| ObjectId::new());
        let mut s = session(a);
        assert_eq!(devices_of(&s), vec![a], "a session never moved or copied");
        s.replicaset = Some(Replicaset {
            policy_revision: 1,
            min: 2,
            max: 3,
            restricted_tags: Vec::new(),
            members: vec![
                member(a, MemberState::Joined, None),
                member(b, MemberState::Joined, None),
                member(c, MemberState::Refused, Some("quota")),
                member(d, MemberState::Leaving, None),
            ],
            short: None,
            placed_at: DateTime::now(),
        });
        // Two moves: h is named by the path map alone, where an earlier run
        // left its workplace.
        s.path_map = vec![
            PathMove {
                fence: 2,
                from: place(h),
                to: place(e),
                at: DateTime::now(),
            },
            PathMove {
                fence: 3,
                from: place(e),
                to: place(a),
                at: DateTime::now(),
            },
        ];
        s.moved = Some(MovedStart {
            from: place(e),
            by: s.owner_id,
            at: DateTime::now(),
        });
        let now = DateTime::now();
        s.promotion = Some(Promotion {
            id: ObjectId::new(),
            to: f,
            to_name: String::new(),
            to_role: "owner".into(),
            folder: "/src".into(),
            from: place(a),
            from_fence: 3,
            by: s.owner_id,
            state: PromotionState::Preparing,
            started_at: now,
            deadline: now,
            drained: None,
            unreachable_from: false,
            prior: None,
            teleport: true,
            fork: None,
        });
        s.from_terminal = Some(FromTerminal {
            device_id: g,
            by: s.owner_id,
            at: now,
            ended_at: None,
            end_reason: None,
            detail: None,
            folder: None,
            refused: None,
            refused_detail: None,
        });
        assert_eq!(
            devices_of(&s),
            vec![a, b, c, d, h, e, f, g],
            "every device the record names"
        );
    }

    /// Only a member that refused its join as a secondary organization's
    /// enrollment, or because it purged the session already, holds nothing
    /// — and only when the record names it in no other role. Any other
    /// refusal may follow a copy taken at an earlier fence.
    #[test]
    fn only_a_member_that_said_so_holds_nothing() {
        let [a, sec, gone, quota, joined, ran]: [ObjectId; 6] =
            std::array::from_fn(|_| ObjectId::new());
        let mut s = session(a);
        s.replicaset = Some(Replicaset {
            policy_revision: 1,
            min: 2,
            max: 6,
            restricted_tags: Vec::new(),
            members: vec![
                member(a, MemberState::Joined, None),
                member(sec, MemberState::Refused, Some("secondary_org")),
                member(gone, MemberState::Refused, Some("purged")),
                member(quota, MemberState::Refused, Some("quota")),
                member(joined, MemberState::Joined, None),
                member(ran, MemberState::Refused, Some("secondary_org")),
            ],
            short: None,
            placed_at: DateTime::now(),
        });
        s.path_map = vec![PathMove {
            fence: 2,
            from: place(ran),
            to: place(a),
            at: DateTime::now(),
        }];
        assert!(holds_nothing(&s, sec));
        assert!(holds_nothing(&s, gone));
        assert!(
            !holds_nothing(&s, quota),
            "a refusal that may follow a copy"
        );
        assert!(!holds_nothing(&s, joined));
        assert!(!holds_nothing(&s, a), "where it runs");
        assert!(
            !holds_nothing(&s, ran),
            "it ran the session before: its workplace is there"
        );
        assert!(
            !holds_nothing(&s, ObjectId::new()),
            "a device the record does not name is not one it knows holds nothing"
        );
    }

    #[test]
    fn the_servers_refusal_words_are_locked() {
        for (r, w) in [
            (PurgeDenyReason::NoPermission, "no_permission"),
            (PurgeDenyReason::InProgress, "in_progress"),
        ] {
            assert_eq!(r.as_str(), w);
            assert!(!r.message().is_empty(), "{w}");
        }
    }

    /// The answer says `purging` until the purge completes, says so when a
    /// fork keeps the conversation, and stays quiet about forks otherwise.
    #[test]
    fn the_answer_says_how_the_purge_stands_and_names_the_forks() {
        let mut p = HivePurge {
            id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            session_id: ObjectId::new(),
            owner_id: ObjectId::new(),
            by: ObjectId::new(),
            reason: "owner".into(),
            room_id: None,
            devices: vec![PurgeEntry::pending(ObjectId::new())],
            at: DateTime::now(),
            done_at: None,
            member: None,
        };
        let v = serde_json::to_value(PurgeResponse::of(&p, 0)).unwrap();
        assert_eq!(v["outcome"], "purging", "{v}");
        assert!(
            v.get("forks").is_none() && v.get("message").is_none(),
            "{v}"
        );
        p.done_at = Some(DateTime::now());
        let v = serde_json::to_value(PurgeResponse::of(&p, 2)).unwrap();
        assert_eq!(v["outcome"], "purged", "{v}");
        assert_eq!(v["forks"], 2, "{v}");
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("does not purge them"),
            "{v}"
        );
        let v = serde_json::to_value(PurgeResponse::refused(PurgeDenyReason::InProgress)).unwrap();
        assert_eq!(v["outcome"], "refused", "{v}");
        assert_eq!(v["reason"], "in_progress", "{v}");
        assert!(v.get("purge").is_none(), "{v}");
    }

    /// FR-90 P2g-4b — `min` holds without a member only on the copies
    /// elsewhere: the primary of a live session, and each member that took
    /// its copy and said where it ends. Never the member itself, one that
    /// has said nothing, one that leaves, nor the primary of a session that
    /// is over.
    #[test]
    fn min_holds_without_a_member_only_on_the_copies_elsewhere() {
        use crate::model::MemberTip;
        let [a, b, c, d]: [ObjectId; 4] = std::array::from_fn(|_| ObjectId::new());
        let tipped = |device, state| ReplicaMember {
            tip: Some(MemberTip {
                fence: 3,
                seq: 9,
                hash: "0".repeat(64),
                checkpoint_seq: Some(9),
                checkpoint_hash: None,
                at: DateTime::now(),
            }),
            ..member(device, state, None)
        };
        let mut s = session(a);
        s.replicaset = Some(Replicaset {
            policy_revision: 1,
            min: 2,
            max: 3,
            restricted_tags: Vec::new(),
            members: vec![
                ReplicaMember {
                    role: MemberRole::Primary.as_str().into(),
                    ..tipped(a, MemberState::Joined)
                },
                tipped(b, MemberState::Joined),
                member(c, MemberState::Joined, None),
                tipped(d, MemberState::Leaving),
            ],
            short: None,
            placed_at: DateTime::now(),
        });
        assert!(holds_without(&s, d), "the primary and b: two");
        assert!(
            !holds_without(&s, b),
            "without b: the primary alone, c has said nothing and d leaves"
        );
        s.status = SessionStatus::Ended;
        assert!(
            !holds_without(&s, d),
            "the primary of a session that is over is not counted"
        );
        s.status = SessionStatus::Idle;
        s.replicaset.as_mut().unwrap().min = 3;
        assert!(!holds_without(&s, d), "min 3: d is still needed");
        s.replicaset.as_mut().unwrap().min = 0;
        assert!(holds_without(&s, b), "min 0: always");
    }

    /// FR-90 P2k-2 (F1) — make-before-break: a copy counts toward `min` only
    /// once it holds as much of the session as the one that goes. A member
    /// says `seq` 0 at its floor the moment it joins, which a tip alone
    /// counted; and a tail past where its fence ended holds nothing, on
    /// either side.
    #[test]
    fn a_copy_stands_in_for_a_leaving_one_only_once_it_holds_as_much() {
        use crate::model::{FenceMark, MemberTip};
        let [a, b, d]: [ObjectId; 3] = std::array::from_fn(|_| ObjectId::new());
        let at = |device, state, fence, seq| ReplicaMember {
            tip: Some(MemberTip {
                fence,
                seq,
                hash: "0".repeat(64),
                checkpoint_seq: None,
                checkpoint_hash: None,
                at: DateTime::now(),
            }),
            ..member(device, state, None)
        };
        let mut s = session(a);
        s.replicaset = Some(Replicaset {
            policy_revision: 1,
            min: 2,
            max: 3,
            restricted_tags: Vec::new(),
            members: vec![
                ReplicaMember {
                    role: MemberRole::Primary.as_str().into(),
                    ..at(a, MemberState::Joined, 3, 20)
                },
                at(b, MemberState::Joined, 3, 0),
                at(d, MemberState::Leaving, 3, 20),
            ],
            short: None,
            placed_at: DateTime::now(),
        });
        let set = |s: &mut AgentSession, i: usize, fence: i64, seq: i64| {
            let t = s.replicaset.as_mut().unwrap().members[i]
                .tip
                .as_mut()
                .unwrap();
            (t.fence, t.seq) = (fence, seq);
        };
        assert!(
            !holds_without(&s, d),
            "a replacement that just joined holds nothing yet"
        );
        set(&mut s, 1, 3, 19);
        assert!(!holds_without(&s, d), "one event short is still short");
        set(&mut s, 1, 3, 20);
        assert!(
            holds_without(&s, d),
            "as much as the one that goes: it may go"
        );

        // Fence 2 ended at seq 15.
        s.fences = vec![FenceMark {
            fence: 2,
            seq: 15,
            hash: "1".repeat(64),
        }];
        set(&mut s, 2, 2, 18);
        set(&mut s, 1, 3, 15);
        assert!(
            holds_without(&s, d),
            "the leaving copy's tail past its fence's end holds nothing"
        );
        set(&mut s, 2, 3, 17);
        set(&mut s, 1, 2, 18);
        assert!(
            !holds_without(&s, d),
            "nor does a member's own tail past its fence's end"
        );
    }

    /// FR-90 P2g-4b — a fork made from a leaving member's copy needs that
    /// copy while its first start is out: unanswered, no run of it reported,
    /// at its first fence, no tombstone. One whose record is not made yet
    /// needs it for a start's redelivery window from the fork's id, and no
    /// longer.
    #[test]
    fn a_fork_needs_its_copy_only_while_its_first_start_is_out() {
        let out = AgentSession {
            status: SessionStatus::Starting,
            fence: 1,
            accepted_at: None,
            ..session(ObjectId::new())
        };
        assert!(first_start_out(&out), "unanswered, at its first fence");
        let answered = AgentSession {
            accepted_at: Some(DateTime::now()),
            ..out.clone()
        };
        assert!(
            !first_start_out(&answered),
            "answered: the copy is in place"
        );
        let ran = AgentSession {
            status: SessionStatus::Idle,
            ..out.clone()
        };
        assert!(
            !first_start_out(&ran),
            "a run reported: the copy is in place"
        );
        let lost = AgentSession {
            status: SessionStatus::Lost,
            ..out.clone()
        };
        assert!(!first_start_out(&lost), "a start never to be answered");
        let moved = AgentSession {
            fence: 2,
            ..out.clone()
        };
        assert!(
            !first_start_out(&moved),
            "a later start is made from the fork's own copy"
        );
        let purged = AgentSession {
            purged: Some(PurgedMark {
                purge_id: ObjectId::new(),
                by: ObjectId::new(),
                at: DateTime::now(),
            }),
            ..out
        };
        assert!(!first_start_out(&purged), "a purged fork is made nowhere");

        let now = DateTime::now();
        let named_ago = |ms: i64| {
            let secs = u32::try_from((now.timestamp_millis() - ms) / 1000).unwrap();
            let mut b = ObjectId::new().bytes();
            b[..4].copy_from_slice(&secs.to_be_bytes());
            ObjectId::from_bytes(b)
        };
        let window = hive_limits::START_REDELIVERY_WINDOW_SECS * 1000;
        assert!(may_yet_be_made(named_ago(0), now), "named just now");
        assert!(
            may_yet_be_made(named_ago(window - 5_000), now),
            "still within the window"
        );
        assert!(
            !may_yet_be_made(named_ago(window + 1_000), now),
            "past the window it never will be"
        );
    }
}
