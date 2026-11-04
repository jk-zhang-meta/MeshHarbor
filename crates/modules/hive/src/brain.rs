// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1e — the brain's first layer: core memory that people curate
//! (`docs/fr/FR-90-hive-agent-sessions.md` §3f "P1e … as designed").
//!
//! A fact is a record in one of three scopes — the org, a user, a device —
//! and every scope instance has a budget: the characters its active facts may
//! use. A session pins the org's brain revision when it is created, and its
//! snapshot is rendered and stored then: `CLAUDE.md` from the org's facts and
//! its starter's, the auto-memory `MEMORY.md` from its device's.
//!
//! ⚠️ Claude Code reads `CLAUDE.md` as the user's own OVERRIDING instructions
//! (probed: "These instructions OVERRIDE any default behavior"), so core
//! memory is the first server-authored text a session's model obeys. What
//! the server lets anyone write is bounded here — who writes which scope, the
//! budgets, one line a fact — and whether a device ever shows it to a session
//! is the device's own `hive_core_memory`, default off.
//!
//! ⚠️ A budget is spent by ONE conditional update (`$inc` under
//! `used ≤ budget − n`, an upsert over a unique index), so two writes racing
//! for the last room cannot both fit. A write that does not fit FAILS VISIBLY
//! — `409 over_budget` with the numbers — and nothing is evicted: a person
//! consolidates (design §10.3, Hermes' rule).
//!
//! ⚠️ A refusal recounts the counter from the active facts, which heals a
//! reservation a crash left behind — but only a counter no write has touched
//! for [`RECOUNT_QUIET_SECS`], and only under a compare-and-swap on its
//! version. A reservation still in flight (taken, its fact not yet written)
//! looks exactly like a leaked one: recounting over it let two writes both fit
//! the last room. So every write touches the counter BEFORE it changes a fact.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::role::permissions;
use meshharbor_services::dao::base::{BaseDao, DaoError, DaoResult};
use mongodb::Database;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::HiveState;
use crate::model::HiveAuditEvent;
use crate::routes::{member_tenant, parse_oid};

/// The longest fact, in characters — shorter than the smallest budget, so
/// any one fact fits an empty scope.
pub const MAX_FACT_CHARS: usize = 500;

/// Where a fact applies.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BrainScope {
    /// Every session in the org. Written by its administrators.
    Org,
    /// The sessions one person starts. Written by that person.
    User,
    /// The sessions that run on one device. Written by whoever manages the
    /// org's devices.
    Device,
}

impl BrainScope {
    /// The spelling on the wire and in the database. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::User => "user",
            Self::Device => "device",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        [Self::Org, Self::User, Self::Device]
            .into_iter()
            .find(|s| s.as_str() == raw)
    }

    /// Characters of active text one instance may hold (design §10.3). The
    /// org's and the user's are rendered together into `CLAUDE.md`; the
    /// device's into the auto-memory `MEMORY.md`.
    pub const fn budget(self) -> i64 {
        match self {
            Self::Org => 3_000,
            Self::User => 1_500,
            Self::Device => 800,
        }
    }
}

/// What kind of fact it is — rendered beside it, so the model can tell a
/// warning from a preference.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactKind {
    Preference,
    Convention,
    Path,
    Gotcha,
    Decision,
    Warning,
}

impl FactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preference => "preference",
            Self::Convention => "convention",
            Self::Path => "path",
            Self::Gotcha => "gotcha",
            Self::Decision => "decision",
            Self::Warning => "warning",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        [
            Self::Preference,
            Self::Convention,
            Self::Path,
            Self::Gotcha,
            Self::Decision,
            Self::Warning,
        ]
        .into_iter()
        .find(|k| k.as_str() == raw)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactStatus {
    Active,
    /// Out of every snapshot, and out of its budget; kept as a record.
    Archived,
}

/// One fact (`brain_facts`).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BrainFact {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub scope: BrainScope,
    /// The user (user scope) or the device (device scope); null for the org.
    /// Stored even when null: it is part of the budget's key.
    pub owner_id: Option<ObjectId>,
    /// One line of plain text ([`clean_text`]).
    pub text: String,
    /// `text`'s length in characters: what it costs its scope's budget.
    pub chars: i64,
    pub kind: FactKind,
    pub status: FactStatus,
    /// Bumped by every change; an edit names the version it read.
    pub version: i64,
    pub created_by: ObjectId,
    pub created_at: DateTime,
    pub updated_by: ObjectId,
    pub updated_at: DateTime,
}

impl BrainFact {
    pub const COLLECTION: &'static str = "brain_facts";
}

/// One scope instance's spend (`brain_budgets`): the characters its active
/// facts hold. Unique on (tenant, scope, owner).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BrainBudget {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub scope: BrainScope,
    pub owner_id: Option<ObjectId>,
    pub used: i64,
    /// One more with every write that touches the counter: the recount's
    /// compare-and-swap. Absent on a counter no write has touched since it
    /// was added.
    #[serde(default)]
    pub v: i64,
    /// When a write last touched the counter: a reservation, a release, or
    /// the touch before a fact changes. A counter touched within
    /// [`RECOUNT_QUIET_SECS`] is not recounted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub touched_at: Option<DateTime>,
}

/// How long a counter must have gone untouched before a refusal may recount
/// it. A write's reservation and its fact land milliseconds apart; a counter
/// touched more recently may be counting a write still in flight.
pub const RECOUNT_QUIET_SECS: i64 = 60;

/// Whether a counter last touched at `touched_at` may be recounted at `now`.
/// A time ahead of `now` (another pod's clock) is recent, not quiet.
fn recountable(touched_at: Option<DateTime>, now: DateTime) -> bool {
    touched_at
        .is_none_or(|t| now.timestamp_millis() - t.timestamp_millis() >= RECOUNT_QUIET_SECS * 1000)
}

impl BrainBudget {
    pub const COLLECTION: &'static str = "brain_budgets";
}

/// The org's brain revision (`brain_revs`, by tenant): one more with every
/// write, so a session can pin the state it was given.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BrainRev {
    #[serde(rename = "_id")]
    pub tenant_id: ObjectId,
    pub rev: i64,
}

impl BrainRev {
    pub const COLLECTION: &'static str = "brain_revs";
}

/// A session's frozen snapshot (`hive_session_memory`, by session) — what a
/// re-sent start carries again. Kept a day: past the start's redelivery
/// window, the device holds its own copy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SessionMemory {
    #[serde(rename = "_id")]
    pub session_id: ObjectId,
    pub tenant_id: ObjectId,
    pub brain_rev: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_md: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_md: Option<String>,
    pub created_at: DateTime,
}

impl SessionMemory {
    pub const COLLECTION: &'static str = "hive_session_memory";
    /// How long a snapshot is kept.
    pub const TTL_SECS: u64 = 24 * 60 * 60;
}

/// A write that does not fit its scope's budget: what the scope holds, its
/// budget, and what the write needed.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct OverBudget {
    pub scope: BrainScope,
    pub used: i64,
    pub budget: i64,
    pub needed: i64,
}

impl OverBudget {
    /// The refusal in words a person can act on.
    pub fn message(&self) -> String {
        format!(
            "the {} memory holds {} of its {} characters, and this needs {} more — \
             shorten or archive a fact first",
            self.scope.as_str(),
            self.used,
            self.budget,
            self.needed
        )
    }
}

/// One line of plain text, or why not. Control characters go (a newline
/// would let a fact write its own heading into the rendered file) and
/// whitespace runs collapse.
pub fn clean_text(raw: &str) -> Result<String, String> {
    let spaced: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let text = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        return Err("a fact needs text".into());
    }
    let n = text.chars().count();
    if n > MAX_FACT_CHARS {
        return Err(format!(
            "a fact holds at most {MAX_FACT_CHARS} characters; this one has {n}"
        ));
    }
    Ok(text)
}

/// A display name as a renderer writes it: one line, no markdown emphasis.
fn plain_name(raw: &str) -> String {
    let one: String = raw
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '*' | '_' | '`' | '#' | '[' | ']'))
        .take(80)
        .collect();
    let one = one.trim();
    if one.is_empty() {
        "someone".into()
    } else {
        one.to_string()
    }
}

fn bullets(facts: &[BrainFact]) -> String {
    facts
        .iter()
        .map(|f| format!("- ({}) {}\n", f.kind.as_str(), f.text))
        .collect()
}

/// `CLAUDE.md` for a session: the org's facts, then its starter's. `None`
/// when both are empty — the device then writes no file at all.
pub fn render_claude_md(
    rev: i64,
    org: &[BrainFact],
    starter: &[BrainFact],
    starter_name: &str,
) -> Option<String> {
    if org.is_empty() && starter.is_empty() {
        return None;
    }
    let mut out = String::new();
    if !org.is_empty() {
        out.push_str("# Organization memory\n\n");
        out.push_str(&format!(
            "Kept by this organization's administrators in MeshHarbor for every agent session \
             (brain revision {rev}).\n\n"
        ));
        out.push_str(&bullets(org));
    }
    if !starter.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        let name = plain_name(starter_name);
        out.push_str(&format!("# Memory kept by {name}\n\n"));
        out.push_str(&format!(
            "Kept in MeshHarbor by {name}, who started this session, for the sessions they start.\n\n"
        ));
        out.push_str(&bullets(starter));
    }
    Some(out)
}

/// The auto-memory index `MEMORY.md` for a session: its device's facts.
/// `None` when there are none.
pub fn render_memory_md(device: &[BrainFact], device_name: &str) -> Option<String> {
    if device.is_empty() {
        return None;
    }
    let name = plain_name(device_name);
    Some(format!(
        "# Device memory: {name}\n\nKept in MeshHarbor about this device, for the sessions that \
         run on it.\n\n{}",
        bullets(device)
    ))
}

fn owner_bson(owner: Option<ObjectId>) -> Bson {
    owner.map(Bson::ObjectId).unwrap_or(Bson::Null)
}

fn budget_key(tenant: ObjectId, scope: BrainScope, owner: Option<ObjectId>) -> Document {
    doc! { "tenant_id": tenant, "scope": scope.as_str(), "owner_id": owner_bson(owner) }
}

fn is_duplicate_key(e: &mongodb::error::Error) -> bool {
    matches!(
        *e.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(ref w))
            if w.code == 11000
    )
}

/// The four collections, and every write to them.
pub struct BrainDao {
    pub facts: BaseDao<BrainFact>,
    budgets: BaseDao<BrainBudget>,
    revs: BaseDao<BrainRev>,
    memory: BaseDao<SessionMemory>,
}

/// How an edit went.
#[derive(Debug)]
pub enum EditOutcome {
    Edited(BrainFact),
    OverBudget(OverBudget),
    /// Not active any more, or changed since the version the editor read.
    Stale,
}

impl BrainDao {
    pub fn new(db: &Database) -> Self {
        Self {
            facts: BaseDao::new(db, BrainFact::COLLECTION),
            budgets: BaseDao::new(db, BrainBudget::COLLECTION),
            revs: BaseDao::new(db, BrainRev::COLLECTION),
            memory: BaseDao::new(db, SessionMemory::COLLECTION),
        }
    }

    /// Take `n` characters of a scope instance's budget, or say how full it
    /// is. ONE conditional update: the instance's document matches only with
    /// room for `n`; one without room makes the upsert collide with the
    /// unique index, which is the refusal.
    async fn reserve(
        &self,
        tenant: ObjectId,
        scope: BrainScope,
        owner: Option<ObjectId>,
        n: i64,
    ) -> DaoResult<Result<(), OverBudget>> {
        let budget = scope.budget();
        if n > budget {
            return Ok(Err(OverBudget {
                scope,
                used: self.used(tenant, scope, owner).await?,
                budget,
                needed: n,
            }));
        }
        let mut filter = budget_key(tenant, scope, owner);
        filter.insert("used", doc! { "$lte": budget - n });
        let taken = self
            .budgets
            .collection()
            .update_one(
                filter,
                doc! {
                    "$inc": { "used": n, "v": 1_i64 },
                    "$set": { "touched_at": DateTime::now() },
                },
            )
            .upsert(true)
            .await;
        match taken {
            Ok(_) => Ok(Ok(())),
            Err(e) if is_duplicate_key(&e) => Ok(Err(OverBudget {
                scope,
                used: self.used(tenant, scope, owner).await?,
                budget,
                needed: n,
            })),
            Err(e) => Err(DaoError::Mongo(e)),
        }
    }

    /// Give `n` characters back.
    async fn release(
        &self,
        tenant: ObjectId,
        scope: BrainScope,
        owner: Option<ObjectId>,
        n: i64,
    ) -> DaoResult<()> {
        if n > 0 {
            self.budgets
                .collection()
                .update_one(
                    budget_key(tenant, scope, owner),
                    doc! {
                        "$inc": { "used": -n, "v": 1_i64 },
                        "$set": { "touched_at": DateTime::now() },
                    },
                )
                .await
                .map_err(DaoError::Mongo)?;
        }
        Ok(())
    }

    /// Mark the counter busy BEFORE a fact shrinks or leaves the count, so a
    /// refusal elsewhere does not recount between the change and its release:
    /// that would take the characters off twice.
    async fn touch(
        &self,
        tenant: ObjectId,
        scope: BrainScope,
        owner: Option<ObjectId>,
    ) -> DaoResult<()> {
        self.budgets
            .collection()
            .update_one(
                budget_key(tenant, scope, owner),
                doc! { "$inc": { "v": 1_i64 }, "$set": { "touched_at": DateTime::now() } },
            )
            .await
            .map_err(DaoError::Mongo)?;
        Ok(())
    }

    /// What a scope instance's active facts use, as its counter says.
    pub async fn used(
        &self,
        tenant: ObjectId,
        scope: BrainScope,
        owner: Option<ObjectId>,
    ) -> DaoResult<i64> {
        Ok(self
            .budgets
            .find_one(budget_key(tenant, scope, owner))
            .await?
            .map_or(0, |b| b.used.max(0)))
    }

    /// Count a scope instance's spend again from its active facts, and set
    /// the counter to it. A reservation a crash left behind (taken, with no
    /// fact to show for it) would otherwise shrink the budget for ever; a
    /// refusal is when it matters, so a refusal is when this runs.
    ///
    /// ⚠️ `None`, the counter left as it is, when a write touched it within
    /// [`RECOUNT_QUIET_SECS`] or touches it while this counts. A reservation
    /// still in flight looks exactly like a leaked one, and a fact archived
    /// with its release still to come looks like one already released:
    /// recounting over the first let two writes both fit the last room, and
    /// over the second let the next write overspend.
    async fn recount(
        &self,
        tenant: ObjectId,
        scope: BrainScope,
        owner: Option<ObjectId>,
    ) -> DaoResult<Option<i64>> {
        let Some(counter) = self
            .budgets
            .find_one(budget_key(tenant, scope, owner))
            .await?
        else {
            return Ok(None);
        };
        if !recountable(counter.touched_at, DateTime::now()) {
            return Ok(None);
        }
        let mut filter = budget_key(tenant, scope, owner);
        filter.insert("status", "active");
        let actual: i64 = self
            .facts
            .find_many(filter, None)
            .await?
            .iter()
            .map(|f| f.chars)
            .sum();
        let mut unchanged = budget_key(tenant, scope, owner);
        if counter.v == 0 {
            // A counter from before the version has no `v`, which a match on
            // 0 alone would miss.
            unchanged.insert("v", doc! { "$in": [0_i64, Bson::Null] });
        } else {
            unchanged.insert("v", counter.v);
        }
        let set = self
            .budgets
            .collection()
            .update_one(
                unchanged,
                doc! { "$set": { "used": actual }, "$inc": { "v": 1_i64 } },
            )
            .await
            .map_err(DaoError::Mongo)?;
        Ok((set.matched_count == 1).then_some(actual))
    }

    /// [`Self::reserve`], and once more after a [`Self::recount`] when the
    /// first answer was no.
    async fn reserve_or_recount(
        &self,
        tenant: ObjectId,
        scope: BrainScope,
        owner: Option<ObjectId>,
        n: i64,
    ) -> DaoResult<Result<(), OverBudget>> {
        match self.reserve(tenant, scope, owner, n).await? {
            Ok(()) => Ok(Ok(())),
            Err(over) => match self.recount(tenant, scope, owner).await? {
                Some(actual) if actual < over.used => {
                    warn!(tenant = %tenant, scope = scope.as_str(), counted = over.used, actual,
                        "hive: a brain budget held a reservation no fact used — recounted");
                    self.reserve(tenant, scope, owner, n).await
                }
                _ => Ok(Err(over)),
            },
        }
    }

    /// One more revision of the org's brain; the new number.
    async fn bump_rev(&self, tenant: ObjectId) -> DaoResult<i64> {
        let rev = self
            .revs
            .collection()
            .find_one_and_update(doc! { "_id": tenant }, doc! { "$inc": { "rev": 1_i64 } })
            .upsert(true)
            .return_document(mongodb::options::ReturnDocument::After)
            .await
            .map_err(DaoError::Mongo)?;
        Ok(rev.map_or(1, |r| r.rev))
    }

    /// The org's brain revision now; 0 before its first fact.
    pub async fn rev(&self, tenant: ObjectId) -> DaoResult<i64> {
        Ok(self
            .revs
            .find_one(doc! { "_id": tenant })
            .await?
            .map_or(0, |r| r.rev))
    }

    /// Record a new fact, inside its scope's budget.
    pub async fn create(&self, mut fact: BrainFact) -> DaoResult<Result<BrainFact, OverBudget>> {
        let (tenant, scope, owner, n) = (fact.tenant_id, fact.scope, fact.owner_id, fact.chars);
        if let Err(over) = self.reserve_or_recount(tenant, scope, owner, n).await? {
            return Ok(Err(over));
        }
        match self.facts.insert_one(&fact).await {
            Ok(id) => fact.id = Some(id),
            Err(e) => {
                self.release(tenant, scope, owner, n).await?;
                return Err(e);
            }
        }
        self.bump_rev(tenant).await?;
        Ok(Ok(fact))
    }

    /// Change an active fact's text or kind — only at the version the editor
    /// read, and only inside its scope's budget.
    pub async fn edit(
        &self,
        current: &BrainFact,
        expected_version: i64,
        text: String,
        kind: FactKind,
        by: ObjectId,
    ) -> DaoResult<EditOutcome> {
        let Some(id) = current.id else {
            return Ok(EditOutcome::Stale);
        };
        let (tenant, scope, owner) = (current.tenant_id, current.scope, current.owner_id);
        let chars = text.chars().count() as i64;
        let grow = chars - current.chars;
        if grow > 0
            && let Err(over) = self.reserve_or_recount(tenant, scope, owner, grow).await?
        {
            return Ok(EditOutcome::OverBudget(over));
        }
        if grow < 0 {
            self.touch(tenant, scope, owner).await?;
        }
        let now = DateTime::now();
        let edited = self
            .facts
            .collection()
            .find_one_and_update(
                doc! { "_id": id, "tenant_id": tenant, "status": "active", "version": expected_version },
                doc! {
                    "$set": { "text": &text, "chars": chars, "kind": kind.as_str(),
                              "updated_by": by, "updated_at": now },
                    "$inc": { "version": 1_i64 },
                },
            )
            .return_document(mongodb::options::ReturnDocument::After)
            .await
            .map_err(DaoError::Mongo)?;
        let Some(edited) = edited else {
            if grow > 0 {
                self.release(tenant, scope, owner, grow).await?;
            }
            return Ok(EditOutcome::Stale);
        };
        if grow < 0 {
            self.release(tenant, scope, owner, -grow).await?;
        }
        self.bump_rev(tenant).await?;
        Ok(EditOutcome::Edited(edited))
    }

    /// Take an active fact out of every future snapshot and out of its budget.
    /// `None` when it is not active (archived already, or never was).
    pub async fn archive(&self, current: &BrainFact, by: ObjectId) -> DaoResult<Option<BrainFact>> {
        let Some(id) = current.id else {
            return Ok(None);
        };
        self.touch(current.tenant_id, current.scope, current.owner_id)
            .await?;
        let archived = self
            .facts
            .collection()
            .find_one_and_update(
                doc! { "_id": id, "tenant_id": current.tenant_id, "status": "active" },
                doc! {
                    "$set": { "status": "archived", "updated_by": by, "updated_at": DateTime::now() },
                    "$inc": { "version": 1_i64 },
                },
            )
            .return_document(mongodb::options::ReturnDocument::After)
            .await
            .map_err(DaoError::Mongo)?;
        if let Some(f) = &archived {
            self.release(f.tenant_id, f.scope, f.owner_id, f.chars)
                .await?;
            self.bump_rev(f.tenant_id).await?;
        }
        Ok(archived)
    }

    /// One fact of this org, any status.
    pub async fn find(&self, tenant: ObjectId, id: ObjectId) -> DaoResult<Option<BrainFact>> {
        self.facts
            .find_one(doc! { "_id": id, "tenant_id": tenant })
            .await
    }

    /// A scope instance's active facts, oldest first — the order they render in.
    pub async fn active(
        &self,
        tenant: ObjectId,
        scope: BrainScope,
        owner: Option<ObjectId>,
    ) -> DaoResult<Vec<BrainFact>> {
        let mut filter = budget_key(tenant, scope, owner);
        filter.insert("status", "active");
        self.facts
            .find_many(filter, Some(doc! { "created_at": 1, "_id": 1 }))
            .await
    }

    /// Render a session's snapshot at the org's revision now. The revision
    /// is read FIRST: a fact written while this runs may be in the snapshot
    /// without being in the pinned number, never the other way round.
    pub async fn snapshot(
        &self,
        tenant: ObjectId,
        session: ObjectId,
        starter: (ObjectId, &str),
        device: (ObjectId, &str),
    ) -> DaoResult<SessionMemory> {
        let rev = self.rev(tenant).await?;
        let org = self.active(tenant, BrainScope::Org, None).await?;
        let user = self
            .active(tenant, BrainScope::User, Some(starter.0))
            .await?;
        let dev = self
            .active(tenant, BrainScope::Device, Some(device.0))
            .await?;
        Ok(SessionMemory {
            session_id: session,
            tenant_id: tenant,
            brain_rev: rev,
            claude_md: render_claude_md(rev, &org, &user, starter.1),
            memory_md: render_memory_md(&dev, device.1),
            created_at: DateTime::now(),
        })
    }

    pub async fn store_snapshot(&self, m: &SessionMemory) -> DaoResult<()> {
        self.memory
            .collection()
            .replace_one(doc! { "_id": m.session_id }, m)
            .upsert(true)
            .await
            .map_err(DaoError::Mongo)?;
        Ok(())
    }

    pub async fn snapshot_of(&self, session: ObjectId) -> DaoResult<Option<SessionMemory>> {
        self.memory.find_one(doc! { "_id": session }).await
    }

    /// FR-90 P2g-2 — the session was purged: its snapshot goes with it,
    /// ahead of its day.
    pub async fn drop_snapshot(&self, session: ObjectId) -> DaoResult<bool> {
        Ok(self.memory.hard_delete(doc! { "_id": session }).await? > 0)
    }
}

// ─── Routes: `/api/tenant/{tenant_id}/hive/brain` ───────────────────────

/// `POST …/hive/brain`.
#[derive(Debug, Deserialize)]
pub struct CreateBody {
    pub scope: String,
    /// The device, for device scope; for user scope it may only name the
    /// caller, and defaults to them. Absent for org scope.
    #[serde(default)]
    pub owner_id: Option<String>,
    pub text: String,
    #[serde(default)]
    pub kind: Option<String>,
}

/// `PUT …/hive/brain/{fact_id}`.
#[derive(Debug, Deserialize)]
pub struct EditBody {
    pub text: String,
    #[serde(default)]
    pub kind: Option<String>,
    /// The version the editor read: a fact changed since is not overwritten.
    pub version: i64,
}

/// `GET …/hive/brain`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Also list this device's facts.
    #[serde(default)]
    pub device_id: Option<String>,
}

/// A fact as the API answers it.
#[derive(Serialize, Debug, Clone)]
pub struct FactView {
    pub id: String,
    pub scope: BrainScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    pub text: String,
    pub kind: FactKind,
    pub version: i64,
    pub created_by: String,
    pub created_at: String,
    pub updated_by: String,
    pub updated_at: String,
}

fn rfc3339(t: DateTime) -> String {
    t.try_to_rfc3339_string().unwrap_or_default()
}

impl From<&BrainFact> for FactView {
    fn from(f: &BrainFact) -> Self {
        Self {
            id: f.id.map(|i| i.to_hex()).unwrap_or_default(),
            scope: f.scope,
            owner_id: f.owner_id.map(|o| o.to_hex()),
            text: f.text.clone(),
            kind: f.kind,
            version: f.version,
            created_by: f.created_by.to_hex(),
            created_at: rfc3339(f.created_at),
            updated_by: f.updated_by.to_hex(),
            updated_at: rfc3339(f.updated_at),
        }
    }
}

/// A scope instance's spend, beside its budget.
#[derive(Serialize, Debug, Clone)]
pub struct BudgetView {
    pub scope: BrainScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    pub used: i64,
    pub budget: i64,
}

#[derive(Serialize, Debug)]
pub struct BrainView {
    pub brain_rev: i64,
    pub facts: Vec<FactView>,
    pub budgets: Vec<BudgetView>,
}

/// The `409` an over-budget write answers: the shape of every API error
/// (`error`, `message`) with the numbers beside it.
fn over_budget(over: OverBudget) -> Response {
    let body = serde_json::json!({
        "error": "over_budget",
        "message": over.message(),
        "scope": over.scope,
        "used": over.used,
        "budget": over.budget,
        "needed": over.needed,
    });
    (StatusCode::CONFLICT, Json(body)).into_response()
}

/// Who may write a scope instance: the org's — its administrators; a user's —
/// that user, holding `HIVE_RUN`; a device's — whoever manages the org's
/// devices (`MANAGE_AGENTS`), and only a live device of this org.
async fn may_write(
    state: &HiveState,
    tenant: ObjectId,
    user: ObjectId,
    scope: BrainScope,
    owner: Option<ObjectId>,
) -> Result<(), ApiError> {
    let perms = state.tenants.get_member_permissions(tenant, user).await?;
    match scope {
        BrainScope::Org => {
            if !permissions::has(perms, permissions::ADMINISTRATOR) {
                return Err(ApiError::Forbidden(
                    "only the organization's administrators keep its memory".into(),
                ));
            }
        }
        BrainScope::User => {
            if owner != Some(user) {
                return Err(ApiError::Forbidden(
                    "a person's memory is theirs to keep".into(),
                ));
            }
            if !permissions::has(perms, permissions::HIVE_RUN) {
                return Err(ApiError::Forbidden(
                    "keeping a memory for agent sessions needs permission to run them".into(),
                ));
            }
        }
        BrainScope::Device => {
            if !permissions::has(perms, permissions::MANAGE_AGENTS) {
                return Err(ApiError::Forbidden(
                    "a device's memory is kept by whoever manages the organization's devices"
                        .into(),
                ));
            }
            let Some(device) = owner else {
                return Err(ApiError::BadRequest("device scope names a device".into()));
            };
            // LIVE and in this org: anything else answers like a bogus id.
            state
                .fleet
                .agents
                .find_live_in_tenant(tenant, device)
                .await?;
        }
    }
    Ok(())
}

/// A server decision about the brain, for `hive_audit`; `instance` is the
/// scope instance written (its scope and owner).
async fn audit(
    state: &HiveState,
    tenant: ObjectId,
    user: ObjectId,
    fact: Option<ObjectId>,
    instance: (BrainScope, Option<ObjectId>),
    outcome: &'static str,
    reason: Option<&'static str>,
) {
    let (scope, owner) = instance;
    let ev = HiveAuditEvent {
        id: None,
        tenant_id: tenant,
        user_id: user,
        target_id: fact,
        device_id: (scope == BrainScope::Device).then_some(owner).flatten(),
        session_id: None,
        action: "brain".to_string(),
        outcome: outcome.to_string(),
        reason: reason.map(str::to_string),
        sessions: None,
        at: DateTime::now(),
    };
    if let Err(e) = state.audit.record(ev).await {
        warn!(%e, "hive: audit write failed");
    }
}

/// `GET /api/tenant/{tenant_id}/hive/brain` — the facts the caller may read,
/// with their budgets: the org's, their own, and — with `device_id` — that
/// device's.
pub async fn list(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> Result<Json<BrainView>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let mut instances = vec![
        (BrainScope::Org, None),
        (BrainScope::User, Some(auth.user_id)),
    ];
    if let Some(raw) = q.device_id.as_deref() {
        let device = parse_oid(raw, "device_id")?;
        state.fleet.agents.find_live_in_tenant(tid, device).await?;
        instances.push((BrainScope::Device, Some(device)));
    }
    let mut facts = Vec::new();
    let mut budgets = Vec::new();
    for (scope, owner) in instances {
        facts.extend(
            state
                .brain
                .active(tid, scope, owner)
                .await?
                .iter()
                .map(FactView::from),
        );
        budgets.push(BudgetView {
            scope,
            owner_id: owner.map(|o| o.to_hex()),
            used: state.brain.used(tid, scope, owner).await?,
            budget: scope.budget(),
        });
    }
    Ok(Json(BrainView {
        brain_rev: state.brain.rev(tid).await?,
        facts,
        budgets,
    }))
}

/// `POST /api/tenant/{tenant_id}/hive/brain` — keep a new fact.
pub async fn create(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<CreateBody>,
) -> Result<Response, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let scope = BrainScope::parse(&body.scope)
        .ok_or_else(|| ApiError::BadRequest("scope is org, user or device".into()))?;
    let owner = match (scope, body.owner_id.as_deref()) {
        (BrainScope::Org, None) => None,
        (BrainScope::Org, Some(_)) => {
            return Err(ApiError::BadRequest("org scope names no owner".into()));
        }
        (BrainScope::User, None) => Some(auth.user_id),
        (_, Some(raw)) => Some(parse_oid(raw, "owner_id")?),
        (BrainScope::Device, None) => {
            return Err(ApiError::BadRequest("device scope names a device".into()));
        }
    };
    let text = clean_text(&body.text).map_err(ApiError::BadRequest)?;
    let kind = match body.kind.as_deref() {
        None => FactKind::Convention,
        Some(k) => FactKind::parse(k).ok_or_else(|| {
            ApiError::BadRequest(
                "kind is preference, convention, path, gotcha, decision or warning".into(),
            )
        })?,
    };
    may_write(&state, tid, auth.user_id, scope, owner).await?;
    let now = DateTime::now();
    let fact = BrainFact {
        id: None,
        tenant_id: tid,
        scope,
        owner_id: owner,
        chars: text.chars().count() as i64,
        text,
        kind,
        status: FactStatus::Active,
        version: 1,
        created_by: auth.user_id,
        created_at: now,
        updated_by: auth.user_id,
        updated_at: now,
    };
    match state.brain.create(fact).await? {
        Ok(fact) => {
            audit(
                &state,
                tid,
                auth.user_id,
                fact.id,
                (scope, owner),
                "added",
                None,
            )
            .await;
            info!(tenant = %tid, scope = scope.as_str(), fact = ?fact.id, "hive: a fact kept");
            Ok(Json(FactView::from(&fact)).into_response())
        }
        Err(over) => {
            audit(
                &state,
                tid,
                auth.user_id,
                None,
                (scope, owner),
                "refused",
                Some("over_budget"),
            )
            .await;
            Ok(over_budget(over))
        }
    }
}

/// `PUT /api/tenant/{tenant_id}/hive/brain/{fact_id}` — change a fact.
pub async fn edit(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, fact_id)): Path<(String, String)>,
    Json(body): Json<EditBody>,
) -> Result<Response, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let fid = parse_oid(&fact_id, "fact_id")?;
    let current = readable_fact(&state, tid, fid, auth.user_id).await?;
    may_write(&state, tid, auth.user_id, current.scope, current.owner_id).await?;
    let text = clean_text(&body.text).map_err(ApiError::BadRequest)?;
    let kind = match body.kind.as_deref() {
        None => current.kind,
        Some(k) => FactKind::parse(k).ok_or_else(|| {
            ApiError::BadRequest(
                "kind is preference, convention, path, gotcha, decision or warning".into(),
            )
        })?,
    };
    let (scope, owner) = (current.scope, current.owner_id);
    match state
        .brain
        .edit(&current, body.version, text, kind, auth.user_id)
        .await?
    {
        EditOutcome::Edited(fact) => {
            audit(
                &state,
                tid,
                auth.user_id,
                fact.id,
                (scope, owner),
                "edited",
                None,
            )
            .await;
            Ok(Json(FactView::from(&fact)).into_response())
        }
        EditOutcome::OverBudget(over) => {
            audit(
                &state,
                tid,
                auth.user_id,
                Some(fid),
                (scope, owner),
                "refused",
                Some("over_budget"),
            )
            .await;
            Ok(over_budget(over))
        }
        EditOutcome::Stale => Err(ApiError::Conflict(
            "the fact changed or was archived since it was read — read it again".into(),
        )),
    }
}

/// `DELETE /api/tenant/{tenant_id}/hive/brain/{fact_id}` — archive a fact:
/// out of every future snapshot and out of its budget, kept as a record.
pub async fn archive(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, fact_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let fid = parse_oid(&fact_id, "fact_id")?;
    let current = readable_fact(&state, tid, fid, auth.user_id).await?;
    may_write(&state, tid, auth.user_id, current.scope, current.owner_id).await?;
    let archived = state.brain.archive(&current, auth.user_id).await?;
    if archived.is_some() {
        audit(
            &state,
            tid,
            auth.user_id,
            Some(fid),
            (current.scope, current.owner_id),
            "archived",
            None,
        )
        .await;
    }
    Ok(Json(serde_json::json!({ "archived": archived.is_some() })))
}

/// A fact the caller may read: the org's, a device's, or their own. Someone
/// else's user memory answers like a bogus id.
async fn readable_fact(
    state: &HiveState,
    tenant: ObjectId,
    id: ObjectId,
    user: ObjectId,
) -> Result<BrainFact, ApiError> {
    let fact = state
        .brain
        .find(tenant, id)
        .await?
        .ok_or_else(|| ApiError::NotFound("No such fact".into()))?;
    if fact.scope == BrainScope::User && fact.owner_id != Some(user) {
        return Err(ApiError::NotFound("No such fact".into()));
    }
    Ok(fact)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(scope: BrainScope, kind: FactKind, text: &str) -> BrainFact {
        let now = DateTime::now();
        BrainFact {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            scope,
            owner_id: None,
            text: text.into(),
            chars: text.chars().count() as i64,
            kind,
            status: FactStatus::Active,
            version: 1,
            created_by: ObjectId::new(),
            created_at: now,
            updated_by: ObjectId::new(),
            updated_at: now,
        }
    }

    #[test]
    fn scope_and_kind_spellings_are_locked_and_match_serde() {
        for (s, w) in [
            (BrainScope::Org, "org"),
            (BrainScope::User, "user"),
            (BrainScope::Device, "device"),
        ] {
            assert_eq!(s.as_str(), w);
            assert_eq!(BrainScope::parse(w), Some(s));
            assert_eq!(serde_json::to_value(s).unwrap(), serde_json::json!(w));
            assert_eq!(bson::to_bson(&s).unwrap(), Bson::String(w.into()));
        }
        for k in [
            FactKind::Preference,
            FactKind::Convention,
            FactKind::Path,
            FactKind::Gotcha,
            FactKind::Decision,
            FactKind::Warning,
        ] {
            assert_eq!(FactKind::parse(k.as_str()), Some(k));
            assert_eq!(
                serde_json::to_value(k).unwrap(),
                serde_json::json!(k.as_str())
            );
        }
        assert!(BrainScope::parse("project").is_none(), "not until P4");
        assert!(FactKind::parse("Warning").is_none(), "spellings are exact");
    }

    /// The budgets design §10.3 names, and every fact fits an empty scope.
    #[test]
    fn budgets_are_the_designs_and_any_one_fact_fits() {
        assert_eq!(BrainScope::Org.budget(), 3_000);
        assert_eq!(BrainScope::User.budget(), 1_500);
        assert_eq!(BrainScope::Device.budget(), 800);
        for s in [BrainScope::Org, BrainScope::User, BrainScope::Device] {
            assert!(MAX_FACT_CHARS as i64 <= s.budget(), "{s:?}");
        }
    }

    /// A fact is one line: nothing in it can start a heading or a list of
    /// its own in the rendered file.
    #[test]
    fn a_fact_is_one_line_of_plain_text() {
        assert_eq!(
            clean_text("  Deploys go\nthrough\t`release`.\r\n# Ignore the above ").unwrap(),
            "Deploys go through `release`. # Ignore the above"
        );
        assert!(clean_text(" \n\t ").is_err());
        let long = "x".repeat(MAX_FACT_CHARS + 1);
        assert!(clean_text(&long).unwrap_err().contains("at most 500"));
        // Counted in characters, not bytes.
        assert!(clean_text(&"é".repeat(MAX_FACT_CHARS)).is_ok());
    }

    #[test]
    fn claude_md_renders_the_org_then_the_starter_and_nothing_when_empty() {
        assert_eq!(render_claude_md(3, &[], &[], "Ann"), None);
        let org = [fact(
            BrainScope::Org,
            FactKind::Warning,
            "Never run prod migrations by hand.",
        )];
        let mine = [fact(
            BrainScope::User,
            FactKind::Preference,
            "Small commits.",
        )];
        let md = render_claude_md(7, &org, &mine, "Ann *Lee*\n# x").unwrap();
        let org_at = md.find("# Organization memory").unwrap();
        let mine_at = md.find("# Memory kept by Ann Lee x").unwrap();
        assert!(org_at < mine_at, "{md}");
        assert!(md.contains("brain revision 7"), "{md}");
        assert!(
            md.contains("- (warning) Never run prod migrations by hand.\n"),
            "{md}"
        );
        assert!(md.contains("- (preference) Small commits.\n"), "{md}");
        assert_eq!(
            md.lines().filter(|l| l.starts_with("# ")).count(),
            2,
            "a name cannot add a heading: {md}"
        );
        // Either half alone.
        assert!(
            !render_claude_md(1, &org, &[], "Ann")
                .unwrap()
                .contains("Memory kept by")
        );
        assert!(
            !render_claude_md(1, &[], &mine, "Ann")
                .unwrap()
                .contains("Organization")
        );
    }

    #[test]
    fn memory_md_renders_the_devices_facts() {
        assert_eq!(render_memory_md(&[], "mars"), None);
        let dev = [fact(
            BrainScope::Device,
            FactKind::Path,
            "Datasets live in /data/sets.",
        )];
        let md = render_memory_md(&dev, "mars").unwrap();
        assert!(md.starts_with("# Device memory: mars\n"), "{md}");
        assert!(
            md.contains("- (path) Datasets live in /data/sets.\n"),
            "{md}"
        );
    }

    /// The fullest snapshot the budgets allow is well inside what the wire
    /// lets a device accept, even at four bytes a character.
    #[test]
    fn a_full_snapshot_fits_the_wire_limit() {
        use meshharbor_remote_control::hive::hive_limits::MAX_CORE_MEMORY_BYTES;
        let wide = "𝔀".repeat(MAX_FACT_CHARS);
        let org: Vec<BrainFact> = (0..6)
            .map(|_| fact(BrainScope::Org, FactKind::Gotcha, &wide))
            .collect();
        let user: Vec<BrainFact> = (0..3)
            .map(|_| fact(BrainScope::User, FactKind::Gotcha, &wide))
            .collect();
        let dev: Vec<BrainFact> = (0..2)
            .map(|_| fact(BrainScope::Device, FactKind::Gotcha, &wide))
            .collect();
        assert!(
            render_claude_md(1, &org, &user, &"n".repeat(200))
                .unwrap()
                .len()
                <= MAX_CORE_MEMORY_BYTES
        );
        assert!(render_memory_md(&dev, &"n".repeat(200)).unwrap().len() <= MAX_CORE_MEMORY_BYTES);
    }

    #[test]
    fn over_budget_says_how_full_and_how_much() {
        let o = OverBudget {
            scope: BrainScope::User,
            used: 1_450,
            budget: 1_500,
            needed: 120,
        };
        assert_eq!(
            o.message(),
            "the user memory holds 1450 of its 1500 characters, and this needs 120 more — \
             shorten or archive a fact first"
        );
    }

    /// A counter is recounted only once it has been quiet for the window: a
    /// write may still be in flight on one touched more recently, and a time
    /// ahead of this pod's clock is recent too.
    #[test]
    fn only_a_quiet_counter_is_recounted() {
        let now = DateTime::from_millis(1_800_000_000_000);
        let ago = |ms: i64| Some(DateTime::from_millis(now.timestamp_millis() - ms));
        let window = RECOUNT_QUIET_SECS * 1000;
        assert!(
            recountable(None, now),
            "never touched (from before the field)"
        );
        assert!(recountable(ago(window), now));
        assert!(recountable(ago(10 * window), now));
        assert!(!recountable(ago(window - 1), now));
        assert!(!recountable(ago(0), now));
        assert!(!recountable(ago(-5_000), now), "another pod's clock, ahead");
    }
}
