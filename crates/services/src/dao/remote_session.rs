// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_remote_control::models::{
    EndReason, EndSource, RemoteSession, SessionPhase, SessionStats,
};
use meshharbor_remote_control::permissions::Permissions;
use meshharbor_remote_control::signaling::Tally;
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct RemoteSessionDao {
    pub base: BaseDao<RemoteSession>,
}

/// FR-130 — what the row of a session no hub holds must name before an end
/// someone asked for is written to it ([`RemoteSessionDao::end_unheld`]).
/// Every part that is set must match; the session id always does.
#[derive(Debug, Clone, Copy, Default)]
pub struct EndScope {
    /// An admin's end: the org the route names.
    pub tenant_id: Option<ObjectId>,
    /// The controller's own end, and a redial's `replaces`: the person.
    pub controller_user_id: Option<ObjectId>,
    /// A redial's `replaces`: the device the redial asks for.
    pub agent_id: Option<ObjectId>,
}

impl RemoteSessionDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, RemoteSession::COLLECTION),
        }
    }

    pub async fn create(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        controller_user_id: ObjectId,
        permissions: Permissions,
    ) -> DaoResult<RemoteSession> {
        let now = DateTime::now();
        let session = RemoteSession {
            id: Some(session_id),
            agent_id,
            tenant_id,
            controller_user_id,
            watchers: Vec::new(),
            permissions,
            phase: SessionPhase::Pending,
            created_at: now,
            started_at: None,
            ended_at: None,
            end_reason: None,
            recording_url: None,
            stats: SessionStats::default(),
            carrier: None,
            attach_seq: 0,
            detached_at: None,
            resume_by: None,
            stats_at: None,
            end_source: None,
            external: false,
        };
        // Insert with explicit _id so the Hub-provided ObjectId remains the canonical key.
        self.base.collection().insert_one(&session).await?;
        Ok(session)
    }

    // FR-32 P1b — a `count_active_for_tenant` was written here for the plan's
    // `max_concurrent_sessions` gate and then REMOVED, because it would have
    // counted an empty collection forever: `RemoteSessionDao::create` has zero
    // callers workspace-wide, and live sessions exist only in the Hub's
    // in-memory `DashMap`. A gate reading a table nothing writes can never
    // fire, while reading in review as though it does — the same trap the
    // `cloud_integrations` gate was withheld for. See the FR-32 spec.

    pub async fn find_in_tenant(
        &self,
        tenant_id: ObjectId,
        session_id: ObjectId,
    ) -> DaoResult<RemoteSession> {
        self.base.find_by_id_in_tenant(tenant_id, session_id).await
    }

    pub async fn list_for_agent(
        &self,
        agent_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<RemoteSession>> {
        self.base
            .find_paginated(
                doc! { "agent_id": agent_id },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    pub async fn list_for_user(
        &self,
        controller_user_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<RemoteSession>> {
        self.base
            .find_paginated(
                doc! { "controller_user_id": controller_user_id },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    pub async fn mark_phase(&self, session_id: ObjectId, phase: SessionPhase) -> DaoResult<bool> {
        let mut set = doc! { "phase": bson::to_bson(&phase).unwrap() };
        if phase == SessionPhase::Active {
            set.insert("started_at", DateTime::now());
        }
        self.base
            .update_by_id(session_id, doc! { "$set": set })
            .await
    }

    /// Wave 2 — fold a live `rc:session.stats` sample into the session
    /// row, scoped to the reporting agent so one agent can never write
    /// another's session.
    ///
    /// Counters are MONOTONIC on the agent side (bytes and event totals
    /// only grow within a session), so last-sample-wins is correct and a
    /// dropped sample costs nothing; `peak_fps` takes the max because a
    /// peak is the interesting value, while `avg_rtt_ms` carries the
    /// latest measurement rather than a true average — the field name
    /// predates this and the value is what the session is doing NOW.
    /// Ended sessions are excluded: a late sample must not resurrect the
    /// numbers `mark_ended` froze.
    ///
    /// FR-130 — the same `$set` stamps `stats_at`, the server's time of this
    /// merge: the row's own clock of being alive, which an end nobody saw is
    /// dated by (spec §4.4). No query of its own, and only while the row is
    /// open, like the rest of the merge.
    pub async fn merge_live_stats(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
        stats: &SessionStats,
        // FR-102 P9c — the carrier the agent recorded, when the sample
        // carries one (already validated to a code by the socket); written
        // beside `stats`, never inside it, so `mark_ended`'s whole-`stats`
        // write cannot reset it. `None` leaves whatever the row holds.
        carrier: Option<&str>,
    ) -> DaoResult<bool> {
        let mut set = doc! {
            "stats.bytes_sent": stats.bytes_sent as i64,
            "stats.bytes_recv": stats.bytes_recv as i64,
            "stats.avg_rtt_ms": f64::from(stats.avg_rtt_ms),
            "stats.keyframe_requests": stats.keyframe_requests as i64,
            "stats.input_events": stats.input_events as i64,
            // P8 Phase 4 — hand-built doc: a field added to
            // SessionStats MUST be added here too or live
            // merges silently drop it (mark_ended's whole-
            // struct to_bson is the safe twin).
            "stats.shared_seconds": stats.shared_seconds as i64,
            "stats.mixed_dial_seconds": stats.mixed_dial_seconds as i64,
            // FR-130 — beside `stats`, so `mark_ended`'s whole-`stats` write
            // leaves it.
            "stats_at": DateTime::now(),
        };
        if let Some(c) = carrier {
            set.insert("carrier", c);
        }
        self.base
            .update_one(
                doc! { "_id": session_id, "agent_id": agent_id, "ended_at": bson::Bson::Null },
                doc! {
                    "$set": set,
                    "$max": { "stats.peak_fps": f64::from(stats.peak_fps) },
                },
            )
            .await
    }

    /// FR-101 P3 — fold a session's cumulative clipboard tallies into its row
    /// and return the readings stored before (zeros the first time), so the
    /// caller keeps only what this sample adds. `$max` keeps the stored totals
    /// monotonic: a sample that arrives late or twice adds nothing.
    ///
    /// Scoped to the reporting agent, and deliberately NOT to a live session:
    /// the device's last sample arrives after the server ended the session,
    /// and the transfers it carries happened. The totals sit in their own
    /// `transfer_totals` field, which `mark_ended`'s whole-`stats` write
    /// cannot reset. A reset would make the next sample count everything
    /// again. `None` = no such session row for this agent (yet).
    pub async fn fold_clipboard_totals(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
        to_host: Tally,
        from_host: Tally,
    ) -> DaoResult<Option<(Tally, Tally)>> {
        let n = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        let before = self
            .base
            .collection()
            .clone_with_type::<bson::Document>()
            .find_one_and_update(
                doc! { "_id": session_id, "agent_id": agent_id },
                doc! { "$max": {
                    "transfer_totals.clipboard_to_host.count": n(to_host.count),
                    "transfer_totals.clipboard_to_host.bytes": n(to_host.bytes),
                    "transfer_totals.clipboard_from_host.count": n(from_host.count),
                    "transfer_totals.clipboard_from_host.bytes": n(from_host.bytes),
                }},
            )
            .return_document(mongodb::options::ReturnDocument::Before)
            .await?;
        Ok(before.map(|row| {
            let stored = |dir: &str| {
                let t = row
                    .get_document("transfer_totals")
                    .and_then(|t| t.get_document(dir))
                    .ok();
                let read = |f: &str| {
                    t.and_then(|t| t.get_i64(f).ok())
                        .map_or(0, |v| u64::try_from(v).unwrap_or(0))
                };
                Tally {
                    count: read("count"),
                    bytes: read("bytes"),
                }
            };
            (stored("clipboard_to_host"), stored("clipboard_from_host"))
        }))
    }

    pub async fn mark_ended(
        &self,
        session_id: ObjectId,
        reason: EndReason,
        stats: SessionStats,
    ) -> DaoResult<bool> {
        let stats_bson = bson::to_bson(&stats).unwrap_or(bson::Bson::Null);
        self.base
            .update_by_id(
                session_id,
                doc! {
                    "$set": {
                        "phase": bson::to_bson(&SessionPhase::Closed).unwrap(),
                        "ended_at": DateTime::now(),
                        "end_reason": bson::to_bson(&reason).unwrap(),
                        "stats": stats_bson,
                    }
                },
            )
            .await
    }

    /// FR-130 — the claim's commit (spec §4.4, "Fencing"): ONE conditional
    /// update that resumes the session at the next fencing number. It matches
    /// only the row the claim read: in the device's tenant, naming the device,
    /// live, at the number read (`seq`), and either never detached or detached
    /// with its window still open at `now`. It bumps the number and clears the
    /// detach. `false` = it matched nothing: someone ended it, another pod
    /// resumed it, or its window passed, and the caller reads the row again.
    pub async fn commit_resume(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        session_id: ObjectId,
        seq: u32,
        now: DateTime,
    ) -> DaoResult<bool> {
        let next = i64::from(seq) + 1;
        let res = self
            .base
            .collection()
            .update_one(
                doc! {
                    "_id": session_id,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    "attach_seq": meshharbor_remote_control::audit::at_seq(seq),
                    "phase": bson::to_bson(&SessionPhase::Active)?,
                    "ended_at": bson::Bson::Null,
                    "$or": [
                        { "resume_by": bson::Bson::Null },
                        { "resume_by": { "$gt": now } },
                    ],
                },
                doc! {
                    "$set": { "attach_seq": next },
                    "$unset": { "detached_at": "", "resume_by": "" },
                },
            )
            .await?;
        Ok(res.matched_count == 1)
    }

    /// FR-130 — the registration read (spec §4.4): the device's live rows
    /// created before `before` (its registration), in its tenant, oldest
    /// first, at most `limit`. A device holds at most its capacity of live
    /// sessions, so more than a few is rows an earlier connection left open,
    /// and the next registration reads the rest.
    pub async fn open_rows_before(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        before: DateTime,
        limit: i64,
    ) -> DaoResult<Vec<RemoteSession>> {
        let rows = self
            .base
            .collection()
            .find(doc! {
                "tenant_id": tenant_id,
                "phase": bson::to_bson(&SessionPhase::Active)?,
                "agent_id": agent_id,
                "ended_at": bson::Bson::Null,
                "created_at": { "$lt": before },
            })
            .sort(doc! { "created_at": 1 })
            .limit(limit)
            .max_time(READ_BUDGET) // P1b-2: indexed and bounded (review L3)
            .await?
            .try_collect()
            .await?;
        Ok(rows)
    }

    /// FR-130 P1b-2 — an end someone asked for (an admin's, the controller's
    /// own, a redial's `replaces` of a session not detached, a rejoin's gate
    /// refused) of a session no hub on the asking pod holds, written straight
    /// to the row (spec §4.4, §4.6): one conditional update that ends it only
    /// while it is live (Active, not ended) and names what `scope` names, at
    /// any fencing number. The caller awaits it BEFORE it publishes the
    /// control event a pod that does hold the session acts on: a claim reads
    /// the row once more after it rebuilt the session, so it either finds
    /// this end or receives that event. The row as it was, when it matched.
    pub async fn end_unheld(
        &self,
        session_id: ObjectId,
        scope: &EndScope,
        reason: EndReason,
        at: DateTime,
    ) -> DaoResult<Option<RemoteSession>> {
        let mut filter = doc! {
            "_id": session_id,
            "phase": bson::to_bson(&SessionPhase::Active)?,
            "ended_at": bson::Bson::Null,
        };
        if let Some(t) = scope.tenant_id {
            filter.insert("tenant_id", t);
        }
        if let Some(u) = scope.controller_user_id {
            filter.insert("controller_user_id", u);
        }
        if let Some(a) = scope.agent_id {
            filter.insert("agent_id", a);
        }
        let before = self
            .base
            .collection()
            .find_one_and_update(
                filter,
                doc! { "$set": {
                    "phase": bson::to_bson(&SessionPhase::Closed)?,
                    "ended_at": at,
                    "end_reason": bson::to_bson(&reason)?,
                }},
            )
            .return_document(mongodb::options::ReturnDocument::Before)
            .await?;
        Ok(before)
    }

    /// FR-130 P1b-2 — the session's row, when it names `controller_user_id`
    /// as its controller. The rejoin and the controller's own end carry no
    /// org, so the row must name the caller, which is narrower than an org.
    /// `NotFound` for another person's session, exactly as for none at all.
    pub async fn find_for_controller(
        &self,
        session_id: ObjectId,
        controller_user_id: ObjectId,
    ) -> DaoResult<RemoteSession> {
        self.base
            .find_one(doc! { "_id": session_id, "controller_user_id": controller_user_id })
            .await?
            .ok_or(super::base::DaoError::NotFound)
    }

    /// FR-130 (review 2, N5) — a device's own end of a session whose end was
    /// inferred BEFORE this connection: by the sweep, once the device had
    /// been away past the window, by an earlier connection's registration,
    /// before the device could say how the session ended, or (D5 = A) by its
    /// viewer's redial naming it in `replaces` while it was detached. As
    /// [`Self::replace_inferred_end`] does for this connection's own
    /// inference, the device's reason replaces `agent_disconnect` and
    /// `end_source` is cleared, in the device's tenant and only for a row
    /// naming the device; `ended_at` stays the row's own last clock. Not the
    /// one-time close's rows (`backfill`): that end is an operator's, taken
    /// only once the row's own clock has stood still for an hour at least and
    /// its device has had a session since, long after any device stopped
    /// keeping the session (a window is 120 s at most). It is no inference
    /// from the device's connection going, which is what the device's word
    /// corrects. When it matched, the row's `ended_at` (for the audit's
    /// trail); `None` = nothing matched.
    pub async fn replace_earlier_inferred_end(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        session_id: ObjectId,
        reason: EndReason,
    ) -> DaoResult<Option<DateTime>> {
        let before = self
            .base
            .collection()
            .find_one_and_update(
                doc! {
                    "_id": session_id,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    "end_reason": bson::to_bson(&EndReason::AgentDisconnect)?,
                    "end_source": { "$in": inferred_by_device_loss()? },
                    // Every inferred end is dated, so a match always has one.
                    "ended_at": { "$ne": bson::Bson::Null },
                },
                doc! {
                    "$set": { "end_reason": bson::to_bson(&reason)? },
                    "$unset": { "end_source": "" },
                },
            )
            .return_document(mongodb::options::ReturnDocument::Before)
            .await?;
        Ok(before.and_then(|row| row.ended_at))
    }

    /// FR-130 P1b-2 — a device's own end of a session that its registration
    /// just ended by inference, reported after its hello (spec §4.4, AC4):
    /// the reason the device gives (`host_disconnect`, `idle_timeout`,
    /// `error`) REPLACES the inferred `agent_disconnect`, in the device's
    /// tenant and only for a row naming the device. The inference may not
    /// have reached the row yet (its write is batched): the row then still
    /// reads live, and this write ends it the same way, so whichever lands
    /// first the row reads the same.
    ///
    /// * `inferred_at: Some(at)` — the registration read ended it at `at`,
    ///   the row's own last clock. The end is now known, so `end_source` is
    ///   CLEARED. `ended_at` stays that clock: the device's frame carries no
    ///   time, and the end it reports happened during the gap, no earlier
    ///   than that clock and no later than the device came back, so the row
    ///   adds no hours it cannot prove.
    /// * `None` — the hub reaped it at the registration (it still held the
    ///   session for the device's earlier connection): a seen end, unmarked,
    ///   so `ended_at` stays the reap's (`now` when this lands first).
    ///
    /// Either way an end the sweep, another pod's registration or (D5 = A) a
    /// redial inferred first (review 2, N5) is replaced the same way, keeping
    /// its clock.
    ///
    /// A row someone else ended meanwhile (an admin's end) matches neither
    /// shape and is left alone. `false` = nothing matched.
    pub async fn replace_inferred_end(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        session_id: ObjectId,
        reason: EndReason,
        inferred_at: Option<DateTime>,
        now: DateTime,
    ) -> DaoResult<bool> {
        let live = doc! {
            "phase": bson::to_bson(&SessionPhase::Active)?,
            "ended_at": bson::Bson::Null,
        };
        let disconnect = bson::to_bson(&EndReason::AgentDisconnect)?;
        let closed = bson::to_bson(&SessionPhase::Closed)?;
        let reason = bson::to_bson(&reason)?;
        // Review 2, N5 — the sweep's inference as well as a registration's:
        // whichever reached the row first, the device's own end replaces it.
        let (inferred, set) = match inferred_at {
            Some(at) => (
                doc! {
                    "end_reason": disconnect,
                    "end_source": { "$in": inferred_by_device_loss()? },
                },
                doc! {
                    "phase": closed,
                    "end_reason": reason,
                    "ended_at": { "$ifNull": ["$ended_at", at] },
                },
            ),
            None => (
                {
                    // The reap's seen end (no `end_source`; `null` in `$in`
                    // matches an absent field), or an inference that reached
                    // the row before it.
                    let mut sources = inferred_by_device_loss()?;
                    sources.insert(0, bson::Bson::Null);
                    doc! { "end_reason": disconnect, "end_source": { "$in": sources } }
                },
                doc! {
                    "phase": closed,
                    "end_reason": reason,
                    "ended_at": { "$ifNull": ["$ended_at", now] },
                },
            ),
        };
        let res = self
            .base
            .collection()
            .update_one(
                doc! {
                    "_id": session_id,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    "$or": [live, inferred],
                },
                // An update pipeline: `$ifNull` reads the row's own value.
                // The end is known now, so it is no longer marked inferred.
                vec![doc! { "$set": set }, doc! { "$unset": ["end_source"] }],
            )
            .await?;
        Ok(res.matched_count == 1)
    }

    /// FR-130 P1b-2 — the sweep's first read: live rows that were detached
    /// when their device's socket went and whose `resume_by` has passed,
    /// oldest first, at most `limit`. Only a detach writes `resume_by`.
    pub async fn detached_past(&self, now: DateTime, limit: i64) -> DaoResult<Vec<RemoteSession>> {
        let rows = self
            .base
            .collection()
            .find(doc! {
                "phase": bson::to_bson(&SessionPhase::Active)?,
                "ended_at": bson::Bson::Null,
                "resume_by": { "$lte": now },
            })
            .sort(doc! { "created_at": 1 })
            .limit(limit)
            .max_time(READ_BUDGET)
            .await?
            .try_collect()
            .await?;
        Ok(rows)
    }

    /// FR-130 P1b-2 — the sweep's second read: live rows with no `resume_by`
    /// whose own clock (`stats_at`, else `started_at`) is older than
    /// `quiet_since`, and that `within` matches (the resume scope as a
    /// filter; `None` = every org), in creation order after `after`, at most
    /// `limit`. Candidates only: a row a pod that died without a word left
    /// open. The sweep checks each one's device before it ends anything, and
    /// pages on from the last row's [`RowCursor`] (review 2, N7), so the rows
    /// it keeps never starve a newer one.
    pub async fn unclaimed_quiet(
        &self,
        quiet_since: DateTime,
        within: Option<bson::Document>,
        after: Option<RowCursor>,
        limit: i64,
    ) -> DaoResult<Vec<RemoteSession>> {
        let mut and = vec![doc! { "$or": [
            { "stats_at": { "$lt": quiet_since } },
            { "stats_at": bson::Bson::Null, "started_at": { "$lt": quiet_since } },
        ]}];
        and.extend(within);
        and.extend(after.map(after_filter));
        let rows = self
            .base
            .collection()
            .find(doc! {
                "phase": bson::to_bson(&SessionPhase::Active)?,
                "ended_at": bson::Bson::Null,
                "resume_by": bson::Bson::Null,
                "$and": and,
            })
            .sort(doc! { "created_at": 1, "_id": 1 })
            .limit(limit)
            .max_time(READ_BUDGET)
            .await?
            .try_collect()
            .await?;
        Ok(rows)
    }

    /// FR-130 P1b-2 — the sweep's end of a row, as it read it (spec §4.4):
    /// only while it is still live, still at the fencing number read AND
    /// still carrying the `resume_by` and the `stats_at` read (absent matches
    /// absent: an abandoned row has no `resume_by`), so a claim that resumed
    /// it meanwhile (which bumps the one and clears the other) is never
    /// undone, nor a session whose own clock moved. `agent_disconnect`, dated
    /// `at` (the row's own last clock) and marked `end_source: sweep`.
    /// `false` = it matched nothing.
    pub async fn end_swept(&self, row: &RemoteSession, at: DateTime) -> DaoResult<bool> {
        self.end_inferred_as_read(row, at, EndSource::Sweep, None)
            .await
    }

    /// FR-130 (D5 = A) — a redial's `replaces` of a session no pod holds
    /// because its DEVICE's socket went (the row detached), as the caller read
    /// the row: `agent_disconnect`, dated `at` (the row's own last clock) and
    /// marked `end_source: redial`, only while the row is still live, at the
    /// fencing number read and with the `resume_by` and `stats_at` read, so a
    /// claim that resumed it meanwhile is never undone. `false` = it matched
    /// nothing.
    pub async fn end_replaced_detached(
        &self,
        row: &RemoteSession,
        at: DateTime,
    ) -> DaoResult<bool> {
        self.end_inferred_as_read(row, at, EndSource::Redial, None)
            .await
    }

    /// FR-130 P1b-2 — the one-time close's read (`POST
    /// /api/admin/rc-sessions/close-dead`): live rows created before
    /// `older_than` whose own clock has not moved since (`stats_at` absent or
    /// older), in creation order after `after`, at most `limit`. The caller
    /// pages on from the last row's [`RowCursor`] (review 2, N7) and decides
    /// each row from its evidence.
    pub async fn dead_candidates(
        &self,
        older_than: DateTime,
        after: Option<RowCursor>,
        limit: i64,
    ) -> DaoResult<Vec<RemoteSession>> {
        let mut and = vec![doc! { "$or": [
            { "stats_at": bson::Bson::Null },
            { "stats_at": { "$lt": older_than } },
        ]}];
        and.extend(after.map(after_filter));
        let rows = self
            .base
            .collection()
            .find(doc! {
                "phase": bson::to_bson(&SessionPhase::Active)?,
                "ended_at": bson::Bson::Null,
                "created_at": { "$lt": older_than },
                "$and": and,
            })
            .sort(doc! { "created_at": 1, "_id": 1 })
            .limit(limit)
            .max_time(READ_BUDGET)
            .await?
            .try_collect()
            .await?;
        Ok(rows)
    }

    /// FR-130 P1b-2 — whether `agent_id` has a session row created after
    /// `created_at`, in its org: the device came back and was used since.
    pub async fn has_later_row(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        created_at: DateTime,
    ) -> DaoResult<bool> {
        let later = self
            .base
            .collection()
            .clone_with_type::<bson::Document>()
            .find_one(doc! {
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "created_at": { "$gt": created_at },
            })
            .projection(doc! { "_id": 1 })
            .max_time(READ_BUDGET)
            .await?;
        Ok(later.is_some())
    }

    /// FR-130 P1b-2 — the one-time close of a row a pod that died before
    /// FR-130 left open: only while it is still live, at the fencing number
    /// and with the `resume_by` and `stats_at` read, and created before
    /// `created_before` (review 2, N1): `agent_disconnect`, dated `at` (the
    /// row's own last clock) and marked `end_source: backfill`. `false` = it
    /// matched nothing (it ended, was resumed or detached, or its own clock
    /// moved, meanwhile).
    pub async fn close_dead(
        &self,
        row: &RemoteSession,
        at: DateTime,
        created_before: DateTime,
    ) -> DaoResult<bool> {
        self.end_inferred_as_read(row, at, EndSource::Backfill, Some(created_before))
            .await
    }

    /// The sweep's, the dead-row close's and a detached session's redial's
    /// write: `agent_disconnect` at `at`, marked `source`, on the row only as
    /// it was read (and, when given, only on a row created before
    /// `created_before`). Never an end over an end: the row must still be
    /// live.
    async fn end_inferred_as_read(
        &self,
        row: &RemoteSession,
        at: DateTime,
        source: EndSource,
        created_before: Option<DateTime>,
    ) -> DaoResult<bool> {
        let Some(session_id) = row.id else {
            return Ok(false);
        };
        let as_read = |t: Option<DateTime>| t.map_or(bson::Bson::Null, bson::Bson::DateTime);
        let mut filter = doc! {
            "_id": session_id,
            "phase": bson::to_bson(&SessionPhase::Active)?,
            "ended_at": bson::Bson::Null,
            "attach_seq": meshharbor_remote_control::audit::at_seq(row.attach_seq),
            "resume_by": as_read(row.resume_by),
            "stats_at": as_read(row.stats_at),
        };
        if let Some(before) = created_before {
            filter.insert("created_at", doc! { "$lt": before });
        }
        let res = self
            .base
            .collection()
            .update_one(
                filter,
                doc! { "$set": {
                    "phase": bson::to_bson(&SessionPhase::Closed)?,
                    "ended_at": at,
                    "end_reason": bson::to_bson(&EndReason::AgentDisconnect)?,
                    "end_source": bson::to_bson(&source)?,
                }},
            )
            .await?;
        Ok(res.matched_count == 1)
    }
}

/// FR-130 P1b-2 (review 2, N7) — where a paged read of live rows goes on
/// from: the last row it returned, by `created_at` and then `_id`.
pub type RowCursor = (DateTime, ObjectId);

/// The rows after `cursor`, in the order a paged read sorts them
/// (`created_at`, then `_id`).
fn after_filter((created_at, id): RowCursor) -> bson::Document {
    doc! { "$or": [
        { "created_at": { "$gt": created_at } },
        { "created_at": created_at, "_id": { "$gt": id } },
    ]}
}

/// FR-130 (review 2, N5) — the inferred ends a device's own end may replace:
/// the registration read's, the sweep's and (D5 = A) a redial's of a detached
/// session. Each ended a session because its device's connection went, while
/// the device may have kept it through the gap. Never `backfill`
/// ([`RemoteSessionDao::replace_earlier_inferred_end`]).
fn inferred_by_device_loss() -> DaoResult<Vec<bson::Bson>> {
    Ok(vec![
        bson::to_bson(&EndSource::Registration)?,
        bson::to_bson(&EndSource::Sweep)?,
        bson::to_bson(&EndSource::Redial)?,
    ])
}

/// FR-130 P1b-2 (P1b-1's review, L3) — the longest a background read of the
/// resume waits on the database: an answer that has not come by then is a
/// failed read, which each caller already handles. Each read is indexed in
/// the remote module's `index_plan` (the registration read by `{agent_id,
/// phase, created_at}`; the sweep and the dead-row close by `{phase,
/// created_at}`, and the close's later-row check by `{agent_id, created_at}`),
/// so this only bounds a database in trouble.
const READ_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
