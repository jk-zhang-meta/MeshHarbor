// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_remote_control::models::{EndReason, RemoteSession, SessionPhase, SessionStats};
use meshharbor_remote_control::permissions::Permissions;
use meshharbor_remote_control::signaling::Tally;
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct RemoteSessionDao {
    pub base: BaseDao<RemoteSession>,
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
}
