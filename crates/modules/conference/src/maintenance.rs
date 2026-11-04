// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Call-state maintenance: the startup stale-call reset and the orphaned
//! call-session closer.
//!
//! FR-69 P4 — the reset ran inline in the host's `main.rs` under the startup
//! lease; it is now the module's leader-gated startup job. The closer lived in
//! the host's `stats_rollup.rs`; it is conference's because it closes
//! conference's rows (`call_sessions`, member call sessions), and the host's
//! rollup loop still calls it every cycle through the composition.

use bson::{Bson, DateTime, Document, doc};
use tracing::{debug, info};

use crate::ConferenceState;

/// No call can be active at server startup: end every `in_progress` room
/// (stamping `actual_end_time` and clearing the call-instance pointer — a
/// duration derived from a crashed room's doc was wrong otherwise), then
/// close the matching call sessions and dangling member sessions.
pub async fn stale_call_reset(state: &ConferenceState) -> anyhow::Result<()> {
    let rooms_coll = state.db.collection::<Document>("rooms");
    let result = rooms_coll
        .update_many(
            doc! { "conference_status": "in_progress" },
            doc! {
                "$set": {
                    "conference_status": "ended",
                    "participant_count": 0_i32,
                    "actual_end_time": DateTime::now(),
                },
                "$unset": { "current_call_id": "" },
            },
        )
        .await
        .ok();
    if let Some(res) = result
        && res.modified_count > 0
    {
        info!(
            "Cleaned up {} stale calls (all in_progress reset to ended)",
            res.modified_count
        );
    }
    // Close the matching call_sessions docs + dangling member sessions
    // (same closer the rollup task runs every cycle).
    let (calls, sessions) = close_orphaned_call_state(state).await;
    if calls > 0 || sessions > 0 {
        info!(
            calls,
            sessions, "startup orphan sweep closed stale call state"
        );
    }
    Ok(())
}

/// Stats PR-2 — close orphaned call state: `call_sessions` still open
/// whose room is no longer `in_progress`, and member sessions still open
/// in such rooms (a pod crash has no leave moment; the startup stale-reset
/// only runs on boot, this runs every rollup cycle). Durations are stamped
/// with the close time — bounded error ≤ one cycle. Returns
/// `(calls_closed, member_docs_touched)`.
pub async fn close_orphaned_call_state(state: &ConferenceState) -> (u64, u64) {
    let in_progress: Vec<Bson> = state
        .db
        .collection::<Document>("rooms")
        .distinct("_id", doc! { "conference_status": "in_progress" })
        .await
        .unwrap_or_default();
    let now = DateTime::now();
    let calls = state
        .db
        .collection::<Document>(meshharbor_services::dao::stats::CALL_SESSIONS)
        .update_many(
            doc! { "ended_at": Bson::Null, "room_id": { "$nin": in_progress.clone() } },
            doc! { "$set": { "ended_at": now, "end_reason": "stale_reset" } },
        )
        .await
        .map(|r| r.modified_count)
        .unwrap_or_else(|e| {
            debug!(%e, "orphan sweep: call close failed");
            0
        });
    let now_b = Bson::DateTime(now);
    let sessions = state
        .db
        .collection::<Document>("room_members")
        .update_many(
            doc! { "sessions.left_at": Bson::Null, "room_id": { "$nin": in_progress } },
            vec![doc! { "$set": {
                "sessions": { "$map": { "input": "$sessions", "as": "s", "in": {
                    "$cond": [
                        { "$eq": [ "$$s.left_at", null ] },
                        { "$mergeObjects": [ "$$s", {
                            "left_at": now_b.clone(),
                            "duration": { "$toLong": { "$divide": [
                                { "$subtract": [ now_b.clone(), "$$s.joined_at" ] },
                                1000,
                            ] } },
                        } ] },
                        "$$s",
                    ]
                }}},
                "updated_at": now_b.clone(),
            }}],
        )
        .await
        .map(|r| r.modified_count)
        .unwrap_or_else(|e| {
            debug!(%e, "orphan sweep: session close failed");
            0
        });
    if calls > 0 || sessions > 0 {
        info!(calls, sessions, "orphaned call state closed");
    }
    (calls, sessions)
}
