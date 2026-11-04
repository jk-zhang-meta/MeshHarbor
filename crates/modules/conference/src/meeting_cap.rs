// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P5 — the meeting-length cap. A plan's `meeting_max_minutes` (Free:
//! 60) ends a meeting at its limit, after a warning [`WARN_BEFORE_MINUTES`]
//! before it. Paid plans carry the unlimited sentinel and are never touched.
//!
//! A sweep, not a timer per call: a timer lives in the pod that started the
//! call, and a rolling deploy restarts pods, so the call would outlive its
//! timer and run uncapped. Every pod sweeps the calls in progress from Mongo
//! every [`SWEEP_EVERY`]. Both writes a sweep makes are conditional
//! (`claim_cap_warning`, `end_call_if_current`), so with two pods sweeping a
//! call is warned once and ended once, and a sweep that read one call never
//! ends the next call in the same room. Precision is one period: the warning
//! lands between 55:00 and 55:30, the end between 60:00 and 60:30.
//!
//! The decision is `quota::evaluate_for` on [`Limit::MeetingMinutes`] ("may it
//! run one more minute?"), the one place plan limits are compared. The limit
//! is established, so `warn` — every new org's default — does not soften it;
//! `meetings.free_cap = false` turns the whole cap off.

use std::{
    collections::{HashMap, hash_map::Entry},
    time::Duration,
};

use bson::{DateTime, oid::ObjectId};
use meshharbor_db::models::{Plan, PlanEnforcement, Tenant};
use meshharbor_services::{
    dao::room::LiveCall,
    quota::{self, Limit},
};
use tracing::{debug, info, warn};

use crate::ConferenceState;

/// How often each pod sweeps.
pub const SWEEP_EVERY: Duration = Duration::from_secs(30);

/// How long before its end a capped meeting is warned.
pub const WARN_BEFORE_MINUTES: u32 = 5;

/// The `room:call_ended` reason a capped meeting ends with (and the
/// `call_sessions.end_reason` it is closed with).
pub const END_REASON: &str = "plan_limit";

/// What the cap asks of one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Short of the warning line, or warned already and short of the end.
    Nothing,
    /// Inside the last [`WARN_BEFORE_MINUTES`] and not warned yet.
    Warn,
    /// At the plan's limit.
    End,
}

/// The cap's decision for a call that has run `elapsed` under `plan`.
pub fn step(
    plan: &Plan,
    seats: u32,
    mode: PlanEnforcement,
    elapsed: Duration,
    warned: bool,
) -> Step {
    let minutes = elapsed.as_secs() / 60;
    let verdict = quota::evaluate_for(plan.clone(), seats, mode, Limit::MeetingMinutes, minutes, 1);
    if verdict.enforced {
        return Step::End;
    }
    let Some(max) = Limit::MeetingMinutes.describe(&plan.limits_for(seats)).0 else {
        return Step::Nothing; // this plan's meetings have no length cap
    };
    if !warned && minutes + u64::from(WARN_BEFORE_MINUTES) >= max {
        Step::Warn
    } else {
        Step::Nothing
    }
}

/// The earliest minute any plan warns at; `None` when no plan caps meetings.
/// It only narrows the sweep's query — [`step`] decides each call.
fn earliest_warn_minutes() -> Option<u32> {
    [Plan::Free, Plan::Pro, Plan::Business, Plan::Enterprise]
        .iter()
        .map(|p| p.limits().meeting_max_minutes)
        .filter(|m| *m != u32::MAX)
        .min()
        .map(|m| m.saturating_sub(WARN_BEFORE_MINUTES))
}

/// What one sweep did, by room.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Swept {
    pub warned: Vec<ObjectId>,
    pub ended: Vec<ObjectId>,
}

/// One sweep at `now`. Errors are logged and the call is left alone: the cap
/// never ends a meeting on a guess, and the next sweep reads it again.
pub async fn sweep(state: &ConferenceState, now: DateTime) -> Swept {
    let mut swept = Swept::default();
    // The kill switch, and a server that sells no plans (`Core::plans_sold`:
    // a self-hosted org is `free` only in name, and no meeting of its ends).
    if !state.settings.meetings.free_cap || !state.plans_sold {
        return swept;
    }
    let Some(earliest) = earliest_warn_minutes() else {
        return swept;
    };
    let cutoff = DateTime::from_millis(now.timestamp_millis() - i64::from(earliest) * 60_000);
    let calls = match state.rooms.live_calls_started_by(cutoff).await {
        Ok(calls) => calls,
        Err(e) => {
            warn!(%e, "meeting cap: the calls in progress could not be read");
            return swept;
        }
    };
    let mut tenants: HashMap<ObjectId, Option<Tenant>> = HashMap::new();
    for call in calls {
        if let Entry::Vacant(slot) = tenants.entry(call.tenant_id) {
            slot.insert(state.tenants.base.find_by_id(call.tenant_id).await.ok());
        }
        // An org that cannot be read is skipped, never capped on a guess.
        let Some(Some(tenant)) = tenants.get(&call.tenant_id) else {
            continue;
        };
        let elapsed_ms = now.timestamp_millis() - call.started_at.timestamp_millis();
        let elapsed = Duration::from_millis(u64::try_from(elapsed_ms).unwrap_or(0));
        match step(
            &tenant.plan,
            tenant.billed_seats(),
            tenant.settings.plan_enforcement,
            elapsed,
            call.warned,
        ) {
            Step::Nothing => {}
            Step::Warn => {
                if warn_call(state, &call, tenant).await {
                    swept.warned.push(call.room_id);
                }
            }
            Step::End => {
                if end_call(state, &call, tenant).await {
                    swept.ended.push(call.room_id);
                }
            }
        }
    }
    swept
}

/// Warn the room once: `true` only for the sweep that won the claim.
async fn warn_call(state: &ConferenceState, call: &LiveCall, tenant: &Tenant) -> bool {
    match state
        .rooms
        .claim_cap_warning(call.room_id, call.call_id)
        .await
    {
        Ok(true) => {}
        // Another pod's sweep warned it, or the call ended meanwhile.
        Ok(false) => return false,
        Err(e) => {
            warn!(room = %call.room_id, %e, "meeting cap: the warning could not be claimed");
            return false;
        }
    }
    let max = tenant.limits().meeting_max_minutes;
    let ends_at = call.started_at.timestamp_millis() + i64::from(max) * 60_000;
    let event = serde_json::json!({
        "type": "room:call_ending_soon",
        "data": {
            "room_id": call.room_id.to_hex(),
            "ends_at": ends_at,
            "max_minutes": max,
            "plan": tenant.plan.id(),
        }
    });
    broadcast_to_members(state, call.room_id, &event).await;
    info!(room = %call.room_id, tenant = %call.tenant_id, max_minutes = max, "meeting cap: warned");
    true
}

/// End the call if it is still the room's: `true` only for the sweep that
/// ended it, which then does what `call/end` does after its own write.
async fn end_call(state: &ConferenceState, call: &LiveCall, tenant: &Tenant) -> bool {
    match state
        .rooms
        .end_call_if_current(call.room_id, call.call_id)
        .await
    {
        Ok(true) => {}
        // Ended by someone else, or a new call started since the read.
        Ok(false) => return false,
        Err(e) => {
            warn!(room = %call.room_id, %e, "meeting cap: the call could not be ended");
            return false;
        }
    }
    // FR-102 P4 — counted once, by the sweep whose end landed.
    meshharbor_core::quota::record_collision(state, tenant, Limit::MeetingMinutes);
    if state.settings.stats.enabled
        && let Err(e) = state
            .stats
            .close_call_session(call.call_id, END_REASON)
            .await
    {
        debug!(room = %call.room_id, %e, "call session close failed (plan_limit)");
    }
    // C-4 — the media island may live on another pod.
    crate::media_cluster::close_room_everywhere(state, &call.room_id).await;
    let max = tenant.limits().meeting_max_minutes;
    let event = serde_json::json!({
        "type": "room:call_ended",
        "data": {
            "room_id": call.room_id.to_hex(),
            "reason": END_REASON,
            "max_minutes": max,
            "plan": tenant.plan.id(),
        }
    });
    broadcast_to_members(state, call.room_id, &event).await;
    info!(room = %call.room_id, tenant = %call.tenant_id, max_minutes = max, "meeting cap: ended");
    true
}

async fn broadcast_to_members(
    state: &ConferenceState,
    room_id: ObjectId,
    event: &serde_json::Value,
) {
    let member_ids = state
        .rooms
        .find_member_user_ids(room_id)
        .await
        .unwrap_or_default();
    if member_ids.is_empty() {
        return;
    }
    meshharbor_core::ws::dispatcher::broadcast_with_redis(
        &state.ws_storage,
        &state.redis_pubsub,
        &member_ids,
        event,
    )
    .await;
}

/// Every pod sweeps every [`SWEEP_EVERY`], the first time one period after
/// boot.
pub fn spawn(state: ConferenceState) {
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval_at(tokio::time::Instant::now() + SWEEP_EVERY, SWEEP_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let swept = sweep(&state, DateTime::now()).await;
            if !swept.warned.is_empty() || !swept.ended.is_empty() {
                debug!(
                    warned = swept.warned.len(),
                    ended = swept.ended.len(),
                    "meeting cap: sweep"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    fn free(elapsed: Duration, warned: bool) -> Step {
        step(&Plan::Free, 1, PlanEnforcement::Warn, elapsed, warned)
    }

    #[test]
    fn a_free_meeting_is_warned_at_55_and_ended_at_60() {
        assert_eq!(
            free(MIN * 54 + Duration::from_secs(59), false),
            Step::Nothing
        );
        assert_eq!(free(MIN * 55, false), Step::Warn);
        assert_eq!(free(MIN * 59 + Duration::from_secs(59), false), Step::Warn);
        assert_eq!(free(MIN * 60, false), Step::End);
        assert_eq!(free(MIN * 600, false), Step::End);
    }

    /// The warning goes out once; a warned call waits for its end.
    #[test]
    fn a_warned_meeting_is_not_warned_again() {
        assert_eq!(free(MIN * 57, true), Step::Nothing);
        assert_eq!(free(MIN * 60, true), Step::End);
    }

    /// Established: the org's enforcement mode never softens the cap.
    #[test]
    fn the_mode_does_not_reach_the_cap() {
        for mode in [
            PlanEnforcement::Off,
            PlanEnforcement::Warn,
            PlanEnforcement::Enforce,
        ] {
            assert_eq!(step(&Plan::Free, 1, mode, MIN * 60, true), Step::End);
            assert_eq!(step(&Plan::Free, 1, mode, MIN * 56, false), Step::Warn);
        }
    }

    #[test]
    fn paid_meetings_run_without_a_clock() {
        for plan in [Plan::Pro, Plan::Business, Plan::Enterprise] {
            for seats in [1, 7] {
                assert_eq!(
                    step(&plan, seats, PlanEnforcement::Enforce, MIN * 10_000, false),
                    Step::Nothing,
                    "{plan:?} × {seats}"
                );
            }
        }
    }

    #[test]
    fn the_sweep_reads_only_calls_old_enough_to_warn() {
        assert_eq!(earliest_warn_minutes(), Some(55));
    }
}
