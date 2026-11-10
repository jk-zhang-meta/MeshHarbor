// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — when a daily puller owes a day, and the hourly loop that
//! asks: the schedule P6's purestat puller set (`purestat_pull::due_days`,
//! `spawn_puller`), shared by P7's pullers so each of them follows it the
//! same way.
//!
//! * **A cycle** starts every UTC day at the puller's cycle hour. Before it,
//!   nothing is due: yesterday may still be open at the source.
//! * **The horizon** is the last `horizon` closed days. A day older than
//!   that is FROZEN — never pulled again, never rewritten, pulled or not.
//! * **Inside it**, a day is due when it was never pulled `ok`, or when it
//!   is still inside the source's `settle` window and its last good pull
//!   predates this cycle — the re-pull that catches a late correction. A
//!   source whose data never settles later (`settle == horizon`) re-pulls
//!   every day of the horizon once per cycle, which is P6's rule.
//! * **Once across pods**: each tick takes a DB-name-scoped Redis `NX`
//!   claim; without Redis the pod runs locally. Every write a puller makes
//!   is idempotent anyway (`$set` on a row's own `_id`).

use std::{collections::HashMap, future::Future};

use bson::DateTime;
use chrono::{Duration, NaiveDate};
use meshharbor_core::Core;
use meshharbor_services::dao::growth::{GrowthPull, PullStatus};
use tracing::debug;

/// The UTC date of an instant.
pub fn date_of(at: DateTime) -> NaiveDate {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(at.timestamp_millis())
        .expect("a BSON date is in range")
        .date_naive()
}

/// `YYYY-MM-DD`.
pub fn day_str(day: NaiveDate) -> String {
    day.format("%Y-%m-%d").to_string()
}

/// The instant today's cycle starts.
pub fn cycle_start_ms(now: DateTime, cycle_hour: u32) -> i64 {
    date_of(now)
        .and_hms_opt(cycle_hour, 0, 0)
        .expect("the cycle hour exists")
        .and_utc()
        .timestamp_millis()
}

/// The closed days a tick at `now` owes, oldest first (see the module docs).
/// `settle` is clamped to `horizon`; a day younger than or exactly `settle`
/// days old is re-pulled once per cycle, an older one only until it is
/// pulled `ok` once.
pub fn due_days(
    now: DateTime,
    pulls: &[GrowthPull],
    cycle_hour: u32,
    horizon: i64,
    settle: i64,
) -> Vec<NaiveDate> {
    let today = date_of(now);
    let cycle_start = cycle_start_ms(now, cycle_hour);
    if now.timestamp_millis() < cycle_start {
        return Vec::new();
    }
    let settle = settle.min(horizon);
    let by_day: HashMap<&str, &GrowthPull> = pulls.iter().map(|p| (p.day.as_str(), p)).collect();
    (1..=horizon)
        .rev()
        .filter_map(|age| {
            let day = today - Duration::days(age);
            let due = match by_day.get(day_str(day).as_str()) {
                None => true,
                Some(p) if p.status != PullStatus::Ok => true,
                Some(p) => {
                    age <= settle
                        && p.pulled_at
                            .is_none_or(|t| t.timestamp_millis() < cycle_start)
                }
            };
            due.then_some(day)
        })
        .collect()
}

/// The hourly loop of one puller: after `first_delay_secs`, every
/// `interval_secs` one pod (the Redis claim `meshharbor:<claim>:<db>`) runs
/// `tick`. A tick logs its own outcome.
pub fn spawn_hourly<F, Fut>(
    core: Core,
    claim: &'static str,
    first_delay_secs: u64,
    interval_secs: u64,
    tick: F,
) where
    F: Fn(Core) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(first_delay_secs)).await;
        loop {
            let claimed = match &core.redis_pubsub {
                Some(redis) => {
                    let key = format!("meshharbor:{claim}:{}", core.db.name());
                    match redis
                        .try_claim(&key, interval_secs.saturating_sub(60).max(1))
                        .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            debug!(%e, claim, "growth puller claim failed; skipping tick");
                            false
                        }
                    }
                }
                None => true,
            };
            if claimed {
                tick(core.clone()).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn at(s: &str) -> DateTime {
        DateTime::parse_rfc3339_str(s).unwrap()
    }

    fn pull(day: &str, status: PullStatus, pulled_at: Option<&str>) -> GrowthPull {
        GrowthPull {
            id: GrowthPull::id_of("x", day),
            source: "x".into(),
            day: day.into(),
            status,
            pulled_at: pulled_at.map(at),
            attempted_at: at("2026-10-14T01:30:00Z"),
            attempts: 1,
            rows: 0,
            error: None,
            missing_goal: None,
            truncated: false,
        }
    }

    /// P6's rule as the special case `settle == horizon`: every day of the
    /// horizon re-pulled once per cycle, nothing before the cycle's hour,
    /// nothing past the horizon.
    #[test]
    fn settle_equal_to_the_horizon_is_p6s_rule() {
        let now = at("2026-10-14T12:00:00Z");
        let due = due_days(now, &[], 1, 7, 7);
        assert_eq!(due.first(), Some(&d("2026-10-07")));
        assert_eq!(due.last(), Some(&d("2026-10-13")));
        assert_eq!(due.len(), 7);
        assert!(due_days(at("2026-10-14T00:59:59Z"), &[], 1, 7, 7).is_empty());
        let pulls = vec![
            pull("2026-10-13", PullStatus::Ok, Some("2026-10-14T01:05:00Z")),
            pull("2026-10-12", PullStatus::Ok, Some("2026-10-13T01:05:00Z")),
        ];
        let due = due_days(now, &pulls, 1, 7, 7);
        assert!(!due.contains(&d("2026-10-13")), "done this cycle");
        assert!(due.contains(&d("2026-10-12")), "last cycle: re-pulled");
    }

    /// A settle window inside the horizon: a young day is re-pulled every
    /// cycle; an older one is pulled until it succeeds once, then frozen in
    /// place; a failed day is retried whatever its age; past the horizon
    /// nothing.
    #[test]
    fn a_day_past_its_settle_window_is_pulled_once_then_left() {
        let now = at("2026-10-20T03:00:00Z");
        let pulls = vec![
            // Young, pulled last cycle: re-pull.
            pull("2026-10-18", PullStatus::Ok, Some("2026-10-19T02:00:00Z")),
            // Old, pulled once long ago: done.
            pull("2026-10-10", PullStatus::Ok, Some("2026-10-12T02:00:00Z")),
            // Old and failed: retried.
            pull("2026-10-09", PullStatus::Failed, None),
        ];
        let due = due_days(now, &pulls, 1, 30, 5);
        assert!(due.contains(&d("2026-10-18")));
        assert!(!due.contains(&d("2026-10-10")));
        assert!(due.contains(&d("2026-10-09")));
        // Never pulled, inside the horizon: the backfill.
        assert!(due.contains(&d("2026-09-20")));
        // Past the horizon: frozen, never due.
        assert!(!due.contains(&d("2026-09-19")));
        assert_eq!(due.first(), Some(&d("2026-09-20")), "oldest first");
        // A settle window longer than the horizon is the horizon.
        assert_eq!(
            due_days(now, &[], 1, 3, 99),
            vec![d("2026-10-17"), d("2026-10-18"), d("2026-10-19")]
        );
    }
}
