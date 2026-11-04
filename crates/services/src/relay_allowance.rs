// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P4a — the relay allowance's arithmetic, in one place for the two
//! readers that must agree: the throttle that decides
//! (`meshharbor-mod-network`'s `relay_allowance`) and the org's analytics page
//! that shows it (`crates/api/src/routes/cost.rs`). What an org is shown and
//! what it is throttled by can never disagree. The month-to-date sum both
//! read is [`crate::dao::stats::StatsDao::relay_month_to_date`].

use bson::DateTime;
use chrono::{Datelike, TimeZone, Utc};
use meshharbor_config::RelayAllowanceSettings;
use meshharbor_db::models::Plan;

/// The Redis key of the published over-allowance set (`{network hex: rate}`),
/// scoped to the database so two deployments that share a Redis never read
/// each other's. The throttle's job writes it; every API pod's refresh and
/// the push to the PoPs (FR-115 P4a-2, `meshharbor_core::relay_load`) read it.
pub fn set_key(db_name: &str) -> String {
    format!("roomler:relay_over_allowance:{db_name}")
}

/// The month's relay allowance in bytes for `plan` with `seats`; `None` when
/// the plan has none (unlimited).
pub fn allowance_bytes(plan: &Plan, seats: u32) -> Option<u64> {
    let allowance = plan.limits_for(seats).relay_bytes_per_month;
    (allowance != u64::MAX).then_some(allowance)
}

/// The rate past the allowance, in kbit/s: Free's, or the paid plans'.
pub fn rate_kbps(plan: &Plan, s: &RelayAllowanceSettings) -> u32 {
    if *plan == Plan::Free {
        s.free_rate_kbps
    } else {
        s.paid_rate_kbps
    }
}

/// The throttled rate (bytes/s) for an org on `plan` with `seats` that has
/// relayed `used` bytes this month; `None` while it is inside its allowance.
pub fn rate_for(plan: &Plan, seats: u32, used: u64, s: &RelayAllowanceSettings) -> Option<u64> {
    let allowance = allowance_bytes(plan, seats)?;
    if used <= allowance {
        return None;
    }
    Some(u64::from(rate_kbps(plan, s)) * 1000 / 8)
}

/// The first instant of `now`'s month, UTC: the allowance resets there.
pub fn month_start(now: DateTime) -> DateTime {
    let at = utc(now);
    first_of(at.year(), at.month())
}

/// The first instant of the month after `now`'s, UTC: when the allowance
/// resets and a throttle lifts.
pub fn next_month_start(now: DateTime) -> DateTime {
    let at = utc(now);
    match at.month() {
        12 => first_of(at.year() + 1, 1),
        m => first_of(at.year(), m + 1),
    }
}

fn utc(now: DateTime) -> chrono::DateTime<Utc> {
    Utc.timestamp_millis_opt(now.timestamp_millis())
        .single()
        .expect("a BSON date is in range")
}

fn first_of(year: i32, month: u32) -> DateTime {
    let first = Utc
        .with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .expect("the first of a month exists");
    DateTime::from_millis(first.timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1_000_000_000;

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime {
        DateTime::from_millis(
            Utc.with_ymd_and_hms(y, mo, d, h, mi, 0)
                .single()
                .unwrap()
                .timestamp_millis(),
        )
    }

    /// Free's allowance is flat; a per-seat plan's grows with its seats; a
    /// plan without one is unlimited.
    #[test]
    fn the_allowance_follows_the_plan_and_its_seats() {
        assert_eq!(allowance_bytes(&Plan::Free, 1), Some(10 * GB));
        assert_eq!(allowance_bytes(&Plan::Free, 7), Some(10 * GB));
        assert_eq!(allowance_bytes(&Plan::Pro, 3), Some(75 * GB));
        assert_eq!(allowance_bytes(&Plan::Business, 2), Some(200 * GB));
        let s = RelayAllowanceSettings::default();
        assert_eq!(rate_kbps(&Plan::Free, &s), s.free_rate_kbps);
        assert_eq!(rate_kbps(&Plan::Pro, &s), s.paid_rate_kbps);
    }

    /// The allowance resets at the first of the next month, UTC, across a
    /// year's end too.
    #[test]
    fn the_next_month_starts_on_its_first_utc() {
        assert_eq!(
            next_month_start(at(2026, 10, 20, 14, 0)),
            at(2026, 11, 1, 0, 0)
        );
        assert_eq!(
            next_month_start(at(2026, 12, 31, 23, 59)),
            at(2027, 1, 1, 0, 0)
        );
        assert_eq!(
            next_month_start(at(2028, 2, 29, 12, 0)),
            at(2028, 3, 1, 0, 0)
        );
        assert_eq!(
            next_month_start(at(2026, 11, 1, 0, 0)),
            at(2026, 12, 1, 0, 0)
        );
    }
}
