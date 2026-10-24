// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Per-(caller, device) request limiter for the exec / SSH control planes.
//!
//! Both subsystems DOCUMENT a per-minute ceiling (`exec::RATE_LIMIT_PER_MINUTE`,
//! `ssh::RATE_LIMIT_PER_MINUTE`) and both define a `RateLimited` deny reason,
//! but nothing ever enforced them: the constants had no readers and the deny
//! reason was constructed only in tests. That left two real gaps —
//!
//! * the global `tower_governor` is per-IP and HTTP-only, so it never saw the
//!   device-originated `rc:rpc.request` / `rc:ssh.request` WebSocket legs; and
//! * an SSH caller could burst grants faster than the target's 16-slot pending
//!   table, evicting a legitimate caller's un-redeemed grant (the table drops
//!   the OLDEST) — a targeted denial of someone else's access.
//!
//! Enforcement lives in the shared `authorize` of each subsystem, which is the
//! one place BOTH the HTTP route and the WS leg funnel through, so neither
//! transport can acquire an unlimited path by accident.
//!
//! Sliding window rather than a token bucket: the documented unit is literally
//! "N per minute", and a window keeps that exact meaning with no refill-rate
//! translation for an operator to get wrong.

use bson::oid::ObjectId;
use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Window length. The configured ceilings are all expressed per minute.
const WINDOW: Duration = Duration::from_secs(60);

/// How many idle keys may accumulate before a sweep runs. Bounded so a fleet
/// sweep (many distinct devices, each hit once) cannot grow the map forever.
const SWEEP_THRESHOLD: usize = 1024;

/// Sliding-window counter keyed by `(caller, device)`.
#[derive(Default)]
pub struct RateLimiter {
    hits: DashMap<(ObjectId, ObjectId), Vec<Instant>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an attempt and report whether it is WITHIN `limit_per_minute`.
    ///
    /// Returns `true` when the caller may proceed. The attempt is recorded
    /// either way: a refused attempt still consumed a slot, so a caller that
    /// keeps hammering stays refused for the rest of the window instead of
    /// being handed a fresh allowance.
    pub fn check(&self, caller: ObjectId, device: ObjectId, limit_per_minute: u32) -> bool {
        // 0 disables the limiter rather than blocking everything — a
        // misconfigured ceiling must not take a fleet offline.
        if limit_per_minute == 0 {
            return true;
        }
        let now = Instant::now();
        self.maybe_sweep(now);

        let mut entry = self.hits.entry((caller, device)).or_default();
        entry.retain(|t| now.duration_since(*t) < WINDOW);
        let allowed = entry.len() < limit_per_minute as usize;
        entry.push(now);
        allowed
    }

    /// Bounded-memory variant for metadata discovery. Only admitted attempts
    /// are retained, at most `limit_per_minute` per key. Refusals neither grow
    /// the vector nor prolong the window. The existing `check` is unchanged.
    /// Callers must derive keys from authenticated identities, not payload ids.
    pub fn check_bounded(&self, caller: ObjectId, device: ObjectId, limit_per_minute: u32) -> bool {
        self.check_bounded_at(caller, device, limit_per_minute, Instant::now())
    }

    fn check_bounded_at(
        &self,
        caller: ObjectId,
        device: ObjectId,
        limit_per_minute: u32,
        now: Instant,
    ) -> bool {
        if limit_per_minute == 0 {
            return true;
        }
        self.maybe_sweep(now);
        let mut entry = self.hits.entry((caller, device)).or_default();
        entry.retain(|t| now.duration_since(*t) < WINDOW);
        if entry.len() >= limit_per_minute as usize {
            return false;
        }
        entry.push(now);
        true
    }

    /// Drop keys whose whole window has expired. Cheap and amortized: only
    /// runs once the map is large enough to be worth walking.
    fn maybe_sweep(&self, now: Instant) {
        if self.hits.len() < SWEEP_THRESHOLD {
            return;
        }
        self.hits
            .retain(|_, v| v.iter().any(|t| now.duration_since(*t) < WINDOW));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_then_refuses() {
        let rl = RateLimiter::new();
        let (caller, device) = (ObjectId::new(), ObjectId::new());
        for i in 0..5 {
            assert!(rl.check(caller, device, 5), "attempt {i} should be allowed");
        }
        assert!(!rl.check(caller, device, 5), "the 6th must be refused");
    }

    #[test]
    fn limit_is_per_caller_device_pair() {
        let rl = RateLimiter::new();
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let (dev1, dev2) = (ObjectId::new(), ObjectId::new());
        for _ in 0..3 {
            assert!(rl.check(a, dev1, 3));
        }
        assert!(!rl.check(a, dev1, 3));
        // A different device, and a different caller, each get their own
        // budget — one noisy pair must not lock out the rest of the fleet.
        assert!(rl.check(a, dev2, 3));
        assert!(rl.check(b, dev1, 3));
    }

    #[test]
    fn zero_disables_the_limiter() {
        let rl = RateLimiter::new();
        let (caller, device) = (ObjectId::new(), ObjectId::new());
        for _ in 0..100 {
            assert!(rl.check(caller, device, 0));
        }
    }

    #[test]
    fn refused_attempts_do_not_refill_the_window() {
        let rl = RateLimiter::new();
        let (caller, device) = (ObjectId::new(), ObjectId::new());
        assert!(rl.check(caller, device, 1));
        // Hammering while refused keeps it refused.
        for _ in 0..10 {
            assert!(!rl.check(caller, device, 1));
        }
    }

    #[test]
    fn bounded_rejections_do_not_grow_memory_or_extend_the_window() {
        let rl = RateLimiter::new();
        let id = ObjectId::new();
        let now = Instant::now();
        for _ in 0..6 {
            assert!(rl.check_bounded_at(id, id, 6, now));
        }
        for _ in 0..10_000 {
            assert!(!rl.check_bounded_at(id, id, 6, now + Duration::from_secs(59)));
        }
        assert_eq!(rl.hits.get(&(id, id)).unwrap().len(), 6);
        assert!(rl.check_bounded_at(id, id, 6, now + WINDOW));
        assert_eq!(rl.hits.get(&(id, id)).unwrap().len(), 1);
    }
}
