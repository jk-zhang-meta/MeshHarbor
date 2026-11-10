// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Monotonic-clock helpers.
//!
//! `Instant` counts from an arbitrary origin — on Windows (QPC) and Linux
//! (`CLOCK_MONOTONIC`) that origin is boot — and `Instant::now() - d`
//! PANICS when the machine has been up for less than `d`
//! ("overflow when subtracting duration from instant"). Seeding a timer
//! "d ago so the first event fires at once" is a common idiom in the media
//! pumps, and it is exactly the shape that dies on a host whose session
//! starts within seconds of boot.
//!
//! Field 2026-09-02, CORPLAP-1: the laptop hard-rebooted at 14:11:15 UTC,
//! the daemon was up 23 s later, the viewer's reconnect storm started three
//! sessions 34–52 s after boot, and every one of them panicked at the
//! FFmpeg pump's `Instant::now() - Duration::from_secs(60)` seed. The one
//! that started at +66 s ran fine. Three dead sessions, a crash-recorder
//! strike, and an attempted rollback — from an idiom that is only wrong for
//! the first minute of uptime.

use std::time::{Duration, Instant};

/// `Instant::now() - d`, saturating at "now" when the monotonic clock has not
/// yet advanced `d` past its origin (a machine up for less than `d`).
///
/// The saturated value loses the "already due" property the caller wanted
/// for at most `d` after boot — a first keyframe request or bitrate apply
/// deferred by its own gap — which is the trade this exists for: the
/// alternative was a dead session.
pub fn instant_before(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_sub(d).unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_panics_and_never_exceeds_now() {
        let before = instant_before(Duration::from_secs(60));
        assert!(before <= Instant::now());
        // The value the field panic came from — plus the extreme.
        let huge = instant_before(Duration::MAX);
        assert!(huge <= Instant::now());
    }

    #[test]
    fn subtracts_when_it_can() {
        // A few milliseconds is always subtractable from a running process
        // (the test itself has been alive longer than that by now).
        let d = Duration::from_millis(1);
        let before = instant_before(d);
        assert!(Instant::now().duration_since(before) >= d);
    }
}
