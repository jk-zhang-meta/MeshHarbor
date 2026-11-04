// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #2024 — hand back to the OS the memory a finished remote-desktop session
//! freed.
//!
//! A session's encoder is large (libvpx VP9 4:4:4 at 1280×800: one 49 MB token
//! buffer and a pool of 5 MB frames), and it IS freed when the session ends: the
//! pump future drops within milliseconds of the terminate, and its encoder thread
//! drops the encoder. glibc keeps what was freed, though. Each thread allocates
//! from an arena of its own (up to eight per core), every session encodes on new
//! threads (`rc-enc-*` and libvpx's workers), and freed memory stays mapped in
//! whichever arena it came from. Measured on a 4-core guest, idle after each of
//! three sessions: heap in use 7.3 → 8.9 → 9.1 → 9.2 MB while glibc held
//! 10 → 59 → 177 → 290 MB across 32 arenas, and RSS climbed 51 → 303 MB. One
//! `malloc_trim(0)` gave 214 MB back (RSS 89 MB), and it stayed back.
//!
//! So [`after_session_ended`] runs `malloc_trim(0)` once, on a short-lived thread
//! of its own, [`QUIET`] after the last session ended: long enough for the
//! encoder thread to have finished freeing, and sessions ending together cost one
//! trim. The trim takes each arena's lock in turn; nothing waits for it.
//!
//! glibc only: `malloc_trim` is a glibc extension, and Linux/glibc is where the
//! growth was measured. Windows and macOS were not. Kill switch
//! `ROOMLERD_MEM_TRIM=0`.

#[cfg(any(test, all(target_os = "linux", target_env = "gnu")))]
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

/// How long after the last session end the trim runs.
pub const QUIET: std::time::Duration = std::time::Duration::from_secs(5);

/// Call when a session has let go of its resources. Never blocks.
pub fn after_session_ended() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    glibc::request();
}

/// Turns any number of requests into one action after a quiet spell. The first
/// request starts a worker, later ones extend the spell, and a request that
/// lands while the action runs gets another round instead of being lost.
#[cfg(any(test, all(target_os = "linux", target_env = "gnu")))]
struct Coalesce {
    /// A worker is waiting or acting.
    running: AtomicBool,
    /// A request arrived since the worker last looked.
    again: AtomicBool,
}

#[cfg(any(test, all(target_os = "linux", target_env = "gnu")))]
impl Coalesce {
    const fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            again: AtomicBool::new(false),
        }
    }

    /// Record a request. `true` means the caller must start the worker.
    fn request(&self) -> bool {
        self.again.store(true, SeqCst);
        !self.running.swap(true, SeqCst)
    }

    /// The worker: `wait` out the quiet spell (again, while requests keep
    /// coming), `act`, and go round once more if a request landed too late for
    /// the last look.
    fn work(&self, mut wait: impl FnMut(), mut act: impl FnMut()) {
        loop {
            while self.again.swap(false, SeqCst) {
                wait();
            }
            act();
            self.running.store(false, SeqCst);
            // A request after the last look saw `running` still set and started
            // no worker: take it over, unless the worker it did start already has.
            if !self.again.load(SeqCst) || self.running.swap(true, SeqCst) {
                return;
            }
        }
    }
}

/// `VmRSS` from a `/proc/<pid>/status` text, in kB.
#[cfg(any(test, all(target_os = "linux", target_env = "gnu")))]
fn vm_rss_kb(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod glibc {
    use super::{Coalesce, QUIET};

    static STATE: Coalesce = Coalesce::new();

    pub(super) fn request() {
        if !tunnel_core::env::flag("MEM_TRIM", true) || !STATE.request() {
            return;
        }
        let spawned = std::thread::Builder::new()
            .name("mem-trim".into())
            .spawn(|| STATE.work(|| std::thread::sleep(QUIET), trim));
        if let Err(e) = spawned {
            // No worker will run: let the next session end try again.
            STATE.running.store(false, super::SeqCst);
            tracing::debug!(%e, "mem-trim: no thread for the trim; skipped");
        }
    }

    fn rss_mb() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .as_deref()
            .and_then(super::vm_rss_kb)
            .map_or(0, |kb| kb / 1024)
    }

    pub(super) fn trim() {
        let before = rss_mb();
        let started = std::time::Instant::now();
        // SAFETY: `malloc_trim` takes no pointers and is thread-safe (it locks
        // each arena in turn). `0` keeps no padding at the top of the heap.
        let released = unsafe { libc::malloc_trim(0) } != 0;
        tracing::info!(
            released,
            rss_before_mb = before,
            rss_after_mb = rss_mb(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "mem-trim: handed the memory finished sessions freed back to the OS (#2024)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn one_request_starts_one_worker_that_acts_once() {
        let c = Coalesce::new();
        assert!(c.request(), "the first request starts the worker");
        let (waits, acts) = (Cell::new(0), Cell::new(0));
        c.work(|| waits.set(waits.get() + 1), || acts.set(acts.get() + 1));
        assert_eq!((waits.get(), acts.get()), (1, 1));
        assert!(
            c.request(),
            "once it is done, the next request starts another"
        );
    }

    #[test]
    fn requests_during_the_quiet_spell_extend_it_and_share_one_action() {
        let c = Coalesce::new();
        assert!(c.request());
        let (waits, acts) = (Cell::new(0), Cell::new(0));
        c.work(
            || {
                waits.set(waits.get() + 1);
                if waits.get() < 3 {
                    assert!(!c.request(), "the waiting worker covers it");
                }
            },
            || acts.set(acts.get() + 1),
        );
        assert_eq!((waits.get(), acts.get()), (3, 1));
    }

    #[test]
    fn a_request_while_acting_gets_another_round() {
        let c = Coalesce::new();
        assert!(c.request());
        let acts = Cell::new(0);
        c.work(
            || {},
            || {
                acts.set(acts.get() + 1);
                if acts.get() == 1 {
                    assert!(!c.request(), "the worker is still running");
                }
            },
        );
        assert_eq!(acts.get(), 2, "the late request was not lost");
        assert!(c.request(), "and the worker let go when it was done");
    }

    #[test]
    fn vm_rss_is_read_from_proc_status() {
        let status =
            "Name:\troomlerd\nVmPeak:\t  412000 kB\nVmRSS:\t  303104 kB\nRssAnon:\t  256224 kB\n";
        assert_eq!(vm_rss_kb(status), Some(303_104));
        assert_eq!(vm_rss_kb("Name:\troomlerd\n"), None);
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn the_trim_runs_and_returns() {
        glibc::trim();
    }
}
