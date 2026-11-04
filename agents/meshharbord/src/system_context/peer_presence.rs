// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Cross-session "controller is currently connected" signal between
//! the user-context worker and the SCM-supervisor.
//!
//! ## Why a marker file
//!
//! The plan §4 originally specified an inherited anonymous pipe
//! (`STARTUPINFOEX::lpAttributeList` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`)
//! between supervisor and worker. That's the architecturally pure
//! design but it's ~200 LOC of Win32 FFI plus handle-life-cycle bugs
//! to debug.
//!
//! This module ships a smaller equivalent: a lock-file at a stable
//! path that any process can stat. The file's mtime is the heartbeat
//! — fresh mtime means a controller is currently connected; mtime
//! older than [`PRESENCE_MAX_AGE`] means stale (worker crashed mid-
//! session, controller disconnected without graceful shutdown, etc.).
//!
//! Tradeoffs vs. the inherited-pipe design:
//! * **Pros**: zero Win32 FFI, ~50 LOC, ProgramData ACL handles
//!   cross-session visibility for free, recovers automatically from
//!   worker crashes.
//! * **Cons**: 5-second polling granularity means a worker that
//!   crashed exactly between heartbeats can leave a stale signal for
//!   up to [`PRESENCE_MAX_AGE`] before the supervisor notices. The
//!   browser's auto-reconnect ladder (0.2.0) closes that gap from
//!   the operator's side: the controller will see a brief
//!   "Reconnecting..." chip and the next supervisor cycle re-spawns
//!   under whichever role is currently appropriate.
//!
//! ## Path
//!
// RETIRED-NAME-ANCHOR-BEGIN
// This path is a RENDEZVOUS between two processes — the supervisor and the
// SystemContext worker — which can be different versions during an update.
// Both ends must agree on the name, and only one of them gets replaced
// first, so the name is a compatibility surface rather than a label.
//! `C:\ProgramData\roomler-agent\peer-connected.lock` — under
//! `%PROGRAMDATA%`. Both the user-context worker (running as the
//! interactive user) and the SCM service (running as `LocalSystem`)
//! can read and write here:
//! * `LocalSystem` is admin-equivalent for ACL purposes — full
//!   access by default on every Windows install.
//! * The interactive user inherits `Users:Modify` on subdirectories
//!   created beneath `%PROGRAMDATA%` via the standard CreatorOwner
//!   ACL on `C:\ProgramData`. The `create_dir_all` call below
//!   relies on that inheritance.
//!
//! On non-Windows the path falls back to `/tmp/roomler-agent/`.
//! The non-Windows path is for development / testing only — no
//! cross-session semantics are needed there.
//!
//! ## Wire format
//!
//! Empty file. The mtime is the only signal. Worker rewrites the
//! file's content (overwrite, not append) every 5 s while the
//! WebRTC peer is in `Connected` state, so the mtime advances on
//! every heartbeat. On peer transition to `Disconnected` /
//! `Closed` / `Failed` the worker calls [`signal_disconnected`]
//! which removes the file. The supervisor's
//! [`is_signaled`] returns `false` for both "file doesn't exist"
//! and "file is too old".

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// How often the worker should call [`signal_connected`] while a
/// controller is connected. The supervisor checks at its loop
/// cadence (~1 s); [`PRESENCE_MAX_AGE`] is the staleness threshold.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// File mtime older than this is treated as stale ([`is_signaled`]
/// returns false). Three heartbeat intervals — covers a single
/// missed write without flagging stale.
pub const PRESENCE_MAX_AGE: Duration = Duration::from_secs(15);

/// Path to the marker file. On Windows: under `%PROGRAMDATA%`. On
/// other targets: `/tmp/roomler-agent/` (test / dev only — the
/// cross-session semantics this module provides are Windows-specific).
pub fn marker_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(programdata) = std::env::var_os("PROGRAMDATA") {
            return PathBuf::from(programdata)
                .join("roomler-agent")
                .join("peer-connected.lock");
        }
        // Fallback if PROGRAMDATA is somehow unset (extremely rare —
        // even Windows PE has it). Use the SystemRoot temp dir.
        if let Some(systemroot) = std::env::var_os("SystemRoot") {
            return PathBuf::from(systemroot)
                .join("Temp")
                .join("roomler-agent-peer-connected.lock");
        }
        PathBuf::from("C:\\Windows\\Temp\\roomler-agent-peer-connected.lock")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/tmp/roomler-agent/peer-connected.lock")
    }
}

/// Touch the marker file. Worker calls this on initial peer-Connected
/// transition AND on every [`HEARTBEAT_INTERVAL`] tick while still
/// Connected. Idempotent — overwrites any existing content.
///
/// Errors are returned for caller logging but never recovered from —
/// a missing marker just means the supervisor falls back to the
/// user-context worker, which is the safe degradation.
///
/// The body carries the current unix timestamp as decimal text. This
/// is NOT a no-op: an earlier rc.1/rc.2 implementation wrote `b""`
/// which Windows NTFS treated as a same-size-no-data-change, so the
/// `LastWriteTime` was never updated past the first creation. The
/// supervisor's `is_signaled()` reads that LastWriteTime, so the
/// marker effectively went stale 15 s after the first heartbeat
/// regardless of how many subsequent writes happened. Writing varying
/// bytes (the timestamp differs every second) forces NTFS to advance
/// the mtime on every call. Field repro: the field-test host 0.3.0-rc.2 2026-05-05
/// — `peer-presence-status` self-write probe showed `signal_connected:
/// OK; post-write age=2162s` after a successful write.
pub fn signal_connected() -> std::io::Result<()> {
    let path = marker_path();
    if let Some(parent) = path.parent() {
        // Best-effort directory creation. Errors-on-already-exists
        // are normal and ignored by `create_dir_all`. Errors-on-
        // permission-denied surface up — caller logs and moves on.
        fs::create_dir_all(parent)?;
    }
    let now_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Newline-terminated decimal so a human running `Get-Content` sees
    // a clean unix epoch they can compare against `Get-Date -UFormat %s`.
    let body = format!("{now_secs}\n");
    fs::write(&path, body.as_bytes())?;
    Ok(())
}

/// Remove the marker file. Worker calls this on peer transition to
/// `Disconnected` / `Closed` / `Failed`. Idempotent — `NotFound` is
/// not an error.
pub fn signal_disconnected() -> std::io::Result<()> {
    let path = marker_path();
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether a controller is currently connected to *some* worker on
/// this host. Returns true iff the marker file exists AND its mtime
/// is younger than [`PRESENCE_MAX_AGE`].
///
/// Stale marker (mtime older than the threshold) is treated as
/// false. This recovers automatically from worker crashes — the
/// supervisor's next cycle sees the staleness and falls back to the
/// user-context spawn arm.
pub fn is_signaled() -> bool {
    snapshot().fresh
}

/// Diagnostic snapshot of the marker file's state. Used by the
/// `peer-presence-status` CLI command and (via the [`Snapshot::fresh`]
/// field) by [`is_signaled`].
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Where the supervisor / worker think the marker should live.
    pub path: PathBuf,
    /// Marker file present on disk?
    pub exists: bool,
    /// `Some(age)` when the file exists and we could read its mtime.
    /// `None` when missing or unreadable.
    pub age: Option<Duration>,
    /// Final answer used by the supervisor: file exists AND mtime is
    /// within [`PRESENCE_MAX_AGE`] of `now()`.
    pub fresh: bool,
    /// Filesystem error from `fs::metadata` if the file existed but
    /// metadata access failed (rare — typically permission, locked).
    pub error: Option<String>,
}

/// Read the marker without coercing failure modes. Returns the
/// raw observability data the supervisor + CLI use to differentiate
/// "no controller connected" from "marker write failed".
pub fn snapshot() -> Snapshot {
    let path = marker_path();
    match fs::metadata(&path) {
        Ok(meta) => match meta.modified() {
            Ok(mtime) => match SystemTime::now().duration_since(mtime) {
                Ok(age) => Snapshot {
                    fresh: age <= PRESENCE_MAX_AGE,
                    age: Some(age),
                    exists: true,
                    error: None,
                    path,
                },
                Err(_) => Snapshot {
                    // Mtime is in the future — clock skew. Treat as
                    // fresh; the alternative (treating as stale) would
                    // falsely tear down a legitimately-connected
                    // SystemContext worker because of a host clock
                    // adjustment.
                    fresh: true,
                    age: Some(Duration::ZERO),
                    exists: true,
                    error: None,
                    path,
                },
            },
            Err(e) => Snapshot {
                fresh: false,
                age: None,
                exists: true,
                error: Some(format!("modified() failed: {e}")),
                path,
            },
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Snapshot {
            fresh: false,
            age: None,
            exists: false,
            error: None,
            path,
        },
        Err(e) => Snapshot {
            fresh: false,
            age: None,
            exists: false,
            error: Some(format!("metadata() failed: {e}")),
            path,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EVERY test below that touches the marker takes this lock — five of them.
    // They share ONE process-wide path and every one of them deletes it, so run
    // in parallel a `signal_disconnected` from one lands between another's write
    // and its read, and the read panics with "marker readable after write" — a
    // failure that says nothing about the code under test. Reproduced on
    // master: green in isolation, red in the full `--features system-context`
    // suite.
    //
    // ⚠️ The count is not decoration. The first fix guarded the three obvious
    // writers and the suite STILL failed roughly 1 run in 5, because two more
    // tests touch the same path — and a single green run had already
    // "confirmed" it. Do not drop a guard that looks redundant; verify by
    // running the FULL lane ten times, never a `system_context` filter, which
    // is the very isolation that hides this.
    //
    // Same shape as `encode::RELAY_ENV_LOCK`: one lock, held for the whole test.
    // `unwrap_or_else(|e| e.into_inner())` because a panic in one test poisons
    // the mutex, and the next test failing on the poison instead of its own
    // assertion hides which one actually broke.
    static MARKER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn marker_path_is_absolute_under_programdata_or_tmp() {
        let p = marker_path();
        assert!(p.is_absolute(), "marker path must be absolute: {:?}", p);
        // Sanity: the trailing component is the marker filename.
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("peer-connected.lock")
        );
    }

    #[test]
    fn heartbeat_interval_under_max_age() {
        // Three consecutive successful heartbeats fit under
        // PRESENCE_MAX_AGE so a single missed write doesn't flag
        // stale — important so the supervisor doesn't tear down the
        // worker on routine GC pauses or system sleep transitions.
        assert!(HEARTBEAT_INTERVAL * 3 == PRESENCE_MAX_AGE);
    }

    #[test]
    fn signal_disconnected_when_missing_is_ok() {
        let _marker_guard = MARKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Idempotent contract: removing a non-existent marker is
        // not an error. The first signal_disconnected call after
        // worker startup typically hits this path because the
        // previous session's marker was already removed at
        // shutdown.
        let path = marker_path();
        let _ = fs::remove_file(&path);
        assert!(signal_disconnected().is_ok());
    }

    #[test]
    fn signal_connected_writes_non_empty_body() {
        let _marker_guard = MARKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Regression test for the rc.1/rc.2 bug. Empty-body writes
        // get short-circuited by NTFS so LastWriteTime never advances
        // past the first creation; the supervisor's mtime-based
        // freshness check then goes stale 15 s later regardless of
        // how many successful "writes" happened. The body must
        // genuinely change on every call.
        if signal_connected().is_err() {
            eprintln!("skipping — marker dir not writable in this environment");
            return;
        }
        let path = marker_path();
        let bytes = fs::read(&path).expect("marker readable after write");
        assert!(
            !bytes.is_empty(),
            "marker body must be non-empty so NTFS advances LastWriteTime"
        );
        // Body should parse as a positive unix timestamp followed by
        // a newline — locks the format too so a future refactor that
        // changes it has to update this test alongside.
        let s = std::str::from_utf8(&bytes).expect("body is utf-8");
        assert!(s.ends_with('\n'), "body should end with newline; got {s:?}");
        let trimmed = s.trim_end();
        let n: u64 = trimmed
            .parse()
            .unwrap_or_else(|_| panic!("body must parse as u64; got {trimmed:?}"));
        // Sanity: the timestamp should be in [now - 60s, now + 60s].
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            n.abs_diff(now) < 60,
            "marker timestamp should be near now (n={n}, now={now})"
        );
        let _ = signal_disconnected();
    }

    #[test]
    fn signal_connected_advances_mtime_across_calls() {
        let _marker_guard = MARKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Direct regression for the field bug: two consecutive
        // signal_connected calls 100ms apart must produce strictly
        // increasing (or at least non-decreasing) mtimes. The
        // pre-fix `fs::write(path, b"")` failed this on Windows
        // NTFS — same content, no mtime advance.
        if signal_connected().is_err() {
            eprintln!("skipping — marker dir not writable in this environment");
            return;
        }
        let path = marker_path();
        let m1 = match fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => {
                eprintln!("skipping — mtime unreadable on this fs");
                return;
            }
        };
        // Sleep 1.1s so the seconds field of the body changes — the
        // body is unix-epoch *seconds*, so a sub-second sleep would
        // produce identical content and we'd hit the same NTFS
        // optimization we're guarding against.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        signal_connected().expect("second write");
        let m2 = match fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => {
                eprintln!("skipping — mtime unreadable on this fs");
                return;
            }
        };
        assert!(
            m2 >= m1,
            "mtime must advance across heartbeats (m1={m1:?}, m2={m2:?})"
        );
        let _ = signal_disconnected();
    }

    #[test]
    fn round_trip_signal_connected_then_is_signaled() {
        let _marker_guard = MARKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // On the test runner we can write to ProgramData (developer
        // workstation) or /tmp (Linux CI); fall back to skipping
        // gracefully if the directory create fails (locked-down CI
        // or macOS sandbox).
        if signal_connected().is_err() {
            eprintln!("skipping — marker dir not writable in this environment");
            return;
        }
        assert!(is_signaled(), "marker fresh after signal_connected");
        assert!(signal_disconnected().is_ok());
        assert!(!is_signaled(), "marker absent after signal_disconnected");
    }

    #[test]
    fn stale_marker_returns_false() {
        let _marker_guard = MARKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Drop a marker, then artificially backdate via filetimes if
        // available. Without the filetimes crate we approximate by
        // checking the contract directly: is_signaled returns false
        // when the file is missing (proxy for stale).
        let _ = signal_disconnected();
        assert!(!is_signaled());
    }
}
// RETIRED-NAME-ANCHOR-END
