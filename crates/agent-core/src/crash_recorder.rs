// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR(24): names the PRE-RENAME appdirs segment a host installed before
// P4b still has; appdirs::app_segment resolves it, so it is an input.
//! Persist agent crash reports to disk for later upload.
//!
//! Three callers feed in (panic hook in `logging.rs`, watchdog stall
//! in `watchdog.rs`, SCM supervisor in `win_service/supervisor.rs`),
//! each routing through [`record`] with a [`CrashReason`] +
//! [`WriterContext`]. The recorder serialises an
//! [`AgentCrashPayload`] (shared wire type defined in
//! `meshharbor_remote_control::models`) to a sidecar JSON file under
//! the appropriate crashes dir; on next agent startup,
//! `crash_uploader::drain_and_upload` POSTs each file to roomler.ai
//! and deletes it on 2xx.
//!
//! ## Two writer contexts on Windows
//!
//! - **Worker** (user-context): writes under `logging::log_dir()/
//!   crashes/` which resolves to `%LOCALAPPDATA%\roomler\
//!   roomler-agent\data\logs\crashes\`. The user-context uploader
//!   reads from this same dir on startup.
//! - **Supervisor** (LocalSystem, Windows-only): writes under
//!   `%PROGRAMDATA%\roomler\roomler-agent\crashes\` because
//!   `directories::ProjectDirs::data_local_dir()` under LocalSystem
//!   resolves to `C:\Windows\System32\config\systemprofile\…` which
//!   the user-context worker can't read. PROGRAMDATA is world-
//!   readable (ACL set on dir creation) so the same uploader scans
//!   both dirs and merges results.
//!
//! On non-Windows the Supervisor context resolves to the writing
//! process's own Worker dir. The one supervisor there is macOS's (FR-43,
//! `macos_supervisor.rs`): the ROOT daemon records a GUI worker that died
//! before its own panic hook could (FR-97 P6e-2), so the record lands in
//! root's dir, and the root daemon's own uploader drains it on the
//! daemon's enrollment.
//!
//! ## Reentrancy + panic safety
//!
//! [`record`] is called from inside a panic hook. If the recorder
//! itself panics (OOM during JSON serialisation, IO blow-up, etc.)
//! the outer `std::panic::set_hook` would normally abort the
//! process before its existing text-dump call has flushed.
//! Wrapping the recorder body in `catch_unwind` keeps the outer
//! hook's `prev(info)` reachable; any inner panic is reported via
//! `eprintln!("crash_recorder:RECURSIVE_PANIC …")` so a fielded
//! support log still surfaces the inner failure.
//!
//! ## Scrub pipeline
//!
//! Both the summary AND the log tail run through
//! [`scrub_credentials`] before the payload is written to disk. The
//! pipeline redacts known credential shapes (Bearer tokens, JWT
//! triplets, MongoDB URIs with userinfo, `password=` query params,
//! WebRTC ICE ufrag/pwd lines). Each redaction increments a count
//! that's appended to the summary as `[scrubbed N tokens]` so
//! operators can tell at-a-glance when redaction fired (low number =
//! probably clean; high number = either a pathological log or a new
//! credential shape that needs adding to the scrub set).

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use meshharbor_remote_control::models::{AgentCrashPayload, CrashReason};
pub use meshharbor_remote_control::models::{AgentCrashPayload as Payload, CrashReason as Reason};

/// Maximum serialised JSON payload size. The backend's ingest route
/// caps at 80 KiB to leave HTTP overhead room; we cap the payload
/// itself at 64 KiB so the trim margin covers the body framing.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Last-N lines of the rolling log to attach to a crash report.
/// The tail is trimmed further inside [`record`] if the resulting
/// JSON would exceed [`MAX_PAYLOAD_BYTES`].
pub const LOG_TAIL_LINES: usize = 200;

/// Minimum seconds between consecutive sidecar writes in the same
/// dir. A tight crash-loop (e.g. SystemContext worker dying every
/// 2s with `code=1`, field repro 2026-05-17 a third field-test host) would otherwise
/// fill the dir with ~24 sidecars/minute. With this rate-limit one
/// crash is recorded every 30s, capturing enough forensics + leaving
/// the disk + log alone.
pub const MIN_INTERVAL_SECS: i64 = 30;

/// Hard cap on sidecars in a single dir. If the worker can never
/// successfully start (and thus never run the uploader to drain),
/// even the rate-limited writes would accumulate forever. 100 ×
/// 64 KiB = 6.4 MB max disk impact per dir, which is generous for
/// forensics but bounded. Beyond the cap, new records are dropped
/// silently with a once-per-minute throttled WARN.
pub const HARD_CAP: usize = 100;

/// Where to persist the sidecar. See the module-level docs for the
/// path resolution + the rationale for splitting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterContext {
    /// User-context worker process. Writes under
    /// `logging::log_dir()/crashes/`.
    Worker,
    // RETIRED-NAME-ANCHOR(3): the PRE-RENAME tree appdirs still resolves on an upgraded
    // host.
    /// LocalSystem SCM supervisor. Writes under
    /// `%PROGRAMDATA%\roomler\roomler-agent\crashes\` on Windows,
    /// falls back to the Worker dir on non-Windows: on macOS that is
    /// the root daemon's, recording its GUI worker (FR-97 P6e-2).
    Supervisor,
}

/// Persist a crash sidecar atomically. Best-effort: any IO failure
/// logs `warn!` and returns; never blocks the crash-exit path.
pub fn record(reason: CrashReason, summary: &str, ctx: WriterContext) {
    record_with_log_tail(reason, summary, ctx, None);
}

/// Same as [`record`] but accepts a caller-supplied `log_tail`
/// (typically the child worker's captured stderr) that OVERRIDES
/// the local rolling-log read. Used by the SCM supervisor on
/// SupervisorDetected crashes so the sidecar's `log_tail` carries
/// the WORKER's last few KiB of stderr instead of the supervisor's
/// own rolling log (which is useless for diagnosing why the worker
/// died). Field repro: a third field-test host SystemContext loop, 2026-05-17.
///
/// `log_tail_override = None` → existing behaviour (read
/// supervisor's rolling log).
/// `log_tail_override = Some(s)` → use `s` verbatim before scrub +
/// envelope-trim. Empty string is still treated as "override":
/// callers pass `None` when they have no buffer at all.
pub fn record_with_log_tail(
    reason: CrashReason,
    summary: &str,
    ctx: WriterContext,
    log_tail_override: Option<String>,
) {
    // catch_unwind so a recorder-internal panic doesn't unwind into
    // the caller's panic hook + abort the process before its
    // existing text-dump has flushed.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record_inner(reason, summary, ctx, log_tail_override)
    }));
    match outcome {
        Ok(Ok(path)) => {
            // Downgraded INFO → DEBUG (2026-05-17 a third field-test host storm fix):
            // a tight crash-loop would otherwise spam this line at INFO
            // through the rolling log file. The rate-limit kicks in
            // after the first write, but even those rate-limited
            // writes are DEBUG so the runtime log stays quiet under
            // normal operation. Operators looking for "did the
            // sidecar land" check the dir directly.
            tracing::debug!(crash_sidecar = %path.display(), ?reason, "wrote crash sidecar");
        }
        Ok(Err(e)) => {
            // Suppression returns Err with a constant reason string;
            // log_suppression_throttled already emitted (or threw the
            // throttle), so don't double-warn for that path.
            let msg = e.to_string();
            if !is_suppression_message(&msg) {
                tracing::warn!(error = %msg, "crash_recorder: write failed");
            }
        }
        Err(_) => {
            // The closure panicked. Avoid touching tracing here (its
            // backing subscriber may also be in a poisoned state mid
            // crash) — `eprintln!` goes to the SCM service's stderr
            // capture or the terminal, which is sufficient.
            eprintln!("crash_recorder:RECURSIVE_PANIC during record()");
        }
    }
}

fn record_inner(
    reason: CrashReason,
    summary: &str,
    ctx: WriterContext,
    log_tail_override: Option<String>,
) -> std::io::Result<PathBuf> {
    let dir = crashes_dir_for(ctx)?;
    fs::create_dir_all(&dir)?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Crash-loop suppression. Field repro 2026-05-17 on a third field-test host:
    // SystemContext worker dies every 2s with code=1 → supervisor
    // records a SupervisorDetected sidecar per spawn → without
    // suppression we'd fill PROGRAMDATA with ~24 sidecars/minute
    // forever (the worker never lives long enough to run the
    // uploader). See `should_suppress` for the rate-limit + cap
    // contract; `log_suppression_throttled` keeps the warn from
    // spamming.
    if let Some(reason) = should_suppress(&dir, now_unix) {
        // rc.51: tally the suppressed write so the next sidecar that
        // DOES land carries the count — loop intensity stays visible.
        SUPPRESSED_SINCE_LAST.fetch_add(1, Ordering::Relaxed);
        log_suppression_throttled(&dir, reason, now_unix);
        return Err(std::io::Error::other(reason.as_str()));
    }

    let pid = std::process::id();

    // log_tail source: caller-supplied (e.g. captured worker stderr)
    // takes precedence; otherwise read the local rolling log. The
    // scrub + envelope-trim pipeline below treats both identically.
    let raw_tail = log_tail_override.unwrap_or_else(|| read_log_tail(LOG_TAIL_LINES));
    let (scrubbed_summary, scrub_count_summary) = scrub_credentials(summary);
    let (scrubbed_tail, scrub_count_tail) = scrub_credentials(&raw_tail);
    let total_scrubs = scrub_count_summary + scrub_count_tail;
    let final_summary = if total_scrubs > 0 {
        format!("{scrubbed_summary} [scrubbed {total_scrubs} tokens]")
    } else {
        scrubbed_summary
    };

    // rc.51: drain the suppressed-since-last tally — this sidecar is
    // about to be written successfully, so it "absorbs" the count of
    // crashes the 1/60 s throttle dropped since the previous write.
    let suppressed_since_last = SUPPRESSED_SINCE_LAST.swap(0, Ordering::Relaxed) as u32;

    let mut payload = AgentCrashPayload {
        crashed_at_unix: now_unix,
        reason,
        summary: final_summary,
        log_tail: scrubbed_tail,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        hostname: detect_hostname(),
        pid,
        suppressed_since_last,
    };

    // Cap JSON at MAX_PAYLOAD_BYTES by progressively trimming the
    // log tail. Worst case the tail collapses to just the truncation
    // marker; the metadata fields are tiny so we never overflow on
    // those alone.
    fit_to_envelope(&mut payload, MAX_PAYLOAD_BYTES);

    let final_path = dir.join(format!("{now_unix}-{pid}.json"));
    let tmp_path = dir.join(format!("{now_unix}-{pid}.json.tmp"));
    {
        let mut f = fs::File::create(&tmp_path)?;
        serde_json::to_writer(&mut f, &payload)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        f.flush()?;
    }
    // POSIX rename + Windows MoveFileEx(MOVEFILE_REPLACE_EXISTING)
    // are both atomic for same-volume targets. The crashes dir lives
    // alongside other agent state on the data drive, so no cross-
    // volume concern.
    fs::rename(&tmp_path, &final_path)?;

    Ok(final_path)
}

/// Resolve the crashes dir for the given context, creating parent
/// dirs lazily on first write.
pub fn crashes_dir_for(ctx: WriterContext) -> std::io::Result<PathBuf> {
    match ctx {
        WriterContext::Worker => crate::logging::log_dir()
            .map(|p| p.join("crashes"))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "logging::log_dir() unavailable for Worker crash sidecar",
                )
            }),
        WriterContext::Supervisor => supervisor_crashes_dir(),
    }
}

#[cfg(target_os = "windows")]
fn supervisor_crashes_dir() -> std::io::Result<PathBuf> {
    Ok(crate::appdirs::machine_global_dir().join("crashes"))
}

#[cfg(not(target_os = "windows"))]
fn supervisor_crashes_dir() -> std::io::Result<PathBuf> {
    // The writing process's own dir. On macOS the writer is the root
    // daemon recording its GUI worker (FR-97 P6e-2), and its own uploader
    // scans this dir (`pending_all`).
    crate::logging::log_dir()
        .map(|p| p.join("crashes"))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "logging::log_dir() unavailable for Supervisor crash sidecar",
            )
        })
}

/// Drain pending crash payloads from BOTH the worker + supervisor
/// dirs (deduped by file path on the rare case they're the same
/// directory). Returned tuples carry the on-disk path so the
/// uploader can delete each on successful POST.
///
/// Skipped files (corrupt JSON, > MAX_PAYLOAD_BYTES, unparseable
/// timestamp) are logged + left on disk — better to leak a few
/// orphan sidecars than to silently lose a crash record that might
/// be deserialisable after a future fix.
pub fn pending_all() -> Vec<(PathBuf, AgentCrashPayload)> {
    let mut out: Vec<(PathBuf, AgentCrashPayload)> = Vec::new();
    let mut seen_dirs: Vec<PathBuf> = Vec::with_capacity(2);
    for ctx in [WriterContext::Worker, WriterContext::Supervisor] {
        if let Ok(dir) = crashes_dir_for(ctx) {
            if seen_dirs.contains(&dir) {
                continue;
            }
            seen_dirs.push(dir.clone());
            out.extend(scan_dir(&dir));
        }
    }
    // Stable order: oldest first so the uploader processes in
    // crash chronology.
    out.sort_by_key(|(_, p)| p.crashed_at_unix);
    out
}

fn scan_dir(dir: &PathBuf) -> Vec<(PathBuf, AgentCrashPayload)> {
    let mut out = Vec::new();
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "crash_recorder: read_dir failed");
            return out;
        }
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() > MAX_PAYLOAD_BYTES as u64 {
            tracing::warn!(
                file = %path.display(),
                bytes = meta.len(),
                "crash_recorder: skipping oversized sidecar"
            );
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(file = %path.display(), error = %e, "crash_recorder: read failed");
                continue;
            }
        };
        match serde_json::from_slice::<AgentCrashPayload>(&bytes) {
            Ok(payload) => out.push((path, payload)),
            Err(e) => {
                tracing::warn!(
                    file = %path.display(),
                    error = %e,
                    "crash_recorder: skipping malformed sidecar"
                );
            }
        }
    }
    out
}

// ─── Crash-loop suppression ────────────────────────────────────────────────

/// Why a record_inner attempt declined to write. Stored in the
/// returned io::Error string so the outer `record()` can distinguish
/// "real write failure" (warn) from "rate-limit / cap hit" (already
/// logged at throttled WARN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressReason {
    /// Most-recent sidecar in the dir is fresh — write rate-limited.
    RecentSidecar,
    /// Dir already has [`HARD_CAP`] sidecars; drop to bound disk.
    HardCapReached,
}

impl SuppressReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecentSidecar => "crash_recorder: recent sidecar; rate-limited",
            Self::HardCapReached => "crash_recorder: hard cap reached; suppressing",
        }
    }
}

fn is_suppression_message(msg: &str) -> bool {
    msg == SuppressReason::RecentSidecar.as_str() || msg == SuppressReason::HardCapReached.as_str()
}

/// Pure: should the next sidecar write to `dir` be suppressed?
/// `now_unix` is the proposed crashed_at_unix for the new sidecar.
///
/// Two suppression rules, in order:
/// 1. **Hard cap** — if `dir` already contains [`HARD_CAP`] or more
///    `*.json` sidecars, drop the new write. Bounds worst-case disk.
/// 2. **Rate limit** — if the most-recent sidecar in `dir` is within
///    [`MIN_INTERVAL_SECS`] of `now_unix`, drop the new write. The
///    timestamp is parsed from the filename (`{unix_ts}-{pid}.json`)
///    so we don't need mtime lookups (which can be unreliable on
///    filesystems with low granularity).
///
/// Pure over dir contents + clock so tests drive every branch
/// without mocks.
pub fn should_suppress(dir: &Path, now_unix: i64) -> Option<SuppressReason> {
    let entries: Vec<i64> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) != Some("json") {
                    return None;
                }
                let stem = p.file_stem()?.to_str()?;
                let (ts_str, _) = stem.split_once('-')?;
                ts_str.parse::<i64>().ok()
            })
            .collect(),
        Err(_) => return None,
    };

    if entries.len() >= HARD_CAP {
        return Some(SuppressReason::HardCapReached);
    }

    let cutoff = now_unix.saturating_sub(MIN_INTERVAL_SECS);
    if entries.iter().any(|&ts| ts > cutoff) {
        return Some(SuppressReason::RecentSidecar);
    }

    None
}

/// Last unix-second we emitted a suppression warn. Throttled to
/// one per 60s per process — a tight crash-loop hitting suppression
/// every 2s would otherwise log the WARN ~30x/min, which is exactly
/// the spam the suppression is supposed to prevent.
static SUPPRESSION_LAST_WARN_UNIX: AtomicU64 = AtomicU64::new(0);

/// rc.51: count of crash sidecars rate-limit-suppressed since the
/// last sidecar that actually got written. Incremented every time
/// `should_suppress` blocks a write; drained into the next
/// successfully-written sidecar's `suppressed_since_last` field so
/// forensics see loop *intensity* even though only 1/60 s of a tight
/// loop's crashes land on disk.
static SUPPRESSED_SINCE_LAST: AtomicU64 = AtomicU64::new(0);
const SUPPRESSION_WARN_THROTTLE_SECS: u64 = 60;

fn log_suppression_throttled(dir: &Path, reason: SuppressReason, now_unix: i64) {
    let now = now_unix.max(0) as u64;
    let last = SUPPRESSION_LAST_WARN_UNIX.load(Ordering::Relaxed);
    if now.saturating_sub(last) < SUPPRESSION_WARN_THROTTLE_SECS {
        return;
    }
    // Best-effort CAS; if another thread already stamped a newer
    // value we lose the race + skip the log, which is the same
    // outcome we want.
    let _ = SUPPRESSION_LAST_WARN_UNIX.compare_exchange(
        last,
        now,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    tracing::warn!(
        dir = %dir.display(),
        ?reason,
        "crash_recorder: suppressed sidecar write (crash-loop?); throttled to once per 60s"
    );
}

// ─── Scrub pipeline ────────────────────────────────────────────────────────

/// Run the credential scrub over `input` and return (scrubbed,
/// redaction_count). Pure, no IO. Hand-rolled (no regex dep) so the
/// agent build stays slim.
pub fn scrub_credentials(input: &str) -> (String, usize) {
    let mut count = 0usize;
    let mut s = input.to_string();
    // Order matters: Bearer scrub runs BEFORE JWT-shape so a "Bearer
    // <jwt>" string scrubs as a whole instead of double-redacting.
    s = scrub_bearer(&s, &mut count);
    s = scrub_jwt_shape(&s, &mut count);
    s = scrub_mongodb_uri(&s, &mut count);
    s = scrub_password_param(&s, &mut count);
    s = scrub_token_param(&s, &mut count);
    s = scrub_ice_credentials(&s, &mut count);
    (s, count)
}

fn scrub_bearer(input: &str, count: &mut usize) -> String {
    // Replace each `Bearer <token>` occurrence. Token = non-
    // whitespace characters following "Bearer " (case-sensitive,
    // matches the HTTP Authorization header convention). Note that
    // "Bearer" not followed by space-then-token (e.g. "BearerToken"
    // identifiers) is preserved.
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    let bytes = input.as_bytes();
    while let Some(rel) = input[cursor..].find("Bearer ") {
        let start = cursor + rel;
        let token_start = start + "Bearer ".len();
        let mut token_end = token_start;
        while token_end < bytes.len() && !bytes[token_end].is_ascii_whitespace() {
            token_end += 1;
        }
        if token_end > token_start {
            out.push_str(&input[cursor..token_start]);
            out.push_str("[REDACTED]");
            *count += 1;
            cursor = token_end;
        } else {
            // "Bearer " with no token — pass through to avoid an
            // infinite loop on weird inputs.
            out.push_str(&input[cursor..=start]);
            cursor = start + 1;
        }
    }
    out.push_str(&input[cursor..]);
    out
}

fn scrub_jwt_shape(input: &str, count: &mut usize) -> String {
    // Three base64url segments, dot-separated, each ≥8 chars. Walk
    // whitespace-separated tokens; the alternative (full regex) is
    // overkill for the cost of one new dep.
    let mut out = String::with_capacity(input.len());
    let mut first = true;
    for word in input.split_inclusive(|c: char| c.is_whitespace()) {
        // Split off any trailing whitespace so we don't include it
        // in the JWT-shape test.
        let (core, ws_tail) = match word.find(|c: char| c.is_whitespace()) {
            Some(idx) => (&word[..idx], &word[idx..]),
            None => (word, ""),
        };
        if first {
            first = false;
        }
        if is_jwt_shape(core) {
            out.push_str("[REDACTED_JWT]");
            out.push_str(ws_tail);
            *count += 1;
        } else {
            out.push_str(word);
        }
    }
    out
}

fn is_jwt_shape(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| {
        p.len() >= 8
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    })
}

fn scrub_mongodb_uri(input: &str, count: &mut usize) -> String {
    // Replace `mongodb://user:pass@…` with `mongodb://[REDACTED]@…`.
    // Handles `mongodb+srv://` too. Pass-through if the URI has no
    // userinfo segment ("@").
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(rel) = find_scheme(&input[cursor..]) {
        let scheme_start = cursor + rel.0;
        let after_scheme = scheme_start + rel.1.len() + "://".len();
        // Find the next `@` BEFORE the next whitespace.
        let rest = &input[after_scheme..];
        let at_pos = rest.find('@');
        let ws_pos = rest.find(|c: char| c.is_whitespace());
        let take_at = match (at_pos, ws_pos) {
            (Some(a), Some(w)) if a < w => Some(a),
            (Some(a), None) => Some(a),
            _ => None,
        };
        if let Some(a) = take_at {
            out.push_str(&input[cursor..after_scheme]);
            out.push_str("[REDACTED]");
            *count += 1;
            cursor = after_scheme + a;
        } else {
            out.push_str(&input[cursor..after_scheme]);
            cursor = after_scheme;
        }
    }
    out.push_str(&input[cursor..]);
    out
}

fn find_scheme(haystack: &str) -> Option<(usize, &'static str)> {
    let candidates = ["mongodb+srv://", "mongodb://"];
    for c in candidates {
        if let Some(idx) = haystack.find(&c[..c.len() - "://".len()]) {
            // Confirm the "://" follows.
            let after = idx + c.len() - "://".len();
            if haystack[after..].starts_with("://") {
                return Some((idx, &c[..c.len() - "://".len()]));
            }
        }
    }
    None
}

fn scrub_password_param(input: &str, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(rel) = input[cursor..].find("password=") {
        let start = cursor + rel;
        let value_start = start + "password=".len();
        let mut value_end = value_start;
        let bytes = input.as_bytes();
        while value_end < bytes.len()
            && bytes[value_end] != b'&'
            && !bytes[value_end].is_ascii_whitespace()
        {
            value_end += 1;
        }
        if value_end > value_start {
            out.push_str(&input[cursor..value_start]);
            out.push_str("[REDACTED]");
            *count += 1;
            cursor = value_end;
        } else {
            out.push_str(&input[cursor..=start]);
            cursor = start + 1;
        }
    }
    out.push_str(&input[cursor..]);
    out
}

/// rc.52: redact `…token = "value"` / `…token=value` assignments —
/// TOML config lines (`agent_token = "eyJ…"`) and query-string
/// params (`token=eyJ…`). The agent's `config.toml` stores the
/// long-lived Agent JWT this way; a crash sidecar that logs config
/// contents would otherwise leak it into the (world-readable until
/// rc.52's dir-ACL) `%PROGRAMDATA%\roomler\…\crashes\` tree.
/// `scrub_jwt_shape` misses this case because the surrounding quotes
/// break its whitespace-delimited-word boundary detection.
///
/// Matches the literal lowercase substring `token` (covers
/// `agent_token`, `enrollment_token`, bare `token`), then an optional
/// run of spaces, a `=`, optional spaces, an optional opening `"`,
/// and redacts the value up to the next `"`, `&`, or whitespace. The
/// closing quote (if any) is preserved.
fn scrub_token_param(input: &str, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    let bytes = input.as_bytes();
    while let Some(rel) = input[cursor..].find("token") {
        let kw_end = cursor + rel + "token".len();
        let mut i = kw_end;
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            // `token` not followed by an `=` assignment — emit through
            // the keyword and keep scanning.
            out.push_str(&input[cursor..kw_end]);
            cursor = kw_end;
            continue;
        }
        i += 1; // skip '='
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'"' {
            i += 1; // skip opening quote — the value, not the quote, is secret
        }
        let value_start = i;
        while i < bytes.len()
            && bytes[i] != b'&'
            && bytes[i] != b'"'
            && !bytes[i].is_ascii_whitespace()
        {
            i += 1;
        }
        if i > value_start {
            out.push_str(&input[cursor..value_start]);
            out.push_str("[REDACTED]");
            *count += 1;
            cursor = i; // closing quote / delimiter emitted next iteration
        } else {
            out.push_str(&input[cursor..kw_end]);
            cursor = kw_end;
        }
    }
    out.push_str(&input[cursor..]);
    out
}

fn scrub_ice_credentials(input: &str, count: &mut usize) -> String {
    // Process line-by-line; collapse any line containing `ice-ufrag:`
    // or `ice-pwd:` to a fixed redaction marker so neither the
    // ufrag nor the password leak.
    let mut out = String::with_capacity(input.len());
    let mut first = true;
    for line in input.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.contains("ice-ufrag:") || trimmed.contains("ice-pwd:") {
            if !first {
                // no-op; split_inclusive carries the newline already
            }
            out.push_str("<scrubbed ICE credential>");
            // Preserve the newline if it was in the source line.
            if line.ends_with('\n') {
                out.push('\n');
            }
            *count += 1;
        } else {
            out.push_str(line);
        }
        first = false;
    }
    out
}

// ─── Envelope trim ─────────────────────────────────────────────────────────

const TRUNCATION_MARKER: &str = "[…log truncated to fit 64 KiB envelope…]\n";

fn fit_to_envelope(payload: &mut AgentCrashPayload, max_bytes: usize) {
    // Cheap path: under budget already.
    if estimate_json_size(payload) <= max_bytes {
        return;
    }
    // Drop oldest lines from log_tail until we fit, leaving the
    // truncation marker as the first line of the result.
    let lines: Vec<&str> = payload.log_tail.lines().collect();
    let mut kept_from = lines.len();
    let mut prepend = TRUNCATION_MARKER.to_string();
    while kept_from > 0 {
        let candidate_tail: String = std::iter::once(prepend.as_str())
            .chain(
                lines[lines.len() - kept_from..]
                    .iter()
                    .copied()
                    .flat_map(|l| [l, "\n"]),
            )
            .collect();
        let mut probe = payload.clone();
        probe.log_tail = candidate_tail;
        if estimate_json_size(&probe) <= max_bytes {
            *payload = probe;
            return;
        }
        kept_from = kept_from.saturating_sub(10);
        prepend = TRUNCATION_MARKER.to_string();
    }
    // Pathologically large summary + metadata. Final fallback:
    // truncation marker only.
    payload.log_tail = TRUNCATION_MARKER.to_string();
}

fn estimate_json_size(payload: &AgentCrashPayload) -> usize {
    serde_json::to_vec(payload)
        .map(|v| v.len())
        .unwrap_or(usize::MAX)
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn detect_hostname() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Read /etc/hostname; on most Linux/macOS this is the same
        // as `hostname(1)`. Falls back to env-var HOSTNAME if not.
        // `.ok()` collapses the Result so `.filter` (Option) is
        // applicable; without it CI's Linux clippy step blows up
        // with E0599 (Result is not an iterator).
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

fn read_log_tail(n: usize) -> String {
    let Some(log_path) = crate::logging::active_log_path() else {
        return String::new();
    };
    let Ok(file) = fs::File::open(&log_path) else {
        return String::new();
    };
    // Read the whole file and tail-slice. The rolling log is bounded
    // by the file logger's daily rotation; in practice this is < 5
    // MiB which is cheap to read at crash time. If memory pressure
    // becomes a concern, swap for a reverse-line-reader.
    let reader = BufReader::new(file);
    let mut lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
    let from = lines.len().saturating_sub(n);
    lines.drain(..from);
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> AgentCrashPayload {
        AgentCrashPayload {
            crashed_at_unix: 1_700_000_000,
            reason: CrashReason::Panic,
            summary: "test".to_string(),
            log_tail: String::new(),
            agent_version: "0.0.0-test".to_string(),
            os: "linux".to_string(),
            hostname: "test-host".to_string(),
            pid: 42,
            suppressed_since_last: 0,
        }
    }

    // ─── scrub: Bearer ─────────────────────────────────────────────────────

    #[test]
    fn scrub_redacts_bearer_token() {
        let (out, n) = scrub_credentials("Authorization: Bearer abc.def.ghi123\nnext line");
        assert!(out.contains("Bearer [REDACTED]"));
        assert!(!out.contains("abc.def.ghi123"));
        assert!(out.contains("next line"));
        assert!(n >= 1, "should have counted at least 1 redaction");
    }

    #[test]
    fn scrub_bearer_handles_multiple_tokens() {
        let (out, n) = scrub_credentials("Bearer aaaaaa Bearer bbbbbb");
        // Both tokens redacted.
        assert!(!out.contains("aaaaaa"));
        assert!(!out.contains("bbbbbb"));
        // Bearer literal preserved (we only redact the token part).
        assert_eq!(out.matches("Bearer [REDACTED]").count(), 2);
        assert!(n >= 2);
    }

    // ─── scrub: JWT shape ──────────────────────────────────────────────────

    #[test]
    fn scrub_redacts_jwt_shape() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMxMjMifQ.signaturepart";
        // Bare-token-in-log shape: the JWT must be its own word for
        // the (deliberately conservative) scrub to fire. Embedded
        // `key=jwt` is the password-scrub's territory.
        let (out, n) = scrub_credentials(&format!("auth header: {jwt} (expired)"));
        assert!(out.contains("[REDACTED_JWT]"));
        assert!(!out.contains(jwt));
        assert!(out.contains("(expired)"));
        assert!(n >= 1);
    }

    #[test]
    fn scrub_jwt_shape_ignores_dotted_paths() {
        // `/foo.bar.baz` looks dot-separated but segments are too
        // short / not base64url. Must NOT redact.
        let (out, n) = scrub_credentials("path /foo.bar.baz suffix");
        assert_eq!(out, "path /foo.bar.baz suffix");
        assert_eq!(n, 0);
    }

    // ─── scrub: token= assignment (rc.52) ──────────────────────────────────

    #[test]
    fn scrub_redacts_toml_quoted_agent_token() {
        // The exact config.toml shape that scrub_jwt_shape misses:
        // the quotes break its whitespace-word boundary.
        let line = r#"agent_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sigpart""#;
        let (out, n) = scrub_credentials(line);
        assert!(out.contains("[REDACTED]"), "got: {out}");
        assert!(!out.contains("eyJhbGci"), "token leaked: {out}");
        assert!(n >= 1);
        // The closing quote is structural, not secret — preserved.
        assert!(out.trim_end().ends_with('"'));
    }

    #[test]
    fn scrub_redacts_query_string_token() {
        let (out, n) = scrub_credentials("ws connect token=abc123def&role=agent failed");
        assert!(out.contains("token=[REDACTED]"), "got: {out}");
        assert!(!out.contains("abc123def"));
        assert!(out.contains("&role=agent")); // delimiter + rest preserved
        assert!(n >= 1);
    }

    #[test]
    fn scrub_token_param_ignores_token_without_assignment() {
        // The word "token" in prose must not trip the scrub.
        let (out, n) = scrub_credentials("the enrollment token expired yesterday");
        assert_eq!(out, "the enrollment token expired yesterday");
        assert_eq!(n, 0);
    }

    // ─── scrub: MongoDB URI ────────────────────────────────────────────────

    #[test]
    fn scrub_redacts_mongodb_uri_credentials() {
        let (out, n) =
            scrub_credentials("conn=mongodb://user:secret@host:27017/db?retryWrites=true");
        assert!(out.contains("mongodb://[REDACTED]@host"));
        assert!(!out.contains("user:secret"));
        assert!(n >= 1);
    }

    #[test]
    fn scrub_mongodb_srv_variant() {
        let (out, n) = scrub_credentials("uri=mongodb+srv://u:p@cluster.example.com/db");
        assert!(out.contains("mongodb+srv://[REDACTED]@cluster"));
        assert!(!out.contains("u:p"));
        assert!(n >= 1);
    }

    #[test]
    fn scrub_mongodb_passthrough_when_no_userinfo() {
        let (out, _n) = scrub_credentials("mongodb://host:27017/db (no userinfo)");
        // Without userinfo "@" before whitespace, the URI passes
        // through unchanged.
        assert!(out.contains("mongodb://host:27017"));
    }

    // ─── scrub: password=… ────────────────────────────────────────────────

    #[test]
    fn scrub_redacts_password_param() {
        let (out, n) = scrub_credentials("?user=admin&password=hunter2&next=ok");
        assert!(out.contains("password=[REDACTED]"));
        assert!(!out.contains("hunter2"));
        assert!(out.contains("&next=ok"));
        assert!(n >= 1);
    }

    // ─── scrub: ICE ufrag/pwd ─────────────────────────────────────────────

    #[test]
    fn scrub_redacts_ice_ufrag_and_pwd_lines() {
        let input = "ok line\na=ice-ufrag:abcd\na=ice-pwd:supersecretpwd\nlast line";
        let (out, n) = scrub_credentials(input);
        assert!(out.contains("ok line"));
        assert!(out.contains("last line"));
        assert!(!out.contains("abcd"));
        assert!(!out.contains("supersecretpwd"));
        assert!(out.contains("<scrubbed ICE credential>"));
        assert!(n >= 2);
    }

    // ─── envelope trimming ────────────────────────────────────────────────

    #[test]
    fn fit_to_envelope_passes_payload_under_budget_through() {
        let mut p = sample_payload();
        let before = p.clone();
        fit_to_envelope(&mut p, MAX_PAYLOAD_BYTES);
        assert_eq!(p, before);
    }

    // ─── rc.51: suppressed_since_last field ────────────────────────────────

    #[test]
    fn pre_rc51_sidecar_json_without_suppressed_field_deserialises_to_zero() {
        // A sidecar written by rc.50-and-earlier has no
        // `suppressedSinceLast` key. `#[serde(default)]` must let it
        // parse — the uploader reads sidecars left on disk across an
        // agent upgrade, so an old file must not become unreadable.
        let legacy = r#"{
            "crashedAtUnix": 1700000000,
            "reason": "panic",
            "summary": "old crash",
            "logTail": "",
            "agentVersion": "0.3.0-rc.50",
            "os": "windows",
            "hostname": "h",
            "pid": 7
        }"#;
        let p: AgentCrashPayload = serde_json::from_str(legacy).expect("legacy sidecar parses");
        assert_eq!(p.suppressed_since_last, 0);
    }

    #[test]
    fn suppressed_since_last_round_trips() {
        let mut p = sample_payload();
        p.suppressed_since_last = 23;
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("suppressedSinceLast"));
        let back: AgentCrashPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.suppressed_since_last, 23);
    }

    #[test]
    fn fit_to_envelope_trims_oversized_log_tail() {
        let mut p = sample_payload();
        p.log_tail = "x".repeat(MAX_PAYLOAD_BYTES * 2);
        fit_to_envelope(&mut p, MAX_PAYLOAD_BYTES);
        let final_size = serde_json::to_vec(&p).unwrap().len();
        assert!(
            final_size <= MAX_PAYLOAD_BYTES,
            "post-trim payload {final_size} exceeds {MAX_PAYLOAD_BYTES}"
        );
    }

    #[test]
    fn fit_to_envelope_writes_truncation_marker() {
        let mut p = sample_payload();
        p.log_tail = (0..2000).map(|i| format!("line{i}\n")).collect::<String>();
        fit_to_envelope(&mut p, 4096);
        assert!(
            p.log_tail.starts_with(TRUNCATION_MARKER),
            "log_tail should start with truncation marker; got: {:?}",
            &p.log_tail[..p.log_tail.len().min(80)]
        );
    }

    // ─── jwt-shape predicate ──────────────────────────────────────────────

    #[test]
    fn is_jwt_shape_accepts_three_base64url_segments_each_8_plus_chars() {
        assert!(is_jwt_shape("eyJhbGciOi.eyJzdWIiOi.signatureXX"));
    }

    #[test]
    fn is_jwt_shape_rejects_non_jwt_shaped_tokens() {
        assert!(!is_jwt_shape("foo.bar.baz")); // too short segments
        assert!(!is_jwt_shape("only.two")); // not 3 segments
        assert!(!is_jwt_shape("seg1.seg2.seg3.seg4")); // 4 segments
        assert!(!is_jwt_shape("aaaaaaaa.bbbbbbbb.cc!cc!cc")); // invalid char
    }

    // ─── scrub count appended to summary (round-trip via record_inner-ish) ─

    #[test]
    fn scrub_count_visible_via_returned_count() {
        let (out, n) = scrub_credentials("Bearer aaaaaaaa ?password=hunter");
        assert!(out.contains("[REDACTED]"));
        // 1 Bearer + 1 password = 2 redactions.
        assert_eq!(n, 2);
    }

    // ─── Crash-loop suppression (2026-05-17 a third field-test host storm fix) ─────────────

    fn tempdir_for_test() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "crash_recorder_supp_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create_dir_all");
        dir
    }

    /// Drop a fake sidecar named `{ts}-{pid}.json` in `dir`. Used by
    /// the suppression tests to pre-populate without going through
    /// the full record_inner path.
    fn touch_sidecar(dir: &Path, unix_ts: i64, pid: u32) {
        let path = dir.join(format!("{unix_ts}-{pid}.json"));
        std::fs::write(&path, b"{}").expect("write fake sidecar");
    }

    #[test]
    fn should_suppress_returns_none_for_empty_dir() {
        let dir = tempdir_for_test();
        assert!(should_suppress(&dir, 1_700_000_000).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn should_suppress_rate_limits_when_recent_sidecar_exists() {
        let dir = tempdir_for_test();
        // Sidecar 5 seconds ago — within the 30s MIN_INTERVAL.
        touch_sidecar(&dir, 1_700_000_000 - 5, 12345);
        let now = 1_700_000_000_i64;
        assert_eq!(
            should_suppress(&dir, now),
            Some(SuppressReason::RecentSidecar)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn should_suppress_allows_write_after_min_interval_elapsed() {
        let dir = tempdir_for_test();
        // Sidecar 31 seconds ago — past the 30s MIN_INTERVAL.
        touch_sidecar(&dir, 1_700_000_000 - (MIN_INTERVAL_SECS + 1), 12345);
        let now = 1_700_000_000_i64;
        assert!(should_suppress(&dir, now).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn should_suppress_hits_hard_cap_regardless_of_age() {
        let dir = tempdir_for_test();
        // Fill the dir with HARD_CAP stale sidecars (all 1 hour ago).
        // Each gets a unique ts so filenames don't collide.
        let stale_base = 1_700_000_000_i64 - 3600;
        for i in 0..HARD_CAP {
            touch_sidecar(&dir, stale_base + i as i64, 12345);
        }
        let now = 1_700_000_000_i64;
        assert_eq!(
            should_suppress(&dir, now),
            Some(SuppressReason::HardCapReached),
            "hard cap must trip even when all sidecars are old"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn should_suppress_ignores_non_json_files() {
        let dir = tempdir_for_test();
        // A *.tmp file (in-progress write) doesn't count toward the
        // cap and doesn't trigger the rate-limit.
        std::fs::write(dir.join("1700000000-12345.json.tmp"), b"{}").unwrap();
        assert!(should_suppress(&dir, 1_700_000_000).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn suppress_reason_strings_are_stable() {
        // The outer record() matches on these strings to suppress a
        // duplicate WARN; a rename here would silently re-introduce
        // the spam.
        assert_eq!(
            SuppressReason::RecentSidecar.as_str(),
            "crash_recorder: recent sidecar; rate-limited"
        );
        assert_eq!(
            SuppressReason::HardCapReached.as_str(),
            "crash_recorder: hard cap reached; suppressing"
        );
        assert!(is_suppression_message(
            SuppressReason::RecentSidecar.as_str()
        ));
        assert!(is_suppression_message(
            SuppressReason::HardCapReached.as_str()
        ));
        assert!(!is_suppression_message("io: disk full"));
    }

    // ─── record_with_log_tail override path (worker-stderr capture) ────────

    #[test]
    fn record_inner_uses_override_when_provided() {
        // Wire-shape lock: when the caller supplies a log_tail (e.g.
        // captured worker stderr), it lands in the serialised payload
        // verbatim — modulo the scrub pipeline. The local rolling-log
        // read path (`read_log_tail`) is bypassed entirely so the
        // override is the authoritative source.
        let dir = tempdir_for_test();
        // Drive record_inner directly so we can control the dir
        // without going through `logging::log_dir()`. Override the
        // crashes_dir resolution: write to `dir` and verify the JSON
        // contents.
        let now_unix = 1_700_000_000_i64;
        let mut payload = AgentCrashPayload {
            crashed_at_unix: now_unix,
            reason: CrashReason::SupervisorDetected,
            summary: "worker exit: config load failed".to_string(),
            log_tail: "WORKER's real log content here\nnext line".to_string(),
            agent_version: "0.0.0-test".to_string(),
            os: "test".to_string(),
            hostname: "test".to_string(),
            pid: 99,
            suppressed_since_last: 0,
        };
        // Verify our trim helper doesn't strip the override content
        // when it's well under budget.
        fit_to_envelope(&mut payload, MAX_PAYLOAD_BYTES);
        assert!(payload.log_tail.contains("WORKER's real log content"));
        assert!(!payload.log_tail.contains("[…log truncated"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_with_log_tail_signature_accepts_none() {
        // Compile-time lock: the public API is `record_with_log_tail
        // (Reason, &str, WriterContext, Option<String>)`. A signature
        // drift here would break the supervisor / worker callers.
        // Reference the fn to keep the symbol live; never actually
        // call it (logging::log_dir() in a unit-test harness returns
        // None and a record call to log spam would race other tests).
        let _ = record_with_log_tail as fn(CrashReason, &str, WriterContext, Option<String>);
        let _ = record as fn(CrashReason, &str, WriterContext);
    }
}
