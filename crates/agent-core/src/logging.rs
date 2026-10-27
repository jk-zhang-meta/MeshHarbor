// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR-BEGIN
// Two survivors, both narrowed by FR-46 P2c. The `roomler-agent.log*` prefix is no
// longer READ — measured first: no such file exists on any reachable host, against a
// control of 5-30 current log files each — but RETENTION still matches it, so a host
// that turns one up ages it out instead of leaking it forever. The `roomler_agent`
// tracing target is gone from all four SHIPPED specs (they already carried
// `roomlerd=info` beside it, so dropping it changed nothing), and
// `mirror_legacy_log_target` now serves only units ALREADY on disk in the field.
// INVARIANT: a retired name here must be one the daemon must still READ. If you
// add one that is not, that is a bug, not a new exemption. docs/fr/FR-21
//! Persistent file logging + panic hook.
//!
//! Stdout output is preserved for foreground / interactive runs; a daily-
//! rolling file appender writes everything to
//! `<data-local-dir>/logs/roomlerd.log[.YYYY-MM-DD]` so a Scheduled-
//! Task / systemd / launchd-supervised agent (where stdout is `/dev/null`)
//! still leaves a forensic trail.
//!
//! P3d Slice B renamed the daemon (`roomler-agent` -> `roomlerd`); the log
//! basename moved to match. Old rolled `roomler-agent.log*` files on an
//! upgraded host stay readable — [`active_log_path`] and [`prune_old_logs_at`]
//! (and `logs_fetch`) accept BOTH prefixes.
//!
//! The log DIR is resolved by `appdirs` (new-then-old segment). On a fresh
//! Windows install that's `%LOCALAPPDATA%\roomler\roomler\data\logs\`; a
//! pre-rename host keeps `...\roomler\roomler-agent\data\logs\`. Linux:
//! `~/.local/share/meshharbor/logs/` (or `.../roomler-agent/logs/` on an upgraded
//! host). macOS: `~/Library/Application Support/live.roomler.roomler/logs/`.
//!
//! A process-wide panic hook captures the message + backtrace and writes
//! it synchronously to `<log_dir>/panic-<pid>-<unix_ts>.log` *before*
//! delegating to the previous hook. The sync write is the belt-and-braces
//! against the non-blocking appender's worker thread not draining the
//! queue before the OS reaps a panicking process.
//!
//! Init is idempotent (a second call is a no-op) so test harness setup
//! that calls `init()` repeatedly doesn't panic on subscriber re-install.

use std::backtrace::Backtrace;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::logs_upload::{LogLine, LogUploadLayer};

/// Holds the non-blocking appender's worker thread alive for the
/// process lifetime. Dropping it stops the writer thread, which would
/// silently drop in-flight log lines.
static GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// Resolved log directory, exposed for diagnostics (the `panic` /
/// `service status` paths surface it to the operator).
static LOG_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Holds the consumer end of the log-upload channel after [`init`]
/// runs. [`take_log_upload_receiver`] consumes it (one-shot) so
/// `main.rs` can spawn the uploader task once config is loaded. If
/// the receiver is never claimed, the layer continues to capture
/// events into the channel until it fills up + drops oldest (cap
/// 10 000 lines).
static LOG_UPLOAD_RX: OnceLock<Mutex<Option<mpsc::Receiver<LogLine>>>> = OnceLock::new();

/// Days to retain rolling log + panic files. Anything older than this
/// is pruned on startup (one-shot, not a background task).
const KEEP_DAYS: u64 = 14;

/// S1b — service-mode log routing. The machine-global `service-logs`
/// dir has been ADVERTISED by the desktop app since M1 but nothing ever
/// wrote there: `ProjectDirs` resolves the SCM host / SystemContext
/// worker into the SYSTEM profile
/// (`C:\Windows\System32\config\systemprofile\…`), invisible to
/// operators. When a role is set BEFORE [`init`], the file appender
/// writes into `%PROGRAMDATA%\roomler\<segment>\service-logs` instead,
/// with a per-role basename so the host and the worker (both possibly
/// live at once) never contend for one rolling file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceLogRole {
    /// The SCM service host process (`meshharbord service-run`).
    Host,
    /// The SystemContext (LocalSystem) worker.
    Worker,
    /// Track A — the session-independent network daemon (`roomlerd netd`,
    /// session 0). Own basename: up to THREE SYSTEM processes may log at
    /// once (host + worker + netd).
    Netd,
}

static SERVICE_ROLE: OnceLock<ServiceLogRole> = OnceLock::new();

/// Route this process's file logs into the machine-global
/// `service-logs` dir. Call BEFORE [`init`]; later calls are no-ops.
pub fn set_service_logging(role: ServiceLogRole) {
    let _ = SERVICE_ROLE.set(role);
}

/// The rolling-log basename for this process. The Host gets its own
/// (`roomlerd-service.log`) so two SYSTEM processes never append the
/// same daily file; everything else keeps `roomlerd.log`.
fn log_basename() -> &'static str {
    match SERVICE_ROLE.get() {
        Some(ServiceLogRole::Host) => "roomlerd-service.log",
        Some(ServiceLogRole::Netd) => "roomlerd-netd.log",
        _ => "roomlerd.log",
    }
}

/// Mirror a legacy `roomler_agent=<level>` directive onto `roomlerd=<level>`.
///
/// FR-21 P2a renamed the daemon LIB `roomler_agent` -> `roomlerd`, and a tracing
/// target IS the crate name — so every `RUST_LOG` that names the old target stopped
/// matching the daemon's own events the moment the rename shipped. That is not a
/// theoretical concern: five places set an explicit override that BEATS the dual
/// default above, three of them shipped units already on disk in the field
/// (`packaging/linux/{roomler,roomlerd}.service`, `com.roomler.agent.plist`) plus the
/// two units `service.rs` generates. A host whose unit is not rewritten would keep
/// running and log nothing but `warn` from the daemon — a silent, fleet-wide
/// observability blackout with no error anywhere.
///
/// So the new target is ADDED rather than substituted: an operator who deliberately
/// set `roomler_agent=debug` gets `roomlerd=debug` too, and anyone already naming
/// `roomlerd` is left alone. Directives for other targets, and the bare global level,
/// pass through untouched.
///
// RETIRED-NAME-ANCHOR(2): `roomler_agent` is the retired target this exists to keep
// working. Deleting it re-creates the blackout described above.
fn mirror_legacy_log_target(spec: &str) -> String {
    const LEGACY: &str = "roomler_agent";
    const CURRENT: &str = "roomlerd";
    if !spec.contains(LEGACY) {
        return spec.to_string();
    }
    let mut out: Vec<String> = Vec::new();
    let mut saw_current = spec
        .split(',')
        .any(|d| d.trim().split('=').next().map(str::trim) == Some(CURRENT));
    for directive in spec.split(',') {
        out.push(directive.to_string());
        if saw_current {
            continue;
        }
        let (target, level) = match directive.split_once('=') {
            Some((t, l)) => (t.trim(), Some(l.trim())),
            // A bare word is a global level (`info`), not a target directive.
            None => (directive.trim(), None),
        };
        if target == LEGACY {
            out.push(match level {
                Some(l) => format!("{CURRENT}={l}"),
                None => CURRENT.to_string(),
            });
            saw_current = true;
        }
    }
    out.join(",")
}

/// Initialise tracing subscribers. Always installs a stdout layer; adds
/// a daily-rolling file layer + panic hook when the platform log dir
/// is writeable. Infallible — file logging failure falls back to
/// stdout-only without erroring out the agent (the agent's signaling
/// loop is the load-bearing path; logging is observability, not
/// correctness).
pub fn init() {
    if GUARD.get().is_some() {
        return;
    }

    // Default filter. `RUST_LOG` (env, or the SCM service Environment
    // block for the SystemContext service) overrides wholesale when
    // set. The fallback keeps `roomler_agent` at info + everything
    // else at warn, with ONE addition: `tunnel_core=info`.
    //
    // rc.74: `tunnel_core=info` surfaces the per-flow throughput
    // logger (`tunnel flow throughput (2s window) …` + the
    // flow-closed totals) added in rc.66. Those live in the
    // `tunnel_core` target, so under the old `roomler_agent=info,warn`
    // default they were filtered out of BOTH the on-disk rolling log
    // AND the centralized upload layer — invisible unless an operator
    // hand-set `RUST_LOG`. The throughput lines are low-volume (one
    // per active flow per 2 s, only when bytes moved) and are exactly
    // the signal we need to diagnose tunnel stalls remotely via the
    // admin-UI log viewer, so they belong on by default. Everything
    // else in `tunnel_core` is debug/trace and stays suppressed; the
    // chatty `webrtc_sctp` / `webrtc_ice` targets stay at warn.
    let env_filter = std::env::var("RUST_LOG")
        .ok()
        .map(|spec| EnvFilter::new(mirror_legacy_log_target(&spec)))
        .unwrap_or_else(|| {
            // S1b follow-up: `roomlerd=info` — events emitted from the BIN
            // (target = the binary crate name) were silently capped at warn,
            // hiding the migration notes + DPI/timer diagnostics the code
            // clearly intended to be visible.
            EnvFilter::new("roomler_agent=info,roomlerd=info,tunnel_core=info,warn")
        })
        // rc.181 — silence the `turn` crate's periodic refresh-failure warns
        // (`refresh allocation/permissions failed`, target `turn::client::relay_conn`).
        // Now that the overlay re-allocates a dead relay carrier on the send-error
        // signal (wg.rs `Carrier::dead` → `sweep_carrier_health`), these are
        // transient noise — one every ~5–10 min per corp-VPN host — and they
        // dominate the error/warn-biased agent_logs upload. Appended
        // UNCONDITIONALLY (even when the SCM service sets `RUST_LOG` wholesale) so
        // it lands fleet-wide on the next binary, not just fresh installs. The
        // sweep's own `relay carrier … — re-allocating` warn is the actionable
        // signal that replaces them.
        .add_directive(
            "turn::client::relay_conn=error"
                .parse()
                .expect("static EnvFilter directive is valid"),
        )
        // FR-110 — each carrier socket's granted buffer sizes, said once per
        // bind (startup and plane rebuilds: a handful of lines a day). On
        // Windows nothing like `ss -m` exists, so the line is the only evidence
        // of the size. The packaged Linux units set `RUST_LOG=roomlerd=info,warn`,
        // which drops `tunnel_core` INFO, so this is appended UNCONDITIONALLY,
        // like the directive above.
        .add_directive(
            "tunnel_core::overlay::sockbuf=info"
                .parse()
                .expect("static EnvFilter directive is valid"),
        );

    let stdout = fmt::layer().with_target(false).compact();

    // rc.58 — log-upload layer. Captures every tracing event into an
    // mpsc channel; `main.rs` claims the receiver via
    // [`take_log_upload_receiver`] and spawns the uploader task once
    // config is loaded. If the receiver is never claimed (e.g. config
    // load fails), the channel fills + drops oldest with no impact on
    // the on-disk rolling log.
    let (upload_layer, upload_rx) = LogUploadLayer::new();
    let _ = LOG_UPLOAD_RX.set(Mutex::new(Some(upload_rx)));

    let dir = resolve_log_dir();
    let _ = LOG_DIR.set(dir.clone());

    if let Some(d) = dir.as_deref()
        && std::fs::create_dir_all(d).is_ok()
    {
        prune_old_logs(d, KEEP_DAYS);
        // P3d Slice B: write under the new `roomlerd.log` basename
        // (S1b: `roomlerd-service.log` for the SCM host — see
        // [`ServiceLogRole`]).
        let appender = tracing_appender::rolling::daily(d, log_basename());
        let (nb, guard) = tracing_appender::non_blocking(appender);
        let _ = GUARD.set(guard);
        let file = fmt::layer()
            .with_writer(nb)
            .with_target(false)
            .with_ansi(false);
        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(stdout)
            .with(file)
            .with(upload_layer)
            .try_init();
        install_panic_hook(d.to_path_buf());
    } else {
        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(stdout)
            .with(upload_layer)
            .try_init();
        // No log dir → no panic hook. Stdout-only is the right
        // fallback for cargo-test and ad-hoc `cargo run` from a
        // checkout where `directories` couldn't resolve a home.
    }
}

/// Claim the consumer end of the log-upload channel. Returns `None`
/// if [`init`] hasn't run yet OR the receiver has already been taken
/// — one-shot semantics so we don't have two parallel uploaders
/// fighting for the same channel.
pub fn take_log_upload_receiver() -> Option<mpsc::Receiver<LogLine>> {
    let lock = LOG_UPLOAD_RX.get()?;
    lock.lock().ok()?.take()
}

/// Path of the log directory, if persistent file logging is active.
/// Returns `None` when the platform doesn't expose a data dir or
/// `init()` hasn't run yet.
pub fn log_dir() -> Option<PathBuf> {
    LOG_DIR.get().cloned().flatten()
}

/// FR-97 P6e (#1538) — say one line on stderr, and never panic doing it.
///
/// `eprintln!` PANICS when the write fails, and a daemon's stderr is a sink it
/// does not own: launchd's `StandardErrorPath` file, journald, a supervisor's
/// pipe, a terminal that has since closed. On 0.4.93 a Mac's agent died exactly
/// there: the single-instance lock's "already running" line hit a failing
/// stderr, and a duplicate start that should have left quietly became a crash.
/// A line the daemon prints itself goes through here instead: losing the line
/// beats losing the process. On the watchdog's paths a panic would also lose
/// the forced exit the line announces.
pub fn say_on_stderr(msg: impl std::fmt::Display) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr().lock(), "{msg}");
}

/// Path of TODAY's rolling log file, if file logging is active.
/// Used by `crash_recorder::record` to attach a `log_tail` to crash
/// sidecars. Returns `None` when `init()` hasn't run yet OR no log
/// dir resolved (test harness / no-home environment).
///
/// The path is computed deterministically from the rolling
/// appender's daily-rotation convention: `<log_dir>/roomlerd.log.YYYY-MM-DD`
/// for archived days; `<log_dir>/roomlerd.log` is the symlink-ish "current"
/// name on some platforms but in practice tracing-appender writes to the dated
/// name from the very first line.
///
/// P3d Slice B: probe the new `roomlerd.log[.date]` basenames first, then fall
/// back to the legacy `roomler-agent.log[.date]` so an upgraded host whose most
/// recent rolled file predates the rename is still found.
pub fn active_log_path() -> Option<PathBuf> {
    let dir = log_dir()?;
    let today = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Format unix seconds → YYYY-MM-DD without pulling chrono.
    // tracing-appender uses UTC by default; mirror that.
    let date = format_utc_date(today);
    // Own basename first so the Host process's crash sidecars attach the
    // Host log tail; then the standard + legacy names.
    let mut bases = vec![log_basename()];
    // FR-46 P2c: the legacy rolled-log name is gone from the READ paths. Measured
    // first — no `roomler-agent.log*` exists on any reachable host, against a control
    // of 5-30 current log files per host. Retention below still matches it, so a host
    // that turns one up ages it out rather than leaking it forever.
    for b in ["roomlerd.log", "roomlerd-service.log"] {
        if !bases.contains(&b) {
            bases.push(b);
        }
    }
    for base in bases {
        let dated = dir.join(format!("{base}.{date}"));
        if dated.exists() {
            return Some(dated);
        }
        let plain = dir.join(base);
        if plain.exists() {
            return Some(plain);
        }
    }
    None
}

/// Format a unix-seconds value as `YYYY-MM-DD` in UTC. Pure +
/// no-dep so the agent build doesn't pull chrono just for this.
/// Algorithm = days-since-epoch + civil-from-days (Howard Hinnant).
fn format_utc_date(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // From Howard Hinnant's "chrono-Compatible Low-Level Date
    // Algorithms" — converts days-since-1970-01-01 to (year, month,
    // day). Pure integer arithmetic.
    let z = z + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// S2 — resolve a `TailLog` source name to a concrete log file, from
/// THIS process's perspective (the daemon serves the verb, so `daemon`
/// is its own active rolling log):
/// * `daemon`  — [`active_log_path`] (role-correct: a SystemContext
///   worker resolves its service-logs file);
/// * `service` — the newest SCM-host/service file in the machine-global
///   `service-logs` dir (Windows; elsewhere = the daemon log);
/// * `panic`   — the newest `panic-*` dump across the log dirs.
///
/// `None` = the source has no file yet (never errored, service never
/// logged) or the name is unknown — the verb maps both to a clean error.
pub fn tail_source_path(source: &str) -> Option<PathBuf> {
    match source {
        // `or_else`: in a process that never ran `init()` (the tray's
        // direct-file fallback) `active_log_path` is None — probe the
        // default dir for the newest daemon rolling file instead.
        "daemon" => active_log_path().or_else(|| {
            let dir = resolve_log_dir()?;
            newest_file_matching(&[dir], |name| name.starts_with("roomlerd.log"))
        }),
        "service" => {
            #[cfg(target_os = "windows")]
            {
                let dir = crate::appdirs::machine_global_dir().join("service-logs");
                newest_file_matching(&[dir], |name| {
                    name.starts_with("roomlerd-service.log") || name.starts_with("roomlerd.log")
                })
            }
            #[cfg(not(target_os = "windows"))]
            {
                // No SCM split off Windows — the daemon log IS the service log.
                active_log_path()
            }
        }
        "panic" => {
            let mut dirs: Vec<PathBuf> = Vec::new();
            if let Some(d) = log_dir().or_else(resolve_log_dir) {
                dirs.push(d);
            }
            #[cfg(target_os = "windows")]
            dirs.push(crate::appdirs::machine_global_dir().join("service-logs"));
            newest_file_matching(&dirs, |name| name.starts_with("panic-"))
        }
        _ => None,
    }
}

/// Newest (by mtime) plain file across `dirs` whose basename satisfies
/// `pred`. Missing dirs are skipped; empty result = `None`.
fn newest_file_matching(dirs: &[PathBuf], pred: impl Fn(&str) -> bool) -> Option<PathBuf> {
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for dir in dirs {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !pred(&name) {
                continue;
            }
            let Ok(md) = e.metadata() else { continue };
            if !md.is_file() {
                continue;
            }
            let mt = md.modified().unwrap_or(UNIX_EPOCH);
            if best.as_ref().is_none_or(|(t, _)| mt > *t) {
                best = Some((mt, e.path()));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// S2 — read the last ≤`cap` bytes of `path` as lossy UTF-8, starting on
/// a line boundary when the cut landed mid-line. Returns the file's
/// TOTAL size alongside (the client polls it to detect growth).
pub fn read_tail(path: &Path, cap: u64) -> std::io::Result<(u64, String)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let size = f.metadata()?.len();
    let start = size.saturating_sub(cap);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::with_capacity(cap.min(size) as usize);
    f.read_to_end(&mut buf)?;
    let mut content = String::from_utf8_lossy(&buf).into_owned();
    if start > 0
        && let Some(nl) = content.find('\n')
    {
        content.drain(..=nl);
    }
    Ok((size, content))
}

/// Compute the default log directory PATH — purely, without the `LOG_DIR`
/// `OnceLock` (which is only set by [`init`], so it's `None` in any process
/// that didn't run the agent's logging setup, e.g. the tray). The tray uses
/// this so "Open Logs Folder" resolves a real path instead of failing.
///
/// S1b: with a [`ServiceLogRole`] set, resolves to the machine-global
/// `service-logs` dir instead of the per-profile data dir.
pub fn resolve_log_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    if SERVICE_ROLE.get().is_some() {
        return Some(crate::appdirs::machine_global_dir().join("service-logs"));
    }
    let dirs = crate::appdirs::project_dirs()?;
    Some(dirs.data_local_dir().join("logs"))
}

/// Delete rolling-log + panic files in `dir` older than `keep_days`.
/// Best-effort; any I/O error is swallowed so a permission glitch
/// doesn't block startup.
fn prune_old_logs(dir: &Path, keep_days: u64) {
    let Some(cutoff) = SystemTime::now().checked_sub(Duration::from_secs(keep_days * 86_400))
    else {
        return;
    };
    prune_old_logs_at(dir, cutoff);
}

/// Same as [`prune_old_logs`] but takes the cutoff as a parameter so
/// tests can drive it deterministically. Files matching one of our
/// prefixes (`roomlerd.log` / legacy `roomler-agent.log` rolling files,
/// `panic-` panic dumps) and with mtime older than `cutoff` are unlinked.
/// Anything else in the directory is left alone — the operator may have
/// stashed notes there.
///
/// P3d Slice B: prunes BOTH the new `roomlerd.log*` files and the legacy
/// `roomler-agent.log*` files so an upgraded host's old rolled logs age out
/// under the same retention policy instead of accreting forever.
fn prune_old_logs_at(dir: &Path, cutoff: SystemTime) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(mtime) = meta.modified() else {
            continue;
        };
        let name = entry.file_name();
        let lossy = name.to_string_lossy();
        let is_ours = lossy.starts_with("roomlerd.log")
            || lossy.starts_with("roomlerd-service.log")
            // RETIRED-NAME-ANCHOR: legacy rolled logs must still AGE OUT; dropping this
            // leaks them forever on an upgraded host. See docs/fr/FR-21.
            || lossy.starts_with("roomler-agent.log")
            || lossy.starts_with("panic-");
        if is_ours && mtime < cutoff {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn install_panic_hook(log_dir: PathBuf) {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let bt = Backtrace::force_capture();
        let pid = std::process::id();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()));
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        let content = format_panic(payload, location.as_deref(), &bt.to_string(), pid, ts);
        let path = log_dir.join(format!("panic-{pid}-{ts}.log"));
        // Sync write — we do not trust the non-blocking appender's
        // worker thread to flush before the process is reaped.
        let _ = std::fs::write(&path, &content);
        // Best-effort tracing emission too — usually flushes via the
        // WorkerGuard's Drop, but the sync file above is the source
        // of truth for post-mortem.
        tracing::error!(panic_log = %path.display(), "agent panicked; details written to disk");

        // Phase 1B: emit a JSON crash sidecar for the uploader to
        // ship to roomler.ai on next agent startup. The sidecar is
        // INDEPENDENT of the text dump above — even if the recorder
        // recursively panics inside its catch_unwind, the text dump
        // has already flushed to disk. Worker context: panic hook
        // always runs in the worker process.
        let summary = format!(
            "{} at {}",
            payload.unwrap_or("panic"),
            location.as_deref().unwrap_or("?"),
        );
        crate::crash_recorder::record(
            crate::crash_recorder::Reason::Panic,
            &summary,
            crate::crash_recorder::WriterContext::Worker,
        );

        prev(info);
    }));
}

/// Pure formatter for the panic-dump file. Extracted so the test
/// suite can lock the on-disk shape without having to manufacture a
/// real `PanicHookInfo` (the type's fields are private).
fn format_panic(
    payload: Option<&str>,
    location: Option<&str>,
    backtrace: &str,
    pid: u32,
    ts: u64,
) -> String {
    let mut buf = format!("--- panic at {ts} (pid {pid}) ---\n");
    if let Some(loc) = location {
        buf.push_str(&format!("location: {loc}\n"));
    }
    buf.push_str(&format!("payload: {}\n", payload.unwrap_or("<unknown>")));
    buf.push_str("backtrace:\n");
    buf.push_str(backtrace);
    if !backtrace.ends_with('\n') {
        buf.push('\n');
    }
    buf
}

#[cfg(test)]
mod tests {
    // ── FR-97 P6e (#1538): a line on a failing stderr is dropped, never a panic ──

    /// The child half of the test below, run by this test binary itself with
    /// its stderr on `/dev/full`, where every write fails (ENOSPC). It does
    /// nothing in an ordinary run.
    #[cfg(target_os = "linux")]
    #[test]
    fn stderr_child() {
        match std::env::var("ROOMLER_STDERR_CHILD").as_deref() {
            Ok("helper") => super::say_on_stderr("a line /dev/full refuses"),
            // The control: what the daemon's own lines did before.
            Ok("eprintln") => eprintln!("a line /dev/full refuses"),
            _ => {}
        }
    }

    /// `stderr_child` in a fresh test process whose stderr is `/dev/full`.
    #[cfg(target_os = "linux")]
    fn child_with_failing_stderr(mode: &str) -> std::process::ExitStatus {
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open /dev/full");
        std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "logging::tests::stderr_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ROOMLER_STDERR_CHILD", mode)
            .stdout(std::process::Stdio::null())
            .stderr(full)
            .status()
            .expect("run the test binary")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_line_on_a_failing_stderr_is_dropped_never_a_panic() {
        // The control first: on this stderr `eprintln!` does panic, so this
        // test can tell a fix from a stderr that never failed.
        assert!(
            !child_with_failing_stderr("eprintln").success(),
            "the control should panic on a stderr that refuses every write"
        );
        assert!(
            child_with_failing_stderr("helper").success(),
            "say_on_stderr must drop the line, not panic"
        );
    }

    // ── FR-21 P2a: the lib rename must not blank a deployed unit's logs ──

    #[test]
    fn legacy_log_target_is_mirrored_onto_the_new_one() {
        // Exactly what packaging/linux/meshharbord.service ships today.
        assert_eq!(
            mirror_legacy_log_target("roomler_agent=info,warn"),
            "roomler_agent=info,roomlerd=info,warn"
        );
        // And what service.rs generates.
        assert_eq!(
            mirror_legacy_log_target("roomler_agent=info,tunnel_core=info,warn"),
            "roomler_agent=info,roomlerd=info,tunnel_core=info,warn"
        );
    }

    #[test]
    fn the_operators_chosen_level_is_carried_over_not_defaulted() {
        // A hand-set `debug` must reach the renamed target, or the rename
        // silently downgrades exactly the person who asked for more detail.
        assert_eq!(
            mirror_legacy_log_target("roomler_agent=debug,webrtc=info"),
            "roomler_agent=debug,roomlerd=debug,webrtc=info"
        );
    }

    #[test]
    fn a_spec_already_naming_the_new_target_is_left_alone() {
        // Idempotence: the shim must not accumulate duplicates when the
        // shipped units are eventually rewritten to name both.
        let both = "roomler_agent=info,roomlerd=info,warn";
        assert_eq!(mirror_legacy_log_target(both), both);
        assert_eq!(
            mirror_legacy_log_target(&mirror_legacy_log_target(both)),
            both
        );
    }

    #[test]
    fn specs_without_the_legacy_target_pass_through_untouched() {
        for spec in [
            "info",
            "warn",
            "roomlerd=debug,warn",
            "tunnel_core=info,warn",
        ] {
            assert_eq!(mirror_legacy_log_target(spec), spec, "spec: {spec}");
        }
    }

    #[test]
    fn a_bare_legacy_target_with_no_level_still_mirrors() {
        assert_eq!(
            mirror_legacy_log_target("roomler_agent"),
            "roomler_agent,roomlerd"
        );
    }

    #[test]
    fn a_target_merely_containing_the_legacy_name_is_not_mistaken_for_it() {
        // `roomler_agent_core` starts with `roomler_agent`; a `starts_with`
        // or `contains` match would wrongly mirror it onto `roomlerd`.
        assert_eq!(
            mirror_legacy_log_target("roomler_agent_core=debug,warn"),
            "roomler_agent_core=debug,warn"
        );
    }

    use super::*;

    #[test]
    fn init_is_idempotent() {
        // Two calls in the same process must not panic. Subsequent
        // calls fall through the `GUARD.get().is_some()` early return.
        init();
        init();
    }

    #[test]
    fn read_tail_caps_and_starts_on_line_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        std::fs::write(&p, "first line\nsecond line\nthird line\n").unwrap();
        // Big cap → whole file, untouched.
        let (size, all) = read_tail(&p, 4096).unwrap();
        assert_eq!(size, 34);
        assert_eq!(all, "first line\nsecond line\nthird line\n");
        // Small cap that cuts mid-"second" → tail starts at "third".
        let (size, tail) = read_tail(&p, 15).unwrap();
        assert_eq!(size, 34);
        assert_eq!(tail, "third line\n");
        // Unknown tail source resolves to nothing (→ clean verb error).
        assert!(tail_source_path("nope").is_none());
    }

    #[test]
    fn newest_file_matching_picks_latest_and_skips_missing_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("panic-1.txt");
        let new = dir.path().join("panic-2.txt");
        std::fs::write(&old, "old").unwrap();
        std::fs::write(&new, "new").unwrap();
        let past = SystemTime::now() - Duration::from_secs(3600);
        // Force distinct mtimes (same-second writes are common on CI).
        let f = std::fs::File::options().append(true).open(&old).unwrap();
        f.set_modified(past).unwrap();
        drop(f);
        let got = newest_file_matching(
            &[dir.path().join("missing"), dir.path().to_path_buf()],
            |n| n.starts_with("panic-"),
        );
        assert_eq!(got.as_deref(), Some(new.as_path()));
    }

    #[test]
    fn format_panic_includes_all_fields() {
        let s = format_panic(
            Some("kapow"),
            Some("src/foo.rs:42:1"),
            "frame 0\nframe 1",
            1234,
            9_999,
        );
        assert!(s.starts_with("--- panic at 9999 (pid 1234) ---\n"));
        assert!(s.contains("location: src/foo.rs:42:1\n"));
        assert!(s.contains("payload: kapow\n"));
        assert!(s.contains("backtrace:\nframe 0\nframe 1\n"));
    }

    #[test]
    fn format_panic_uses_unknown_when_payload_missing() {
        let s = format_panic(None, None, "bt", 1, 1);
        assert!(s.contains("payload: <unknown>\n"));
        assert!(!s.contains("location: "));
    }

    #[test]
    fn prune_with_future_cutoff_drops_matching_files() {
        let tmp = tempfile::tempdir().unwrap();
        // New (roomlerd) + legacy (roomler-agent) rolling files must BOTH be
        // pruned (P3d Slice B both-name retention).
        let logd = tmp.path().join("roomlerd.log.2026-07-15");
        let logd_root = tmp.path().join("roomlerd.log");
        let log = tmp.path().join("roomler-agent.log.2026-04-29");
        let log_root = tmp.path().join("roomler-agent.log");
        let panic = tmp.path().join("panic-1234-100.log");
        let unrelated = tmp.path().join("readme.txt");
        for p in [&logd, &logd_root, &log, &log_root, &panic, &unrelated] {
            std::fs::write(p, b"x").unwrap();
        }
        // Cutoff 1 day in the future — every file's mtime is older.
        let future = SystemTime::now() + Duration::from_secs(86_400);
        prune_old_logs_at(tmp.path(), future);
        assert!(!logd.exists(), "new rolling log should be pruned");
        assert!(
            !logd_root.exists(),
            "new current rolling log should be pruned"
        );
        assert!(!log.exists(), "legacy rolling log should be pruned");
        assert!(
            !log_root.exists(),
            "legacy current rolling log should be pruned"
        );
        assert!(!panic.exists(), "panic dump should be pruned");
        assert!(unrelated.exists(), "unrelated files must be left alone");
    }

    #[test]
    fn prune_with_past_cutoff_keeps_everything() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("roomler-agent.log.2026-04-29");
        std::fs::write(&log, b"x").unwrap();
        // Cutoff 1 day in the past — every fresh file is newer.
        let past = SystemTime::now() - Duration::from_secs(86_400);
        prune_old_logs_at(tmp.path(), past);
        assert!(log.exists());
    }

    #[test]
    fn prune_handles_missing_directory_gracefully() {
        // No panic when the dir doesn't exist.
        let bogus = std::path::PathBuf::from("definitely/not/a/real/path/12345");
        prune_old_logs_at(&bogus, SystemTime::now());
    }
}
// RETIRED-NAME-ANCHOR-END
