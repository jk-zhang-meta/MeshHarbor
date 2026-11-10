// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! #1731 — the stall watchdog.
//!
//! A `meshharbor2` pod went completely silent twice in 9 h: not one log line,
//! `/health` unanswered, until the liveness probe killed it ~105 s later. A
//! kill takes the only evidence with it, and a runtime that makes no progress
//! cannot log why. So the evidence has to be taken by something that does not
//! need the runtime, and kept somewhere that outlives the container.
//!
//! - A **heartbeat** task on the runtime stamps an atomic every 500 ms.
//! - A plain OS **thread** looks every second. When the stamp is older than
//!   the threshold, it writes a dump, and while the stall lasts it adds a fresh
//!   sample every 20 s, so the dump shows whether the stuck threads move at all.
//! - A sample is written in stages, each one on disk before the next is
//!   attempted: the header (runtime metrics, the stdout/stderr pipe fill, memory,
//!   pressure and throttling), then every thread's `/proc` state (its syscall
//!   with arguments, its kernel wait channel), then stacks one thread at a time.
//!   Each stack is walked by the thread itself in a signal handler, because
//!   only it can walk its own stack without stopping the world. A thread that
//!   cannot answer (uninterruptible sleep, stopped) is not asked, and the whole
//!   sample has a stack budget, so a dump is never lost to a slow walk.
//! - The dump goes to a FILE, never to stdout or through `tracing`. A blocked
//!   stdout was #1731's cause (reproduced: the fmt layer wrote synchronously
//!   under the process-wide stdout lock). Logging is non-blocking now
//!   (`crate::logging`), but whatever stalls the runtime next may block the
//!   log as well, so the watchdog never depends on it. The next process reports
//!   any unreported dump at boot ([`report_previous_dumps`]), which puts it in
//!   plain `kubectl logs`.
//!
//! Linux only, which is production. Elsewhere [`start`] runs the heartbeat and
//! the watchdog, but a dump says stacks are not captured there.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How often the runtime proves it is alive.
const BEAT_EVERY: Duration = Duration::from_millis(500);
/// How often the watchdog thread looks.
const LOOK_EVERY: Duration = Duration::from_secs(1);
/// While a stall lasts, a fresh sample this often...
const RESAMPLE_EVERY: Duration = Duration::from_secs(20);
/// ...up to this many per stall. The liveness probe ends a stall ~105 s in.
const SAMPLES_PER_STALL: u32 = 4;
/// At most one stall dumped per this window. A lifetime cap could be spent on
/// spurious triggers (a debugger pause, a paused VM) before the real stall.
const DUMP_COOLDOWN: Duration = Duration::from_secs(10 * 60);
/// Dumps kept in the directory. The oldest reported ones go at boot first.
const KEEP_DUMPS: usize = 20;
/// The boot-time report logs at most this many lines of a dump.
const REPORT_LINES: usize = 60;
const DUMP_PREFIX: &str = "stall-";
const DUMP_SUFFIX: &str = ".txt";
/// Written next to a dump once a later process has reported it.
const REPORTED_SUFFIX: &str = ".reported";

#[derive(Debug, Clone)]
pub struct Config {
    /// How long the heartbeat may go unseen before it counts as a stall.
    pub threshold: Duration,
    /// Where dumps go. It has to outlive a container restart.
    pub dump_dir: PathBuf,
    /// Also write each sample to stderr (production: yes).
    pub echo_stderr: bool,
}

/// A running watchdog. Dropping this handle leaves it running, and production
/// never stops it; [`StallWatchdog::stop`] exists for tests.
pub struct StallWatchdog {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl StallWatchdog {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Has the heartbeat gone unseen for longer than `threshold`?
pub(crate) fn is_stalled(last_beat_ms: u64, now_ms: u64, threshold: Duration) -> bool {
    now_ms.saturating_sub(last_beat_ms) > threshold.as_millis() as u64
}

/// Set when the heartbeat task is dropped, i.e. when its runtime shuts down.
/// A shutdown is not a stall, and the watchdog must not outlive its runtime
/// just to dump it.
struct RuntimeGone(Arc<AtomicBool>);

impl Drop for RuntimeGone {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Start the heartbeat on `handle`'s runtime and the watchdog thread.
pub fn start(handle: &tokio::runtime::Handle, cfg: Config) -> std::io::Result<StallWatchdog> {
    #[cfg(target_os = "linux")]
    linux::install_handler()?;
    let origin = Instant::now();
    let beat = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let gone = Arc::new(AtomicBool::new(false));
    {
        let beat = beat.clone();
        let stop = stop.clone();
        let gone = RuntimeGone(gone.clone());
        handle.spawn(async move {
            let _gone = gone;
            let mut tick = tokio::time::interval(BEAT_EVERY);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            while !stop.load(Ordering::Acquire) {
                tick.tick().await;
                beat.store(origin.elapsed().as_millis() as u64, Ordering::Release);
            }
        });
    }
    let thread = {
        let handle = handle.clone();
        let stop = stop.clone();
        std::thread::Builder::new()
            .name("stall-watchdog".into())
            .spawn(move || watch(&handle, &cfg, origin, &beat, &stop, &gone))?
    };
    Ok(StallWatchdog {
        stop,
        thread: Some(thread),
    })
}

struct Stall {
    /// The last heartbeat before the stall, on the watchdog's clock.
    last_beat_ms: u64,
    dump: Option<PathBuf>,
    samples: u32,
    last_sample: Instant,
}

fn watch(
    handle: &tokio::runtime::Handle,
    cfg: &Config,
    origin: Instant,
    beat: &AtomicU64,
    stop: &AtomicBool,
    gone: &AtomicBool,
) {
    // Everything a dump needs that could itself block during a stall is read
    // now, while the process is healthy: the unwinder's and symbolizer's
    // one-time setup, and the executable's mapping (`/proc/self/maps` takes
    // the mm lock a thread stuck in reclaim may hold).
    #[cfg(target_os = "linux")]
    linux::warm_up();
    #[cfg(target_os = "linux")]
    let exe = linux::exe_mapping();
    #[cfg(not(target_os = "linux"))]
    let exe = String::new();
    let mut stall: Option<Stall> = None;
    let mut last_dump: Option<Instant> = None;
    while !stop.load(Ordering::Acquire) && !gone.load(Ordering::Acquire) {
        std::thread::sleep(LOOK_EVERY);
        let now = origin.elapsed().as_millis() as u64;
        let last = beat.load(Ordering::Acquire);
        if gone.load(Ordering::Acquire) {
            break;
        }
        if is_stalled(last, now, cfg.threshold) {
            match stall.as_mut() {
                None => {
                    if last_dump.is_some_and(|t| t.elapsed() < DUMP_COOLDOWN) {
                        continue;
                    }
                    last_dump = Some(Instant::now());
                    let mut out = DumpOut::create(&cfg.dump_dir);
                    sample(handle, &mut out, now - last, 1, &exe);
                    let dump = out.finish(cfg.echo_stderr);
                    stall = Some(Stall {
                        last_beat_ms: last,
                        dump,
                        samples: 1,
                        last_sample: Instant::now(),
                    });
                }
                Some(s)
                    if s.samples < SAMPLES_PER_STALL
                        && s.last_sample.elapsed() >= RESAMPLE_EVERY =>
                {
                    s.samples += 1;
                    s.last_sample = Instant::now();
                    let mut out = DumpOut::append_to(s.dump.clone());
                    sample(handle, &mut out, now - last, s.samples, &exe);
                    let _ = out.finish(cfg.echo_stderr);
                }
                Some(_) => {}
            }
        } else if let Some(s) = stall.take() {
            let lasted_ms = now.saturating_sub(s.last_beat_ms);
            let mut out = DumpOut::append_to(s.dump.clone());
            out.write(&format!(
                "\n=== recovered: the heartbeat resumed ~{lasted_ms} ms after the last beat before the stall ===\n"
            ));
            let _ = out.finish(false);
            // Log from a throwaway thread: whatever stalled the runtime may
            // still hold up the log, and this watchdog must be here for the
            // next stall either way.
            let dump = s.dump;
            let _ = std::thread::Builder::new()
                .name("stall-log".into())
                .spawn(move || {
                    tracing::error!(
                        stalled_ms = lasted_ms,
                        dump = ?dump,
                        "stall watchdog: the runtime stopped making progress and recovered on its own — the dump says what every thread was doing (#1731)"
                    );
                });
        }
    }
}

/// Where a sample goes, stage by stage: each stage is appended to the dump
/// file and synced before the next is attempted, so a sample that is cut
/// short (a kill, a walk that never returns) still leaves every stage before.
struct DumpOut {
    path: Option<PathBuf>,
    /// The same text, for the stderr copy.
    echo: String,
}

impl DumpOut {
    /// A new dump file. If the configured directory refuses, the temp dir: a
    /// dump that dies with the container still beats none if the stall
    /// resolves on its own (and its stderr copy lands in the log).
    fn create(dir: &Path) -> Self {
        let name = format!("{DUMP_PREFIX}{}{DUMP_SUFFIX}", unix_ms());
        for dir in [dir.to_path_buf(), std::env::temp_dir()] {
            let path = dir.join(&name);
            let created = std::fs::create_dir_all(&dir).and_then(|()| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
            });
            if created.is_ok() {
                return Self {
                    path: Some(path),
                    echo: String::new(),
                };
            }
        }
        Self {
            path: None,
            echo: String::new(),
        }
    }

    fn append_to(path: Option<PathBuf>) -> Self {
        Self {
            path,
            echo: String::new(),
        }
    }

    fn write(&mut self, text: &str) {
        if let Some(path) = &self.path
            && let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(path)
        {
            let _ = f.write_all(text.as_bytes());
            let _ = f.sync_data();
        }
        self.echo.push_str(text);
    }

    /// Copy the sample to stderr, from a throwaway thread: if the log pipe is
    /// what blocked, it blocks that thread and nothing else, and the text still
    /// lands in the log if the pipe ever drains.
    fn finish(self, echo_stderr: bool) -> Option<PathBuf> {
        if echo_stderr && !self.echo.is_empty() {
            let text = self.echo;
            let _ = std::thread::Builder::new()
                .name("stall-echo".into())
                .spawn(move || {
                    let _ = std::io::stderr().write_all(text.as_bytes());
                });
        }
        self.path
    }
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

fn sample(
    handle: &tokio::runtime::Handle,
    out: &mut DumpOut,
    heartbeat_age_ms: u64,
    n: u32,
    exe: &str,
) {
    let mut head = String::new();
    let _ = writeln!(head, "=== meshharbor stall dump (#1731), sample {n} ===");
    let _ = writeln!(head, "written_at_unix_ms: {}", unix_ms());
    let _ = writeln!(head, "heartbeat_age_ms: {heartbeat_age_ms}");
    let _ = writeln!(head, "server_version: {}", env!("CARGO_PKG_VERSION"));
    let m = handle.metrics();
    // `global_queue_depth` counts tasks woken from OUTSIDE the runtime (timers,
    // I/O, other threads) that no worker has picked up yet.
    let _ = writeln!(
        head,
        "tokio: workers={} alive_tasks={} global_queue_depth={}",
        m.num_workers(),
        m.num_alive_tasks(),
        m.global_queue_depth()
    );
    let _ = writeln!(head, "exe: {exe}");
    out.write(&head);
    #[cfg(target_os = "linux")]
    linux::sample_process(out);
    #[cfg(not(target_os = "linux"))]
    out.write("(thread stacks are captured on Linux only)\n");
    out.write(&format!("=== end of sample {n} ===\n"));
}

fn is_dump(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(DUMP_PREFIX) && n.ends_with(DUMP_SUFFIX))
}

fn reported_marker(dump: &Path) -> PathBuf {
    let mut name = dump.as_os_str().to_owned();
    name.push(REPORTED_SUFFIX);
    PathBuf::from(name)
}

/// The lines of a dump worth putting in the log: the header of every sample,
/// and every thread that is writing, in uninterruptible sleep, or stopped.
/// The whole dump stays in the file.
fn summarize(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| {
            l.starts_with("===")
                || l.starts_with("heartbeat_age_ms")
                || l.starts_with("tokio:")
                || l.starts_with("fd ")
                || l.starts_with("cgroup memory.events")
                || (l.starts_with("tid ")
                    && (l.contains("syscall=[write")
                        || l.contains(" state=D ")
                        || l.contains(" state=T ")))
        })
        .take(REPORT_LINES)
        .collect()
}

/// At boot: report every dump a previous process left and no process has
/// reported yet, then mark it. A stall normally ends in a liveness kill, so
/// this is where its dump first becomes visible, in the log of the container
/// that replaced it. Returns the dumps it reported.
///
/// The marker is written BEFORE anything is logged, and only a bounded
/// summary is logged: a report that could wedge on the log would otherwise
/// repeat on every boot.
pub fn report_previous_dumps(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dumps: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| is_dump(p))
        .collect();
    // The names embed the unix ms they were written at, so this is age order.
    dumps.sort();
    // Prune the oldest REPORTED ones first; an unreported dump goes only when
    // nothing else is left to prune.
    while dumps.len() > KEEP_DUMPS {
        let victim = dumps
            .iter()
            .position(|d| reported_marker(d).exists())
            .unwrap_or(0);
        let old = dumps.remove(victim);
        let _ = std::fs::remove_file(reported_marker(&old));
        let _ = std::fs::remove_file(&old);
    }
    let mut reported = Vec::new();
    for dump in &dumps {
        let marker = reported_marker(dump);
        if marker.exists() || std::fs::write(&marker, b"").is_err() {
            continue;
        }
        match std::fs::read_to_string(dump) {
            Ok(text) => {
                tracing::error!(
                    "stall watchdog: a previous process on this pod stalled (#1731). Summary of {} (the whole dump is in that file, `kubectl exec <pod> -- cat` it):\n{}",
                    dump.display(),
                    summarize(&text).join("\n")
                );
            }
            Err(e) => {
                tracing::warn!(dump = %dump.display(), error = %e, "stall watchdog: could not read a previous stall dump");
            }
        }
        reported.push(dump.clone());
    }
    reported
}

#[cfg(target_os = "linux")]
mod linux {
    use super::DumpOut;
    use std::fmt::Write as _;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    const MAX_FRAMES: usize = 64;
    /// How long a signalled thread gets to walk its own stack.
    pub(super) const ANSWER_WITHIN: Duration = Duration::from_millis(250);
    /// How long a walk that was claimed but not finished may still take.
    const WALK_GRACE: Duration = Duration::from_secs(1);
    /// All stack walks of one sample together.
    const STACK_BUDGET: Duration = Duration::from_secs(5);

    // One capture at a time. `STATE` packs a request id with its phase; the
    // handler has to CLAIM a request (armed → walking) before it may touch the
    // slots, and the watchdog either sees it done, or takes the request back
    // (armed → idle) before reusing them. A walk that was claimed and is still
    // running keeps the slots reserved.
    const IDLE: u64 = 0;
    const ARMED: u64 = 1;
    const WALKING: u64 = 2;
    const DONE: u64 = 3;
    const PHASE: u64 = 0b11;

    fn pack(request: u64, phase: u64) -> u64 {
        (request << 2) | phase
    }

    static INSTALLED: AtomicBool = AtomicBool::new(false);
    /// The thread asked to walk its stack. 0 = nobody.
    static TARGET: AtomicI32 = AtomicI32::new(0);
    static REQUEST: AtomicU64 = AtomicU64::new(0);
    static STATE: AtomicU64 = AtomicU64::new(0);
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    static FRAMES: [AtomicUsize; MAX_FRAMES] = [const { AtomicUsize::new(0) }; MAX_FRAMES];
    static CAPTURE: Mutex<()> = Mutex::new(());

    /// A real-time signal nothing else in this server uses (tokio registers
    /// only SIGINT/SIGTERM; the in-process mediasoup worker installs no
    /// handlers). Its default action terminates the process, which is why
    /// [`stack_of`] refuses to send it until the handler is installed.
    fn stack_signal() -> libc::c_int {
        libc::SIGRTMIN() + 5
    }

    pub(super) fn install_handler() -> std::io::Result<()> {
        if INSTALLED.load(Ordering::Acquire) {
            return Ok(());
        }
        // SAFETY: zeroed `sigaction`s are valid starting values; the first
        // call only reads the current action.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(stack_signal(), std::ptr::null(), &mut old) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Someone else's handler on this signal: leave it alone.
            if old.sa_sigaction != libc::SIG_DFL {
                return Err(std::io::Error::other(format!(
                    "signal {} already has a handler",
                    stack_signal()
                )));
            }
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_stack_signal as *const () as usize;
            // SA_RESTART resumes a plain blocking read/write the signal
            // interrupted. Waits that never restart (timed futex waits,
            // epoll_wait, nanosleep, poll) return EINTR instead; every waiter
            // in this process retries on EINTR (std, tokio's driver, `polling`,
            // libuv), and the server crates make no raw blocking libc calls.
            // So a thread that answers carries on as it was.
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(stack_signal(), &sa, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        INSTALLED.store(true, Ordering::Release);
        Ok(())
    }

    extern "C" fn on_stack_signal(
        _sig: libc::c_int,
        _info: *mut libc::siginfo_t,
        _ctx: *mut libc::c_void,
    ) {
        // SAFETY: errno is thread-local; restore what the interrupted code saw.
        let saved_errno = unsafe { *libc::__errno_location() };
        let armed = STATE.load(Ordering::Acquire);
        // SAFETY: gettid is async-signal-safe.
        let me = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        if armed & PHASE == ARMED
            && me == TARGET.load(Ordering::Acquire)
            && STATE
                .compare_exchange(
                    armed,
                    pack(armed >> 2, WALKING),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            let mut n = 0usize;
            // SAFETY: the closure never allocates and only stores into fixed
            // atomics. The unwinder is libgcc's; its FDE lookup is lock-free on
            // the production glibc (`_dl_find_object`), and its one-time setup
            // already ran in `warm_up`. A walk that never returns only costs
            // this thread's answer, which `stack_of` survives.
            unsafe {
                backtrace::trace_unsynchronized(|frame| {
                    if n == MAX_FRAMES {
                        return false;
                    }
                    FRAMES[n].store(frame.ip() as usize, Ordering::Relaxed);
                    n += 1;
                    true
                });
            }
            COUNT.store(n, Ordering::Relaxed);
            STATE.store(pack(armed >> 2, DONE), Ordering::Release);
        }
        // SAFETY: as above.
        unsafe { *libc::__errno_location() = saved_errno };
    }

    pub(super) enum Capture {
        Stack(Vec<usize>),
        /// `tgkill` failed: the thread is gone.
        Exited,
        /// It never claimed the request, so it was taken back.
        NoAnswer,
        /// It claimed the request but its walk has not finished.
        WalkStuck,
        /// An earlier walk still holds the slots.
        Busy,
        NotInstalled,
    }

    fn wait_for(want: u64, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        loop {
            if STATE.load(Ordering::Acquire) == want {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn take_frames() -> Vec<usize> {
        (0..COUNT.load(Ordering::Relaxed).min(MAX_FRAMES))
            .map(|i| FRAMES[i].load(Ordering::Relaxed))
            .collect()
    }

    /// Ask thread `tid` to walk its own stack.
    pub(super) fn stack_of(tid: i32) -> Capture {
        if !INSTALLED.load(Ordering::Acquire) {
            return Capture::NotInstalled;
        }
        let _one_at_a_time = CAPTURE.lock().unwrap_or_else(|p| p.into_inner());
        // A walk claimed by an earlier request may still be writing the slots.
        let current = STATE.load(Ordering::Acquire);
        if current & PHASE == WALKING && !wait_for(pack(current >> 2, DONE), WALK_GRACE) {
            return Capture::Busy;
        }
        let request = REQUEST.fetch_add(1, Ordering::AcqRel) + 1;
        COUNT.store(0, Ordering::Relaxed);
        TARGET.store(tid, Ordering::Release);
        STATE.store(pack(request, ARMED), Ordering::Release);
        // SAFETY: tgkill to a thread of this process, with a signal whose
        // handler is installed (checked above).
        let sent = unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                tid,
                stack_signal() as libc::c_long,
            )
        } == 0;
        let result = if !sent {
            STATE.store(pack(request, IDLE), Ordering::Release);
            Capture::Exited
        } else if wait_for(pack(request, DONE), ANSWER_WITHIN) {
            Capture::Stack(take_frames())
        } else {
            match STATE.compare_exchange(
                pack(request, ARMED),
                pack(request, IDLE),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => Capture::NoAnswer,
                // Claimed: give the walk a little longer, and if it still has
                // not finished, leave the slots to it.
                Err(_) if wait_for(pack(request, DONE), WALK_GRACE) => {
                    Capture::Stack(take_frames())
                }
                Err(_) => Capture::WalkStuck,
            }
        };
        TARGET.store(0, Ordering::Release);
        result
    }

    /// Name the function `ip` is in. `backtrace::resolve` already looks one
    /// byte back from the address (a frame's ip is its return address).
    /// `@` is the address in the file, when the lookup knows it: what
    /// `addr2line -e <binary>` takes.
    pub(super) fn symbolize(ip: usize) -> String {
        let mut found: Option<String> = None;
        backtrace::resolve(ip as *mut libc::c_void, |sym| {
            if found.is_none() {
                let name = sym
                    .name()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".to_string());
                found = Some(match sym.addr() {
                    Some(at) => format!("{name} @{:#x}", at as usize),
                    None => name,
                });
            }
        });
        found.unwrap_or_else(|| "?".to_string())
    }

    /// Run everything with a one-time setup cost now, on a healthy process:
    /// the unwinder (a walk of this very thread) and the symbolizer.
    pub(super) fn warm_up() {
        // SAFETY: an ordinary walk of the calling thread's own stack.
        unsafe {
            backtrace::trace_unsynchronized(|_| false);
        }
        let _ = symbolize(warm_up as *const () as usize);
    }

    pub(super) fn gettid() -> i32 {
        // SAFETY: plain syscall, no arguments.
        unsafe { libc::syscall(libc::SYS_gettid) as i32 }
    }

    fn read_trim(path: &str) -> String {
        std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|e| format!("? ({e})"))
    }

    pub(super) fn thread_ids() -> Vec<i32> {
        let mut tids: Vec<i32> = std::fs::read_dir("/proc/self/task")
            .map(|rd| {
                rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        tids.sort_unstable();
        tids
    }

    /// The run state from `/proc/self/task/<tid>/stat`. The comm there is
    /// parenthesized and may hold spaces, so it is the first field after the
    /// LAST ')'.
    fn run_state(tid: i32) -> String {
        read_trim(&format!("/proc/self/task/{tid}/stat"))
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .unwrap_or("?")
            .to_string()
    }

    /// `/proc/self/task/<tid>`: name, run state, kernel wait channel, and the
    /// syscall it is in. A thread blocked writing stdout shows `write` with
    /// fd `0x1` as its first argument.
    pub(super) fn thread_info(tid: i32) -> String {
        let base = format!("/proc/self/task/{tid}");
        let comm = read_trim(&format!("{base}/comm"));
        let state = run_state(tid);
        let wchan = read_trim(&format!("{base}/wchan"));
        let syscall = describe_syscall(&read_trim(&format!("{base}/syscall")));
        format!("\"{comm}\" state={state} wchan={wchan} syscall=[{syscall}]")
    }

    /// `/proc/<tid>/syscall` reads `nr arg1..arg6 sp pc` while the thread is in
    /// a syscall. Name the few this bug is about; print the rest as numbers.
    pub(super) fn describe_syscall(raw: &str) -> String {
        let mut fields = raw.split_whitespace();
        let Some(nr) = fields.next().and_then(|n| n.parse::<libc::c_long>().ok()) else {
            return raw.to_string();
        };
        let name = match nr {
            n if n == libc::SYS_write => "write",
            n if n == libc::SYS_writev => "writev",
            n if n == libc::SYS_read => "read",
            n if n == libc::SYS_futex => "futex",
            n if n == libc::SYS_epoll_pwait => "epoll_pwait",
            #[cfg(target_arch = "x86_64")]
            n if n == libc::SYS_epoll_wait => "epoll_wait",
            _ => "syscall",
        };
        let rest: Vec<&str> = fields.collect();
        format!("{name}#{nr} {}", rest.join(" "))
    }

    /// What fd 1 or 2 is, and for a pipe how much of it the reader has not
    /// taken yet. `unread_bytes == pipe_capacity` means the reader stopped.
    pub(super) fn describe_fd(fd: libc::c_int) -> String {
        let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|e| format!("? ({e})"));
        let mut unread: libc::c_int = 0;
        // SAFETY: FIONREAD writes one int through the pointer we pass.
        let unread = if unsafe { libc::ioctl(fd, libc::FIONREAD, &mut unread) } == 0 {
            unread.to_string()
        } else {
            "n/a".to_string()
        };
        // SAFETY: F_GETPIPE_SZ takes no argument and fails on a non-pipe.
        let capacity = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
        let capacity = if capacity >= 0 {
            capacity.to_string()
        } else {
            "n/a".to_string()
        };
        format!("fd {fd}: {target}  unread_bytes={unread}  pipe_capacity={capacity}")
    }

    /// Where the executable is mapped, so a raw address in a dump can also be
    /// symbolized offline against the same image's binary. Read once at
    /// start: `/proc/self/maps` takes the mm lock.
    pub(super) fn exe_mapping() -> String {
        let exe = std::fs::read_link("/proc/self/exe")
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
        maps.lines()
            .find(|l| !exe.is_empty() && l.ends_with(&exe))
            .map(|l| format!("{exe} first mapping: {l}"))
            .unwrap_or_else(|| format!("{exe} (mapping not found)"))
    }

    /// Memory, pressure and throttling, from the process and its cgroup (v2
    /// paths inside the container). A stall in reclaim near `memory.max`, or
    /// CPU throttling, looks from outside exactly like a hang. These say
    /// whether either was happening. Missing files are skipped.
    fn resources() -> String {
        let mut out = String::new();
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        for line in status.lines().filter(|l| {
            ["VmRSS:", "VmHWM:", "Threads:"]
                .iter()
                .any(|k| l.starts_with(k))
        }) {
            let _ = writeln!(
                out,
                "proc {}",
                line.split_whitespace().collect::<Vec<_>>().join(" ")
            );
        }
        for file in [
            "memory.current",
            "memory.max",
            "memory.events",
            "memory.pressure",
            "cpu.pressure",
            "io.pressure",
            "cpu.stat",
        ] {
            if let Ok(text) = std::fs::read_to_string(format!("/sys/fs/cgroup/{file}")) {
                let _ = writeln!(out, "cgroup {file}: {}", text.trim().replace('\n', " | "));
            }
        }
        out
    }

    /// The Linux part of a sample, in stages, each on disk before the next.
    pub(super) fn sample_process(out: &mut DumpOut) {
        let me = gettid();
        let mut head = String::new();
        let _ = writeln!(head, "pid: {}  watchdog_tid: {me}", std::process::id());
        for fd in [1, 2] {
            let _ = writeln!(head, "{}", describe_fd(fd));
        }
        head.push_str(&resources());
        out.write(&head);

        let tids = thread_ids();
        let mut procs = format!("threads: {}\n", tids.len());
        for &tid in &tids {
            let _ = writeln!(procs, "tid {tid} {}", thread_info(tid));
        }
        out.write(&procs);

        out.write("--- stacks ---\n");
        let started = Instant::now();
        let mut stopped = false;
        for &tid in &tids {
            let mut block = format!("tid {tid}:\n");
            let state = run_state(tid);
            if tid == me {
                block.push_str("    (the watchdog itself)\n");
            } else if stopped {
                block.push_str("    (not asked: stack capture stopped earlier in this sample)\n");
            } else if matches!(state.as_str(), "D" | "T" | "t" | "Z" | "X") {
                // It cannot run a signal handler now: its /proc line above is
                // what there is.
                let _ = writeln!(block, "    (not asked: state {state})");
            } else if started.elapsed() >= STACK_BUDGET {
                let _ = writeln!(
                    block,
                    "    (not asked: the {STACK_BUDGET:?} stack budget is spent)"
                );
            } else {
                match stack_of(tid) {
                    Capture::Stack(ips) => {
                        for (i, ip) in ips.iter().enumerate() {
                            let _ = writeln!(block, "    #{i:<2} {ip:#014x} {}", symbolize(*ip));
                        }
                    }
                    Capture::Exited => block.push_str("    (the thread has exited)\n"),
                    Capture::NoAnswer => {
                        let _ = writeln!(block, "    (no answer within {ANSWER_WITHIN:?})");
                    }
                    Capture::WalkStuck => {
                        block.push_str("    (its walk started and never finished; no more stacks this sample)\n");
                        stopped = true;
                    }
                    Capture::Busy => {
                        block.push_str("    (an earlier walk still holds the slots; no more stacks this sample)\n");
                        stopped = true;
                    }
                    Capture::NotInstalled => {
                        block.push_str("    (no handler installed)\n");
                        stopped = true;
                    }
                }
            }
            out.write(&block);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_heartbeat_older_than_the_threshold_is_a_stall() {
        let t = Duration::from_secs(10);
        assert!(!is_stalled(1_000, 1_000, t));
        assert!(
            !is_stalled(1_000, 11_000, t),
            "exactly the threshold is not yet a stall"
        );
        assert!(is_stalled(1_000, 11_001, t));
        // A beat stamped after `now` was read is fresh, never an underflow.
        assert!(!is_stalled(5_000, 4_000, t));
    }

    fn dump_name(n: usize) -> String {
        format!("{DUMP_PREFIX}{:013}{DUMP_SUFFIX}", 1_000 + n)
    }

    #[test]
    fn a_previous_dump_is_reported_once_and_reported_ones_are_pruned_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        for i in 0..(KEEP_DUMPS + 2) {
            std::fs::write(dir.path().join(dump_name(i)), format!("dump {i}")).expect("write");
        }
        // Two NEWER ones were reported by an earlier boot, so pruning the
        // reported first and pruning the oldest first pick different victims.
        for i in [5, 6] {
            std::fs::write(reported_marker(&dir.path().join(dump_name(i))), b"").expect("marker");
        }
        std::fs::write(dir.path().join("unrelated.txt"), "keep me").expect("write");

        let first = report_previous_dumps(dir.path());
        assert_eq!(first.len(), KEEP_DUMPS, "every unreported dump is reported");
        assert!(
            !dir.path().join(dump_name(5)).exists() && !dir.path().join(dump_name(6)).exists(),
            "the reported ones are pruned before any unreported one"
        );
        assert!(
            dir.path().join(dump_name(0)).exists() && dir.path().join(dump_name(1)).exists(),
            "an unreported dump survives, however old"
        );
        assert!(
            first.iter().all(|d| reported_marker(d).exists()),
            "each is marked reported"
        );
        assert!(
            report_previous_dumps(dir.path()).is_empty(),
            "a second boot reports nothing again"
        );
        assert!(
            dir.path().join("unrelated.txt").exists(),
            "other files are left alone"
        );
    }

    #[test]
    fn the_boot_summary_keeps_headers_and_suspicious_threads_only() {
        let dump = "=== meshharbor stall dump (#1731), sample 1 ===\n\
                    heartbeat_age_ms: 11000\n\
                    tokio: workers=2 alive_tasks=40 global_queue_depth=7\n\
                    fd 1: pipe:[1]  unread_bytes=65536  pipe_capacity=65536\n\
                    tid 10 \"tokio-rt-worker\" state=S wchan=pipe_write syscall=[write#1 0x1 0x0]\n\
                    tid 11 \"tokio-rt-worker\" state=S wchan=futex_wait_queue syscall=[futex#202 0x0]\n\
                    tid 12 \"blocking\" state=D wchan=folio_wait_bit syscall=[read#0 0x5]\n\
                    --- stacks ---\n\
                    tid 10:\n    #0  0x0000 std::io::stdio::StdoutRaw::write\n";
        let kept = summarize(dump);
        assert!(kept.iter().any(|l| l.contains("unread_bytes=65536")));
        assert!(kept.iter().any(|l| l.starts_with("tid 10 ")), "the writer");
        assert!(
            kept.iter().any(|l| l.starts_with("tid 12 ")),
            "the D-state thread"
        );
        assert!(
            !kept.iter().any(|l| l.starts_with("tid 11 ")),
            "an ordinary waiter"
        );
        assert!(
            !kept.iter().any(|l| l.contains("StdoutRaw")),
            "no stacks in the summary"
        );
    }

    #[cfg(target_os = "linux")]
    mod linux_capture {
        use super::super::linux;
        use super::super::*;
        use std::sync::mpsc;

        #[inline(never)]
        fn parked_for_the_stall_watchdog_test(release: mpsc::Receiver<()>) {
            let _ = release.recv();
            std::hint::black_box(());
        }

        /// The signalled thread walks its own stack, and the walk names the
        /// function it is parked in.
        #[test]
        fn a_signalled_thread_names_the_function_it_is_parked_in() {
            linux::install_handler().expect("handler");
            let (release_tx, release_rx) = mpsc::channel();
            let (tid_tx, tid_rx) = mpsc::channel();
            let parked = std::thread::spawn(move || {
                tid_tx.send(linux::gettid()).expect("tid");
                parked_for_the_stall_watchdog_test(release_rx);
            });
            let tid = tid_rx.recv().expect("tid");
            std::thread::sleep(Duration::from_millis(100));
            let linux::Capture::Stack(ips) = linux::stack_of(tid) else {
                panic!("the parked thread answers");
            };
            let names: Vec<String> = ips.iter().map(|ip| linux::symbolize(*ip)).collect();
            assert!(
                names
                    .iter()
                    .any(|n| n.contains("parked_for_the_stall_watchdog_test")),
                "the walk names where the thread waits: {names:#?}"
            );
            release_tx.send(()).expect("release");
            parked.join().expect("join");
        }

        /// A thread that is gone is reported as gone, not as silent.
        #[test]
        fn an_exited_thread_is_reported_as_exited() {
            linux::install_handler().expect("handler");
            let tid = std::thread::spawn(linux::gettid).join().expect("join");
            // `join` returns when the thread has terminated, but the kernel may
            // not have reaped its task yet, and until then `tgkill` succeeds
            // (the signal is never handled). Gone means gone from /proc.
            let task = format!("/proc/self/task/{tid}");
            let deadline = Instant::now() + Duration::from_secs(5);
            while Path::new(&task).exists() {
                assert!(Instant::now() < deadline, "the task was never reaped");
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(matches!(linux::stack_of(tid), linux::Capture::Exited));
        }

        /// The stdout suspect: a writer blocked on a pipe nobody reads shows
        /// `write` on that fd, and the pipe reads full.
        #[test]
        fn a_writer_blocked_on_a_full_pipe_shows_write_and_a_full_pipe() {
            let mut fds: [libc::c_int; 2] = [0; 2];
            // SAFETY: pipe fills the two-int array we pass.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let (read_fd, write_fd) = (fds[0], fds[1]);
            let (tid_tx, tid_rx) = mpsc::channel();
            let writer = std::thread::spawn(move || {
                tid_tx.send(linux::gettid()).expect("tid");
                let chunk = [b'x'; 4096];
                let mut written = 0usize;
                // Blocks for good once the pipe is full, until the test closes it.
                while written < 1 << 20 {
                    // SAFETY: writing from a live stack buffer to our pipe.
                    let n = unsafe { libc::write(write_fd, chunk.as_ptr().cast(), chunk.len()) };
                    if n <= 0 {
                        break;
                    }
                    written += n as usize;
                }
            });
            let tid = tid_rx.recv().expect("tid");
            std::thread::sleep(Duration::from_millis(300));
            let info = linux::thread_info(tid);
            let pipe = linux::describe_fd(write_fd);
            assert!(
                info.contains(&format!("write#{} {:#x} ", libc::SYS_write, write_fd)),
                "the blocked writer shows write on fd {write_fd}: {info}"
            );
            let unread: usize = pipe
                .split("unread_bytes=")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .expect("unread bytes");
            let capacity: usize = pipe
                .split("pipe_capacity=")
                .nth(1)
                .and_then(|s| s.parse().ok())
                .expect("capacity");
            assert_eq!(unread, capacity, "the pipe reads full: {pipe}");
            // SAFETY: closing the read end fails the writer's blocked write
            // with EPIPE; SIGPIPE is ignored in Rust programs by default.
            unsafe { libc::close(read_fd) };
            writer.join().expect("join");
            // SAFETY: our own fd.
            unsafe { libc::close(write_fd) };
        }

        #[inline(never)]
        fn frozen_for_the_stall_watchdog_test(release: &mpsc::Receiver<()>) {
            // A blocking wait on a runtime worker: the runtime stops.
            let _ = release.recv_timeout(Duration::from_secs(30));
            std::hint::black_box(());
        }

        fn dumps_in(dir: &Path) -> Vec<PathBuf> {
            std::fs::read_dir(dir)
                .map(|rd| {
                    rd.filter_map(|e| e.ok().map(|e| e.path()))
                        .filter(|p| is_dump(p))
                        .collect()
                })
                .unwrap_or_default()
        }

        /// End to end: a healthy runtime writes nothing. A runtime whose only
        /// worker is stuck gets a dump naming where, and the dump records the
        /// recovery once the worker is released. (The watchdog signals every
        /// thread of this test binary while it samples; they all answer and
        /// carry on, which is part of what this test shows.)
        #[test]
        fn a_frozen_runtime_leaves_a_dump_naming_where_its_worker_is_stuck() {
            let dir = tempfile::tempdir().expect("tempdir");
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("runtime");
            let watchdog = start(
                rt.handle(),
                Config {
                    threshold: Duration::from_secs(1),
                    dump_dir: dir.path().to_path_buf(),
                    echo_stderr: false,
                },
            )
            .expect("start");

            std::thread::sleep(Duration::from_millis(3_000));
            assert!(
                dumps_in(dir.path()).is_empty(),
                "a healthy runtime is never dumped"
            );

            let (release_tx, release_rx) = mpsc::channel::<()>();
            rt.spawn(async move { frozen_for_the_stall_watchdog_test(&release_rx) });
            let deadline = Instant::now() + Duration::from_secs(20);
            let (dump, text) = loop {
                if let Some(d) = dumps_in(dir.path()).into_iter().next() {
                    let text = std::fs::read_to_string(&d).expect("read dump");
                    // Stages land one by one; wait for the sample to close.
                    if text.contains("=== end of sample 1 ===") {
                        break (d, text);
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "no complete dump within 20 s of the freeze"
                );
                std::thread::sleep(Duration::from_millis(200));
            };
            assert!(text.contains("heartbeat_age_ms"), "{text}");
            assert!(text.contains("--- stacks ---"), "{text}");
            assert!(
                text.contains("frozen_for_the_stall_watchdog_test"),
                "the dump names where the worker is stuck:\n{text}"
            );

            let _ = release_tx.send(());
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let text = std::fs::read_to_string(&dump).expect("read dump");
                if text.contains("=== recovered") {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "the recovery was never recorded:\n{text}"
                );
                std::thread::sleep(Duration::from_millis(200));
            }
            watchdog.stop();
            rt.shutdown_timeout(Duration::from_secs(5));
        }

        /// A runtime that shuts down is not a stall: the heartbeat's drop
        /// guard retires the watchdog instead of letting it dump the corpse.
        #[test]
        fn a_runtime_that_shuts_down_retires_its_watchdog() {
            let dir = tempfile::tempdir().expect("tempdir");
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("runtime");
            let watchdog = start(
                rt.handle(),
                Config {
                    threshold: Duration::from_secs(1),
                    dump_dir: dir.path().to_path_buf(),
                    echo_stderr: false,
                },
            )
            .expect("start");
            std::thread::sleep(Duration::from_millis(1_500));
            rt.shutdown_timeout(Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(3_000));
            assert!(
                dumps_in(dir.path()).is_empty(),
                "a runtime that shut down is never dumped"
            );
            watchdog.stop();
        }
    }
}
