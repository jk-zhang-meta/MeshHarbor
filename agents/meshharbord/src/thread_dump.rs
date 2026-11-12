// SPDX-License-Identifier: MPL-2.0
//! Linux-only, best-effort dump of every thread's state and user stack, taken
//! in the last seconds before a watchdog forces the process out.
//!
//! A watchdog exit used to say only *that* the runtime froze. A
//! watchdog-of-watchdog trip means no runtime worker came back to the async
//! watchdog for 60 s: either every worker is blocked (a lock held across an
//! await, a lock-order deadlock, blocking I/O on a worker) or the drivers
//! stopped. Telling those apart needs every thread's state AND where it
//! stands, so this module records:
//!
//! - per thread, from `/proc/self/task/<tid>`: `comm`, the scheduler state,
//!   `wchan`, and the syscall it is blocked in (202 = futex is a lock or a
//!   condvar wait; "running" is a spin);
//! - per thread, its user-space return addresses, captured by the thread
//!   itself in a real-time signal handler into a static, pre-allocated slot
//!   (no allocation, no lock), and symbolised afterwards by the dumper thread.
//!
//! ⚠️ The process may be deadlocked when this runs, possibly inside the
//! allocator or the stderr lock, so the parts that cannot afford to block do
//! not touch either:
//! - the dumper thread is spawned up front, at watchdog start, so a trip
//!   allocates nothing on the watchdog thread;
//! - the signal handler writes only atomics;
//! - output goes through raw `write(2)`, never the locked `Stderr`.
//!
//! The dumper itself allocates (symbol resolution), so the caller waits for
//! it with a deadline and exits regardless ([`request_and_wait`]). A stuck
//! dump costs at most that deadline; it never costs the exit.
//!
//! Kill switch: `MESHHARBORD_STALL_THREAD_DUMP=0`.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::thread::Thread;
use std::time::{Duration, Instant};

const MAX_THREADS: usize = 256;
const MAX_FRAMES: usize = 48;
/// How long the dumper waits for every signalled thread to record its stack.
/// A thread blocked with real-time signals masked never answers.
const SIGNAL_WAIT: Duration = Duration::from_secs(2);

struct Slot {
    tid: AtomicI32,
    len: AtomicUsize,
    done: AtomicBool,
    ips: [AtomicUsize; MAX_FRAMES],
}

static SLOTS: [Slot; MAX_THREADS] = [const {
    Slot {
        tid: AtomicI32::new(0),
        len: AtomicUsize::new(0),
        done: AtomicBool::new(false),
        ips: [const { AtomicUsize::new(0) }; MAX_FRAMES],
    }
}; MAX_THREADS];
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

static DUMPER: OnceLock<Thread> = OnceLock::new();
static REQUESTED: AtomicBool = AtomicBool::new(false);
static FINISHED: AtomicBool = AtomicBool::new(false);
/// The reason of the pending request, as a static string so the requester
/// never allocates.
static REASON: OnceLock<&'static str> = OnceLock::new();

fn enabled() -> bool {
    !matches!(
        std::env::var("MESHHARBORD_STALL_THREAD_DUMP").as_deref(),
        Ok("0") | Ok("false") | Ok("off") | Ok("no")
    )
}

fn dump_signal() -> libc::c_int {
    // glibc reserves the first real-time signals for NPTL; SIGRTMIN() already
    // skips them. Nothing else in the daemon uses real-time signals.
    libc::SIGRTMIN() + 7
}

fn gettid() -> i32 {
    // SAFETY: SYS_gettid takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

/// Async-signal-safe: atomics only, plus the unwinder, which reads the
/// thread's own stack.
extern "C" fn on_dump_signal(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut std::ffi::c_void) {
    let i = NEXT_SLOT.fetch_add(1, Ordering::AcqRel);
    if i >= MAX_THREADS {
        return;
    }
    let slot = &SLOTS[i];
    slot.tid.store(gettid(), Ordering::Relaxed);
    let mut n = 0usize;
    // SAFETY: the unsynchronized walk is what a signal handler must use (the
    // synchronized one takes a lock the interrupted thread may hold); it only
    // reads this thread's stack and the already-loaded unwind tables.
    unsafe {
        backtrace::trace_unsynchronized(|frame| {
            if n >= MAX_FRAMES {
                return false;
            }
            slot.ips[n].store(frame.ip() as usize, Ordering::Relaxed);
            n += 1;
            true
        });
    }
    slot.len.store(n, Ordering::Relaxed);
    slot.done.store(true, Ordering::Release);
}

/// Raw `write(2)` to stderr: no `Stderr` lock, no panic on failure. The
/// watchdog-of-watchdog's own line goes through here too: a thread blocked
/// writing to a stalled stderr pipe holds the `Stderr` lock, and the last line
/// of defense must not wait on it.
pub fn raw_stderr(bytes: &[u8]) {
    let mut off = 0;
    while off < bytes.len() {
        // SAFETY: valid pointer and length into `bytes`.
        let n = unsafe {
            libc::write(
                2,
                bytes[off..].as_ptr() as *const libc::c_void,
                bytes.len() - off,
            )
        };
        if n <= 0 {
            return;
        }
        off += n as usize;
    }
}

fn read_trim(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into())
}

/// `/proc/<pid>/task/<tid>/stat`: the state is the first field after the
/// parenthesised `comm` (which may itself contain spaces or parentheses).
fn stat_state(stat: &str) -> String {
    stat.rfind(')')
        .and_then(|i| stat[i + 1..].split_whitespace().next())
        .unwrap_or("?")
        .to_string()
}

/// `/proc/<pid>/task/<tid>/syscall`: the syscall number, `running`, or `-1`
/// (blocked, but not in a syscall).
fn syscall_nr(raw: &str) -> String {
    raw.split_whitespace().next().unwrap_or("?").to_string()
}

fn task_ids() -> Vec<i32> {
    let mut v: Vec<i32> = std::fs::read_dir("/proc/self/task")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    v
}

fn install_handler() -> bool {
    // SAFETY: a zeroed sigaction with SA_SIGINFO and our handler is valid.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_dump_signal as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(dump_signal(), &sa, std::ptr::null_mut()) == 0
    }
}

fn symbolise(ip: usize) -> String {
    let mut out = String::new();
    backtrace::resolve(ip as *mut std::ffi::c_void, |sym| {
        if !out.is_empty() {
            return;
        }
        let name = sym
            .name()
            .map(|n| format!("{n:#}"))
            .unwrap_or_else(|| "?".into());
        out = match (sym.filename(), sym.lineno()) {
            (Some(f), Some(l)) => format!("{name} ({}:{l})", f.display()),
            _ => name,
        };
    });
    if out.is_empty() { "?".into() } else { out }
}

/// Build the dump text for every thread. Runs on the dumper thread.
fn collect(reason: &str) -> String {
    collect_from(reason, None)
}

/// [`collect`], with the signalled set narrowed (tests signal only their own
/// probe thread, so they never interrupt a sibling test's syscalls).
fn collect_from(reason: &str, only: Option<&[i32]>) -> String {
    use std::fmt::Write as _;
    let me = gettid();
    let pid = std::process::id() as i32;
    let tids = task_ids();
    let mut text = String::new();
    let _ = writeln!(
        text,
        "stall-dump: reason={reason} pid={pid} threads={}",
        tids.len()
    );
    for &tid in &tids {
        let base = format!("/proc/self/task/{tid}");
        let _ = writeln!(
            text,
            "stall-dump: thread tid={tid} name={} state={} wchan={} syscall={}",
            read_trim(&format!("{base}/comm")),
            stat_state(&read_trim(&format!("{base}/stat"))),
            read_trim(&format!("{base}/wchan")),
            syscall_nr(&read_trim(&format!("{base}/syscall"))),
        );
    }
    if !install_handler() {
        let _ = writeln!(text, "stall-dump: no stacks (sigaction failed)");
        return text;
    }
    NEXT_SLOT.store(0, Ordering::Release);
    for s in SLOTS.iter() {
        s.done.store(false, Ordering::Release);
    }
    let mut signalled = 0usize;
    for &tid in &tids {
        if tid == me || only.is_some_and(|o| !o.contains(&tid)) {
            continue;
        }
        // SAFETY: tgkill to a thread of our own process with a signal whose
        // handler is installed above.
        if unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, dump_signal()) } == 0 {
            signalled += 1;
        }
    }
    let deadline = Instant::now() + SIGNAL_WAIT;
    while Instant::now() < deadline {
        let filled = SLOTS
            .iter()
            .take(NEXT_SLOT.load(Ordering::Acquire).min(MAX_THREADS))
            .filter(|s| s.done.load(Ordering::Acquire))
            .count();
        if filled >= signalled.min(MAX_THREADS) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let answered = NEXT_SLOT.load(Ordering::Acquire).min(MAX_THREADS);
    let _ = writeln!(
        text,
        "stall-dump: stacks answered={answered} of signalled={signalled}"
    );
    for slot in SLOTS.iter().take(answered) {
        if !slot.done.load(Ordering::Acquire) {
            continue;
        }
        let tid = slot.tid.load(Ordering::Relaxed);
        let _ = writeln!(
            text,
            "stall-dump: stack tid={tid} name={}",
            read_trim(&format!("/proc/self/task/{tid}/comm"))
        );
        let len = slot.len.load(Ordering::Relaxed).min(MAX_FRAMES);
        for (i, ip) in slot.ips.iter().take(len).enumerate() {
            let ip = ip.load(Ordering::Relaxed);
            let _ = writeln!(text, "stall-dump:   #{i:<2} {ip:#x} {}", symbolise(ip));
        }
    }
    text
}

fn emit(text: &str) {
    raw_stderr(text.as_bytes());
    if let Some(dir) = crate::logging::log_dir() {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = std::fs::write(dir.join(format!("stall-threads-{secs}.txt")), text);
    }
}

/// Spawn the dumper thread up front. Called where the watchdog-of-watchdog
/// starts, so a later trip allocates nothing on the tripping thread.
pub fn prepare() {
    if !enabled() || DUMPER.get().is_some() {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("meshharbord-stall-dump".into())
        .spawn(|| {
            while !REQUESTED.load(Ordering::Acquire) {
                std::thread::park();
            }
            let reason = REASON.get().copied().unwrap_or("unknown");
            emit(&collect(reason));
            FINISHED.store(true, Ordering::Release);
        });
    if let Ok(h) = spawned {
        let _ = DUMPER.set(h.thread().clone());
    }
}

/// Ask the pre-spawned dumper for one dump and wait at most `timeout` for it.
/// Returns whether it finished. Safe to call from a thread that must not
/// allocate: it only flips atomics, unparks, and sleeps.
pub fn request_and_wait(reason: &'static str, timeout: Duration) -> bool {
    let Some(dumper) = DUMPER.get() else {
        return false;
    };
    let _ = REASON.set(reason);
    if REQUESTED.swap(true, Ordering::AcqRel) {
        // A dump is already running (both watchdogs tripping at once):
        // just wait for it.
    } else {
        dumper.unpark();
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if FINISHED.load(Ordering::Acquire) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    FINISHED.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_and_syscall_fields_parse_from_proc_shapes() {
        assert_eq!(stat_state("1234 (tokio-rt (worker)) S 1 2 3"), "S");
        assert_eq!(stat_state("1234 (x) D 1"), "D");
        assert_eq!(stat_state("garbage"), "?");
        assert_eq!(syscall_nr("202 0x7f 0x80 0x0"), "202");
        assert_eq!(syscall_nr("running"), "running");
    }

    /// The whole path on a live process: every thread is listed, and a
    /// parked thread answers the signal with a symbolised stack that reaches
    /// back into this test.
    #[test]
    fn collect_lists_threads_and_captures_a_parked_threads_stack() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (tid_tx, tid_rx) = std::sync::mpsc::channel::<i32>();
        let parked = std::thread::Builder::new()
            .name("dump-probe".into())
            .spawn(move || {
                let _ = tid_tx.send(gettid());
                let _ = rx.recv();
            })
            .unwrap();
        let probe = tid_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let text = collect_from("test", Some(&[probe]));
        let _ = tx.send(());
        parked.join().unwrap();
        assert!(text.contains("stall-dump: reason=test"), "{text}");
        assert!(text.contains("name=dump-probe"), "{text}");
        let stack_line = text
            .lines()
            .find(|l| l.starts_with("stall-dump: stack ") && l.contains("name=dump-probe"));
        assert!(stack_line.is_some(), "the parked thread answered: {text}");
        assert!(text.contains("stall-dump:   #0"), "{text}");
    }
}
