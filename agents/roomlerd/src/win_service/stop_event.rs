// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #1683 — the graceful-stop channel between the Windows SCM service host and
//! its worker.
//!
//! The service host stops its worker with `TerminateProcess`
//! ([`super::supervisor::OwnedProcess::terminate`]). A hard kill delivers no
//! console control event and never trips the worker's `terminate_signal()`, so
//! the worker never reaches its `os_initiated_stop` arm — which means an
//! **ephemeral** device installed as the SCM service never self-unenrolls on a
//! clean stop (only the server-side reaper collects it, after the TTL), and a
//! deliberate stop is miscounted toward `crash_count` on the next start (the
//! #1040 wall, on Windows). FR-51 promised a clean stop self-unenrolls in
//! seconds; that worked on Linux (SIGTERM) only.
//!
//! The fix is a named Win32 **manual-reset** event that the host creates BEFORE
//! it spawns each worker and signals on SCM stop / preshutdown: the host asks
//! the worker to leave gracefully, waits a bounded time
//! ([`super::supervisor::WORKER_GRACEFUL_STOP_BUDGET`]), and only then falls
//! back to `TerminateProcess`. The worker's Windows `terminate_signal()` waits
//! on the same event and, when it fires, takes the exact `os_initiated_stop`
//! arm a Unix SIGTERM takes.
//!
//! ## The worker POLLS — it never parks a blocking task on the event
//!
//! [`wait_for_stop_event`] probes the event with `WaitForSingleObject(h, 0)`
//! every [`STOP_EVENT_POLL`] between plain tokio sleeps. That shape is
//! load-bearing. The worker's shutdown `select!` has other arms — an update's
//! internal shutdown, FR-84 D3's requested restart — and they win by DROPPING
//! this future. `main()` then drops the runtime at the end of its `block_on`,
//! and a runtime drop waits for every `spawn_blocking` task to *return*. A
//! blocking wait that could only return on the host's signal would therefore
//! have held process exit hostage: the worker never left on an auto-update, and
//! a requested restart never landed. Here the handle lives inside the future
//! and closes on drop, so nothing outlives a lost select; the ≤ 250 ms of
//! latency is invisible against the host's 8 s budget.
//!
//! ## Security — why the DACL is load-bearing
//!
//! The worker may run as **SYSTEM** (SystemContext) or as the **signed-in user**
//! (the attended flavour). If any local user could *signal* this event, any
//! local user could stop a SYSTEM worker — a denial-of-service, and for an
//! ephemeral device an unenroll-by-anyone. So the event carries an explicit,
//! protected DACL ([`STOP_EVENT_SDDL`]):
//!
//! * **SYSTEM** (the host) gets `EVENT_ALL_ACCESS` — it created the event and is
//!   the only principal that may `SetEvent` it.
//! * **Interactive users** get `SYNCHRONIZE` only — enough to *probe*
//!   ([`WorkerStopEvent::is_signaled`]), never enough to signal. `SYNCHRONIZE`
//!   (`0x100000`) does not include `EVENT_MODIFY_STATE` (`0x2`), so a second
//!   interactive user (fast-user-switch), or the worker itself, can wait but
//!   cannot stop anyone.
//!
//! The name is unique per spawn (host PID + a monotonic counter), so a restart
//! never opens a stale, possibly-already-signaled handle. The host cannot use
//! the worker PID in the name — it must create the event before the worker
//! exists — so per-spawn uniqueness stands in for "per worker": each spawn gets
//! a fresh event, fresh name, fresh handle, torn down with the worker.
//!
//! Everything degrades safely: if the event cannot be created the worker spawns
//! anyway (the shutdown path just hard-terminates, exactly as before this
//! change), and if the worker cannot open/probe the event it falls through to
//! `std::future::pending()` (today's behaviour), so the host's bounded wait
//! simply times out into the `TerminateProcess` fallback. The server-side
//! reaper remains the backstop for every exit that never reaches self-unenroll.
//!
//! Whether a stop that DID arrive may unenroll the device is a separate, pure
//! decision — `crate::updater::should_self_unenroll` — because the MSI's own
//! service stop during an update must never read as the device leaving.

#![cfg(target_os = "windows")]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError, HANDLE, LocalFree,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenEventW, SetEvent, WaitForSingleObject,
};

/// The security descriptor, in SDDL, applied to the stop event. **This is a
/// security decision — read the module docs before changing it.**
///
/// * `D:P` — a protected DACL: nothing is inherited, only what is written here.
/// * `(A;;0x1f0003;;;SY)` — `EVENT_ALL_ACCESS` for **SYSTEM** (the host). Full
///   access includes `EVENT_MODIFY_STATE`, so only SYSTEM may `SetEvent`.
/// * `(A;;0x100000;;;IU)` — `SYNCHRONIZE` for **Interactive Users** (the
///   attended worker, which runs as the console user). Wait-only: `0x100000`
///   excludes `EVENT_MODIFY_STATE` (`0x2`), so no unprivileged local user can
///   stop a SYSTEM worker through this event.
///
/// The SystemContext worker runs as SYSTEM and is covered by the `SY` ACE; the
/// attended worker is an interactive logon and is covered by `IU`.
const STOP_EVENT_SDDL: &str = "D:P(A;;0x1f0003;;;SY)(A;;0x100000;;;IU)";

/// `SDDL_REVISION_1` — the only defined SDDL revision.
const SDDL_REVISION_1: u32 = 1;

/// `SYNCHRONIZE` — the sole access the worker asks for when it opens the event.
/// Deliberately NOT `EVENT_MODIFY_STATE`: the worker probes, it never signals.
const SYNCHRONIZE: u32 = 0x0010_0000;

/// The kernel-object name prefix. `Global\` so the worker (which may be in a
/// user session, i.e. session ≥ 1) can open an event the host created in
/// session 0. The host is SYSTEM and holds `SeCreateGlobalPrivilege`; opening a
/// `Global\` object needs no privilege.
const STOP_EVENT_NAME_PREFIX: &str = "Global\\roomler-worker-stop-";

/// How often the worker probes the event. Each probe is a non-blocking
/// `WaitForSingleObject(h, 0)`, and the sleep between probes is a plain tokio
/// timer, so the wait is cancelled — and the handle closed — the instant the
/// future is dropped (see the module docs for why that must hold). 250 ms is
/// invisible against the host's 8 s budget; a manual-reset event stays
/// signaled, so a probe can never miss a signal that landed between two probes.
pub const STOP_EVENT_POLL: Duration = Duration::from_millis(250);

/// Monotonic per-process counter that makes each spawn's event name unique.
static SPAWN_SEQ: AtomicU64 = AtomicU64::new(0);

/// A NUL-terminated UTF-16 buffer for a Win32 wide-string argument.
fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// The unique name for the next spawn's stop event: `Global\roomler-worker-stop-
/// <host-pid>-<seq>`. Host PID keeps names from colliding across concurrent
/// hosts (there is only ever one, but a stale PID-reused name would still not
/// collide with a live one); the sequence keeps them unique within a host's
/// lifetime.
fn next_event_name() -> String {
    let seq = SPAWN_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{}{}-{}", STOP_EVENT_NAME_PREFIX, std::process::id(), seq)
}

/// Owns a Win32 `HANDLE`, closing it on drop. Local to this module (the
/// supervisor has its own `OwnedHandle`); a stop-event handle never leaves it.
struct EventHandle(HANDLE);

// SAFETY: a Win32 `HANDLE` is a process-wide reference to a kernel object with
// no thread affinity; `SetEvent` / `WaitForSingleObject` / `CloseHandle` are
// all thread-safe. Send so a `HostStopEvent` may live on the supervisor's
// `ActiveWorker`, and so the worker's wait future (which holds one) is Send.
unsafe impl Send for EventHandle {}

impl Drop for EventHandle {
    fn drop(&mut self) {
        // SAFETY: we own this handle and hand its raw value to no other owner.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// The host side of the stop event: created by the SCM service host before it
/// spawns a worker, signaled once on SCM stop / preshutdown, and dropped (which
/// closes the handle) when the worker it belongs to is reaped or swapped.
pub struct HostStopEvent {
    handle: EventHandle,
    name: String,
}

impl HostStopEvent {
    /// Create a fresh, uniquely-named manual-reset event with [`STOP_EVENT_SDDL`],
    /// initially unsignaled. The caller passes [`name`](Self::name) to the
    /// worker as `--stop-event <name>`.
    pub fn create() -> io::Result<Self> {
        let name = next_event_name();

        // Build the security descriptor from SDDL. `psd` is LocalAlloc'd and
        // must be LocalFree'd; the OS copies it into the event at create time,
        // so we free our copy immediately after CreateEventW.
        let sddl_w = to_wide(STOP_EVENT_SDDL);
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl_w` is a NUL-terminated UTF-16 buffer; `psd` is a valid
        // out-pointer; the size-out argument is null (documented optional).
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };
        let name_w = to_wide(&name);
        // SAFETY: `&sa` outlives the call; `sa.lpSecurityDescriptor` is the SD
        // we just built; `name_w` is NUL-terminated. Manual-reset (1) so a
        // set-before-wait is never lost; initial state unsignaled (0).
        let handle = unsafe { CreateEventW(&sa, 1, 0, name_w.as_ptr()) };
        // Capture the create error BEFORE freeing the SD (LocalFree could reset
        // the thread-local error).
        // SAFETY: GetLastError is a thread-local read.
        let create_err = unsafe { GetLastError() };
        // SAFETY: `psd` came from ConvertStringSecurityDescriptor…W (LocalAlloc);
        // the event has copied it, so LocalFree of our copy is the documented
        // release and safe on all paths below.
        let _ = unsafe { LocalFree(psd) };

        if handle.is_null() {
            return Err(io::Error::from_raw_os_error(create_err as i32));
        }
        if create_err == ERROR_ALREADY_EXISTS {
            // A name collision (effectively impossible with host-PID + counter)
            // would hand us a pre-existing, possibly-already-signaled event.
            // Refuse it: a fresh handle here would be worse than falling back to
            // the hard-terminate path, which the caller does when create fails.
            // SAFETY: `handle` is the valid handle CreateEventW just returned.
            unsafe {
                CloseHandle(handle);
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("stop event {name} already existed"),
            ));
        }
        Ok(Self {
            handle: EventHandle(handle),
            name,
        })
    }

    /// The kernel-object name — pass it to the worker as `--stop-event <name>`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Signal the event: the SCM host calls this on stop / preshutdown to ask
    /// the worker to leave gracefully. Best-effort — a failure is logged and the
    /// caller's bounded wait then falls back to `TerminateProcess`.
    pub fn signal(&self) {
        // SAFETY: the creator's handle carries EVENT_ALL_ACCESS (incl.
        // EVENT_MODIFY_STATE) regardless of the DACL, so SetEvent is permitted.
        let ok = unsafe { SetEvent(self.handle.0) };
        if ok == 0 {
            // SAFETY: GetLastError is a thread-local read.
            let err = unsafe { GetLastError() };
            tracing::warn!(name = %self.name, err, "stop event: SetEvent failed");
        }
    }
}

/// The worker side: the host's stop event, opened for `SYNCHRONIZE` only —
/// enough to probe, never enough to signal.
pub struct WorkerStopEvent {
    handle: EventHandle,
}

impl WorkerStopEvent {
    /// Open the named event with `SYNCHRONIZE`. `Err` when it does not exist or
    /// the DACL denies us — the caller must then treat the channel as absent,
    /// never as a stop.
    pub fn open(name: &str) -> io::Result<Self> {
        let name_w = to_wide(name);
        // SAFETY: `name_w` is NUL-terminated; we ask for SYNCHRONIZE (probe)
        // only, not inheritable. A null return means the open failed.
        let handle = unsafe { OpenEventW(SYNCHRONIZE, 0, name_w.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle: EventHandle(handle),
        })
    }

    /// Non-blocking probe: has the host signaled? `WaitForSingleObject` with a
    /// zero timeout returns at once. Because the event is manual-reset it stays
    /// signaled, so a probe never misses a signal that arrived between probes.
    pub fn is_signaled(&self) -> io::Result<bool> {
        // SAFETY: a valid handle opened for SYNCHRONIZE; a 0 ms wait never blocks.
        let r = unsafe { WaitForSingleObject(self.handle.0, 0) };
        match r {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            other => Err(io::Error::other(format!(
                "WaitForSingleObject on the stop event returned 0x{other:x}"
            ))),
        }
    }
}

/// Worker side: resolve when the SCM host signals the stop event named `name`.
/// One arm of the worker's shutdown `select!` (`terminate_signal` in main.rs).
///
/// It POLLS ([`STOP_EVENT_POLL`]) instead of parking a blocking task on the
/// event — see the module docs: a blocking wait that lost the `select!` would
/// have kept the runtime's drop, and so process exit, waiting for a signal that
/// never comes. Here the handle lives in this future and is closed on drop.
///
/// `Err` when the event cannot be opened or probed — the caller must NOT treat
/// that as a stop (it awaits `pending()` instead), so a missing or inaccessible
/// event never fabricates a shutdown or a self-unenroll.
pub async fn wait_for_stop_event(name: &str) -> io::Result<()> {
    let ev = WorkerStopEvent::open(name)?;
    loop {
        if ev.is_signaled()? {
            return Ok(());
        }
        tokio::time::sleep(STOP_EVENT_POLL).await;
    }
}

// ── FR-97 P4d — a per-user daemon's own stop channel ──────────────────────

/// FR-97 P4d — the stop event a per-user daemon (the Scheduled Task install, or
/// a hand-run `meshharbord run`) creates for itself, named by the instance id of
/// its config ([`crate::instance_lock::instance_id`]). No service host stands
/// between such a daemon and `schtasks /End`, which is a `TerminateProcess`:
/// before P4d an ephemeral device installed that way never self-unenrolled on a
/// stop, which an SCM install has done since #1683.
///
/// `Local\`: the user's own session namespace, where the task runs (an
/// interactive token) and where the same user's `meshharbord service stop` looks.
/// Another session cannot even see it. Default security, which is the creating
/// token's default DACL (this user and SYSTEM): the person who owns the daemon
/// can stop it, which Task Manager already lets them do, and no other principal
/// gains anything. Keyed by the config, as the single-instance lock is: one
/// person may run two daemons on two configs, and `service stop` must reach the
/// one its own config names.
pub const USER_STOP_EVENT_PREFIX: &str = "Local\\roomler-user-stop-";

/// The per-user stop event's name for the daemon of `instance_id`.
pub fn user_stop_event_name(instance_id: &str) -> String {
    format!("{USER_STOP_EVENT_PREFIX}{instance_id}")
}

/// `EVENT_MODIFY_STATE` — what `service stop` asks for: enough to signal.
const EVENT_MODIFY_STATE: u32 = 0x0002;

/// The event, as the daemon holds it.
struct UserStopEvent {
    handle: EventHandle,
}

// SAFETY: the handle is a process-wide kernel-object reference with no thread
// affinity, and `WaitForSingleObject` on it is thread-safe; the event lives in
// a `static`, so it must be shareable.
unsafe impl Sync for UserStopEvent {}

impl UserStopEvent {
    /// Create the event, manual-reset and unsignaled. `Err(AlreadyExists)`
    /// when another live process holds the name: an instance of this config
    /// still on its way out, whose event may already be signaled. Taking it
    /// would stop this daemon the moment it starts.
    fn create(name: &str) -> io::Result<Self> {
        let name_w = to_wide(name);
        // SAFETY: a null SECURITY_ATTRIBUTES is the documented "default
        // security"; `name_w` is NUL-terminated. Manual-reset (1), unsignaled (0).
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, name_w.as_ptr()) };
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        if handle.is_null() {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        if err == ERROR_ALREADY_EXISTS {
            // SAFETY: `handle` is the valid handle CreateEventW just returned.
            unsafe {
                CloseHandle(handle);
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{name} is held by another process"),
            ));
        }
        Ok(Self {
            handle: EventHandle(handle),
        })
    }

    fn is_signaled(&self) -> io::Result<bool> {
        // SAFETY: the creator's handle carries full access; a zero timeout
        // returns at once.
        match unsafe { WaitForSingleObject(self.handle.0, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

/// What ended a per-user daemon's wait for a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStop {
    /// `meshharbord service stop` signaled the event.
    Asked,
    /// Windows is ending the session ([`super::session_end`]).
    SessionEnd(super::session_end::SessionEnd),
}

/// A per-user daemon's stop channel: the event's name, and the event once this
/// process holds it. Held, never dropped, until the process exits: `service
/// stop` reads the event's disappearance as the daemon's exit
/// ([`user_stop_event_held`]), so the handle must outlive the shutdown that
/// follows the signal (an ephemeral device's unenroll among it).
pub struct UserStopChannel {
    name: String,
    held: OnceLock<UserStopEvent>,
}

impl UserStopChannel {
    pub fn new(name: String) -> Self {
        Self {
            name,
            held: OnceLock::new(),
        }
    }

    /// The event, created on the first try that succeeds. While another
    /// instance of this config still holds the name, `Err(AlreadyExists)`, and
    /// the caller tries again on its next poll: so a daemon started while the
    /// one before it is leaving gets its channel the moment the name is free.
    fn event(&self) -> io::Result<&UserStopEvent> {
        if let Some(ev) = self.held.get() {
            return Ok(ev);
        }
        let ev = UserStopEvent::create(&self.name)?;
        Ok(self.held.get_or_init(|| ev))
    }
}

/// The daemon's channel: one per process, named by the config `run` started
/// with.
pub fn user_stop_channel(instance_id: &str) -> &'static UserStopChannel {
    static CHANNEL: OnceLock<UserStopChannel> = OnceLock::new();
    CHANNEL.get_or_init(|| UserStopChannel::new(user_stop_event_name(instance_id)))
}

/// Daemon side: resolve when `meshharbord service stop` signals the channel's
/// event, or when `ending` reports Windows ending the session. It polls, as
/// [`wait_for_stop_event`] does and for the same reason. An event that cannot
/// be had or probed is never read as a stop: the wait says so once, keeps
/// watching for the session's end, and tries the event again on each poll.
pub async fn wait_for_user_stop(
    channel: &UserStopChannel,
    ending: impl Fn() -> Option<super::session_end::SessionEnd>,
) -> UserStop {
    let mut missing = false;
    loop {
        if let Some(kind) = ending() {
            return UserStop::SessionEnd(kind);
        }
        match channel.event().and_then(UserStopEvent::is_signaled) {
            Ok(true) => return UserStop::Asked,
            Ok(false) => {
                if missing {
                    missing = false;
                    tracing::info!(name = %channel.name, "per-user stop event held now");
                }
            }
            Err(e) => {
                if !missing {
                    missing = true;
                    tracing::warn!(
                        error = %e,
                        name = %channel.name,
                        "no per-user stop event yet: until there is one, `meshharbord service stop` \
                         ends this daemon with schtasks /End (retrying)"
                    );
                }
            }
        }
        tokio::time::sleep(STOP_EVENT_POLL).await;
    }
}

/// The `meshharbord service stop` side: ask the per-user daemon whose event is
/// `name` to leave. `Ok(false)` when no daemon holds it: none is running, or it
/// is from before P4d.
pub fn signal_user_stop(name: &str) -> io::Result<bool> {
    let name_w = to_wide(name);
    // SAFETY: `name_w` is NUL-terminated; we ask for EVENT_MODIFY_STATE only.
    let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name_w.as_ptr()) };
    if handle.is_null() {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        if err == ERROR_FILE_NOT_FOUND {
            return Ok(false);
        }
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let h = EventHandle(handle);
    // SAFETY: `h.0` is the handle just opened with EVENT_MODIFY_STATE.
    if unsafe { SetEvent(h.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

/// Whether a per-user daemon still holds the event `name`. The event lives
/// exactly as long as some process holds a handle, and only the daemon keeps
/// one, until it exits: so the event's disappearance is the daemon's exit.
pub fn user_stop_event_held(name: &str) -> bool {
    let name_w = to_wide(name);
    // SAFETY: `name_w` is NUL-terminated; SYNCHRONIZE is enough to open it.
    let handle = unsafe { OpenEventW(SYNCHRONIZE, 0, name_w.as_ptr()) };
    if handle.is_null() {
        return false;
    }
    drop(EventHandle(handle));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_thread_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// The worker's `select!` has three arms. When ANOTHER arm wins (an
    /// auto-update's internal shutdown, FR-84 D3 "Apply now"), this future is
    /// dropped — and then `main()` drops the runtime, which waits for every
    /// spawned blocking task to RETURN. A wait that can only return when the
    /// host signals the event therefore hangs process exit: the worker never
    /// leaves on an update, and a requested restart never lands. This test is
    /// that exit: drive the wait on an unsignaled event, lose the select, drop
    /// the runtime, and demand it comes back promptly. (RED against the
    /// `spawn_blocking(INFINITE)` shape; the poll shape passes.)
    #[test]
    fn dropping_the_wait_future_never_hangs_runtime_shutdown() {
        let ev = HostStopEvent::create().expect("create");
        let name = ev.name().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = current_thread_rt();
            rt.block_on(async {
                tokio::select! {
                    r = wait_for_stop_event(&name) => {
                        panic!("the event is never signaled; the wait must not resolve: {r:?}")
                    }
                    _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                }
            });
            // What `main()` does at the end of its `block_on` statement.
            drop(rt);
            let _ = tx.send(());
        });
        let done = rx.recv_timeout(Duration::from_secs(2));
        assert!(
            done.is_ok(),
            "dropping the runtime must not wait on a stop-event wait that lost its select! \
             — the worker would never exit on an auto-update or a requested restart"
        );
        drop(ev);
    }

    /// The mechanism end to end, in one process: a "worker" runtime awaits the
    /// wait on a helper thread, the host signals from here, the wait resolves.
    /// Before this module the worker's Windows `terminate_signal()` was
    /// `pending()` forever, so this round-trip did not exist.
    #[test]
    fn host_signal_resolves_the_worker_wait() {
        let ev = HostStopEvent::create().expect("create");
        let name = ev.name().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = current_thread_rt();
            // The timeout's timer must be built INSIDE the runtime context.
            let r = rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), wait_for_stop_event(&name)).await
            });
            let _ = tx.send(r);
        });
        // Let the waiter open the event and start probing, then signal.
        std::thread::sleep(Duration::from_millis(200));
        ev.signal();
        let got = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the waiter must report a result");
        assert!(
            matches!(got, Ok(Ok(()))),
            "the worker's wait must resolve on the host's signal: {got:?}"
        );
    }

    /// Proves the wait actually blocks on the event: an early resolve would, in
    /// `terminate_signal`, fabricate a stop — and for an ephemeral device an
    /// erroneous self-unenroll.
    #[test]
    fn an_unsignaled_event_does_not_resolve() {
        let ev = HostStopEvent::create().expect("create");
        let rt = current_thread_rt();
        // The timeout's timer must be built INSIDE the runtime context.
        let r = rt.block_on(async {
            tokio::time::timeout(Duration::from_millis(700), wait_for_stop_event(ev.name())).await
        });
        assert!(r.is_err(), "an unsignaled event must not resolve: {r:?}");
    }

    /// FR-97 P4d — a name of the test's own. Never the real one: signalling
    /// that would stop a per-user daemon running on this machine.
    fn user_test_name() -> String {
        format!(
            "Local\\roomler-user-stop-test-{}-{}",
            std::process::id(),
            SPAWN_SEQ.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// The per-user channel end to end: `service stop` finds nothing to signal
    /// without a daemon, signals one that holds the event, and reads the
    /// event's disappearance as the daemon's exit.
    #[test]
    fn a_service_stop_signals_the_per_user_daemon_and_sees_it_go() {
        let name = user_test_name();
        assert!(!user_stop_event_held(&name), "nothing holds a fresh name");
        assert!(
            !signal_user_stop(&name).expect("probe"),
            "no daemon: nothing to signal"
        );
        let ev = UserStopEvent::create(&name).expect("create");
        assert!(
            user_stop_event_held(&name),
            "a running daemon holds its event"
        );
        assert!(
            !ev.is_signaled().expect("probe"),
            "a fresh event is unsignaled"
        );
        assert!(
            signal_user_stop(&name).expect("signal"),
            "a running daemon is signalled"
        );
        assert!(ev.is_signaled().expect("probe"), "the daemon sees the stop");
        drop(ev);
        assert!(
            !user_stop_event_held(&name),
            "the daemon's exit is the event's disappearance"
        );
    }

    /// A daemon starting while the one before it is still leaving must not
    /// take that one's event, which `service stop` has already signalled: it
    /// would stop the moment it starts.
    #[test]
    fn a_new_daemon_never_takes_a_name_still_held() {
        let name = user_test_name();
        let leaving = UserStopEvent::create(&name).expect("create");
        assert!(signal_user_stop(&name).expect("signal"));
        let starting = UserStopEvent::create(&name);
        assert_eq!(
            starting.err().map(|e| e.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        drop(leaving);
        let after = UserStopEvent::create(&name).expect("free once the old one is gone");
        assert!(
            !after.is_signaled().expect("probe"),
            "a name freed by the old daemon starts unsignaled"
        );
    }

    fn never_ending() -> Option<super::super::session_end::SessionEnd> {
        None
    }

    /// The daemon's wait resolves on the signal, and not before it.
    #[test]
    fn the_per_user_wait_resolves_on_the_signal() {
        let name = user_test_name();
        let channel = UserStopChannel::new(name.clone());
        let rt = current_thread_rt();
        let early = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(600),
                wait_for_user_stop(&channel, never_ending),
            )
            .await
        });
        assert!(
            early.is_err(),
            "an unsignaled event must not resolve: {early:?}"
        );
        assert!(
            user_stop_event_held(&name),
            "the wait took the event, and it outlives the wait"
        );
        let n2 = name.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            let _ = signal_user_stop(&n2);
        });
        let r = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                wait_for_user_stop(&channel, never_ending),
            )
            .await
        });
        assert_eq!(
            r.ok(),
            Some(UserStop::Asked),
            "the wait must resolve on the signal"
        );
    }

    /// A session end resolves the wait too, with nothing signaled.
    #[test]
    fn the_per_user_wait_resolves_when_the_session_ends() {
        use super::super::session_end::SessionEnd;
        let channel = UserStopChannel::new(user_test_name());
        let ends = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probe = {
            let ends = ends.clone();
            move || ends.load(Ordering::Acquire).then_some(SessionEnd::Shutdown)
        };
        let flip = ends.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            flip.store(true, Ordering::Release);
        });
        let rt = current_thread_rt();
        let r = rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), wait_for_user_stop(&channel, probe)).await
        });
        assert_eq!(r.ok(), Some(UserStop::SessionEnd(SessionEnd::Shutdown)));
    }

    /// A daemon started while the one before it is leaving: it never takes
    /// the old, already-signaled event, so it does not stop on that signal,
    /// and it takes the name once the old one is gone, so `service stop`
    /// reaches it after all.
    #[test]
    fn a_daemon_started_while_the_last_one_leaves_gets_the_name_once_it_is_free() {
        let name = user_test_name();
        let leaving = UserStopEvent::create(&name).expect("create");
        assert!(signal_user_stop(&name).expect("signal the leaving daemon"));
        let channel = UserStopChannel::new(name.clone());
        let rt = current_thread_rt();
        let r = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(800),
                wait_for_user_stop(&channel, never_ending),
            )
            .await
        });
        assert!(
            r.is_err(),
            "the old daemon's signal must not stop the new one: {r:?}"
        );
        drop(leaving);
        let n2 = name.clone();
        std::thread::spawn(move || {
            // Past two polls, so the new daemon has taken the freed name.
            std::thread::sleep(STOP_EVENT_POLL * 3);
            let _ = signal_user_stop(&n2);
        });
        let r = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                wait_for_user_stop(&channel, never_ending),
            )
            .await
        });
        assert_eq!(r.ok(), Some(UserStop::Asked));
    }

    #[test]
    fn user_stop_event_names_are_per_session_and_keyed_by_the_config() {
        let a = user_stop_event_name(&crate::instance_lock::instance_id(std::path::Path::new(
            "C:\\a\\config.toml",
        )));
        let b = user_stop_event_name(&crate::instance_lock::instance_id(std::path::Path::new(
            "C:\\b\\config.toml",
        )));
        assert!(a.starts_with("Local\\roomler-user-stop-"), "{a}");
        assert_ne!(a, b, "two configs, two daemons, two events");
    }

    #[test]
    fn is_signaled_flips_when_the_host_signals() {
        let ev = HostStopEvent::create().expect("create");
        let w = WorkerStopEvent::open(ev.name()).expect("open with SYNCHRONIZE");
        assert!(
            !w.is_signaled().expect("probe"),
            "fresh event is unsignaled"
        );
        ev.signal();
        assert!(
            w.is_signaled().expect("probe"),
            "manual-reset: once signaled it stays signaled for the next probe"
        );
    }

    /// The safe-degradation path: no event ⇒ Err ⇒ the worker awaits
    /// `pending()` instead of treating it as a stop.
    #[test]
    fn waiting_on_a_missing_event_errs() {
        let rt = current_thread_rt();
        let r = rt.block_on(wait_for_stop_event(
            "Global\\roomler-worker-stop-nonexistent-1683",
        ));
        assert!(
            r.is_err(),
            "opening an absent event must error so the worker degrades to terminate"
        );
    }

    /// The host waits `WORKER_GRACEFUL_STOP_BUDGET` after signaling; the worker
    /// must notice long before that — many probes per budget, not one.
    #[test]
    fn the_poll_interval_is_well_inside_the_hosts_budget() {
        assert_eq!(STOP_EVENT_POLL, Duration::from_millis(250));
        assert!(STOP_EVENT_POLL * 8 < super::super::supervisor::WORKER_GRACEFUL_STOP_BUDGET);
    }

    #[test]
    fn sddl_is_the_locked_security_contract() {
        // Only SYSTEM may SIGNAL (EVENT_MODIFY_STATE ⊂ 0x1f0003); an interactive
        // user gets 0x100000 = SYNCHRONIZE = PROBE ONLY. That is the whole
        // security property (#1683): no unprivileged local user can stop a
        // SYSTEM worker. Changing this string is changing that decision.
        assert_eq!(STOP_EVENT_SDDL, "D:P(A;;0x1f0003;;;SY)(A;;0x100000;;;IU)");
        // …and it must actually convert + create, or every host would fail
        // closed (no stop event ⇒ hard-terminate ⇒ the bug is back).
        let ev = HostStopEvent::create();
        assert!(
            ev.is_ok(),
            "the locked SDDL must build an event: {:?}",
            ev.err()
        );
    }

    #[test]
    fn stop_event_names_are_unique_and_global() {
        let a = HostStopEvent::create().expect("create a");
        let b = HostStopEvent::create().expect("create b");
        assert_ne!(a.name(), b.name(), "each spawn needs its own event name");
        assert!(
            a.name().starts_with(STOP_EVENT_NAME_PREFIX),
            "name must be in the Global namespace: {}",
            a.name()
        );
    }
}
