// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! M3 A1 SYSTEM-context input injection backend.
//!
//! Same shape as [`super::enigo_backend::EnigoInjector`] (dedicated
//! OS thread + `std::mpsc` command channel + enigo `SendInput`), but
//! the worker thread:
//!
//! 1. Calls [`super::super::system_context::desktop_rebind::attach_to_winsta0`]
//!    once at startup. The SCM service container's window-station is
//!    `Service-0x0-3e7$` by default — `OpenDesktopW("Default" |
//!    "Winlogon")` fails with `ERROR_NOACCESS` from there. Attaching
//!    to `WinSta0` is the bootstrap that unblocks every subsequent
//!    desktop call.
//! 2. Runs an initial [`super::super::system_context::desktop_rebind::try_change_desktop`]
//!    so the thread starts bound to whichever desktop currently
//!    receives input (`Default` if a user is logged in, `Winlogon` if
//!    locked, `Screen-saver.Default` for an active screensaver).
//! 3. Constructs `Enigo` *after* the desktop binding is in place so
//!    enigo's lazy keyboard-layout cache (HKL) is loaded against the
//!    right desktop's window-station ACL.
//! 4. Re-runs `try_change_desktop` before every inject. The cost is
//!    one `OpenInputDesktop` syscall (microseconds); cheap enough at
//!    1000+ events/s during fast typing. `try_change_desktop` is
//!    self-deduping — only fires `SetThreadDesktop` when the input
//!    desktop actually differs from the thread's current binding.
//!
//! ## Why a dedicated thread
//!
//! `SetThreadDesktop` is per-thread. Tokio's work-stealing executor
//! distributes tasks across worker threads non-deterministically, so
//! a tokio-task injection that did `SetThreadDesktop` on one tokio
//! worker could find itself dispatched on a different worker on the
//! next poll, with the wrong desktop binding. Pinning to a single
//! `std::thread` owned by this module sidesteps that entirely.
//!
//! ## Why we don't reconstruct `Enigo` on rebind
//!
//! Enigo's internal state (cached HKL, modifier shadow state) is per-
//! thread, not per-desktop. Once the calling thread is `SetThreadDesktop`-
//! switched, subsequent `SendInput` calls land on the new desktop —
//! the per-thread state moves with the thread, not against it.
//! Rebuilding Enigo each rebind would lose the modifier shadow state
//! (Ctrl-down across a lock would never be released) without buying
//! anything.
//!
//! ## Wire-format passthrough
//!
//! `dispatch` is the same one [`super::enigo_backend`] uses (we re-
//! export it via `pub(super) fn dispatch`). The HID-to-VK table in
//! `hid_to_key` is shared too — this backend is purely a
//! desktop-rebind preamble in front of the same SendInput pipeline,
//! not a different keyboard semantics.
//!
//! ## Failure modes
//!
//! * `attach_to_winsta0` failing at startup → constructor returns
//!   `Err(...)`. Caller falls back to the standard EnigoInjector
//!   which still works in user context (the perUser MSI never gets
//!   here because `worker_role::probe_self()` returns
//!   `WorkerRole::User`).
//! * `try_change_desktop` failing per-event → log at warn and
//!   dispatch against the last-known binding. Better than dropping
//!   the event silently — the operator sees their click land on the
//!   previous desktop, which is wrong but recoverable on the next
//!   event after the rebind succeeds.
//! * Enigo `SendInput` failing per-event → log at debug; events drop
//!   silently (matches the user-context backend's behaviour).

#![cfg(all(
    feature = "system-context",
    target_os = "windows",
    feature = "enigo-input"
))]

use anyhow::{Context, Result, anyhow};
use enigo::Enigo;
use std::sync::mpsc as std_mpsc;
use std::thread;

use super::enigo_backend;
use super::enigo_backend::Job;
use super::{InputInjector, InputMsg, PxJob};
use crate::system_context::desktop_rebind;
use tunnel_core::env::node_env;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenIntegrityLevel,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

/// Async-side handle. Constructor blocks until the worker thread has
/// successfully attached to `WinSta0` AND constructed `Enigo`; then
/// returns. After that all `inject` calls just push onto the mpsc.
pub struct SystemContextInjector {
    tx: std_mpsc::Sender<Job>,
    has_perm: bool,
}

impl SystemContextInjector {
    pub fn new() -> Result<Self> {
        let (tx, rx) = std_mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = std_mpsc::channel::<Result<()>>();

        thread::Builder::new()
            .name("roomlerd-system-input".into())
            .spawn(move || {
                if let Err(e) = desktop_rebind::attach_to_winsta0() {
                    let _ = ready_tx.send(Err(anyhow!("attach_to_winsta0: {e}")));
                    return;
                }
                match desktop_rebind::try_change_desktop() {
                    Ok(desktop_rebind::DesktopChange::Unchanged) => {
                        tracing::info!(
                            "system-context input: thread already bound to input desktop at startup"
                        );
                    }
                    Ok(desktop_rebind::DesktopChange::Switched(name)) => {
                        tracing::info!(
                            %name,
                            "system-context input: bound to input desktop at startup"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            %e,
                            "initial try_change_desktop in system-context input thread — non-fatal, will retry per-event"
                        );
                    }
                }
                // FR-109 — enigo_settings, or `Coordinate::Rel` goes out absolute.
                let settings = enigo_backend::enigo_settings();
                let enigo = match Enigo::new(&settings) {
                    Ok(e) => {
                        let _ = ready_tx.send(Ok(()));
                        e
                    }
                    Err(e) => {
                        let _ =
                            ready_tx.send(Err(anyhow!("enigo init in SYSTEM context: {e}")));
                        return;
                    }
                };
                // rc.120 — log the worker's own integrity level + the foreground
                // window's integrity at startup. The REGAL-112500982 field report
                // (can't type into a "Run as admin" PowerShell, can type into a
                // normal one) is the textbook UIPI signature; this line tells us
                // whether the system-context worker is actually at System IL
                // (UIPI-exempt — so the cause is external/EDR) or has ended up
                // below the elevated target's High IL.
                tracing::info!(
                    worker_integrity = %self_integrity_label(),
                    enable_system_swap = node_env("ENABLE_SYSTEM_SWAP").as_deref().unwrap_or("<unset>"),
                    foreground = %foreground_window_diag(),
                    "system-context input: worker identity diagnostic (rc.120) — keystrokes land only when worker_integrity >= the focused window's integrity (UIPI)"
                );
                run_worker(enigo, rx);
            })
            .context("spawn system-context input thread")?;

        ready_rx
            .recv()
            .context("system-context input thread never responded")??;
        Ok(Self { tx, has_perm: true })
    }
}

/// Worker loop. Receives `InputMsg` commands; rebinds the thread's
/// desktop on each one (cheap; self-deduping); dispatches via the
/// shared enigo dispatcher.
fn run_worker(mut enigo: Enigo, rx: std_mpsc::Receiver<Job>) {
    let mut events_since_log: u64 = 0;
    let mut consec_dispatch_errors: u64 = 0;
    let mut key_events: u64 = 0;
    while let Ok(job) = rx.recv() {
        let msg = match job {
            Job::Input(msg) => msg,
            // FR-92 — keep-busy's reads and moves run on THIS thread, after
            // the same rebind an event gets: a GetCursorPos from a thread
            // still bound to a stale desktop answers for the wrong one.
            Job::Px(px) => {
                if let Ok(desktop_rebind::DesktopChange::Switched(name)) =
                    desktop_rebind::try_change_desktop()
                {
                    tracing::info!(%name, "system-context input: rebound desktop before a keep-busy job");
                    if let Ok(fresh) = Enigo::new(&enigo_backend::enigo_settings()) {
                        enigo = fresh;
                    }
                }
                enigo_backend::run_px_job(&mut enigo, px);
                continue;
            }
        };
        events_since_log = events_since_log.wrapping_add(1);
        // rc.121 — rc.120 PROVED this is NOT UIPI on REGAL-112500982 (worker
        // integrity=System 0x4000 > foreground powershell.exe High 0x3000 ⇒
        // UIPI-exempt) yet letters don't land while Enter/Backspace do. The
        // remaining unknown is the INJECTION PATH: a printable letter arrives as
        // `key_text` → enigo.text() → KEYEVENTF_UNICODE (VK_PACKET — which the
        // Windows console / PSReadLine is known to drop), whereas Enter/Backspace
        // arrive as `key` → a real virtual key (accepted). This logs the path +
        // first-char CLASS + enigo's result so one reproduction settles it.
        //
        // PRIVACY: never log the literal typed text (it can be a password) — only
        // the message kind, char count, and the Unicode class of the first char.
        let key_diag: Option<String> = match &msg {
            InputMsg::Key { code, down, mods } => Some(format!(
                "path=key(real-VK) code=0x{code:02x} down={down} mods=0x{mods:02x}"
            )),
            InputMsg::KeyText { text } => {
                let n = text.chars().count();
                let class = match text.chars().next() {
                    Some(c) if c.is_alphabetic() => "alpha",
                    Some(c) if c.is_ascii_digit() => "digit",
                    Some(c) if c.is_ascii_punctuation() => "punct",
                    Some(c) if c.is_whitespace() => "space",
                    Some(_) => "other",
                    None => "empty",
                };
                let ascii = text.chars().next().map(|c| c.is_ascii()).unwrap_or(false);
                Some(format!(
                    "path=key_text(rc.122 real-VK+scancode, unicode fallback) chars={n} first_class={class} first_ascii={ascii}"
                ))
            }
            _ => None,
        };
        let log_key = if key_diag.is_some() {
            key_events = key_events.wrapping_add(1);
            key_events <= 30 || key_events.is_multiple_of(256)
        } else {
            false
        };
        match desktop_rebind::try_change_desktop() {
            Ok(desktop_rebind::DesktopChange::Unchanged) => {
                // Most common branch by ~1000:1. Stay quiet.
            }
            Ok(desktop_rebind::DesktopChange::Switched(name)) => {
                tracing::info!(
                    %name,
                    events_since_last_switch = events_since_log,
                    "system-context input: rebound desktop before dispatch"
                );
                events_since_log = 0;
                // Reset Enigo's per-thread state. After SetThreadDesktop
                // crosses a desktop boundary the previous Enigo's
                // cached HKL / modifier shadow state is stale; held
                // modifiers can't be released because their down-
                // events landed on the OLD desktop. Rebuilding Enigo
                // is cheap (~ms) and resets cached state cleanly.
                if let Ok(fresh) = Enigo::new(&enigo_backend::enigo_settings()) {
                    enigo = fresh;
                }
            }
            Err(e) => {
                tracing::warn!(
                    %e,
                    "try_change_desktop before input dispatch failed; dispatching against last-known binding"
                );
            }
        }
        let dispatch_result = enigo_backend::dispatch_for_external(&mut enigo, msg.clone());
        // rc.121 — log the path + enigo result for key events (rate-limited). If
        // `dispatch=ok` but the letter never appears in PowerShell, enigo injected
        // it (KEYEVENTF_UNICODE) and the CONSOLE dropped it → fix = inject typed
        // chars as real virtual keys, not VK_PACKET. If `dispatch=err`, injection
        // itself failed. If letters arrive as `path=key(real-VK)` (not key_text),
        // the deployed browser is sending VK codes → fix is browser-side.
        if log_key && let Some(desc) = &key_diag {
            let dispatch = match &dispatch_result {
                Ok(_) => "ok".to_string(),
                Err(e) => format!("err: {e}"),
            };
            tracing::info!(
                seq = key_events,
                detail = %desc,
                dispatch = %dispatch,
                worker_integrity = %self_integrity_label(),
                foreground = %foreground_window_diag(),
                "system-context input: key dispatch diagnostic (rc.121)"
            );
        }
        match dispatch_result {
            Ok(_) => {
                consec_dispatch_errors = 0;
            }
            Err(e) => {
                consec_dispatch_errors = consec_dispatch_errors.saturating_add(1);
                // First error in a streak: attempt explicit rebind +
                // single retry. SendInput / SetCursorPos commonly
                // fail ACCESS_DENIED when the desktop's handle was
                // recycled mid-session (lock/unlock); a fresh
                // try_change_desktop + retry recovers without
                // session restart.
                if consec_dispatch_errors == 1 {
                    tracing::warn!(
                        %e,
                        "system-context input dispatch error; forcing rebind + retry"
                    );
                    let _ = desktop_rebind::try_change_desktop();
                    if let Ok(fresh) = Enigo::new(&enigo_backend::enigo_settings()) {
                        enigo = fresh;
                    }
                    if let Err(e2) = enigo_backend::dispatch_for_external(&mut enigo, msg) {
                        tracing::warn!(
                            error = %e2,
                            "system-context input retry-after-rebind also failed"
                        );
                    }
                } else if consec_dispatch_errors.is_multiple_of(32) {
                    // Streak of failures; rate-limit logging to once
                    // per 32 consecutive errors so we don't spam.
                    tracing::warn!(
                        consec_errors = consec_dispatch_errors,
                        %e,
                        "system-context input dispatch failing in a streak"
                    );
                }
            }
        }
    }
    tracing::info!("system-context input worker thread exiting (cmd channel closed)");
}

impl InputInjector for SystemContextInjector {
    fn inject(&mut self, event: InputMsg) -> Result<()> {
        self.tx
            .send(Job::Input(event))
            .map_err(|_| anyhow!("system-context input worker exited"))
    }

    fn has_permission(&self) -> bool {
        self.has_perm
    }

    fn cursor_px(&mut self) -> Result<(i32, i32)> {
        super::px_round_trip(&self.tx, |reply| Job::Px(PxJob::Locate(reply)))
    }

    fn move_px(&mut self, x: i32, y: i32) -> Result<()> {
        super::px_round_trip(&self.tx, |reply| Job::Px(PxJob::Move { x, y, reply }))
    }

    fn buttons_held(&mut self) -> Result<bool> {
        super::px_round_trip(&self.tx, |reply| Job::Px(PxJob::Buttons(reply)))
    }
}

// ───────────────────────── rc.120 input diagnostics ─────────────────────────
// REGAL-112500982 (rc.116): keystrokes reach a normal (Medium-IL) PowerShell
// but NOT a "Run as administrator" (High-IL) one. That is the textbook UIPI
// integrity block — and `SendInput` returns SUCCESS even when UIPI silently
// drops the event, so nothing showed up in the logs. We never logged the
// worker's own integrity level, so we could not tell whether the system-context
// worker is genuinely at System IL (UIPI-exempt — pointing at an external
// blocker like corporate EDR) or has somehow ended up below the elevated
// target's High IL. These helpers surface both, so one field session settles it.

/// Map a Windows mandatory-integrity RID to a human label.
fn integrity_rid_to_label(rid: u32) -> &'static str {
    match rid {
        0x0000 => "Untrusted",
        0x1000 => "Low",
        0x2000 => "Medium",
        0x2100 => "MediumPlus",
        0x3000 => "High",
        0x4000 => "System",
        0x5000 => "ProtectedProcess",
        _ => "Unknown",
    }
}

/// Read a token's integrity level — the single subauthority of its
/// `TokenIntegrityLevel` label SID (an `S-1-16-<rid>`). Returns e.g.
/// `"System (0x4000)"`. The RID lives at byte offset 8..12 of the SID, same
/// fixed-layout read [`crate::system_context::worker_role`] uses for the user SID.
fn token_integrity_label(token: HANDLE) -> String {
    // SAFETY: `token` is a valid TOKEN_QUERY handle owned by the caller. The
    // two-call GetTokenInformation size-discovery pattern is documented; we read
    // only the fixed SID prefix the OS guarantees self-consistent.
    unsafe {
        let mut needed: u32 = 0;
        let _ = GetTokenInformation(
            token,
            TokenIntegrityLevel,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            return "err:needed0".to_string();
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenIntegrityLevel,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        );
        if ok == 0 {
            return format!("err:gti:{}", GetLastError());
        }
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid as *const u8;
        if sid.is_null() {
            return "err:nullsid".to_string();
        }
        if *sid.add(1) == 0 {
            return "err:subcount0".to_string();
        }
        let rid = u32::from_le_bytes([*sid.add(8), *sid.add(9), *sid.add(10), *sid.add(11)]);
        format!("{} (0x{rid:04x})", integrity_rid_to_label(rid))
    }
}

/// Integrity label of the calling (worker) process.
fn self_integrity_label() -> String {
    // SAFETY: GetCurrentProcess is a pseudo-handle; OpenProcessToken with
    // TOKEN_QUERY over our own process is documented infallible. Handle closed
    // before return.
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return format!("err:opt:{}", GetLastError());
        }
        let label = token_integrity_label(tok);
        CloseHandle(tok);
        label
    }
}

/// Trailing path component of a Windows path (after the last `\` or `/`).
fn basename(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Snapshot of the foreground window's owning process: exe basename, pid, and
/// integrity level — i.e. the window keystrokes would land in. If the worker's
/// IL is below this IL, UIPI silently drops the input (the REGAL symptom).
fn foreground_window_diag() -> String {
    // SAFETY: all calls take valid args; every opened handle is closed. A null
    // HWND / failed open returns a sentinel string rather than dereferencing.
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.is_null() {
            return "fg=none".to_string();
        }
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == 0 {
            return "fg=nopid".to_string();
        }
        let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if proc.is_null() {
            return format!("fg_pid={pid} open_err={}", GetLastError());
        }
        let mut nbuf = [0u16; 260];
        let mut nsz: u32 = nbuf.len() as u32;
        let exe = if QueryFullProcessImageNameW(proc, 0, nbuf.as_mut_ptr(), &mut nsz) != 0 {
            let full = String::from_utf16_lossy(&nbuf[..nsz as usize]);
            basename(&full).to_string()
        } else {
            "?".to_string()
        };
        let mut tok: HANDLE = std::ptr::null_mut();
        let il = if OpenProcessToken(proc, TOKEN_QUERY, &mut tok) != 0 {
            let l = token_integrity_label(tok);
            CloseHandle(tok);
            l
        } else {
            format!("opt_err={}", GetLastError())
        };
        CloseHandle(proc);
        format!("fg_exe={exe} fg_pid={pid} fg_integrity={il}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_labels_cover_known_rids() {
        assert_eq!(integrity_rid_to_label(0x2000), "Medium");
        assert_eq!(integrity_rid_to_label(0x3000), "High");
        assert_eq!(integrity_rid_to_label(0x4000), "System");
        assert_eq!(integrity_rid_to_label(0x1234), "Unknown");
    }

    #[test]
    fn basename_extracts_trailing_component() {
        assert_eq!(
            basename(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "powershell.exe"
        );
        assert_eq!(basename("powershell.exe"), "powershell.exe");
        assert_eq!(basename("/usr/bin/foo"), "foo");
    }

    #[test]
    fn self_integrity_label_is_nonempty() {
        // Under the test runner this is the developer's process (Medium/High);
        // we only assert it produces a real label, not an error sentinel.
        let l = self_integrity_label();
        assert!(!l.is_empty());
        assert!(!l.starts_with("err:"), "unexpected error label: {l}");
    }

    #[test]
    fn injector_is_send() {
        // ScreenCapture / InputInjector both require Send. The cmd_tx
        // is std::mpsc::Sender<InputMsg> which is Send when InputMsg
        // is Send (verified separately). Lock at compile time.
        fn assert_send<T: Send>() {}
        assert_send::<SystemContextInjector>();
    }

    #[test]
    fn impls_input_injector_trait() {
        fn assert_trait<T: InputInjector>() {}
        assert_trait::<SystemContextInjector>();
    }

    #[test]
    fn constructor_does_not_panic() {
        // Under the user-context test runner: attach_to_winsta0 is
        // idempotent (already on WinSta0); try_change_desktop returns
        // Unchanged; Enigo::new() succeeds. CI without a desktop:
        // Enigo::new() may fail; we accept Err. Lock against panic.
        let res = SystemContextInjector::new();
        drop(res);
    }
}
