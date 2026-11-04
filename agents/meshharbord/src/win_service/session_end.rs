// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P4d — a per-user daemon's clean stop at sign-out and shutdown.
//!
//! A per-user daemon (the Scheduled Task install, or a hand-run `meshharbord run`)
//! is no service: Windows ends it with the rest of the session at sign-out and
//! at shutdown, and nothing tells it first. A console program's control handler
//! would hear `CTRL_LOGOFF_EVENT` / `CTRL_SHUTDOWN_EVENT`, but only while the
//! process has not loaded `user32.dll`, and the daemon loads it (capture, input,
//! the indicator). What Windows sends such a process instead is
//! `WM_QUERYENDSESSION` and `WM_ENDSESSION`, to its top-level windows. So this
//! module owns one: hidden, never shown, on a thread of its own that does
//! nothing but pump its messages.
//!
//! On a `WM_ENDSESSION` that ends the session, it raises the flag the daemon's
//! `terminate_signal` polls, which takes the same OS-initiated arm a Unix
//! SIGTERM and the SCM host's stop event take: an ephemeral device unenrolls,
//! and the clean shutdown is marked. Then it WAITS, bounded
//! ([`SESSION_END_BUDGET`]), for that shutdown to reach disk
//! ([`clean_stop_done`]): once the handler returns, Windows may end the process
//! at any moment.
//!
//! What it never acts on:
//! - `WM_QUERYENDSESSION`: a question, still cancellable. It answers yes and
//!   does nothing; only `WM_ENDSESSION` with `wParam` TRUE is final.
//! - `ENDSESSION_CLOSEAPP`: Restart Manager asking applications to close so an
//!   installer can replace their files, which is not the session ending. Read
//!   as one, a manual MSI upgrade would unenroll an ephemeral device (the trap
//!   #1683 names for the service). Ignored, the installer meets the daemon as
//!   it did before P4d. An auto-update stops the daemon by its own, internal arm.
//! - `WM_CLOSE`: what a `taskkill` without `/F` posts. `DefWindowProc` would
//!   destroy the window, and every later sign-out notice with it.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use std::sync::{Condvar, Mutex, Once};
use std::time::Duration;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, ENDSESSION_CLOSEAPP, ENDSESSION_LOGOFF,
    GetMessageW, MSG, RegisterClassExW, TranslateMessage, WM_CLOSE, WM_ENDSESSION,
    WM_QUERYENDSESSION, WNDCLASSEXW, WS_EX_TOOLWINDOW, WS_OVERLAPPED,
};

/// Why the session is ending, for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The person is signing out (`ENDSESSION_LOGOFF`).
    SignOut,
    /// Windows is shutting down or restarting, `ENDSESSION_CRITICAL` included.
    Shutdown,
}

/// What a `WM_ENDSESSION` means for the daemon. `ending` is its `wParam`
/// (FALSE: the end was cancelled), `flags` its `lParam`. `None`: not a session
/// end this daemon stops for (see the module docs).
pub fn classify(ending: bool, flags: u32) -> Option<SessionEnd> {
    if !ending || flags & ENDSESSION_CLOSEAPP != 0 {
        return None;
    }
    if flags & ENDSESSION_LOGOFF != 0 {
        Some(SessionEnd::SignOut)
    } else {
        Some(SessionEnd::Shutdown)
    }
}

/// How long the window holds `WM_ENDSESSION` for the clean stop. The slowest
/// steps are each capped: an ephemeral device's unenroll at 3 s, and the hive
/// wind-down at 3 s where sessions run. Usually the whole stop takes well under
/// a second. Windows does not wait on a program at sign-out for long, and the
/// server's reaper collects an ephemeral device whose unenroll was cut short.
pub const SESSION_END_BUDGET: Duration = Duration::from_secs(5);

const NOT_ENDING: u8 = 0;
const SIGN_OUT: u8 = 1;
const SHUTDOWN: u8 = 2;

static ENDING: AtomicU8 = AtomicU8::new(NOT_ENDING);

/// The session end the window saw, if any. The daemon's stop wait polls it.
pub fn ending() -> Option<SessionEnd> {
    match ENDING.load(Ordering::Acquire) {
        SIGN_OUT => Some(SessionEnd::SignOut),
        SHUTDOWN => Some(SessionEnd::Shutdown),
        _ => None,
    }
}

fn note_ending(kind: SessionEnd) {
    let v = match kind {
        SessionEnd::SignOut => SIGN_OUT,
        SessionEnd::Shutdown => SHUTDOWN,
    };
    ENDING.store(v, Ordering::Release);
}

static DONE: Mutex<bool> = Mutex::new(false);
static DONE_CV: Condvar = Condvar::new();

/// The daemon's half: the clean shutdown is on disk (an ephemeral device's
/// unenroll, `mark_clean_shutdown`). Called on every exit that reaches that
/// point; only a window holding `WM_ENDSESSION` waits for it.
pub fn clean_stop_done() {
    let mut done = DONE.lock().unwrap_or_else(|e| e.into_inner());
    *done = true;
    DONE_CV.notify_all();
}

/// `true` when [`clean_stop_done`] was called within `budget`.
fn wait_for_clean_stop(budget: Duration) -> bool {
    let done = DONE.lock().unwrap_or_else(|e| e.into_inner());
    let (done, _) = DONE_CV
        .wait_timeout_while(done, budget, |d| !*d)
        .unwrap_or_else(|e| e.into_inner());
    *done
}

/// The window, once it exists (tests send it messages).
static WINDOW: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// `ROOMLERD_SESSION_END`, on unless set false. Off, no window is made, and a
/// sign-out or shutdown ends the daemon unannounced, as before P4d.
pub fn enabled() -> bool {
    tunnel_core::env::flag("SESSION_END", true)
}

/// Start the window thread, once per process. Best-effort: when the window
/// cannot be made (no window station to make it in), it says so and the
/// daemon stops at sign-out as it did before P4d.
pub fn watch() {
    static START: Once = Once::new();
    START.call_once(|| {
        if !enabled() {
            tracing::info!("no session-end window (ROOMLERD_SESSION_END=0)");
            return;
        }
        let spawned = std::thread::Builder::new()
            .name("roomlerd-session-end".into())
            .spawn(|| {
                if let Err(e) = run_window() {
                    tracing::warn!(
                        error = %e,
                        "no session-end window: at sign-out or shutdown this daemon will be \
                         ended without a clean stop (an ephemeral device is left to the reaper)"
                    );
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(error = %e, "could not start the session-end window's thread");
        }
    });
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn run_window() -> std::io::Result<()> {
    let class = wide("RoomlerdSessionEnd");
    let title = wide("roomlerd");
    // SAFETY: every pointer handed over is valid for its call: `class` and
    // `title` are NUL-terminated buffers that outlive the window (this function
    // never returns while the window lives), `wc` is a fully initialised local,
    // and `msg` is a live local the loop owns.
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        if RegisterClassExW(&wc) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Top-level (no parent, and NOT `HWND_MESSAGE`: a message-only window
        // hears no broadcast, and the session end is one), never shown, sized
        // zero, and kept off Alt+Tab and the taskbar by `WS_EX_TOOLWINDOW`.
        let hwnd = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null::<c_void>(),
        );
        if hwnd.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        WINDOW.store(hwnd, Ordering::Release);
        tracing::debug!("session-end window up: a sign-out or shutdown stops this daemon cleanly");
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        // Yes, end it: the daemon never vetoes a sign-out.
        WM_QUERYENDSESSION => 1,
        WM_ENDSESSION => {
            if let Some(kind) = classify(wparam != 0, lparam as u32) {
                note_ending(kind);
                tracing::info!(
                    ?kind,
                    "Windows is ending the session: stopping cleanly before it ends this daemon"
                );
                if wait_for_clean_stop(SESSION_END_BUDGET) {
                    tracing::info!("the clean stop is on disk; the session may end");
                } else {
                    tracing::warn!(
                        budget_s = SESSION_END_BUDGET.as_secs(),
                        "the clean stop did not finish in time; Windows ends this daemon anyway \
                         (the server's reaper collects an ephemeral device)"
                    );
                }
            }
            0
        }
        // Not a stop: keep the window, or the next sign-out goes unheard.
        WM_CLOSE => 0,
        // SAFETY: the arguments are the ones this window procedure was called
        // with, passed on unchanged.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        ENDSESSION_CRITICAL, IsWindow, SendMessageW,
    };

    #[test]
    fn only_a_final_session_end_stops_the_daemon() {
        // Cancelled: someone vetoed the WM_QUERYENDSESSION.
        assert_eq!(classify(false, ENDSESSION_LOGOFF), None);
        assert_eq!(classify(false, 0), None);
        assert_eq!(classify(true, ENDSESSION_LOGOFF), Some(SessionEnd::SignOut));
        assert_eq!(classify(true, 0), Some(SessionEnd::Shutdown));
        assert_eq!(
            classify(true, ENDSESSION_CRITICAL),
            Some(SessionEnd::Shutdown)
        );
        // Restart Manager, alone or with any other flag, is an installer
        // asking for files, never the session ending.
        assert_eq!(classify(true, ENDSESSION_CLOSEAPP), None);
        assert_eq!(
            classify(true, ENDSESSION_CLOSEAPP | ENDSESSION_CRITICAL),
            None
        );
        assert_eq!(
            classify(true, ENDSESSION_CLOSEAPP | ENDSESSION_LOGOFF),
            None
        );
    }

    /// The real window, end to end: Windows' messages, sent to it the way
    /// Windows sends them. One test, because the flag it raises is the
    /// process's own.
    #[test]
    fn the_window_stops_the_daemon_on_a_session_end_and_on_nothing_else() {
        watch();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let hwnd = loop {
            let h = WINDOW.load(Ordering::Acquire);
            if !h.is_null() {
                break h;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the session-end window never came up"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        // SAFETY: `hwnd` is the live window `watch` made; each message is one
        // its procedure handles, with plain integer arguments.
        unsafe {
            assert_eq!(
                SendMessageW(hwnd, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF as LPARAM),
                1
            );
            assert_eq!(ending(), None, "a question is not the end");
            SendMessageW(hwnd, WM_ENDSESSION, 1, ENDSESSION_CLOSEAPP as LPARAM);
            assert_eq!(ending(), None, "Restart Manager is not the session ending");
            SendMessageW(hwnd, WM_ENDSESSION, 0, ENDSESSION_LOGOFF as LPARAM);
            assert_eq!(ending(), None, "a cancelled end is not the end");
            SendMessageW(hwnd, WM_CLOSE, 0, 0);
            assert_ne!(IsWindow(hwnd), 0, "WM_CLOSE must not take the window down");
            // The daemon's clean stop is already on disk here, so the window
            // must return at once rather than wait out its budget.
            clean_stop_done();
            let sent = std::time::Instant::now();
            SendMessageW(hwnd, WM_ENDSESSION, 1, ENDSESSION_LOGOFF as LPARAM);
            assert!(sent.elapsed() < Duration::from_secs(2));
        }
        assert_eq!(ending(), Some(SessionEnd::SignOut));
    }
}
