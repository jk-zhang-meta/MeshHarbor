// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `SetThreadDesktop` rebind primitives for the M3 A1 SYSTEM-context
//! input thread.
//!
//! ## Lifecycle
//!
//! When the SCM-launched LocalSystem service spawns a SYSTEM-in-
//! session-N worker via [`super::winlogon_token::spawn_worker_as_system`],
//! that worker starts in the SCM's **window station**
//! `Service-0x0-3e7$` (the noninteractive Session 0 winstation).
//! Every `OpenDesktopW("Default" | "Winlogon")` call from there
//! returns `ERROR_NOACCESS` because those desktops live under
//! `WinSta0`, not the SCM's. So the worker MUST first call
//! [`attach_to_winsta0`] before doing any desktop work — that's a
//! one-time bootstrap step at process startup, idempotent if the
//! process is already on WinSta0.
//!
//! Once attached to WinSta0, the worker's input thread runs a
//! [`try_change_desktop`] check before each SendInput dispatch. The
//! function calls `OpenInputDesktop()` to learn which desktop
//! currently receives input, compares to the desktop the thread is
//! already attached to, and `SetThreadDesktop`-switches if they
//! differ. This is the lazy-rebind pattern from RustDesk
//! `windows.rs:935-956` — instead of polling for desktop changes we
//! react to them at the natural granularity of input dispatch.
//!
//! ## Why a dedicated input thread
//!
//! `SetThreadDesktop` is per-thread. Tokio's work-stealing executor
//! distributes tasks across worker threads non-deterministically, so
//! an input task that did `SetThreadDesktop` on one tokio worker
//! could find itself running on a different worker on the next
//! poll, with the wrong desktop binding. The M3 A1 input pump is
//! therefore a dedicated `std::thread` that owns the binding, fed
//! by a `tokio::sync::mpsc` channel from the WS handler.
//!
//! ## What `try_change_desktop` returns
//!
//! [`DesktopChange`] carries the result so callers can decide
//! whether to bail-on-change (the capture pump does this — a
//! desktop swap means the captured frame is stale and the encoder
//! needs to flush) or just keep going (the input thread does this —
//! the next event will land on the new desktop). The string-typed
//! `Switched(String)` arm carries the new desktop name for logging
//! / surfacing to the browser via the `rc:desktop_changed` control
//! message.
//!
//! ## Failure modes
//!
//! `OpenInputDesktop` returns `Ok(None)` on access-denied (DACL or
//! winstation-not-attached). Under the SYSTEM-context worker that's
//! a hard error — the supervisor's contract is "you're SYSTEM, you
//! see Winlogon"; if the call fails the M3 A1 path can't proceed.
//! [`try_change_desktop`] surfaces this as `Err` so the input thread
//! can exit and let the supervisor respawn.
//!
//! `SetThreadDesktop` fails when the calling thread owns hooks /
//! windows (the OS forbids switching while you're a window owner).
//! The M3 A1 input thread never creates windows, so this should
//! not fire — surface as `Err` if it does.

#![cfg(target_os = "windows")]

use anyhow::{Result, bail};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{FALSE, GetLastError};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseWindowStation, HWINSTA, OpenWindowStationW, SetProcessWindowStation, SetThreadDesktop,
};

use crate::win_service::desktop::{
    OwnedDesktop, current_thread_desktop_name, desktop_name_of, open_input_desktop_for_injection,
};

/// `WINSTA_ALL_ACCESS` — full-access mask for `OpenWindowStationW`.
/// Inlined here because windows-sys' `Win32_System_StationsAndDesktops`
/// feature doesn't currently re-export the constant. Value matches
/// `winuser.h`.
const WINSTA_ALL_ACCESS: u32 = 0x37F;

/// Result of [`try_change_desktop`]. Lets callers distinguish "no
/// change, carry on" from "switched, log + force keyframe" without
/// having to compare two strings on every input event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopChange {
    /// The thread was already attached to the current input desktop.
    /// The most common case — operators don't trigger a desktop swap
    /// per click.
    Unchanged,
    /// The input desktop differs from what the thread had; we
    /// `SetThreadDesktop`-switched. The new name is carried for
    /// logging + the `rc:desktop_changed` control-DC message.
    Switched(String),
}

/// Attach the calling process to `WinSta0`. **Idempotent** — calling
/// this from a process that's already on WinSta0 succeeds silently
/// (the OS treats it as a no-op `SetProcessWindowStation` to the
/// same handle). Call once at SYSTEM-context worker startup;
/// subsequent calls are safe but unnecessary.
///
/// SAFETY-RELEVANT: changes process-wide window-station state. If
/// the worker is multi-threaded at the call site (it shouldn't be —
/// this is one of the first things `main` does), a concurrent thread
/// could be mid-OpenDesktopW expecting the prior winstation. The M3
/// A1 worker is single-threaded at this point in startup so the
/// hazard is theoretical.
pub fn attach_to_winsta0() -> Result<()> {
    let mut wide: Vec<u16> = OsStr::new("WinSta0").encode_wide().collect();
    wide.push(0);
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer alive for
    // the call. WINSTA_ALL_ACCESS is documented; FALSE means we
    // don't want to inherit the handle.
    let h: HWINSTA = unsafe { OpenWindowStationW(wide.as_ptr(), FALSE, WINSTA_ALL_ACCESS) };
    if h.is_null() {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("OpenWindowStationW(\"WinSta0\") failed: win32 error {err}");
    }
    // SAFETY: `h` is a valid HWINSTA we own.
    let ok = unsafe { SetProcessWindowStation(h) };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        // SAFETY: `h` was non-null and we own it; close on the
        // failure path.
        unsafe {
            CloseWindowStation(h);
        }
        bail!("SetProcessWindowStation(WinSta0) failed: win32 error {err}");
    }
    // Deliberately do NOT close `h` — the process now owns the
    // attachment via the handle. CloseWindowStation here would
    // detach. The handle leaks on shutdown, which is fine; the OS
    // reclaims it when the process exits.
    Ok(())
}

/// Compare the calling thread's current desktop binding against the
/// input desktop and `SetThreadDesktop` rebind if they differ.
/// Returns [`DesktopChange::Unchanged`] when no rebind was needed,
/// [`DesktopChange::Switched`] (with the new name) when one was.
///
/// Cost: one `OpenInputDesktop` syscall per call. Fast enough to run
/// before every input event in practice (microseconds on a typical
/// Win11 box) but the input thread can dedupe by tracking the last
/// observed desktop name and only retrying after N events / time.
pub fn try_change_desktop() -> Result<DesktopChange> {
    let current_name = current_thread_desktop_name()?;
    let input = match open_input_desktop_for_injection()? {
        Some(d) => d,
        None => bail!(
            "OpenInputDesktop(GENERIC_READ|GENERIC_WRITE) returned access-denied — \
             SYSTEM-context worker cannot reach the input desktop. Either we're \
             not attached to WinSta0 (call attach_to_winsta0() at startup) or we \
             lost SYSTEM somewhere upstream"
        ),
    };
    let target_name = desktop_name_of(input.raw())?;
    // Always SetThreadDesktop, even when names match. The desktop
    // HANDLE may have changed underneath us — `OpenInputDesktop`
    // returns a fresh handle for the same desktop after Win+L /
    // unlock cycles, and the thread's previous binding (still on
    // the OLD handle) loses its WRITE access rights when the OS
    // recycles the desktop's session_id. Re-binding to the FRESH
    // handle every time costs one syscall (~µs) but means the
    // thread's access token is always current. Field repro
    // the field-test host rc.8 (2026-05-06): try_change_desktop returned
    // Unchanged across a Win+L cycle (names matched stale handle)
    // but SendInput failed ACCESS_DENIED because the bound handle
    // had stale rights.
    set_thread_desktop(&input)?;
    if current_name == target_name {
        return Ok(DesktopChange::Unchanged);
    }
    Ok(DesktopChange::Switched(target_name))
}

/// `SetThreadDesktop(desk)`. Per-thread; caller must guarantee `desk`
/// outlives every operation made under it on this thread. RAII via
/// `OwnedDesktop` + a single `attach`-and-leak in the input thread's
/// loop covers this trivially.
///
/// Wraps the `win_service::desktop::set_thread_desktop` of the same
/// shape — duplicated here only so the M3 A1 module exports a
/// self-contained surface. The implementation cost is one FFI call.
pub fn set_thread_desktop(desk: &OwnedDesktop) -> Result<()> {
    // SAFETY: `desk.raw()` is a valid HDESK we own.
    let ok = unsafe { SetThreadDesktop(desk.raw()) };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("SetThreadDesktop failed: win32 error {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winsta_all_access_constant_is_correct() {
        // 0x37F is the documented WINSTA_ALL_ACCESS value from
        // winuser.h. Lock it so a pasting accident doesn't change
        // the access mask.
        assert_eq!(WINSTA_ALL_ACCESS, 0x37F);
    }

    #[test]
    fn desktop_change_unchanged_eq_self() {
        assert_eq!(DesktopChange::Unchanged, DesktopChange::Unchanged);
    }

    #[test]
    fn desktop_change_switched_compares_by_name() {
        assert_eq!(
            DesktopChange::Switched("Winlogon".into()),
            DesktopChange::Switched("Winlogon".into())
        );
        assert_ne!(
            DesktopChange::Switched("Winlogon".into()),
            DesktopChange::Switched("Default".into())
        );
        assert_ne!(
            DesktopChange::Switched("Default".into()),
            DesktopChange::Unchanged
        );
    }

    #[test]
    fn try_change_desktop_does_not_panic() {
        // The user-context test runner is on WinSta0 + Default
        // already, so try_change_desktop should return
        // DesktopChange::Unchanged. If something pathological
        // (CI runner on a non-default winstation) happens, an Err
        // is acceptable — we lock against panic, not specific
        // outcomes.
        let _ = try_change_desktop();
    }

    #[test]
    fn attach_to_winsta0_is_idempotent_under_user_context() {
        // The cargo test runner is already on WinSta0. attach_to_
        // winsta0 should succeed (re-attach to the same winstation
        // is a no-op that the OS accepts). If it errors, we're on
        // a stripped-down CI runner that lacks the ACL — accept
        // either outcome, lock against panic.
        let _ = attach_to_winsta0();
    }
}
