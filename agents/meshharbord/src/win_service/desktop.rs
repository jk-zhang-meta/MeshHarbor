// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Win32 desktop wrappers for the M3 SYSTEM-context capture path.
//!
//! Background. A Windows session has multiple "desktops" within it.
//! The user's normal interactive surface is `winsta0\Default`; the
//! Windows logon UI (lock screen, password prompt, UAC consent) lives
//! on `winsta0\Winlogon`. A given thread is attached to exactly one
//! desktop at a time and can only capture / inject input on that
//! desktop. The user-context worker the M2 supervisor spawns lives on
//! `Default` and cannot follow focus to `Winlogon` (the Winlogon DACL
//! denies access to non-SYSTEM principals).
//!
//! M3's job is to add a SYSTEM-context capture+input path that polls
//! the *input desktop* (the desktop currently receiving keyboard +
//! mouse input) and `SetThreadDesktop`-switches to it on each change.
//! These wrappers are the building blocks.
//!
//! Feature gate: this module is `pub(crate)` and the `system-capture-
//! smoke` CLI subcommand surfaces it for the spike binary. The
//! supervisor wires it in once the spike confirms WGC capture works
//! from session 0 on a real Win11 box (M3 derisking step per the
//! 2026-05-02 critic review).

#![cfg(target_os = "windows")]

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, FALSE, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetThreadDesktop, GetUserObjectInformationW, HDESK, OpenDesktopW,
    OpenInputDesktop, SetThreadDesktop, UOI_NAME,
};

/// RAII for `HDESK`. Calls `CloseDesktop` on drop. The handle returned
/// by `GetThreadDesktop` is a *non-owning* alias and must NOT be
/// closed; that path returns a `BorrowedDesktop` instead. Keeping the
/// two types distinct at the type level makes "do we own this?" a
/// compile-time question.
pub struct OwnedDesktop {
    h: HDESK,
}

impl OwnedDesktop {
    fn new(h: HDESK) -> Option<Self> {
        // HDESK is a pointer-sized opaque integer; null is the failure
        // sentinel from the OpenDesktop family.
        if h.is_null() { None } else { Some(Self { h }) }
    }

    pub fn raw(&self) -> HDESK {
        self.h
    }
}

impl Drop for OwnedDesktop {
    fn drop(&mut self) {
        // SAFETY: we own the handle (constructed via OpenDesktopW or
        // OpenInputDesktop). CloseDesktop on a valid HDESK is the
        // canonical cleanup; failure is logged and ignored — there's
        // nothing to do about it from a Drop impl.
        unsafe {
            CloseDesktop(self.h);
        }
    }
}

/// `OpenDesktopW("<name>", 0, FALSE, GENERIC_READ)`. `name` is the
/// desktop name relative to the calling thread's window station, e.g.
/// `"Default"` or `"Winlogon"`. Returns `Ok(None)` and a debug log
/// when access is denied so the caller can decide whether to fall
/// back to a different strategy (the user-context worker can't open
/// Winlogon; SYSTEM can).
///
/// Access mask is `GENERIC_READ` only — `DESKTOP_SWITCHDESKTOP`
/// requires `SE_TCB_NAME` privilege which is reserved for SYSTEM /
/// LocalService / NetworkService and which non-SYSTEM callers
/// (including admins) do NOT have. Requesting it false-fails the
/// open under user context with `ACCESS_DENIED`, which is the bug
/// that bricked input on agents 0.2.0–0.2.6 (see
/// `project_input_regression_0_2_x.md`). The codebase never calls
/// `SwitchDesktop`, so the right was always dead weight.
pub fn open_desktop_by_name(name: &str) -> Result<Option<OwnedDesktop>> {
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer alive for the
    // call. The remaining args are documented constants. Out-error is
    // checked via GetLastError immediately.
    let h: HDESK = unsafe { OpenDesktopW(wide.as_ptr(), 0, FALSE, GENERIC_READ) };
    if h.is_null() {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        if err == ERROR_ACCESS_DENIED {
            tracing::debug!(
                desktop = name,
                "open_desktop_by_name: access denied (need SYSTEM context for {name})"
            );
            return Ok(None);
        }
        bail!("OpenDesktopW({name:?}) failed (err {err})");
    }
    Ok(OwnedDesktop::new(h))
}

/// `OpenInputDesktop(0, FALSE, GENERIC_READ)`. Returns the desktop
/// currently receiving input (which on a typical Win11 host swaps
/// between `Default` and `Winlogon` as the user locks/unlocks, hits
/// Ctrl+Alt+Del, or accepts a UAC prompt). Returns `Ok(None)` on
/// access denied.
///
/// Access mask is `GENERIC_READ` only — see `open_desktop_by_name`
/// for the full rationale (TL;DR: `DESKTOP_SWITCHDESKTOP` requires
/// `SE_TCB_NAME` which non-SYSTEM callers lack, and we never call
/// `SwitchDesktop`). This call is the lock-state probe's hot path:
/// requesting the privileged right made it false-positive `Locked`
/// for every user-context worker, dropping all input.
pub fn open_input_desktop() -> Result<Option<OwnedDesktop>> {
    // SAFETY: zero flags is a documented call form; out-error is
    // checked.
    let h: HDESK = unsafe { OpenInputDesktop(0, FALSE, GENERIC_READ) };
    if h.is_null() {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        if err == ERROR_ACCESS_DENIED {
            tracing::debug!("open_input_desktop: access denied (need SYSTEM context)");
            return Ok(None);
        }
        bail!("OpenInputDesktop failed (err {err})");
    }
    Ok(OwnedDesktop::new(h))
}

/// `OpenInputDesktop(0, FALSE, GENERIC_READ | GENERIC_WRITE)`. Same as
/// [`open_input_desktop`] but with the WRITE access mask, which the
/// SystemContext input thread needs in order for `SendInput` /
/// `SetCursorPos` to succeed after `SetThreadDesktop` binding.
///
/// **Why a separate function**: the user-context lock-state probe
/// path (`lock_state.rs`) must NOT request `GENERIC_WRITE` — most
/// users don't have it on Winlogon's DACL even after Win+L, and the
/// extra ask false-positives `Locked` for every user-context worker.
/// That regression was the entire 0.2.7 hotfix (see
/// `project_input_regression_0_2_x.md`). This helper is gated to the
/// SystemContext path where we ARE SYSTEM and DO have full write
/// rights to both Default and Winlogon. Field repro on the field-test host
/// during 0.3.0-rc.7 and rc.8 testing (2026-05-06): `Zugriff
/// verweigert (os error 5)` spam at roughly 50/s during the lock
/// screen because the thread was bound via `GENERIC_READ` only and
/// `SendInput` lacked the DESKTOP_HOOKCONTROL and
/// DESKTOP_JOURNALPLAYBACK rights that `GENERIC_WRITE` carries.
///
/// `GENERIC_WRITE` on a desktop maps to (per Win32 generic-mapping
/// rules): `DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
/// DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK |
/// DESKTOP_JOURNALRECORD | DESKTOP_WRITEOBJECTS |
/// STANDARD_RIGHTS_WRITE`. The `JOURNALPLAYBACK` / `HOOKCONTROL`
/// rights are what `SendInput` checks against the thread's bound
/// desktop access token at inject time.
pub fn open_input_desktop_for_injection() -> Result<Option<OwnedDesktop>> {
    // SAFETY: zero flags is a documented call form; out-error is
    // checked.
    let h: HDESK = unsafe { OpenInputDesktop(0, FALSE, GENERIC_READ | GENERIC_WRITE) };
    if h.is_null() {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        if err == ERROR_ACCESS_DENIED {
            tracing::warn!(
                "open_input_desktop_for_injection: ACCESS_DENIED — caller likely \
                 isn't SYSTEM. SystemContext path requires LocalSystem token to \
                 obtain GENERIC_WRITE on Winlogon."
            );
            return Ok(None);
        }
        bail!("OpenInputDesktop(GENERIC_READ|GENERIC_WRITE) failed (err {err})");
    }
    Ok(OwnedDesktop::new(h))
}

/// Attach the calling thread to `desk`. After this call, `SendInput`
/// and WGC capture from this thread target `desk`'s desktop. The
/// desk must outlive every operation made under it.
pub fn set_thread_desktop(desk: &OwnedDesktop) -> Result<()> {
    // SAFETY: `desk.raw()` is a valid HDESK we own. The call returns
    // BOOL; failure is reported via GetLastError.
    let ok = unsafe { SetThreadDesktop(desk.raw()) };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("SetThreadDesktop failed (err {err})");
    }
    Ok(())
}

/// Read the name of the desktop the calling thread is currently
/// attached to. Returns e.g. `"Default"` or `"Winlogon"`. Useful for
/// diagnostic logging — the SYSTEM worker logs every desktop swap so
/// the field can correlate "frames stopped flowing" with "we're now
/// on Winlogon".
pub fn current_thread_desktop_name() -> Result<String> {
    // SAFETY: GetThreadDesktop returns a non-owning HDESK (the OS
    // owns the lifetime; we must NOT CloseDesktop it).
    let h: HDESK = unsafe { GetThreadDesktop(get_current_thread_id()) };
    if h.is_null() {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("GetThreadDesktop failed (err {err})");
    }
    desktop_name_of(h).context("reading current thread's desktop name")
}

fn get_current_thread_id() -> u32 {
    // SAFETY: GetCurrentThreadId has no preconditions and is thread-
    // local. Pulling it from a different module path to keep the
    // top-of-file imports tight.
    unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() }
}

/// `GetUserObjectInformationW(h, UOI_NAME, ...)` reading the desktop
/// name into a Rust `String`. Two-call pattern: first call with NULL
/// buffer to get the required size, second call to read.
pub fn desktop_name_of(h: HDESK) -> Result<String> {
    let mut needed: u32 = 0;
    // First call with NULL buffer returns 0 with last-error
    // ERROR_INSUFFICIENT_BUFFER and writes the required size in
    // `needed`. The signature takes `*mut c_void` — we pass NULL.
    // SAFETY: Documented Win32 idiom; out-pointer is valid.
    let _ = unsafe {
        GetUserObjectInformationW(h.cast(), UOI_NAME, std::ptr::null_mut(), 0, &mut needed)
    };
    if needed == 0 {
        // The OS gave us a name length of zero — unusual but not
        // worth bailing the whole spike.
        return Ok(String::new());
    }
    // `needed` is in bytes; UTF-16 chars are 2 bytes each plus a NUL.
    let cap_words = (needed as usize).div_ceil(2);
    let mut buf: Vec<u16> = vec![0; cap_words];
    // SAFETY: `buf` is alive for the call; the OS writes at most
    // `needed` bytes into it.
    let ok = unsafe {
        GetUserObjectInformationW(
            h.cast(),
            UOI_NAME,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("GetUserObjectInformationW(UOI_NAME) failed (err {err})");
    }
    // Trim the trailing NUL the OS includes in `needed`.
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(OsString::from_wide(&buf).to_string_lossy().into_owned())
}

/// How long the supervisor's input-desktop poll loop sleeps between
/// `OpenInputDesktop` calls. 250 ms balances "user perceives the
/// black-frame gap as transient" against "we don't burn CPU spinning
/// on the OS for no reason." Locked here so the M3 system worker and
/// the spike binary use the same cadence.
pub const INPUT_DESKTOP_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// HANDLE wrapper used by the spike binary's diagnostic prints.
/// Mirrors the `OwnedHandle` in supervisor.rs; kept separate to avoid
/// a cross-module dependency just for one struct.
pub struct DiagHandle(pub HANDLE);

impl Drop for DiagHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: We own this handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_desktop_by_name_default_round_trip_or_skip() {
        // A user-context test runner is attached to `winsta0\Default`
        // on its window station, so opening Default should succeed.
        // CI runners (windows-latest) historically have the same
        // setup. Skip with a log if the runner is in a stripped-down
        // environment that denies this.
        match open_desktop_by_name("Default") {
            Ok(Some(_d)) => {}
            Ok(None) => {
                eprintln!(
                    "open_desktop_by_name('Default') returned None — \
                     unexpected on a normal Win11 host but tolerable on CI"
                );
            }
            Err(e) => panic!("open_desktop_by_name('Default') failed: {e}"),
        }
    }

    #[test]
    fn open_desktop_by_name_winlogon_returns_none_for_non_system() {
        // The unit-test runner is not SYSTEM, so opening Winlogon must
        // surface ERROR_ACCESS_DENIED -> Ok(None). If the test fails
        // because Some is returned, either the runner is elevated to
        // SYSTEM (which would be a CI misconfig) or the Winlogon DACL
        // has been weakened on this host.
        match open_desktop_by_name("Winlogon") {
            Ok(None) => {}
            Ok(Some(_)) => panic!(
                "open_desktop_by_name('Winlogon') returned Some — \
                 either we're running as SYSTEM (unexpected) or the \
                 Winlogon DACL was modified"
            ),
            Err(e) => panic!("open_desktop_by_name('Winlogon') errored: {e}"),
        }
    }

    #[test]
    fn open_input_desktop_works_or_denies_cleanly() {
        // On the user's interactive desktop, OpenInputDesktop should
        // succeed; under SYSTEM it also succeeds; under a service
        // running on a noninteractive winsta it returns ACCESS_DENIED
        // -> Ok(None). Either Some or None is acceptable here; what
        // we lock is "doesn't panic, doesn't return Err".
        let r = open_input_desktop();
        if let Err(e) = r {
            panic!("open_input_desktop returned Err: {e}");
        }
    }

    #[test]
    fn current_thread_desktop_name_smoke() {
        // The unit test runner is attached to *some* desktop. We
        // can't assert exactly which one (Default usually, but on a
        // headless agent it might be a session-noninteractive name);
        // just assert the call returns a non-empty string without
        // panicking.
        let name = current_thread_desktop_name().expect("GetThreadDesktop");
        assert!(
            !name.is_empty(),
            "expected a non-empty desktop name, got {name:?}"
        );
    }

    #[test]
    fn input_desktop_poll_interval_is_250ms() {
        // Lock the poll cadence so M3's system_worker doesn't drift
        // into a faster value that burns CPU or a slower one that
        // makes the black-frame gap user-perceptible.
        assert_eq!(INPUT_DESKTOP_POLL_INTERVAL, Duration::from_millis(250));
    }

    #[test]
    fn open_input_desktop_does_not_request_switch_privilege() {
        // P0 regression guard for 0.2.0–0.2.6.
        //
        // The privileged DesktopSwitch right requires SE_TCB_NAME,
        // reserved for SYSTEM / NetworkService / LocalService. Even
        // local administrators don't have it. Requesting it from a
        // user-context caller (the perUser MSI agent) makes
        // `OpenInputDesktop` fail with ACCESS_DENIED, which the
        // lock-state monitor translates to `Locked` permanently —
        // dropping every input event and substituting the lock-overlay
        // capture frame. The codebase never calls SwitchDesktop, so
        // the right is dead weight.
        //
        // Field repro: the field-test host / operator 2026-05-04. Fixed in 0.2.7.
        // Memory: project_input_regression_0_2_x.md.
        //
        // Needle is the bitwise-or call-site fragment (pipe + space +
        // identifier), built via concat! so this test's own source
        // doesn't contain the contiguous identifier and trip itself.
        // Prose mentions of the constant in comments don't have a
        // leading pipe, so the needle is targeted at the call sites
        // and imports that actually broke input.
        let needle = concat!("| ", "DESKTOP_SWITCH", "DESKTOP");
        let src = include_str!("desktop.rs");
        assert!(
            !src.contains(needle),
            "the privileged DesktopSwitch right is back in desktop.rs \
             call sites — re-introduces the 0.2.0–0.2.6 input \
             regression. Use GENERIC_READ alone."
        );
        // Also block the import form, e.g. `use ... ::{... DESKTOP_SWITCHDESKTOP, ...};`.
        let import_needle = concat!(", ", "DESKTOP_SWITCH", "DESKTOP", ",");
        assert!(
            !src.contains(import_needle),
            "import of the privileged DesktopSwitch right is back in \
             desktop.rs — drop it from the windows-sys import list."
        );
    }

    #[test]
    fn system_context_probe_does_not_request_switch_privilege() {
        // Sibling lock for the M3 spike binary. Same rationale as
        // open_input_desktop_does_not_request_switch_privilege above.
        let needle = concat!("| ", "DESKTOP_SWITCH", "DESKTOP");
        let src = include_str!("system_context_probe.rs");
        assert!(
            !src.contains(needle),
            "the privileged DesktopSwitch right is back in \
             system_context_probe.rs call sites — re-introduces the \
             0.2.0–0.2.6 input regression in code paths derived from \
             the spike binary"
        );
        let import_needle = concat!(", ", "DESKTOP_SWITCH", "DESKTOP", ",");
        assert!(
            !src.contains(import_needle),
            "import of the privileged DesktopSwitch right is back in \
             system_context_probe.rs — drop it from the windows-sys \
             import list."
        );
    }
}
