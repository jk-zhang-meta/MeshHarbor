// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows backend for remote app selection & launch: `EnumWindows`
//! (list), `SetForegroundWindow` (focus), and `std::process::Command`
//! (launch). No new crate — `windows-sys` is already a dependency.
//!
//! ## Why plain in-process Win32 works, even under SystemContext
//! The control data-channel handler runs in the same process as the
//! input injector (`peer.rs` sets both up in one `on_data_channel`
//! callback). Input injection (`SendInput`) only works from the active
//! user's interactive desktop, and it demonstrably works on the
//! SystemContext fleet — so this process is already bound to
//! `winsta0\Default` in the active session. `EnumWindows` /
//! `SetForegroundWindow` therefore see + drive the user's windows, and a
//! plain `Command` spawn lands on the user's desktop. (If a future
//! field test shows the blocking-pool thread lacks a desktop under
//! SystemContext, the fix is a `SetThreadDesktop(winsta0\Default)` at
//! the top of `list`/`focus` — deferred until observed.)
//!
//! `window_id` on Windows is the `HWND` as a decimal string; the browser
//! round-trips it opaquely. Launch is allowlist-key-only (argv, no
//! shell), same as Linux.

use std::process::{Command, Stdio};

use anyhow::{Result, anyhow, bail};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GW_OWNER, GetForegroundWindow, GetWindow, GetWindowTextLengthW, GetWindowTextW,
    IsIconic, IsWindowVisible, SW_RESTORE, SW_SHOW, SetForegroundWindow, ShowWindow,
};

use super::{Coverage, LaunchOutcome, ResolvedApp, WindowInfo, WindowManager};

/// BOOL is `i32`; use literals to avoid depending on the `TRUE`/`FALSE`
/// re-exports moving between windows-sys versions.
const BOOL_TRUE: i32 = 1;

pub struct WindowsWm;

struct RawWin {
    hwnd: isize,
    title: String,
}

/// `EnumWindows` callback: keep top-level, visible, titled, non-owned
/// windows (skips tool windows / owned dialogs). Always returns TRUE so
/// enumeration continues to the end.
unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> i32 {
    // SAFETY: EnumWindows calls this synchronously on the calling thread;
    // every FFI call operates on the passed HWND, and `lparam` is the
    // `&mut Vec<RawWin>` handed to EnumWindows in `list()` (live for the
    // whole enumeration).
    unsafe {
        if IsWindowVisible(hwnd) == 0 {
            return BOOL_TRUE;
        }
        // An owned window (GW_OWNER != null) is a tool window / dialog — skip.
        if !GetWindow(hwnd, GW_OWNER).is_null() {
            return BOOL_TRUE;
        }
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return BOOL_TRUE;
        }
        let mut buf: Vec<u16> = vec![0u16; (len + 1) as usize];
        let n = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
        if n <= 0 {
            return BOOL_TRUE;
        }
        buf.truncate(n as usize);
        let title = String::from_utf16_lossy(&buf);
        if title.trim().is_empty() {
            return BOOL_TRUE;
        }
        let out = &mut *(lparam as *mut Vec<RawWin>);
        out.push(RawWin {
            hwnd: hwnd as isize,
            title,
        });
        BOOL_TRUE
    }
}

impl WindowManager for WindowsWm {
    /// FR-56 P2 — `EnumWindows` sees every top-level window on the desktop,
    /// so a Windows listing has no second source hiding behind it.
    fn coverage(&self) -> Coverage {
        Coverage {
            sources: vec!["win32"],
            unlisted: None,
            // FR-56 P5 — nothing to miss: this backend calls Win32 directly
            // rather than shelling out, so there is no helper binary whose
            // absence could silently remove a button. Empty here is a
            // measured "nothing missing", not "not checked".
            missing_tools: Vec::new(),
        }
    }

    fn list(&self) -> Result<Vec<WindowInfo>> {
        let mut raw: Vec<RawWin> = Vec::new();
        // SAFETY: enum_proc only dereferences this pointer during the
        // synchronous EnumWindows call below; `raw` outlives it.
        unsafe {
            EnumWindows(Some(enum_proc), &mut raw as *mut Vec<RawWin> as LPARAM);
        }
        let fg = unsafe { GetForegroundWindow() } as isize;
        Ok(raw
            .into_iter()
            .map(|w| WindowInfo {
                window_id: w.hwnd.to_string(),
                title: w.title,
                app_key: None,
                session: None,
                focused: w.hwnd != 0 && w.hwnd == fg,
            })
            .collect())
    }

    fn focus(&self, window_id: &str) -> Result<()> {
        let handle = window_id
            .parse::<isize>()
            .map_err(|_| anyhow!("invalid window id"))?;
        if handle == 0 {
            bail!("invalid window id");
        }
        let hwnd = handle as HWND;
        // SAFETY: all calls are thread-agnostic USER32 ops on a caller-
        // supplied HWND; a stale/invalid HWND makes them no-op/return 0,
        // which we surface as an error rather than UB.
        unsafe {
            if IsIconic(hwnd) != 0 {
                ShowWindow(hwnd, SW_RESTORE);
            }
            if SetForegroundWindow(hwnd) == 0 {
                // Retry after ensuring the window is shown — covers a
                // hidden/minimised target. (The AttachThreadInput focus-
                // steal workaround is deferred until a field test shows
                // SYSTEM-in-session focus grabs are actually blocked.)
                ShowWindow(hwnd, SW_SHOW);
                if SetForegroundWindow(hwnd) == 0 {
                    bail!("SetForegroundWindow was rejected (window gone or foreground lock)");
                }
            }
        }
        Ok(())
    }

    fn launch(&self, app: &ResolvedApp) -> Result<LaunchOutcome> {
        // The handler runs on the active user's desktop (see module docs),
        // so a plain detached spawn appears on the user's screen. tmux is
        // Linux-only; on Windows `terminal` is a no-op (cmd/pwsh/GUI apps
        // create their own window).
        let (program, rest) = app
            .command
            .split_first()
            .ok_or_else(|| anyhow!("empty command"))?;
        Command::new(program)
            .args(rest)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("spawn {program}: {e}"))?;
        Ok(LaunchOutcome::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_rejects_bad_ids() {
        let wm = WindowsWm;
        assert!(wm.focus("not-a-number").is_err());
        assert!(wm.focus("0").is_err());
    }

    #[test]
    fn list_runs_and_returns_titled_windows() {
        // Smoke: EnumWindows must not crash and returns 0+ windows with
        // non-empty titles + valid decimal ids. (CI/headless may have 0
        // top-level windows — that's fine, we only assert well-formedness.)
        let wm = WindowsWm;
        let windows = wm.list().expect("EnumWindows should not error");
        for w in &windows {
            assert!(!w.title.trim().is_empty(), "titles are filtered non-empty");
            assert!(w.window_id.parse::<isize>().is_ok(), "id is a decimal HWND");
            assert!(w.session.is_none() && w.app_key.is_none());
        }
    }
}
