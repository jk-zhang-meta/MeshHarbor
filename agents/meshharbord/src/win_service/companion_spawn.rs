// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D6 — start the desktop companion from a USER-CONTEXT daemon without
//! handing it a single handle of ours.
//!
//! #1035: tunnel listener ports stayed bound for hours after the daemon
//! process that bound them was gone, and killing `meshharbor-desktop` freed them
//! within seconds. The companion's parent was that dead daemon. The
//! user-session respawn used `std::process::Command`, which calls
//! `CreateProcessW` with `bInheritHandles = TRUE`: every handle the daemon
//! had marked inheritable at that instant — and there is a window in which
//! some are (`make_pipe` below, the SSH console-user capture, third-party
//! code) — was copied into a GUI app that lives for months. The SYSTEM path
//! (`supervisor::spawn_in_session`) already passes `FALSE`; this is the same
//! guarantee for the other path.
//!
//! What this passes, and why:
//! * `bInheritHandles = FALSE` — the whole point; no `STARTF_USESTDHANDLES`
//!   (which would require inheritance), so the child gets no std handles.
//! * `DETACHED_PROCESS` — a console-subsystem build (debug) gets no console
//!   of ours; a GUI build ignores it.
//! * `CREATE_NEW_PROCESS_GROUP` — a Ctrl+C aimed at an attended `roomlerd
//!   run` does not reach the tray.
//! * `CREATE_BREAKAWAY_FROM_JOB`, when the job allows it — the per-user
//!   Scheduled Task runs the daemon inside a job, and a companion left in it
//!   dies with the task (an update, `schtasks /End`). Retried without it
//!   when the job forbids breakaway (`ERROR_ACCESS_DENIED`).

#![cfg(target_os = "windows")]

use anyhow::{Result, bail};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, FALSE, GetLastError, HANDLE,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CreateProcessW, DETACHED_PROCESS,
    PROCESS_INFORMATION, STARTUPINFOW,
};

/// Quote one argument so `CommandLineToArgvW` (and the MSVC CRT) read it
/// back unchanged: bare when it has no whitespace or quote, else wrapped in
/// quotes with each embedded quote escaped and every run of backslashes
/// before a quote — including the closing one — doubled.
pub fn quote_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '"'));
    if !needs_quotes {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // n backslashes before a quote → 2n, then an escaped quote.
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    // Backslashes before the CLOSING quote are doubled too.
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// The full command line: the quoted EXE, then each argument quoted as
/// needed. (A Windows path cannot contain `"`, so the EXE needs no escaping.)
pub fn command_line(exe: &Path, args: &[&str]) -> String {
    let mut s = format!("\"{}\"", exe.display());
    for a in args {
        s.push(' ');
        s.push_str(&quote_arg(a));
    }
    s
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Start `exe args…` detached, inheriting NO handle. Returns the child's pid;
/// the process and thread handles are closed at once (nobody waits on it).
pub fn spawn_detached_no_inherit(exe: &Path, args: &[&str]) -> Result<u32> {
    let exe_w = wide(exe.as_os_str());
    let line = command_line(exe, args);
    let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    let mut last_err = 0u32;
    for flags in [base | CREATE_BREAKAWAY_FROM_JOB, base] {
        // CreateProcessW may write into the command-line buffer, so each
        // attempt gets a fresh one.
        let mut line_w = wide(OsStr::new(&line));
        // SAFETY: zero-initialised Win32 structs are valid "no options".
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every buffer outlives the call; out-params are valid.
        // `bInheritHandles = FALSE` and no STARTF_USESTDHANDLES: the child
        // receives none of this process's handles.
        let ok = unsafe {
            CreateProcessW(
                exe_w.as_ptr(),
                line_w.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                FALSE,
                flags,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        if ok != 0 {
            // SAFETY: both handles were just returned to us.
            unsafe {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            return Ok(pi.dwProcessId);
        }
        // SAFETY: thread-local read.
        last_err = unsafe { GetLastError() };
        // A job that forbids breakaway refuses the first attempt with
        // ERROR_ACCESS_DENIED; anything else is a real failure.
        if !(last_err == ERROR_ACCESS_DENIED && flags & CREATE_BREAKAWAY_FROM_JOB != 0) {
            break;
        }
    }
    bail!("CreateProcessW({}) failed (err {last_err})", exe.display())
}

/// This process's Terminal Services session. `0` is services' session: no
/// desktop anyone can see.
pub fn own_session_id() -> Option<u32> {
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    let mut sid = 0u32;
    // SAFETY: plain out-param call on our own pid.
    let ok = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut sid) };
    (ok != 0).then_some(sid)
}

/// The user's Roaming AppData for `token` (a logged-on user's token from
/// `WTSQueryUserToken`). `SHGetKnownFolderPath` with a token resolves the
/// user's REAL folder — folder redirection included — where `C:\Users\<name>`
/// would only guess. `None` on any failure.
///
/// # Safety
/// `token` must be a live user token opened with at least `TOKEN_QUERY |
/// TOKEN_IMPERSONATE` (a `WTSQueryUserToken` token qualifies).
pub unsafe fn roaming_app_data_for_token(token: HANDLE) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_RoamingAppData, SHGetKnownFolderPath};
    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: valid GUID pointer, flags 0, caller-guaranteed token, out-param.
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_RoamingAppData, 0, token, &mut raw) };
    let path = if hr >= 0 && !raw.is_null() {
        // SAFETY: on success `raw` is a NUL-terminated wide string.
        let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        let slice = unsafe { std::slice::from_raw_parts(raw, len) };
        Some(PathBuf::from(std::ffi::OsString::from_wide(slice)))
    } else {
        None
    };
    // SAFETY: the API allocates with CoTaskMemAlloc even on failure paths;
    // freeing null is a no-op.
    unsafe { CoTaskMemFree(raw as *const core::ffi::c_void) };
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_survive_the_windows_parser() {
        let table: &[(&str, &str)] = &[
            ("--first-run", "--first-run"),
            ("a b", r#""a b""#),
            ("", r#""""#),
            (r#"he said "hi""#, r#""he said \"hi\"""#),
            // A trailing backslash in a QUOTED argument must be doubled, or it
            // escapes the closing quote and swallows the next argument.
            (r"C:\dir with space\", r#""C:\dir with space\\""#),
            // Backslashes not followed by a quote are literal.
            (r"C:\plain\path", r"C:\plain\path"),
            ("tab\there", "\"tab\there\""),
        ];
        for (arg, want) in table {
            assert_eq!(quote_arg(arg), *want, "quoting {arg:?}");
        }
    }

    #[test]
    fn command_line_quotes_the_exe_and_each_argument() {
        let exe = Path::new(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe");
        assert_eq!(
            command_line(exe, &["--first-run"]),
            r#""C:\Program Files\MeshHarbor\meshharbor-desktop.exe" --first-run"#
        );
        assert_eq!(
            command_line(exe, &["--view=welcome", "two words"]),
            r#""C:\Program Files\MeshHarbor\meshharbor-desktop.exe" --view=welcome "two words""#
        );
        assert_eq!(
            command_line(exe, &[]),
            r#""C:\Program Files\MeshHarbor\meshharbor-desktop.exe""#
        );
    }

    /// #1035 — the regression test. An INHERITABLE pipe is open in this
    /// process when the child is started; the parent then closes its write
    /// end and reads. With no inheritance the read sees end-of-file at once;
    /// if the child got a copy of the write handle, the read blocks until the
    /// child exits (~3 s here). `std::process::Command` — the pre-D6 spawn —
    /// fails this.
    #[test]
    fn the_spawned_child_holds_no_handle_of_ours() {
        use std::sync::mpsc;
        use std::time::Duration;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, TRUE};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::Storage::FileSystem::ReadFile;
        use windows_sys::Win32::System::Pipes::CreatePipe;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_TERMINATE, TerminateProcess,
        };

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: TRUE,
        };
        let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: out-pointers are valid; `sa` outlives the call.
        assert_ne!(unsafe { CreatePipe(&mut read, &mut write, &sa, 0) }, 0);

        // A child that lives ~3 s and never touches the pipe.
        let ping = std::path::PathBuf::from(
            std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()),
        )
        .join("System32")
        .join("PING.EXE");
        let pid = spawn_detached_no_inherit(&ping, &["-n", "4", "127.0.0.1"])
            .expect("spawning the probe child");

        // SAFETY: we own `write`; closing it leaves only copies a child took.
        unsafe { CloseHandle(write) };
        let read_raw = read as usize;
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 16];
            let mut n = 0u32;
            // SAFETY: `read_raw` is our live read handle; buffer is valid.
            let ok = unsafe {
                ReadFile(
                    read_raw as HANDLE,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut n,
                    std::ptr::null_mut(),
                )
            };
            let _ = tx.send((ok, n));
        });
        let eof_at_once = rx.recv_timeout(Duration::from_millis(1500));

        // Clean up the child either way, then the reader.
        // SAFETY: plain process-handle open/terminate/close on our own child.
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !h.is_null() {
                TerminateProcess(h, 0);
                CloseHandle(h);
            }
        }
        let _ = reader.join();
        // SAFETY: we own `read`.
        unsafe { CloseHandle(read) };

        match eof_at_once {
            Ok((ok, n)) => assert!(
                ok == 0 && n == 0,
                "the read must end in end-of-file (broken pipe), got ok={ok} n={n}"
            ),
            Err(_) => panic!(
                "the pipe stayed open after the parent closed its end: the child \
                 inherited our write handle (#1035)"
            ),
        }
    }
}
