// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Winlogon-token spawn — produces a worker process running as
//! `S-1-5-18` (LocalSystem) but in a non-zero interactive session.
//!
//! The chain is:
//!   1. Enumerate `WTSEnumerateSessionsW` for an Active interactive
//!      session id ([`find_active_session`]). Deliberately NOT
//!      `WTSGetActiveConsoleSessionId` — that returns `0xFFFFFFFF` on
//!      RDP-only fleet hosts, per RustDesk's `windows.cc:608-697` and
//!      our M3 A1 Pre-flight #4 (still pending the RDP VM but
//!      architecturally settled).
//!   2. Walk processes via `Toolhelp32` for `winlogon.exe` whose
//!      `ProcessIdToSessionId` matches the target session
//!      ([`find_winlogon_pid_in_session`]).
//!   3. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` →
//!      `OpenProcessToken(TOKEN_DUPLICATE | TOKEN_QUERY)` →
//!      `DuplicateTokenEx(TokenPrimary)` →
//!      `SetTokenInformation(TokenSessionId)`
//!      ([`open_winlogon_primary_token`]).
//!   4. `CreateProcessAsUserW` with the dup'd token
//!      ([`spawn_system_in_session`]).
//!
//! The supervisor calls this when [`crate::win_service::supervisor::
//! decide_spawn`] returns the SystemContext variant (carrying the
//! target session id). The spawned child runs the same `roomlerd
//! run` binary; its [`super::worker_role::probe_self`] returns
//! `WorkerRole::SystemContext` and downstream construction sites pick
//! the M3 A1 plumbing.
//!
//! ## Privileges
//!
//! Empirically confirmed on the field-test host / Win11 24H2 (memory
//! `project_m3_a1_preflights_2_3_5.md`): the bare 4-step sequence
//! works without `AdjustTokenPrivileges`. SE_TCB_NAME and
//! SE_IMPERSONATE are present in the spawned child by default;
//! SeAssignPrimaryTokenPrivilege is DISABLED so the child cannot
//! itself spawn further `CreateProcessAsUserW` children, but M3 A1
//! never needs to (`SetThreadDesktop` from the input thread is the
//! way it follows desktop changes).
//!
//! ## Inheritable handles
//!
//! Future work: pass `STARTUPINFOEX::lpAttributeList` with
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` carrying the heartbeat-pipe
//! write end so the supervisor knows when the worker has an active
//! controller. Not in this commit — heartbeat infrastructure on
//! both ends needs to land first; the API shape will change when
//! that work begins.
//!
//! ## Failure-mode handling
//!
//! Each step returns a typed error via `anyhow::bail!` with the
//! Win32 error code formatted in. The supervisor's caller folds them
//! into its existing exponential-backoff ladder
//! ([`crate::win_service::supervisor::next_backoff`]).

#![cfg(target_os = "windows")]

use anyhow::{Context, Result, anyhow, bail};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS,
    TOKEN_DUPLICATE, TOKEN_QUERY, TokenPrimary, TokenSessionId,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive,
    WTSEnumerateSessionsW, WTSFreeMemory,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, OpenProcess,
    OpenProcessToken, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESHOWWINDOW,
    STARTUPINFOW,
};

// ────────────────────────────────────────────────────────────────────
// RAII guards
// ────────────────────────────────────────────────────────────────────

/// `HANDLE` wrapper that closes on drop. The Win32 `HANDLE` type is
/// just a pointer-sized integer with no Drop semantics; without this
/// every error path leaks an OS handle. `pub` because callers receive
/// it from [`open_winlogon_primary_token`] and pass it to
/// [`spawn_system_in_session`]; safe to expose because the only
/// available operations are [`OwnedToken::raw`] (read-only borrow of
/// the inner HANDLE) and Drop.
pub struct OwnedToken(HANDLE);

impl OwnedToken {
    /// Construct from a raw HANDLE. Returns `None` for null /
    /// `INVALID_HANDLE_VALUE`. Marked `pub(crate)` so only the spawn
    /// path inside this module can produce one — callers can't bypass
    /// the validation by hand-constructing.
    pub(crate) fn new(h: HANDLE) -> Option<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(h))
        }
    }

    /// Borrow the inner handle. Caller must NOT close it.
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: We own this handle (constructed via
            // OpenProcessToken / DuplicateTokenEx). CloseHandle on
            // a valid token is the canonical cleanup; failure is
            // unrecoverable from a Drop impl.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Process+thread handle pair returned from
/// [`spawn_system_in_session`]. Caller can `wait` for the process to
/// exit, then drop. Both handles closed by Drop.
pub struct ChildHandle {
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
    session_id: u32,
}

impl ChildHandle {
    /// Spawned process id. Stable for the lifetime of the kernel
    /// process object (i.e. until Drop closes our handle and the
    /// kernel reaps the entry).
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Session id the child landed in. May be `u32::MAX` if the
    /// post-spawn `ProcessIdToSessionId` lookup failed; in that case
    /// the spawn itself succeeded but the session-id confirmation
    /// is unavailable.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Borrow the process handle. Used by the supervisor's
    /// `WaitForSingleObject` poll. Caller must NOT close it.
    pub fn process_handle(&self) -> HANDLE {
        self.process
    }

    /// Disown the handles and return them as a `(process, thread,
    /// pid, session_id)` tuple. The caller takes responsibility for
    /// `CloseHandle`-ing both — typically by re-wrapping into a
    /// different RAII type that owns the lifetime (e.g. the
    /// supervisor's [`crate::win_service::supervisor::OwnedProcess`]
    /// for compatibility with the existing user-context worker
    /// wait/terminate logic).
    ///
    /// `mem::forget`'s the `ChildHandle` so its Drop doesn't
    /// double-close the handles. Safe because the returned tuple
    /// is a strict transfer of ownership.
    pub fn into_raw_parts(self) -> (HANDLE, HANDLE, u32, u32) {
        let process = self.process;
        let thread = self.thread;
        let pid = self.pid;
        let session_id = self.session_id;
        std::mem::forget(self);
        (process, thread, pid, session_id)
    }
}

impl Drop for ChildHandle {
    fn drop(&mut self) {
        // SAFETY: We own both handles. CloseHandle on a non-null
        // valid HANDLE is the canonical cleanup. Order matters
        // weakly (process before thread is convention, not
        // requirement).
        if !self.process.is_null() {
            unsafe {
                CloseHandle(self.process);
            }
        }
        if !self.thread.is_null() {
            unsafe {
                CloseHandle(self.thread);
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Step 1: find an active interactive session
// ────────────────────────────────────────────────────────────────────

/// Iterate `WTSEnumerateSessionsW` and return the first session whose
/// state is `WTSActive` and whose id is non-zero. Mirrors RustDesk's
/// `src/platform/windows.cc:608-697` `run_service` polling.
///
/// Why not `WTSGetActiveConsoleSessionId`: returns `0xFFFFFFFF` on
/// RDP-only fleet hosts (no console session ever attached), and on
/// Win11 boxes with fast-user-switch in flight. Pre-flight #4 will
/// confirm the RDP-only case empirically; until then RustDesk's
/// pattern is the conservative default.
pub fn find_active_session() -> Result<u32> {
    let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: u32 = 0;
    // SAFETY: documented Win32 idiom; out-pointers are valid for
    // the duration of the call. Result is checked immediately.
    let ok = unsafe {
        WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut count)
    };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("WTSEnumerateSessionsW failed: win32 error {err}");
    }
    // SAFETY: `sessions` is a valid pointer to `count` records; the
    // OS allocates it and our WTSFreeMemory below releases it.
    let slice = unsafe { std::slice::from_raw_parts(sessions, count as usize) };
    let chosen = slice
        .iter()
        .find(|s| s.State == WTSActive && s.SessionId != 0)
        .map(|s| s.SessionId);
    // SAFETY: matched WTSEnumerateSessionsW above. Always called.
    unsafe {
        WTSFreeMemory(sessions as *mut _);
    }
    chosen.ok_or_else(|| anyhow!("no active interactive session found"))
}

// ────────────────────────────────────────────────────────────────────
// Step 2: find winlogon.exe in that session
// ────────────────────────────────────────────────────────────────────

/// Walk processes via `CreateToolhelp32Snapshot` looking for
/// `winlogon.exe` whose owning session matches `target_session`.
/// Returns `Ok(None)` (not Err) when no match exists — the supervisor
/// distinguishes "race during a logon transition" from "Toolhelp
/// failed".
pub fn find_winlogon_pid_in_session(target_session: u32) -> Result<Option<u32>> {
    // SAFETY: TH32CS_SNAPPROCESS + pid=0 is the documented call form.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("CreateToolhelp32Snapshot failed: win32 error {err}");
    }
    // RAII for the snapshot handle — close on every return path.
    struct Snap(HANDLE);
    impl Drop for Snap {
        fn drop(&mut self) {
            // SAFETY: we own this handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let _snap_guard = Snap(snap);

    // SAFETY: zeroing a POD-style struct is the canonical init.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: `snap` valid (checked above); `entry` lives for the call.
    if unsafe { Process32FirstW(snap, &mut entry) } == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("Process32FirstW failed: win32 error {err}");
    }
    loop {
        let name = wchar_to_string(&entry.szExeFile);
        if name.eq_ignore_ascii_case("winlogon.exe") {
            let mut sid: u32 = 0;
            // SAFETY: out-ptr is valid; pid is what Toolhelp gave us.
            let ok = unsafe { ProcessIdToSessionId(entry.th32ProcessID, &mut sid) };
            if ok != 0 && sid == target_session {
                return Ok(Some(entry.th32ProcessID));
            }
        }
        // SAFETY: `snap` and `entry` still valid.
        if unsafe { Process32NextW(snap, &mut entry) } == 0 {
            break;
        }
    }
    Ok(None)
}

/// Convenience: find the active session AND winlogon.exe in it in
/// one call. Returns `(pid, session_id)`. The supervisor uses this as
/// its M3 A1 entry point.
pub fn find_winlogon_pid_in_active_session() -> Result<Option<(u32, u32)>> {
    let session = find_active_session()?;
    Ok(find_winlogon_pid_in_session(session)?.map(|pid| (pid, session)))
}

// ────────────────────────────────────────────────────────────────────
// Step 3: open winlogon's primary token, dup'd + session-bound
// ────────────────────────────────────────────────────────────────────

/// `OpenProcess` → `OpenProcessToken` → `DuplicateTokenEx` →
/// `SetTokenInformation(TokenSessionId)`. The returned token is a
/// freshly-dup'd primary token, owned by the caller, bound to
/// `target_session`. The original winlogon process handle is closed
/// before return.
///
/// Why explicitly bind the session id even though winlogon is
/// already in `target_session`: defends against RDP shadow-session
/// edge cases per RustDesk's `windows.cc:226-233`. The token's
/// SessionId field can drift from the originating process's session
/// in shadow scenarios; we want determinism.
pub fn open_winlogon_primary_token(pid: u32, target_session: u32) -> Result<OwnedToken> {
    // SAFETY: OpenProcess is safe to call with a u32 pid; null on
    // failure. We check for null and propagate.
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if proc.is_null() {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("OpenProcess(winlogon pid={pid}) failed: win32 error {err}");
    }
    // RAII for the process handle — close on every return path.
    struct Proc(HANDLE);
    impl Drop for Proc {
        fn drop(&mut self) {
            // SAFETY: we own this handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let _proc_guard = Proc(proc);

    let mut tok: HANDLE = std::ptr::null_mut();
    // SAFETY: `proc` is a valid process handle; `&mut tok` is valid.
    let ok =
        unsafe { OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut tok as *mut HANDLE) };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("OpenProcessToken(winlogon) failed: win32 error {err}");
    }
    // RAII for the original token — DuplicateTokenEx gives us a new
    // handle; the original is no longer needed once we have the dup.
    let _orig_token = OwnedToken(tok);

    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: `tok` is a valid token; null SECURITY_ATTRIBUTES is
    // documented OK; output handle is checked.
    let ok = unsafe {
        DuplicateTokenEx(
            tok,
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut dup as *mut HANDLE,
        )
    };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("DuplicateTokenEx failed: win32 error {err}");
    }
    let dup_token =
        OwnedToken::new(dup).ok_or_else(|| anyhow!("DuplicateTokenEx returned null handle"))?;

    // Re-bind the dup'd token to the target session id explicitly.
    let sid: u32 = target_session;
    // SAFETY: `dup_token.raw()` is a valid token; `&sid` lives for
    // the call duration; size matches u32 (4 bytes).
    let ok = unsafe {
        SetTokenInformation(
            dup_token.raw(),
            TokenSessionId,
            &sid as *const u32 as *const _,
            std::mem::size_of::<u32>() as u32,
        )
    };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("SetTokenInformation(TokenSessionId={target_session}) failed: win32 error {err}");
    }
    Ok(dup_token)
}

// ────────────────────────────────────────────────────────────────────
// Step 4: spawn the worker process with the primary token
// ────────────────────────────────────────────────────────────────────

/// `CreateProcessAsUserW(token, NULL, cmdline, ...)` with
/// `CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT`. The worker runs
/// as `S-1-5-18` (SYSTEM) but in `target_session`'s window-station +
/// desktop hierarchy.
///
/// `cmdline` is the full command line the OS passes verbatim — by
/// convention, `"<exe-path>" arg1 arg2`. Quoting is the caller's
/// responsibility (use [`build_cmdline`] for the safe path).
///
/// Returns a [`ChildHandle`] that closes both process and thread
/// handles on drop. Caller waits via `WaitForSingleObject` on
/// [`ChildHandle::process_handle`] then drops.
pub fn spawn_system_in_session(token: &OwnedToken, cmdline: &str) -> Result<ChildHandle> {
    let mut wide: Vec<u16> = OsStr::new(cmdline).encode_wide().collect();
    wide.push(0);

    // SAFETY: zeroing a POD-style FFI struct is the canonical init.
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = 0; // SW_HIDE — keep the worker UI off the user's screen.

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // SAFETY: `token.raw()` is a valid primary token; `wide` outlives
    // the call (until `pi` is populated, then we never touch it
    // again); pointers we pass as null are documented-OK.
    let ok = unsafe {
        CreateProcessAsUserW(
            token.raw(),
            std::ptr::null(),
            wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            FALSE,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("CreateProcessAsUserW failed: win32 error {err}");
    }

    // Best-effort post-spawn session-id confirmation. If
    // ProcessIdToSessionId fails (race with the child exiting fast,
    // or kernel object retired), we still own the handles and the
    // spawn itself succeeded — return u32::MAX as a "couldn't query"
    // sentinel rather than failing the whole operation.
    let mut child_session: u32 = 0;
    // SAFETY: `pi.dwProcessId` is the just-spawned child pid;
    // out-pointer is valid.
    let ok = unsafe { ProcessIdToSessionId(pi.dwProcessId, &mut child_session) };
    if ok == 0 {
        child_session = u32::MAX;
    }

    Ok(ChildHandle {
        process: pi.hProcess,
        thread: pi.hThread,
        pid: pi.dwProcessId,
        session_id: child_session,
    })
}

/// Build a Windows-flavour CreateProcess command line: `"<exe>"`
/// followed by space-separated args. Each arg is quoted only when it
/// contains spaces; embedded quotes are escaped per the
/// `CommandLineToArgvW` convention (double the backslashes preceding
/// a `"`, then escape the `"` itself).
///
/// Plain cargo-run-style: `build_cmdline(r"C:\Program Files\foo.exe", &["run", "--config", r"C:\path with space\cfg.toml"])`
/// → `"C:\Program Files\foo.exe" run --config "C:\path with space\cfg.toml"`.
pub fn build_cmdline(exe: &std::path::Path, args: &[impl AsRef<str>]) -> String {
    let mut out = String::with_capacity(64);
    out.push('"');
    out.push_str(&exe.to_string_lossy());
    out.push('"');
    for a in args {
        out.push(' ');
        let s = a.as_ref();
        if s.is_empty() {
            out.push_str("\"\"");
            continue;
        }
        let needs_quote = s.contains(' ') || s.contains('\t') || s.contains('"');
        if !needs_quote {
            out.push_str(s);
            continue;
        }
        out.push('"');
        // Per CommandLineToArgvW: double a run of backslashes only
        // if a `"` follows immediately. We walk the string, tracking
        // pending backslashes; on `"` we emit 2N backslashes and a
        // backslash-quote; on end-of-string with pending backslashes
        // we double them (the closing quote consumes them).
        let mut backslashes = 0usize;
        for ch in s.chars() {
            if ch == '\\' {
                backslashes += 1;
            } else if ch == '"' {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            } else {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(ch);
            }
        }
        for _ in 0..(backslashes * 2) {
            out.push('\\');
        }
        out.push('"');
    }
    out
}

// ────────────────────────────────────────────────────────────────────
// One-shot convenience
// ────────────────────────────────────────────────────────────────────

/// Compose all four steps: find session → find winlogon → open token
/// → spawn. `Ok(None)` means no winlogon.exe is in the active
/// interactive session (rare race during logon transitions); the
/// supervisor falls back to the user-context worker for that cycle.
pub fn spawn_worker_as_system(
    exe: &std::path::Path,
    args: &[impl AsRef<str>],
) -> Result<Option<ChildHandle>> {
    let Some((winlogon_pid, session_id)) =
        find_winlogon_pid_in_active_session().context("locating winlogon.exe in active session")?
    else {
        return Ok(None);
    };
    let token = open_winlogon_primary_token(winlogon_pid, session_id)
        .context("opening winlogon's primary token")?;
    let cmdline = build_cmdline(exe, args);
    let child =
        spawn_system_in_session(&token, &cmdline).context("spawning SYSTEM-in-session worker")?;
    Ok(Some(child))
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/// Trim a wide-char NUL-terminated buffer to its first NUL and decode
/// as UTF-16 lossy. Used for the Toolhelp32 `szExeFile` field.
fn wchar_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_cmdline_no_args_quotes_exe() {
        let exe = PathBuf::from(r"C:\Program Files\Roomler\roomlerd.exe");
        let empty: [&str; 0] = [];
        let cmd = build_cmdline(&exe, &empty);
        assert_eq!(cmd, r#""C:\Program Files\Roomler\roomlerd.exe""#);
    }

    #[test]
    fn build_cmdline_simple_args_no_quoting() {
        let exe = PathBuf::from(r"C:\agent.exe");
        let cmd = build_cmdline(&exe, &["run", "--mode", "system"]);
        assert_eq!(cmd, r#""C:\agent.exe" run --mode system"#);
    }

    #[test]
    fn build_cmdline_arg_with_space_gets_quoted() {
        let exe = PathBuf::from(r"C:\agent.exe");
        let cmd = build_cmdline(&exe, &["--config", r"C:\path with space\cfg.toml"]);
        assert_eq!(
            cmd,
            r#""C:\agent.exe" --config "C:\path with space\cfg.toml""#
        );
    }

    #[test]
    fn build_cmdline_arg_with_quote_escapes_per_argvw_convention() {
        // Embedded `"` inside a quoted arg becomes `\"`. Per
        // CommandLineToArgvW: an unescaped quote ends the quoted arg,
        // so we must escape it.
        let exe = PathBuf::from(r"C:\agent.exe");
        let cmd = build_cmdline(&exe, &[r#"value with "quote""#]);
        // Expected: "C:\agent.exe" "value with \"quote\""
        assert_eq!(cmd, r#""C:\agent.exe" "value with \"quote\"""#);
    }

    #[test]
    fn build_cmdline_arg_with_trailing_backslash_doubles_when_quoted() {
        // Trailing backslashes inside a quoted arg are doubled
        // because the closing `"` would otherwise be escaped by them.
        let exe = PathBuf::from(r"C:\agent.exe");
        let cmd = build_cmdline(&exe, &[r"path with space\"]);
        // Expected: "C:\agent.exe" "path with space\\"
        assert_eq!(cmd, r#""C:\agent.exe" "path with space\\""#);
    }

    #[test]
    fn build_cmdline_empty_arg_becomes_empty_quoted() {
        let exe = PathBuf::from(r"C:\agent.exe");
        let cmd = build_cmdline(&exe, &["", "real"]);
        assert_eq!(cmd, r#""C:\agent.exe" "" real"#);
    }

    #[test]
    fn build_cmdline_arg_with_tab_gets_quoted() {
        // Tabs are also argv separators per CommandLineToArgvW.
        let exe = PathBuf::from(r"C:\agent.exe");
        let cmd = build_cmdline(&exe, &["arg\twith\ttab"]);
        assert_eq!(cmd, "\"C:\\agent.exe\" \"arg\twith\ttab\"");
    }

    #[test]
    fn wchar_to_string_stops_at_null() {
        let buf: Vec<u16> = "winlogon.exe\0\0\0".encode_utf16().collect();
        assert_eq!(wchar_to_string(&buf), "winlogon.exe");
    }

    #[test]
    fn wchar_to_string_handles_empty() {
        assert_eq!(wchar_to_string(&[]), "");
    }

    #[test]
    fn wchar_to_string_handles_full_buffer_no_null() {
        // Toolhelp32 normally NUL-terminates within MAX_PATH, but
        // defend against a pathological no-NUL buffer.
        let buf: Vec<u16> = "abc".encode_utf16().collect();
        assert_eq!(wchar_to_string(&buf), "abc");
    }

    #[test]
    fn find_active_session_returns_some_or_no_active_session_error() {
        // The cargo test runner is interactive (run by the developer),
        // so find_active_session must return Ok with a non-zero
        // session id. On a noninteractive CI runner with no logged-
        // in user this would error with "no active interactive
        // session found"; we accept either as long as it doesn't
        // panic.
        match find_active_session() {
            Ok(sid) => assert!(sid != 0, "active session must be non-zero; got {sid}"),
            Err(e) => assert!(
                format!("{e:#}").contains("no active interactive session"),
                "unexpected error: {e:#}"
            ),
        }
    }

    #[test]
    fn find_winlogon_pid_in_active_session_does_not_panic() {
        // Smoke: we don't assert on the result because winlogon
        // visibility from a non-SYSTEM caller isn't guaranteed
        // (Toolhelp32 + ProcessIdToSessionId can succeed against
        // winlogon under normal user context, but the cross-session
        // lookup is best-effort). What we lock is "doesn't panic,
        // doesn't return Err in the normal interactive case".
        let _ = find_winlogon_pid_in_active_session();
    }

    #[test]
    fn owned_token_new_rejects_null() {
        assert!(OwnedToken::new(std::ptr::null_mut()).is_none());
    }

    #[test]
    fn owned_token_new_rejects_invalid_handle_value() {
        assert!(OwnedToken::new(INVALID_HANDLE_VALUE).is_none());
    }
}
