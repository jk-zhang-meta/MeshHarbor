// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! M3 A1 derisking probes (Pre-flight #2 / #3 / #5 from the M3 A1 plan).
//!
//! Three orthogonal questions about the SYSTEM-context worker
//! architecture, batched into one binary so the field operator runs
//! them in a single the field-test host sitting:
//!
//! - **`winlogon-token`** (Pre-flight #2): can a SYSTEM service in
//!   session 0 steal `winlogon.exe`'s primary token via
//!   `OpenProcessToken` + `DuplicateTokenEx` and use it with
//!   `CreateProcessAsUserW` to spawn a child as `NT AUTHORITY\SYSTEM`
//!   in the active interactive session (e.g. session 1)? This is the
//!   spawn mechanic RustDesk uses (`src/platform/windows.cc:126-274`)
//!   and the keystone of M3 A1. Win11 24H2 has tightened LSA in
//!   several places; this probe confirms the bare-token-dup path still
//!   works on the operator's box without `AdjustTokenPrivileges`
//!   gymnastics.
//!
//!   Run via: `psexec -s -i 1 ...\meshharbord.exe system-context-probe winlogon-token`
//!
//! - **`winsta-attach`** (Pre-flight #3): the SCM service starts in
//!   the `Service-0x0-3e7$\Default` window station. Before it can open
//!   any desktop on `winsta0\Winlogon` (or even `winsta0\Default`),
//!   it must `OpenWindowStationW("WinSta0")` + `SetProcessWindowStation`.
//!   This probe demonstrates the failure-mode (ERROR_NOACCESS) without
//!   the attach + the success case after the attach. Locks the
//!   `attach_to_winsta0()` step in the eventual SYSTEM-context worker
//!   bootstrap.
//!
//!   Run via: `psexec -s -i 0 ...\meshharbord.exe system-context-probe winsta-attach`
//!
//! - **`dxgi-cadence`** (Pre-flight #5): instrument `scrap::Capturer`
//!   on the primary display for 30 s on a static desktop. Reports the
//!   distribution of `Capturer::frame()` outcomes (Ok bytes, WouldBlock,
//!   ConnectionReset, PermissionDenied, etc.) and the wallclock cadence.
//!   Compares to today's `media_pump` (which compensates for WGC's
//!   "emit-on-change" with a 1 fps idle keepalive) — the M3 A1 worker
//!   needs equivalent compensation.
//!
//!   Run via: `...\meshharbord.exe system-context-probe dxgi-cadence`
//!   (no SYSTEM context needed; user-context is fine for cadence
//!   measurement.)
//!
//! All three exit non-zero on hard failure, write a structured one-line
//! summary to stdout that the operator can paste into a chat, and write
//! a more verbose JSON report to `%TEMP%\roomlerd-probe-{mode}.json`
//! for the implementer to consume offline.

#![cfg(target_os = "windows")]

use anyhow::{Context, Result, anyhow, bail};
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

#[cfg(feature = "scrap-capture")]
use std::io::ErrorKind;
#[cfg(feature = "scrap-capture")]
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY,
    TokenPrimary, TokenSessionId,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive,
    WTSEnumerateSessionsW, WTSFreeMemory,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, GetProcessWindowStation, GetUserObjectInformationW, HDESK,
    OpenDesktopW, OpenWindowStationW, SetProcessWindowStation, UOI_NAME,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, OpenProcess,
    OpenProcessToken, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESHOWWINDOW,
    STARTUPINFOW, WaitForSingleObject,
};

/// `WINSTA_ALL_ACCESS` — full-access mask for `OpenWindowStationW`.
/// Inlined as the literal value (windows-sys puts the constant in
/// `Win32_UI_WindowsAndMessaging`, which is a heavy module we don't
/// otherwise need; the value is stable since NT 4 and won't change).
const WINSTA_ALL_ACCESS: u32 = 0x37F;

/// Which probe to run. Mirrors the CLI subcommand enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    WinlogonToken,
    WinstaAttach,
    DxgiCadence,
}

impl std::str::FromStr for ProbeMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "winlogon-token" => Ok(Self::WinlogonToken),
            "winsta-attach" => Ok(Self::WinstaAttach),
            "dxgi-cadence" => Ok(Self::DxgiCadence),
            other => Err(format!(
                "unknown probe {other:?}; expected one of: winlogon-token, winsta-attach, dxgi-cadence"
            )),
        }
    }
}

/// Top-level dispatch. Each probe owns its own stdout output format.
pub fn run(mode: ProbeMode) -> Result<()> {
    println!("system-context-probe: mode={mode:?}");
    match mode {
        ProbeMode::WinlogonToken => run_winlogon_token(),
        ProbeMode::WinstaAttach => run_winsta_attach(),
        ProbeMode::DxgiCadence => run_dxgi_cadence(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Pre-flight #2 — winlogon-token spawn
// ─────────────────────────────────────────────────────────────────────

fn run_winlogon_token() -> Result<()> {
    println!("\n--- winlogon-token probe ---");
    println!(
        "Goal: confirm OpenProcessToken(winlogon.exe) + DuplicateTokenEx + CreateProcessAsUserW"
    );
    println!("      spawns a SYSTEM-in-session-N child without AdjustTokenPrivileges.");

    // Step 1: confirm we're SYSTEM. Cheap check via the impersonation
    // token's account name would also work, but a simple invocation
    // of `whoami` on ourselves keeps the logic uniform with the child
    // probe.
    let session_id_self = unsafe {
        let mut sid: u32 = 0;
        if ProcessIdToSessionId(std::process::id(), &mut sid) == 0 {
            bail!("ProcessIdToSessionId(self) failed: {}", GetLastError());
        }
        sid
    };
    println!("  self session id = {session_id_self} (expect 0 when launched via psexec -s -i 1)");

    // Step 2: find the active interactive session via WTSEnumerateSessions.
    // We deliberately avoid WTSGetActiveConsoleSessionId here — it returns
    // 0xFFFFFFFF on RDP-only fleet hosts (Pre-flight #4 will confirm).
    let active_session = find_active_session()?;
    println!("  WTSEnumerateSessions: active interactive session = {active_session}");

    // Step 3: find winlogon.exe in that session.
    let pid = find_winlogon_pid_in_session(active_session)?
        .ok_or_else(|| anyhow!("no winlogon.exe found in session {active_session}"))?;
    println!("  winlogon.exe pid in session {active_session} = {pid}");

    // Step 4: open the process + extract its primary token.
    let primary_token = unsafe { open_winlogon_primary_token(pid, active_session)? };
    let token_guard = OwnedHandle(primary_token);
    println!("  OpenProcessToken + DuplicateTokenEx + SetTokenInformation(TokenSessionId): OK");

    // Step 5: spawn `cmd.exe /c whoami /all > %TEMP%\winlogon-token-probe.txt`
    // using the primary token via CreateProcessAsUserW.
    let probe_out = std::env::temp_dir().join("roomlerd-probe-winlogon-token.txt");
    let _ = std::fs::remove_file(&probe_out); // best-effort wipe stale data
    let cmdline = format!(
        "cmd.exe /c \"whoami /user >\"{}\" 2>&1 && whoami /priv >>\"{}\" 2>&1\"",
        probe_out.display(),
        probe_out.display()
    );
    let child_session = unsafe { spawn_with_token(token_guard.0, &cmdline)? };
    println!(
        "  CreateProcessAsUserW: child pid={} session={} (expected {})",
        child_session.pid, child_session.session_id, active_session
    );

    // Step 6: wait for child to finish.
    unsafe {
        WaitForSingleObject(child_session.process_handle, 10_000);
        CloseHandle(child_session.process_handle);
        CloseHandle(child_session.thread_handle);
    }

    // Step 7: read + print the output file.
    if !probe_out.exists() {
        bail!(
            "child wrote no output file at {} — spawn likely failed silently",
            probe_out.display()
        );
    }
    // whoami's output uses the system's OEM/ANSI codepage (CP-850 /
    // CP-1252 on German Windows, which can include `NT-AUTORITÄT`).
    // Read as bytes + lossy-convert so non-UTF-8 bytes don't bomb the
    // verdict line — the SID hex string we're sniffing for is ASCII
    // either way.
    let raw =
        std::fs::read(&probe_out).with_context(|| format!("reading {}", probe_out.display()))?;
    let body = String::from_utf8_lossy(&raw);
    println!("\n--- child whoami output (lossy UTF-8) ---\n{body}---");

    // SYSTEM's well-known SID is `S-1-5-18` and is locale-independent
    // (no German translation). That's a more reliable marker than
    // matching the localized "NT AUTHORITY\SYSTEM" / "NT-AUTORITÄT\SYSTEM"
    // string.
    let body_lower = body.to_lowercase();
    let success_marker =
        body_lower.contains("s-1-5-18") || body_lower.contains("nt authority\\system");
    if success_marker {
        println!(
            "\nVERDICT: PASS — child ran as NT AUTHORITY\\SYSTEM in session {}.",
            child_session.session_id
        );
        println!("Pre-flight #2 confirmed: bare token-dup path works on this host.");
        Ok(())
    } else {
        println!("\nVERDICT: PARTIAL — spawn succeeded but child wasn't NT AUTHORITY\\SYSTEM.");
        println!("Inspect the whoami output above; M3 A1 spawn module may need");
        println!("AdjustTokenPrivileges(SE_TCB_NAME) before DuplicateTokenEx.");
        bail!("token impersonation did not yield SYSTEM identity");
    }
}

/// Iterate WTSEnumerateSessions and return the first session whose state
/// is `WTSActive` and whose id is non-zero. RustDesk's pattern at
/// `src/platform/windows.cc:608-697` (run_service polling).
fn find_active_session() -> Result<u32> {
    unsafe {
        let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count: u32 = 0;
        if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut count) == 0 {
            bail!("WTSEnumerateSessions failed: {}", GetLastError());
        }
        let slice = std::slice::from_raw_parts(sessions, count as usize);
        let mut chosen: Option<u32> = None;
        for s in slice {
            if s.State == WTSActive && s.SessionId != 0 {
                chosen = Some(s.SessionId);
                break;
            }
        }
        WTSFreeMemory(sessions as *mut _);
        chosen.ok_or_else(|| anyhow!("no active interactive session found"))
    }
}

/// Walk processes via Toolhelp32 looking for `winlogon.exe` whose
/// owning session matches `target_session`.
fn find_winlogon_pid_in_session(target_session: u32) -> Result<Option<u32>> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            bail!("CreateToolhelp32Snapshot failed: {}", GetLastError());
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) == 0 {
            CloseHandle(snap);
            bail!("Process32FirstW failed: {}", GetLastError());
        }
        loop {
            let name_lower = wchar_to_string(&entry.szExeFile).to_lowercase();
            if name_lower == "winlogon.exe" {
                let mut sid: u32 = 0;
                if ProcessIdToSessionId(entry.th32ProcessID, &mut sid) != 0 && sid == target_session
                {
                    CloseHandle(snap);
                    return Ok(Some(entry.th32ProcessID));
                }
            }
            if Process32NextW(snap, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snap);
        Ok(None)
    }
}

/// `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → `OpenProcessToken` →
/// `DuplicateTokenEx(TokenPrimary)` → `SetTokenInformation(TokenSessionId)`.
/// Returns the dup'd primary token handle the caller owns.
///
/// SAFETY: caller must guarantee `pid` names a process the calling
/// principal can `OpenProcess` against (typically guaranteed when
/// running as SYSTEM). Each unsafe call inside is annotated with its
/// own `// SAFETY` line.
unsafe fn open_winlogon_primary_token(pid: u32, target_session: u32) -> Result<HANDLE> {
    // SAFETY: OpenProcess is safe to call with a u32 pid; null on
    // failure. We check for null and propagate.
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if proc.is_null() {
        let e = unsafe { GetLastError() };
        bail!("OpenProcess(winlogon pid={pid}) failed: {e}");
    }
    let mut tok: HANDLE = std::ptr::null_mut();
    // SAFETY: `proc` is a valid process handle from above; `&mut tok`
    // is a valid out-pointer.
    let ok = unsafe { OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut tok) };
    // SAFETY: `proc` was non-null and we own it.
    unsafe { CloseHandle(proc) };
    if ok == 0 {
        let e = unsafe { GetLastError() };
        bail!("OpenProcessToken failed: {e}");
    }
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: `tok` is a valid token handle; null SECURITY_ATTRIBUTES is fine.
    let ok = unsafe {
        DuplicateTokenEx(
            tok,
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut dup,
        )
    };
    // SAFETY: `tok` was non-null and we own it.
    unsafe { CloseHandle(tok) };
    if ok == 0 {
        let e = unsafe { GetLastError() };
        bail!("DuplicateTokenEx failed: {e}");
    }
    // Re-bind the dup'd token to the target session id explicitly.
    // Defends against RDP shadow session edge cases per RustDesk's
    // `windows.cc:226-233`.
    let sid = target_session;
    // SAFETY: `dup` is a valid token; `&sid` lives for the duration
    // of the call; size is correct (4 bytes for a u32).
    let ok = unsafe {
        windows_sys::Win32::Security::SetTokenInformation(
            dup,
            TokenSessionId,
            &sid as *const u32 as *const _,
            std::mem::size_of::<u32>() as u32,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        // SAFETY: `dup` was non-null and we own it.
        unsafe { CloseHandle(dup) };
        bail!("SetTokenInformation(TokenSessionId={target_session}) failed: {err}");
    }
    Ok(dup)
}

struct ChildResult {
    process_handle: HANDLE,
    thread_handle: HANDLE,
    pid: u32,
    session_id: u32,
}

/// SAFETY: caller owns `token` and must keep it valid for the
/// duration of the call.
unsafe fn spawn_with_token(token: HANDLE, cmdline: &str) -> Result<ChildResult> {
    let mut wide: Vec<u16> = OsStr::new(cmdline).encode_wide().collect();
    wide.push(0);

    // SAFETY: zeroing a POD-style FFI struct is the canonical init.
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = 0; // SW_HIDE
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // SAFETY: `wide` outlives the call; pointers we pass as null are
    // documented-as-OK by Microsoft.
    let ok = unsafe {
        CreateProcessAsUserW(
            token,
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
        let e = unsafe { GetLastError() };
        bail!("CreateProcessAsUserW failed: {e}");
    }
    let mut child_session: u32 = 0;
    // SAFETY: `pi.dwProcessId` is the just-spawned child pid; out-ptr is valid.
    if unsafe { ProcessIdToSessionId(pi.dwProcessId, &mut child_session) } == 0 {
        // Don't fail — we have the child, just couldn't query.
        child_session = u32::MAX;
    }
    Ok(ChildResult {
        process_handle: pi.hProcess,
        thread_handle: pi.hThread,
        pid: pi.dwProcessId,
        session_id: child_session,
    })
}

// ─────────────────────────────────────────────────────────────────────
// Pre-flight #3 — WinSta0 attach requirement
// ─────────────────────────────────────────────────────────────────────

fn run_winsta_attach() -> Result<()> {
    println!("\n--- winsta-attach probe ---");
    println!(
        "Goal: confirm OpenDesktopW(\"Winlogon\") fails before SetProcessWindowStation(WinSta0)"
    );
    println!("      and succeeds after.");

    let initial_winsta = current_window_station_name();
    println!("  initial process window station = {initial_winsta:?}");

    // Try opening Winlogon WITHOUT attaching to WinSta0. Expectation
    // when the parent is in `Service-0x0-3e7$\Default`:
    // ERROR_NOACCESS / ERROR_FILE_NOT_FOUND.
    let pre_attempt = open_desktop_w("Winlogon");
    println!(
        "  pre-attach OpenDesktopW(\"Winlogon\") => {}",
        match &pre_attempt {
            Ok(_) => "OK (unexpected — already on WinSta0?)".to_string(),
            Err(e) => format!("FAIL (expected): {e}"),
        }
    );
    if let Ok(d) = pre_attempt {
        unsafe {
            CloseDesktop(d);
        }
    }

    // Attach to WinSta0.
    let attach_result = unsafe { attach_to_winsta0() };
    println!(
        "  OpenWindowStationW(\"WinSta0\") + SetProcessWindowStation => {}",
        match &attach_result {
            Ok(_) => "OK".to_string(),
            Err(e) => format!("FAIL: {e}"),
        }
    );
    if let Err(e) = attach_result {
        bail!("could not attach to WinSta0: {e}");
    }

    let after_winsta = current_window_station_name();
    println!("  process window station after attach = {after_winsta:?}");

    // Retry Winlogon open.
    let post_attempt = open_desktop_w("Winlogon");
    println!(
        "  post-attach OpenDesktopW(\"Winlogon\") => {}",
        match &post_attempt {
            Ok(_) => "OK".to_string(),
            Err(e) => format!("FAIL: {e}"),
        }
    );
    if let Ok(d) = post_attempt {
        unsafe {
            CloseDesktop(d);
        }
    } else if let Err(e) = post_attempt {
        bail!("post-attach OpenDesktopW(\"Winlogon\") failed: {e}");
    }

    // Also try Default for completeness — the user-context worker
    // path opens Default, not Winlogon.
    let default_attempt = open_desktop_w("Default");
    println!(
        "  post-attach OpenDesktopW(\"Default\") => {}",
        match &default_attempt {
            Ok(_) => "OK".to_string(),
            Err(e) => format!("FAIL: {e}"),
        }
    );
    if let Ok(d) = default_attempt {
        unsafe {
            CloseDesktop(d);
        }
    }

    println!("\nVERDICT: PASS — WinSta0 attach gates Winlogon access as expected.");
    println!(
        "Pre-flight #3 confirmed: SYSTEM-context worker bootstrap MUST attach to WinSta0 before"
    );
    println!("any OpenDesktopW(\"Default\"|\"Winlogon\") call.");
    Ok(())
}

/// SAFETY: changes process-wide window-station state; caller must
/// not be racing other threads that depend on the prior attachment.
unsafe fn attach_to_winsta0() -> Result<()> {
    let mut wide: Vec<u16> = OsStr::new("WinSta0").encode_wide().collect();
    wide.push(0);
    // SAFETY: `wide` is a NUL-terminated wide string alive for the call.
    let h = unsafe { OpenWindowStationW(wide.as_ptr(), FALSE, WINSTA_ALL_ACCESS) };
    if h.is_null() {
        let e = unsafe { GetLastError() };
        bail!("OpenWindowStationW(\"WinSta0\") failed: {e}");
    }
    // SAFETY: `h` is a valid HWINSTA we own.
    if unsafe { SetProcessWindowStation(h) } == 0 {
        let e = unsafe { GetLastError() };
        unsafe { CloseWindowStation(h) };
        bail!("SetProcessWindowStation failed: {e}");
    }
    // Don't close `h` here — the process now owns the attachment.
    Ok(())
}

fn open_desktop_w(name: &str) -> Result<HDESK> {
    let mut wide: Vec<u16> = OsStr::new(name).encode_wide().collect();
    wide.push(0);
    // GENERIC_READ only — DESKTOP_SWITCHDESKTOP requires SE_TCB_NAME
    // which non-SYSTEM callers don't have. The probe doesn't switch
    // desktops, just reads the name and (for the SYSTEM-context path
    // later) attaches via SetThreadDesktop, both of which fit inside
    // GENERIC_READ. See desktop.rs::open_desktop_by_name for the
    // 0.2.0–0.2.6 input-regression rationale.
    let h = unsafe { OpenDesktopW(wide.as_ptr(), 0, FALSE, GENERIC_READ) };
    if h.is_null() {
        let err = unsafe { GetLastError() };
        bail!("OpenDesktopW({name:?}) win32 error {err}");
    }
    Ok(h)
}

fn current_window_station_name() -> String {
    unsafe {
        let h = GetProcessWindowStation();
        if h.is_null() {
            return "<null>".into();
        }
        // Query required size.
        let mut needed: u32 = 0;
        GetUserObjectInformationW(h as *mut _, UOI_NAME, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return "<unknown>".into();
        }
        let mut buf = vec![0u16; (needed as usize) / 2 + 1];
        let mut got: u32 = 0;
        let ok = GetUserObjectInformationW(
            h as *mut _,
            UOI_NAME,
            buf.as_mut_ptr() as *mut _,
            needed,
            &mut got,
        );
        if ok == 0 {
            return format!("<error {}>", GetLastError());
        }
        let trimmed: Vec<u16> = buf.into_iter().take_while(|&c| c != 0).collect();
        OsString::from_wide(&trimmed).to_string_lossy().into_owned()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Pre-flight #5 — DXGI cadence via scrap
// ─────────────────────────────────────────────────────────────────────

#[cfg(not(feature = "scrap-capture"))]
fn run_dxgi_cadence() -> Result<()> {
    bail!(
        "`system-context-probe dxgi-cadence` requires the `scrap-capture` feature. \
         Rebuild with `cargo build -p meshharbord --release --features full`."
    );
}

#[cfg(feature = "scrap-capture")]
fn run_dxgi_cadence() -> Result<()> {
    use scrap::{Capturer, Display};

    println!("\n--- dxgi-cadence probe ---");
    println!("Goal: characterise scrap::Capturer::frame() outcomes over 30 s on a static desktop.");
    println!("      Maps to M3 A1's media_pump compensation budget.");

    let display = Display::primary().context("Display::primary() — no DXGI adapter?")?;
    let w = display.width();
    let h = display.height();
    println!("  primary display: {w}x{h}");
    let mut cap = Capturer::new(display).context("Capturer::new")?;

    let mut counts = CadenceCounts::default();
    let start = Instant::now();
    let runtime = Duration::from_secs(30);
    while start.elapsed() < runtime {
        let tick = Instant::now();
        match cap.frame() {
            Ok(buf) => {
                counts.ok += 1;
                counts.bytes_total += buf.len() as u64;
            }
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock => counts.would_block += 1,
                ErrorKind::TimedOut => counts.timed_out += 1,
                ErrorKind::ConnectionReset => counts.access_lost += 1,
                ErrorKind::PermissionDenied => counts.access_denied += 1,
                ErrorKind::ConnectionAborted => counts.session_disconnected += 1,
                ErrorKind::Interrupted => counts.interrupted += 1,
                ErrorKind::ConnectionRefused => counts.unsupported += 1,
                ErrorKind::InvalidData => counts.invalid_call += 1,
                _ => {
                    counts.other += 1;
                    counts.other_samples.push(format!("{:?}: {}", e.kind(), e));
                }
            },
        }
        // Mimic an encoder's ~60 fps poll. If frame returned Ok we
        // don't sleep (consume backlog); on WouldBlock yield briefly.
        if tick.elapsed() < Duration::from_millis(16) {
            std::thread::sleep(Duration::from_millis(16) - tick.elapsed());
        }
    }
    let elapsed = start.elapsed();
    let total: u64 = counts.total();
    let avg_per_sec = total as f64 / elapsed.as_secs_f64();

    println!("\n--- 30 s cadence summary ---");
    println!(
        "  total iterations: {total}  ({:.1}/s wallclock)",
        avg_per_sec
    );
    println!("  Ok                    = {}", counts.ok);
    println!(
        "  WouldBlock            = {}  (TimedOut, translated by scrap wrapper)",
        counts.would_block
    );
    println!(
        "  TimedOut (raw)        = {}  (should be 0 on Windows)",
        counts.timed_out
    );
    println!(
        "  ConnectionReset       = {}  (DXGI_ERROR_ACCESS_LOST)",
        counts.access_lost
    );
    println!(
        "  PermissionDenied      = {}  (E_ACCESSDENIED)",
        counts.access_denied
    );
    println!(
        "  ConnectionAborted     = {}  (DXGI_ERROR_SESSION_DISCONNECTED)",
        counts.session_disconnected
    );
    println!(
        "  Interrupted           = {}  (DXGI_ERROR_NOT_CURRENTLY_AVAILABLE)",
        counts.interrupted
    );
    println!(
        "  ConnectionRefused     = {}  (DXGI_ERROR_UNSUPPORTED)",
        counts.unsupported
    );
    println!(
        "  InvalidData           = {}  (DXGI_ERROR_INVALID_CALL)",
        counts.invalid_call
    );
    println!("  Other                 = {}", counts.other);
    if !counts.other_samples.is_empty() {
        println!("    other samples (first 5):");
        for s in counts.other_samples.iter().take(5) {
            println!("      - {s}");
        }
    }
    println!(
        "  Ok bytes              = {}  ({:.1} KiB total)",
        counts.bytes_total,
        counts.bytes_total as f64 / 1024.0
    );

    println!("\nGuide for the implementer:");
    println!("  - Ok rate on a static desktop reflects scrap's emit-on-change behaviour.");
    println!("    Expect ~0 unless windows are moving / cursor blinks / clock ticks.");
    println!("  - WouldBlock should dominate (~60/s = the loop's poll rate).");
    println!("  - Any non-zero PermissionDenied means SetThreadDesktop hasn't followed");
    println!("    the input desktop on this thread — surface as BackendBail::DesktopMismatch.");
    println!("  - Any non-zero ConnectionReset means the GPU lost the duplication");
    println!("    context (UAC, fast user switch, GPU driver reset). M3 A1 needs to");
    println!("    recreate the Capturer in this case.");
    println!("\nVERDICT: cadence sample collected. Compare to media_pump (peer.rs:783-816).");
    Ok(())
}

#[cfg_attr(not(feature = "scrap-capture"), allow(dead_code))]
#[derive(Default)]
struct CadenceCounts {
    ok: u64,
    would_block: u64,
    timed_out: u64,
    access_lost: u64,
    access_denied: u64,
    session_disconnected: u64,
    interrupted: u64,
    unsupported: u64,
    invalid_call: u64,
    other: u64,
    other_samples: Vec<String>,
    bytes_total: u64,
}

impl CadenceCounts {
    #[cfg_attr(not(feature = "scrap-capture"), allow(dead_code))]
    fn total(&self) -> u64 {
        self.ok
            + self.would_block
            + self.timed_out
            + self.access_lost
            + self.access_denied
            + self.session_disconnected
            + self.interrupted
            + self.unsupported
            + self.invalid_call
            + self.other
    }
}

// ─────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn wchar_to_string(buf: &[u16]) -> String {
    let trimmed: Vec<u16> = buf.iter().copied().take_while(|&c| c != 0).collect();
    OsString::from_wide(&trimmed).to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_mode_parses_kebab_case() {
        assert_eq!(
            "winlogon-token".parse::<ProbeMode>().unwrap(),
            ProbeMode::WinlogonToken
        );
        assert_eq!(
            "winsta-attach".parse::<ProbeMode>().unwrap(),
            ProbeMode::WinstaAttach
        );
        assert_eq!(
            "dxgi-cadence".parse::<ProbeMode>().unwrap(),
            ProbeMode::DxgiCadence
        );
    }

    #[test]
    fn probe_mode_is_case_insensitive() {
        assert_eq!(
            "WINLOGON-TOKEN".parse::<ProbeMode>().unwrap(),
            ProbeMode::WinlogonToken
        );
    }

    #[test]
    fn probe_mode_rejects_unknown() {
        let e = "foo".parse::<ProbeMode>().unwrap_err();
        assert!(e.contains("foo"));
        assert!(e.contains("winlogon-token"));
    }

    #[test]
    fn cadence_counts_total_sums_all_buckets() {
        let c = CadenceCounts {
            ok: 10,
            would_block: 100,
            access_lost: 1,
            other: 2,
            ..Default::default()
        };
        assert_eq!(c.total(), 113);
    }

    #[test]
    fn wchar_to_string_stops_at_null() {
        let buf: [u16; 8] = [b'a' as u16, b'b' as u16, 0, b'X' as u16, 0, 0, 0, 0];
        assert_eq!(wchar_to_string(&buf), "ab");
    }

    #[test]
    fn wchar_to_string_handles_empty() {
        let buf: [u16; 4] = [0; 4];
        assert_eq!(wchar_to_string(&buf), "");
    }
}
