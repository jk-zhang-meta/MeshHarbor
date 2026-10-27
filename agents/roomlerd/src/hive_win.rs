// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1i — agent sessions on Windows: who a session runs as, which harness
//! it runs, and the session's preparation.
//!
//! A Windows device runs a session as the user signed in at the console, and as
//! nobody else (design §0.1, D2). Never as SYSTEM, and never elevated. Never as
//! another account either, which would take that account's password: there is
//! no S4U and no `LogonUser` here, and the daemon asks for no credential. So
//! `hive_accounts` must map the starter to the console user, and with nobody
//! signed in a start is refused `no_console_user`.
//!
//! The daemon that hosts sessions is the service's WORKER. On a device
//! installed with SystemContext it runs as SYSTEM, in the console session,
//! all the time; without SystemContext, as the console user, elevated
//! (`ROOMLERD_ELEVATE_WORKER`). [`console_user`] reaches the same person from
//! either, at Medium integrity: FR-85's recorder rule, whose token code
//! [`crate::win_token`] now holds for both.
//!
//! These are the Windows counterparts of what the Unix launcher does with
//! `setuid` and a `/bin/sh` wrapper (`hive/supervisor.rs`):
//!
//! | Unix | Windows |
//! |---|---|
//! | `apply_run_as` to the mapped account | [`console_user`]'s token, after [`check_mapping`] |
//! | `resolve_harness` | [`resolve_harness`], then [`harness_command_line`] |
//! | the wrapper, run as the account | `meshharbord hive-prep` ([`prep`]), which [`run_prep`] runs as the console user |
//! | the harness's process group | its Job Object ([`JobObject`], [`spawn_into_job`]) |
//!
//! The supervisor launches through them from P1i-2, which also brings the
//! toolbelt's named pipe and the directories' DACLs here. The Windows release
//! build carries `hive` from P1i-3; until then only a build made with it does.
//!
//! [`JobObject`]: crate::win_service::supervisor::JobObject
//! [`spawn_into_job`]: crate::win_service::supervisor::spawn_into_job

#![cfg(windows)]

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use roomler_ai_remote_control::hive::HiveRefusal;
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetTokenInformation, LookupAccountSidW, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SID_NAME_USE,
    SetFileSecurityW, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OVERLAPPED,
    FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::win_service::supervisor::{
    self, CapturedChild, EnvBlock, JobObject, OwnedHandle, OwnedProcess, SpawnAs,
};

/// The hidden subcommand the daemon runs as the console user before a harness
/// starts: `meshharbord hive-prep <config-dir> <folder> <memory-dir>
/// <auto-memory-dir>`, `<memory-dir>` empty for none.
pub const PREP_SUBCOMMAND: &str = "hive-prep";

/// How long a preparation may take: two directories and two small copies.
pub const PREP_TIMEOUT: Duration = Duration::from_secs(30);

/// What a preparation's output is read up to: it says one line at most.
const PREP_OUTPUT: u64 = 8 * 1024;

/// The user signed in at the console: the one account a session here runs as.
pub struct ConsoleUser {
    /// The console's session id.
    pub session: u32,
    /// `LookupAccountSidW`'s domain: the computer's name for a local account,
    /// `AzureAD` for an Entra ID one, the NetBIOS domain for a domain one.
    pub domain: String,
    pub name: String,
    /// The account's SID (`S-1-5-21-…`): what the session's toolbelt pipe and
    /// runtime directory grant access to (P1i-2).
    pub sid: String,
    /// The profile Windows records for the user, from the token. Never built
    /// from the name: `C:\Users\alice` and `C:\Users\alice.CORP` are two people.
    pub profile: PathBuf,
    /// `%APPDATA%` in the user's own environment, where npm puts `claude.cmd`.
    pub appdata: Option<PathBuf>,
    token: UserToken,
}

/// The token a session's processes start with.
enum UserToken {
    /// The console session's, as Windows hands it out (`WTSQueryUserToken`).
    Session(OwnedHandle),
    /// A restricted, Medium copy of this daemon's own.
    Restricted(crate::win_token::Owned),
}

impl ConsoleUser {
    /// What a session's processes are started as. The token lives as long as
    /// `self`, so `self` must outlive the spawn.
    pub fn spawn_as(&self) -> SpawnAs {
        SpawnAs::User(match &self.token {
            UserToken::Session(t) => t.raw(),
            UserToken::Restricted(t) => t.raw(),
        })
    }

    /// `DOMAIN\name`.
    pub fn qualified(&self) -> String {
        format!("{}\\{}", self.domain, self.name)
    }
}

/// Who a session here runs as, or why none can: the same person, at Medium
/// integrity, whichever worker hosts it.
///
/// | this daemon is | a session runs as |
/// |---|---|
/// | SYSTEM | the user signed in at the console, by the token Windows hands out for that session (`WTSQueryUserToken`), which for a UAC administrator is the filtered one; `no_console_user` with nobody signed in |
/// | a person (the worker, often elevated) | that person, by a restricted, Medium copy of this daemon's own token ([`crate::win_token::restricted_medium_copy`]): every administrator group deny-only, no privilege but traverse |
pub fn console_user() -> Result<ConsoleUser, (HiveRefusal, String)> {
    if crate::win_identity::process_is_local_system() {
        signed_in_user()
    } else {
        this_user()
    }
}

/// This daemon's own person, never elevated.
fn this_user() -> Result<ConsoleUser, (HiveRefusal, String)> {
    let token = crate::win_token::restricted_medium_copy().map_err(|e| {
        (
            HiveRefusal::LaunchFailed,
            format!("a restricted copy of this daemon's token: {e}"),
        )
    })?;
    let mut session = 0u32;
    // SAFETY: GetCurrentProcessId has no preconditions; `session` is a valid
    // out-param.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) };
    user_of(session, UserToken::Restricted(token))
}

/// The user signed in at the console, for a daemon that is SYSTEM.
fn signed_in_user() -> Result<ConsoleUser, (HiveRefusal, String)> {
    let Some(session) = supervisor::active_console_session_id() else {
        return Err((
            HiveRefusal::NoConsoleUser,
            "nobody is signed in at the console, and on Windows a session runs only as the \
             console user"
                .into(),
        ));
    };
    let token = match supervisor::query_user_token(session) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Err((
                HiveRefusal::NoConsoleUser,
                format!(
                    "nobody is signed in at the console (session {session} has no user), and on \
                     Windows a session runs only as the console user"
                ),
            ));
        }
        Err(e) => {
            return Err((
                HiveRefusal::LaunchFailed,
                format!("cannot obtain the console user's token ({e})"),
            ));
        }
    };
    user_of(session, UserToken::Session(token))
}

/// The person `token` is for: their account, SID, profile and `%APPDATA%`.
fn user_of(session: u32, token: UserToken) -> Result<ConsoleUser, (HiveRefusal, String)> {
    let raw = match &token {
        UserToken::Session(t) => t.raw(),
        UserToken::Restricted(t) => t.raw(),
    };
    let (domain, name) = account_of_token(raw).map_err(|e| {
        (
            HiveRefusal::LaunchFailed,
            format!("reading the console user's account: {e}"),
        )
    })?;
    let sid = sid_of_token(raw).map_err(|e| {
        (
            HiveRefusal::LaunchFailed,
            format!("reading the console user's SID: {e}"),
        )
    })?;
    let profile = crate::win_identity::profile_dir_of_token(raw)
        .map(PathBuf::from)
        .ok_or_else(|| {
            (
                HiveRefusal::LaunchFailed,
                format!("{domain}\\{name} has no profile directory"),
            )
        })?;
    let appdata = EnvBlock::for_token(raw)
        .ok()
        .and_then(|block| env_value(&block.entries(), "APPDATA"))
        .map(PathBuf::from);
    Ok(ConsoleUser {
        session,
        domain,
        name,
        sid,
        profile,
        appdata,
        token,
    })
}

/// A token's `TOKEN_USER`, in `u64`s so the structure, which holds a pointer,
/// is aligned; the SID it points at lives in the same buffer. `token` must be
/// live, with `TOKEN_QUERY`.
fn token_user(token: HANDLE) -> Result<Vec<u64>, String> {
    let mut len: u32 = 0;
    // SAFETY: the documented size query: no buffer, the size written to `len`.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(format!(
            "GetTokenInformation(TokenUser): {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` bytes and outlives the call.
    if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0
    {
        return Err(format!(
            "GetTokenInformation(TokenUser): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(buf)
}

/// The SID string (`S-1-5-21-…`) of the account `token` is for. `token` must
/// be live, with `TOKEN_QUERY`.
fn sid_of_token(token: HANDLE) -> Result<String, String> {
    let buf = token_user(token)?;
    // SAFETY: a TOKEN_USER, whose SID points into `buf`, alive below.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: a valid SID; `text` receives a LocalAlloc'd string, freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(format!(
            "ConvertSidToStringSidW: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: a NUL-terminated wide string the call allocated.
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    // SAFETY: `len` units were just read from `text`.
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
    // SAFETY: the one allocation ConvertSidToStringSidW made, freed once.
    unsafe { LocalFree(text as _) };
    Ok(s)
}

/// This process's own account's SID string.
pub fn own_sid() -> Result<String, String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: our own process's token, closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!(
            "OpenProcessToken: {}",
            std::io::Error::last_os_error()
        ));
    }
    let sid = sid_of_token(token);
    // SAFETY: the handle OpenProcessToken gave us, closed once.
    unsafe { CloseHandle(token) };
    sid
}

/// The SID string of the account at the far end of a server pipe instance:
/// the process that connected, by its pid, and its token. `pipe` must be a
/// live, connected server end.
///
/// A pid can name another process by the time it is read, if the client
/// exited at once. Then this reads that other process's account: one the pipe
/// refuses unless it is the same account, whose dead connection carries
/// nothing. The pipe's DACL decides who may connect at all.
pub(crate) fn pipe_client_sid(pipe: HANDLE) -> Result<String, String> {
    let mut pid = 0u32;
    // SAFETY: a live server pipe handle; `pid` is a valid out-param.
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
        return Err(format!(
            "GetNamedPipeClientProcessId: {}",
            std::io::Error::last_os_error()
        ));
    }
    process_sid(pid)
}

/// The SID string of the account a process runs as, by its pid, from its
/// token. A pid read from elsewhere can name another process by now, if its
/// own exited: callers compare the account, and refuse any but the one they
/// serve.
pub(crate) fn process_sid(pid: u32) -> Result<String, String> {
    // SAFETY: a plain open; closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(format!(
            "OpenProcess({pid}): {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: a live process handle; `token` is closed below.
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } != 0;
    // SAFETY: the handle OpenProcess gave us, closed once.
    unsafe { CloseHandle(process) };
    if !opened {
        return Err(format!(
            "OpenProcessToken({pid}): {}",
            std::io::Error::last_os_error()
        ));
    }
    let sid = sid_of_token(token);
    // SAFETY: the handle OpenProcessToken gave us, closed once.
    unsafe { CloseHandle(token) };
    sid
}

/// FR-90 P3-5b-4 — the pid of the process at the client end of a loopback
/// TCP connection this daemon accepted: the row of the system's connection
/// table whose local end is `client` and whose remote end is `server`.
/// `None` when no row is that connection (its client has gone).
pub(crate) fn tcp_client_pid(
    client: std::net::SocketAddrV4,
    server: std::net::SocketAddrV4,
) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
    };
    const AF_INET: u32 = 2;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    // An address as a row holds it (network order, as stored), and a port
    // (network order, in the low word).
    let addr = |ip: &std::net::Ipv4Addr| u32::from_ne_bytes(ip.octets());
    let port = |raw: u32| u16::from_be((raw & 0xffff) as u16);
    let mut size = 0u32;
    // The table grows when connections open between the size it reports and
    // the read: asked again with the room it then says it needs.
    for _ in 0..4 {
        let mut buf = vec![0u32; (size as usize).div_ceil(4) + 1];
        let mut len = (buf.len() * 4) as u32;
        // SAFETY: `buf` holds `len` bytes, aligned for the rows' u32 fields.
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut len,
                0,
                AF_INET,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if rc == ERROR_INSUFFICIENT_BUFFER {
            size = len;
            continue;
        }
        if rc != 0 {
            return None;
        }
        let room = (buf.len() - 1) * 4 / std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
        let n = (buf[0] as usize).min(room);
        // SAFETY: the table is `dwNumEntries` then that many rows, which the
        // API wrote into `buf`; `n` is bounded by the room `buf` has.
        let rows = unsafe {
            std::slice::from_raw_parts(buf.as_ptr().add(1).cast::<MIB_TCPROW_OWNER_PID>(), n)
        };
        return rows
            .iter()
            .find(|r| {
                r.dwLocalAddr == addr(client.ip())
                    && port(r.dwLocalPort) == client.port()
                    && r.dwRemoteAddr == addr(server.ip())
                    && port(r.dwRemotePort) == server.port()
            })
            .map(|r| r.dwOwningPid);
    }
    None
}

/// FR-97 P4c — who is at the far end of a server pipe instance, by the
/// security context the pipe carries for its client: their SID and account.
pub(crate) struct PipePeer {
    pub sid: String,
    pub domain: String,
    pub name: String,
}

impl PipePeer {
    /// `DOMAIN\name`.
    pub fn qualified(&self) -> String {
        format!("{}\\{}", self.domain, self.name)
    }

    /// An account that runs services, or nobody at all, rather than a person:
    /// SYSTEM, LOCAL SERVICE, NETWORK SERVICE, and the anonymous logon a
    /// client that forbade identification shows. The adopt pipe refuses them
    /// as the Unix socket refuses root.
    pub fn is_service(&self) -> bool {
        is_service_sid(&self.sid)
    }
}

/// The well-known SIDs of [`PipePeer::is_service`].
pub(crate) fn is_service_sid(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-7")
}

/// FR-97 P4c — the client of a server pipe instance, by impersonating it just
/// long enough to take its token. The caller must have read from the pipe
/// first: Windows names the client by the last message read.
///
/// No pid is involved, unlike [`pipe_client_sid`]. The adopt pipe takes any
/// interactive user, so a client that ended (its pipe handle passed to a
/// process of its own) must never be named by whatever process took its pid.
///
/// The impersonation ends before any lookup. A client may allow no more than
/// identification (tokio's default), and an LSA call made while wearing that
/// fails with `ERROR_BAD_IMPERSONATION_LEVEL`; the token handle, opened as
/// this process, answers the same questions after the revert.
pub(crate) fn pipe_peer(pipe: HANDLE) -> Result<PipePeer, String> {
    use windows_sys::Win32::Security::RevertToSelf;
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    /// Ends this thread's impersonation, even on an early return.
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // SAFETY: ends this thread's impersonation.
            if unsafe { RevertToSelf() } == 0 {
                // A thread left wearing a client's identity would act as them
                // in whatever it ran next. There is no safe way on; the
                // service manager restarts the daemon.
                std::process::abort();
            }
        }
    }

    // SAFETY: a live, connected server end the caller has read from.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(format!(
            "ImpersonateNamedPipeClient: {}",
            std::io::Error::last_os_error()
        ));
    }
    let revert = Revert;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: this thread's impersonation token, opened as the PROCESS
    // (`OpenAsSelf` = TRUE: an identification-level token may not open
    // itself); `token` is closed below.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0;
    let open_error = std::io::Error::last_os_error();
    drop(revert);
    if !opened {
        return Err(format!("OpenThreadToken: {open_error}"));
    }
    let sid = sid_of_token(token);
    let account = account_of_token(token);
    // SAFETY: the handle OpenThreadToken gave us, closed once.
    unsafe { CloseHandle(token) };
    let (domain, name) = account?;
    Ok(PipePeer {
        sid: sid?,
        domain,
        name,
    })
}

/// The pid of a server pipe instance's client, for what it is good for: the
/// adopt sweep's terminal lookup ([`crate::hive::procs::hook_terminal`]).
/// Never who the client is: that is [`pipe_peer`]'s.
pub(crate) fn pipe_client_pid(pipe: HANDLE) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: a live server pipe handle; `pid` is a valid out-param.
    (unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } != 0 && pid != 0).then_some(pid)
}

/// The account a token is for, as `(domain, name)`. `token` must be live,
/// with `TOKEN_QUERY`.
fn account_of_token(token: HANDLE) -> Result<(String, String), String> {
    let buf = token_user(token)?;
    // SAFETY: a TOKEN_USER, whose SID points into `buf`, alive below.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    let (mut name_len, mut domain_len) = (0u32, 0u32);
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: the documented size query: null buffers, the sizes written out.
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        )
    };
    if name_len == 0 {
        return Err(format!(
            "LookupAccountSidW: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    domain_len = domain.len() as u32;
    // SAFETY: both buffers hold the sizes passed and outlive the call.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return Err(format!(
            "LookupAccountSidW: {}",
            std::io::Error::last_os_error()
        ));
    }
    // On success the lengths exclude the terminators.
    let name = &name[..(name_len as usize).min(name.len())];
    let domain = &domain[..(domain_len as usize).min(domain.len())];
    Ok((
        String::from_utf16_lossy(domain),
        String::from_utf16_lossy(name),
    ))
}

/// Whether `mapped`, what `hive_accounts` maps the starter to, names the
/// console user `domain\name`. It may say `name`, `DOMAIN\name`, or `.\name`
/// for an account local to this computer (`computer`), compared
/// case-insensitively, as Windows compares account names. An empty name never
/// matches, nor does `.` on a computer whose name is unknown.
pub fn names_console_user(mapped: &str, domain: &str, name: &str, computer: &str) -> bool {
    let same = |a: &str, b: &str| !a.is_empty() && a.to_uppercase() == b.to_uppercase();
    let mapped = mapped.trim();
    match mapped.split_once('\\') {
        None => same(mapped, name),
        Some((".", n)) => same(computer, domain) && same(n, name),
        Some((d, n)) => same(d, domain) && same(n, name),
    }
}

/// A start's account gate on Windows: what `hive_accounts` maps the starter to
/// must name the console user. A refusal says who is at the console, which is
/// what the device's owner needs to fix the map.
pub fn check_mapping(mapped: &str, console: &ConsoleUser) -> Result<(), (HiveRefusal, String)> {
    let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
    check_mapping_for(mapped, &console.domain, &console.name, &computer)
}

fn check_mapping_for(
    mapped: &str,
    domain: &str,
    name: &str,
    computer: &str,
) -> Result<(), (HiveRefusal, String)> {
    if names_console_user(mapped, domain, name, computer) {
        return Ok(());
    }
    Err((
        HiveRefusal::NoAccount,
        format!(
            "this user maps to {mapped:?}, but {domain}\\{name} is signed in at the console, and \
             on Windows a session runs only as the console user (map them to `name` or \
             `DOMAIN\\name`)"
        ),
    ))
}

/// Where Claude Code is looked for, in order: `hive_harness` alone when it is
/// set; else the native installer's `%USERPROFILE%\.local\bin\claude.exe`, then
/// npm's `%APPDATA%\npm\claude.cmd`.
pub fn harness_candidates(
    configured: Option<&Path>,
    profile: &Path,
    appdata: Option<&Path>,
) -> Vec<PathBuf> {
    if let Some(h) = configured {
        return vec![h.to_path_buf()];
    }
    let mut c = vec![profile.join(".local").join("bin").join("claude.exe")];
    if let Some(a) = appdata {
        c.push(a.join("npm").join("claude.cmd"));
    }
    c
}

/// The first candidate that is a file, or `None`: `harness_missing`.
pub fn resolve_harness(
    configured: Option<&Path>,
    profile: &Path,
    appdata: Option<&Path>,
) -> Option<PathBuf> {
    harness_candidates(configured, profile, appdata)
        .into_iter()
        .find(|p| std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false))
}

/// One argument as `CommandLineToArgvW` and the C runtime read it back:
/// as it is when nothing in it needs quoting; otherwise in quotes, each `"`
/// escaped, and each run of backslashes before a `"`, or before the closing
/// quote, doubled.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut slashes = 0usize;
    for c in arg.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        if c == '"' {
            out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
        } else {
            out.extend(std::iter::repeat_n('\\', slashes));
        }
        slashes = 0;
        out.push(c);
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}

/// A program's path as the first token of a command line: in quotes, which a
/// Windows path cannot contain, so no escaping is needed and none is possible.
fn program(path: &Path) -> Result<String, String> {
    let p = utf8(path.as_os_str(), "the program's path")?;
    if p.contains('"') {
        return Err(format!("{p} holds a quote"));
    }
    Ok(format!("\"{p}\""))
}

fn utf8<'a>(s: &'a std::ffi::OsStr, what: &str) -> Result<&'a str, String> {
    s.to_str()
        .ok_or_else(|| format!("{what} is not valid Unicode: {}", s.to_string_lossy()))
}

/// What `cmd.exe` reads as its own, inside quotes or out: expansion (`%`, and
/// `!` should delayed expansion be on), escapes, and the quote itself.
const CMD_UNSAFE_ANYWHERE: &[char] = &['%', '!', '^', '"'];
/// What it reads as its own outside quotes, where an argument the shim passes
/// on with `%*` lands: npm's `claude.cmd` expands `%*` inside an `IF (…)` block,
/// so a `)` there ends the block early.
const CMD_UNSAFE_UNQUOTED: &[char] = &['&', '|', '<', '>', '(', ')'];

/// The command line that starts `harness` with `args`.
///
/// An `.exe` runs directly, each argument quoted for the C runtime. A `.cmd`
/// or `.bat` (npm's shim) runs through `cmd.exe`, which reads the line again
/// by its own rules, and the shim passes it on once more with `%*`. No quoting
/// is right for both readers, so there an argument, or the path, holding one of
/// cmd's metacharacters is refused, never escaped. Anything else is refused,
/// because it would not start.
pub fn harness_command_line(harness: &Path, args: &[OsString]) -> Result<String, String> {
    let ext = harness
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    let args: Vec<&str> = args
        .iter()
        .map(|a| utf8(a, "an argument"))
        .collect::<Result<_, _>>()?;
    match ext.as_deref() {
        Some("exe") => {
            let mut line = program(harness)?;
            for a in args {
                line.push(' ');
                line.push_str(&quote_arg(a));
            }
            Ok(line)
        }
        Some("cmd" | "bat") => {
            let path = utf8(harness.as_os_str(), "the harness's path")?;
            if path.contains(CMD_UNSAFE_ANYWHERE) || path.contains(char::is_control) {
                return Err(format!(
                    "{path} holds a character cmd.exe would read as its own; install Claude Code \
                     where its path has none, or set hive_harness to its .exe"
                ));
            }
            let mut inner = format!("\"{path}\"");
            for a in args {
                if a.contains(CMD_UNSAFE_ANYWHERE)
                    || a.contains(CMD_UNSAFE_UNQUOTED)
                    || a.contains(char::is_control)
                {
                    return Err(format!(
                        "the argument {a:?} holds a character cmd.exe would read as its own, so \
                         {path} cannot be given it safely; set hive_harness to Claude Code's .exe"
                    ));
                }
                inner.push(' ');
                inner.push_str(&quote_arg(a));
            }
            // `/s`: cmd strips the first and the last quote and runs the rest
            // as it stands. `/d`: no AutoRun from the registry runs first.
            // `/v:off`: no delayed expansion, whatever the registry says.
            Ok(format!(
                "{} /d /v:off /s /c \"{inner}\"",
                program(&system_cmd())?
            ))
        }
        _ => Err(format!(
            "{} is neither an .exe nor a .cmd, so Windows cannot start it",
            harness.display()
        )),
    }
}

/// `%SystemRoot%\System32\cmd.exe`, by its full path: a bare `cmd.exe` is
/// looked for in the daemon's own directory first.
pub(crate) fn system_cmd() -> PathBuf {
    std::env::var_os("SystemRoot")
        .filter(|r| !r.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join("cmd.exe")
}

/// A variable's value among an environment block's entries, the name compared
/// case-insensitively.
fn env_value(entries: &[Vec<u16>], name: &str) -> Option<OsString> {
    let name: Vec<u16> = name.encode_utf16().collect();
    entries.iter().find_map(|e| {
        let (n, rest) = e.split_at_checked(name.len())?;
        let (eq, value) = rest.split_first()?;
        (*eq == u16::from(b'=')
            && String::from_utf16_lossy(n).to_uppercase()
                == String::from_utf16_lossy(&name).to_uppercase())
        .then(|| OsString::from_wide(value))
    })
}

/// `meshharbord hive-prep`'s arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepArgs {
    /// `CLAUDE_CONFIG_DIR`: made, as the user.
    pub config_dir: PathBuf,
    /// The session's folder: it must open as the user.
    pub folder: PathBuf,
    /// The daemon's copy of the session's core memory, when the start came
    /// with one and the device shows it.
    pub memory_dir: Option<PathBuf>,
    /// Where `MEMORY.md` goes.
    pub auto_memory_dir: PathBuf,
}

impl PrepArgs {
    /// This process's own, when it was started as `meshharbord hive-prep`:
    /// `None` when it was not, and an error when it was, wrongly.
    pub fn from_env() -> Option<Result<Self, String>> {
        Self::parse(std::env::args_os().skip(1))
    }

    fn parse(mut args: impl Iterator<Item = OsString>) -> Option<Result<Self, String>> {
        if args.next()? != PREP_SUBCOMMAND {
            return None;
        }
        let rest: Vec<OsString> = args.collect();
        let given = rest.len();
        let Ok([config_dir, folder, memory, auto_memory_dir]) = <[OsString; 4]>::try_from(rest)
        else {
            return Some(Err(format!(
                "{PREP_SUBCOMMAND} takes four arguments (<config-dir> <folder> <memory-dir> \
                 <auto-memory-dir>), got {given}"
            )));
        };
        Some(Ok(Self {
            config_dir: config_dir.into(),
            folder: folder.into(),
            memory_dir: (!memory.is_empty()).then(|| memory.into()),
            auto_memory_dir: auto_memory_dir.into(),
        }))
    }

    /// The command line that runs it: `"<exe>" hive-prep …`.
    pub fn command_line(&self, exe: &Path) -> Result<String, String> {
        let mut line = program(exe)?;
        line.push(' ');
        line.push_str(PREP_SUBCOMMAND);
        let empty = PathBuf::new();
        for p in [
            &self.config_dir,
            &self.folder,
            self.memory_dir.as_ref().unwrap_or(&empty),
            &self.auto_memory_dir,
        ] {
            line.push(' ');
            line.push_str(&quote_arg(utf8(p.as_os_str(), "a path")?));
        }
        Ok(line)
    }
}

/// Prepare a session, as the user it runs as: what the Unix wrapper does as
/// the account before it becomes the harness.
///
/// Makes the config directory. When the start came with core memory, copies
/// its `CLAUDE.md` into the config directory and its `MEMORY.md` into the
/// auto-memory directory, each only when nothing is there yet, so a resume
/// keeps what the session has, its own edits included; a copy that fails is
/// skipped, because memory never stops a session. Last, the folder must open
/// as this user, as the wrapper's `cd` requires.
///
/// The directories are made under the user's profile and inherit its
/// permissions, which are the user's own: the counterpart of the wrapper's
/// `umask 077`.
pub fn prep(args: &PrepArgs) -> Result<(), String> {
    let paths = [
        ("the config directory", Some(&args.config_dir)),
        ("the folder", Some(&args.folder)),
        ("the memory directory", args.memory_dir.as_ref()),
        ("the auto-memory directory", Some(&args.auto_memory_dir)),
    ];
    for (what, path) in paths {
        if let Some(p) = path
            && !p.is_absolute()
        {
            return Err(format!(
                "{what} must be an absolute path, got {}",
                p.display()
            ));
        }
    }
    std::fs::create_dir_all(&args.config_dir)
        .map_err(|e| format!("making {}: {e}", args.config_dir.display()))?;
    if let Some(memory) = &args.memory_dir {
        copy_if_absent(&memory.join("CLAUDE.md"), &args.config_dir, "CLAUDE.md");
        copy_if_absent(
            &memory.join("MEMORY.md"),
            &args.auto_memory_dir,
            "MEMORY.md",
        );
    }
    std::fs::read_dir(&args.folder)
        .map(drop)
        .map_err(|e| format!("{} does not open as this user: {e}", args.folder.display()))
}

/// `src` into `dir\name` when `src` is a file and nothing is at the
/// destination, not even a link; `dir` is made when it must be. Every failure
/// is skipped.
fn copy_if_absent(src: &Path, dir: &Path, name: &str) {
    let dst = dir.join(name);
    let is_file = std::fs::metadata(src).map(|m| m.is_file()).unwrap_or(false);
    if !is_file || std::fs::symlink_metadata(&dst).is_ok() {
        return;
    }
    if std::fs::create_dir_all(dir).is_ok() {
        let _ = std::fs::copy(src, &dst);
    }
}

/// Run `cmdline` (a [`PrepArgs::command_line`]) as `who`, and wait for it, at
/// most `timeout`: `Ok` when it exited 0, else what it said, for the refusal.
/// It runs in a job of its own, so a preparation that hangs is ended whole.
///
/// # Safety
/// As [`spawn_into_job`](supervisor::spawn_into_job): `SpawnAs::User`'s token
/// must stay alive across the call.
pub unsafe fn run_prep(who: SpawnAs, cmdline: &str, timeout: Duration) -> Result<(), String> {
    let job = JobObject::kill_on_close().map_err(|e| format!("{e:#}"))?;
    // SAFETY: forwarded from the caller.
    let child = unsafe { supervisor::spawn_into_job(who, cmdline, None, &[], false, &job) }
        .map_err(|e| format!("{e:#}"))?;
    let CapturedChild {
        process,
        stdout,
        stderr,
        ..
    } = child;
    // Both pipes at once (one read to the end first deadlocks on the other),
    // and bounded.
    let budget = Arc::new(AtomicU64::new(PREP_OUTPUT));
    let out_budget = Arc::clone(&budget);
    let out = std::thread::spawn(move || supervisor::read_pipe_to_end(&stdout, &out_budget));
    let err = std::thread::spawn(move || supervisor::read_pipe_to_end(&stderr, &budget));
    let finished = process.wait_for_exit(timeout);
    if !finished {
        let _ = job.terminate(1);
        let _ = process.wait_for_exit(Duration::from_secs(5));
    }
    let _ = out.join();
    let said = err
        .join()
        .map(|(bytes, _)| String::from_utf8_lossy(&bytes).trim().to_string())
        .unwrap_or_default();
    if !finished {
        return Err(format!(
            "preparing the session did not finish within {} s",
            timeout.as_secs()
        ));
    }
    match process.try_wait() {
        Ok(Some(0)) => Ok(()),
        Ok(Some(code)) if said.is_empty() => {
            Err(format!("preparing the session failed (exit {code})"))
        }
        Ok(Some(_)) => Err(said),
        Ok(None) => Err("preparing the session had not ended".into()),
        Err(e) => Err(format!("{e:#}")),
    }
}

// ─── P1i-2: where a session's files live, and who may touch them ────────────
//
// On Windows the daemon that hosts sessions is the WORKER: SYSTEM on a device
// installed with SystemContext, else the console user, elevated
// (`ROOMLERD_ELEVATE_WORKER`); a remote-desktop connection changes neither.
// Either reaches the service's machine-wide directory, so the store, what the
// device hosts and each session's runtime files live there, and a new worker
// finds what the last one hosted. Every directory is owned by
// Administrators with a protected DACL, so a folder someone else made there
// first is taken over, never trusted: as its owner its maker would keep
// WRITE_DAC whatever the DACL said.

/// The replica store's directory and the runtime root: SYSTEM's and
/// Administrators', owned by Administrators, inheritance off. Unix's `0700` for
/// a daemon that runs as SYSTEM or as an elevated administrator. A session's
/// restricted Medium token, whose Administrators group is deny-only, reads none
/// of it.
///
/// P1i-4 — except one grant, on the directory itself: `FILE_READ_ATTRIBUTES |
/// SYNCHRONIZE` (`0x100080`) for Authenticated Users, inherited by nothing.
/// Both directories lie on the way to every session's files
/// (`…\hive\run\<sid>\settings.json`), and Claude Code examines each component
/// of a path it is handed and refuses the file when one cannot be examined:
/// "Refusing to read a file whose path could not be vetted". Field-found on
/// Windows 11, Claude Code 2.1.296, which `FILE_READ_ATTRIBUTES` alone let
/// through; `SYNCHRONIZE` too, because `CreateFileW` asks for it with every
/// synchronous open, libuv's `lstat` and Rust's among them. The grant is a stat
/// of the directory alone: it lists nothing, so the sessions' ids stay unknown,
/// and another session's directory stays unexaminable, its own DACL granting
/// only its account.
pub const PRIVATE_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x100080;;;AU)";

/// A session's own runtime directory: its account (`peer`) may also list,
/// traverse and read it (`0x1200a9`) for its settings, its MCP config and its
/// core memory, and write nothing.
pub fn session_dir_sddl(peer: &str) -> String {
    format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;{peer})")
}

/// A session's toolbelt pipe: SYSTEM's and Administrators' (the daemon is one
/// or the other, and makes an instance for each client), and the session's
/// account's (`peer`) to read and write (`0x12008b`). Not `GENERIC_WRITE`,
/// which carries `FILE_CREATE_PIPE_INSTANCE`: with it a process of that account
/// could add an instance of its own under the name and take the next
/// connection, so the relay opens the pipe with exactly this mask
/// ([`open_toolbelt_pipe`]). A session's token is a restricted copy whose
/// Administrators group is deny-only, so the last grant is all it has, even
/// when the daemon is the same person, elevated. The Medium no-write-up label
/// keeps anything below Medium integrity from writing to it.
pub fn toolbelt_pipe_sddl(peer: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;{peer})S:(ML;;NW;;;ME)")
}

/// FR-90 P3-5f-3 — a vault SSH agent's pipe: SYSTEM's and Administrators', as
/// the toolbelt pipe's, and the session's account's (`peer`) to open for
/// reading and writing whole (`GRGW`), since that is how Win32-OpenSSH opens
/// an agent (`GENERIC_READ | GENERIC_WRITE`, its `fileio_connect`). The
/// toolbelt pipe's `0x12008b` leaves out `FILE_APPEND_DATA`,
/// `FILE_WRITE_ATTRIBUTES` and `FILE_WRITE_EA`, so a session's `ssh.exe`, whose
/// token's Administrators group is deny-only, would be refused.
///
/// ⚠️ `GENERIC_WRITE` carries `FILE_CREATE_PIPE_INSTANCE`: a process of that
/// account could add an instance of its own and take the next `ssh`'s agent
/// connection. Unlike on the toolbelt pipe, that gains it nothing it lacks: it
/// can already connect to the agent as that account, and point its own `ssh`
/// anywhere; the key never crosses the pipe.
pub fn agent_pipe_sddl(peer: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{peer})S:(ML;;NW;;;ME)")
}

/// FR-97 P4c — the adopt pipe: the toolbelt pipe's grants, with every
/// Interactive user (`IU`) in place of one session's account, since any person
/// at this machine may adopt their own terminal sessions.
///
/// - The same `0x12008b` for a person, never `GENERIC_WRITE`: its
///   `FILE_CREATE_PIPE_INSTANCE` would let a person add an instance of their
///   own and take another person's next hook. The hook opens the pipe with
///   exactly this mask (`hive_adopt::open_pipe`).
/// - The daemon's own account (`daemon`, its SID) as well as SYSTEM and
///   Administrators. An attended worker that could not be elevated is a
///   person whose Administrators group is deny-only, and it must still add an
///   instance for every client. Its account's other processes gain nothing:
///   they hold everything the daemon holds already, and another person's
///   hook sends nothing to a pipe owned by neither SYSTEM nor that person.
///
/// Who each client is, the daemon reads from its token ([`pipe_peer`]).
pub fn adopt_pipe_sddl(daemon: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{daemon})(A;;0x12008b;;;IU)S:(ML;;NW;;;ME)")
}

/// The replica store's directory, `%ProgramData%\roomler\roomler\hive`, also
/// holding what the device hosts.
pub fn store_dir() -> PathBuf {
    roomler_node_core::appdirs::machine_global_dir().join("hive")
}

/// Where each session's runtime directory is made: `…\hive\run`.
pub fn runtime_root() -> PathBuf {
    store_dir().join("run")
}

/// A security descriptor built from SDDL, and the `SECURITY_ATTRIBUTES` that
/// hand it to `CreateDirectoryW` or a pipe instance. Frees it on drop.
pub struct Sddl {
    sa: SECURITY_ATTRIBUTES,
    psd: PSECURITY_DESCRIPTOR,
}

// SAFETY: the descriptor is a LocalAlloc'd buffer with no thread affinity;
// freeing it on another thread is sound. A pipe's accept loop holds one across
// `.await`.
unsafe impl Send for Sddl {}

impl Sddl {
    pub fn new(sddl: &str) -> std::io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string; `psd` receives a LocalAlloc'd
        // descriptor, freed in Drop; the size out-param is optional.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            sa: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            },
            psd,
        })
    }

    /// Valid while `self` lives; the system copies the descriptor into each
    /// object made with it.
    pub fn attributes(&mut self) -> *mut SECURITY_ATTRIBUTES {
        &raw mut self.sa
    }
}

impl Drop for Sddl {
    fn drop(&mut self) {
        // SAFETY: the one descriptor ConvertStringSecurityDescriptor… made.
        unsafe { LocalFree(self.psd as _) };
    }
}

/// Make the directory `dir` with `sddl`'s owner and DACL, or give the plain
/// directory already there that owner and DACL, protected from inheritance. Its
/// parent must exist. The owner is set as well because an owner keeps
/// WRITE_DAC whatever the DACL says: a folder someone else made there first
/// would otherwise stay theirs to reopen. A link or junction on the way, or
/// anything but a directory in its place, is refused, never followed.
pub fn dir_with_dacl(dir: &Path, sddl: &str) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    if let Some(link) = roomler_node_core::recording_dir::link_component(dir) {
        return Err(format!("{} is a link", link.display()));
    }
    let failed = |e: std::io::Error| format!("{}: {e}", dir.display());
    let mut sd = Sddl::new(sddl).map_err(failed)?;
    let wide: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    match std::fs::symlink_metadata(dir) {
        Ok(m) => {
            if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(format!("{} is not a plain directory", dir.display()));
            }
            // SAFETY: a NUL-terminated path; the descriptor lives in `sd`.
            let ok = unsafe {
                SetFileSecurityW(
                    wide.as_ptr(),
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    sd.psd,
                )
            };
            if ok == 0 {
                return Err(failed(std::io::Error::last_os_error()));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // SAFETY: a NUL-terminated path; the attributes live in `sd`.
            if unsafe { CreateDirectoryW(wide.as_ptr(), sd.attributes()) } == 0 {
                return Err(failed(std::io::Error::last_os_error()));
            }
            Ok(())
        }
        Err(e) => Err(failed(e)),
    }
}

/// The client end of a session's toolbelt pipe, opened for reading and for
/// writing data only: the access its DACL grants ([`toolbelt_pipe_sddl`]).
/// Overlapped, as tokio needs, and at the identification level, so the daemon
/// can name the relay's account and never act as it.
pub fn open_toolbelt_pipe(
    name: &Path,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let wide: Vec<u16> = name
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: a NUL-terminated name; the handle is handed to tokio below, or
    // closed.
    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | FILE_WRITE_DATA,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a pipe handle opened overlapped, owned from here by tokio.
    match unsafe { tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(h as _) } {
        Ok(c) => Ok(c),
        Err(e) => {
            // SAFETY: tokio did not take it; closed once.
            unsafe { CloseHandle(h) };
            Err(e)
        }
    }
}

/// A harness started into its Job Object, with the surface of tokio's
/// `Child` the session task uses: its three pipes as async files, and `id`,
/// `wait` and `start_kill`. Dropping it closes the job, which ends the harness
/// and everything it started, as `kill_on_drop` does on Unix.
pub struct HarnessChild {
    pub stdin: Option<tokio::fs::File>,
    pub stdout: Option<tokio::fs::File>,
    pub stderr: Option<tokio::fs::File>,
    process: OwnedProcess,
    job: JobObject,
    status: Option<std::process::ExitStatus>,
}

impl HarnessChild {
    pub fn new(child: CapturedChild, job: JobObject) -> Self {
        let file = |h: OwnedHandle| {
            // SAFETY: a pipe handle this value owned; the file owns it now.
            tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_handle(h.into_raw() as _) })
        };
        Self {
            stdin: child.stdin.map(file),
            stdout: Some(file(child.stdout)),
            stderr: Some(file(child.stderr)),
            process: child.process,
            job,
            status: None,
        }
    }

    /// The process id, until the process has been waited for.
    pub fn id(&self) -> Option<u32> {
        self.status.is_none().then_some(self.process.pid)
    }

    /// Wait for the process to exit, polling: cancel-safe, as a `select!` and
    /// a timeout need it to be, and holding no thread while it waits.
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        use std::os::windows::process::ExitStatusExt;
        loop {
            if let Some(s) = self.status {
                return Ok(s);
            }
            match self.process.try_wait() {
                Ok(Some(code)) => self.status = Some(std::process::ExitStatus::from_raw(code)),
                Ok(None) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(e) => return Err(std::io::Error::other(format!("{e:#}"))),
            }
        }
    }

    /// End the harness and everything in its job. Asynchronous: [`Self::wait`]
    /// sees it gone.
    pub fn start_kill(&mut self) -> std::io::Result<()> {
        self.job
            .terminate(1)
            .map_err(|e| std::io::Error::other(format!("{e:#}")))
    }
}

// ─── FR-90 P2b-3a: a checkpoint, taken as the console user ──────────────────

/// The command line that runs `meshharbord hive-checkpoint <request>`.
pub fn checkpoint_command_line(exe: &Path, request: &Path) -> Result<String, String> {
    Ok(format!(
        "{} {} {}",
        program(exe)?,
        crate::hive::CHECKPOINT_SUBCOMMAND,
        quote_arg(utf8(request.as_os_str(), "the request's path")?)
    ))
}

/// Run `cmdline` (a [`checkpoint_command_line`]) as `who` and answer what it
/// wrote to stdout: at most `max` bytes, within `timeout`, else refused. In a
/// job of its own, so a checkpoint that hangs is ended whole, its `git` too.
///
/// # Safety
/// As [`run_prep`]: `SpawnAs::User`'s token must stay alive across the call.
pub unsafe fn run_checkpoint(
    who: SpawnAs,
    cmdline: &str,
    timeout: Duration,
    max: u64,
) -> Result<Vec<u8>, String> {
    // SAFETY: forwarded from the caller.
    unsafe { run_fed(who, cmdline, None, "the checkpoint", timeout, max) }
}

/// FR-90 P2f-2a — the command line that runs `meshharbord hive-pack`, which reads
/// its request on stdin (P2f-2b), fed as [`run_fed`] feeds a materialize.
pub fn pack_command_line(exe: &Path) -> Result<String, String> {
    Ok(format!(
        "{} {}",
        program(exe)?,
        crate::hive::PACK_SUBCOMMAND
    ))
}

/// FR-90 P2g-1 — the command line that runs `meshharbord hive-purge`, which
/// reads its request on stdin, fed as [`run_fed`] feeds a pack.
pub fn purge_command_line(exe: &Path) -> Result<String, String> {
    Ok(format!(
        "{} {}",
        program(exe)?,
        crate::hive::PURGE_SUBCOMMAND
    ))
}

// ─── FR-90 P2b-4a: a materialize, fed as the console user ───────────────────

/// The command line that runs `meshharbord hive-materialize`, which reads its
/// frames on stdin.
pub fn materialize_command_line(exe: &Path) -> Result<String, String> {
    Ok(format!(
        "{} {}",
        program(exe)?,
        crate::hive::MATERIALIZE_SUBCOMMAND
    ))
}

/// [`run_checkpoint`], with `feed` written to the child's stdin when given:
/// each buffer as it arrives, on a thread of its own, and the pipe closed —
/// the child's end of input — once every sender is dropped. A child that
/// stops reading ends the thread, and with it the receiver, so the sender
/// learns it at its next send. `what` names the child in a refusal.
///
/// # Safety
/// As [`run_prep`]: `SpawnAs::User`'s token must stay alive across the call.
pub unsafe fn run_fed(
    who: SpawnAs,
    cmdline: &str,
    feed: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    what: &str,
    timeout: Duration,
    max: u64,
) -> Result<Vec<u8>, String> {
    let job = JobObject::kill_on_close().map_err(|e| format!("{e:#}"))?;
    // SAFETY: forwarded from the caller.
    let child =
        unsafe { supervisor::spawn_into_job(who, cmdline, None, &[], feed.is_some(), &job) }
            .map_err(|e| format!("{e:#}"))?;
    let CapturedChild {
        process,
        stdout,
        stderr,
        stdin,
    } = child;
    if let (Some(pipe), Some(mut feed)) = (stdin, feed) {
        // Not joined: it ends when the senders are dropped, or at the first
        // write the child no longer reads.
        std::thread::spawn(move || {
            while let Some(buf) = feed.blocking_recv() {
                if supervisor::write_all_to_pipe(&pipe, &buf).is_err() {
                    break;
                }
            }
        });
    }
    // Each pipe drained on its own thread (one read to the end first
    // deadlocks on the other), each against its own budget.
    let out_budget = Arc::new(AtomicU64::new(max.saturating_add(1)));
    let err_budget = Arc::new(AtomicU64::new(PREP_OUTPUT));
    let out = std::thread::spawn(move || supervisor::read_pipe_to_end(&stdout, &out_budget));
    let err = std::thread::spawn(move || supervisor::read_pipe_to_end(&stderr, &err_budget));
    let finished = process.wait_for_exit(timeout);
    if !finished {
        let _ = job.terminate(1);
        let _ = process.wait_for_exit(Duration::from_secs(5));
    }
    let (bytes, over) = out.join().unwrap_or_default();
    let said = err
        .join()
        .map(|(b, _)| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default();
    if !finished {
        return Err(format!(
            "{what} did not finish within {} s",
            timeout.as_secs()
        ));
    }
    if over || bytes.len() as u64 > max {
        return Err(format!("{what} wrote more than {max} bytes"));
    }
    match process.try_wait() {
        Ok(Some(0)) => Ok(bytes),
        Ok(Some(code)) if said.is_empty() => Err(format!("{what} failed (exit {code})")),
        Ok(Some(_)) => Err(said),
        Ok(None) => Err(format!("{what} had not ended")),
        Err(e) => Err(format!("{e:#}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

    /// What a command line reads back as, by the rules a C-runtime program
    /// (Claude Code's `.exe`, `roomlerd`) parses it with.
    fn argv(line: &str) -> Vec<String> {
        let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
        let mut n = 0i32;
        // SAFETY: a NUL-terminated line; the array is freed below.
        let list = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut n) };
        assert!(!list.is_null(), "CommandLineToArgvW failed on {line:?}");
        let out = (0..n as usize)
            .map(|i| {
                // SAFETY: `n` NUL-terminated strings.
                let p = unsafe { *list.add(i) };
                let len = (0..).take_while(|&k| unsafe { *p.add(k) } != 0).count();
                String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
            })
            .collect();
        // SAFETY: the one block CommandLineToArgvW allocated.
        unsafe { LocalFree(list as _) };
        out
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_map_must_name_the_console_user_and_nobody_else() {
        // (mapped, the console's domain, its name, this computer) → names it?
        let table = [
            ("dev", "WS-1", "dev", "WS-1", true),
            ("DEV", "WS-1", "dev", "WS-1", true),
            (" dev ", "WS-1", "dev", "WS-1", true),
            (r"WS-1\dev", "WS-1", "dev", "WS-1", true),
            (r"ws-1\DEV", "WS-1", "dev", "WS-1", true),
            (r".\dev", "WS-1", "dev", "WS-1", true),
            (r"AzureAD\JaneDoe", "AzureAD", "JaneDoe", "WS-1", true),
            // Another account, or this one in another domain.
            ("ops", "WS-1", "dev", "WS-1", false),
            (r"CORP\dev", "WS-1", "dev", "WS-1", false),
            // `.` is THIS computer: a domain account is not local.
            (r".\dev", "CORP", "dev", "WS-1", false),
            // A computer whose name is unknown matches no `.`.
            (r".\dev", "WS-1", "dev", "", false),
            // Nothing matches nothing.
            ("", "WS-1", "dev", "WS-1", false),
            (r"WS-1\", "WS-1", "dev", "WS-1", false),
            (r"\dev", "WS-1", "dev", "WS-1", false),
            // A UPN is not one of the forms.
            ("dev@example.com", "WS-1", "dev", "WS-1", false),
        ];
        for (mapped, domain, name, computer, names) in table {
            assert_eq!(
                names_console_user(mapped, domain, name, computer),
                names,
                "{mapped:?} vs {domain}\\{name} on {computer:?}"
            );
        }
    }

    /// The refusal is `no_account`, and says who is at the console: what an
    /// owner whose map says `jane` needs to see when Windows calls her
    /// `AzureAD\JaneDoe`.
    #[test]
    fn a_map_naming_someone_else_is_refused_saying_who_is_at_the_console() {
        let (refusal, detail) =
            check_mapping_for("jane", "AzureAD", "JaneDoe", "WS-1").unwrap_err();
        assert_eq!(refusal, HiveRefusal::NoAccount);
        assert!(detail.contains("\"jane\""), "{detail}");
        assert!(detail.contains(r"AzureAD\JaneDoe"), "{detail}");
        assert!(check_mapping_for(r"AzureAD\JaneDoe", "AzureAD", "JaneDoe", "WS-1").is_ok());
    }

    #[test]
    fn the_harness_is_hive_harness_alone_else_the_native_install_then_npm() {
        let profile = Path::new(r"C:\Users\dev");
        let appdata = Path::new(r"C:\Users\dev\AppData\Roaming");
        assert_eq!(
            harness_candidates(None, profile, Some(appdata)),
            [
                PathBuf::from(r"C:\Users\dev\.local\bin\claude.exe"),
                PathBuf::from(r"C:\Users\dev\AppData\Roaming\npm\claude.cmd"),
            ]
        );
        assert_eq!(
            harness_candidates(None, profile, None),
            [PathBuf::from(r"C:\Users\dev\.local\bin\claude.exe")]
        );
        assert_eq!(
            harness_candidates(
                Some(Path::new(r"D:\tools\claude.exe")),
                profile,
                Some(appdata)
            ),
            [PathBuf::from(r"D:\tools\claude.exe")],
            "a configured harness is the only candidate"
        );
    }

    #[test]
    fn the_first_candidate_that_is_a_file_is_the_harness() {
        let home = tempfile::tempdir().unwrap();
        let appdata = home.path().join("AppData").join("Roaming");
        assert_eq!(resolve_harness(None, home.path(), Some(&appdata)), None);
        std::fs::create_dir_all(appdata.join("npm")).unwrap();
        std::fs::write(appdata.join("npm").join("claude.cmd"), "@echo off").unwrap();
        assert_eq!(
            resolve_harness(None, home.path(), Some(&appdata)),
            Some(appdata.join("npm").join("claude.cmd"))
        );
        let native = home.path().join(".local").join("bin");
        std::fs::create_dir_all(&native).unwrap();
        // A directory by that name is not the harness.
        std::fs::create_dir(native.join("claude.exe")).unwrap();
        assert_eq!(
            resolve_harness(None, home.path(), Some(&appdata)),
            Some(appdata.join("npm").join("claude.cmd"))
        );
        std::fs::remove_dir(native.join("claude.exe")).unwrap();
        std::fs::write(native.join("claude.exe"), b"MZ").unwrap();
        assert_eq!(
            resolve_harness(None, home.path(), Some(&appdata)),
            Some(native.join("claude.exe"))
        );
        assert_eq!(
            resolve_harness(
                Some(&home.path().join("missing.exe")),
                home.path(),
                Some(&appdata)
            ),
            None,
            "a configured harness that is not there is missing, with no fallback"
        );
    }

    /// Every argument reads back exactly as it was given, however it is made.
    #[test]
    fn an_exe_harness_gets_each_argument_back_exactly() {
        let args = [
            "-p",
            "",
            "two words",
            r"C:\ProgramData\Roomler\hive\run\abc\settings.json",
            r"C:\dir with space\",
            r#"say "hi""#,
            r#"a\"b"#,
            r"trailing\\",
            "tab\there",
            "mcp__roomler__approve",
        ];
        let line =
            harness_command_line(Path::new(r"C:\Users\dev\.local\bin\claude.exe"), &os(&args))
                .unwrap();
        let back = argv(&line);
        assert_eq!(back[0], r"C:\Users\dev\.local\bin\claude.exe");
        assert_eq!(&back[1..], &args);
    }

    #[test]
    fn a_cmd_harness_runs_through_cmd_and_refuses_what_cmd_would_read() {
        let shim = Path::new(r"C:\Users\dev\AppData\Roaming\npm\claude.cmd");
        let line = harness_command_line(shim, &os(&["-p", "--session-id", "x y"])).unwrap();
        assert!(
            line.ends_with(r#" /d /v:off /s /c ""C:\Users\dev\AppData\Roaming\npm\claude.cmd" -p --session-id "x y"""#),
            "{line}"
        );
        assert!(
            line.to_ascii_lowercase()
                .starts_with(&format!("\"{}", system_cmd().display()).to_ascii_lowercase()),
            "cmd.exe by its full path: {line}"
        );
        for bad in [
            "100%", "a&b", "a|b", "a>b", "a<b", "a)b", "a(b", "a^b", "a!b", r#"a"b"#, "a\nb",
        ] {
            assert!(
                harness_command_line(shim, &os(&[bad])).is_err(),
                "{bad:?} must be refused for a .cmd harness"
            );
        }
        assert!(
            harness_command_line(Path::new(r"C:\Users\100%\npm\claude.cmd"), &[]).is_err(),
            "a path cmd would expand is refused"
        );
        assert!(harness_command_line(Path::new(r"C:\tools\claude.ps1"), &[]).is_err());
        assert!(harness_command_line(Path::new(r"C:\tools\claude"), &[]).is_err());
    }

    #[test]
    fn prep_args_read_back_from_their_command_line() {
        let a = PrepArgs {
            config_dir: PathBuf::from(r"C:\Users\dev\.roomler\hive\s1\claude"),
            folder: PathBuf::from(r"C:\work\my app"),
            memory_dir: None,
            auto_memory_dir: PathBuf::from(
                r"C:\Users\dev\.roomler\hive\s1\claude\projects\hive-s1\memory",
            ),
        };
        let line = a
            .command_line(Path::new(r"C:\Program Files\Roomler\roomlerd.exe"))
            .unwrap();
        let back = argv(&line);
        assert_eq!(back[0], r"C:\Program Files\Roomler\roomlerd.exe");
        assert_eq!(back[1], PREP_SUBCOMMAND);
        assert_eq!(back[4], "", "no memory is an empty argument");
        let parsed = PrepArgs::parse(back.into_iter().skip(1).map(OsString::from))
            .unwrap()
            .unwrap();
        assert_eq!(parsed, a);

        let with_memory = PrepArgs {
            memory_dir: Some(PathBuf::from(r"C:\ProgramData\Roomler\hive\run\s1\memory")),
            ..a
        };
        let back = argv(
            &with_memory
                .command_line(Path::new(r"C:\r\roomlerd.exe"))
                .unwrap(),
        );
        let parsed = PrepArgs::parse(back.into_iter().skip(1).map(OsString::from))
            .unwrap()
            .unwrap();
        assert_eq!(parsed, with_memory);
    }

    #[test]
    fn only_hive_prep_with_four_arguments_is_a_preparation() {
        let p = |a: &[&str]| PrepArgs::parse(os(a).into_iter());
        assert!(p(&[]).is_none());
        assert!(p(&["run"]).is_none());
        assert!(p(&["hive-mcp", "x"]).is_none());
        assert!(p(&["hive-prep", "a", "b", "c"]).unwrap().is_err());
        assert!(p(&["hive-prep", "a", "b", "c", "d", "e"]).unwrap().is_err());
        assert!(p(&["hive-prep", "a", "b", "c", "d"]).unwrap().is_ok());
    }

    #[test]
    fn prep_makes_the_config_dir_and_copies_memory_only_where_nothing_is() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("state").join("claude");
        let auto = config.join("projects").join("hive-s1").join("memory");
        let folder = root.path().join("work");
        let memory = root.path().join("memory");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::create_dir_all(&memory).unwrap();
        std::fs::write(memory.join("CLAUDE.md"), "org rules").unwrap();
        std::fs::write(memory.join("MEMORY.md"), "org memory").unwrap();
        let args = PrepArgs {
            config_dir: config.clone(),
            folder: folder.clone(),
            memory_dir: Some(memory.clone()),
            auto_memory_dir: auto.clone(),
        };
        prep(&args).unwrap();
        assert_eq!(
            std::fs::read_to_string(config.join("CLAUDE.md")).unwrap(),
            "org rules"
        );
        assert_eq!(
            std::fs::read_to_string(auto.join("MEMORY.md")).unwrap(),
            "org memory"
        );

        // A resume keeps what the session has, its own edits included.
        std::fs::write(config.join("CLAUDE.md"), "edited").unwrap();
        std::fs::remove_file(auto.join("MEMORY.md")).unwrap();
        std::fs::create_dir(auto.join("MEMORY.md")).unwrap();
        std::fs::write(memory.join("CLAUDE.md"), "newer org rules").unwrap();
        prep(&args).unwrap();
        assert_eq!(
            std::fs::read_to_string(config.join("CLAUDE.md")).unwrap(),
            "edited"
        );
        assert!(
            auto.join("MEMORY.md").is_dir(),
            "something there is never replaced"
        );

        // Without memory, nothing is copied.
        let bare = PrepArgs {
            config_dir: root.path().join("other").join("claude"),
            memory_dir: None,
            ..args.clone()
        };
        prep(&bare).unwrap();
        assert!(bare.config_dir.is_dir());
        assert!(!bare.config_dir.join("CLAUDE.md").exists());
    }

    #[test]
    fn prep_refuses_a_folder_that_does_not_open_and_a_relative_path() {
        let root = tempfile::tempdir().unwrap();
        let args = PrepArgs {
            config_dir: root.path().join("claude"),
            folder: root.path().join("missing"),
            memory_dir: None,
            auto_memory_dir: root.path().join("claude").join("memory"),
        };
        let e = prep(&args).unwrap_err();
        assert!(e.contains("does not open"), "{e}");
        let relative = PrepArgs {
            folder: PathBuf::from("work"),
            ..args
        };
        assert!(prep(&relative).unwrap_err().contains("absolute"));
    }

    fn cmd(script: &str) -> String {
        format!("{} /d /c \"{script}\"", program(&system_cmd()).unwrap())
    }

    /// FR-90 P2b-3a — a checkpoint's stdout comes back whole within its
    /// budget; a failure says what its stderr said; more than the budget is
    /// refused, never cut and passed on.
    #[test]
    fn a_checkpoints_stdout_comes_back_within_its_budget() {
        // SAFETY: `Daemon` carries no token.
        unsafe {
            let out =
                run_checkpoint(SpawnAs::Daemon, &cmd("echo HIVECP1"), PREP_TIMEOUT, 1024).unwrap();
            assert_eq!(String::from_utf8_lossy(&out).trim(), "HIVECP1");
            let e = run_checkpoint(
                SpawnAs::Daemon,
                &cmd("echo no such folder 1>&2 & exit 2"),
                PREP_TIMEOUT,
                1024,
            )
            .unwrap_err();
            assert_eq!(e, "no such folder");
            let e = run_checkpoint(SpawnAs::Daemon, &cmd("echo 0123456789"), PREP_TIMEOUT, 4)
                .unwrap_err();
            assert!(e.contains("more than 4 bytes"), "{e}");
        }
    }

    /// FR-90 P2b-4a — what is fed reaches the child's stdin, whose end of
    /// input is the sender's drop; a child that does not read is answered in
    /// its own words, and the sender learns the pipe is gone.
    #[test]
    fn a_fed_child_reads_its_stdin_and_one_that_stops_closes_the_feed() {
        let delayed = |script: &str| {
            format!(
                "{} /v:on /d /c \"{script}\"",
                program(&system_cmd()).unwrap()
            )
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        tx.blocking_send(b"hello\r\n".to_vec()).unwrap();
        drop(tx);
        // SAFETY: `Daemon` carries no token.
        let out = unsafe {
            run_fed(
                SpawnAs::Daemon,
                &delayed("set /p X=& echo got !X!"),
                Some(rx),
                "the materialize",
                PREP_TIMEOUT,
                1024,
            )
        }
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&out).trim(), "got hello");

        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        tx.blocking_send(vec![b'x'; 1 << 20]).unwrap();
        // SAFETY: as above.
        let e = unsafe {
            run_fed(
                SpawnAs::Daemon,
                &cmd("echo the folder is not allowed 1>&2 & exit 1"),
                Some(rx),
                "the materialize",
                PREP_TIMEOUT,
                1024,
            )
        }
        .unwrap_err();
        assert_eq!(e, "the folder is not allowed");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match tx.try_send(vec![b'y']) {
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                _ => {
                    assert!(Instant::now() < deadline, "the feed never learned");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    #[test]
    fn run_prep_is_ok_on_exit_0_and_says_what_a_failure_said() {
        // SAFETY: `Daemon` carries no token.
        unsafe {
            assert_eq!(
                run_prep(SpawnAs::Daemon, &cmd("exit 0"), PREP_TIMEOUT),
                Ok(())
            );
            let e = run_prep(
                SpawnAs::Daemon,
                &cmd("echo meshharbord hive-prep: making X: denied 1>&2 & exit 1"),
                PREP_TIMEOUT,
            )
            .unwrap_err();
            assert_eq!(e, "meshharbord hive-prep: making X: denied");
            let e = run_prep(SpawnAs::Daemon, &cmd("exit 3"), PREP_TIMEOUT).unwrap_err();
            assert!(e.contains("exit 3"), "{e}");
        }
    }

    #[test]
    fn a_preparation_that_hangs_is_ended_at_its_deadline() {
        let started = Instant::now();
        // SAFETY: `Daemon` carries no token.
        let e = unsafe {
            run_prep(
                SpawnAs::Daemon,
                &cmd("ping -n 60 127.0.0.1 >NUL"),
                Duration::from_secs(1),
            )
        }
        .unwrap_err();
        assert!(e.contains("did not finish"), "{e}");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "ended, not waited out"
        );
    }

    /// The account read from a token is the one Windows says this process
    /// runs as.
    #[test]
    fn a_tokens_account_is_read_back() {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: our own process's token, closed below.
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
            0
        );
        let got = account_of_token(token);
        // SAFETY: the handle OpenProcessToken gave us, closed once.
        unsafe { CloseHandle(token) };
        let (domain, name) = got.unwrap();
        assert!(!domain.is_empty() && !name.is_empty());
        if let Ok(user) = std::env::var("USERNAME") {
            assert!(
                name.eq_ignore_ascii_case(&user),
                "{name} vs USERNAME={user}"
            );
        }
    }

    /// P1i-2 — a daemon that is not SYSTEM (this test process, elevated on CI's
    /// runner) runs a session as itself, never elevated: what it starts with
    /// the session's token carries the Medium label and not the High one. The
    /// labels are read by SID, which no display language changes.
    #[test]
    fn a_daemon_that_is_not_system_runs_a_session_as_itself_at_medium() {
        if crate::win_identity::process_is_local_system() {
            return;
        }
        let u = console_user().unwrap();
        assert_eq!(u.sid, own_sid().unwrap(), "this process's own person");
        if let Ok(user) = std::env::var("USERNAME") {
            assert!(u.name.eq_ignore_ascii_case(&user), "{} vs {user}", u.name);
        }
        let job = JobObject::kill_on_close().unwrap();
        let whoami = format!(
            "{} /groups /fo csv /nh",
            program(&system_cmd().with_file_name("whoami.exe")).unwrap()
        );
        // SAFETY: `u` holds the token across the call.
        let child =
            unsafe { supervisor::spawn_into_job(u.spawn_as(), &whoami, None, &[], false, &job) }
                .unwrap();
        let budget = std::sync::atomic::AtomicU64::new(256 * 1024);
        let (out, _) = supervisor::read_pipe_to_end(&child.stdout, &budget);
        assert!(child.process.wait_for_exit(Duration::from_secs(10)));
        let groups = String::from_utf8_lossy(&out);
        assert!(groups.contains("S-1-16-8192"), "the Medium label: {groups}");
        assert!(!groups.contains("S-1-16-12288"), "never High: {groups}");
    }

    #[test]
    fn a_variable_is_found_whatever_its_case() {
        let entries: Vec<Vec<u16>> = [
            r"=C:=C:\x",
            r"AppData=C:\Users\dev\AppData\Roaming",
            "APPDATAX=no",
        ]
        .iter()
        .map(|e| e.encode_utf16().collect())
        .collect();
        assert_eq!(
            env_value(&entries, "APPDATA"),
            Some(OsString::from(r"C:\Users\dev\AppData\Roaming"))
        );
        assert_eq!(env_value(&entries, "TEMP"), None);
    }

    /// `cmd.exe` with delayed expansion, so `!L!` reads what `set /p` read.
    fn cmd_v(script: &str) -> String {
        format!(
            "{} /d /v:on /c \"{script}\"",
            program(&system_cmd()).unwrap()
        )
    }

    /// P1i-2 — what the session task does with a harness: a line to its stdin,
    /// a line back from its stdout, and its end, all through tokio's files
    /// over the anonymous pipes.
    #[tokio::test]
    async fn a_harness_child_speaks_over_its_pipes_and_is_waited_for() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let job = JobObject::kill_on_close().unwrap();
        // SAFETY: `Daemon` carries no token.
        let child = unsafe {
            supervisor::spawn_into_job(
                SpawnAs::Daemon,
                &cmd_v("set /p L=& echo got !L!& exit 7"),
                None,
                &[],
                true,
                &job,
            )
        }
        .unwrap();
        let mut h = HarnessChild::new(child, job);
        assert!(h.id().is_some(), "running");
        let mut stdin = h.stdin.take().unwrap();
        stdin.write_all(b"hello\r\n").await.unwrap();
        stdin.flush().await.unwrap();
        let mut lines = BufReader::new(h.stdout.take().unwrap()).lines();
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(line.trim(), "got hello");
        let status = tokio::time::timeout(Duration::from_secs(10), h.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!(h.id(), None, "no id once it has been waited for");
    }

    /// P1i-2 — a stop that the harness does not heed ends its job, and the
    /// wait sees it.
    #[tokio::test]
    async fn killing_a_harness_child_ends_it_and_its_wait_returns() {
        let job = JobObject::kill_on_close().unwrap();
        // SAFETY: `Daemon` carries no token.
        let child = unsafe {
            supervisor::spawn_into_job(
                SpawnAs::Daemon,
                &cmd("ping -n 60 127.0.0.1 >NUL"),
                None,
                &[],
                true,
                &job,
            )
        }
        .unwrap();
        let mut h = HarnessChild::new(child, job);
        h.start_kill().unwrap();
        let status = tokio::time::timeout(Duration::from_secs(10), h.wait())
            .await
            .expect("ended, not waited out")
            .unwrap();
        assert_eq!(status.code(), Some(1), "the job's exit code");
    }

    /// The DACL a directory carries, as SDDL.
    fn dacl_of(dir: &Path) -> String {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        let what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let wide: Vec<u16> = dir
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated path; `sd` receives a LocalAlloc'd
        // descriptor, freed below; the other out-params are optional.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                what,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(rc, 0, "GetNamedSecurityInfoW");
        let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
        // SAFETY: the descriptor read above; `text` is LocalAlloc'd, freed below.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                1,
                what,
                &mut text,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            ok, 0,
            "ConvertSecurityDescriptorToStringSecurityDescriptorW"
        );
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        // SAFETY: `len` units were just read from `text`.
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        // SAFETY: the two allocations above, each freed once.
        unsafe {
            LocalFree(text as _);
            LocalFree(sd as _);
        }
        s
    }

    /// How the system writes `sid` back in SDDL: by its alias where it has one.
    /// CI's runner signs in as the built-in Administrator, which comes back as
    /// `LA`, never as its `S-1-5-21-…-500`. Asked of the system, so no rule
    /// for which accounts have an alias is guessed here.
    fn as_written(sid: &str) -> String {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        let sd = Sddl::new(&format!("O:{sid}")).unwrap();
        let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
        // SAFETY: a descriptor `sd` owns; `text` is LocalAlloc'd, freed below.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd.psd,
                1,
                OWNER_SECURITY_INFORMATION,
                &mut text,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            ok, 0,
            "ConvertSecurityDescriptorToStringSecurityDescriptorW"
        );
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        // SAFETY: `len` units were just read from `text`.
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        // SAFETY: the one allocation above, freed once.
        unsafe { LocalFree(text as _) };
        s.trim_start_matches("O:").to_string()
    }

    /// P1i-2 — a session's directory is made with exactly its DACL, protected
    /// from what its parent would hand down, and given it again when it is
    /// there already; and a junction where it goes is refused, not followed.
    #[test]
    fn a_session_directory_carries_its_dacl_and_a_junction_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let me = own_sid().unwrap();
        let shown = as_written(&me);
        let dir = root.path().join("s1");
        dir_with_dacl(&dir, &session_dir_sddl(&me)).unwrap();
        let sddl = dacl_of(&dir);
        assert!(
            sddl.starts_with("O:BAD:P"),
            "owned by Administrators, protected: {sddl}"
        );
        assert!(
            sddl.contains(&format!(";;;{shown})")),
            "the session's account: {sddl}"
        );
        assert!(sddl.contains(";;;SY)") && sddl.contains(";;;BA)"), "{sddl}");
        assert!(
            !sddl.contains(";;;BU)") && !sddl.contains(";;;AU)"),
            "no Users: {sddl}"
        );

        // Again over the one already there, with another DACL.
        dir_with_dacl(&dir, PRIVATE_DIR_SDDL).unwrap();
        assert!(
            !dacl_of(&dir).contains(&format!(";;;{shown})")),
            "the account's grant is gone"
        );

        // A folder someone else made first, and owns: taken over, owner and
        // all, since an owner keeps WRITE_DAC whatever the DACL says.
        let squatted = root.path().join("s0");
        dir_with_dacl(&squatted, &format!("O:{me}D:P(A;OICI;FA;;;{me})")).unwrap();
        assert!(
            dacl_of(&squatted).starts_with(&format!("O:{shown}D:")),
            "the squatter owns it"
        );
        dir_with_dacl(&squatted, PRIVATE_DIR_SDDL).unwrap();
        let taken = dacl_of(&squatted);
        assert!(
            taken.starts_with("O:BAD:P"),
            "Administrators own it now: {taken}"
        );
        assert!(
            !taken.contains(&format!(";;;{shown})")),
            "and the squatter has nothing: {taken}"
        );

        let target = root.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let link = root.path().join("s2");
        let made = std::process::Command::new(system_cmd())
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink /J: {made:?}");
        assert!(
            dir_with_dacl(&link, PRIVATE_DIR_SDDL).is_err(),
            "a junction is refused"
        );
        assert!(
            !dacl_of(&target).contains("D:P"),
            "and what it points at is untouched"
        );
    }

    /// P1i-2 — the SID read from a token is this process's account's, and a
    /// toolbelt's pipe grants the session's account no right to make an
    /// instance, and nobody but SYSTEM and Administrators anything more.
    #[test]
    fn the_sid_is_ours_and_the_pipe_grants_no_instance_creation() {
        let me = own_sid().unwrap();
        assert!(me.starts_with("S-1-5-"), "{me}");
        let sddl = toolbelt_pipe_sddl(&me);
        let aces: Vec<&str> = sddl
            .trim_start_matches("D:P(")
            .split(")S:")
            .next()
            .unwrap()
            .split(")(")
            .collect();
        let grant = aces
            .iter()
            .find(|ace| ace.ends_with(&format!(";;;{me}")))
            .unwrap();
        let mask = grant.split(';').nth(2).unwrap();
        let mask = u32::from_str_radix(mask.trim_start_matches("0x"), 16).unwrap();
        // FILE_CREATE_PIPE_INSTANCE (= FILE_APPEND_DATA) is 0x4.
        assert_eq!(mask & 0x4, 0, "{sddl}");
        for ace in &aces {
            assert!(
                ace.ends_with(";;;SY") || ace.ends_with(";;;BA") || *ace == *grant,
                "only SYSTEM, Administrators and the session's account: {ace}"
            );
        }
        assert!(Sddl::new(&sddl).is_ok(), "the SDDL parses");
    }

    /// FR-97 P4c — the adopt pipe gives every interactive user read and write
    /// and never `FILE_CREATE_PIPE_INSTANCE`; everything more goes to SYSTEM,
    /// Administrators and the daemon's own account alone.
    #[test]
    fn the_adopt_pipe_lets_people_in_and_only_the_daemon_add_an_instance() {
        let me = own_sid().unwrap();
        let sddl = adopt_pipe_sddl(&me);
        let aces: Vec<&str> = sddl
            .trim_start_matches("D:P(")
            .split(")S:")
            .next()
            .unwrap()
            .split(")(")
            .collect();
        let people = aces.iter().find(|ace| ace.ends_with(";;;IU")).unwrap();
        let mask = people.split(';').nth(2).unwrap();
        let mask = u32::from_str_radix(mask.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(mask, 0x12008b, "read and write data, nothing more: {sddl}");
        assert_eq!(mask & 0x4, 0, "no FILE_CREATE_PIPE_INSTANCE: {sddl}");
        for ace in &aces {
            let full = ace.starts_with("A;;GA;;;")
                && (ace.ends_with(";;;SY")
                    || ace.ends_with(";;;BA")
                    || ace.ends_with(&format!(";;;{me}")));
            assert!(full || *ace == *people, "an unexpected grant: {ace}");
        }
        assert!(
            sddl.ends_with("S:(ML;;NW;;;ME)"),
            "below Medium cannot write: {sddl}"
        );
        assert!(Sddl::new(&sddl).is_ok(), "the SDDL parses");
    }

    /// FR-97 P4c — the accounts the adopt pipe refuses as root: the three that
    /// run services, and the anonymous logon of a client that forbade
    /// identification. A person's SID is not one of them.
    #[test]
    fn service_accounts_and_nobody_are_never_adopted() {
        for sid in ["S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-7"] {
            assert!(is_service_sid(sid), "{sid}");
        }
        assert!(!is_service_sid(&own_sid().unwrap()));
        assert!(!is_service_sid("S-1-5-21-1-2-3-1001"));
    }

    /// FR-97 P4c — a pipe's client is named by its token once it has written:
    /// here, this very process through the hook's own client, so its own SID
    /// and account, and its pid for the terminal lookup.
    #[tokio::test]
    async fn the_adopt_pipe_names_its_client_by_its_token() {
        use std::os::windows::io::{AsRawHandle, IntoRawHandle};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let name = format!(r"\\.\pipe\roomler-adopt-peer-test-{}", std::process::id());
        let mut sddl = Sddl::new(&adopt_pipe_sddl(&own_sid().unwrap())).unwrap();
        // SAFETY: the attributes outlive the call; the descriptor is copied.
        let mut server = unsafe {
            tokio::net::windows::named_pipe::ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(&name, sddl.attributes().cast())
        }
        .unwrap();
        let opened = tokio::task::spawn_blocking({
            let name = name.clone();
            move || tunnel_core::localapi::hive_adopt::open_pipe_at(&name)
        });
        server.connect().await.unwrap();
        let raw = opened
            .await
            .unwrap()
            .expect("the hook's open, with the exact mask")
            .into_raw_handle();
        // SAFETY: an overlapped pipe handle, owned from here by tokio.
        let mut client =
            unsafe { tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(raw) }
                .unwrap();
        client.write_all(b"{}\n").await.unwrap();
        let mut line = [0u8; 3];
        server.read_exact(&mut line).await.unwrap();
        let peer = pipe_peer(server.as_raw_handle() as _).unwrap();
        assert_eq!(peer.sid, own_sid().unwrap());
        assert!(!peer.is_service());
        assert!(peer.qualified().contains('\\'), "{}", peer.qualified());
        assert_eq!(
            pipe_client_pid(server.as_raw_handle() as _),
            Some(std::process::id())
        );
    }

    /// P3-5b-4 — a loopback connection this test makes is found in the
    /// connection table as this process's, and this process's account is
    /// read from its token; a connection that is not there is no one's.
    #[test]
    fn a_loopback_connection_names_the_process_that_made_it() {
        use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(server) = listener.local_addr().unwrap() else {
            panic!("IPv4");
        };
        let _client = TcpStream::connect(server).unwrap();
        let (_accepted, SocketAddr::V4(client)) = listener.accept().unwrap() else {
            panic!("IPv4");
        };
        assert_eq!(tcp_client_pid(client, server), Some(std::process::id()));
        assert_eq!(process_sid(std::process::id()), own_sid());
        let nobody = SocketAddrV4::new(*server.ip(), 1);
        assert_eq!(tcp_client_pid(nobody, server), None);
    }
}
