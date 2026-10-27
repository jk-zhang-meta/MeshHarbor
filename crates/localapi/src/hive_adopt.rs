// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1j — the adopt socket's protocol: what `meshharbor hive hook`, run by
//! Claude Code as the person at a terminal, tells the daemon about that
//! terminal's session (`docs/fr/FR-90-hive-agent-sessions.md` §3h).
//!
//! ⚠️ This is NOT the LocalAPI socket, which on a root daemon is root-only and
//! whose verbs mostly trust the socket alone. The adopt socket is open to
//! every local account, because every account may adopt its own sessions,
//! and the daemon trusts nothing a hook says about who it is. It reads the
//! peer's uid from the kernel, maps that account through the device's own
//! `hive_accounts`, and refuses root. A hook can only ever speak for its own
//! account's terminals.
//!
//! ⚠️ The hook reads the transcript and SENDS it. The daemon never opens a path
//! a hook names: a root daemon reading `transcript_path` would read any file
//! the requester could point it at.
//!
//! FR-97 P4c — on Windows the socket is a named pipe, [`PIPE_NAME`], and both
//! ends check the other through the kernel:
//! - the daemon names the hook by the client's token (its SID), never by what
//!   the hook says, and refuses the service accounts as it refuses root;
//! - the hook sends nothing unless the pipe is owned by SYSTEM, Administrators
//!   or its own account. A pipe name is global, unlike a socket in the
//!   daemon's runtime directory, so a process that took the name first would
//!   otherwise receive the person's transcript.
//!
//! Wire: newline-delimited JSON. Each request is answered by one [`Reply`]
//! before the next is read.
//!
//! ```text
//! hook                                   daemon
//!  ── Hello {harness_session, cwd, event} ─▶   (adopted already? offer it to the server)
//!  ◀─ Reply {ok, offset} ──────────────────
//!  ── Lines {from: offset, data} ─────────▶   whole lines only; repeated to EOF
//!  ◀─ Reply {ok, offset} ──────────────────
//!  ── TurnEnded | End {reason} ───────────▶   the Stop / SessionEnd hook
//!  ◀─ Reply {ok} ──────────────────────────
//! ```

use serde::{Deserialize, Serialize};

/// The socket's file name in the daemon's Hive runtime directory.
pub const SOCKET_NAME: &str = "adopt.sock";

/// FR-97 P4c — the adopt socket on Windows: one named pipe per machine.
pub const PIPE_NAME: &str = r"\\.\pipe\roomler-hive-adopt";

/// The most transcript bytes one [`Request::Lines`] carries. Whole lines only,
/// so a hook stops before the line that would cross this and sends it next.
pub const MAX_CHUNK: usize = 1024 * 1024;

/// The longest single transcript line the daemon takes. A longer one (a huge
/// tool output) is skipped by the hook and noted, never truncated mid-JSON.
pub const MAX_LINE: usize = 4 * 1024 * 1024;

/// The most bytes one hook run sends before it stops: the rest goes with the
/// next turn's hook. Bounds how long a hook can hold the daemon's attention.
pub const MAX_PER_RUN: usize = 64 * 1024 * 1024;

/// Which Claude Code hook ran.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookEvent {
    SessionStart,
    Stop,
    SessionEnd,
    /// An event this build does not know. The daemon treats it as a mirror
    /// request and nothing more.
    #[serde(other)]
    Other,
}

/// One request from a hook.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// The first word of every hook run: which terminal session, where, and
    /// which hook. The account is the kernel's answer, never the hook's.
    Hello {
        /// Claude Code's own session id (a UUID).
        harness_session: String,
        /// The terminal's working directory, as Claude Code reports it.
        cwd: String,
        event: HookEvent,
    },
    /// The transcript's next whole lines, starting at byte `from`. A `from`
    /// that is not where the daemon's copy ends is answered with where it does
    /// end, and the hook sends from there.
    ///
    /// `skipped`: bytes AFTER `data` the hook did not send: one line longer
    /// than [`MAX_LINE`] (a huge tool output), whose place the daemon's copy
    /// moves past and marks. Never part of a line: whole lines only.
    Lines {
        from: u64,
        data: String,
        #[serde(default, skip_serializing_if = "is_zero")]
        skipped: u64,
    },
    /// The turn the person just finished (the `Stop` hook).
    TurnEnded,
    /// The terminal session ended (`SessionEnd`), with Claude Code's reason.
    End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Where a daemon on this system listens: its Hive runtime directory, which
/// it owns and clears at boot. `None` on Windows, where it listens on
/// [`PIPE_NAME`] instead.
pub fn socket_path() -> Option<std::path::PathBuf> {
    let dir = if cfg!(target_os = "linux") {
        RUNTIME_DIR_LINUX
    } else if cfg!(target_os = "macos") {
        RUNTIME_DIR_MACOS
    } else {
        return None;
    };
    Some(std::path::Path::new(dir).join(SOCKET_NAME))
}

/// FR-97 P4c — the hook's end of [`PIPE_NAME`], kept only when the pipe is
/// the daemon's: owned by SYSTEM, Administrators or this process's account.
///
/// - The pipe is opened for reading and writing data and nothing more. The
///   daemon grants a person no more than that, and `FILE_CREATE_PIPE_INSTANCE`
///   least of all, since with it a process could add an instance of its own
///   under the name and take the next hook's connection. `GENERIC_WRITE`
///   carries that right, so it is not asked for.
/// - It is opened at identification level, so the daemon may read who is
///   calling but not act as them.
/// - A busy pipe (every instance taken) is waited for, briefly.
///
/// `NotFound`: no daemon adopts here now. `PermissionDenied`: something else
/// holds the name, and the transcript is not sent to it.
#[cfg(windows)]
pub fn connect_pipe() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use std::os::windows::io::IntoRawHandle;
    let h = open_pipe()?.into_raw_handle();
    // SAFETY: a pipe handle opened overlapped, owned from here by tokio.
    match unsafe { tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(h) } {
        Ok(c) => Ok(c),
        Err(e) => {
            // SAFETY: tokio did not take it; closed once.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(h as _) };
            Err(e)
        }
    }
}

/// [`connect_pipe`]'s open and check, without the async runtime: the handle,
/// once the pipe is known to be the daemon's. Whether a device adopts is this
/// succeeding.
#[cfg(windows)]
pub fn open_pipe() -> std::io::Result<std::os::windows::io::OwnedHandle> {
    open_pipe_at(PIPE_NAME)
}

/// [`open_pipe`] for the pipe called `name`: what tests open, on a name of
/// their own.
#[cfg(windows)]
pub fn open_pipe_at(name: &str) -> std::io::Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_BUSY, GENERIC_READ, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut tries = 0;
    let h = loop {
        // SAFETY: a NUL-terminated name; the handle is handed to tokio below,
        // or closed.
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
        if h != INVALID_HANDLE_VALUE {
            break h;
        }
        let e = std::io::Error::last_os_error();
        tries += 1;
        if e.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) || tries > 3 {
            return Err(e);
        }
        // SAFETY: a NUL-terminated name; waits at most 2 s for an instance.
        unsafe { WaitNamedPipeW(wide.as_ptr(), 2000) };
    };
    if let Err(e) = server_is_trusted(h) {
        // SAFETY: the handle opened above, not handed on; closed once.
        unsafe { CloseHandle(h) };
        return Err(e);
    }
    // SAFETY: a live handle this function opened and owns alone.
    Ok(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(h as _) })
}

/// Whether `pipe` is the daemon's: owned by SYSTEM, by the Administrators
/// group, or by this process's own account, the owners the daemon's
/// instances have (SYSTEM's, an elevated person's, or an unelevated person's
/// own). Anyone else who took the name owns what they made, and cannot make
/// SYSTEM or Administrators its owner without being an administrator. A pipe
/// whose owner cannot be read is refused.
///
/// The OWNER, read through the pipe's own handle (its `READ_CONTROL`), and
/// not the server process's token: a person may not open a SYSTEM process's
/// token, so that check refused the real daemon (measured, FR-97 P4c's first
/// field run).
#[cfg(windows)]
fn server_is_trusted(pipe: windows_sys::Win32::Foundation::HANDLE) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        TOKEN_QUERY, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let refused = |why: &str| {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("the adopt pipe is not this device's daemon's: {why}"),
        ))
    };
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a live pipe handle opened with READ_CONTROL; the owner points
    // into `sd`, which the call allocates and is freed below.
    let rc = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    let verdict = if rc != 0 || owner.is_null() {
        refused("its owner cannot be read")
    // SAFETY: `owner` points into `sd`, alive until the free below.
    } else if unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid) != 0
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
    } {
        Ok(())
    } else {
        let mut mine = std::ptr::null_mut();
        // SAFETY: this process's own token; closed below, once.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut mine) } != 0;
        let mut buf = [0u64; 32];
        let me = opened.then(|| token_user(mine, &mut buf)).flatten();
        if opened {
            // SAFETY: the token opened above, closed once.
            unsafe { CloseHandle(mine) };
        }
        match me {
            // SAFETY: both SIDs valid here: `me` in `buf`, `owner` in `sd`.
            Some(me) if unsafe { EqualSid(owner, me) } != 0 => Ok(()),
            Some(_) => refused("another account owns it"),
            None => refused("this process's own account cannot be read"),
        }
    };
    if !sd.is_null() {
        // SAFETY: the one descriptor GetSecurityInfo allocated, freed once.
        unsafe { LocalFree(sd as _) };
    }
    verdict
}

/// The user SID of `token`, read into `buf` (a `TOKEN_USER` and the SID it
/// points into: a SID is at most 68 bytes, so 256 are ample, and `u64` keeps
/// the structure aligned). The pointer is valid while `buf` is.
#[cfg(windows)]
fn token_user(
    token: windows_sys::Win32::Foundation::HANDLE,
    buf: &mut [u64; 32],
) -> Option<windows_sys::Win32::Security::PSID> {
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER, TokenUser};
    let mut len = 0u32;
    // SAFETY: a live token with TOKEN_QUERY; `buf` is writable for the length
    // passed and aligned for TOKEN_USER.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            std::mem::size_of_val(buf) as u32,
            &mut len,
        )
    } != 0;
    // SAFETY: on success `buf` begins with a TOKEN_USER whose SID points into
    // `buf`.
    ok.then(|| unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

/// The daemon's Hive runtime directory on Linux (`/run` is cleared at boot).
pub const RUNTIME_DIR_LINUX: &str = "/run/meshharbor-hive";
/// … and on macOS, which clears `/var/run` at boot.
pub const RUNTIME_DIR_MACOS: &str = "/var/run/meshharbor-hive";

/// The daemon's answer to one [`Request`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct Reply {
    pub ok: bool,
    /// Where the daemon's copy of the transcript ends: the hook sends from
    /// here next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Why not, for `ok: false`: a word the hook may log, never shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
}

impl Reply {
    pub fn ok(offset: Option<u64>) -> Self {
        Self {
            ok: true,
            offset,
            refused: None,
        }
    }

    pub fn refused(word: impl Into<String>, offset: Option<u64>) -> Self {
        Self {
            ok: false,
            offset,
            refused: Some(word.into()),
        }
    }
}

/// Every word [`Reply::refused`] carries. Locked by test: the hook's log and
/// `meshharbor hive adopt`'s status read them.
pub mod refusal {
    /// The device's owner has not allowed adopting (`hive_adopt` off).
    pub const ADOPT_DISABLED: &str = "adopt_disabled";
    /// The account this terminal runs as maps to nobody in `hive_accounts`.
    pub const NO_ACCOUNT: &str = "no_account";
    /// Root's own sessions are never adopted, nor on Windows those of a
    /// service account (SYSTEM, LOCAL SERVICE, NETWORK SERVICE).
    pub const ROOT: &str = "root";
    /// The server is not reachable now; the next hook offers it again.
    pub const OFFLINE: &str = "offline";
    /// The server refused it; its word follows after a colon.
    pub const SERVER: &str = "server";
    /// Mirroring was stopped for this terminal session (from Roomler, or
    /// because it ended); nothing more is taken for it.
    pub const STOPPED: &str = "stopped";
    /// Another account's terminal session.
    pub const NOT_YOURS: &str = "not_yours";
    /// The request was malformed or out of order.
    pub const BAD_REQUEST: &str = "bad_request";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_is_locked() {
        let hello = Request::Hello {
            harness_session: "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70".into(),
            cwd: "/home/alice/x".into(),
            event: HookEvent::SessionStart,
        };
        assert_eq!(
            serde_json::to_value(&hello).unwrap(),
            serde_json::json!({
                "op": "hello",
                "harness_session": "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70",
                "cwd": "/home/alice/x",
                "event": "session_start",
            })
        );
        assert_eq!(
            serde_json::to_value(Request::Lines {
                from: 7,
                data: "{}\n".into(),
                skipped: 0,
            })
            .unwrap(),
            serde_json::json!({"op": "lines", "from": 7, "data": "{}\n"})
        );
        assert_eq!(
            serde_json::to_value(Request::Lines {
                from: 7,
                data: String::new(),
                skipped: 9,
            })
            .unwrap(),
            serde_json::json!({"op": "lines", "from": 7, "data": "", "skipped": 9})
        );
        assert_eq!(
            serde_json::to_value(Request::TurnEnded).unwrap(),
            serde_json::json!({"op": "turn_ended"})
        );
        assert_eq!(
            serde_json::to_value(Request::End { reason: None }).unwrap(),
            serde_json::json!({"op": "end"})
        );
        assert_eq!(
            serde_json::to_value(Reply::ok(Some(3))).unwrap(),
            serde_json::json!({"ok": true, "offset": 3})
        );
        assert_eq!(
            serde_json::to_value(Reply::refused(refusal::STOPPED, None)).unwrap(),
            serde_json::json!({"ok": false, "refused": "stopped"})
        );
    }

    #[test]
    fn an_unknown_hook_event_still_decodes() {
        let r: Request = serde_json::from_value(serde_json::json!({
            "op": "hello", "harness_session": "u", "cwd": "/", "event": "pre_compact"
        }))
        .unwrap();
        assert!(matches!(
            r,
            Request::Hello {
                event: HookEvent::Other,
                ..
            }
        ));
    }

    /// A pipe name of a test's own, never the daemon's.
    #[cfg(windows)]
    fn test_pipe(tag: &str) -> String {
        format!(r"\\.\pipe\roomler-adopt-test-{tag}-{}", std::process::id())
    }

    /// FR-97 P4c — the hook keeps a pipe its own account serves (an attended
    /// daemon is the person), opened with read and write alone.
    #[cfg(windows)]
    #[tokio::test]
    async fn the_hook_opens_a_pipe_its_own_account_serves() {
        let name = test_pipe("own");
        let server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let opened = tokio::task::spawn_blocking({
            let name = name.clone();
            move || open_pipe_at(&name)
        });
        server.connect().await.unwrap();
        assert!(
            opened.await.unwrap().is_ok(),
            "this account's own server is trusted"
        );
    }

    /// … and with nothing listening says so, for `meshharbor hive adopt` to tell
    /// the person.
    #[cfg(windows)]
    #[test]
    fn with_no_pipe_the_hook_finds_nothing() {
        let e = open_pipe_at(&test_pipe("none")).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    }
}
