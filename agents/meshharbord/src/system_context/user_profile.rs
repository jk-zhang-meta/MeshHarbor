// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR(4): names the PRE-RENAME appdirs segment a host installed before
// P4b still has; appdirs::app_segment resolves it, so it is an input.
//! Resolve the active-session user's profile directory from a
//! SystemContext worker.
//!
//! ## Why
//!
//! The SystemContext worker runs as `LocalSystem` (S-1-5-18) but
//! lives in the user's interactive session (typically session 1).
//! That means the worker's own `%APPDATA%` resolves to
//! `C:\Windows\System32\config\systemprofile\AppData\Roaming\` —
//! NOT the user's profile. The agent's config file (with the
//! enrollment token, agent_id, server URL, etc.) was written into
//! the user's profile by the user-context enrollment flow, so the
//! SystemContext worker can't see it via the default
//! `ProjectDirs::config_dir()` lookup.
//!
//! Field repro the field-test host 2026-05-06: every SystemContext spawn exited
//! with `code=1` within ~500 ms, no log files written. Root cause:
//! `config::load(default_path)` returned `not found` for the SYSTEM-
//! profile path; `anyhow` propagated to main; process exited with
//! code 1 BEFORE `logging::init()` had a chance to fire.
//!
//! ## How
//!
//! 1. `ProcessIdToSessionId(GetCurrentProcessId())` — discover the
//!    worker's own session id. This works regardless of whether the
//!    user is on the lock screen or actively interacting.
//! 2. `WTSQuerySessionInformationW(NULL, sid, WTSUserName)` — look
//!    up the username for that session. Returns "Administrator"
//!    or whatever; empty string if no user is logged in.
//! 3. Build `C:\Users\<username>\AppData\Roaming\roomler\
//!    roomler\config\config.toml` (a host installed before the
//!    rename keeps `roomler-agent` there, so both are tried — see
//!    `config_candidates_under`). Uses the standard Win11
//!    profile location; fails gracefully (returns `None`) if the
//!    profile isn't there.
//!
//!
// RETIRED-NAME-ANCHOR-BEGIN
// From here down, `roomler-agent` names the PRE-RENAME appdirs segment that
// a host installed before P4b still has. The resolver returns both segments
// and the tests pin the order; dropping the retired one is what removed the
// user-config rung from every post-rename install in the first place.
//! ## Limitations
//!
//! * Assumes the user's profile directory is at `C:\Users\<name>`.
//!   On hosts with redirected profiles (drive D:, mapped network
//!   home folders) this is wrong. We could read
//!   `HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList`
//!   for the SID-keyed profile path, but that's significantly more
//!   FFI for a corner case. The operator can override with
//!   `--config <explicit>` on the SCM service's ImagePath as the
//!   workaround.
//! * Returns `None` (caller falls back to default path) if any FFI
//!   call fails. The worker will then exit with code 1, but at
//!   least the supervisor's log line is honest about it.

#![cfg(all(feature = "system-context", target_os = "windows"))]

use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTSFreeMemory, WTSQuerySessionInformationW,
    WTSUserName,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

/// Resolve the active-session user's profile root (`C:\Users\<name>`).
/// Returns `None` if any of the discovery steps fail (no logged-in
/// user, FFI failure).
///
/// Used by the various `active_user_*_path()` helpers below; pulled
/// out so each new feature with a profile-relative path doesn't
/// re-implement the FFI dance. The lesson from rc.6 (config) and rc.7
/// (file-DC Downloads): every SystemContext feature that touches a
/// `%USERPROFILE%`-derived path needs an active-user fallback.
pub fn active_user_profile_root() -> Option<PathBuf> {
    let session_id = current_session_id()?;
    let username = user_name_for_session(session_id)?;
    Some(PathBuf::from(format!("C:\\Users\\{username}")))
}

/// Per-user config candidates under `root`, most-current first.
///
/// The segment under `%APPDATA%\roomler\` is the appdirs *application*
/// name, which P4b renamed `roomler-agent` -> `roomler`. A host installed
/// before that rename still has the old tree, so both are candidates.
///
/// This cannot just call `appdirs`: a SystemContext worker runs as
/// LocalSystem, so `ProjectDirs` would resolve the LocalSystem profile —
/// the whole reason this module exists is to reach the INTERACTIVE user's
/// profile instead. The segment list is therefore duplicated here on
/// purpose, and `appdirs`'s own constants are the thing to keep it in step
/// with.
fn config_candidates_under(root: &Path) -> [PathBuf; 2] {
    let base = root.join("AppData").join("Roaming").join("roomler");
    [
        base.join("roomler").join("config").join("config.toml"),
        base.join("roomler-agent")
            .join("config")
            .join("config.toml"),
    ]
}

/// Resolve the active-session user's config file path.
/// Returns `None` if any of the discovery steps fail (no logged-in
/// user, FFI failure, profile not at standard location).
///
/// Caller (typically main.rs's config_path resolution) uses this as
/// a fallback when the default `ProjectDirs::config_dir()` lookup
/// returns a path that doesn't exist. That caller then filters on
/// `exists()`, so returning only ONE segment silently drops the rung
/// whenever the host is on the other one — which is what happened to
/// every post-rename install until FR-21: the hardcoded segment was the
/// pre-rename one, so a freshly installed host had no user-config rung
/// at all, with nothing logged.
///
/// Returns the first candidate that exists; if neither does, the current
/// one, so the logged path names where the config SHOULD go.
pub fn active_user_config_path() -> Option<PathBuf> {
    let root = active_user_profile_root()?;
    let candidates = config_candidates_under(&root);
    Some(
        candidates
            .iter()
            .find(|p| p.exists())
            .cloned()
            .unwrap_or_else(|| candidates[0].clone()),
    )
}

/// Resolve the active-session user's Downloads folder path.
///
/// Used by the file-DC handler (`files::download_dir`) under
/// SystemContext to land uploads in the user's actual Downloads
/// folder, not the LocalSystem profile's
/// `C:\Windows\System32\config\systemprofile\Downloads\` (which
/// usually doesn't exist; field repro the field-test host rc.7: the file-DC
/// `begin()` call hung because `tokio::fs::create_dir_all` failed
/// silently on a path with no SYSTEM-profile parent ACL grant).
///
/// Returns `None` if the user has no logged-in session OR if the
/// resolved path doesn't exist (don't optimistically point uploads
/// at a phantom directory). The caller is expected to fall through
/// to a non-SystemContext resolution (`directories::UserDirs`) or
/// the temp-dir fallback.
pub fn active_user_downloads_path() -> Option<PathBuf> {
    let path = active_user_profile_root()?.join("Downloads");
    if path.exists() { Some(path) } else { None }
}

/// `ProcessIdToSessionId(GetCurrentProcessId())`. Returns the session
/// id this worker is attached to. The SystemContext spawn pipeline
/// puts the worker in the active interactive session so this is the
/// session where the user lives.
fn current_session_id() -> Option<u32> {
    // SAFETY: GetCurrentProcessId is a thread-safe Win32 call with
    // no preconditions, no ownership concerns.
    let pid = unsafe { GetCurrentProcessId() };
    let mut sid: u32 = 0;
    // SAFETY: `sid` is a stack-allocated u32 the API writes into.
    // Return value: 0 on failure, non-zero on success.
    let ok = unsafe { ProcessIdToSessionId(pid, &mut sid) };
    if ok == 0 { None } else { Some(sid) }
}

/// `WTSQuerySessionInformationW(NULL, sid, WTSUserName, ...)` →
/// owned `String`. Returns `None` for failure or empty username
/// (no logged-in user — typically the lock screen with no user
/// session yet, e.g. fresh boot before first login).
fn user_name_for_session(sid: u32) -> Option<String> {
    let mut buffer: *mut u16 = std::ptr::null_mut();
    let mut bytes_returned: u32 = 0;

    // SAFETY: WTS_CURRENT_SERVER_HANDLE is a documented sentinel
    // that means "this server"; sid is a u32; WTSUserName is a
    // documented enum value; `&mut buffer` is a stack ptr the API
    // writes into; same for `&mut bytes_returned`. On success the
    // buffer is OS-allocated and must be released via WTSFreeMemory.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE as HANDLE,
            sid,
            WTSUserName,
            &mut buffer,
            &mut bytes_returned,
        )
    };
    if ok == 0 || buffer.is_null() {
        return None;
    }
    let result = unsafe { extract_wide_string(buffer) };
    // SAFETY: We own `buffer` via the WTS contract; pair Free with
    // the successful Query.
    unsafe { WTSFreeMemory(buffer as *mut _) };
    let s = result?;
    if s.is_empty() { None } else { Some(s) }
}

/// Read a NUL-terminated UTF-16 string from a raw pointer into an
/// owned `String`. Lossy: invalid UTF-16 surrogates become the
/// Unicode replacement character. Returns `None` if the pointer is
/// null. Caller must guarantee the pointer is valid for the duration
/// of the call.
///
/// SAFETY: `ptr` must be a valid pointer to a NUL-terminated UTF-16
/// sequence within an allocation owned by the caller.
unsafe fn extract_wide_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        // Sanity cap: usernames are at most ~256 chars on Windows.
        // 4096 covers any realistic case and bounds the loop in
        // case the buffer is unexpectedly unterminated.
        if len > 4096 {
            return None;
        }
    }
    if len == 0 {
        return Some(String::new());
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf16_lossy(slice))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_session_id_returns_some_under_test_runner() {
        // Cargo test runner is in some session (1 typically). Lock
        // against panic + None return.
        let sid = current_session_id();
        assert!(
            sid.is_some(),
            "current_session_id should succeed on any logged-in box"
        );
    }

    #[test]
    fn active_user_config_path_under_test_runner_resolves() {
        // Under cargo test we're a logged-in user, so this resolves to OUR
        // profile. Which SEGMENT it lands on depends on what exists on this
        // box, so assert the shape, not one spelling — pinning a single
        // segment is what let the pre-rename one survive here unnoticed.
        let path = active_user_config_path();
        assert!(path.is_some(), "should resolve under user context");
        let p = path.unwrap();
        let s = p.to_string_lossy().to_lowercase();
        assert!(
            s.contains("\\users\\"),
            "path should be under C:\\Users: {p:?}"
        );
        assert!(
            s.ends_with("\\roomler\\config\\config.toml")
                || s.ends_with("\\roomler-agent\\config\\config.toml"),
            "path should end with a known config segment: {p:?}"
        );
    }

    #[test]
    fn config_candidates_put_the_current_segment_first() {
        // The bug this replaced: only the PRE-RENAME segment was ever
        // returned, so on a freshly installed host the caller's exists()
        // filter dropped the user-config rung entirely — silently, because
        // a missing candidate is indistinguishable from no logged-in user.
        let root = Path::new("C:\\Users\\someone");
        let got = config_candidates_under(root);
        let a = got[0].to_string_lossy().to_lowercase();
        let b = got[1].to_string_lossy().to_lowercase();
        assert!(
            a.ends_with("\\roomler\\roomler\\config\\config.toml"),
            "current segment must come first: {a}"
        );
        assert!(
            b.ends_with("\\roomler\\roomler-agent\\config\\config.toml"),
            "pre-rename segment must still be offered: {b}"
        );
    }
    #[test]
    fn active_user_profile_root_under_test_runner_resolves() {
        let root = active_user_profile_root();
        assert!(root.is_some(), "should resolve under user context");
        let p = root.unwrap();
        let s = p.to_string_lossy().to_lowercase();
        assert!(
            s.starts_with("c:\\users\\"),
            "path should be C:\\Users\\<name>: {p:?}"
        );
    }

    #[test]
    fn active_user_downloads_path_existence_gated() {
        // Under cargo test runner, our user profile DOES exist and
        // Downloads usually does too — but not guaranteed (e.g. CI
        // runners with stripped profiles). The function returns
        // None when the path doesn't exist; assert only the shape
        // when Some, and accept None silently otherwise.
        if let Some(p) = active_user_downloads_path() {
            let s = p.to_string_lossy().to_lowercase();
            assert!(
                s.contains("\\users\\"),
                "path should be under C:\\Users: {p:?}"
            );
            assert!(
                s.ends_with("\\downloads"),
                "path should end with \\Downloads: {p:?}"
            );
            assert!(
                p.exists(),
                "function returned Some(p) but p doesn't exist: {p:?}"
            );
        }
    }

    #[test]
    fn extract_wide_string_handles_empty() {
        let zero: u16 = 0;
        // SAFETY: zero is a valid local; address is valid for the
        // lifetime of this scope; first u16 is 0 (terminator).
        let result = unsafe { extract_wide_string(&zero) };
        assert_eq!(result, Some(String::new()));
    }

    #[test]
    fn extract_wide_string_handles_simple_ascii() {
        let buf: Vec<u16> = "hello\0".encode_utf16().collect();
        // SAFETY: buf is alive for the call; last element is 0.
        let result = unsafe { extract_wide_string(buf.as_ptr()) };
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn extract_wide_string_returns_none_on_null() {
        let result = unsafe { extract_wide_string(std::ptr::null()) };
        assert!(result.is_none());
    }
}
// RETIRED-NAME-ANCHOR-END
