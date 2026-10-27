// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Is THIS process `LocalSystem`, and whose profile does its session belong
//! to? — answered on every Windows build (FR-84 D4).
//!
//! `system_context::worker_role` answers the first question for the capture /
//! input plumbing, but it is compiled only with the `system-context` feature.
//! The `files_dir` placement rule — a SYSTEM writer stays inside the active
//! user's profile — is a security control and must not depend on which
//! features a build carries: a `meshharbord run` started under a SYSTEM token by
//! any means (`psexec -s -i`, a scheduled task running as SYSTEM) writes
//! dropped files as SYSTEM whether or not it can capture the lock screen. So
//! the token read lives here, feature-free, reading the same bytes
//! `worker_role` does.
//!
//! The profile comes from the session user's TOKEN, never from their name:
//! `system_context::user_profile::active_user_profile_root` builds
//! `C:\Users\<name>`, which is wrong for a redirected profile and — worse,
//! for a security rule — names ANOTHER account's folder when a local and a
//! domain account share a name (`C:\Users\alice` vs `C:\Users\alice.CORP`).

#![cfg(target_os = "windows")]

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
};
use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;

/// `true` when the calling process's primary token is `S-1-5-18`
/// (`NT AUTHORITY\SYSTEM`). Any failure to read the token is `false`: the
/// only consequence of a wrong `false` is the ordinary (user) folder rules,
/// which SYSTEM still cannot be talked past on the system roots.
pub fn process_is_local_system() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` is a pseudo-handle that is always valid;
    // `OpenProcessToken` with `TOKEN_QUERY` on our own process is documented
    // infallible in normal conditions; the out-pointer is checked on return.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 || token.is_null() {
        return false;
    }
    let result = token_user_is_local_system(token);
    // SAFETY: we own the handle `OpenProcessToken` gave us.
    unsafe { CloseHandle(token) };
    result
}

fn token_user_is_local_system(token: HANDLE) -> bool {
    let mut needed: u32 = 0;
    // SAFETY: the documented size-discovery call — a NULL buffer and a zero
    // length; `ERROR_INSUFFICIENT_BUFFER` is the expected outcome.
    let _ = unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return false;
    }
    let mut buf: Vec<u8> = vec![0; needed as usize];
    // SAFETY: `buf` is alive for the call and at least `needed` bytes long;
    // the OS writes at most `needed` bytes into it.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return false;
    }
    // SAFETY: the buffer holds a `TOKEN_USER`; its `User.Sid` points INTO
    // this same buffer (the SID follows the struct) — the documented idiom.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid as *const u8;
    if sid.is_null() {
        return false;
    }
    // Bound the read to the buffer the OS filled: a SID we compare needs its
    // 8-byte header and one 4-byte sub-authority.
    let start = sid as usize;
    let base = buf.as_ptr() as usize;
    if start < base || start + 12 > base + buf.len() {
        return false;
    }
    // SAFETY: the 12 bytes at `sid` are inside `buf`, checked just above.
    let bytes = unsafe { std::slice::from_raw_parts(sid, 12) };
    sid_bytes_are_local_system(bytes)
}

/// The profile directory of the user signed in to THIS process's session —
/// the "active user" for a SYSTEM writer. A SystemContext worker lives in
/// the interactive session it serves, so that is the person at the screen
/// being shared; a SYSTEM process in session 0 has no such user.
///
/// `None` when there is no user in the session (session 0, the pre-logon
/// lock screen), when this process may not ask (`WTSQueryUserToken` needs
/// SYSTEM with `SeTcbPrivilege` — any other caller gets
/// `ERROR_PRIVILEGE_NOT_HELD`), or on any other failure. `None` refuses
/// every `files_dir` for a privileged writer: a security rule that cannot
/// name the profile does not guess one.
pub fn session_user_profile_dir() -> Option<String> {
    let mut session: u32 = 0;
    // SAFETY: `GetCurrentProcessId` has no preconditions; `session` is a
    // live out-pointer the call writes one u32 into.
    let ok = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) };
    if ok == 0 {
        return None;
    }
    match crate::win_service::supervisor::query_user_token(session) {
        Ok(Some(token)) => profile_dir_of_token(token.raw()),
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(%e, session, "files_dir: no user token for this session");
            None
        }
    }
}

/// Run `f` on this thread AS the user signed in to this process's session.
/// For a SYSTEM writer touching a path that user controls — their profile.
///
/// ⚠️ Every file access inside `f` is checked against THEIR token. That is
/// the point: a profile folder is the user's to rearrange, so a SYSTEM write
/// there can be steered by a junction plus an object-manager link to ANY
/// path SYSTEM can write (the classic arbitrary-file-overwrite escalation).
/// Validating the path first does not close it — the link can be swapped
/// between the check and the write. Impersonated, the write can only land
/// where the user could have written anyway.
///
/// `None` when nobody is signed in to the session, when the token cannot be
/// had (`WTSQueryUserToken` needs SYSTEM with `SeTcbPrivilege`), or when
/// impersonation is refused. Then `f` has not run: a privileged writer that
/// cannot become the user does not fall back to writing as itself.
pub fn as_session_user<T>(f: impl FnOnce() -> T) -> Option<T> {
    use windows_sys::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};

    /// Ends the impersonation even if `f` panics.
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // SAFETY: ends this thread's impersonation.
            if unsafe { RevertToSelf() } == 0 {
                // A thread left wearing someone else's identity would run
                // whatever it does next as the wrong account. There is no
                // safe way on; the service manager restarts us.
                std::process::abort();
            }
        }
    }

    let mut session: u32 = 0;
    // SAFETY: as in `session_user_profile_dir`.
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } == 0 {
        return None;
    }
    let token = match crate::win_service::supervisor::query_user_token(session) {
        Ok(Some(t)) => t,
        Ok(None) => return None,
        Err(e) => {
            tracing::debug!(%e, session, "as_session_user: no user token for this session");
            return None;
        }
    };
    // SAFETY: a live primary token from `WTSQueryUserToken`. Should the
    // impersonation be refused, Windows hands the thread an identification
    // token instead and every open fails: closed, never open.
    if unsafe { ImpersonateLoggedOnUser(token.raw()) } == 0 {
        tracing::warn!(session, "as_session_user: ImpersonateLoggedOnUser refused");
        return None;
    }
    let _revert = Revert;
    Some(f())
}

/// This process's OWN profile directory, from its own token — an
/// unprivileged writer's home. A registry read, unlike the known-folder
/// lookups `directories::UserDirs` makes (those verify every folder they
/// resolve, so a Documents redirected to an offline share can stall them).
pub fn own_profile_dir() -> Option<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: as in `process_is_local_system`.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 || token.is_null() {
        return None;
    }
    let dir = profile_dir_of_token(token);
    // SAFETY: we own the handle `OpenProcessToken` gave us.
    unsafe { CloseHandle(token) };
    dir
}

/// `GetUserProfileDirectoryW` for `token` — the profile root Windows itself
/// records for that user (`ProfileList\<SID>\ProfileImagePath`), however it
/// is named or redirected.
pub(crate) fn profile_dir_of_token(token: HANDLE) -> Option<String> {
    let mut len: u32 = 0;
    // SAFETY: the documented size query — a NULL buffer and a zero length;
    // it fails with ERROR_INSUFFICIENT_BUFFER and writes the size needed
    // (in WCHARs, terminator included) into `len`.
    let _ = unsafe { GetUserProfileDirectoryW(token, std::ptr::null_mut(), &mut len) };
    if len == 0 || len > 32_768 {
        return None;
    }
    let mut buf: Vec<u16> = vec![0; len as usize];
    // SAFETY: `buf` holds `len` WCHARs and outlives the call; the OS writes
    // at most `len` of them, terminator included.
    let ok = unsafe { GetUserProfileDirectoryW(token, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let dir = String::from_utf16_lossy(&buf[..end]);
    (!dir.is_empty()).then_some(dir)
}

/// `S-1-5-18` in SID byte layout: revision 1, exactly one sub-authority,
/// the NT authority `{0,0,0,0,0,5}`, sub-authority[0] = 18 (little-endian).
/// Pure, so it is testable with synthetic buffers.
pub(crate) fn sid_bytes_are_local_system(sid: &[u8]) -> bool {
    sid.len() >= 12
        && sid[0] == 1
        && sid[1] == 1
        && sid[2..8] == [0, 0, 0, 0, 0, 5]
        && u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]) == 18
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(revision: u8, count: u8, auth: [u8; 6], sub0: u32) -> Vec<u8> {
        let mut v = vec![revision, count];
        v.extend_from_slice(&auth);
        v.extend_from_slice(&sub0.to_le_bytes());
        v
    }

    #[test]
    fn local_system_sid_is_recognised_and_nothing_else_is() {
        assert!(sid_bytes_are_local_system(&sid(
            1,
            1,
            [0, 0, 0, 0, 0, 5],
            18
        )));
        // LocalService / NetworkService share the authority, not the RID.
        assert!(!sid_bytes_are_local_system(&sid(
            1,
            1,
            [0, 0, 0, 0, 0, 5],
            19
        )));
        assert!(!sid_bytes_are_local_system(&sid(
            1,
            1,
            [0, 0, 0, 0, 0, 5],
            20
        )));
        // A domain / local user: S-1-5-21-…, several sub-authorities.
        assert!(!sid_bytes_are_local_system(&sid(
            1,
            5,
            [0, 0, 0, 0, 0, 5],
            21
        )));
        // Wrong authority, wrong revision, truncated.
        assert!(!sid_bytes_are_local_system(&sid(
            1,
            1,
            [0, 0, 0, 0, 0, 1],
            18
        )));
        assert!(!sid_bytes_are_local_system(&sid(
            2,
            1,
            [0, 0, 0, 0, 0, 5],
            18
        )));
        assert!(!sid_bytes_are_local_system(&[1, 1, 0, 0, 0, 0, 0, 5]));
        assert!(!sid_bytes_are_local_system(&[]));
    }

    #[test]
    fn the_test_runner_is_not_local_system() {
        // `cargo test` runs as the developer or the CI user; the read must
        // succeed (no panic) and say so.
        assert!(!process_is_local_system());
    }

    /// The token → profile half, on our OWN token: Windows' recorded
    /// profile for the test runner is its `%USERPROFILE%`. (The session
    /// half, `WTSQueryUserToken`, needs SYSTEM and is proven on a
    /// perMachine host — see FR-84's field log.)
    #[test]
    fn profile_of_our_own_token_is_our_userprofile() {
        let got = own_profile_dir();
        let want = std::env::var("USERPROFILE").expect("USERPROFILE is set for a test runner");
        assert!(
            got.as_deref()
                .is_some_and(|g| g.eq_ignore_ascii_case(want.trim_end_matches('\\'))),
            "{got:?} vs {want:?}"
        );
    }

    /// Not SYSTEM ⇒ `WTSQueryUserToken` refuses ⇒ no profile, never a
    /// guess — and never a panic.
    #[test]
    fn a_non_system_caller_gets_no_session_profile() {
        assert_eq!(session_user_profile_dir(), None);
    }

    /// FR-92 — with no session user's token to become, the closure does NOT
    /// run: a privileged writer that cannot act as the person must never act
    /// as itself instead. (A test runner is not SYSTEM, so the token is
    /// refused, exactly as when nobody is signed in.)
    #[test]
    fn without_the_session_users_token_nothing_runs() {
        assert!(!process_is_local_system());
        let mut ran = false;
        assert_eq!(as_session_user(|| ran = true), None);
        assert!(!ran);
    }
}
