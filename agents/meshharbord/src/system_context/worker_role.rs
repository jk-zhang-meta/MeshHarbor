// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Token-probe at worker startup — picks the User-mode or
//! SystemContext-mode plumbing tree.
//!
//! The agent binary is spawned identically by both the SCM service
//! (M2 user-context path: `WTSQueryUserToken` + `CreateProcessAsUserW`)
//! and the M3 A1 path (winlogon-token + `CreateProcessAsUserW`). The
//! caller's token is what differentiates the two. Rather than ship a
//! `--worker-mode` CLI flag (which would be falsifiable and
//! ambiguous), the worker reads its OWN primary token via
//! `OpenProcessToken(GetCurrentProcess())` + `GetTokenInformation`,
//! checks the SID, and selects its `CaptureSource` + `InputSink`
//! traits accordingly.
//!
//! Three SIDs are recognised:
//!
//! * `S-1-5-18` — **LocalSystem** (`NT AUTHORITY\SYSTEM`). The M3 A1
//!   winlogon-token spawn produces a token with this SID even when
//!   the session id has been overridden to a non-zero interactive
//!   session, so this is the discriminator. Selects
//!   [`WorkerRole::SystemContext`].
//!
//! * Any other SID — a user token. Almost always `S-1-5-21-...` for
//!   a normal Active Directory / local user; on legacy boxes it
//!   could be `S-1-5-7` (anonymous) or `S-1-5-19/20` (LocalService /
//!   NetworkService) but those don't have an interactive session
//!   and would never reach this code in production. Selects
//!   [`WorkerRole::User`].
//!
//! ## Why probe at startup, not per-call
//!
//! Token info doesn't change over the lifetime of a process —
//! `SetTokenInformation` can adjust privileges and session id but
//! not the user SID. One probe at `Run` startup is enough; the
//! result is cached in a `WorkerRole` value and consulted by every
//! capture / input construction site.
//!
//! ## Default on non-Windows
//!
//! The whole module is `#[cfg(target_os = "windows")]`-gated by the
//! parent `system_context` mod gate. Non-Windows builds with the
//! `system-context` feature still link cleanly because the parent
//! gate keeps the file out of the build entirely.
//!
//! ## Failure modes
//!
//! `OpenProcessToken` and `GetTokenInformation` against the calling
//! process are documented infallible in normal conditions (we always
//! have at least `PROCESS_QUERY_LIMITED_INFORMATION` over our own
//! handle). Out of paranoia the public `probe_self` API returns a
//! `Result`; in practice every code path will use `unwrap_or` to
//! default to [`WorkerRole::User`] (the pre-M3 behaviour) on the
//! impossible-error branch — failing closed is correct because
//! User-mode plumbing is what every existing build does today.

#![cfg(target_os = "windows")]

use anyhow::{Context, Result, bail};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, SID_IDENTIFIER_AUTHORITY, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// What kind of capture / input plumbing this worker uses. Resolved
/// once at startup from the worker's own primary token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerRole {
    /// Normal user session — the M2 default and the M3 A1 case when
    /// the supervisor decides the active desktop is `Default` (not
    /// `Winlogon`). Capture: WGC / scrap. Input: plain `enigo`. Lock
    /// detection: `lock_state.rs` polling `OpenInputDesktop`.
    User,
    /// SYSTEM-in-session-N worker, spawned via the winlogon-token
    /// path. Capture: DXGI Desktop Duplication (no WGC because
    /// session-0 WinRT activation fails per the 0.2.5 NO-GO). Input:
    /// `enigo` from a dedicated thread that owns
    /// `SetThreadDesktop(OpenInputDesktop())`. Lock detection: not
    /// needed — the SYSTEM worker IS the path that drives the lock
    /// screen.
    SystemContext,
}

impl WorkerRole {
    /// Whether this role drives the M3 A1 SYSTEM-context plumbing.
    /// Convenience for branch sites that don't care about the User
    /// shape.
    pub fn is_system_context(self) -> bool {
        matches!(self, WorkerRole::SystemContext)
    }
}

/// Probe the calling process's own primary token and decide which
/// `WorkerRole` to use. Documented infallible in production but
/// returns `Result` so a misconfigured test harness (process
/// genuinely missing TOKEN_QUERY rights) surfaces an error rather
/// than silently misclassifying.
pub fn probe_self() -> Result<WorkerRole> {
    let token = open_self_token().context("opening own primary token for role probe")?;
    let role = classify_from_token(token.raw())?;
    Ok(role)
}

/// Wrapper that closes the token handle on drop. The Win32 `HANDLE`
/// type is just a pointer-sized integer with no Drop semantics;
/// without this every error path leaks an OS handle.
struct OwnedToken(HANDLE);

impl OwnedToken {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: We own this handle (constructed via
            // OpenProcessToken). CloseHandle on a valid token is the
            // canonical cleanup; failure is unrecoverable from a
            // Drop impl.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn open_self_token() -> Result<OwnedToken> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that's
    // always valid; OpenProcessToken with TOKEN_QUERY against our
    // own process is documented infallible in normal conditions.
    // Out-pointer is checked immediately on return.
    let ok =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token as *mut HANDLE) };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("OpenProcessToken(self, TOKEN_QUERY) failed (err {err})");
    }
    Ok(OwnedToken(token))
}

/// Read `TokenUser` from `token` and classify the SID.
///
/// The two-call pattern of `GetTokenInformation`:
///   1. First call with NULL buffer + 0 length to get the required
///      size in `needed`.
///   2. Second call with a buffer of that size.
///
/// We could use a stack-allocated `MaybeUninit<TOKEN_USER>` but the
/// trailing SID lives off the end of the struct (a flexible array
/// member in C, opaque pointer in Rust); the heap-Vec approach is
/// simpler and we run this exactly once per process lifetime.
fn classify_from_token(token: HANDLE) -> Result<WorkerRole> {
    let mut needed: u32 = 0;
    // SAFETY: token is a valid HANDLE we own; first call with NULL
    // buffer is the documented size-discovery pattern. ERROR_
    // INSUFFICIENT_BUFFER (122) is expected and not a failure.
    let _ = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed as *mut u32,
        )
    };
    if needed == 0 {
        bail!("GetTokenInformation(TokenUser) returned needed=0");
    }
    let mut buf: Vec<u8> = vec![0; needed as usize];
    // SAFETY: buf is alive for the call; the OS writes at most
    // `needed` bytes into it. token is valid.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed as *mut u32,
        )
    };
    if ok == 0 {
        // SAFETY: GetLastError is a thread-local read.
        let err = unsafe { GetLastError() };
        bail!("GetTokenInformation(TokenUser) failed (err {err})");
    }
    // The buffer holds a TOKEN_USER struct. Its `User.Sid` field is
    // a pointer that points INTO the same buffer (the SID lives
    // immediately after the TOKEN_USER's User member). Reading it
    // out of the buffer is the documented idiom.
    //
    // SAFETY: buf size matches what the OS returned for TOKEN_USER;
    // the cast lines up with the struct layout. The SID pointer is
    // valid for the lifetime of `buf`.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;
    if sid.is_null() {
        bail!("TOKEN_USER.User.Sid is null");
    }
    Ok(classify_sid_pointer(sid))
}

/// Classify a SID pointer as `SystemContext` (S-1-5-18) or `User`
/// (anything else). Pulled out as a free function so unit tests can
/// build synthetic SID-shaped buffers without invoking the OS.
///
/// `S-1-5-18` is the LocalSystem SID. Format:
///   * Revision = 1
///   * SubAuthorityCount = 1
///   * IdentifierAuthority = {0,0,0,0,0,5} (NT_AUTHORITY)
///   * SubAuthority[0] = 18 (LOCAL_SYSTEM_RID)
///
/// We read the first byte (Revision), the second byte (count), the
/// 6-byte authority, and the first 4-byte subauthority via direct
/// offset rather than going through the windows-sys `SID` struct
/// (which has a 1-element FAM that triggers warnings).
fn classify_sid_pointer(sid: *mut std::ffi::c_void) -> WorkerRole {
    // SAFETY: caller asserted sid is a valid SID pointer (layout per
    // SID struct above). We read the fixed-size prefix only —
    // revision (u8), subauthority count (u8), 6-byte authority,
    // optional 4-byte first subauthority. SubAuthorityCount=0 means
    // no subauthority follows, which is fine — we only read it
    // when count >= 1.
    let bytes = sid as *const u8;
    // Bounds check: a valid SID is at least 8 bytes (header) and
    // grows by 4 per subauthority. We don't have the buffer size
    // here, but the OS-supplied SID is always self-consistent.
    let revision = unsafe { *bytes };
    let sub_count = unsafe { *bytes.add(1) };
    if revision != 1 || sub_count == 0 {
        // Malformed or no subauthorities → not LocalSystem.
        return WorkerRole::User;
    }
    // IdentifierAuthority is at offset 2..8 (6 bytes, big-endian
    // 48-bit). We only need to compare against {0,0,0,0,0,5}.
    let auth: [u8; 6] = unsafe {
        [
            *bytes.add(2),
            *bytes.add(3),
            *bytes.add(4),
            *bytes.add(5),
            *bytes.add(6),
            *bytes.add(7),
        ]
    };
    if auth != [0, 0, 0, 0, 0, 5] {
        return WorkerRole::User;
    }
    // SubAuthority[0] is at offset 8..12 (little-endian u32).
    let sub0_bytes: [u8; 4] =
        unsafe { [*bytes.add(8), *bytes.add(9), *bytes.add(10), *bytes.add(11)] };
    let sub0 = u32::from_le_bytes(sub0_bytes);
    // S-1-5-18 has exactly one subauthority = 18. The supervisor
    // never spawns a worker with a stripped-down LocalSystem token
    // (e.g. via SetTokenInformation removing groups) so an exact
    // match is the right contract.
    if sub_count == 1 && sub0 == 18 {
        WorkerRole::SystemContext
    } else {
        WorkerRole::User
    }
}

// `SID_IDENTIFIER_AUTHORITY` is unused at runtime (we read raw bytes
// for the comparison) but kept as a documentation anchor on what
// the windows-sys binding looks like. Suppress the unused-import
// warning so `cargo clippy` stays clean.
#[allow(dead_code)]
const _SID_AUTHORITY_TYPE_PIN: Option<SID_IDENTIFIER_AUTHORITY> = None;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic LocalSystem SID buffer matching the on-disk
    /// shape `GetTokenInformation` would return.
    fn make_localsystem_sid() -> Vec<u8> {
        let mut sid = Vec::with_capacity(12);
        sid.push(1); // Revision
        sid.push(1); // SubAuthorityCount
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // NT_AUTHORITY
        sid.extend_from_slice(&18u32.to_le_bytes()); // LOCAL_SYSTEM_RID
        sid
    }

    /// Build a synthetic local-user SID — `S-1-5-21-1-2-3-1001`.
    fn make_user_sid() -> Vec<u8> {
        let mut sid = Vec::with_capacity(28);
        sid.push(1); // Revision
        sid.push(5); // SubAuthorityCount
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // NT_AUTHORITY
        sid.extend_from_slice(&21u32.to_le_bytes()); // SECURITY_NT_NON_UNIQUE
        sid.extend_from_slice(&1u32.to_le_bytes());
        sid.extend_from_slice(&2u32.to_le_bytes());
        sid.extend_from_slice(&3u32.to_le_bytes());
        sid.extend_from_slice(&1001u32.to_le_bytes());
        sid
    }

    #[test]
    fn classify_localsystem_sid_returns_system_context() {
        let sid = make_localsystem_sid();
        let role = classify_sid_pointer(sid.as_ptr() as *mut std::ffi::c_void);
        assert_eq!(role, WorkerRole::SystemContext);
    }

    #[test]
    fn classify_user_sid_returns_user() {
        let sid = make_user_sid();
        let role = classify_sid_pointer(sid.as_ptr() as *mut std::ffi::c_void);
        assert_eq!(role, WorkerRole::User);
    }

    #[test]
    fn classify_localservice_sid_returns_user() {
        // S-1-5-19 (LocalService). Not the M3 A1 path's target, so
        // we treat it as User-mode. Documenting this in the test
        // because someone might naively expect "any SYSTEM-ish
        // account" to map to SystemContext — it does not.
        let mut sid = Vec::with_capacity(12);
        sid.push(1);
        sid.push(1);
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
        sid.extend_from_slice(&19u32.to_le_bytes());
        let role = classify_sid_pointer(sid.as_ptr() as *mut std::ffi::c_void);
        assert_eq!(role, WorkerRole::User);
    }

    #[test]
    fn classify_networkservice_sid_returns_user() {
        // S-1-5-20 (NetworkService). Same reasoning as LocalService.
        let mut sid = Vec::with_capacity(12);
        sid.push(1);
        sid.push(1);
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
        sid.extend_from_slice(&20u32.to_le_bytes());
        let role = classify_sid_pointer(sid.as_ptr() as *mut std::ffi::c_void);
        assert_eq!(role, WorkerRole::User);
    }

    #[test]
    fn classify_zero_subauthority_sid_returns_user() {
        // SubAuthorityCount = 0 means "no subauthorities present" —
        // S-1-0 (Null) for instance. We treat this as User and let
        // the caller fail downstream rather than mis-classify.
        let mut sid = Vec::with_capacity(8);
        sid.push(1);
        sid.push(0);
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let role = classify_sid_pointer(sid.as_ptr() as *mut std::ffi::c_void);
        assert_eq!(role, WorkerRole::User);
    }

    #[test]
    fn classify_wrong_revision_returns_user() {
        // SID revision should always be 1 in current Windows. Anything
        // else is malformed; we fail closed to User.
        let mut sid = Vec::with_capacity(12);
        sid.push(2); // Wrong revision
        sid.push(1);
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
        sid.extend_from_slice(&18u32.to_le_bytes());
        let role = classify_sid_pointer(sid.as_ptr() as *mut std::ffi::c_void);
        assert_eq!(role, WorkerRole::User);
    }

    #[test]
    fn classify_world_sid_returns_user() {
        // S-1-1-0 (Everyone). Different identifier authority
        // (WORLD_SID_AUTHORITY = {0,0,0,0,0,1}). Not LocalSystem.
        let mut sid = Vec::with_capacity(12);
        sid.push(1);
        sid.push(1);
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 1]); // WORLD
        sid.extend_from_slice(&0u32.to_le_bytes());
        let role = classify_sid_pointer(sid.as_ptr() as *mut std::ffi::c_void);
        assert_eq!(role, WorkerRole::User);
    }

    #[test]
    fn worker_role_is_system_context_helper() {
        assert!(WorkerRole::SystemContext.is_system_context());
        assert!(!WorkerRole::User.is_system_context());
    }

    #[test]
    fn probe_self_returns_user_under_normal_test_runner() {
        // The cargo test runner inherits the developer's user token,
        // not LocalSystem, so probe_self must return User. If this
        // test ever fails with SystemContext, we're on a SYSTEM-
        // privileged CI runner (which would mask the M3 A1
        // architecture's actual behaviour) — investigate.
        let role = probe_self().expect("probe_self");
        assert_eq!(role, WorkerRole::User);
    }
}
