// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P4a — the SCM host's half of the real Ctrl+Alt+Del.
//!
//! `SendSAS(FALSE)` is honoured only from the service process. Measured: the
//! SystemContext worker's own call (SYSTEM, but in the person's session, a
//! child of the service and not the service) returns, and the lock screen
//! never moves. So the host owns one named, auto-reset event for its lifetime,
//! hands its name to every worker it spawns (`--sas-event <name>`), and a
//! thread of its own waits on it: each signal is one `SendSAS(FALSE)`
//! (`crate::input::sas::host_send`, which re-checks the policy rather than
//! trusting that the worker did).
//!
//! ## Only SYSTEM may signal it
//!
//! [`SAS_RELAY_SDDL`] is a protected DACL that grants SYSTEM everything and
//! nobody else anything. The SystemContext worker is SYSTEM. An attended
//! worker, which runs as the signed-in person, cannot open it, so that install
//! keeps typing keys. A SAS is what the physical chord raises: a SYSTEM process
//! that asks for one gains nothing it lacked, and the kernel refuses anyone
//! else. Auto-reset, so signals that arrive while one is being answered
//! coalesce into one more, never a queue.
//!
//! Everything degrades to the keys: if the event or its thread cannot be made,
//! the worker is handed no relay, says `keys-only`, and types three keys as
//! before P4a.

#![cfg(target_os = "windows")]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, LocalFree, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

/// SYSTEM gets `EVENT_ALL_ACCESS`; nobody else gets anything. **A security
/// decision**: read the module docs before widening it.
pub const SAS_RELAY_SDDL: &str = "D:P(A;;0x1f0003;;;SY)";

/// `Global\`, so a worker in the person's session opens what the host made in
/// session 0. Completed by the host's PID: one relay per host.
const SAS_RELAY_PREFIX: &str = "Global\\roomler-sas-";

/// `SDDL_REVISION_1`, the only defined SDDL revision.
const SDDL_REVISION_1: u32 = 1;

/// The relay's handle, owned by its thread for the host's lifetime.
struct RelayHandle(HANDLE);

// SAFETY: a Win32 `HANDLE` is a process-wide kernel-object reference with no
// thread affinity; the relay thread is its only user once it is moved there.
unsafe impl Send for RelayHandle {}

/// The `--sas-event <name>` argv for a worker spawn, starting the relay on the
/// first call. Empty when the relay could not be made: that worker then types
/// keys, as before P4a.
pub fn worker_args() -> Vec<String> {
    static RELAY: OnceLock<Option<String>> = OnceLock::new();
    match RELAY.get_or_init(start) {
        Some(name) => vec!["--sas-event".to_string(), name.clone()],
        None => Vec::new(),
    }
}

fn start() -> Option<String> {
    let name = format!("{SAS_RELAY_PREFIX}{}", std::process::id());
    let handle = match create(&name) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "sas relay: no event; Ctrl+Alt+Del stays three keys here");
            return None;
        }
    };
    let spawned = std::thread::Builder::new()
        .name("roomlerd-sas-relay".into())
        .spawn(move || serve(handle));
    match spawned {
        Ok(_) => {
            tracing::info!(%name, "sas relay: ready for the worker's Ctrl+Alt+Del");
            Some(name)
        }
        Err(e) => {
            tracing::warn!(error = %e, "sas relay: no thread; Ctrl+Alt+Del stays three keys here");
            None
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// The auto-reset event, unsignaled, with [`SAS_RELAY_SDDL`]. Refuses a name
/// that already exists: a stale relay could be someone else's.
fn create(name: &str) -> io::Result<RelayHandle> {
    let sddl = wide(SAS_RELAY_SDDL);
    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `psd` is a valid out-pointer; the size
    // out-pointer is documented optional.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd,
        bInheritHandle: 0,
    };
    let name_w = wide(name);
    // SAFETY: `sa` and its descriptor outlive the call; `name_w` is
    // NUL-terminated. Auto-reset (0), unsignaled (0).
    let handle = unsafe { CreateEventW(&sa, 0, 0, name_w.as_ptr()) };
    // SAFETY: a thread-local read, before LocalFree can reset it.
    let err = unsafe { GetLastError() };
    // SAFETY: `psd` came from the conversion above; the event copied it.
    let _ = unsafe { LocalFree(psd) };
    if handle.is_null() {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    if err == ERROR_ALREADY_EXISTS {
        // SAFETY: the handle CreateEventW just returned, closed once.
        unsafe { CloseHandle(handle) };
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{name} already existed"),
        ));
    }
    Ok(RelayHandle(handle))
}

/// Answer each signal with one `SendSAS(FALSE)`, for the host's lifetime.
fn serve(handle: RelayHandle) {
    loop {
        // SAFETY: a live event handle this thread owns; an infinite wait on
        // the relay thread, which does nothing else.
        match unsafe { WaitForSingleObject(handle.0, INFINITE) } {
            WAIT_OBJECT_0 => match crate::input::sas::host_send() {
                Ok(()) => tracing::info!("sas relay: sent the secure attention sequence"),
                Err(e) => tracing::warn!(error = %e, "sas relay: nothing sent"),
            },
            other => {
                tracing::warn!(
                    result = other,
                    "sas relay: the wait failed; no more Ctrl+Alt+Del from this host"
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SYSTEM alone: an interactive user must not be able to raise a SAS on
    /// the console. Changing this string is changing that decision.
    #[test]
    fn only_system_may_signal_the_relay() {
        assert_eq!(SAS_RELAY_SDDL, "D:P(A;;0x1f0003;;;SY)");
        assert!(!SAS_RELAY_SDDL.contains(";IU)") && !SAS_RELAY_SDDL.contains(";WD)"));
    }

    /// The descriptor builds into a real event; a second relay under the same
    /// name is refused rather than shared; and this test, which runs as a
    /// person and not as SYSTEM, cannot open it to signal. (Measured: as a
    /// person even the second create is refused for access before Windows
    /// says the name exists.)
    #[test]
    fn the_relay_is_made_once_and_a_person_cannot_signal_it() {
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        use windows_sys::Win32::System::Threading::OpenEventW;
        let name = format!("{SAS_RELAY_PREFIX}test-{}", std::process::id());
        let first = create(&name).expect("the SDDL must build an event");
        let second = create(&name);
        assert!(matches!(
            second.err().map(|e| e.kind()),
            Some(io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied)
        ));
        let name_w = wide(&name);
        // SAFETY: `name_w` is NUL-terminated; EVENT_MODIFY_STATE (0x2) is what
        // a worker asks for.
        let opened = unsafe { OpenEventW(0x0002, 0, name_w.as_ptr()) };
        // SAFETY: a thread-local read.
        let err = unsafe { GetLastError() };
        if !opened.is_null() {
            // SAFETY: closed once; the assertion below then fails.
            unsafe { CloseHandle(opened) };
        }
        assert!(
            opened.is_null() && err == ERROR_ACCESS_DENIED,
            "a process that is not SYSTEM must not be able to ask for a SAS"
        );
        // SAFETY: the handle `create` returned, closed once.
        unsafe { CloseHandle(first.0) };
    }
}
