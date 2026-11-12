// SPDX-License-Identifier: AGPL-3.0-only
//! MeshHarbor — who a SHARED session's file operations run as.
//!
//! A device share hands its file channel to a recipient who is not the
//! device's owner. Whatever they list, read, download or upload must never run
//! as root or SYSTEM. The server sends the share's account on the lease
//! (`SharedSessionLease::account`, only to an agent advertising
//! `shared-files-as-account`). This module decides what that means, per
//! session, from this install's own privilege:
//!
//! | lease account | this install | file operations run as |
//! |---|---|---|
//! | set | Linux root | that account: a thread fsuid switch (`fs_identity`) per step |
//! | set | macOS root / Windows service | refused — no per-step switch here / no Unix account |
//! | set | unprivileged | the daemon only if it IS that account; else refused |
//! | none | unprivileged (a per-user install: the owner's own account) | the daemon, as before |
//! | none | privileged | refused: the owner must choose a share account |
//!
//! "Privileged" is the INSTALL, not only this process. A Windows service's
//! console worker and a macOS supervisor's GUI worker run as whoever sits at
//! the screen, which is not the owner's explicit choice. The Linux root seat0
//! person (`FsAs::now`) is the same case, so a shared session never takes it.
//! A session that is not shared is untouched by all of this.
//!
//! The registry is filled where the session's lease attaches to its peer
//! (`signaling::handle_server_msg`, `rc:sdp.offer`), in whichever process
//! serves the peer, and emptied at `rc:terminate`. The hub never gives a
//! shared session file children (`shared child inheritance unavailable`), so
//! only the session's own `files` channel consults it, and a child channel of
//! a shared session is refused here too.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, OnceLock};

use bson::oid::ObjectId;
use meshharbor_remote_control::signaling::SharedSessionLease;

use crate::files::FsAs;

/// What a shared session's file channel may do on this device.
#[derive(Debug)]
pub(crate) enum SharedFiles {
    /// Serve it, every filesystem step as this identity.
    As(FsAs),
    /// Refuse it, with the reason the recipient is shown.
    Refused(String),
}

/// How privileged THIS install is, for the rule in the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Privilege {
    /// A per-user install: the daemon is its owner's own account.
    Unprivileged,
    /// A Linux/macOS root daemon, or a worker a root supervisor spawned.
    #[cfg(unix)]
    Root,
    /// A Windows SYSTEM process, or a worker a service install spawned.
    #[cfg(windows)]
    WindowsService,
}

/// Shared sessions whose lease attached in this process, and the share
/// account each one carries.
static SHARED: LazyLock<Mutex<HashMap<ObjectId, Option<String>>>> = LazyLock::new(Default::default);

/// Set once at start-up from who spawned this process.
static PRIVILEGED_SUPERVISOR: OnceLock<bool> = OnceLock::new();

/// Record whether a privileged supervisor spawned this process: a Windows
/// service host's worker (`run --supervisor scm`), or a macOS supervisor's
/// GUI worker (`run --supervised`). Either runs as the person at the screen
/// while the install itself is a system one.
pub fn note_supervision(s: crate::supervision::Supervision) {
    use crate::supervision::Supervision;
    let _ = PRIVILEGED_SUPERVISOR.set(matches!(
        s,
        Supervision::WindowsScm | Supervision::MacosSupervisor
    ));
}

/// A shared session's lease attached to its peer here: its file channel, if
/// one opens, follows this module's rule. Idempotent for a renegotiated offer
/// (the lease is immutable, `shared_lease`).
pub fn note(session_id: ObjectId, lease: &SharedSessionLease) {
    SHARED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(session_id, lease.account.clone());
}

/// The session ended.
pub fn forget(session_id: ObjectId) {
    SHARED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&session_id);
}

/// `None` for a session that is not shared: its file channel is served as it
/// always was. `Some` for a shared one: how to serve it, or why not.
pub(crate) fn for_session(session_id: ObjectId) -> Option<SharedFiles> {
    let account = SHARED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&session_id)
        .cloned()?;
    Some(decide(account.as_deref(), privilege()))
}

/// Is `session_id` a shared session served by this process?
pub(crate) fn is_shared(session_id: ObjectId) -> bool {
    SHARED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&session_id)
}

/// This install's privilege: the process's own identity, or the supervisor
/// that spawned it.
pub(crate) fn privilege() -> Privilege {
    let supervised = PRIVILEGED_SUPERVISOR.get().copied().unwrap_or(false);
    #[cfg(unix)]
    {
        // SAFETY: reads this process's own credentials.
        if supervised || unsafe { libc::geteuid() } == 0 {
            Privilege::Root
        } else {
            Privilege::Unprivileged
        }
    }
    #[cfg(windows)]
    {
        if supervised || crate::win_identity::process_is_local_system() {
            Privilege::WindowsService
        } else {
            Privilege::Unprivileged
        }
    }
}

/// The rule itself, pure apart from the account lookup.
pub(crate) fn decide(account: Option<&str>, privilege: Privilege) -> SharedFiles {
    let Some(name) = account else {
        return match privilege {
            // A per-user install IS its owner: the share runs as the owner's
            // own account, exactly as an unshared session does.
            Privilege::Unprivileged => SharedFiles::As(FsAs::Daemon),
            #[cfg(unix)]
            Privilege::Root => SharedFiles::Refused(
                "file sharing on this device needs a share account: the owner must choose \
                 one for this share"
                    .into(),
            ),
            #[cfg(windows)]
            Privilege::WindowsService => SharedFiles::Refused(
                "file sharing is not available on a system-service install".into(),
            ),
        };
    };
    if !crate::local_accounts::valid_name(name) {
        return SharedFiles::Refused(format!(
            "the share account {name:?} is not a valid account name"
        ));
    }
    as_named(name, privilege)
}

#[cfg(target_os = "linux")]
fn as_named(name: &str, privilege: Privilege) -> SharedFiles {
    // `exec`'s resolution: uid 0 is refused by name, so a share can never be
    // pointed at root.
    let account = match crate::fs_identity::Account::by_name(name) {
        Ok(a) => a,
        Err(e) => {
            return SharedFiles::Refused(format!(
                "the share account {name} is not usable on this device: {e}"
            ));
        }
    };
    // SAFETY: reads this process's own credentials.
    let euid = unsafe { libc::geteuid() };
    match privilege {
        Privilege::Root if euid == 0 => match crate::exec::account_home(name) {
            Ok(home) => SharedFiles::As(FsAs::Person { account, home }),
            Err(e) => SharedFiles::Refused(format!(
                "the share account {name} is not usable on this device: {e}"
            )),
        },
        _ if account.uid == euid => SharedFiles::As(FsAs::Daemon),
        _ => SharedFiles::Refused(format!(
            "this device's agent runs as a single user and cannot act as the share \
             account {name}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn as_named(name: &str, privilege: Privilege) -> SharedFiles {
    match privilege {
        // SAFETY: reads this process's own credentials.
        Privilege::Unprivileged if uid_of(name) == Some(unsafe { libc::geteuid() }) => {
            SharedFiles::As(FsAs::Daemon)
        }
        Privilege::Unprivileged => SharedFiles::Refused(format!(
            "this device's agent runs as a single user and cannot act as the share \
             account {name}"
        )),
        // macOS has no per-thread filesystem identity like Linux's fsuid, and
        // a supervisor's GUI worker is not root at all, so a step-by-step
        // switch cannot be made here. Refused rather than served as root or
        // as whoever sits at the screen.
        _ => SharedFiles::Refused(
            "file sharing as a share account is not yet available on a macOS system install".into(),
        ),
    }
}

#[cfg(windows)]
fn as_named(_name: &str, _privilege: Privilege) -> SharedFiles {
    SharedFiles::Refused(
        "a share account applies to Linux and macOS devices; this Windows device cannot act \
         as one"
            .into(),
    )
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn as_named(name: &str, _privilege: Privilege) -> SharedFiles {
    SharedFiles::Refused(format!(
        "this device cannot act as the share account {name}"
    ))
}

/// The uid `getpwnam_r` gives for `name`.
#[cfg(target_os = "macos")]
fn uid_of(name: &str) -> Option<libc::uid_t> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 1024];
    // SAFETY: a plain C struct, written by `getpwnam_r` before it is read.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        // SAFETY: every pointer is to memory this frame owns, sized as passed.
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 64 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        return Some(pwd.pw_uid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(s: SharedFiles) -> String {
        match s {
            SharedFiles::Refused(r) => r,
            SharedFiles::As(who) => panic!("expected a refusal, got {who:?}"),
        }
    }

    #[test]
    fn no_account_runs_as_a_per_user_daemon_and_refuses_on_a_privileged_one() {
        assert!(matches!(
            decide(None, Privilege::Unprivileged),
            SharedFiles::As(FsAs::Daemon)
        ));
        #[cfg(unix)]
        assert!(refused(decide(None, Privilege::Root)).contains("must choose"));
        #[cfg(windows)]
        assert!(
            refused(decide(None, Privilege::WindowsService)).contains("system-service install")
        );
    }

    #[test]
    fn an_invalid_account_name_is_refused_on_every_install() {
        let all = [
            Privilege::Unprivileged,
            #[cfg(unix)]
            Privilege::Root,
            #[cfg(windows)]
            Privilege::WindowsService,
        ];
        for p in all {
            for bad in ["", "Root", "a b", "../etc", "x\0y"] {
                assert!(
                    refused(decide(Some(bad), p)).contains("not a valid account name"),
                    "{bad:?} {p:?}"
                );
            }
        }
    }

    #[test]
    fn the_registry_tells_shared_from_ordinary_sessions() {
        let sid = ObjectId::new();
        assert!(for_session(sid).is_none(), "an ordinary session");
        assert!(!is_shared(sid));
        note(
            sid,
            &SharedSessionLease {
                grant_id: ObjectId::new(),
                lease_epoch: "e".into(),
                account: None,
            },
        );
        assert!(is_shared(sid));
        assert!(for_session(sid).is_some(), "a shared one is always decided");
        // On a root process (the test runner here), a shared session without
        // an account is refused: never served as root, never as seat0's person.
        #[cfg(unix)]
        {
            // SAFETY: reads our own credentials.
            if unsafe { libc::geteuid() } == 0 {
                assert!(
                    matches!(for_session(sid), Some(SharedFiles::Refused(r)) if r.contains("must choose")),
                    "a root install refuses a shared file channel without an account"
                );
            }
        }
        forget(sid);
        assert!(for_session(sid).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_root_runs_as_the_share_account_and_never_as_root() {
        // SAFETY: reads our own credentials.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        match decide(Some("nobody"), Privilege::Root) {
            SharedFiles::As(FsAs::Person { account, .. }) => {
                assert_eq!(account.name, "nobody");
                assert_ne!(account.uid, 0);
            }
            other => panic!("expected the share account, got {other:?}"),
        }
        // uid 0 is refused by name, even on a root install.
        assert!(refused(decide(Some("root"), Privilege::Root)).contains("not usable"));
        assert!(
            refused(decide(Some("no-such-account-mh"), Privilege::Root)).contains("not usable")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_unprivileged_daemon_serves_only_its_own_account() {
        // As root, `nobody` is another account: an unprivileged install could
        // not take it on, so it is refused, never served as the daemon.
        // SAFETY: reads our own credentials.
        if unsafe { libc::geteuid() } == 65534 {
            return;
        }
        assert!(refused(decide(Some("nobody"), Privilege::Unprivileged)).contains("cannot act as"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_never_takes_a_share_account() {
        for p in [Privilege::Unprivileged, Privilege::WindowsService] {
            assert!(refused(decide(Some("alice"), p)).contains("Linux and macOS"));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_installs_refuse_a_share_account() {
        assert!(refused(decide(Some("alice"), Privilege::Root)).contains("not yet available"));
    }
}
