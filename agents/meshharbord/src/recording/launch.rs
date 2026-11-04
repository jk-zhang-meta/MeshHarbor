// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P1e — who the recorder runs as, and launching it as that.
//!
//! **The identity rule.** Whenever a person is signed in at the device, the
//! recorder runs as THAT person at normal integrity: never SYSTEM, never root,
//! never elevated. A recording is theirs. It goes into their folder, as them,
//! where they can find it and where no one else's rights reach.
//!
//! | This daemon runs as | The recorder runs as |
//! |---|---|
//! | an ordinary user at normal integrity (a per-user install, a user unit) | the same: nothing to change |
//! | an ELEVATED user: the default Windows service worker of a UAC-split administrator (`MESHHARBORD_ELEVATE_WORKER`) | a restricted copy of the same token: admin groups deny-only, no privileges, medium integrity |
//! | SYSTEM, with someone signed in at the console | that person's own token |
//! | root on Linux, with someone signed in at the active graphical session | that person: their uid, gid and groups, in their session's environment |
//! | SYSTEM or Linux root, a screen showing that nobody is signed in to: Windows' sign-in screen, a Linux display manager's greeter or root's own desktop, or (Linux) a display or scanout the recorder could reach with no session registered | refused, by name ([`Refusal::LoginScreen`], decision 6): nobody to record as, and someone may be standing at it |
//! | Linux root with no screen anyone could be at: its own virtual desktop or the synthetic test source, or no active graphical session and no display or DRM scanout the recorder could reach | a REMOTE recording only (P1f, [`Identity::Unattended`]): the daemon itself, into the daemon's own folder, locked to the service side; a local one is refused, by name |
//! | root on macOS | refused, by name: a root daemon there has no WindowServer and can never see the screen. A supervised Mac records in its GUI WORKER instead, which is the person, in their session, with the Screen Recording grant it already captures with (the row above; FR-85 P1e-mac) |
//!
//! ⚠️ **A login screen is not "nobody"** (FR-85 decision 6). It shows account
//! names, a person may be standing at it, and nothing on it can say that a
//! recording runs, so the unattended exception is only for a device with no
//! screen anyone could be at. Windows always has one: the console session
//! shows the sign-in screen whenever nobody is signed in, so a Windows service
//! never records unattended.
//!
//! ⚠️ **A restricted COPY, not the linked token.** An elevated administrator's
//! token links to the filtered one, but without `SeTcbPrivilege` (a worker has
//! none) `TokenLinkedToken` hands back an IDENTIFICATION-level token. That kind
//! can be neither impersonated nor launched with. A restricted token made from
//! this process's OWN token is a child of it, which `CreateProcessAsUserW`
//! accepts without `SeAssignPrimaryTokenPrivilege`.
//!
//! ⚠️ **The daemon touches the folder the way the recorder does.** Listing,
//! downloading and deleting recordings run on a thread that impersonates the
//! same token ([`as_identity`]). The folder is the user's to rearrange. A
//! junction or a hard link planted in it would otherwise be followed with
//! SYSTEM's rights, or the elevated token's, and an elevated reader or deleter
//! in a user-writable folder is exactly the medium-to-high primitive this rule
//! exists to avoid. Impersonated, every open is checked against the user's own
//! rights, wherever the path turns out to lead.
//!
//! ⚠️ **On Linux the same rule, by the thread's filesystem identity.** The
//! daemon's own work in the folder runs with the thread's fsuid, fsgid and
//! supplementary groups switched to the person's ([`unix::FsIdentity`]):
//! Linux checks every open against those, and the root capabilities that
//! would bypass the checks leave the thread's effective set with the fsuid.
//! The groups are switched too, by the raw syscall (glibc's `setgroups`
//! would change every thread of the daemon): without that, root's group 0
//! would still open a `root:root 0640` file a link in the folder pointed at.
//!
//! macOS (P1e-mac) is not a drop: nothing root starts can reach the person's
//! GUI session except through `launchctl asuser` and `sudo -u`, and the
//! supervisor already starts one such process, the GUI worker, which holds
//! the grants. A delegated session's `record` channel opens on the worker's
//! peer, so the worker records, and the daemon only carries the record context
//! across (`delegate::SessionParams::record`) and advertises the worker's
//! `record` caps.

use std::ffi::OsString;
use std::path::Path;

/// Who a recorder launched now would run as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// This daemon's own identity is already an ordinary user at normal
    /// integrity.
    Inherit,
    /// (Windows) A restricted, medium-integrity copy of this daemon's own,
    /// elevated, token.
    RestrictedCopy,
    /// (Windows) The token of the person signed in at console session
    /// `session`. This daemon is SYSTEM.
    ConsoleUser { session: u32 },
    /// (Linux) The account signed in at the active graphical session, by
    /// uid. This daemon is root.
    SessionUser { uid: u32 },
    /// FR-85 P1f — SYSTEM or root with NOBODY signed in: the daemon itself,
    /// for a REMOTE recording only (a local one needs someone at the device
    /// to ask for it), into the daemon's own folder, locked to the service
    /// side ([`crate::recording::folder::unattended_dir`]). Never a person's
    /// folder: a service writing where a user can plant links is exactly
    /// what the identity rule exists to prevent.
    Unattended,
}

/// Why no recorder can be launched here right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Linux root, and no screen anyone could be at: a host running its own
    /// virtual desktop, or one with no active graphical session and no real
    /// screen the recorder could reach (`unix::shows_a_screen`). A REMOTE
    /// recording takes the unattended exception (P1f).
    NoConsoleUser,
    /// FR-85 decision 6 — SYSTEM (or root on Linux), nobody the recorder can
    /// run as is signed in, but a screen is showing: its login screen
    /// (Windows' sign-in screen; on Linux a display manager's greeter or
    /// root's own desktop), or on Linux a display or scanout the recorder
    /// could reach with no session registered for it. Someone may be
    /// standing at it, and nothing on it can say a recording runs, so this
    /// is never "nobody" for the unattended exception: a remote recording is
    /// refused, by this name.
    LoginScreen,
    /// root on macOS: no WindowServer, so no screen. A supervised Mac records
    /// in its GUI worker (P1e-mac); this refusal is the root daemon's own.
    RootDaemon,
    /// `MESHHARBORD_RECORDING=0`: the device's own kill switch.
    SwitchedOff,
}

impl Refusal {
    /// The sentence a client shows (the state's `unavailable_reason`, a
    /// refused start).
    pub fn message(self) -> &'static str {
        match self {
            Self::NoConsoleUser if cfg!(windows) => {
                "this device service runs as SYSTEM and nobody is signed in at its screen: a \
                 recording is made as the person signed in at the device, so there is no one to \
                 record as"
            }
            Self::NoConsoleUser => {
                "this device service runs as root and nobody is signed in at its screen (a \
                 graphical session): a recording is made as the person signed in at the device, \
                 so there is no one to record as"
            }
            Self::LoginScreen if cfg!(windows) => {
                "this device is at its sign-in screen: nobody is signed in to record as, and \
                 someone may be standing at the screen where nothing could say it is being \
                 recorded"
            }
            Self::LoginScreen => {
                "this device shows a screen nobody is signed in to (its login screen, or a \
                 display with no session): someone may be standing at it, nothing on it could say \
                 it is being recorded, and a recording is made as the person signed in"
            }
            Self::RootDaemon => {
                "this device service runs as root, which cannot see the screen on macOS: \
                 recordings are made by its GUI worker, in your own session \
                 (`macos_supervise_gui_worker`), or by `meshharbord record` run in your session"
            }
            Self::SwitchedOff => {
                "recording is switched off on this device (MESHHARBORD_RECORDING=0 in the \
                 service's environment)"
            }
        }
    }
}

/// `MESHHARBORD_RECORDING` switches recording off with `0`, `false`, `off` or
/// `no`, in any case. Anything else, unset included, leaves it on: a
/// misspelt value must not quietly disable a feature someone relies on, and
/// the gates that keep it closed by default are elsewhere.
pub fn switched_off(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        )
    })
}

/// What the decision reads. Split out so its table is a unit test on every
/// platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    pub windows: bool,
    /// Linux: a root daemon can launch the recorder in the signed-in
    /// person's session.
    pub linux: bool,
    /// SYSTEM on Windows, root on unix.
    pub service_account: bool,
    /// (Windows) this process's integrity is above medium.
    pub above_medium: bool,
    /// (Windows, SYSTEM only) the console session, when a person is signed in
    /// there and their token can be had.
    pub console_session: Option<u32>,
    /// (Linux, root only) the uid signed in at the active graphical session:
    /// a person's, never a display manager's greeter.
    pub console_uid: Option<u32>,
    /// (SYSTEM or root only, when nobody the recorder can run as is signed
    /// in) a screen is showing anyway: on Windows always (the console's
    /// sign-in screen); on Linux an active graphical session that is not a
    /// person's (a display manager's greeter, root's own desktop), or a
    /// display or scanout the recorder could reach with no session for it,
    /// never the host's own virtual desktop (`unix::shows_a_screen`). FR-85
    /// decision 6: someone may be standing at it.
    pub login_screen: bool,
}

/// The identity rule, as a table.
pub fn decide_from(f: Facts) -> Result<Identity, Refusal> {
    if f.service_account {
        if f.windows {
            return match f.console_session {
                Some(session) => Ok(Identity::ConsoleUser { session }),
                None if f.login_screen => Err(Refusal::LoginScreen),
                None => Err(Refusal::NoConsoleUser),
            };
        }
        if f.linux {
            return match f.console_uid {
                Some(uid) => Ok(Identity::SessionUser { uid }),
                None if f.login_screen => Err(Refusal::LoginScreen),
                None => Err(Refusal::NoConsoleUser),
            };
        }
        return Err(Refusal::RootDaemon);
    }
    if f.windows && f.above_medium {
        return Ok(Identity::RestrictedCopy);
    }
    Ok(Identity::Inherit)
}

/// Read the facts for THIS process, now (who is signed in may be an answer
/// from the last few seconds; see [`decide_fresh`]).
pub fn facts() -> Facts {
    facts_with(false)
}

/// `fresh`: ask the system who is signed in, never a cached answer. Windows
/// asks every time anyway; Linux caches `loginctl`'s answer for a few
/// seconds unless asked fresh.
fn facts_with(fresh: bool) -> Facts {
    #[cfg(windows)]
    {
        let _ = fresh;
        let service_account = crate::win_identity::process_is_local_system();
        let console_session = if service_account {
            win::signed_in_console_session()
        } else {
            None
        };
        Facts {
            windows: true,
            linux: false,
            service_account,
            above_medium: win::own_integrity_rid().is_none_or(|rid| rid > win::MEDIUM_RID),
            console_session,
            console_uid: None,
            // With nobody signed in, the console shows the sign-in screen: a
            // Windows device always has one (a headless server's console
            // session included). A user token that cannot be had, and the
            // instant the console session is attaching or detaching, read the
            // same: refused, never unattended.
            login_screen: service_account && console_session.is_none(),
        }
    }
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` reads the caller's own credentials; it cannot
        // fail.
        let root = unsafe { libc::geteuid() } == 0;
        #[cfg(target_os = "linux")]
        let seat = if root {
            unix::seat(fresh)
        } else {
            unix::Seat::Empty
        };
        #[cfg(not(target_os = "linux"))]
        let _ = fresh;
        Facts {
            windows: false,
            linux: cfg!(target_os = "linux"),
            service_account: root,
            above_medium: false,
            console_session: None,
            #[cfg(target_os = "linux")]
            console_uid: seat.person(),
            #[cfg(not(target_os = "linux"))]
            console_uid: None,
            // A greeter, or a screen the recorder could reach with no session
            // registered for it; never the host's own virtual desktop, which
            // only a remote controller ever sees (`unix::shows_a_screen`).
            #[cfg(target_os = "linux")]
            login_screen: root && unix::shows_a_screen(seat, unix::Reach::of_this_process()),
            #[cfg(not(target_os = "linux"))]
            login_screen: false,
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = fresh;
        Facts {
            windows: false,
            linux: false,
            service_account: true,
            above_medium: false,
            console_session: None,
            console_uid: None,
            login_screen: false,
        }
    }
}

/// Who a recorder launched now would run as, or why none can be.
pub fn decide() -> Result<Identity, Refusal> {
    decide_from(facts())
}

/// [`decide`], asking the system afresh who is signed in (P1f): the
/// launch-time re-check of an unattended start and the watch over a running
/// one must see a sign-in the moment it happens, never a cached "nobody".
pub fn decide_fresh() -> Result<Identity, Refusal> {
    decide_from(facts_with(true))
}

/// What `meshharbord record --whoami` prints: the identity a recorder actually
/// got, for the tests and for a field question ("what does it run as here?").
pub fn describe_self() -> serde_json::Value {
    #[cfg(windows)]
    {
        serde_json::json!({
            "user": win::own_user_sid(),
            "integrity_rid": win::own_integrity_rid(),
            "admin_enabled": win::admin_group_enabled(),
            "system": crate::win_identity::process_is_local_system(),
        })
    }
    #[cfg(unix)]
    {
        // SAFETY: all read the caller's own credentials; they cannot fail.
        let (uid, euid, gid) = unsafe { (libc::getuid(), libc::geteuid(), libc::getgid()) };
        serde_json::json!({ "uid": uid, "euid": euid, "gid": gid, "groups": own_groups() })
    }
    #[cfg(not(any(windows, unix)))]
    {
        serde_json::json!({})
    }
}

/// A launched recorder: its pipes and its process.
pub struct Launched {
    pub stdin: Option<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>,
    pub stdout: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    pub child: Child,
}

/// The recorder's process, however it was launched.
pub enum Child {
    Tokio(Box<tokio::process::Child>),
    #[cfg(windows)]
    Win(std::sync::Arc<crate::win_service::supervisor::OwnedProcess>),
}

impl Child {
    /// Wait for the process to exit. Cancel-safe: dropping the future leaves
    /// the process alone.
    pub async fn wait(&mut self) {
        match self {
            Self::Tokio(c) => {
                let _ = c.wait().await;
            }
            #[cfg(windows)]
            // Polled rather than a blocking wait, so a caller's timeout never
            // strands a pool thread waiting on a recorder that outlives it.
            Self::Win(p) => loop {
                match p.try_wait() {
                    Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                    _ => return,
                }
            },
        }
    }

    /// Kill the process (a recorder that missed its start deadline).
    pub fn start_kill(&mut self) {
        match self {
            Self::Tokio(c) => {
                let _ = c.start_kill();
            }
            #[cfg(windows)]
            Self::Win(p) => p.terminate(),
        }
    }
}

/// Launch `exe args` as `identity`, with `env` added to its environment,
/// stdin and stdout piped.
pub fn spawn(
    identity: Identity,
    exe: &Path,
    args: &[OsString],
    env: &[(String, String)],
) -> std::io::Result<Launched> {
    match identity {
        // P1f — the unattended recorder is the daemon itself; `--out` points
        // it at the daemon's own locked folder.
        Identity::Inherit | Identity::Unattended => spawn_inherit(exe, args, env),
        #[cfg(windows)]
        Identity::RestrictedCopy | Identity::ConsoleUser { .. } => {
            win::spawn_as(identity, exe, args, env)
        }
        #[cfg(target_os = "linux")]
        Identity::SessionUser { uid } => unix::spawn_session_user(uid, exe, args, env),
        // Windows' identities off Windows, Linux's off Linux.
        _ => Err(std::io::Error::other(
            "that identity is not one this platform launches",
        )),
    }
}

fn spawn_inherit(
    exe: &Path,
    args: &[OsString],
    env: &[(String, String)],
) -> std::io::Result<Launched> {
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(args)
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    launch_piped(cmd)
}

/// Start `cmd` with stdin and stdout piped (stderr into the daemon's own).
fn launch_piped(mut cmd: tokio::process::Command) -> std::io::Result<Launched> {
    use std::process::Stdio;
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(false);
    let mut child = cmd.spawn()?;
    let stdin = child
        .stdin
        .take()
        .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("the recorder has no stdout"))?;
    Ok(Launched {
        stdin,
        stdout: Box::new(stdout),
        child: Child::Tokio(Box::new(child)),
    })
}

/// Run `f` on THIS thread as `identity`, then return to this process's own.
/// Blocking work only: the caller is on a blocking thread (`spawn_blocking`),
/// never an async worker, because the identity belongs to the thread.
///
/// `Inherit` just runs `f`.
pub fn as_identity<R>(identity: Identity, f: impl FnOnce() -> R) -> Result<R, String> {
    match identity {
        Identity::Inherit | Identity::Unattended => Ok(f()),
        #[cfg(windows)]
        Identity::RestrictedCopy | Identity::ConsoleUser { .. } => {
            let token = win::token_for(identity)?;
            let _as_them = win::Impersonating::begin(&token)?;
            Ok(f())
        }
        #[cfg(target_os = "linux")]
        Identity::SessionUser { uid } => {
            let account = unix::Account::by_uid(uid)?;
            let _as_them = unix::FsIdentity::begin(&account)?;
            Ok(f())
        }
        _ => Err("that identity is not one this platform takes on".into()),
    }
}

#[cfg(windows)]
pub(crate) mod win {
    //! The Windows half: the restricted copy, the console user's token, the
    //! launch with a bounded handle list, and impersonation.

    use std::ffi::{OsStr, OsString, c_void};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use std::sync::Arc;

    use windows_sys::Win32::Foundation::{
        GENERIC_ALL, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, TRUE,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, GetLengthSid, ImpersonateLoggedOnUser,
        InitializeAcl, PSID, RevertToSelf, SECURITY_ATTRIBUTES, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
    };

    use super::{Child, Identity, Launched};
    use crate::win_service::supervisor::{self, OwnedProcess};
    // FR-90 P1i-2 — the token identity lives in `crate::win_token` now, which
    // every Windows build has (agent sessions use it too). These are the names
    // this module has always used.
    pub use crate::win_token::{
        MEDIUM_RID, Owned, admin_group_enabled, own_integrity_rid, own_user_sid,
        restricted_medium_copy,
    };
    use crate::win_token::{last_error, well_known_sid};

    /// The console session, when a person is signed in at it and their
    /// token can be had. SYSTEM only: `WTSQueryUserToken` needs `SeTcb`.
    pub fn signed_in_console_session() -> Option<u32> {
        let session = supervisor::active_console_session_id()?;
        match supervisor::query_user_token(session) {
            Ok(Some(_)) => Some(session),
            _ => None,
        }
    }

    /// FR-85 P1f — lock `dir` to the service side: a PROTECTED DACL (nothing
    /// inherited from above, where `%PROGRAMDATA%` grants Users read and
    /// create) holding exactly SYSTEM and Administrators, both inherited by
    /// what the recorder creates inside. An unattended recording is a screen
    /// with nobody at it; only the machine's own side may read it back.
    pub(crate) fn lock_to_service_accounts(dir: &Path) -> Result<(), String> {
        use windows_sys::Win32::Security::{
            AddAccessAllowedAceEx, DACL_SECURITY_INFORMATION, InitializeSecurityDescriptor,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_DESCRIPTOR,
            SetFileSecurityW, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
        };
        const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
        const OBJECT_AND_CONTAINER_INHERIT: u32 = 0x1 | 0x2;
        let mut system = well_known_sid(WinLocalSystemSid)?;
        let mut admins = well_known_sid(WinBuiltinAdministratorsSid)?;
        let (system, admins): (PSID, PSID) =
            (system.as_mut_ptr().cast(), admins.as_mut_ptr().cast());
        // SAFETY: both SIDs are valid; the ACL buffer is sized for exactly the
        // two ACEs and outlives every call that points at it, as does the
        // descriptor.
        unsafe {
            let size = std::mem::size_of::<ACL>() as u32
                + 2 * (std::mem::size_of::<ACCESS_ALLOWED_ACE>() as u32 - 4)
                + GetLengthSid(system)
                + GetLengthSid(admins);
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            let acl = buf.as_mut_ptr() as *mut ACL;
            if InitializeAcl(acl, size, ACL_REVISION) == 0
                || AddAccessAllowedAceEx(
                    acl,
                    ACL_REVISION,
                    OBJECT_AND_CONTAINER_INHERIT,
                    GENERIC_ALL,
                    system,
                ) == 0
                || AddAccessAllowedAceEx(
                    acl,
                    ACL_REVISION,
                    OBJECT_AND_CONTAINER_INHERIT,
                    GENERIC_ALL,
                    admins,
                ) == 0
            {
                return Err(last_error("building the unattended folder's DACL"));
            }
            let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
            let psd = (&mut sd as *mut SECURITY_DESCRIPTOR).cast();
            // The owner too, explicitly: an owner keeps WRITE_DAC whatever the
            // DACL says, so a folder that pre-existed with someone else's
            // ownership would otherwise stay theirs to reopen.
            if InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) == 0
                || SetSecurityDescriptorDacl(psd, 1, acl, 0) == 0
                || SetSecurityDescriptorOwner(psd, admins, 0) == 0
            {
                return Err(last_error("building the unattended folder's descriptor"));
            }
            let path: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
            if SetFileSecurityW(
                path.as_ptr(),
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                psd,
            ) == 0
            {
                return Err(last_error("locking the unattended folder"));
            }
        }
        Ok(())
    }

    /// A token for `identity`: ours restricted, or the console user's.
    pub enum Token {
        Mine(Owned),
        Theirs(supervisor::OwnedHandle),
    }

    impl Token {
        pub fn raw(&self) -> HANDLE {
            match self {
                Self::Mine(t) => t.raw(),
                Self::Theirs(t) => t.raw(),
            }
        }
    }

    pub fn token_for(identity: Identity) -> Result<Token, String> {
        match identity {
            Identity::RestrictedCopy => restricted_medium_copy().map(Token::Mine),
            Identity::ConsoleUser { session } => match supervisor::query_user_token(session) {
                Ok(Some(t)) => Ok(Token::Theirs(t)),
                Ok(None) => Err(format!(
                    "nobody is signed in at console session {session} any more"
                )),
                Err(e) => Err(format!("cannot obtain the console user's token: {e:#}")),
            },
            Identity::Inherit | Identity::Unattended => {
                Err("the daemon's own identity needs no token".into())
            }
            Identity::SessionUser { .. } => Err("a Linux identity has no Windows token".into()),
        }
    }

    /// This thread, impersonating a token until dropped.
    ///
    /// Not `Send`: an identity belongs to the thread that took it on.
    pub struct Impersonating(std::marker::PhantomData<*const ()>);

    impl Impersonating {
        pub fn begin(token: &Token) -> Result<Self, String> {
            // SAFETY: a live primary token with QUERY | DUPLICATE access.
            // Should impersonation be refused, Windows quietly gives the
            // thread an identification-level token instead, and every open
            // then fails: closed, never open.
            if unsafe { ImpersonateLoggedOnUser(token.raw()) } == 0 {
                return Err(last_error("ImpersonateLoggedOnUser"));
            }
            Ok(Self(std::marker::PhantomData))
        }
    }

    impl Drop for Impersonating {
        fn drop(&mut self) {
            // SAFETY: ends this thread's impersonation.
            if unsafe { RevertToSelf() } == 0 {
                // A pool thread left wearing someone else's identity would run
                // whatever it is handed next as the wrong account. There is no
                // safe way to continue; the service manager restarts us.
                std::process::abort();
            }
        }
    }

    /// Append one argument the way the child's own parser (the MSVC CRT
    /// rules, which Rust's `std::env::args` follows) reads it back — the
    /// algorithm `std::process::Command` uses. A display name or a folder is
    /// always ONE argument, whatever quotes or backslashes it holds.
    pub fn append_arg(cmd: &mut Vec<u16>, arg: &OsStr) {
        let quote = arg.is_empty()
            || arg
                .encode_wide()
                .any(|c| c == u16::from(b' ') || c == u16::from(b'\t'));
        if quote {
            cmd.push(u16::from(b'"'));
        }
        let mut backslashes = 0usize;
        for c in arg.encode_wide() {
            if c == u16::from(b'\\') {
                backslashes += 1;
            } else {
                if c == u16::from(b'"') {
                    // n backslashes before a quote become 2n + 1.
                    cmd.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes + 1));
                }
                backslashes = 0;
            }
            cmd.push(c);
        }
        if quote {
            // …and before the closing quote, 2n.
            cmd.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
            cmd.push(u16::from(b'"'));
        }
    }

    /// `"exe" arg arg…`, NUL-terminated.
    pub fn command_line(exe: &Path, args: &[OsString]) -> Vec<u16> {
        let mut cmd = Vec::new();
        // argv[0] follows simpler rules (no escapes), and a path holds no quote.
        cmd.push(u16::from(b'"'));
        cmd.extend(exe.as_os_str().encode_wide());
        cmd.push(u16::from(b'"'));
        for a in args {
            cmd.push(u16::from(b' '));
            append_arg(&mut cmd, a);
        }
        cmd.push(0);
        cmd
    }

    /// The pairs of a `CreateEnvironmentBlock` block.
    ///
    /// # Safety
    /// `block` must be a UTF-16, double-NUL-terminated environment block.
    unsafe fn parse_env_block(block: *const u16) -> Vec<(OsString, OsString)> {
        let mut out = Vec::new();
        let mut p = block;
        loop {
            let mut len = 0usize;
            // SAFETY: forwarded; each entry is NUL-terminated and the block
            // ends with an empty one.
            while unsafe { *p.add(len) } != 0 {
                len += 1;
            }
            if len == 0 {
                break;
            }
            // SAFETY: `len` u16s were just read from `p`.
            let entry = unsafe { std::slice::from_raw_parts(p, len) };
            // `=C:=C:\…` entries (the per-drive directories) start with `=`:
            // the name is up to the SECOND `=`.
            if let Some(eq) = entry.iter().skip(1).position(|c| *c == u16::from(b'=')) {
                let eq = eq + 1;
                out.push((
                    OsString::from_wide(&entry[..eq]),
                    OsString::from_wide(&entry[eq + 1..]),
                ));
            }
            // SAFETY: past this entry's NUL, still inside the block.
            p = unsafe { p.add(len + 1) };
        }
        out
    }

    /// A sorted, double-NUL-terminated block of `base` with `extra` on top
    /// (names compared case-insensitively, as Windows does).
    pub fn env_block(base: Vec<(OsString, OsString)>, extra: &[(String, String)]) -> Vec<u16> {
        let upper = |s: &OsStr| s.to_string_lossy().to_uppercase();
        let mut vars: Vec<(OsString, OsString)> = base
            .into_iter()
            .filter(|(k, _)| !extra.iter().any(|(e, _)| upper(k) == e.to_uppercase()))
            .collect();
        vars.extend(
            extra
                .iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v))),
        );
        vars.sort_by_key(|(k, _)| upper(k));
        let mut block = Vec::new();
        for (k, v) in vars {
            block.extend(k.encode_wide());
            block.push(u16::from(b'='));
            block.extend(v.encode_wide());
            block.push(0);
        }
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        block
    }

    /// An anonymous pipe whose `child` end is inheritable and whose other end
    /// is not. Returns `(read, write)`.
    fn pipe(child_reads: bool) -> std::io::Result<(Owned, Owned)> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: TRUE,
        };
        let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: valid out-params; `sa` outlives the call.
        if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let (r, w) = (Owned(r), Owned(w));
        // Ours must not leak into the child: a child holding our end of its
        // own stdout keeps the pipe open after it exits, and we never see EOF.
        let ours = if child_reads { &w } else { &r };
        // SAFETY: a live handle we own.
        if unsafe { SetHandleInformation(ours.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((r, w))
    }

    /// The recorder's stderr, into this daemon's log (a service has no
    /// stderr of its own to share with it).
    fn forward_stderr(read: Owned) {
        use std::io::BufRead;
        // SAFETY: the handle is ours; the File closes it.
        let file = unsafe { std::fs::File::from_raw_handle(read.into_raw()) };
        for line in std::io::BufReader::new(file).lines() {
            let Ok(line) = line else { break };
            let line: String = line.chars().take(2048).collect();
            tracing::info!(target: "meshharbord::recorder", "{line}");
        }
    }

    /// Launch the recorder with a token: the bounded handle list, our end of
    /// each pipe kept back, the child's ends closed here the moment it has
    /// them.
    pub fn spawn_as(
        identity: Identity,
        exe: &Path,
        args: &[OsString],
        env: &[(String, String)],
    ) -> std::io::Result<Launched> {
        let token = token_for(identity).map_err(std::io::Error::other)?;
        // A console user's own environment (their PATH, USERPROFILE, APPDATA
        // — a SYSTEM daemon's are the wrong ones); a restricted copy is the
        // same user as us, so ours.
        let base = match identity {
            Identity::ConsoleUser { .. } => {
                let block = supervisor::EnvBlock::for_token(token.raw())
                    .map_err(|e| std::io::Error::other(format!("{e:#}")))?;
                // SAFETY: CreateEnvironmentBlock's own block, alive here.
                unsafe { parse_env_block(block.raw as *const u16) }
            }
            _ => std::env::vars_os().collect(),
        };
        let env_w = env_block(base, env);

        let (in_r, in_w) = pipe(true)?;
        let (out_r, out_w) = pipe(false)?;
        let (err_r, err_w) = pipe(false)?;

        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = in_r.raw();
        si.StartupInfo.hStdOutput = out_w.raw();
        si.StartupInfo.hStdError = err_w.raw();

        // ⚠️ Inheritance must be ON for the std handles to reach the child,
        // and ON alone hands it EVERY inheritable handle in this daemon (other
        // children's pipes among them). The list makes it exactly these three.
        let mut inherit: Box<[HANDLE; 3]> = Box::new([in_r.raw(), out_w.raw(), err_w.raw()]);
        let mut bytes: usize = 0;
        // SAFETY: the sizing call is documented to fail with the size out.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes) };
        if bytes == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut attr_buf = vec![0u8; bytes];
        let attrs = attr_buf.as_mut_ptr().cast();
        // SAFETY: the buffer is the size the sizing call asked for.
        if unsafe { InitializeProcThreadAttributeList(attrs, 1, 0, &mut bytes) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        struct Attrs(*mut c_void);
        impl Drop for Attrs {
            fn drop(&mut self) {
                // SAFETY: initialised above, deleted once.
                unsafe { DeleteProcThreadAttributeList(self.0.cast()) };
            }
        }
        let _attrs = Attrs(attrs);
        // SAFETY: `inherit` outlives the CreateProcessAsUserW call below.
        if unsafe {
            UpdateProcThreadAttribute(
                attrs,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherit.as_mut_ptr() as *const c_void,
                std::mem::size_of::<HANDLE>() * 3,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        si.lpAttributeList = attrs;

        // A console user's process belongs on the interactive desktop; a
        // restricted copy stays where this worker is.
        let mut desktop: Vec<u16> = OsStr::new("winsta0\\default")
            .encode_wide()
            .chain(Some(0))
            .collect();
        if matches!(identity, Identity::ConsoleUser { .. }) {
            si.StartupInfo.lpDesktop = desktop.as_mut_ptr();
        }

        let app: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut cmdline = command_line(exe, args);
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every buffer outlives the call; `app` names the program, so
        // the command line's first token is never searched for; the env block
        // is UTF-16 and double-NUL-terminated.
        let ok = unsafe {
            CreateProcessAsUserW(
                token.raw(),
                app.as_ptr(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                TRUE,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                env_w.as_ptr() as *const c_void,
                std::ptr::null(),
                &si.StartupInfo,
                &mut pi,
            )
        };
        if ok == 0 {
            let e = std::io::Error::last_os_error();
            return Err(std::io::Error::new(
                e.kind(),
                format!("CreateProcessAsUserW: {e}"),
            ));
        }
        // The child has its ends; ours go now, or EOF never comes.
        drop((in_r, out_w, err_w));
        std::thread::Builder::new()
            .name("recorder-stderr".into())
            .spawn(move || forward_stderr(err_r))
            .ok();

        // SAFETY: the handles are ours; each File closes its own.
        let stdin = unsafe { std::fs::File::from_raw_handle(in_w.into_raw()) };
        // SAFETY: as above.
        let stdout = unsafe { std::fs::File::from_raw_handle(out_r.into_raw()) };
        Ok(Launched {
            stdin: Some(Box::new(tokio::fs::File::from_std(stdin))),
            stdout: Box::new(tokio::fs::File::from_std(stdout)),
            child: Child::Win(Arc::new(OwnedProcess::from_raw_parts(
                pi.hProcess,
                pi.hThread,
                pi.dwProcessId,
            ))),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::win_token::{integrity_rid, own_token, sid_string, token_info};
        use windows_sys::Win32::Security::{
            TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenUser,
        };

        /// The quoting is checked against Windows's own parser: a controller's
        /// display name or a folder with quotes, backslashes or spaces stays
        /// ONE argument, and nothing in it can become another flag.
        #[test]
        fn every_argument_comes_back_whole() {
            use windows_sys::Win32::Foundation::LocalFree;
            use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
            let cases = [
                "plain",
                "",
                "two words",
                "tab\there",
                "\"",
                "\\",
                "trailing\\",
                "trailing space\\",
                "a\\\\\"b",
                "\\\\server\\share\\",
                "--remote-user-name=Ana \"--out C:\\Windows\" Maria",
                "\" --out C:\\Windows\\System32 \"",
                "Ведран Јовановић",
                "C:\\Users\\a b\\Videos\\MeshHarbor",
            ];
            let args: Vec<OsString> = cases.iter().map(OsString::from).collect();
            let cmd = command_line(Path::new(r"C:\Program Files\MeshHarbor\meshharbord.exe"), &args);
            let mut n = 0i32;
            // SAFETY: a NUL-terminated command line; the array is freed below.
            let argv = unsafe { CommandLineToArgvW(cmd.as_ptr(), &mut n) };
            assert!(!argv.is_null());
            let parsed: Vec<String> = (0..n as usize)
                .map(|i| {
                    // SAFETY: `argv` holds `n` NUL-terminated strings.
                    unsafe {
                        let p = *argv.add(i);
                        let len = (0..).take_while(|&j| *p.add(j) != 0).count();
                        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
                    }
                })
                .collect();
            // SAFETY: the array CommandLineToArgvW allocated.
            unsafe { LocalFree(argv.cast()) };
            assert_eq!(parsed[0], r"C:\Program Files\MeshHarbor\meshharbord.exe");
            assert_eq!(&parsed[1..], &cases[..]);
        }

        /// The token this thread acts with right now — its impersonation
        /// token when it has one — as text: user, integrity, every group
        /// with its attribute bits, every enabled privilege. For a failure
        /// that has to explain itself from a CI log.
        fn effective_token() -> String {
            use windows_sys::Win32::Security::{
                LUID_AND_ATTRIBUTES, LookupPrivilegeNameW, TOKEN_PRIVILEGES, TokenPrivileges,
            };
            use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
            let mut t: HANDLE = std::ptr::null_mut();
            // SAFETY: the pseudo-handle of this thread, a valid out-param.
            let (tok, impersonating) =
                if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut t) } != 0 {
                    (Owned::new(t), true)
                } else {
                    (own_token(TOKEN_QUERY), false)
                };
            let Some(tok) = tok else {
                return "no token".into();
            };
            let user = token_info(tok.raw(), TokenUser)
                // SAFETY: a TOKEN_USER whose SID lives in the buffer.
                .map(|b| sid_string(unsafe { (*(b.as_ptr() as *const TOKEN_USER)).User.Sid }));
            let groups = token_info(tok.raw(), TokenGroups).map(|b| {
                // SAFETY: a TOKEN_GROUPS whose array and SIDs live in `b`.
                unsafe {
                    let g = &*(b.as_ptr() as *const TOKEN_GROUPS);
                    std::slice::from_raw_parts(g.Groups.as_ptr(), g.GroupCount as usize)
                        .iter()
                        .map(|x| format!("{}:{:#x}", sid_string(x.Sid), x.Attributes))
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            });
            let privileges = token_info(tok.raw(), TokenPrivileges).map(|b| {
                // SAFETY: a TOKEN_PRIVILEGES whose array lives in `b`.
                let list: &[LUID_AND_ATTRIBUTES] = unsafe {
                    let p = &*(b.as_ptr() as *const TOKEN_PRIVILEGES);
                    std::slice::from_raw_parts(p.Privileges.as_ptr(), p.PrivilegeCount as usize)
                };
                list.iter()
                    .filter(|p| p.Attributes & 0x2 != 0) // SE_PRIVILEGE_ENABLED
                    .map(|p| {
                        let mut name = [0u16; 128];
                        let mut len = name.len() as u32;
                        // SAFETY: `name` holds `len` u16s.
                        let ok = unsafe {
                            LookupPrivilegeNameW(
                                std::ptr::null(),
                                &p.Luid,
                                name.as_mut_ptr(),
                                &mut len,
                            )
                        };
                        if ok != 0 {
                            String::from_utf16_lossy(&name[..len as usize])
                        } else {
                            format!("luid:{}", p.Luid.LowPart)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            });
            format!(
                "impersonating={impersonating} user={user:?} il={:?} groups=[{}] enabled_privileges=[{}]",
                integrity_rid(tok.raw()),
                groups.unwrap_or_default(),
                privileges.unwrap_or_default(),
            )
        }

        /// Make `dir` a folder ONLY Administrators may touch: owned by them,
        /// one ACE, nothing inherited.
        ///
        /// ⚠️ Built with the Win32 security APIs, not `icacls /inheritance:r
        /// /grant:r`. On GitHub's Windows runner (the built-in Administrator,
        /// UAC off) a new folder under a parent with nothing inheritable
        /// takes the creating token's default DACL as EXPLICIT ACEs — SYSTEM,
        /// Administrators AND the user — so `/inheritance:r` removed nothing,
        /// the user kept Full Control, and the recorder's identity (the same
        /// user) was rightly allowed in. The cell went red for a folder that
        /// was never Administrators-only; this sets the whole descriptor.
        fn lock_to_administrators(dir: &Path) {
            use windows_sys::Win32::Security::{
                AddAccessAllowedAceEx, DACL_SECURITY_INFORMATION, InitializeSecurityDescriptor,
                OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
                SECURITY_DESCRIPTOR, SetFileSecurityW, SetSecurityDescriptorDacl,
                SetSecurityDescriptorOwner,
            };
            const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
            const OBJECT_AND_CONTAINER_INHERIT: u32 = 0x1 | 0x2;
            let mut admins = well_known_sid(WinBuiltinAdministratorsSid).unwrap();
            let sid: PSID = admins.as_mut_ptr().cast();
            // SAFETY: `admins` holds a valid SID; the buffers below are sized
            // for exactly one ACE and outlive every call that points at them.
            unsafe {
                let size = std::mem::size_of::<ACL>() as u32
                    + std::mem::size_of::<ACCESS_ALLOWED_ACE>() as u32
                    - 4
                    + GetLengthSid(sid);
                let mut acl_buf = vec![0u64; (size as usize).div_ceil(8)];
                let acl = acl_buf.as_mut_ptr() as *mut ACL;
                assert_ne!(InitializeAcl(acl, size, ACL_REVISION), 0);
                assert_ne!(
                    AddAccessAllowedAceEx(
                        acl,
                        ACL_REVISION,
                        OBJECT_AND_CONTAINER_INHERIT,
                        GENERIC_ALL,
                        sid
                    ),
                    0
                );
                let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
                let psd = (&mut sd as *mut SECURITY_DESCRIPTOR).cast();
                assert_ne!(
                    InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION),
                    0
                );
                assert_ne!(SetSecurityDescriptorDacl(psd, 1, acl, 0), 0);
                assert_ne!(SetSecurityDescriptorOwner(psd, sid, 0), 0);
                let path: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
                assert_ne!(
                    SetFileSecurityW(
                        path.as_ptr(),
                        OWNER_SECURITY_INFORMATION
                            | DACL_SECURITY_INFORMATION
                            | PROTECTED_DACL_SECURITY_INFORMATION,
                        psd,
                    ),
                    0,
                    "{}",
                    last_error("SetFileSecurityW")
                );
            }
        }

        /// The daemon's work in the person's folder gets only the person's
        /// rights: on an elevated run, a folder only Administrators may write
        /// to takes this process's write and refuses the same write made
        /// through `as_identity(RestrictedCopy, …)` — so a junction from the
        /// recordings folder to such a place reaches nothing. The thread is
        /// itself again afterwards.
        #[test]
        fn work_done_as_the_recorder_gets_only_the_recorders_rights() {
            if admin_group_enabled() != Some(true) {
                // The CI lane runs elevated on purpose; there, skipping
                // would pass without proving anything.
                assert!(
                    std::env::var_os("MESHHARBORD_TEST_REQUIRE_ELEVATED").is_none(),
                    "this lane must run elevated for the refusal to be proven"
                );
                println!("not elevated: there is no higher right to withhold here");
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let locked = dir.path().join("administrators-only");
            std::fs::create_dir(&locked).unwrap();
            lock_to_administrators(&locked);

            let acl = std::process::Command::new("icacls")
                .arg(&locked)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            let outside_token = effective_token();

            std::fs::write(locked.join("as-the-daemon"), b"x")
                .expect("the elevated daemon may write there: the control");
            let (inside, inside_token, write) =
                super::super::as_identity(Identity::RestrictedCopy, || {
                    (
                        admin_group_enabled(),
                        effective_token(),
                        std::fs::write(locked.join("as-the-recorder"), b"x"),
                    )
                })
                .unwrap();
            println!(
                "the folder: {acl}\nthe daemon: {outside_token}\nas the recorder: {inside_token}"
            );
            assert_eq!(
                inside,
                Some(false),
                "the thread did not take the identity on"
            );
            assert!(
                write.is_err(),
                "work done as the recorder wrote into an Administrators-only folder.\n\
                 the folder: {acl}\nthe daemon: {outside_token}\nas the recorder: {inside_token}"
            );
            assert!(!locked.join("as-the-recorder").exists());
            assert_eq!(
                admin_group_enabled(),
                Some(true),
                "the thread is itself again"
            );
        }

        /// FR-85 P1f — the unattended folder is the service side's alone. A
        /// folder under the user's own temp dir (whose ACEs hand the user
        /// full control) is locked by `lock_to_service_accounts`; the
        /// elevated daemon still writes there, and a write made as the
        /// restricted copy (the person, admin deny-only) is refused. Red
        /// without the lock: the user's own ACE lets the copy in.
        #[test]
        fn the_unattended_folder_is_the_service_sides_alone() {
            if admin_group_enabled() != Some(true) {
                assert!(
                    std::env::var_os("MESHHARBORD_TEST_REQUIRE_ELEVATED").is_none(),
                    "this lane must run elevated for the refusal to be proven"
                );
                println!("not elevated: there is no service side to keep a person out for");
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let locked = dir.path().join("unattended");
            std::fs::create_dir(&locked).unwrap();
            super::lock_to_service_accounts(&locked).expect("locking the folder");
            std::fs::write(locked.join("as-the-daemon"), b"x")
                .expect("the service side writes there: the control");
            let write = super::super::as_identity(Identity::RestrictedCopy, || {
                std::fs::write(locked.join("as-a-person"), b"x")
            })
            .unwrap();
            assert!(write.is_err(), "a person wrote into the unattended folder");
            assert!(!locked.join("as-a-person").exists());
        }

        #[test]
        fn extra_variables_replace_their_namesake_whatever_its_case() {
            let base = vec![
                (OsString::from("Path"), OsString::from("C:\\x")),
                (
                    OsString::from("MESHHARBORD_SYNTHETIC_FRAMES"),
                    OsString::from("0"),
                ),
                (OsString::from("=C:"), OsString::from("C:\\")),
            ];
            let block = env_block(base, &[("meshharbord_synthetic_frames".into(), "1".into())]);
            // SAFETY: `env_block` builds a double-NUL-terminated block.
            let back = unsafe { parse_env_block(block.as_ptr()) };
            let get = |k: &str| {
                back.iter()
                    .filter(|(n, _)| n.to_string_lossy().eq_ignore_ascii_case(k))
                    .map(|(_, v)| v.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            };
            assert_eq!(get("MESHHARBORD_SYNTHETIC_FRAMES"), vec!["1".to_string()]);
            assert_eq!(get("PATH"), vec!["C:\\x".to_string()]);
            assert_eq!(get("=C:"), vec!["C:\\".to_string()]);
        }
    }
}

/// This thread's supplementary groups. It lives with the filesystem
/// identity it serves (FR-97 P3d moved both to `crate::fs_identity`).
#[cfg(unix)]
use crate::fs_identity::own_groups;

/// The Linux half: who is signed in at the screen, the launch into their
/// session, and this thread's filesystem identity.
#[cfg(target_os = "linux")]
pub(crate) mod unix {
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::Launched;
    // The account and the thread's filesystem identity: shared with received
    // files since FR-97 P3d (`crate::fs_identity`).
    #[cfg(test)]
    use crate::fs_identity::fsuid;
    pub(crate) use crate::fs_identity::{Account, FsIdentity};

    /// How long an answer to "who is signed in" is reused. The Recordings
    /// view polls the state every second while a recording runs, and each
    /// lookup is several `loginctl` processes; a sign-in or sign-out shows
    /// within this.
    const CONSOLE_TTL: Duration = Duration::from_secs(5);

    /// What logind says about who is at the screen.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Seat {
        /// A person is signed in (`Class=user`, not root): record as them.
        Person(u32),
        /// A graphical session is active and nobody can be recorded as: a
        /// display manager's greeter at the login screen, or root's own
        /// desktop (the recorder never runs as root). Someone may be at it.
        NoPerson,
        /// logind lists no active graphical session. NOT proof that nobody
        /// is at a screen: a display the daemon's environment names, or the
        /// physical scanout, can still be one ([`shows_a_screen`]).
        Empty,
        /// logind could not be asked (no `loginctl`, or it failed). Never
        /// read as [`Seat::Empty`]'s "no session".
        Unknown,
    }

    impl Seat {
        /// The uid to record as, when there is one.
        pub(crate) fn person(self) -> Option<u32> {
            match self {
                Self::Person(uid) => Some(uid),
                Self::NoPerson | Self::Empty | Self::Unknown => None,
            }
        }
    }

    /// What a recorder launched as THIS daemon could capture. An unattended
    /// recorder inherits the daemon's environment, and the capture cascade
    /// opens whatever that names (`capture::open_for_recording`).
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct Reach {
        /// The daemon runs its own virtual desktop: only a remote controller
        /// ever sees that display.
        pub(crate) own_virtual_desktop: bool,
        /// The synthetic test source (a test build with it switched on).
        pub(crate) synthetic: bool,
        /// `DISPLAY` or `WAYLAND_DISPLAY` in the daemon's environment: a
        /// display logind may know nothing about.
        pub(crate) display: bool,
        /// DRM scanout capture is on: the physical screen, whatever runs on
        /// it (a text console, a kiosk, a greeter no session registers).
        pub(crate) drm: bool,
    }

    impl Reach {
        pub(crate) fn of_this_process() -> Self {
            Self {
                own_virtual_desktop: crate::virtual_desktop::requested(),
                synthetic: crate::capture::synthetic_frames_requested(),
                display: std::env::var_os("DISPLAY").is_some()
                    || std::env::var_os("WAYLAND_DISPLAY").is_some(),
                drm: cfg!(feature = "drm-capture") && tunnel_core::env::flag("DRM_CAPTURE", false),
            }
        }
    }

    /// FR-85 decision 6 — with nobody to record as, does a screen show that
    /// someone may be standing at? Then a recording is refused
    /// ([`super::Refusal::LoginScreen`]); only otherwise may the unattended
    /// exception apply.
    ///
    /// A greeter, or root's own desktop, is one. So is a seat logind reports
    /// empty, or cannot be asked about, whenever the recorder could still
    /// reach a real screen: a display named in the daemon's environment, or
    /// the scanout (found in review — "no logind session" is not "no
    /// screen"). The host's own virtual desktop and the synthetic source are
    /// no one's screen, whatever the seat says.
    pub(crate) fn shows_a_screen(seat: Seat, reach: Reach) -> bool {
        match seat {
            Seat::Person(_) => false,
            _ if reach.own_virtual_desktop || reach.synthetic => false,
            Seat::NoPerson => true,
            Seat::Empty | Seat::Unknown => reach.display || reach.drm,
        }
    }

    /// The last answer to "who is signed in", and when it was had.
    pub(super) struct ConsoleCache(Mutex<Option<(Instant, Seat)>>);

    impl ConsoleCache {
        pub(super) const fn new() -> Self {
            Self(Mutex::new(None))
        }

        /// `lookup`'s answer, reused for [`CONSOLE_TTL`] unless `fresh`.
        ///
        /// ⚠️ P1f's guards pass `fresh`: the re-check before an unattended
        /// recorder launches, and the watch while one runs. A cached "nobody"
        /// read twice within a few milliseconds is ONE observation, so a
        /// person who signed in inside the window would be recorded with no
        /// banner (found in review: the re-check was a no-op on the cache).
        pub(super) fn get(&self, fresh: bool, lookup: impl FnOnce() -> Seat) -> Seat {
            let mut cached = self.0.lock().unwrap_or_else(|p| p.into_inner());
            if !fresh
                && let Some((at, seat)) = *cached
                && at.elapsed() < CONSOLE_TTL
            {
                return seat;
            }
            let seat = lookup();
            *cached = Some((Instant::now(), seat));
            seat
        }
    }

    static CONSOLE: ConsoleCache = ConsoleCache::new();

    /// Who is at the active graphical session. A person is a `Class=user`
    /// session, never a display manager's greeter, and uid 0 is no person:
    /// the recorder never runs as root. `fresh` asks the system now,
    /// whatever was asked a moment ago.
    ///
    /// ⚠️ FR-85 decision 6: a greeter is NOT an empty seat. Both mean
    /// "nobody to record as", but only an empty one can mean nobody is
    /// looking ([`shows_a_screen`] decides, with what the recorder could
    /// reach).
    pub(super) fn seat(fresh: bool) -> Seat {
        CONSOLE.get(fresh, || {
            let person = crate::companion::graphical_session_matching(None, true)
                .ok()
                .map(|s| s.uid);
            classify(person, any_graphical_session)
        })
    }

    /// The pure half of [`seat`]: `person` is the uid at the active
    /// `Class=user` session, if one is; `any_active` asks whether ANY
    /// graphical session is active (a greeter's included), and is asked only
    /// when no person was found. An `Err` from it is [`Seat::Unknown`].
    pub(super) fn classify(
        person: Option<u32>,
        any_active: impl FnOnce() -> anyhow::Result<bool>,
    ) -> Seat {
        match person {
            Some(uid) if uid != 0 => Seat::Person(uid),
            _ => match any_active() {
                Ok(true) => Seat::NoPerson,
                Ok(false) => Seat::Empty,
                Err(_) => Seat::Unknown,
            },
        }
    }

    /// Is ANY graphical session active, a greeter's or root's included? Only
    /// `Type` and `Active` count: the person walk also needs a `Name` and a
    /// parseable `User`, and a session it skips for want of one is still a
    /// screen someone may be at. `Err` when `loginctl` could not be asked at
    /// all, which is never "no session" (found in review: both folded into
    /// one `Err` before, and read as an empty seat).
    fn any_graphical_session() -> anyhow::Result<bool> {
        use anyhow::Context as _;
        let list = std::process::Command::new("loginctl")
            .args(["list-sessions", "--no-legend", "--no-pager"])
            .output()
            .context("spawning loginctl")?;
        anyhow::ensure!(
            list.status.success(),
            "loginctl list-sessions: {}",
            list.status
        );
        Ok(any_active_in(
            &String::from_utf8_lossy(&list.stdout),
            |id| {
                std::process::Command::new("loginctl")
                    .args([
                        "show-session",
                        id,
                        "--no-pager",
                        "-p",
                        "Type",
                        "-p",
                        "Active",
                    ])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            },
        ))
    }

    /// The pure half of [`any_graphical_session`]. `list` is `loginctl
    /// list-sessions --no-legend`, of which only the first column is read
    /// (its other columns move between systemd releases; `companion` reads
    /// it the same way); `show` is one session's `Type=`/`Active=` lines, or
    /// `None` for a session that went away between the two asks.
    pub(super) fn any_active_in(list: &str, show: impl Fn(&str) -> Option<String>) -> bool {
        list.lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter_map(show)
            .any(|props| {
                let field = |k: &str| {
                    props
                        .lines()
                        .find_map(|l| l.trim().strip_prefix(k)?.strip_prefix('='))
                        .map(str::trim)
                };
                matches!(field("Type"), Some("x11" | "wayland")) && field("Active") == Some("yes")
            })
    }

    /// Launch the recorder in the session signed in as `uid`: the variables
    /// that put a process in that session, then the one privilege drop
    /// (`exec::drop_to_std`: groups, then gid, then uid, verified).
    pub(super) fn spawn_session_user(
        uid: u32,
        exe: &Path,
        args: &[OsString],
        env: &[(String, String)],
    ) -> std::io::Result<Launched> {
        let session =
            crate::companion::graphical_session_matching(Some(uid), true).map_err(|e| {
                std::io::Error::other(format!("the session signed in as uid {uid}: {e:#}"))
            })?;
        // The two a session is made of (the uid drop is what makes them
        // usable: the runtime dir is 0700, the bus checks `SO_PEERCRED`),
        // the display, and the X cookie without which an X11 capture gets
        // `Authorization required`.
        let mut session_env = vec![
            ("XDG_RUNTIME_DIR".to_string(), format!("/run/user/{uid}")),
            (
                "DBUS_SESSION_BUS_ADDRESS".to_string(),
                format!("unix:path=/run/user/{uid}/bus"),
            ),
        ];
        if let Some(d) = session.display {
            session_env.push(("DISPLAY".to_string(), d));
        }
        if let Some(w) = session.wayland_display {
            session_env.push(("WAYLAND_DISPLAY".to_string(), w));
        }
        if let Some(xa) = crate::apps::find_xauthority(uid) {
            session_env.push(("XAUTHORITY".to_string(), xa.to_string_lossy().into_owned()));
        }
        spawn_as_account(&session.name, &session_env, exe, args, env)
    }

    /// The launch itself, apart from the session lookup, so a test can run
    /// it as an account that has no session (`nobody`).
    pub(super) fn spawn_as_account(
        account: &str,
        session_env: &[(String, String)],
        exe: &Path,
        args: &[OsString],
        env: &[(String, String)],
    ) -> std::io::Result<Launched> {
        let mut cmd = std::process::Command::new(exe);
        cmd.args(args)
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .envs(session_env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        crate::exec::drop_to_std(&mut cmd, account).map_err(std::io::Error::other)?;
        super::launch_piped(tokio::process::Command::from(cmd))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        /// These need root. Skipped elsewhere, unless the privileged lane
        /// says root is required, and then an unprivileged run FAILS rather
        /// than passing by skipping.
        fn root() -> bool {
            // SAFETY: reads our own credentials.
            let root = unsafe { libc::geteuid() } == 0;
            if !root && std::env::var_os("MESHHARBORD_TEST_REQUIRE_ROOT").is_some() {
                panic!("MESHHARBORD_TEST_REQUIRE_ROOT is set and this test is not running as root");
            }
            root
        }

        fn nobody() -> Account {
            Account::by_name("nobody").expect("the `nobody` account")
        }

        /// Work done as the person gets only the person's rights: a folder
        /// only root may write is refused, a `root:root 0640` file only
        /// root's group may read is refused (red without the per-thread
        /// groups: root's group 0 reads it), and afterwards the thread is
        /// root again.
        #[test]
        fn work_done_as_the_person_gets_only_the_persons_rights() {
            if !root() {
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            // A file only group root may read, in a folder anyone may enter.
            let open = tempfile::tempdir().unwrap();
            std::fs::set_permissions(open.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let grouped = open.path().join("grouped");
            std::fs::write(&grouped, b"group root's").unwrap();
            std::fs::set_permissions(&grouped, std::fs::Permissions::from_mode(0o640)).unwrap();

            // The control: root writes one and reads the other.
            std::fs::write(dir.path().join("as-root"), b"x").unwrap();
            std::fs::read(&grouped).unwrap();

            let person = nobody();
            let (write, read) = {
                let _as_them = FsIdentity::begin(&person).expect("taking on nobody");
                (
                    std::fs::write(dir.path().join("as-nobody"), b"x"),
                    std::fs::read(&grouped),
                )
            };
            let write = write.expect_err("nobody wrote into a folder only root may write");
            assert_eq!(
                write.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{write}"
            );
            let read = read.expect_err("nobody read a file only root's group may read");
            assert_eq!(read.kind(), std::io::ErrorKind::PermissionDenied, "{read}");

            // And the thread is root again: the same write goes through.
            assert_eq!(fsuid(), 0);
            std::fs::write(dir.path().join("root-again"), b"x")
                .expect("the thread is root again after the guard");
        }

        /// The recorder launched as the person IS the person: their uid, not
        /// root's, and none of root's groups (`id` reports what the child got).
        #[test]
        fn the_launch_runs_as_the_person_with_the_persons_groups() {
            if !root() {
                return;
            }
            let person = nobody();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let out = rt.block_on(async {
                use tokio::io::AsyncReadExt;
                let mut l = spawn_as_account(&person.name, &[], Path::new("/usr/bin/id"), &[], &[])
                    .expect("launch as nobody");
                drop(l.stdin.take());
                let mut out = String::new();
                l.stdout.read_to_string(&mut out).await.unwrap();
                l.child.wait().await;
                out
            });
            let uid = format!("uid={}(", person.uid);
            assert!(out.contains(&uid), "not nobody: {out}");
            assert!(
                !out.contains("(root)"),
                "a root group survived the drop: {out}"
            );
        }

        #[test]
        fn root_is_never_the_account_a_session_resolves_to() {
            assert!(Account::by_uid(0).is_err());
        }

        /// P1f's guards ask FRESH. Inside its window a cached "nobody" is
        /// still the answer after someone signed in; a fresh ask goes to the
        /// system, sees them, and refreshes the cache. Red when `fresh` is
        /// ignored: the launch re-check and the running watch would read the
        /// same stale "nobody" and record the person with no banner.
        #[test]
        fn a_fresh_ask_sees_a_sign_in_the_cache_would_hide() {
            let cache = ConsoleCache::new();
            assert_eq!(
                cache.get(false, || Seat::NoPerson),
                Seat::NoPerson,
                "nobody signed in"
            );
            assert_eq!(
                cache.get(false, || Seat::Person(1000)),
                Seat::NoPerson,
                "inside the window the cached answer stands"
            );
            assert_eq!(cache.get(true, || Seat::Person(1000)), Seat::Person(1000));
            assert_eq!(
                cache.get(false, || Seat::Empty),
                Seat::Person(1000),
                "the fresh answer refreshed the cache"
            );
        }

        #[test]
        fn only_a_person_is_someone_to_record_as() {
            assert_eq!(Seat::Person(1000).person(), Some(1000));
            assert_eq!(Seat::NoPerson.person(), None);
            assert_eq!(Seat::Empty.person(), None);
            assert_eq!(Seat::Unknown.person(), None);
        }

        /// FR-85 decision 6: a greeter, and root's own desktop, are a login
        /// screen — someone may be at them — distinct from no active
        /// graphical session, and a logind that cannot be asked is neither.
        /// Red when the second walk is skipped (a greeter reads as nobody),
        /// or when its failure reads as "no session".
        #[test]
        fn a_greeter_is_a_login_screen_not_an_empty_seat() {
            // A person: no second walk.
            assert_eq!(
                classify(Some(1000), || panic!(
                    "asked for any session with a person found"
                )),
                Seat::Person(1000)
            );
            // A greeter at the login screen: no `Class=user` session, one active.
            assert_eq!(classify(None, || Ok(true)), Seat::NoPerson);
            // root's own desktop: never recorded as, and someone is at it.
            assert_eq!(classify(Some(0), || Ok(true)), Seat::NoPerson);
            // logind answers: no active graphical session.
            assert_eq!(classify(None, || Ok(false)), Seat::Empty);
            // logind could not be asked: not "no session".
            assert_eq!(
                classify(None, || Err(anyhow::anyhow!("spawning loginctl"))),
                Seat::Unknown
            );
        }

        /// The second walk counts any ACTIVE graphical session, whoever's,
        /// from `loginctl`'s own output (its layout per systemd 255/257):
        /// only `Type` and `Active` decide. Red when a greeter's session is
        /// filtered out, or a text console or an inactive session counts.
        #[test]
        fn any_active_graphical_session_counts_whoevers_it_is() {
            let list = "c1  128 gdm     seat0 tty1 active no -\n\
                        3  1000 alice   seat0 tty2 online no -\n\
                        7     0 root          pts/0 active no -\n";
            let props = |c1: &'static str, s3: &'static str, s7: &'static str| {
                move |id: &str| match id {
                    "c1" => Some(c1.to_string()),
                    "3" => Some(s3.to_string()),
                    "7" => Some(s7.to_string()),
                    _ => None,
                }
            };
            // The greeter is the active graphical session.
            assert!(any_active_in(
                list,
                props(
                    "Type=x11\nActive=yes\n",
                    "Type=wayland\nActive=no\n",
                    "Type=tty\nActive=yes\n"
                )
            ));
            // A Wayland greeter too.
            assert!(any_active_in(
                list,
                props(
                    "Type=wayland\nActive=yes\n",
                    "Type=wayland\nActive=no\n",
                    "Type=tty\nActive=yes\n"
                )
            ));
            // Only an inactive desktop and an active text console: none.
            assert!(!any_active_in(
                list,
                props(
                    "Type=x11\nActive=no\n",
                    "Type=wayland\nActive=no\n",
                    "Type=tty\nActive=yes\n"
                )
            ));
            // Sessions gone between the two asks, and an empty list: none.
            assert!(!any_active_in(list, |_| None));
            assert!(!any_active_in("", |_| panic!("no session to ask about")));
        }

        /// FR-85 decision 6 — the refusal's whole table. A greeter refuses
        /// whatever the recorder could reach; an empty or unknown seat
        /// refuses when a real screen is reachable anyway (review: "no
        /// logind session" is not "no screen" under DRM, or with a DISPLAY
        /// inherited from someone's session); the host's own virtual
        /// desktop and the synthetic source never refuse. Red, each on its
        /// own: the reach ignored (DISPLAY and DRM record unattended), the
        /// virtual desktop not recognised (every greeter host refused), an
        /// unknown seat read as empty-with-nothing-reachable.
        #[test]
        fn a_screen_someone_may_be_at_refuses_and_no_ones_does_not() {
            let none = Reach::default();
            let display = Reach {
                display: true,
                ..none
            };
            let drm = Reach { drm: true, ..none };
            let own = Reach {
                own_virtual_desktop: true,
                display: true,
                ..none
            };
            let synthetic = Reach {
                synthetic: true,
                ..none
            };
            // Someone signed in: recorded as them, never refused here.
            for r in [none, display, drm, own, synthetic] {
                assert!(!shows_a_screen(Seat::Person(1000), r), "{r:?}");
            }
            // A greeter or root's desktop: refused, unless no one's screen.
            for r in [none, display, drm] {
                assert!(shows_a_screen(Seat::NoPerson, r), "{r:?}");
            }
            // No session, or none knowable: refused when a screen is reachable.
            for seat in [Seat::Empty, Seat::Unknown] {
                assert!(!shows_a_screen(seat, none), "{seat:?}: nothing to capture");
                assert!(shows_a_screen(seat, display), "{seat:?} with a DISPLAY");
                assert!(shows_a_screen(seat, drm), "{seat:?} with DRM");
            }
            // The host's own virtual desktop and the synthetic source.
            for seat in [Seat::NoPerson, Seat::Empty, Seat::Unknown] {
                assert!(!shows_a_screen(seat, own), "{seat:?}");
                assert!(!shows_a_screen(seat, synthetic), "{seat:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(windows: bool, service: bool, high: bool, console: Option<u32>) -> Facts {
        Facts {
            windows,
            linux: false,
            service_account: service,
            above_medium: high,
            console_session: console,
            console_uid: None,
            login_screen: false,
        }
    }

    /// Linux: `console` is the uid at the active graphical session.
    fn linux(root: bool, console: Option<u32>) -> Facts {
        Facts {
            windows: false,
            linux: true,
            service_account: root,
            above_medium: false,
            console_session: None,
            console_uid: console,
            login_screen: false,
        }
    }

    /// The same facts, at a login screen.
    fn at_login(f: Facts) -> Facts {
        Facts {
            login_screen: true,
            ..f
        }
    }

    #[test]
    fn the_identity_rule_as_a_table() {
        // An ordinary user: nothing to change.
        assert_eq!(
            decide_from(f(true, false, false, None)),
            Ok(Identity::Inherit)
        );
        assert_eq!(
            decide_from(f(false, false, false, None)),
            Ok(Identity::Inherit)
        );
        // An elevated worker: never records elevated.
        assert_eq!(
            decide_from(f(true, false, true, None)),
            Ok(Identity::RestrictedCopy)
        );
        // SYSTEM with someone at the console: as them.
        assert_eq!(
            decide_from(f(true, true, true, Some(3))),
            Ok(Identity::ConsoleUser { session: 3 })
        );
        // SYSTEM with nobody: refused, never "as SYSTEM".
        assert_eq!(
            decide_from(f(true, true, true, None)),
            Err(Refusal::NoConsoleUser)
        );
        // root on macOS: refused until the drop exists there.
        assert_eq!(
            decide_from(f(false, true, false, None)),
            Err(Refusal::RootDaemon)
        );
        // root on Linux with someone at the screen: as them.
        assert_eq!(
            decide_from(linux(true, Some(1000))),
            Ok(Identity::SessionUser { uid: 1000 })
        );
        // root on Linux with nobody: refused, never "as root".
        assert_eq!(decide_from(linux(true, None)), Err(Refusal::NoConsoleUser));
        // An ordinary Linux user (a user unit): nothing to change, whoever
        // else is signed in.
        assert_eq!(decide_from(linux(false, Some(1000))), Ok(Identity::Inherit));
    }

    /// FR-85 decision 6: a login screen is not an empty seat. Nobody is
    /// signed in to record as, but someone may be standing at it, so the
    /// refusal is its own — the one the unattended exception never covers.
    /// Red when `login_screen` is ignored: both read `NoConsoleUser`, and a
    /// remote recording starts at a greeter with no banner anywhere.
    #[test]
    fn a_login_screen_is_not_nobody() {
        // SYSTEM, a console session with nobody signed in at it.
        assert_eq!(
            decide_from(at_login(f(true, true, true, None))),
            Err(Refusal::LoginScreen)
        );
        // root, a greeter (or root's own desktop) at the active session.
        assert_eq!(
            decide_from(at_login(linux(true, None))),
            Err(Refusal::LoginScreen)
        );
        // Someone signed in wins, whatever else is on the console.
        assert_eq!(
            decide_from(at_login(f(true, true, true, Some(3)))),
            Ok(Identity::ConsoleUser { session: 3 })
        );
        assert_eq!(
            decide_from(at_login(linux(true, Some(1000)))),
            Ok(Identity::SessionUser { uid: 1000 })
        );
        // An identity that is not the service's never asks.
        assert_eq!(
            decide_from(at_login(f(true, false, false, None))),
            Ok(Identity::Inherit)
        );
        assert_eq!(
            decide_from(at_login(linux(false, None))),
            Ok(Identity::Inherit)
        );
        // The message says what is on the screen, not who the service is.
        let m = Refusal::LoginScreen.message();
        assert!(
            m.contains("sign-in screen") || m.contains("login screen"),
            "{m}"
        );
        assert_ne!(Refusal::LoginScreen, Refusal::NoConsoleUser);
    }

    /// The refusal a Linux root daemon gives names root, not SYSTEM.
    #[test]
    fn a_refusal_names_the_account_this_service_runs_as() {
        let m = Refusal::NoConsoleUser.message();
        assert!(m.contains("this device service runs as"), "{m}");
        if cfg!(windows) {
            assert!(m.contains("SYSTEM"), "{m}");
        } else {
            assert!(m.contains("root") && !m.contains("SYSTEM"), "{m}");
        }
    }

    #[test]
    fn the_kill_switch_reads_only_an_explicit_off() {
        for off in ["0", "false", "OFF", " no ", "False"] {
            assert!(switched_off(Some(off)), "{off:?}");
        }
        // Unset, empty, on, or a typo: recording stays as its gates say.
        for on in [
            None,
            Some(""),
            Some("1"),
            Some("true"),
            Some("of"),
            Some("disable"),
        ] {
            assert!(!switched_off(on), "{on:?}");
        }
    }

    /// A test run is an ordinary account or an elevated one, never SYSTEM
    /// or (outside a container) root; the probe must read it as such.
    #[test]
    fn this_process_is_not_refused() {
        #[cfg(unix)]
        // SAFETY: reads our own credentials.
        if unsafe { libc::geteuid() } == 0 {
            return; // a root container: the refusal is right
        }
        assert!(decide().is_ok(), "{:?}", facts());
    }
}
