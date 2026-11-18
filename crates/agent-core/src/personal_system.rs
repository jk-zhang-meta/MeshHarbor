// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Personal account login -> default machine-level (`root` / `SYSTEM`) promotion.
//!
//! Shared by `meshharbord` (`mh login`) and `meshharbor-desktop` (`Sign In`) so
//! both surfaces promote an auto-enrolled personal device to Administrator /
//! `root` privileges through one hardened `enroll-personal-system` handoff:
//! - Enrollment tokens NEVER appear on CLI `argv` or environment variables.
//! - Request and status files are created with `create_new(true)` (`0600` on
//!   Unix) inside the caller's private config directory and removed on `Drop`.
//! - The elevated helper rejects symlink/junction components along the path,
//!   opens both files without following symlinks/reparse points (`O_NOFOLLOW` +
//!   `fstat` regular-file `nlink == 1` on Unix; `FILE_FLAG_OPEN_REPARSE_POINT`
//!   + `share_mode(0)` + `GetFileInformationByHandle` non-reparse disk file
//!   `nNumberOfLinks == 1` on Windows), overwrites + truncates + fsyncs the
//!   request file on disk (failing closed on any scrub error) BEFORE parsing or
//!   network I/O, and NEVER creates or unlinks paths inside unprivileged user
//!   directories.

use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Maximum serialized `SystemEnrollRequest` payload accepted by the elevated
/// helper (512 KiB — ~60x headroom for `seed_config_toml` + invitation state).
pub const MAX_REQUEST_BYTES: u64 = 512 * 1024;

/// Maximum diagnostic message written back to the pre-created status file.
const MAX_STATUS_BYTES: usize = 8 * 1024;

/// Unix canonical root config path.
pub const UNIX_SYSTEM_CONFIG_PATH: &str = "/etc/meshharbor/config.toml";

/// One-shot promotion payload passed from an unprivileged `mh login` or
/// `meshharbor-desktop` session to `meshharbord enroll-personal-system`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEnrollRequest {
    pub server_url: String,
    pub enrollment_token: String,
    pub device_name: String,
    #[serde(default)]
    pub replace: bool,
    #[serde(default)]
    pub calling_uid: Option<u32>,
    /// Windows: the unprivileged caller's own account SID (`S-1-5-21-…`). The
    /// elevated step grants exactly this account READ on the system config it
    /// locks down, so the person's own desktop app keeps working after the
    /// promotion; it held the same credential in its per-user config before.
    /// `None` from an older caller: administrators-only, as before.
    #[serde(default)]
    pub calling_sid: Option<String>,
    /// Existing per-user `config.toml` snapshot captured by the unprivileged
    /// caller before elevation, merged into `/etc/meshharbor/config.toml` or
    /// `%PROGRAMDATA%\meshharbor\meshharbor\config.toml` so `machine_id`,
    /// WireGuard keys, secondary orgs, and SIAT invitations survive promotion
    /// without root/SYSTEM touching user-owned directories.
    #[serde(default)]
    pub seed_config_toml: Option<String>,
    #[serde(default)]
    pub seed_temporary_json: Option<String>,
    #[serde(default)]
    pub seed_history_json: Option<String>,
}

fn read_optional_utf8(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

impl SystemEnrollRequest {
    /// Build a promotion request, snapshotting any existing non-system user
    /// config and SIAT invitation sidecars from `user_config_path` in the
    /// caller's own unprivileged context. Fails closed if an existing user
    /// config or sidecar cannot be read, preventing post-promotion retirement
    /// from ever deleting unread credentials.
    pub fn from_user_config_path(
        server_url: String,
        enrollment_token: String,
        device_name: String,
        replace: bool,
        user_config_path: Option<&Path>,
    ) -> std::io::Result<Self> {
        #[cfg(unix)]
        // SAFETY: libc::geteuid has no preconditions.
        let calling_uid = Some(unsafe { libc::geteuid() });
        #[cfg(not(unix))]
        let calling_uid = None;
        let calling_sid = own_user_sid().filter(|s| is_user_account_sid(s));

        let mut seed_config_toml = None;
        let mut seed_temporary_json = None;
        let mut seed_history_json = None;

        if let Some(p) = user_config_path.filter(|p| !is_system_config_path(p)) {
            seed_config_toml = read_optional_utf8(p)?;
            seed_temporary_json = read_optional_utf8(&crate::device_invite::marker_path(p))?;
            seed_history_json = read_optional_utf8(&crate::device_invite::history_path(p))?;
        }

        Ok(Self {
            server_url,
            enrollment_token,
            device_name,
            replace,
            calling_uid,
            calling_sid,
            seed_config_toml,
            seed_temporary_json,
            seed_history_json,
        })
    }
}

/// A local or domain ACCOUNT SID (`S-1-5-21-<a>-<b>-<c>-<rid>`), never a
/// well-known group such as Everyone or Users. It is spliced into an SDDL
/// string, so only this exact digits-and-dashes shape is accepted.
pub fn is_user_account_sid(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("S-1-5-21-") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// This process's own account SID string. `None` off Windows or on failure.
pub fn own_user_sid() -> Option<String> {
    #[cfg(windows)]
    {
        win_sid::own_sid().ok()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
mod win_sid {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub(super) fn own_sid() -> Result<String, String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the current-process pseudo handle; `token` receives a handle closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(format!(
                "OpenProcessToken: {}",
                std::io::Error::last_os_error()
            ));
        }
        let out = sid_of_token(token);
        // SAFETY: the handle OpenProcessToken returned, closed once.
        unsafe { CloseHandle(token) };
        out
    }

    fn sid_of_token(token: HANDLE) -> Result<String, String> {
        let mut len: u32 = 0;
        // SAFETY: the documented size query: no buffer, the size written to `len`.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(format!(
                "GetTokenInformation(TokenUser): {}",
                std::io::Error::last_os_error()
            ));
        }
        // In u64s so the TOKEN_USER (which holds a pointer) is aligned.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `len` bytes and outlives the call.
        if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
            == 0
        {
            return Err(format!(
                "GetTokenInformation(TokenUser): {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: a TOKEN_USER whose SID points into `buf`, alive below.
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
        let n = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        // SAFETY: `n` units were just read from `text`.
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, n) });
        // SAFETY: the one allocation ConvertSidToStringSidW made, freed once.
        unsafe { LocalFree(text as _) };
        Ok(s)
    }
}

/// Whether `path` already points at the machine-wide system config file.
pub fn is_system_config_path(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let mg = crate::config::machine_global_config_path();
        path.to_string_lossy()
            .replace('/', "\\")
            .eq_ignore_ascii_case(&mg.to_string_lossy().replace('/', "\\"))
    }
    #[cfg(not(windows))]
    {
        path == Path::new(UNIX_SYSTEM_CONFIG_PATH)
    }
}

/// Remove migrated per-user config & invitation sidecars in the unprivileged
/// caller's own context AFTER system promotion has succeeded, preventing
/// split-brain between stale per-user files and the live root/SYSTEM daemon.
pub fn retire_migrated_user_config(user_config_path: &Path) {
    if is_system_config_path(user_config_path) {
        return;
    }
    let _ = std::fs::remove_file(user_config_path);
    let _ = std::fs::remove_file(user_config_path.with_extension("toml.prev"));
    let _ = std::fs::remove_file(crate::device_invite::marker_path(user_config_path));
    let _ = std::fs::remove_file(crate::device_invite::history_path(user_config_path));
}

/// Whether the current process already runs as `root` (Unix) or an elevated
/// Administrator / `LocalSystem` token (Windows).
pub fn is_process_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: libc::geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            let _ = CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
}

/// Whether `group_name` grants administrative / `sudo` elevation capability
/// on macOS (`is_macos == true`) or Linux/other Unix (`is_macos == false`).
pub fn is_unix_admin_group_name(is_macos: bool, group_name: &str) -> bool {
    if is_macos {
        matches!(group_name, "admin" | "wheel")
    } else {
        matches!(group_name, "sudo" | "wheel" | "admin" | "root")
    }
}

/// Whether the OS account running this process possesses Administrator / `root`
/// / `sudo` capability and therefore MUST be required to authorize system-level
/// promotion (returning `false` only for genuinely unprivileged standard user
/// accounts that should enroll directly in per-user mode).
pub fn can_current_user_elevate() -> bool {
    if is_process_elevated() {
        return true;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, TOKEN_ELEVATION_TYPE,
            TOKEN_QUERY, TokenElevationType, TokenElevationTypeFull, TokenElevationTypeLimited,
            WinBuiltinAdministratorsSid,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0 {
                let mut etype: TOKEN_ELEVATION_TYPE = 0;
                let mut returned: u32 = 0;
                let ok = GetTokenInformation(
                    token,
                    TokenElevationType,
                    (&mut etype as *mut TOKEN_ELEVATION_TYPE).cast(),
                    std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
                    &mut returned,
                );
                let _ = CloseHandle(token);
                if ok != 0
                    && (etype == TokenElevationTypeFull || etype == TokenElevationTypeLimited)
                {
                    return true;
                }
            }

            // Also cover UAC-disabled (`EnableLUA=0`) Administrator tokens where
            // `TokenElevationType` is `TokenElevationTypeDefault`.
            let mut sid = [0u8; 68];
            let mut sid_len = sid.len() as u32;
            let mut member: i32 = 0;
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut sid_len,
            ) != 0
                && CheckTokenMembership(std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut member)
                    != 0
                && member != 0
        }
    }
    #[cfg(unix)]
    {
        if std::process::Command::new("sudo")
            .args(["-n", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            return true;
        }
        unix_current_user_in_admin_group()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(unix)]
fn unix_current_user_in_admin_group() -> bool {
    let is_macos = cfg!(target_os = "macos");
    // SAFETY: getgid/getegid/getgroups read process credentials.
    let mut gids = unsafe {
        let mut v = vec![libc::getgid(), libc::getegid()];
        let count = libc::getgroups(0, std::ptr::null_mut());
        if count > 0 {
            let mut supp = vec![0 as libc::gid_t; count as usize];
            let got = libc::getgroups(count, supp.as_mut_ptr());
            if got > 0 {
                supp.truncate(got as usize);
                v.extend(supp);
            }
        }
        v
    };
    gids.sort_unstable();
    gids.dedup();
    for gid in gids {
        if let Some(name) = unix_group_name_by_gid(gid)
            && is_unix_admin_group_name(is_macos, &name)
        {
            return true;
        }
    }

    // Also inspect `/etc/group` / DirectoryService member lists for the
    // current UID so a newly added group membership takes effect immediately.
    let uid = unsafe { libc::getuid() };
    if let Some((username, pw_gid)) = unix_passwd_name_and_gid(uid) {
        if let Some(primary_group) = unix_group_name_by_gid(pw_gid)
            && is_unix_admin_group_name(is_macos, &primary_group)
        {
            return true;
        }
        let candidates: &[&str] = if is_macos {
            &["admin", "wheel"]
        } else {
            &["sudo", "wheel", "admin", "root"]
        };
        for &cand in candidates {
            if unix_group_lists_member(cand, &username) {
                return true;
            }
        }
    }
    false
}

#[cfg(unix)]
fn unix_group_name_by_gid(gid: libc::gid_t) -> Option<String> {
    use std::ffi::CStr;
    let mut buf_len = 1024usize;
    while buf_len <= 262_144 {
        let mut buf = vec![0u8; buf_len];
        let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
        let mut res: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrgid_r(gid, &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut res)
        };
        if rc == 0 {
            if res.is_null() || grp.gr_name.is_null() {
                return None;
            }
            let name = unsafe { CStr::from_ptr(grp.gr_name) }.to_str().ok()?;
            return Some(name.to_string());
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return None;
    }
    None
}

#[cfg(unix)]
fn unix_passwd_name_and_gid(uid: libc::uid_t) -> Option<(String, libc::gid_t)> {
    use std::ffi::CStr;
    let mut buf_len = 1024usize;
    while buf_len <= 262_144 {
        let mut buf = vec![0u8; buf_len];
        let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut res)
        };
        if rc == 0 {
            if res.is_null() || pwd.pw_name.is_null() {
                return None;
            }
            let name = unsafe { CStr::from_ptr(pwd.pw_name) }.to_str().ok()?;
            return Some((name.to_string(), pwd.pw_gid));
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return None;
    }
    None
}

#[cfg(unix)]
fn unix_group_lists_member(group_name: &str, username: &str) -> bool {
    use std::ffi::{CStr, CString};
    let Ok(c_group) = CString::new(group_name) else {
        return false;
    };
    let mut buf_len = 1024usize;
    while buf_len <= 262_144 {
        let mut buf = vec![0u8; buf_len];
        let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
        let mut res: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                c_group.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut res,
            )
        };
        if rc == 0 {
            if res.is_null() || grp.gr_mem.is_null() {
                return false;
            }
            let mut ptr = grp.gr_mem;
            unsafe {
                while !(*ptr).is_null() {
                    if CStr::from_ptr(*ptr).to_str().ok() == Some(username) {
                        return true;
                    }
                    ptr = ptr.add(1);
                }
            }
            return false;
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return false;
    }
    false
}

/// First untrusted symlink/junction component along `path` (or `None` if clean).
///
/// - On Windows: identical to [`crate::recording_dir::link_component`] — every
///   symlink or directory junction at any depth is rejected.
/// - On Linux/other Unix: every symlink at any depth is rejected.
/// - On macOS: standard APFS root layout exposes `/etc -> private/etc`,
///   `/var -> private/var`, and `/tmp -> private/tmp` as OS-managed root-owned
///   symlinks directly under `/`. Only that exact top-level alias (`depth == 0`,
///   non-leaf, root-owned symlink in root-owned non-group/world-writable `/`
///   pointing to `private/<name>` or `/private/<name>`, where `/private` and
///   `/private/<name>` are root-owned real directories) is resolved onto
///   `/private/<name>`; EVERY symlink below that prefix (including
///   `/etc/meshharbor`, `/etc/meshharbor/config.toml`, any subdirectory under
///   `/var` or `/tmp`, or any leaf component) is rejected.
pub fn untrusted_promotion_link_component(path: &Path) -> Option<PathBuf> {
    #[cfg(not(unix))]
    {
        crate::recording_dir::link_component(path)
    }
    #[cfg(unix)]
    {
        untrusted_promotion_link_unix(path, Path::new("/"), cfg!(target_os = "macos"), true)
    }
}

#[cfg(unix)]
fn untrusted_promotion_link_unix(
    path: &Path,
    fs_root: &Path,
    allow_macos_root_aliases: bool,
    require_root_uid: bool,
) -> Option<PathBuf> {
    use std::path::Component;

    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Some(path.to_path_buf());
    }
    let Ok(rel) = path.strip_prefix(fs_root) else {
        return Some(path.to_path_buf());
    };
    let mut normals = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(s) => normals.push(s),
            _ => return Some(path.to_path_buf()),
        }
    }
    if normals.is_empty() {
        return match std::fs::symlink_metadata(fs_root) {
            Ok(m) if m.file_type().is_symlink() => Some(fs_root.to_path_buf()),
            Ok(_) => None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => Some(fs_root.to_path_buf()),
        };
    }

    let mut cur = fs_root.to_path_buf();
    for (depth, &comp) in normals.iter().enumerate() {
        let is_leaf = depth + 1 == normals.len();
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                if allow_macos_root_aliases
                    && depth == 0
                    && !is_leaf
                    && let Some(alias_target) =
                        verified_macos_root_alias(fs_root, &cur, comp, &m, require_root_uid)
                {
                    cur = alias_target;
                    continue;
                }
                return Some(cur);
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Some(cur),
        }
    }
    None
}

#[cfg(unix)]
fn verified_macos_root_alias(
    fs_root: &Path,
    link_path: &Path,
    comp: &std::ffi::OsStr,
    link_meta: &std::fs::Metadata,
    require_root_uid: bool,
) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let name = comp.to_str()?;
    if !matches!(name, "etc" | "var" | "tmp") {
        return None;
    }
    if require_root_uid && link_meta.uid() != 0 {
        return None;
    }

    let root_meta = std::fs::symlink_metadata(fs_root).ok()?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return None;
    }
    if require_root_uid && root_meta.uid() != 0 {
        return None;
    }
    if (root_meta.mode() & 0o022) != 0 {
        return None;
    }

    let raw_target = std::fs::read_link(link_path).ok()?;
    let expected_rel = PathBuf::from("private").join(name);
    let expected_abs = fs_root.join("private").join(name);
    if raw_target != expected_rel && raw_target != expected_abs {
        return None;
    }

    let private_dir = fs_root.join("private");
    let private_meta = std::fs::symlink_metadata(&private_dir).ok()?;
    if private_meta.file_type().is_symlink() || !private_meta.is_dir() {
        return None;
    }
    if require_root_uid && private_meta.uid() != 0 {
        return None;
    }
    if (private_meta.mode() & 0o022) != 0 {
        return None;
    }

    let target_meta = std::fs::symlink_metadata(&expected_abs).ok()?;
    if target_meta.file_type().is_symlink() || !target_meta.is_dir() {
        return None;
    }
    if require_root_uid && target_meta.uid() != 0 {
        return None;
    }
    let target_mode = target_meta.mode();
    let mode_ok = if name == "tmp" {
        (target_mode & 0o022) == 0 || (target_mode & 0o1000) != 0
    } else {
        (target_mode & 0o022) == 0
    };
    if !mode_ok {
        return None;
    }

    Some(expected_abs)
}

/// Pure check that a candidate Windows SCM service binary lives under a
/// trusted `%ProgramFiles%` root (never a user-writable directory).
pub fn is_trusted_windows_service_exe(exe: &Path, program_files: &[PathBuf]) -> bool {
    crate::companion_autostart::windows_scope_for_exe(exe, program_files)
        == crate::companion_autostart::InstallScope::Machine
}

/// Guard owning the single-use `request-<nonce>.json` and `status-<nonce>.txt`
/// files for one elevation attempt; removes both unconditionally on `Drop`.
pub struct TempPromotionFiles {
    pub request_path: PathBuf,
    pub status_path: PathBuf,
}

impl TempPromotionFiles {
    pub fn create_in(dir: &Path, req: &SystemEnrollRequest) -> std::io::Result<Self> {
        if let Some(link) = untrusted_promotion_link_component(dir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "promotion directory {} contains untrusted symbolic link or junction {}",
                    dir.display(),
                    link.display()
                ),
            ));
        }
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::symlink_metadata(dir)
                && meta.is_dir()
                && (meta.permissions().mode() & 0o077) != 0
            {
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        let request_path = dir.join(format!("promote-req-{nonce}.json"));
        let status_path = dir.join(format!("promote-status-{nonce}.txt"));

        let payload = serde_json::to_vec(req).map_err(std::io::Error::other)?;
        if payload.len() as u64 > MAX_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "promotion request exceeds maximum size",
            ));
        }

        let mut req_opts = std::fs::OpenOptions::new();
        req_opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            req_opts.mode(0o600);
        }
        let mut req_file = req_opts.open(&request_path)?;
        if let Err(e) = req_file
            .write_all(&payload)
            .and_then(|()| req_file.sync_all())
        {
            drop(req_file);
            let _ = std::fs::remove_file(&request_path);
            return Err(e);
        }
        drop(req_file);

        let mut st_opts = std::fs::OpenOptions::new();
        st_opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            st_opts.mode(0o600);
        }
        if let Err(e) = st_opts.open(&status_path) {
            let _ = std::fs::remove_file(&request_path);
            return Err(e);
        }

        Ok(Self {
            request_path,
            status_path,
        })
    }

    /// True if the elevated helper has NOT yet consumed (zeroed) the request.
    /// Lets `sudo -n` fallback distinguish an auth rejection (helper never ran)
    /// from an execution failure after token consumption.
    pub fn has_unconsumed_request(&self) -> bool {
        std::fs::metadata(&self.request_path)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
    }
}

impl Drop for TempPromotionFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.request_path);
        let _ = std::fs::remove_file(&self.status_path);
    }
}

#[cfg(windows)]
fn open_single_link_plain_file_win(
    path: &Path,
    read: bool,
    write: bool,
) -> std::io::Result<(std::fs::File, u64)> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_TYPE_DISK,
        GetFileInformationByHandle, GetFileType,
    };

    if let Some(link) = crate::recording_dir::link_component(path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is a symbolic link or junction", link.display()),
        ));
    }

    let file = std::fs::OpenOptions::new()
        .read(read)
        .write(write)
        .create(false)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;

    let raw_handle = file.as_raw_handle() as HANDLE;
    // SAFETY: `raw_handle` is a live handle owned by `file`.
    if unsafe { GetFileType(raw_handle) } != FILE_TYPE_DISK {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "promotion file is not a regular disk file",
        ));
    }
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `raw_handle` is live and `info` is sized for BY_HANDLE_FILE_INFORMATION.
    if unsafe { GetFileInformationByHandle(raw_handle, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    const FORBIDDEN_ATTRS: u32 =
        FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE;
    if (info.dwFileAttributes & FORBIDDEN_ATTRS) != 0 || info.nNumberOfLinks != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "promotion file must be a single-link non-reparse regular file",
        ));
    }
    let size = ((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64);
    Ok((file, size))
}

fn scrub_request_writer<W: Write + Seek>(
    writer: &mut W,
    len: usize,
    truncate_zero: impl FnOnce(&mut W) -> std::io::Result<()>,
    sync: impl FnOnce(&mut W) -> std::io::Result<()>,
) -> std::io::Result<()> {
    if len > 0 {
        writer.seek(SeekFrom::Start(0))?;
        let zeros = vec![0u8; len];
        writer.write_all(&zeros)?;
        writer.flush()?;
    }
    truncate_zero(writer)?;
    sync(writer)?;
    Ok(())
}

/// Read and immediately scrub (zero-overwrite + `set_len(0)` + `sync_all`) a
/// single-use `SystemEnrollRequest` file without following symlinks/reparse
/// points or unlinking paths in user-controlled directories. Any scrub or sync
/// error fails closed before parsing or network I/O.
pub fn consume_request_file(path: &Path) -> anyhow::Result<SystemEnrollRequest> {
    if let Some(link) = untrusted_promotion_link_component(path) {
        anyhow::bail!(
            "promotion request path {} contains symbolic link or junction {}",
            path.display(),
            link.display()
        );
    }

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| anyhow::anyhow!("opening promotion request {}: {e}", path.display()))?;
        let meta = f
            .metadata()
            .map_err(|e| anyhow::anyhow!("stat promotion request {}: {e}", path.display()))?;
        if !meta.is_file() || meta.nlink() != 1 {
            anyhow::bail!(
                "promotion request {} must be a single-link regular file",
                path.display()
            );
        }
        if (meta.mode() & 0o077) != 0 {
            anyhow::bail!(
                "promotion request {} has group/other permissions ({:o}); refusing",
                path.display(),
                meta.mode() & 0o777
            );
        }
        if meta.len() == 0 {
            anyhow::bail!(
                "promotion request {} was already consumed or empty",
                path.display()
            );
        }
        if meta.len() > MAX_REQUEST_BYTES {
            anyhow::bail!(
                "promotion request {} exceeds maximum allowed size",
                path.display()
            );
        }
        f
    };

    #[cfg(windows)]
    let mut file = {
        let (f, size) = open_single_link_plain_file_win(path, true, true)
            .map_err(|e| anyhow::anyhow!("opening promotion request {}: {e}", path.display()))?;
        if size == 0 {
            anyhow::bail!(
                "promotion request {} was already consumed or empty",
                path.display()
            );
        }
        if size > MAX_REQUEST_BYTES {
            anyhow::bail!(
                "promotion request {} exceeds maximum allowed size",
                path.display()
            );
        }
        f
    };

    let mut raw = Vec::new();
    if let Err(e) = (&mut file)
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut raw)
    {
        raw.fill(0);
        return Err(anyhow::anyhow!("reading promotion request: {e}"));
    }

    // Scrub the bearer enrollment token from disk BEFORE parsing or network I/O.
    let scrub_res = scrub_request_writer(&mut file, raw.len(), |f| f.set_len(0), |f| f.sync_all());
    drop(file);
    if let Err(e) = scrub_res {
        raw.fill(0);
        return Err(anyhow::anyhow!(
            "scrubbing promotion request {}: {e}",
            path.display()
        ));
    }

    if raw.is_empty() || (raw.len() as u64) > MAX_REQUEST_BYTES {
        raw.fill(0);
        anyhow::bail!("promotion request size out of bounds");
    }
    let parsed = serde_json::from_slice(&raw)
        .map_err(|e| anyhow::anyhow!("decoding promotion request payload: {e}"));
    raw.fill(0);
    parsed
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Write a bounded error string into an existing single-link non-symlink
/// `status_file` (`create(false)`, handle-validated on both Unix and Windows).
/// Best-effort; silently refuses symlinks, junctions, hardlinks, or missing
/// targets so root/SYSTEM can never be tricked into overwriting an unintended file.
pub fn write_status_error(status_file: &Path, message: &str) {
    if untrusted_promotion_link_component(status_file).is_some() {
        return;
    }
    let trimmed = truncate_utf8(message.trim(), MAX_STATUS_BYTES);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create(false)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(status_file)
        else {
            return;
        };
        let Ok(meta) = f.metadata() else {
            return;
        };
        if !meta.is_file() || meta.nlink() != 1 {
            return;
        }
        let _ = f.set_len(0);
        let _ = f.write_all(trimmed.as_bytes());
        let _ = f.flush();
    }
    #[cfg(windows)]
    {
        let Ok((mut f, _size)) = open_single_link_plain_file_win(status_file, false, true) else {
            return;
        };
        let _ = f.set_len(0);
        let _ = f.write_all(trimmed.as_bytes());
        let _ = f.flush();
    }
}

/// Read any error message left by the elevated helper in `status_file`.
pub fn read_status_error(status_file: &Path) -> Option<String> {
    let mut f = std::fs::File::open(status_file).ok()?;
    let mut buf = String::new();
    let _ = (&mut f)
        .take((MAX_STATUS_BYTES + 1) as u64)
        .read_to_string(&mut buf)
        .ok()?;
    let msg = buf.trim();
    if msg.is_empty() {
        None
    } else {
        Some(msg.to_string())
    }
}

/// Quote a single Windows command-line argument using standard `CommandLineToArgvW` rules.
pub fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
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
            out.push(ch);
            backslashes = 0;
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

fn temp_base_dir() -> Result<PathBuf, String> {
    let cfg_path = crate::config::default_config_path()
        .map_err(|e| format!("resolving local config directory: {e}"))?;
    cfg_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "local config path has no parent directory".to_string())
}

fn run_direct_elevated(daemon_exe: &Path, temp: &TempPromotionFiles) -> Result<(), String> {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut cmd = std::process::Command::new(daemon_exe);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = cmd
        .arg("enroll-personal-system")
        .arg("--request-file")
        .arg(&temp.request_path)
        .arg("--status-file")
        .arg(&temp.status_path)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("launching {}: {e}", daemon_exe.display()))?;
    if out.status.success() {
        return Ok(());
    }
    if let Some(err) = read_status_error(&temp.status_path) {
        return Err(err);
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !stderr.is_empty() {
        return Err(stderr);
    }
    Err(format!(
        "system device promotion exited with status {}",
        out.status
    ))
}

/// Execute `meshharbord enroll-personal-system` with Administrator (`SYSTEM`)
/// or `root` privileges across Windows (UAC `runas`), Linux (`sudo -n`, TTY
/// `sudo`, or `pkexec`), and macOS (`sudo -n`, TTY `sudo`, or `osascript`
/// `with administrator privileges`).
pub fn invoke_elevated_enroll_system(
    daemon_exe: &Path,
    req: &SystemEnrollRequest,
    interactive_tty: bool,
) -> Result<(), String> {
    let dir = temp_base_dir()?;
    let temp = TempPromotionFiles::create_in(&dir, req)
        .map_err(|e| format!("preparing secure promotion files: {e}"))?;

    if is_process_elevated() {
        let _ = interactive_tty;
        return run_direct_elevated(daemon_exe, &temp);
    }

    #[cfg(windows)]
    {
        let _ = interactive_tty;
        invoke_windows_runas(daemon_exe, &temp)
    }

    #[cfg(target_os = "linux")]
    {
        invoke_linux_elevated(daemon_exe, &temp, interactive_tty)
    }

    #[cfg(target_os = "macos")]
    {
        invoke_macos_elevated(daemon_exe, &temp, interactive_tty)
    }
}

#[cfg(windows)]
fn invoke_windows_runas(daemon_exe: &Path, temp: &TempPromotionFiles) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_CANCELLED, GetLastError, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };

    fn wide_nul(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    let verb = wide_nul(std::ffi::OsStr::new("runas"));
    let file = wide_nul(daemon_exe.as_os_str());
    let params_str = [
        quote_windows_arg("enroll-personal-system"),
        quote_windows_arg("--request-file"),
        quote_windows_arg(&temp.request_path.to_string_lossy()),
        quote_windows_arg("--status-file"),
        quote_windows_arg(&temp.status_path.to_string_lossy()),
    ]
    .join(" ");
    let params = wide_nul(std::ffi::OsStr::new(&params_str));

    unsafe {
        let mut sei: SHELLEXECUTEINFOW = std::mem::zeroed();
        sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = verb.as_ptr();
        sei.lpFile = file.as_ptr();
        sei.lpParameters = params.as_ptr();
        sei.nShow = 0; // SW_HIDE

        if ShellExecuteExW(&mut sei) == 0 {
            let code = GetLastError();
            if code == ERROR_CANCELLED {
                return Err(
                    "Administrator approval (UAC) was cancelled; personal device promotion aborted."
                        .to_string(),
                );
            }
            return Err(format!(
                "Could not elevate {} for Administrator setup (Win32 error {code}).",
                daemon_exe.display()
            ));
        }
        if sei.hProcess.is_null() {
            return Err("Elevated helper launched without a process handle.".to_string());
        }
        let wait = WaitForSingleObject(sei.hProcess, 180_000);
        if wait != WAIT_OBJECT_0 {
            let _ = CloseHandle(sei.hProcess);
            return Err(
                "Timed out waiting for elevated MeshHarbor system service setup.".to_string(),
            );
        }
        let mut exit_code: u32 = 1;
        let _ = GetExitCodeProcess(sei.hProcess, &mut exit_code);
        let _ = CloseHandle(sei.hProcess);
        if exit_code == 0 {
            return Ok(());
        }
        if let Some(err) = read_status_error(&temp.status_path) {
            return Err(err);
        }
        Err(format!(
            "Elevated MeshHarbor setup failed with exit code {exit_code}."
        ))
    }
}

#[cfg(target_os = "linux")]
fn invoke_linux_elevated(
    daemon_exe: &Path,
    temp: &TempPromotionFiles,
    interactive_tty: bool,
) -> Result<(), String> {
    if let Ok(out) = std::process::Command::new("sudo")
        .arg("-n")
        .arg("--")
        .arg(daemon_exe)
        .arg("enroll-personal-system")
        .arg("--request-file")
        .arg(&temp.request_path)
        .arg("--status-file")
        .arg(&temp.status_path)
        .stdin(std::process::Stdio::null())
        .output()
    {
        if out.status.success() {
            return Ok(());
        }
        if !temp.has_unconsumed_request() {
            return Err(read_status_error(&temp.status_path)
                .unwrap_or_else(|| String::from_utf8_lossy(&out.stderr).trim().to_string()));
        }
    }

    if interactive_tty
        && let Ok(status) = std::process::Command::new("sudo")
            .arg("--")
            .arg(daemon_exe)
            .arg("enroll-personal-system")
            .arg("--request-file")
            .arg(&temp.request_path)
            .arg("--status-file")
            .arg(&temp.status_path)
            .status()
    {
        if status.success() {
            return Ok(());
        }
        if !temp.has_unconsumed_request() {
            return Err(read_status_error(&temp.status_path)
                .unwrap_or_else(|| format!("elevated setup exited with {status}")));
        }
    }

    let has_gui = std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
    if has_gui
        && let Ok(out) = std::process::Command::new("pkexec")
            .arg(daemon_exe)
            .arg("enroll-personal-system")
            .arg("--request-file")
            .arg(&temp.request_path)
            .arg("--status-file")
            .arg(&temp.status_path)
            .stdin(std::process::Stdio::null())
            .output()
    {
        if out.status.success() {
            return Ok(());
        }
        if let Some(err) = read_status_error(&temp.status_path) {
            return Err(err);
        }
        if matches!(out.status.code(), Some(126 | 127)) {
            return Err(
                "Administrator authentication was cancelled; device promotion aborted.".to_string(),
            );
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if !stderr.is_empty() {
            return Err(stderr);
        }
    }

    Err(
        "Root privileges are required to register this device with full root access. \
         Re-run with `sudo mh login` (or pass `mh login --user` for unprivileged user mode)."
            .to_string(),
    )
}

#[cfg(target_os = "macos")]
fn invoke_macos_elevated(
    daemon_exe: &Path,
    temp: &TempPromotionFiles,
    interactive_tty: bool,
) -> Result<(), String> {
    if let Ok(out) = std::process::Command::new("sudo")
        .arg("-n")
        .arg("--")
        .arg(daemon_exe)
        .arg("enroll-personal-system")
        .arg("--request-file")
        .arg(&temp.request_path)
        .arg("--status-file")
        .arg(&temp.status_path)
        .stdin(std::process::Stdio::null())
        .output()
    {
        if out.status.success() {
            return Ok(());
        }
        if !temp.has_unconsumed_request() {
            return Err(read_status_error(&temp.status_path)
                .unwrap_or_else(|| String::from_utf8_lossy(&out.stderr).trim().to_string()));
        }
    }

    if interactive_tty
        && let Ok(status) = std::process::Command::new("sudo")
            .arg("--")
            .arg(daemon_exe)
            .arg("enroll-personal-system")
            .arg("--request-file")
            .arg(&temp.request_path)
            .arg("--status-file")
            .arg(&temp.status_path)
            .status()
    {
        if status.success() {
            return Ok(());
        }
        if !temp.has_unconsumed_request() {
            return Err(read_status_error(&temp.status_path)
                .unwrap_or_else(|| format!("elevated setup exited with {status}")));
        }
    }

    const SCRIPT: &str = r#"on run argv
    set exePath to item 1 of argv
    set reqPath to item 2 of argv
    set statusPath to item 3 of argv
    do shell script (quoted form of exePath) & " enroll-personal-system --request-file " & (quoted form of reqPath) & " --status-file " & (quoted form of statusPath) with administrator privileges
end run"#;

    let out = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(SCRIPT)
        .arg("--")
        .arg(daemon_exe)
        .arg(&temp.request_path)
        .arg(&temp.status_path)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("launching macOS administrator prompt: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    if let Some(err) = read_status_error(&temp.status_path) {
        return Err(err);
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if stderr.contains("-128") || stderr.to_ascii_lowercase().contains("user canceled") {
        return Err("Administrator approval was cancelled; device promotion aborted.".to_string());
    }
    if !stderr.is_empty() {
        return Err(stderr);
    }
    Err("macOS administrator setup failed.".to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_an_account_sid_may_be_granted_config_read() {
        assert!(super::is_user_account_sid(
            "S-1-5-21-1111111111-2222222222-3333333333-1001"
        ));
        for bad in [
            "S-1-1-0",        // Everyone
            "S-1-5-32-545",   // BUILTIN\\Users
            "S-1-5-11",       // Authenticated Users
            "S-1-5-21-1-2-3", // too short
            "S-1-5-21-1-2-3-4-5",
            "S-1-5-21-1-2-3-4)(A;;FA;;;WD",
            "",
        ] {
            assert!(!super::is_user_account_sid(bad), "{bad}");
        }
    }

    use super::*;

    fn sample_req() -> SystemEnrollRequest {
        SystemEnrollRequest {
            server_url: "https://www.itachi.fans/meshharbor".to_string(),
            enrollment_token: "eyJ.secret.token".to_string(),
            device_name: "workstation-01".to_string(),
            replace: false,
            calling_uid: Some(1000),
            calling_sid: None,
            seed_config_toml: None,
            seed_temporary_json: None,
            seed_history_json: None,
        }
    }

    #[test]
    fn temp_promotion_files_roundtrip_scrubs_on_consume_and_cleans_up_on_drop() {
        let dir = std::env::temp_dir().join(format!(
            "mh-ps-test-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        let req_path;
        let st_path;
        {
            let temp = TempPromotionFiles::create_in(&dir, &sample_req()).unwrap();
            req_path = temp.request_path.clone();
            st_path = temp.status_path.clone();
            assert!(temp.has_unconsumed_request());

            let parsed = consume_request_file(&req_path).unwrap();
            assert_eq!(parsed.enrollment_token, "eyJ.secret.token");
            assert_eq!(parsed.device_name, "workstation-01");
            assert!(!temp.has_unconsumed_request());
            assert_eq!(std::fs::metadata(&req_path).unwrap().len(), 0);
            assert!(consume_request_file(&req_path).is_err());

            write_status_error(&st_path, "anchor verification failed");
            assert_eq!(
                read_status_error(&st_path).as_deref(),
                Some("anchor verification failed")
            );
        }
        assert!(!req_path.exists(), "Drop must remove request file");
        assert!(!st_path.exists(), "Drop must remove status file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scrub_failure_propagates_and_zeros_payload() {
        let mut backing = std::io::Cursor::new(b"secret-bearer-token".to_vec());
        scrub_request_writer(&mut backing, 19, |_| Ok(()), |_| Ok(())).unwrap();
        assert_eq!(backing.get_ref().as_slice(), &[0u8; 19]);

        let mut backing_trunc_err = std::io::Cursor::new(b"secret".to_vec());
        let err = scrub_request_writer(
            &mut backing_trunc_err,
            6,
            |_| Err(std::io::Error::other("truncate failed")),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("truncate failed"), "{err}");

        let mut backing_sync_err = std::io::Cursor::new(b"secret".to_vec());
        let err = scrub_request_writer(
            &mut backing_sync_err,
            6,
            |_| Ok(()),
            |_| Err(std::io::Error::other("fsync failed")),
        )
        .unwrap_err();
        assert!(err.to_string().contains("fsync failed"), "{err}");
    }

    #[test]
    fn hardlink_request_and_status_files_are_refused() {
        let dir = std::env::temp_dir().join(format!(
            "mh-ps-hlink-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "UNTAMPERED").unwrap();
        let hard_status = dir.join("status-hard.txt");
        std::fs::hard_link(&victim, &hard_status).unwrap();

        write_status_error(&hard_status, "OVERWRITTEN");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "UNTAMPERED");

        let temp = TempPromotionFiles::create_in(&dir, &sample_req()).unwrap();
        let hard_req = dir.join("req-hard.json");
        std::fs::hard_link(&temp.request_path, &hard_req).unwrap();
        assert!(
            consume_request_file(&temp.request_path).is_err(),
            "request file with nlink > 1 must be refused"
        );
        assert!(
            consume_request_file(&hard_req).is_err(),
            "hardlinked request alias must be refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_request_and_status_files_are_refused() {
        let dir = std::env::temp_dir().join(format!(
            "mh-ps-sym-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "UNTAMPERED").unwrap();
        let sym_status = dir.join("status-link.txt");
        std::os::unix::fs::symlink(&victim, &sym_status).unwrap();

        write_status_error(&sym_status, "OVERWRITTEN");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "UNTAMPERED");

        let real_req = dir.join("real-req.json");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&real_req)
                .unwrap();
            f.write_all(&serde_json::to_vec(&sample_req()).unwrap())
                .unwrap();
        }
        let sym_req = dir.join("req-link.json");
        std::os::unix::fs::symlink(&real_req, &sym_req).unwrap();
        assert!(consume_request_file(&sym_req).is_err());

        let sym_dir = dir.join("dir-link");
        std::os::unix::fs::symlink(&dir, &sym_dir).unwrap();
        assert!(
            consume_request_file(&sym_dir.join("real-req.json")).is_err(),
            "ancestor directory symlink must be refused"
        );

        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&real_req, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(consume_request_file(&real_req).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn junction_ancestor_on_windows_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "mh-ps-junc-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        let real_dir = dir.join("real");
        let junc_dir = dir.join("junc");
        std::fs::create_dir_all(&real_dir).unwrap();
        let temp = TempPromotionFiles::create_in(&real_dir, &sample_req()).unwrap();
        let st = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junc_dir)
            .arg(&real_dir)
            .status()
            .unwrap();
        assert!(st.success(), "mklink /J failed");

        let via_junc_req = junc_dir.join(temp.request_path.file_name().unwrap());
        let via_junc_st = junc_dir.join(temp.status_path.file_name().unwrap());
        assert!(consume_request_file(&via_junc_req).is_err());
        write_status_error(&via_junc_st, "THROUGH_JUNCTION");
        assert!(read_status_error(&temp.status_path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_service_dir_validation_and_arg_quoting() {
        let roots = vec![
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ];
        assert!(is_trusted_windows_service_exe(
            Path::new(r"C:\Program Files\MeshHarbor\meshharbord.exe"),
            &roots
        ));
        assert!(!is_trusted_windows_service_exe(
            Path::new(r"C:\Users\alice\AppData\Local\MeshHarbor\meshharbord.exe"),
            &roots
        ));
        assert!(!is_trusted_windows_service_exe(
            Path::new(r"C:\Program Files Evil\meshharbord.exe"),
            &roots
        ));
        assert_eq!(
            quote_windows_arg(r#"C:\Users\Alice Bob\promote "1"\"#),
            r#""C:\Users\Alice Bob\promote \"1\"\\""#
        );
    }

    #[test]
    fn snapshot_and_retire_user_config_uses_canonical_sidecars_and_fails_closed_on_io_err() {
        let dir = std::env::temp_dir().join(format!(
            "mh-ps-sidecar-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.toml");
        std::fs::write(&cfg_path, "machine_id = \"m1\"\n").unwrap();
        std::fs::write(dir.join("temporary.json"), "{\"access_until_ms\":123}").unwrap();
        std::fs::write(dir.join("invites.json"), "[{\"invite_id\":\"inv1\"}]").unwrap();

        let req = SystemEnrollRequest::from_user_config_path(
            "https://mh.example".into(),
            "tok".into(),
            "box".into(),
            false,
            Some(&cfg_path),
        )
        .unwrap();
        assert_eq!(
            req.seed_config_toml.as_deref(),
            Some("machine_id = \"m1\"\n")
        );
        assert_eq!(
            req.seed_temporary_json.as_deref(),
            Some("{\"access_until_ms\":123}")
        );
        assert_eq!(
            req.seed_history_json.as_deref(),
            Some("[{\"invite_id\":\"inv1\"}]")
        );

        retire_migrated_user_config(&cfg_path);
        assert!(!cfg_path.exists());
        assert!(!dir.join("temporary.json").exists());
        assert!(!dir.join("invites.json").exists());

        // An unreadable config path (e.g. a directory where config.toml is expected)
        // must fail closed rather than returning None and allowing retirement.
        std::fs::create_dir_all(&cfg_path).unwrap();
        assert!(
            SystemEnrollRequest::from_user_config_path(
                "https://mh.example".into(),
                "tok".into(),
                "box".into(),
                false,
                Some(&cfg_path),
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn macos_root_alias_allows_trusted_system_prefix_and_rejects_deeper_or_spoofed_links() {
        use std::os::unix::fs::PermissionsExt;

        let raw_base = std::env::temp_dir().join(format!(
            "mh-ps-macos-layout-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&raw_base).unwrap();
        let fake_root = std::fs::canonicalize(&raw_base).unwrap();
        std::fs::set_permissions(&fake_root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let priv_dir = fake_root.join("private");
        let priv_etc = priv_dir.join("etc");
        let priv_var = priv_dir.join("var");
        let priv_tmp = priv_dir.join("tmp");
        std::fs::create_dir_all(&priv_etc).unwrap();
        std::fs::create_dir_all(priv_var.join("folders/T")).unwrap();
        std::fs::create_dir_all(&priv_tmp).unwrap();
        std::fs::set_permissions(&priv_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&priv_etc, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&priv_var, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&priv_tmp, std::fs::Permissions::from_mode(0o1777)).unwrap();

        std::os::unix::fs::symlink("private/etc", fake_root.join("etc")).unwrap();
        std::os::unix::fs::symlink("private/var", fake_root.join("var")).unwrap();
        std::os::unix::fs::symlink("private/tmp", fake_root.join("tmp")).unwrap();

        let sys_cfg = fake_root.join("etc/meshharbor/config.toml");

        // 1. Linux mode (`allow_macos_root_aliases = false`) still rejects `/etc` symlink.
        assert_eq!(
            untrusted_promotion_link_unix(&sys_cfg, &fake_root, false, false),
            Some(fake_root.join("etc"))
        );

        // 2. macOS mode (`allow_macos_root_aliases = true`) accepts `/etc -> private/etc`
        //    both before `/private/etc/meshharbor` exists and after `config.toml` exists.
        assert_eq!(
            untrusted_promotion_link_unix(&sys_cfg, &fake_root, true, false),
            None
        );
        std::fs::create_dir_all(priv_etc.join("meshharbor")).unwrap();
        std::fs::write(
            priv_etc.join("meshharbor/config.toml"),
            r#"machine_id = "m""#,
        )
        .unwrap();
        assert_eq!(
            untrusted_promotion_link_unix(&sys_cfg, &fake_root, true, false),
            None
        );

        // 3. `/var -> private/var` and `/tmp -> private/tmp` prefixes also work cleanly.
        assert_eq!(
            untrusted_promotion_link_unix(
                &fake_root.join("var/folders/T/promote-req.json"),
                &fake_root,
                true,
                false
            ),
            None
        );
        assert_eq!(
            untrusted_promotion_link_unix(
                &fake_root.join("tmp/promote-req.json"),
                &fake_root,
                true,
                false
            ),
            None
        );

        // 4. Leaf `/etc` itself is still rejected.
        assert_eq!(
            untrusted_promotion_link_unix(&fake_root.join("etc"), &fake_root, true, false),
            Some(fake_root.join("etc"))
        );

        // 5. Symlink at `/etc/meshharbor/config.toml` (leaf under `/private/etc`) is rejected!
        let victim = fake_root.join("victim.toml");
        std::fs::write(&victim, "secret").unwrap();
        std::fs::remove_file(priv_etc.join("meshharbor/config.toml")).unwrap();
        std::os::unix::fs::symlink(&victim, priv_etc.join("meshharbor/config.toml")).unwrap();
        assert_eq!(
            untrusted_promotion_link_unix(&sys_cfg, &fake_root, true, false),
            Some(priv_etc.join("meshharbor/config.toml"))
        );

        // 6. Directory symlink at `/etc/meshharbor` (depth 1 under `/private/etc`) is rejected!
        std::fs::remove_dir_all(priv_etc.join("meshharbor")).unwrap();
        let outside_dir = fake_root.join("outside");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::os::unix::fs::symlink(&outside_dir, priv_etc.join("meshharbor")).unwrap();
        assert_eq!(
            untrusted_promotion_link_unix(&sys_cfg, &fake_root, true, false),
            Some(priv_etc.join("meshharbor"))
        );

        // 7. Deeper symlink under `/var/folders/T` is rejected!
        std::os::unix::fs::symlink(&outside_dir, priv_var.join("folders/T/evil")).unwrap();
        assert_eq!(
            untrusted_promotion_link_unix(
                &fake_root.join("var/folders/T/evil/promote-req.json"),
                &fake_root,
                true,
                false
            ),
            Some(priv_var.join("folders/T/evil"))
        );

        // 8. Non-allowlisted top-level alias (`opt -> private/opt`) and spoofed target (`etc -> outside`) are rejected!
        std::fs::create_dir_all(priv_dir.join("opt")).unwrap();
        std::os::unix::fs::symlink("private/opt", fake_root.join("opt")).unwrap();
        assert_eq!(
            untrusted_promotion_link_unix(
                &fake_root.join("opt/meshharbor/config.toml"),
                &fake_root,
                true,
                false
            ),
            Some(fake_root.join("opt"))
        );

        std::fs::remove_file(fake_root.join("etc")).unwrap();
        std::os::unix::fs::symlink("outside", fake_root.join("etc")).unwrap();
        assert_eq!(
            untrusted_promotion_link_unix(&sys_cfg, &fake_root, true, false),
            Some(fake_root.join("etc"))
        );

        // 9. On real macOS hosts, verify `/etc/meshharbor/config.toml` passes live `untrusted_promotion_link_component`.
        #[cfg(target_os = "macos")]
        assert_eq!(
            untrusted_promotion_link_component(Path::new("/etc/meshharbor/config.toml")),
            None
        );

        let _ = std::fs::remove_dir_all(&fake_root);
    }

    #[test]
    fn unix_admin_group_classifier_matches_platform_conventions() {
        for g in ["sudo", "wheel", "admin", "root"] {
            assert!(
                is_unix_admin_group_name(false, g),
                "linux should accept {g}"
            );
        }
        for g in ["users", "staff", "docker", "cuizhuoxu", "nogroup", ""] {
            assert!(!is_unix_admin_group_name(false, g), "linux must reject {g}");
        }
        for g in ["admin", "wheel"] {
            assert!(is_unix_admin_group_name(true, g), "macos should accept {g}");
        }
        for g in ["staff", "sudo", "users", "everyone", ""] {
            assert!(!is_unix_admin_group_name(true, g), "macos must reject {g}");
        }
        if is_process_elevated() {
            assert!(can_current_user_elevate());
        }
    }
}
