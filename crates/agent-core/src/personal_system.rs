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
//! - The elevated helper opens both files without following symlinks
//!   (`O_NOFOLLOW` + `fstat` regular-file `nlink == 1` on Unix; non-reparse
//!   `create(false)` on Windows), zeroes the request file on disk immediately
//!   before parsing or network I/O, and NEVER creates or unlinks paths inside
//!   unprivileged user directories.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
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
    /// Existing per-user `config.toml` snapshot captured by the unprivileged
    /// caller before elevation, used ONLY to seed `/etc/meshharbor/config.toml`
    /// or `%PROGRAMDATA%\meshharbor\meshharbor\config.toml` when no system
    /// config exists yet (preserving `machine_id`, WireGuard keys, and SIAT
    /// invitations without root/SYSTEM touching user-owned directories).
    #[serde(default)]
    pub seed_config_toml: Option<String>,
    #[serde(default)]
    pub seed_temporary_json: Option<String>,
    #[serde(default)]
    pub seed_history_json: Option<String>,
}

impl SystemEnrollRequest {
    /// Build a promotion request, snapshotting any existing non-system user
    /// config and SIAT invitation sidecars from `user_config_path` in the
    /// caller's own unprivileged context.
    pub fn from_user_config_path(
        server_url: String,
        enrollment_token: String,
        device_name: String,
        replace: bool,
        user_config_path: Option<&Path>,
    ) -> Self {
        #[cfg(unix)]
        // SAFETY: libc::geteuid has no preconditions.
        let calling_uid = Some(unsafe { libc::geteuid() });
        #[cfg(not(unix))]
        let calling_uid = None;

        let mut seed_config_toml = None;
        let mut seed_temporary_json = None;
        let mut seed_history_json = None;

        if let Some(p) = user_config_path.filter(|p| !is_system_config_path(p) && p.exists()) {
            seed_config_toml = std::fs::read_to_string(p).ok();
            let temp_path = crate::device_invite::marker_path(p);
            if temp_path.exists() {
                seed_temporary_json = std::fs::read_to_string(&temp_path).ok();
            }
            let hist_path = crate::device_invite::history_path(p);
            if hist_path.exists() {
                seed_history_json = std::fs::read_to_string(&hist_path).ok();
            }
        }

        Self {
            server_url,
            enrollment_token,
            device_name,
            replace,
            calling_uid,
            seed_config_toml,
            seed_temporary_json,
            seed_history_json,
        }
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
        if let Err(e) = req_file.write_all(&payload).and_then(|()| req_file.sync_all()) {
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

/// Read and immediately scrub (`set_len(0)` + `sync_all`) a single-use
/// `SystemEnrollRequest` file without following symlinks or unlinking paths in
/// user-controlled directories.
pub fn consume_request_file(path: &Path) -> anyhow::Result<SystemEnrollRequest> {
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
            anyhow::bail!("promotion request {} must be a single-link regular file", path.display());
        }
        if (meta.mode() & 0o077) != 0 {
            anyhow::bail!(
                "promotion request {} has group/other permissions ({:o}); refusing",
                path.display(),
                meta.mode() & 0o777
            );
        }
        if meta.len() == 0 {
            anyhow::bail!("promotion request {} was already consumed or empty", path.display());
        }
        if meta.len() > MAX_REQUEST_BYTES {
            anyhow::bail!("promotion request {} exceeds maximum allowed size", path.display());
        }
        f
    };

    #[cfg(windows)]
    let mut file = {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| anyhow::anyhow!("stat promotion request {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            anyhow::bail!("promotion request {} must be a regular non-reparse file", path.display());
        }
        if meta.len() == 0 {
            anyhow::bail!("promotion request {} was already consumed or empty", path.display());
        }
        if meta.len() > MAX_REQUEST_BYTES {
            anyhow::bail!("promotion request {} exceeds maximum allowed size", path.display());
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(path)
            .map_err(|e| anyhow::anyhow!("opening promotion request {}: {e}", path.display()))?
    };

    let mut raw = Vec::new();
    (&mut file)
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| anyhow::anyhow!("reading promotion request: {e}"))?;
    // Scrub the bearer enrollment token from disk BEFORE parsing or network I/O.
    let _ = file.set_len(0);
    let _ = file.sync_all();
    drop(file);

    if raw.is_empty() || (raw.len() as u64) > MAX_REQUEST_BYTES {
        anyhow::bail!("promotion request size out of bounds");
    }
    serde_json::from_slice(&raw)
        .map_err(|e| anyhow::anyhow!("decoding promotion request payload: {e}"))
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

/// Write a bounded error string into an existing non-symlink `status_file`
/// (`create(false)`, `O_NOFOLLOW` + `nlink == 1` on Unix). Best-effort; silently
/// refuses symlinks, hardlinks, or missing targets so root/SYSTEM can never be
/// tricked into overwriting an arbitrary file.
pub fn write_status_error(status_file: &Path, message: &str) {
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
        let Ok(meta) = std::fs::symlink_metadata(status_file) else {
            return;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            return;
        }
        let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create(false)
            .open(status_file)
        else {
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
    let _ = (&mut f).take((MAX_STATUS_BYTES + 1) as u64).read_to_string(&mut buf).ok()?;
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
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, GetLastError, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};

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
            return Err(read_status_error(&temp.status_path).unwrap_or_else(|| {
                String::from_utf8_lossy(&out.stderr).trim().to_string()
            }));
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
            return Err(read_status_error(&temp.status_path).unwrap_or_else(|| {
                String::from_utf8_lossy(&out.stderr).trim().to_string()
            }));
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
    use super::*;

    fn sample_req() -> SystemEnrollRequest {
        SystemEnrollRequest {
            server_url: "https://www.itachi.fans/meshharbor".to_string(),
            enrollment_token: "eyJ.secret.token".to_string(),
            device_name: "workstation-01".to_string(),
            replace: false,
            calling_uid: Some(1000),
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

        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&real_req, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(consume_request_file(&real_req).is_err());

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
    fn snapshot_and_retire_user_config_uses_canonical_sidecars() {
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
        );
        assert_eq!(req.seed_config_toml.as_deref(), Some("machine_id = \"m1\"\n"));
        assert_eq!(req.seed_temporary_json.as_deref(), Some("{\"access_until_ms\":123}"));
        assert_eq!(req.seed_history_json.as_deref(), Some("[{\"invite_id\":\"inv1\"}]"));

        retire_migrated_user_config(&cfg_path);
        assert!(!cfg_path.exists());
        assert!(!dir.join("temporary.json").exists());
        assert!(!dir.join("invites.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
