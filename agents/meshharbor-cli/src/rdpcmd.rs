// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! X17 — `mh rdp`: client-side OS credential-store passwordless RDP over an
//! authorized local loopback tunnel.
//!
//! Security & trust boundaries:
//! 1. **Default OFF + Kill Switch**: Saving (`--save-credentials`) and reading
//!    (`--use-saved-credentials`) stored RDP credentials are both opt-in and
//!    OFF by default. Either `--no-saved-credentials` or
//!    `MESHHARBOR_RDP_PASSWORDLESS_DISABLED=1` immediately disables them.
//! 2. **Server Never Sees RDP Secrets**: `mh rdp` only resolves the device and
//!    opens an authorized TCP forward to the remote RDP port. No RDP username,
//!    domain, or password is ever transmitted to `meshharbord` or the server.
//! 3. **No Secret in `argv`, `env`, Temp Files, `.rdp` Files, Logs, or URLs**:
//!    - Windows: Win32 Credential Manager (`CredWriteW` / `CredReadW` /
//!      `CredDeleteW` / `CredFree`) in process memory. `cmdkey /pass:` is
//!      strictly forbidden.
//!    - Linux: `secret-tool` via `stdin` pipe; `xfreerdp3` / `xfreerdp` with
//!      `/from-stdin` via `stdin` pipe.
//!    - macOS: `/usr/bin/security -i` via `stdin` pipe.
//! 4. **Certificate Pinning**: Target TLS certificate SHA-256 fingerprint is
//!    pinned when reported or specified via `--cert-sha256`. Flags that disable
//!    certificate verification (`/cert:ignore`, `/cert-ignore`, etc.) are
//!    refused.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use tunnel_core::localapi;

/// Environment variable that acts as an operator/user kill switch for saved RDP
/// credentials (`1`, `true`, `yes`, `on` case-insensitively).
pub const KILL_SWITCH_ENV: &str = "MESHHARBOR_RDP_PASSWORDLESS_DISABLED";

/// CLI options parsed from `mh rdp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpCliOptions {
    pub target: String,
    pub user: Option<String>,
    pub domain: Option<String>,
    pub port: u16,
    pub cert_sha256: Option<String>,
    pub save_credentials: bool,
    pub use_saved_credentials: bool,
    pub clear_credentials: bool,
    pub no_saved_credentials: bool,
    pub extra_args: Vec<String>,
}

/// Scoped key identifying a target device in the client's local OS credential
/// store (`MeshHarbor:rdp:<org_id>:<device_id>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RdpCredentialScope {
    pub org_id: String,
    pub device_id: String,
}

impl RdpCredentialScope {
    pub fn store_target_name(&self) -> String {
        format!("MeshHarbor:rdp:{}:{}", self.org_id, self.device_id)
    }
}

/// Stored RDP credential in the client machine's OS secure credential store.
/// The password is redacted in `Debug` and zeroized on `Drop`.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredRdpCredential {
    pub username: String,
    pub domain: Option<String>,
    password: String,
}

impl std::fmt::Debug for StoredRdpCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredRdpCredential")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl StoredRdpCredential {
    pub fn new(
        username: impl Into<String>,
        domain: Option<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            domain,
            password: password.into(),
        }
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn qualified_username(&self) -> String {
        match self
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
        {
            Some(d) => format!("{d}\\{}", self.username),
            None => self.username.clone(),
        }
    }

    pub fn from_qualified_username(qualified: &str, password: impl Into<String>) -> Self {
        if let Some((domain, user)) = qualified.split_once('\\') {
            Self::new(
                user.to_string(),
                Some(domain.to_string()).filter(|d| !d.is_empty()),
                password,
            )
        } else {
            Self::new(qualified.to_string(), None, password)
        }
    }
}

impl Drop for StoredRdpCredential {
    fn drop(&mut self) {
        unsafe {
            for b in self.password.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

/// Resolved target device metadata from the local daemon / server (never
/// includes any RDP password or secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRdpDevice {
    pub org_id: String,
    pub device_id: String,
    pub device_name: String,
}

static SESSION_LOOPBACK_BASE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
static SESSION_LOOPBACK_SEQ: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Allocate a unique per-session loopback IPv4 address in `127.77.x.y`
/// (`127.0.0.0/8`, never `127.0.0.1`) so Windows `TERMSRV/<ip>` session
/// credentials never collide with user-saved `TERMSRV/127.0.0.1` entries or
/// concurrent `mh rdp` sessions.
pub fn allocate_session_loopback_ip() -> std::net::Ipv4Addr {
    let base = *SESSION_LOOPBACK_BASE.get_or_init(|| {
        let pid = std::process::id() as usize;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as usize)
            .unwrap_or(0);
        pid.wrapping_mul(0x9E37_79B9).wrapping_add(nanos)
    });
    let seq = SESSION_LOOPBACK_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let slot = base.wrapping_add(seq) % (254 * 254);
    let x = ((slot / 254) as u8) + 1;
    let y = ((slot % 254) as u8) + 1;
    std::net::Ipv4Addr::new(127, 77, x, y)
}

/// Resolve the FreeRDP client binary from a given `PATH` (`xfreerdp3`
/// preferred, falling back to `xfreerdp` or `wlfreerdp`).
pub fn resolve_freerdp_program_in_path(path_env: Option<&std::ffi::OsStr>) -> String {
    if let Some(path_os) = path_env {
        for candidate in ["xfreerdp3", "xfreerdp", "wlfreerdp"] {
            for dir in std::env::split_paths(path_os) {
                let full = dir.join(candidate);
                if full.is_file() {
                    return candidate.to_string();
                }
            }
        }
    }
    "xfreerdp3".to_string()
}

/// Resolve the FreeRDP client binary on Linux/macOS (`MESHHARBOR_FREERDP_BIN`
/// override, else `xfreerdp3` -> `xfreerdp` -> `wlfreerdp` in `PATH`).
pub fn resolve_freerdp_program() -> String {
    if let Ok(custom) = std::env::var("MESHHARBOR_FREERDP_BIN") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    resolve_freerdp_program_in_path(std::env::var_os("PATH").as_deref())
}

/// Extract the `attribute.username` value from `secret-tool search` output,
/// failing closed if missing or empty.
pub fn parse_linux_secret_tool_username(search_output: &str) -> Result<String> {
    for line in search_output.lines() {
        if let Some(rest) = line.trim().strip_prefix("attribute.username = ") {
            let user = rest.trim();
            if !user.is_empty() {
                return Ok(user.to_string());
            }
        }
    }
    bail!(
        "stored RDP credential in secret-tool is missing a non-empty 'username' attribute; refusing fallback username"
    )
}

/// Abstract client-local OS secure credential store seam.
pub trait RdpCredentialStore: Send + Sync {
    fn save(&self, scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()>;
    fn load(&self, scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>>;
    fn delete(&self, scope: &RdpCredentialScope) -> Result<bool>;
}

/// Planned native RDP client process invocation.
/// `stdin_payload` is redacted in `Debug` so secrets can never leak to logs.
#[derive(Clone, PartialEq, Eq)]
pub struct PlannedRdpInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub stdin_payload: Option<String>,
    pub windows_session_target: Option<String>,
    pub pinned_cert_sha256: Option<String>,
    pub local_tunnel_addr: SocketAddr,
}

impl std::fmt::Debug for PlannedRdpInvocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlannedRdpInvocation")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env", &self.env)
            .field(
                "stdin_payload",
                &self.stdin_payload.as_ref().map(|_| "<redacted>"),
            )
            .field("windows_session_target", &self.windows_session_target)
            .field("pinned_cert_sha256", &self.pinned_cert_sha256)
            .field("local_tunnel_addr", &self.local_tunnel_addr)
            .finish()
    }
}

/// Parse `<user>@<device>` or `<device>`.
pub fn parse_user_and_device(raw: &str) -> Result<(Option<String>, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("target device must not be empty");
    }
    if let Some((user, host)) = trimmed.rsplit_once('@') {
        let user = user.trim();
        let host = host.trim();
        if user.is_empty() {
            bail!("empty username before '@' in target '{trimmed}'");
        }
        if host.is_empty() {
            bail!("empty device name after '@' in target '{trimmed}'");
        }
        Ok((Some(user.to_string()), host.to_string()))
    } else {
        Ok((None, trimmed.to_string()))
    }
}

/// Validate extra arguments forwarded to the native RDP client.
/// Rejects any flag that carries a password on the command line or weakens
/// TLS certificate verification.
pub fn validate_extra_client_args(args: &[String]) -> Result<()> {
    for raw in args {
        let lower = raw.trim().to_ascii_lowercase();
        if lower == "cmdkey"
            || lower == "cmdkey.exe"
            || lower.starts_with("/pass:")
            || lower.starts_with("/pass=")
            || lower == "/pass"
        {
            bail!(
                "refusing unsafe argument '{raw}': `cmdkey /pass:` leaks secrets into process argv"
            );
        }
        if lower.starts_with("/p:")
            || lower.starts_with("/p=")
            || lower == "/p"
            || lower.starts_with("/password")
            || lower == "-p"
            || lower == "--password"
            || lower.starts_with("--password=")
        {
            bail!(
                "refusing plaintext password flag '{raw}': RDP passwords must never be passed in argv"
            );
        }
        if lower == "/cert:ignore"
            || lower == "/cert-ignore"
            || lower == "--ignore-certificate"
            || lower == "/cert:tofu"
            || lower == "/cert-tofu"
        {
            bail!("refusing '{raw}': disabling RDP certificate verification is not permitted");
        }
    }
    Ok(())
}

/// Normalize a SHA-256 certificate fingerprint (`AA:BB:...` or 64 hex chars)
/// into lowercase colon-separated `aa:bb:...` format.
pub fn normalize_cert_sha256(raw: &str) -> Result<String> {
    let hex_only: String = raw
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != '-')
        .collect();
    if hex_only.len() != 64 || !hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!(
            "invalid RDP certificate SHA-256 fingerprint '{raw}': expected 64 hex digits (or 32 colon-separated hex bytes)"
        );
    }
    let lower = hex_only.to_ascii_lowercase();
    let pairs: Vec<&str> = (0..32).map(|i| &lower[i * 2..i * 2 + 2]).collect();
    Ok(pairs.join(":"))
}

pub fn is_kill_switch_enabled(cli_no_saved: bool, env_val: Option<&str>) -> bool {
    if cli_no_saved {
        return true;
    }
    matches!(
        env_val.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Build the Linux `secret-tool store` invocation plan.
/// The password is written exclusively to `stdin`, never `argv`.
pub fn build_linux_secret_tool_store_plan(
    scope: &RdpCredentialScope,
    cred: &StoredRdpCredential,
) -> Result<(String, Vec<String>, String)> {
    if scope.org_id.trim().is_empty() || scope.device_id.trim().is_empty() {
        bail!("credential scope org_id and device_id must not be empty");
    }
    let qualified = cred.qualified_username();
    if qualified.trim().is_empty() {
        bail!("RDP username must not be empty");
    }
    let label = format!("MeshHarbor RDP ({})", scope.store_target_name());
    let args = vec![
        "store".to_string(),
        format!("--label={label}"),
        "service".to_string(),
        "meshharbor-rdp".to_string(),
        "org".to_string(),
        scope.org_id.clone(),
        "device".to_string(),
        scope.device_id.clone(),
        "username".to_string(),
        qualified,
    ];
    let stdin_payload = format!("{}\n", cred.password());
    Ok(("secret-tool".to_string(), args, stdin_payload))
}

/// Build the macOS `/usr/bin/security -i` (interactive stdin) invocation plan.
/// Passing `-i` reads the `add-generic-password` command from `stdin` so `-w`
/// never appears in the process `argv` table (`ps`).
pub fn build_macos_security_store_plan(
    scope: &RdpCredentialScope,
    cred: &StoredRdpCredential,
) -> Result<(String, Vec<String>, String)> {
    if scope.org_id.trim().is_empty() || scope.device_id.trim().is_empty() {
        bail!("credential scope org_id and device_id must not be empty");
    }
    let qualified = cred.qualified_username();
    if qualified.trim().is_empty() {
        bail!("RDP username must not be empty");
    }
    if cred.password().contains('\n')
        || cred.password().contains('\r')
        || cred.password().contains('\0')
    {
        bail!("RDP password must not contain control newline/NUL characters");
    }
    let service = scope.store_target_name();
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let stdin_cmd = format!(
        "add-generic-password -U -a \"{}\" -s \"{}\" -w \"{}\"\n",
        esc(&qualified),
        esc(&service),
        esc(cred.password())
    );
    Ok((
        "/usr/bin/security".to_string(),
        vec!["-i".to_string()],
        stdin_cmd,
    ))
}

/// Pure session planner that enforces all X17 security invariants:
/// - Default OFF (neither reads nor writes `store` unless explicitly opted in).
/// - Kill switch (`--no-saved-credentials` or `MESHHARBOR_RDP_PASSWORDLESS_DISABLED=1`).
/// - `--clear-credentials` deletes from `store` and returns `Ok(None)`.
/// - Rejects non-loopback tunnel addresses and forbidden extra arguments.
/// - Pins target TLS certificate SHA-256 fingerprint when available.
pub fn plan_rdp_session(
    opts: &RdpCliOptions,
    device: &ResolvedRdpDevice,
    local_tunnel_addr: SocketAddr,
    store: &dyn RdpCredentialStore,
    password_prompt: Option<&str>,
    kill_switch_env_val: Option<&str>,
    platform: &str,
) -> Result<Option<PlannedRdpInvocation>> {
    validate_extra_client_args(&opts.extra_args)?;
    if opts.port == 0 {
        bail!("remote RDP port must be between 1 and 65535");
    }
    if !local_tunnel_addr.ip().is_loopback() {
        bail!(
            "local RDP tunnel address {} must be a loopback address (127.0.0.1 or ::1)",
            local_tunnel_addr
        );
    }

    let (target_user, _target_host) = parse_user_and_device(&opts.target)?;
    let scope = RdpCredentialScope {
        org_id: device.org_id.clone(),
        device_id: device.device_id.clone(),
    };

    if opts.clear_credentials {
        let _ = store.delete(&scope)?;
        return Ok(None);
    }

    if is_kill_switch_enabled(opts.no_saved_credentials, kill_switch_env_val)
        && (opts.save_credentials || opts.use_saved_credentials)
    {
        bail!(
            "saved RDP credentials are disabled by kill switch (--no-saved-credentials or {}=1)",
            KILL_SWITCH_ENV
        );
    }

    let explicit_user = opts
        .user
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(ToOwned::to_owned)
        .or(target_user);

    let explicit_domain = opts
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(ToOwned::to_owned);

    let pinned_cert_sha256 = match opts.cert_sha256.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(normalize_cert_sha256(raw)?),
        _ => None,
    };

    let platform_norm = platform.trim().to_ascii_lowercase();
    if platform_norm == "windows" && pinned_cert_sha256.is_some() {
        bail!(
            "--cert-sha256 is not supported on Windows because mstsc.exe validates server certificates via the Windows trust store and does not accept a SHA-256 fingerprint pin; use FreeRDP on Linux/macOS for --cert-sha256 pinning"
        );
    }

    let mut active_cred: Option<StoredRdpCredential> = None;

    if opts.save_credentials {
        let user = explicit_user.clone().context(
            "--save-credentials requires an RDP username (via `--user <name>` or `<user>@<device>`)",
        )?;
        let pw = password_prompt
            .filter(|p| !p.is_empty())
            .context("--save-credentials requires a non-empty RDP password from stdin/prompt")?;
        let cred = StoredRdpCredential::new(user, explicit_domain.clone(), pw);
        store.save(&scope, &cred)?;
        if opts.use_saved_credentials {
            active_cred = Some(cred);
        }
    }

    if opts.use_saved_credentials && active_cred.is_none() {
        let loaded = store.load(&scope)?.with_context(|| {
            format!(
                "no saved RDP credential found in local OS store for device '{}' ({}); run once with --save-credentials first",
                device.device_name,
                scope.store_target_name()
            )
        })?;
        active_cred = Some(loaded);
    }

    let effective_user = active_cred
        .as_ref()
        .map(|c| c.username.clone())
        .or(explicit_user);
    let effective_domain = active_cred
        .as_ref()
        .and_then(|c| c.domain.clone())
        .or(explicit_domain);

    let dial_endpoint = format!("{}:{}", local_tunnel_addr.ip(), local_tunnel_addr.port());

    if platform_norm == "windows" {
        let mut args = vec![format!("/v:{dial_endpoint}")];
        args.extend(opts.extra_args.iter().cloned());
        let windows_session_target = if active_cred.is_some() {
            if local_tunnel_addr.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                || local_tunnel_addr.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            {
                bail!(
                    "refusing shared loopback address {} for Windows TERMSRV credential target; allocate a unique per-session 127.77.x.y loopback IP",
                    local_tunnel_addr.ip()
                );
            }
            Some(format!("TERMSRV/{}", local_tunnel_addr.ip()))
        } else {
            None
        };
        Ok(Some(PlannedRdpInvocation {
            program: "mstsc.exe".to_string(),
            args,
            env: BTreeMap::new(),
            stdin_payload: None,
            windows_session_target,
            pinned_cert_sha256,
            local_tunnel_addr,
        }))
    } else {
        let mut args = vec![format!("/v:{dial_endpoint}")];
        if let Some(u) = &effective_user {
            args.push(format!("/u:{u}"));
        }
        if let Some(d) = &effective_domain {
            args.push(format!("/d:{d}"));
        }
        if let Some(fp) = &pinned_cert_sha256 {
            args.push(format!("/cert:fingerprint:sha256:{fp}"));
        }
        let stdin_payload = if let Some(cred) = &active_cred {
            args.push("/from-stdin:force".to_string());
            Some(cred.password().to_string())
        } else {
            None
        };
        args.extend(opts.extra_args.iter().cloned());
        Ok(Some(PlannedRdpInvocation {
            program: resolve_freerdp_program(),
            args,
            env: BTreeMap::new(),
            stdin_payload,
            windows_session_target: None,
            pinned_cert_sha256,
            local_tunnel_addr,
        }))
    }
}

/// Real OS secure credential store implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRdpCredentialStore;

impl RdpCredentialStore for OsRdpCredentialStore {
    fn save(&self, scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()> {
        os_store::save(scope, cred)
    }

    fn load(&self, scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        os_store::load(scope)
    }

    fn delete(&self, scope: &RdpCredentialScope) -> Result<bool> {
        os_store::delete(scope)
    }
}

/// Ephemeral session-scoped `CRED_TYPE_DOMAIN_PASSWORD` entry in Windows
/// Credential Manager (`TERMSRV/127.0.0.1`) that is automatically removed on drop.
#[derive(Debug)]
pub struct WindowsSessionTargetGuard {
    target: String,
}

impl WindowsSessionTargetGuard {
    pub fn install(target: &str, cred: &StoredRdpCredential) -> Result<Self> {
        os_store::install_windows_session_target(target, cred)?;
        Ok(Self {
            target: target.to_string(),
        })
    }

    pub fn exists(target: &str) -> Result<bool> {
        os_store::windows_session_target_exists(target)
    }

    pub fn read(target: &str) -> Result<Option<StoredRdpCredential>> {
        os_store::read_windows_session_target(target)
    }
}

impl Drop for WindowsSessionTargetGuard {
    fn drop(&mut self) {
        let _ = os_store::remove_windows_session_target(&self.target);
    }
}

#[cfg(windows)]
mod os_store {
    use super::{RdpCredentialScope, StoredRdpCredential};
    use anyhow::{Result, bail};
    use core::ffi::c_void;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    const CRED_TYPE_GENERIC: u32 = 1;
    const CRED_TYPE_DOMAIN_PASSWORD: u32 = 2;
    const CRED_PERSIST_SESSION: u32 = 1;
    const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
    const ERROR_NOT_FOUND: u32 = 1168;

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    #[repr(C)]
    struct CredentialW {
        flags: u32,
        cred_type: u32,
        target_name: *mut u16,
        comment: *mut u16,
        last_written: FileTime,
        credential_blob_size: u32,
        credential_blob: *mut u8,
        persist: u32,
        attribute_count: u32,
        attributes: *mut c_void,
        target_alias: *mut u16,
        user_name: *mut u16,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn CredWriteW(credential: *const CredentialW, flags: u32) -> i32;
        fn CredReadW(
            target_name: *const u16,
            cred_type: u32,
            flags: u32,
            credential: *mut *mut CredentialW,
        ) -> i32;
        fn CredDeleteW(target_name: *const u16, cred_type: u32, flags: u32) -> i32;
        fn CredFree(buffer: *const c_void);
    }

    fn to_wide_null(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        std::ffi::OsString::from_wide(slice)
            .to_string_lossy()
            .into_owned()
    }

    fn write_cred(
        target: &str,
        cred_type: u32,
        persist: u32,
        qualified_user: &str,
        password: &str,
    ) -> Result<()> {
        let mut target_w = to_wide_null(target);
        let mut user_w = to_wide_null(qualified_user);
        let mut blob_u16: Vec<u16> = password.encode_utf16().collect();
        let blob_bytes_len = (blob_u16.len() * 2) as u32;
        let raw = CredentialW {
            flags: 0,
            cred_type,
            target_name: target_w.as_mut_ptr(),
            comment: core::ptr::null_mut(),
            last_written: FileTime::default(),
            credential_blob_size: blob_bytes_len,
            credential_blob: if blob_u16.is_empty() {
                core::ptr::null_mut()
            } else {
                blob_u16.as_mut_ptr() as *mut u8
            },
            persist,
            attribute_count: 0,
            attributes: core::ptr::null_mut(),
            target_alias: core::ptr::null_mut(),
            user_name: user_w.as_mut_ptr(),
        };
        let ok = unsafe { CredWriteW(&raw, 0) };
        for w in &mut blob_u16 {
            unsafe { std::ptr::write_volatile(w, 0) };
        }
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            bail!("CredWriteW failed for '{target}': {err}");
        }
        Ok(())
    }

    fn read_cred(target: &str, cred_type: u32) -> Result<Option<StoredRdpCredential>> {
        let target_w = to_wide_null(target);
        let mut ptr: *mut CredentialW = core::ptr::null_mut();
        let ok = unsafe { CredReadW(target_w.as_ptr(), cred_type, 0, &mut ptr) };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                return Ok(None);
            }
            bail!("CredReadW failed for '{target}': {err}");
        }
        let res = unsafe {
            let c = &*ptr;
            let user_str = wide_ptr_to_string(c.user_name);
            let u16_len = (c.credential_blob_size as usize) / 2;
            let pw_str = if c.credential_blob.is_null() || u16_len == 0 {
                String::new()
            } else {
                let slice = std::slice::from_raw_parts(c.credential_blob as *const u16, u16_len);
                String::from_utf16_lossy(slice)
            };
            StoredRdpCredential::from_qualified_username(&user_str, pw_str)
        };
        unsafe { CredFree(ptr as *const c_void) };
        Ok(Some(res))
    }

    fn delete_cred(target: &str, cred_type: u32) -> Result<bool> {
        let target_w = to_wide_null(target);
        let ok = unsafe { CredDeleteW(target_w.as_ptr(), cred_type, 0) };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                return Ok(false);
            }
            bail!("CredDeleteW failed for '{target}': {err}");
        }
        Ok(true)
    }

    pub fn save(scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()> {
        write_cred(
            &scope.store_target_name(),
            CRED_TYPE_GENERIC,
            CRED_PERSIST_LOCAL_MACHINE,
            &cred.qualified_username(),
            cred.password(),
        )
    }

    pub fn load(scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        read_cred(&scope.store_target_name(), CRED_TYPE_GENERIC)
    }

    pub fn delete(scope: &RdpCredentialScope) -> Result<bool> {
        delete_cred(&scope.store_target_name(), CRED_TYPE_GENERIC)
    }

    pub fn install_windows_session_target(target: &str, cred: &StoredRdpCredential) -> Result<()> {
        if target.eq_ignore_ascii_case("TERMSRV/127.0.0.1")
            || target.eq_ignore_ascii_case("TERMSRV/localhost")
        {
            bail!(
                "refusing to write shared Windows credential target '{target}'; use a unique per-session 127.77.x.y loopback address"
            );
        }
        if windows_session_target_exists(target)? {
            bail!("refusing to overwrite existing Windows credential target '{target}'");
        }
        let domain_user = match cred.domain.as_deref() {
            Some(d) => format!(r"{d}\{}", cred.username),
            None if cred.username.contains('\\') || cred.username.contains('@') => {
                cred.username.clone()
            }
            None => format!(r".\{}", cred.username),
        };
        write_cred(
            target,
            CRED_TYPE_GENERIC,
            CRED_PERSIST_SESSION,
            &cred.qualified_username(),
            cred.password(),
        )?;
        let _ = write_cred(
            target,
            CRED_TYPE_DOMAIN_PASSWORD,
            CRED_PERSIST_SESSION,
            &domain_user,
            cred.password(),
        );
        Ok(())
    }

    pub fn windows_session_target_exists(target: &str) -> Result<bool> {
        Ok(read_cred(target, CRED_TYPE_GENERIC)?.is_some()
            || read_cred(target, CRED_TYPE_DOMAIN_PASSWORD)
                .unwrap_or(None)
                .is_some())
    }

    pub fn read_windows_session_target(target: &str) -> Result<Option<StoredRdpCredential>> {
        if let Some(c) = read_cred(target, CRED_TYPE_GENERIC)? {
            return Ok(Some(c));
        }
        Ok(read_cred(target, CRED_TYPE_DOMAIN_PASSWORD).unwrap_or(None))
    }

    pub fn remove_windows_session_target(target: &str) -> Result<bool> {
        let gen_removed = delete_cred(target, CRED_TYPE_GENERIC)?;
        let dom_removed = delete_cred(target, CRED_TYPE_DOMAIN_PASSWORD).unwrap_or(false);
        Ok(gen_removed || dom_removed)
    }
}

#[cfg(target_os = "linux")]
mod os_store {
    use super::{
        RdpCredentialScope, StoredRdpCredential, build_linux_secret_tool_store_plan,
        parse_linux_secret_tool_username,
    };
    use anyhow::{Context, Result, bail};
    use std::io::Write;
    use std::process::{Command, Stdio};

    pub fn save(scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()> {
        let _ = delete(scope);
        let (prog, args, stdin_payload) = build_linux_secret_tool_store_plan(scope, cred)?;
        let mut child = Command::new(&prog)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn `secret-tool` (install libsecret-tools)")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_payload.as_bytes())
                .context("failed to write secret to `secret-tool` stdin")?;
        }
        let out = child
            .wait_with_output()
            .context("failed waiting for `secret-tool store`")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("`secret-tool store` failed: {}", stderr.trim());
        }
        Ok(())
    }

    pub fn load(scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        let pw_out = Command::new("secret-tool")
            .args([
                "lookup",
                "service",
                "meshharbor-rdp",
                "org",
                &scope.org_id,
                "device",
                &scope.device_id,
            ])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `secret-tool lookup`")?;
        if !pw_out.status.success() {
            return Ok(None);
        }
        let pw = String::from_utf8_lossy(&pw_out.stdout)
            .trim_end_matches(&['\r', '\n'][..])
            .to_string();
        if pw.is_empty() {
            return Ok(None);
        }
        // Look up the stored entry's username attribute via secret-tool search;
        // fail closed if missing or empty (never fall back to a guessed username).
        let out = Command::new("secret-tool")
            .args([
                "search",
                "--all",
                "service",
                "meshharbor-rdp",
                "org",
                &scope.org_id,
                "device",
                &scope.device_id,
            ])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `secret-tool search`")?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        let user = parse_linux_secret_tool_username(&combined).with_context(|| {
            format!(
                "invalid stored credential for {}",
                scope.store_target_name()
            )
        })?;
        Ok(Some(StoredRdpCredential::from_qualified_username(
            &user, pw,
        )))
    }

    pub fn delete(scope: &RdpCredentialScope) -> Result<bool> {
        let out = Command::new("secret-tool")
            .args([
                "clear",
                "service",
                "meshharbor-rdp",
                "org",
                &scope.org_id,
                "device",
                &scope.device_id,
            ])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `secret-tool clear`")?;
        Ok(out.status.success())
    }

    pub fn install_windows_session_target(
        _target: &str,
        _cred: &StoredRdpCredential,
    ) -> Result<()> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn windows_session_target_exists(_target: &str) -> Result<bool> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn read_windows_session_target(_target: &str) -> Result<Option<StoredRdpCredential>> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn remove_windows_session_target(_target: &str) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(target_os = "macos")]
mod os_store {
    use super::{RdpCredentialScope, StoredRdpCredential, build_macos_security_store_plan};
    use anyhow::{Context, Result, bail};
    use std::io::Write;
    use std::process::{Command, Stdio};

    pub fn save(scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()> {
        let (prog, args, stdin_payload) = build_macos_security_store_plan(scope, cred)?;
        let mut child = Command::new(&prog)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn `/usr/bin/security -i`")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_payload.as_bytes())
                .context("failed writing to `/usr/bin/security -i` stdin")?;
        }
        let out = child
            .wait_with_output()
            .context("failed waiting for `/usr/bin/security -i`")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("`/usr/bin/security -i` failed: {}", stderr.trim());
        }
        Ok(())
    }

    pub fn load(scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        let service = scope.store_target_name();
        let meta = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", &service])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `/usr/bin/security find-generic-password`")?;
        if !meta.status.success() {
            return Ok(None);
        }
        let stdout = String::from_utf8_lossy(&meta.stdout);
        let mut acct = String::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("\"acct\"<blob>=") {
                if let Some((_, rhs)) = trimmed.split_once('=') {
                    acct = rhs.trim().trim_matches('"').to_string();
                    break;
                }
            }
        }
        let pw_out = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", &service, "-w"])
            .stdin(Stdio::null())
            .output()
            .context("failed to read password from macOS Keychain")?;
        if !pw_out.status.success() {
            return Ok(None);
        }
        let pw = String::from_utf8_lossy(&pw_out.stdout)
            .trim_end_matches(&['\r', '\n'][..])
            .to_string();
        if pw.is_empty() {
            return Ok(None);
        }
        if acct.trim().is_empty() {
            bail!(
                "stored RDP credential in macOS Keychain for '{}' is missing account/username attribute; refusing fallback username",
                service
            );
        }
        Ok(Some(StoredRdpCredential::from_qualified_username(
            acct.trim(),
            pw,
        )))
    }

    pub fn delete(scope: &RdpCredentialScope) -> Result<bool> {
        let service = scope.store_target_name();
        let out = Command::new("/usr/bin/security")
            .args(["delete-generic-password", "-s", &service])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `/usr/bin/security delete-generic-password`")?;
        Ok(out.status.success())
    }

    pub fn install_windows_session_target(
        _target: &str,
        _cred: &StoredRdpCredential,
    ) -> Result<()> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn windows_session_target_exists(_target: &str) -> Result<bool> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn read_windows_session_target(_target: &str) -> Result<Option<StoredRdpCredential>> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn remove_windows_session_target(_target: &str) -> Result<bool> {
        Ok(false)
    }
}

fn read_password_from_stdin_or_tty(user: &str, device_name: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        let prompt = format!("RDP password for {user}@{device_name} (saved locally): ");
        let pw = rpassword::prompt_password(prompt)
            .context("failed reading RDP password from terminal")?;
        if pw.is_empty() {
            bail!("RDP password must not be empty");
        }
        Ok(pw)
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed reading RDP password from stdin")?;
        let trimmed = buf.trim_end_matches(&['\r', '\n'][..]).to_string();
        if trimmed.is_empty() {
            bail!("RDP password on stdin must not be empty");
        }
        Ok(trimmed)
    }
}

/// Strictly resolve a target device and its owning organization's real
/// `tenant_id` and `node_id` from the local daemon's `NodeStatus` and
/// `PeerInfo` table. Fails closed if the peer is unknown, ambiguous across
/// organizations, or missing a real `tenant_id`, `node_id`, or `overlay_ip`.
pub fn resolve_peer_scope(
    status: &localapi::NodeStatus,
    peers: &[localapi::PeerInfo],
    target_host: &str,
) -> Result<(ResolvedRdpDevice, String, Option<u16>)> {
    let trimmed = target_host.trim();
    if trimmed.is_empty() {
        bail!("target device must not be empty");
    }

    let (org_filter, peer_selector) = match trimmed.split_once('/') {
        Some((org_part, host_part)) => {
            let o = org_part.trim();
            let h = host_part.trim();
            if o.is_empty() || h.is_empty() {
                bail!("invalid '<org>/<device>' target '{trimmed}'");
            }
            (Some(o), h)
        }
        None => (None, trimmed),
    };

    let matches: Vec<&localapi::PeerInfo> = peers
        .iter()
        .filter(|p| {
            if let Some(of) = org_filter {
                let org_matches_label = p.org.eq_ignore_ascii_case(of)
                    || (p.org.is_empty() && of.eq_ignore_ascii_case("primary"));
                let org_matches_tenant = status
                    .orgs
                    .iter()
                    .find(|o| {
                        o.label.eq_ignore_ascii_case(&p.org)
                            || (p.org.is_empty() && o.primary)
                            || (p.org.eq_ignore_ascii_case("primary") && o.primary)
                    })
                    .and_then(|o| o.tenant_id.as_deref())
                    .is_some_and(|tid| tid.eq_ignore_ascii_case(of));
                if !org_matches_label && !org_matches_tenant {
                    return false;
                }
            }
            p.node_id.eq_ignore_ascii_case(peer_selector)
                || p.agent_id
                    .as_deref()
                    .is_some_and(|aid| aid.eq_ignore_ascii_case(peer_selector))
                || p.name.eq_ignore_ascii_case(peer_selector)
                || p.overlay_ip.as_deref() == Some(peer_selector)
        })
        .collect();

    if matches.is_empty() {
        bail!(
            "target device '{trimmed}' was not found in the local daemon peer list; refusing to fall back to an unverified device name"
        );
    }
    if matches.len() > 1 {
        bail!(
            "target device '{trimmed}' is ambiguous across {} peers/organizations; specify the exact node_id or '<org>/<device>'",
            matches.len()
        );
    }

    let peer = matches[0];
    let device_id = {
        let nid = peer.node_id.trim();
        if !nid.is_empty() && !nid.eq_ignore_ascii_case(&peer.name) {
            nid.to_string()
        } else if let Some(aid) = peer
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            aid.to_string()
        } else if !nid.is_empty() {
            nid.to_string()
        } else {
            bail!(
                "peer '{}' has no real node_id or agent_id; refusing to derive credential scope",
                peer.name
            );
        }
    };

    let peer_org_label = peer.org.trim();
    let resolved_tenant_id: Option<&str> = if !status.orgs.is_empty() {
        if !peer_org_label.is_empty() {
            status
                .orgs
                .iter()
                .find(|o| {
                    o.label.eq_ignore_ascii_case(peer_org_label)
                        || (peer_org_label.eq_ignore_ascii_case("primary") && o.primary)
                })
                .and_then(|o| {
                    o.tenant_id.as_deref().or(if o.primary {
                        status.tenant_id.as_deref()
                    } else {
                        None
                    })
                })
        } else if status.orgs.len() == 1 {
            status.orgs[0]
                .tenant_id
                .as_deref()
                .or(status.tenant_id.as_deref())
        } else {
            None
        }
    } else if peer_org_label.is_empty() || peer_org_label.eq_ignore_ascii_case("primary") {
        status.tenant_id.as_deref()
    } else {
        None
    };

    let org_id = resolved_tenant_id
        .map(str::trim)
        .filter(|tid| !tid.is_empty() && !tid.eq_ignore_ascii_case("primary"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot resolve real tenant_id for device '{}' (org '{}'); refusing to fall back to label",
                peer.name,
                peer.org
            )
        })?
        .to_string();

    let dial_ip = peer
        .overlay_ip
        .as_deref()
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "device '{}' ({}) has no overlay IP in the local daemon peer list",
                peer.name,
                device_id
            )
        })?
        .to_string();

    let device_name = if peer.name.trim().is_empty() {
        device_id.clone()
    } else {
        peer.name.trim().to_string()
    };

    Ok((
        ResolvedRdpDevice {
            org_id,
            device_id,
            device_name,
        },
        dial_ip,
        status.overlay_socks5_port,
    ))
}

async fn resolve_target_device(
    target_host: &str,
) -> Result<(ResolvedRdpDevice, String, Option<u16>)> {
    let mut client = localapi::connect().await.context(
        "failed to connect to local MeshHarbor daemon (meshharbord) to resolve device identity",
    )?;
    let status = client
        .status()
        .await
        .context("failed to query local daemon status for organization tenant_id")?;
    let peers = client
        .peers()
        .await
        .context("failed to query local daemon peer list for device identity")?;
    resolve_peer_scope(&status, &peers, target_host)
}

async fn bind_unique_session_loopback_listener() -> Result<tokio::net::TcpListener> {
    let mut last_err = None;
    for _ in 0..8 {
        let ip = allocate_session_loopback_ip();
        match tokio::net::TcpListener::bind((ip, 0)).await {
            Ok(listener) => return Ok(listener),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::other("failed to bind unique 127.77.x.y session loopback listener")
    }))
    .context("failed to bind local per-session loopback listener for RDP tunnel")
}

/// Top-level `mh rdp` execution entrypoint.
pub async fn run(opts: RdpCliOptions) -> Result<i32> {
    validate_extra_client_args(&opts.extra_args)?;
    let (parsed_user, target_host) = parse_user_and_device(&opts.target)?;
    let (device, dial_ip, socks_port) = resolve_target_device(&target_host).await?;
    let store = OsRdpCredentialStore;
    let kill_env = std::env::var(KILL_SWITCH_ENV).ok();

    if opts.clear_credentials {
        let placeholder =
            SocketAddr::new(std::net::IpAddr::V4(allocate_session_loopback_ip()), 3389);
        let _ = plan_rdp_session(
            &opts,
            &device,
            placeholder,
            &store,
            None,
            kill_env.as_deref(),
            std::env::consts::OS,
        )?;
        return Ok(0);
    }

    if is_kill_switch_enabled(opts.no_saved_credentials, kill_env.as_deref())
        && (opts.save_credentials || opts.use_saved_credentials)
    {
        bail!(
            "saved RDP credentials are disabled by kill switch (--no-saved-credentials or {}=1)",
            KILL_SWITCH_ENV
        );
    }

    let prompt_pw = if opts.save_credentials {
        let user_for_prompt = opts.user.as_deref().or(parsed_user.as_deref()).context(
            "--save-credentials requires an RDP username (`--user <u>` or `<user>@<device>`)",
        )?;
        Some(read_password_from_stdin_or_tty(
            user_for_prompt,
            &device.device_name,
        )?)
    } else {
        None
    };

    // Bind a per-session local loopback listener in 127.77.x.y:0 (never shared
    // 127.0.0.1) and bridge each accepted TCP stream to the target device's RDP
    // port (via overlay SOCKS5 in netstack mode, or direct overlay TCP in OS-TUN mode).
    let listener = bind_unique_session_loopback_listener().await?;
    let local_addr = listener.local_addr()?;

    let plan = plan_rdp_session(
        &opts,
        &device,
        local_addr,
        &store,
        prompt_pw.as_deref(),
        kill_env.as_deref(),
        std::env::consts::OS,
    )?
    .context("internal error: expected an RDP invocation plan")?;

    let scope = RdpCredentialScope {
        org_id: device.org_id.clone(),
        device_id: device.device_id.clone(),
    };
    let _win_guard = if let Some(target) = &plan.windows_session_target {
        let cred = store
            .load(&scope)?
            .context("missing stored credential for Windows session target")?;
        Some(WindowsSessionTargetGuard::install(target, &cred)?)
    } else {
        None
    };

    let forward_host = dial_ip.clone();
    let forward_port = opts.port;
    let pump_task = tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let h = forward_host.clone();
            tokio::spawn(async move {
                let upstream_res = match socks_port {
                    Some(sp) => {
                        match tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, sp))
                            .await
                        {
                            Ok(mut s) => {
                                if tunnel_core::socks5::client_connect(&mut s, &h, forward_port)
                                    .await
                                    .is_ok()
                                {
                                    Ok(s)
                                } else {
                                    Err(std::io::Error::other("SOCKS5 connect failed"))
                                }
                            }
                            Err(e) => Err(e),
                        }
                    }
                    None => tokio::net::TcpStream::connect((h.as_str(), forward_port)).await,
                };
                if let Ok(mut remote) = upstream_res {
                    let _ = tcp.set_nodelay(true);
                    let _ = remote.set_nodelay(true);
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut remote).await;
                }
            });
        }
    });

    let mut cmd = Command::new(&plan.program);
    cmd.args(&plan.args).envs(&plan.env);
    if plan.stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to launch native RDP client '{}'", plan.program))?;
    if let (Some(payload), Some(mut child_stdin)) =
        (plan.stdin_payload.as_ref(), child.stdin.take())
    {
        child_stdin
            .write_all(format!("{payload}\n").as_bytes())
            .context("failed passing RDP credential to client stdin")?;
    }
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .context("RDP client wait task panicked")?
        .context("failed waiting for native RDP client")?;
    pump_task.abort();
    Ok(status.code().unwrap_or(1))
}
