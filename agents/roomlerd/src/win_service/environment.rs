// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! SCM `Environment` registry-value helpers.
//!
//! The Service Control Manager passes a service's startup environment
//! block from the `REG_MULTI_SZ` value `Environment` under
//! `HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE_NAME>\`. This
//! module reads + writes that value, so the installer wizard's
//! SystemContext mode can flip `ROOMLERD_ENABLE_SYSTEM_SWAP=1`
//! (and similar) without an operator shell.
//!
//! **NOT** in [`crate::service`] — that module wraps the cross-platform
//! Scheduled Task / systemd / launchd auto-start hooks. The SCM
//! Environment block is per-service and only meaningful on Windows
//! when the service is registered, so it lives next to the SCM-aware
//! [`crate::win_service`] code.
//!
//! ## REG_MULTI_SZ wire format
//!
//! The SCM expects:
//!
//! ```text
//! name1=value1\0name2=value2\0\0     (UTF-16-LE, NUL-separated, double-NUL terminator)
//! ```
//!
//! Empty environment is a single NUL pair: `\0\0`.
//!
//! ## SCM does NOT auto-reload Environment changes
//!
//! After [`set_service_env_var`], call [`restart_service`] to make
//! the new env block take effect. A running service continues to
//! see its previous Environment until the SCM hands it a fresh
//! process at next start.

#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use std::ptr;
use std::time::{Duration, Instant};
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_MULTI_SZ, RegCloseKey,
    RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

use super::resolved_service_name;

const ENV_KEY_PREFIX: &str = r"SYSTEM\CurrentControlSet\Services\";
const ENV_VALUE_NAME: &str = "Environment";

// ─── pure encoder / decoder ────────────────────────────────────────────────────

/// Encode `(name, value)` pairs into the UTF-16-LE byte stream the
/// SCM expects under REG_MULTI_SZ. Always emits the trailing
/// double-NUL.
///
/// An empty input encodes as `[0x00, 0x00]` (a single u16 NUL,
/// preceded by no entries — the second NUL of the "double-NUL
/// terminator" is the only NUL present, which matches what Windows
/// writes for empty Environment blocks).
pub fn encode_multi_sz(pairs: &[(String, String)]) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for (name, value) in pairs {
        let entry = format!("{name}={value}");
        out.extend(entry.encode_utf16());
        out.push(0);
    }
    out.push(0); // final terminating NUL
    out
}

/// Inverse of [`encode_multi_sz`]. Tolerates the (rare) case where
/// the buffer lacks the trailing NUL — some Windows builds omit it
/// on read-back of empty REG_MULTI_SZ values.
///
/// Entries without an `=` sign are dropped silently (cannot represent
/// them as `(name, value)`); this matches CreateProcess's behaviour
/// of ignoring malformed env-block entries.
pub fn decode_multi_sz(buf: &[u16]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, &w) in buf.iter().enumerate() {
        if w == 0 {
            if i > start {
                let entry = String::from_utf16_lossy(&buf[start..i]);
                if let Some((name, value)) = entry.split_once('=') {
                    out.push((name.to_string(), value.to_string()));
                }
            }
            start = i + 1;
        }
    }
    // Handle the case where the buffer ends without a trailing NUL.
    if start < buf.len() {
        let entry = String::from_utf16_lossy(&buf[start..]);
        if let Some((name, value)) = entry.split_once('=') {
            out.push((name.to_string(), value.to_string()));
        }
    }
    out
}

/// Pure read-modify-write: produce the new pair-list when setting
/// `name=value`. Replaces in-place when `name` already exists;
/// appends when new. Preserves order of unrelated entries.
pub fn rmw_set(pairs: Vec<(String, String)>, name: &str, value: &str) -> Vec<(String, String)> {
    let mut found = false;
    let mut out: Vec<(String, String)> = pairs
        .into_iter()
        .map(|(n, v)| {
            if !found && n.eq_ignore_ascii_case(name) {
                found = true;
                (n, value.to_string())
            } else {
                (n, v)
            }
        })
        .collect();
    if !found {
        out.push((name.to_string(), value.to_string()));
    }
    out
}

/// Pure read-modify-write: remove `name` from the pair list (case-
/// insensitive on the name). No-op when `name` is missing.
pub fn rmw_unset(pairs: Vec<(String, String)>, name: &str) -> Vec<(String, String)> {
    pairs
        .into_iter()
        .filter(|(n, _)| !n.eq_ignore_ascii_case(name))
        .collect()
}

// ─── SCM-side IO ──────────────────────────────────────────────────────────────

fn service_env_key_path() -> String {
    format!("{ENV_KEY_PREFIX}{}", resolved_service_name())
}

fn wide_with_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// RAII wrapper so we never leak HKEY handles.
struct OpenKey(HKEY);
impl Drop for OpenKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle was returned by RegOpenKeyExW.
            unsafe { RegCloseKey(self.0) };
        }
    }
}

fn open_service_key(access: u32) -> Result<OpenKey> {
    let path = service_env_key_path();
    let wpath = wide_with_nul(&path);
    let mut out: HKEY = ptr::null_mut();
    // SAFETY: wpath is NUL-terminated and lives through the call.
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wpath.as_ptr(), 0, access, &mut out) };
    if rc != ERROR_SUCCESS {
        anyhow::bail!("RegOpenKeyExW(HKLM\\{path}, access={access:#x}) failed: error {rc}");
    }
    Ok(OpenKey(out))
}

/// Read the `Environment` REG_MULTI_SZ value. Missing-value returns
/// an empty list (SCM-equivalent of "no environment overrides").
pub fn read_service_env() -> Result<Vec<(String, String)>> {
    let key = open_service_key(KEY_QUERY_VALUE)?;
    let wname = wide_with_nul(ENV_VALUE_NAME);
    let mut buf_len: u32 = 0;
    let mut value_type: u32 = 0;
    // Size the buffer first.
    // SAFETY: standard double-call pattern.
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            wname.as_ptr(),
            ptr::null_mut(),
            &mut value_type,
            ptr::null_mut(),
            &mut buf_len,
        )
    };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(Vec::new());
    }
    if rc != ERROR_SUCCESS {
        anyhow::bail!("RegQueryValueExW(Environment) failed: error {rc}");
    }
    if value_type != REG_MULTI_SZ {
        anyhow::bail!("Environment value has unexpected type {value_type} (expected REG_MULTI_SZ)");
    }
    if buf_len == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0u8; buf_len as usize];
    // SAFETY: bytes has buf_len capacity; we pass it back as the size.
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            wname.as_ptr(),
            ptr::null_mut(),
            &mut value_type,
            bytes.as_mut_ptr(),
            &mut buf_len,
        )
    };
    if rc != ERROR_SUCCESS {
        anyhow::bail!("RegQueryValueExW(Environment) read failed: error {rc}");
    }
    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(decode_multi_sz(&wide))
}

/// Read a single named env var. Returns `Ok(None)` when absent.
pub fn read_service_env_var(name: &str) -> Result<Option<String>> {
    let pairs = read_service_env()?;
    Ok(pairs
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v))
}

fn write_service_env(pairs: &[(String, String)]) -> Result<()> {
    let key = open_service_key(KEY_SET_VALUE)?;
    let wname = wide_with_nul(ENV_VALUE_NAME);
    if pairs.is_empty() {
        // No env overrides left: DELETE the `Environment` value rather than write
        // an empty REG_MULTI_SZ. `encode_multi_sz(&[])` yields a single UTF-16
        // null, but a valid (even empty) REG_MULTI_SZ needs a DOUBLE-null
        // terminator — the SCM reads this value to build the service's env block,
        // and a malformed one makes StartServiceW fail with error 87 ("parameter
        // is incorrect"), permanently wedging the service. This was the P3d
        // service-start bug: `disable-system-context`'s unset left an empty list.
        // Deleting the value = the service simply has no env override. Tolerate
        // "value absent" (ERROR_FILE_NOT_FOUND).
        let rc = unsafe { RegDeleteValueW(key.0, wname.as_ptr()) };
        if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
            anyhow::bail!("RegDeleteValueW(Environment) failed: error {rc}");
        }
        return Ok(());
    }
    let encoded = encode_multi_sz(pairs);
    let bytes: Vec<u8> = encoded.iter().flat_map(|w| w.to_le_bytes()).collect();
    // SAFETY: bytes is a flat byte buffer; we pass the byte length.
    let rc = unsafe {
        RegSetValueExW(
            key.0,
            wname.as_ptr(),
            0,
            REG_MULTI_SZ,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if rc != ERROR_SUCCESS {
        anyhow::bail!("RegSetValueExW(Environment) failed: error {rc}");
    }
    Ok(())
}

/// Read-modify-write: set `name=value` in the service's Environment.
/// Preserves all unrelated entries; replaces existing `name` (case-
/// insensitive) in place; appends new.
///
/// Caller must invoke [`restart_service`] for the change to take
/// effect on a currently-running service.
pub fn set_service_env_var(name: &str, value: &str) -> Result<()> {
    let pairs = read_service_env()?;
    let updated = rmw_set(pairs, name, value);
    write_service_env(&updated)
}

/// Read-modify-write: remove `name` from the service's Environment.
/// No-op when `name` is missing. Same restart caveat as
/// [`set_service_env_var`].
pub fn unset_service_env_var(name: &str) -> Result<()> {
    let pairs = read_service_env()?;
    let updated = rmw_unset(pairs, name);
    write_service_env(&updated)
}

// ─── service restart ──────────────────────────────────────────────────────────

/// Stop the service (wait for `STOPPED`), then start (wait for `RUNNING`).
/// `timeout` is per transition; worst-case wall time is ~2 × timeout.
///
/// Returns `Err` when either transition doesn't complete in time — the
/// service is left in whatever state it ended up in; the operator can
/// recover via `services.msc`.
pub fn restart_service(timeout: Duration) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("ServiceManager::local_computer(CONNECT)")?;
    let service = manager
        .open_service(
            resolved_service_name(),
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START,
        )
        .with_context(|| format!("open_service({})", resolved_service_name()))?;

    let status = service.query_status().context("query_status before stop")?;
    if status.current_state == ServiceState::Running
        || status.current_state == ServiceState::StartPending
    {
        let _ = service.stop().context("service.stop()")?;
        wait_for_state(&service, ServiceState::Stopped, timeout).context("waiting for STOPPED")?;
    }

    service.start::<&str>(&[]).context("service.start()")?;
    wait_for_state(&service, ServiceState::Running, timeout).context("waiting for RUNNING")?;
    Ok(())
}

/// FR-84 D3 — start the service if it is not running, and wait for `RUNNING`.
/// The `--as-service` half of `meshharbord service start`; needs `SERVICE_START`
/// on the service, i.e. elevation on a stock install. A service already
/// running (or start-pending) is left alone and reported as success — the
/// SCM supervisor respawns its own worker, so this is only ever needed when
/// the whole service is down.
pub fn start_service(timeout: Duration) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("ServiceManager::local_computer(CONNECT)")?;
    let service = manager
        .open_service(
            resolved_service_name(),
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )
        .with_context(|| format!("open_service({})", resolved_service_name()))?;
    let status = service
        .query_status()
        .context("query_status before start")?;
    if status.current_state == ServiceState::Running {
        return Ok(());
    }
    if status.current_state != ServiceState::StartPending {
        service.start::<&str>(&[]).context("service.start()")?;
    }
    wait_for_state(&service, ServiceState::Running, timeout).context("waiting for RUNNING")?;
    Ok(())
}

/// FR-97 P4d — stop the service if it is running, and wait for `STOPPED`. The
/// `--as-service` half of `meshharbord service stop`, and the same Stop `sc stop`
/// sends: the host asks its worker to leave through the #1683 stop event, so
/// an ephemeral device unenrolls. Needs `SERVICE_STOP` on the service, i.e.
/// elevation on a stock install. A service already stopped is left alone and
/// reported as success.
pub fn stop_service(timeout: Duration) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("ServiceManager::local_computer(CONNECT)")?;
    let service = manager
        .open_service(
            resolved_service_name(),
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )
        .with_context(|| format!("open_service({})", resolved_service_name()))?;
    let status = service.query_status().context("query_status before stop")?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    if status.current_state != ServiceState::StopPending {
        let _ = service.stop().context("service.stop()")?;
    }
    wait_for_state(&service, ServiceState::Stopped, timeout).context("waiting for STOPPED")?;
    Ok(())
}

fn wait_for_state(
    service: &windows_service::service::Service,
    target: ServiceState,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = service.query_status().context("query_status during wait")?;
        if status.current_state == target {
            return Ok(());
        }
        if Instant::now() > deadline {
            anyhow::bail!(
                "timeout: service state {:?}, expected {:?}",
                status.current_state,
                target
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn empty_round_trips() {
        let encoded = encode_multi_sz(&[]);
        let decoded = decode_multi_sz(&encoded);
        assert_eq!(decoded, Vec::<(String, String)>::new());
    }

    #[test]
    fn single_pair_round_trips() {
        let original = pairs(&[("ROOMLERD_ENABLE_SYSTEM_SWAP", "1")]);
        let encoded = encode_multi_sz(&original);
        // expected wire: "ROOMLERD_ENABLE_SYSTEM_SWAP=1\0\0"
        assert_eq!(*encoded.last().unwrap(), 0);
        assert_eq!(encoded[encoded.len() - 2], 0);
        let decoded = decode_multi_sz(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn multiple_pairs_round_trip_in_order() {
        let original = pairs(&[("A", "1"), ("B", "2"), ("C", "3")]);
        let encoded = encode_multi_sz(&original);
        let decoded = decode_multi_sz(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn unicode_value_round_trips() {
        let original = pairs(&[("LOCALE", "日本語"), ("PATH", "C:\\Program Files\\foo")]);
        let encoded = encode_multi_sz(&original);
        let decoded = decode_multi_sz(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_tolerates_missing_trailing_nul() {
        // Manually-constructed buffer that lacks the final NUL.
        let mut buf: Vec<u16> = "FOO=bar".encode_utf16().collect();
        buf.push(0);
        // No second NUL.
        let decoded = decode_multi_sz(&buf);
        assert_eq!(decoded, pairs(&[("FOO", "bar")]));
    }

    #[test]
    fn decode_ignores_entry_without_equals() {
        let mut buf: Vec<u16> = "FOO".encode_utf16().collect();
        buf.push(0);
        buf.extend("BAR=baz".encode_utf16());
        buf.push(0);
        buf.push(0);
        let decoded = decode_multi_sz(&buf);
        assert_eq!(decoded, pairs(&[("BAR", "baz")]));
    }

    #[test]
    fn rmw_set_replaces_existing_in_place() {
        let original = pairs(&[("A", "1"), ("B", "2"), ("C", "3")]);
        let updated = rmw_set(original, "B", "two");
        assert_eq!(updated, pairs(&[("A", "1"), ("B", "two"), ("C", "3")]));
    }

    #[test]
    fn rmw_set_is_case_insensitive_on_name() {
        let original = pairs(&[("Path", "C:\\Win")]);
        let updated = rmw_set(original, "PATH", "C:\\Win;C:\\Bin");
        // Name kept as originally cased; only value updated.
        assert_eq!(updated, pairs(&[("Path", "C:\\Win;C:\\Bin")]));
    }

    #[test]
    fn rmw_set_appends_when_new() {
        let original = pairs(&[("A", "1")]);
        let updated = rmw_set(original, "B", "2");
        assert_eq!(updated, pairs(&[("A", "1"), ("B", "2")]));
    }

    #[test]
    fn rmw_unset_removes_matching_name() {
        let original = pairs(&[("A", "1"), ("B", "2")]);
        let updated = rmw_unset(original, "A");
        assert_eq!(updated, pairs(&[("B", "2")]));
    }

    #[test]
    fn rmw_unset_noop_when_missing() {
        let original = pairs(&[("A", "1")]);
        let updated = rmw_unset(original, "MISSING");
        assert_eq!(updated, pairs(&[("A", "1")]));
    }
}
