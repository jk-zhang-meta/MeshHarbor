// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! F1 — Per-enrollment overlay runtime mode tracking, unprivileged Windows
//! netstack fallback latching, and bounded start-failure backoff.
//!
//! Ungated so [`crate::localapi_state`] and default-feature unit tests can
//! inspect effective overlay mode (`"tun"`, `"netstack"`, `"off"`, or
//! `"error (...)"`), effective loopback SOCKS5 port, and bounded retry state
//! regardless of which overlay cargo features are compiled in.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::AgentConfig;

/// Maximum consecutive overlay start failures for the same config shape before
/// halting automatic respawns (prevents the 25 s keepalive loop from sending
/// `rc:overlay.join` forever when the overlay genuinely cannot start).
pub const MAX_OVERLAY_START_ATTEMPTS: u32 = 3;

/// Backoff delays after attempt 1 and attempt 2 (attempt 3 halts).
/// Attempt 1's 30 s delay ensures the first 25 s keepalive tick is skipped.
pub const OVERLAY_BACKOFF_STEPS: [Duration; 2] =
    [Duration::from_secs(30), Duration::from_secs(60)];

#[derive(Clone, Debug, Default)]
struct OrgOverlayState {
    config_shape_key: Option<String>,
    effective_mode: Option<String>,
    fallback_to_netstack: bool,
    socks_port: Option<u16>,
    failures: u32,
    halted: bool,
    next_retry_at: Option<Instant>,
    last_error: Option<String>,
}

static ORG_OVERLAY_STATE: Mutex<BTreeMap<String, OrgOverlayState>> = Mutex::new(BTreeMap::new());

/// Compute a stable shape key for `cfg`'s overlay configuration so a config
/// change resets any previous failure/halt state.
pub fn shape_key_for_config(cfg: &AgentConfig) -> String {
    format!(
        "{}|{}|{:?}|{:?}|{:?}|{}",
        cfg.tenant_id,
        cfg.server_url,
        cfg.overlay_wg_secret_key,
        cfg.netstack_socks_port,
        cfg.effective_overlay_advertised_routes(),
        cfg.overlay_exit_node.as_deref().unwrap_or("")
    )
}

/// Does this process have sufficient OS privilege to create/configure a real
/// OS TUN adapter (`SystemTun`)?
///
/// - On Windows: requires an elevated token (`TokenIsElevated != 0` or
///   `LocalSystem`); a Medium IL interactive process returns `false` and
///   falls back to the userspace `netstack`.
/// - On Unix: `SystemTun` creation requires root (`geteuid() == 0`), though
///   reactive fallback in `tun_factory` also catches `EPERM`/`EACCES`.
pub fn process_can_create_os_tun() -> bool {
    #[cfg(target_os = "windows")]
    {
        crate::win_identity::process_is_elevated()
    }
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}

/// True when `err` indicates that OS TUN creation failed due to insufficient
/// privileges or Wintun driver/adapter creation refusal on Windows.
pub fn is_tun_privilege_error(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        return true;
    }
    // 1 = EPERM, 5 = ERROR_ACCESS_DENIED, 13 = EACCES, 1314 = ERROR_PRIVILEGE_NOT_HELD
    if matches!(err.raw_os_error(), Some(1 | 5 | 13 | 1314)) {
        return true;
    }
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("wintuncreateadapter failed")
        || msg.contains("access is denied")
        || msg.contains("permission denied")
        || msg.contains("operation not permitted")
        || msg.contains("requires elevation")
        || msg.contains("requires administrator")
        || msg.contains("privilege")
}

/// Whether `tenant_id` has already latched into userspace `netstack` fallback.
pub fn has_latched_netstack_fallback(tenant_id: &str) -> bool {
    ORG_OVERLAY_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(tenant_id)
        .is_some_and(|s| s.fallback_to_netstack)
}

/// Whether `tenant_id` is currently operating in `netstack` mode (configured or fallback).
pub fn is_org_in_netstack_mode(tenant_id: &str) -> bool {
    ORG_OVERLAY_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(tenant_id)
        .is_some_and(|s| s.fallback_to_netstack || s.effective_mode.as_deref() == Some("netstack"))
}

/// Effective loopback SOCKS5 port for `tenant_id` (configured or auto-allocated on fallback).
pub fn effective_socks5_port(tenant_id: &str) -> Option<u16> {
    if tenant_id.is_empty() {
        return None;
    }
    ORG_OVERLAY_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(tenant_id)
        .and_then(|s| s.socks_port)
}

/// Effective overlay mode reported in `NodeStatus.orgs[i].overlay_mode`.
///
/// - When `configured_mode == "off"`, returns `"off"`.
/// - When fallback to netstack is active, returns `"netstack"`.
/// - When overlay start failed and is in backoff or halted, returns
///   `"error (...)"` with the attempt count and reason.
/// - Otherwise returns `configured_mode`.
pub fn effective_overlay_mode(tenant_id: &str, configured_mode: &str) -> String {
    if configured_mode == "off" || tenant_id.is_empty() {
        return configured_mode.to_string();
    }
    let guard = ORG_OVERLAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(state) = guard.get(tenant_id) else {
        return configured_mode.to_string();
    };
    if state.halted {
        let why = state.last_error.as_deref().unwrap_or("unknown error");
        return format!(
            "error (halted after {} failed attempts: {why})",
            state.failures
        );
    }
    if state.failures > 0 && state.effective_mode.as_deref() == Some("error") {
        let why = state.last_error.as_deref().unwrap_or("unknown error");
        return format!(
            "error (attempt {}/{}, backoff: {why})",
            state.failures, MAX_OVERLAY_START_ATTEMPTS
        );
    }
    if let Some(mode) = &state.effective_mode {
        return mode.clone();
    }
    configured_mode.to_string()
}

/// Record that `tenant_id`'s overlay surface is up (`"tun"` or `"netstack"`),
/// clearing any prior failure/backoff state.
pub fn record_overlay_running(
    tenant_id: &str,
    shape_key: &str,
    mode: &str,
    socks_port: Option<u16>,
    fallback: bool,
) {
    let mut guard = ORG_OVERLAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.entry(tenant_id.to_string()).or_default();
    state.config_shape_key = Some(shape_key.to_string());
    state.effective_mode = Some(mode.to_string());
    state.fallback_to_netstack |= fallback;
    if socks_port.is_some() {
        state.socks_port = socks_port;
    } else if mode == "tun" {
        state.socks_port = None;
    }
    state.failures = 0;
    state.halted = false;
    state.next_retry_at = None;
    state.last_error = None;
}

/// Record an unrecoverable overlay start failure for `tenant_id` at `now`,
/// advancing bounded backoff (`30s`, `60s`) and halting after
/// [`MAX_OVERLAY_START_ATTEMPTS`] attempts for the same `shape_key`.
pub fn record_overlay_failure(tenant_id: &str, shape_key: &str, error: String, now: Instant) {
    let mut guard = ORG_OVERLAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.entry(tenant_id.to_string()).or_default();
    if state.config_shape_key.as_deref() != Some(shape_key) {
        state.config_shape_key = Some(shape_key.to_string());
        state.failures = 0;
        state.halted = false;
        state.next_retry_at = None;
    }
    state.failures = state.failures.saturating_add(1);
    state.effective_mode = Some("error".to_string());
    state.last_error = Some(error);
    if state.failures >= MAX_OVERLAY_START_ATTEMPTS {
        state.halted = true;
        state.next_retry_at = None;
    } else {
        let idx = (state.failures as usize - 1).min(OVERLAY_BACKOFF_STEPS.len() - 1);
        state.next_retry_at = Some(now + OVERLAY_BACKOFF_STEPS[idx]);
    }
}

/// Check whether `tenant_id` is allowed to start/respawn the overlay runtime
/// at `now` for `shape_key`. If `shape_key` changed since the last failure,
/// the failure state is reset and `true` is returned.
pub fn can_attempt_start(tenant_id: &str, shape_key: &str, now: Instant) -> bool {
    let mut guard = ORG_OVERLAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(state) = guard.get_mut(tenant_id) else {
        return true;
    };
    if state.config_shape_key.as_deref() != Some(shape_key) {
        state.config_shape_key = Some(shape_key.to_string());
        state.failures = 0;
        state.halted = false;
        state.next_retry_at = None;
        state.last_error = None;
        return true;
    }
    if state.halted {
        return false;
    }
    if let Some(until) = state.next_retry_at {
        return now >= until;
    }
    true
}

/// Whether `signaling::run` may respawn the overlay runtime at `now` after it exited.
pub fn should_respawn_after_exit_at(cfg: &AgentConfig, now: Instant) -> bool {
    if !cfg.overlay_enabled {
        return false;
    }
    let shape = shape_key_for_config(cfg);
    can_attempt_start(&cfg.tenant_id, &shape, now)
}

/// Whether `signaling::run` may respawn the overlay runtime after it exited.
pub fn should_respawn_after_exit(cfg: &AgentConfig) -> bool {
    should_respawn_after_exit_at(cfg, Instant::now())
}

/// Clear all tracked overlay state for `tenant_id` (on org teardown or disable).
pub fn clear_org_state(tenant_id: &str) {
    ORG_OVERLAY_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(tenant_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privilege_error_classifier_recognises_wintun_and_access_denied() {
        let wintun = std::io::Error::other(
            "Failed to create adapter: WintunCreateAdapter failed: \"No inner logs\"",
        );
        assert!(is_tun_privilege_error(&wintun));

        let perm = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        assert!(is_tun_privilege_error(&perm));

        let os5 = std::io::Error::from_raw_os_error(5);
        assert!(is_tun_privilege_error(&os5));

        let fatal = std::io::Error::other("fatal hardware fault");
        assert!(!is_tun_privilege_error(&fatal));
    }

    #[test]
    fn bounded_backoff_and_status_reporting_state_machine() {
        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = "tenant-sup-test".to_string();
        cfg.overlay_enabled = true;
        let shape = shape_key_for_config(&cfg);
        let t0 = Instant::now();

        record_overlay_failure(&cfg.tenant_id, &shape, "tun bringup failed".into(), t0);
        assert!(!should_respawn_after_exit_at(&cfg, t0 + Duration::from_secs(25)));
        assert!(should_respawn_after_exit_at(&cfg, t0 + Duration::from_secs(31)));
        assert!(
            effective_overlay_mode(&cfg.tenant_id, "tun")
                .starts_with("error (attempt 1/3, backoff: tun bringup failed)")
        );

        let t1 = t0 + Duration::from_secs(31);
        record_overlay_failure(&cfg.tenant_id, &shape, "tun bringup failed".into(), t1);
        assert!(!should_respawn_after_exit_at(&cfg, t1 + Duration::from_secs(59)));
        assert!(should_respawn_after_exit_at(&cfg, t1 + Duration::from_secs(61)));

        let t2 = t1 + Duration::from_secs(61);
        record_overlay_failure(&cfg.tenant_id, &shape, "tun bringup failed".into(), t2);
        assert!(!should_respawn_after_exit_at(&cfg, t2 + Duration::from_secs(7200)));
        assert_eq!(
            effective_overlay_mode(&cfg.tenant_id, "tun"),
            "error (halted after 3 failed attempts: tun bringup failed)"
        );

        // Switching to netstack fallback clears error state and reports netstack + port.
        record_overlay_running(&cfg.tenant_id, &shape, "netstack", Some(54321), true);
        assert_eq!(effective_overlay_mode(&cfg.tenant_id, "tun"), "netstack");
        assert_eq!(effective_socks5_port(&cfg.tenant_id), Some(54321));
        assert!(has_latched_netstack_fallback(&cfg.tenant_id));

        clear_org_state(&cfg.tenant_id);
    }
}
