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

use sha2::{Digest, Sha256};

use crate::config::AgentConfig;

/// Backoff delay ladder for consecutive non-privilege overlay start failures.
/// Interval grows up to the 600 s cap and retries indefinitely (never halts
/// permanently, so a transient boot-time adapter issue always recovers).
pub const OVERLAY_BACKOFF_STEPS: [Duration; 5] = [
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(300),
    Duration::from_secs(600),
];

#[derive(Clone, Debug, Default)]
struct OrgOverlayState {
    config_shape_key: Option<String>,
    effective_mode: Option<String>,
    fallback_to_netstack: bool,
    pending_immediate_respawn: bool,
    socks_port: Option<u16>,
    failures: u32,
    next_retry_at: Option<Instant>,
    last_error: Option<String>,
}

static ORG_OVERLAY_STATE: Mutex<BTreeMap<String, OrgOverlayState>> = Mutex::new(BTreeMap::new());

/// Compute the retry delay for failure attempt `failures` (1-indexed), capped
/// at the last step (`600 s`).
pub fn backoff_delay_for_failure(failures: u32) -> Duration {
    let idx = (failures.saturating_sub(1) as usize).min(OVERLAY_BACKOFF_STEPS.len() - 1);
    OVERLAY_BACKOFF_STEPS[idx]
}

/// Compute a stable shape key for `cfg`'s overlay configuration so a config
/// change resets any previous failure state. Never includes the raw WireGuard
/// secret key (uses its SHA-256 digest instead).
pub fn shape_key_for_config(cfg: &AgentConfig) -> String {
    let wg_identity = match cfg.overlay_wg_secret_key.as_deref() {
        None => "none".to_string(),
        Some(secret) => format!("sha256:{}", hex::encode(Sha256::digest(secret.as_bytes()))),
    };
    format!(
        "{}|{}|{}|{:?}|{:?}|{}",
        cfg.tenant_id,
        cfg.server_url,
        wg_identity,
        cfg.netstack_socks_port,
        cfg.effective_overlay_advertised_routes(),
        cfg.overlay_exit_node.as_deref().unwrap_or("")
    )
}

/// Whether the current compilation target is Windows.
pub fn is_windows_platform() -> bool {
    cfg!(target_os = "windows")
}

/// Does this process have sufficient OS privilege to create/configure a real
/// OS TUN adapter (`SystemTun`) on Windows?
///
/// - On Windows: requires an elevated token (`TokenIsElevated != 0` or
///   `LocalSystem`); a Medium IL interactive process returns `false` and
///   proactively selects userspace `netstack`.
/// - On non-Windows platforms: returns `true` (F1 automatic netstack fallback
///   is scoped to Windows only; Unix platforms always attempt their configured
///   mode directly).
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
/// privileges or Wintun driver/adapter creation refusal on Windows. Always
/// returns `false` when `is_windows` is `false`.
pub fn is_tun_privilege_error_on(err: &std::io::Error, is_windows: bool) -> bool {
    if !is_windows {
        return false;
    }
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        return true;
    }
    // 5 = ERROR_ACCESS_DENIED, 1314 = ERROR_PRIVILEGE_NOT_HELD
    if matches!(err.raw_os_error(), Some(5 | 1314)) {
        return true;
    }
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("wintuncreateadapter failed")
        || msg.contains("access is denied")
        || msg.contains("permission denied")
        || msg.contains("requires elevation")
        || msg.contains("requires administrator")
        || msg.contains("privilege")
}

/// True when `err` is a Windows TUN privilege error on the current platform.
pub fn is_tun_privilege_error(err: &std::io::Error) -> bool {
    is_tun_privilege_error_on(err, is_windows_platform())
}

/// Latch userspace `netstack` fallback for `tenant_id` after a Windows TUN
/// privilege failure so the runtime immediately rebuilds with
/// `netstack_socks = Some(port)` without counting as a failure backoff.
pub fn latch_netstack_fallback(tenant_id: &str, shape_key: &str) {
    let mut guard = ORG_OVERLAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.entry(tenant_id.to_string()).or_default();
    state.config_shape_key = Some(shape_key.to_string());
    state.effective_mode = Some("netstack".to_string());
    state.fallback_to_netstack = true;
    state.pending_immediate_respawn = true;
    state.failures = 0;
    state.next_retry_at = None;
    state.last_error = None;
}

/// Whether `tenant_id` has already latched into userspace `netstack` fallback.
pub fn has_latched_netstack_fallback(tenant_id: &str) -> bool {
    ORG_OVERLAY_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(tenant_id)
        .is_some_and(|s| s.fallback_to_netstack)
}

/// Whether `tenant_id` is waiting for an immediate runtime rebuild after
/// latching reactive `netstack` fallback.
pub fn has_pending_immediate_respawn(tenant_id: &str) -> bool {
    ORG_OVERLAY_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(tenant_id)
        .is_some_and(|s| s.pending_immediate_respawn)
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
/// - When overlay start failed and is in backoff, returns
///   `"error (attempt N, backoff Xs: <reason>)"`.
/// - Otherwise returns `configured_mode`.
pub fn effective_overlay_mode(tenant_id: &str, configured_mode: &str) -> String {
    if configured_mode == "off" || tenant_id.is_empty() {
        return configured_mode.to_string();
    }
    let guard = ORG_OVERLAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(state) = guard.get(tenant_id) else {
        return configured_mode.to_string();
    };
    if state.failures > 0 && state.effective_mode.as_deref() == Some("error") {
        let why = state.last_error.as_deref().unwrap_or("unknown error");
        let delay_s = backoff_delay_for_failure(state.failures).as_secs();
        return format!(
            "error (attempt {}, backoff {delay_s}s: {why})",
            state.failures
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
    state.pending_immediate_respawn = false;
    if socks_port.is_some() {
        state.socks_port = socks_port;
    } else if mode == "tun" {
        state.socks_port = None;
    }
    state.failures = 0;
    state.next_retry_at = None;
    state.last_error = None;
}

/// Record a non-privilege overlay start failure for `tenant_id` at `now`,
/// advancing bounded-interval backoff (`30s -> 60s -> 120s -> 300s -> 600s` cap).
pub fn record_overlay_failure(tenant_id: &str, shape_key: &str, error: String, now: Instant) {
    let mut guard = ORG_OVERLAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.entry(tenant_id.to_string()).or_default();
    if state.config_shape_key.as_deref() != Some(shape_key) {
        state.config_shape_key = Some(shape_key.to_string());
        state.failures = 0;
        state.next_retry_at = None;
    }
    state.pending_immediate_respawn = false;
    state.failures = state.failures.saturating_add(1);
    state.effective_mode = Some("error".to_string());
    state.last_error = Some(error);
    let delay = backoff_delay_for_failure(state.failures);
    state.next_retry_at = Some(now + delay);
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
        state.pending_immediate_respawn = false;
        state.next_retry_at = None;
        state.last_error = None;
        return true;
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

/// Whether the supervision loop should invoke `overlay::maybe_start` at `now`
/// given `evt_tx_closed`:
/// - `Some(false)`: runtime channel is currently open/alive -> `false`.
/// - `Some(true)`: runtime channel closed mid-session -> `should_respawn_after_exit_at(cfg, now)`.
/// - `None`: no runtime channel on this WS session -> returns `true` only when
///   overlay was previously suppressed by failure backoff (or latched for
///   immediate fallback respawn) and `can_attempt_start` is now `true`.
pub fn should_poll_start_at(cfg: &AgentConfig, evt_tx_closed: Option<bool>, now: Instant) -> bool {
    if !cfg.overlay_enabled {
        return false;
    }
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    let has_valid_wg_key = cfg
        .overlay_wg_secret_key
        .as_deref()
        .and_then(tunnel_core::overlay::WgKeypair::from_secret_base64)
        .is_some();
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    let has_valid_wg_key = cfg
        .overlay_wg_secret_key
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    if !has_valid_wg_key {
        return false;
    }
    match evt_tx_closed {
        Some(false) => false,
        Some(true) => should_respawn_after_exit_at(cfg, now),
        None => {
            let has_pending_retry = {
                let guard = ORG_OVERLAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
                guard.get(&cfg.tenant_id).is_some_and(|s| {
                    s.pending_immediate_respawn || (s.failures > 0 && s.next_retry_at.is_some())
                })
            };
            if !has_pending_retry {
                return false;
            }
            let shape = shape_key_for_config(cfg);
            can_attempt_start(&cfg.tenant_id, &shape, now)
        }
    }
}

/// Convenience wrapper for [`should_poll_start_at`] at `Instant::now()`.
pub fn should_poll_start(cfg: &AgentConfig, evt_tx_closed: Option<bool>) -> bool {
    should_poll_start_at(cfg, evt_tx_closed, Instant::now())
}

/// Clear all tracked overlay state for `tenant_id` (on org teardown or disable).
pub fn clear_org_state(tenant_id: &str) {
    ORG_OVERLAY_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(tenant_id);
}

#[cfg(test)]
mod overlay_fallback_supervision_tests {
    use super::*;

    #[test]
    fn shape_key_never_contains_wireguard_secret_key() {
        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = "tenant-shape-secret-test".to_string();
        let secret = "c2VjcmV0LXdpcmVndWFyZC1rZXktMzItYnl0ZXMtYjY0".to_string();
        cfg.overlay_wg_secret_key = Some(secret.clone());

        let key = shape_key_for_config(&cfg);
        assert!(
            !key.contains(&secret),
            "shape_key_for_config must never include the WireGuard secret key"
        );
        let expected_hash = hex::encode(Sha256::digest(secret.as_bytes()));
        assert!(
            key.contains(&expected_hash),
            "shape_key_for_config should identify the key by its SHA-256 digest"
        );
    }

    #[test]
    fn non_windows_tun_permission_error_does_not_fall_back_to_netstack() {
        let perm = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Operation not permitted",
        );
        let eperm = std::io::Error::from_raw_os_error(1);
        let eacces = std::io::Error::from_raw_os_error(13);
        assert!(
            !is_tun_privilege_error_on(&perm, false),
            "non-Windows PermissionDenied must not trigger Windows netstack fallback"
        );
        assert!(!is_tun_privilege_error_on(&eperm, false));
        assert!(!is_tun_privilege_error_on(&eacces, false));

        let wintun = std::io::Error::other(
            "Failed to create adapter: WintunCreateAdapter failed: \"No inner logs\"",
        );
        assert!(is_tun_privilege_error_on(&wintun, true));
        assert!(!is_tun_privilege_error_on(&wintun, false));
    }

    #[test]
    fn continuous_retry_caps_backoff_at_600s_and_never_halts_permanently() {
        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = "tenant-sup-continuous-backoff".to_string();
        cfg.overlay_enabled = true;
        let shape = shape_key_for_config(&cfg);
        let mut now = Instant::now();

        let expected_delays = [30u64, 60, 120, 300, 600, 600, 600];
        for (idx, &delay_secs) in expected_delays.iter().enumerate() {
            let attempt = (idx + 1) as u32;
            record_overlay_failure(&cfg.tenant_id, &shape, "adapter not ready".into(), now);
            assert!(
                !should_respawn_after_exit_at(&cfg, now + Duration::from_secs(delay_secs - 1)),
                "attempt {attempt} must remain in backoff before {delay_secs}s"
            );
            assert!(
                should_respawn_after_exit_at(&cfg, now + Duration::from_secs(delay_secs)),
                "attempt {attempt} must be allowed to retry at {delay_secs}s (never halt permanently)"
            );
            let mode = effective_overlay_mode(&cfg.tenant_id, "tun");
            assert!(
                mode.contains(&format!("attempt {attempt}")) && mode.contains("adapter not ready"),
                "status must report attempt count and reason, got: {mode}"
            );
            assert!(
                !mode.contains("halted"),
                "status must never report permanent halt, got: {mode}"
            );
            now += Duration::from_secs(delay_secs);
        }

        record_overlay_running(&cfg.tenant_id, &shape, "tun", None, false);
        assert_eq!(effective_overlay_mode(&cfg.tenant_id, "tun"), "tun");
        clear_org_state(&cfg.tenant_id);
    }

    #[test]
    fn ws_reconnect_during_backoff_still_retries_after_backoff_expires_without_further_reconnect() {
        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = "tenant-sup-ws-reconnect-backoff".to_string();
        cfg.overlay_enabled = true;
        cfg.overlay_wg_secret_key =
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());
        let shape = shape_key_for_config(&cfg);
        let t0 = Instant::now();

        // Idle org with no prior failure and no runtime channel does not poll-start on keepalive.
        assert!(!should_poll_start_at(&cfg, None, t0));

        // Attempt 1 fails at t0 -> 30s backoff.
        record_overlay_failure(&cfg.tenant_id, &shape, "transient driver busy".into(), t0);

        // At t0 + 10s, WS reconnects: maybe_start is suppressed by backoff and returns None.
        assert!(!can_attempt_start(
            &cfg.tenant_id,
            &shape,
            t0 + Duration::from_secs(10)
        ));
        // At t0 + 25s keepalive tick (overlay_evt_tx is None): still in backoff.
        assert!(!should_poll_start_at(
            &cfg,
            None,
            t0 + Duration::from_secs(25)
        ));
        // At t0 + 35s keepalive tick (overlay_evt_tx is STILL None, no further WS reconnect):
        // backoff expired, so keepalive poll MUST trigger a start!
        assert!(
            should_poll_start_at(&cfg, None, t0 + Duration::from_secs(35)),
            "keepalive must retry overlay start after backoff expires even when WS reconnected during backoff (overlay_evt_tx == None)"
        );

        clear_org_state(&cfg.tenant_id);
    }
}
