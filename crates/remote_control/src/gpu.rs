// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — GPU servers at a glance wire types and pure state/freshness helpers.
//!
//! Shared across the daemon (`meshharbord`), the coordination server
//! (`meshharbor-mod-fleet`), LocalAPI, and CLI (`mh nvitop`). Every hardware
//! metric is `Option`: `None` means *not available / not supported*, NEVER `0`.

use serde::{Deserialize, Serialize};

/// Agent-reported GPU sampler host status (FR-139 §5.2).
///
/// Unknown strings from a newer agent deserialize to [`Self::Unknown`] rather
/// than failing the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GpuHostStatus {
    Ok,
    NoGpu,
    DriverMissing,
    DriverRebootPending,
    Limited,
    OffLocal,
    SamplerStalled,
    DriverHung,
    Unavailable,
    #[default]
    #[serde(other)]
    Unknown,
}

impl GpuHostStatus {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NoGpu => "no_gpu",
            Self::DriverMissing => "driver_missing",
            Self::DriverRebootPending => "driver_reboot_pending",
            Self::Limited => "limited",
            Self::OffLocal => "off_local",
            Self::SamplerStalled => "sampler_stalled",
            Self::DriverHung => "driver_hung",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        }
    }
}

/// Process-list availability for one GPU sample (FR-139 §5.2, §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProcsState {
    Ok,
    Partial,
    Off,
    Unsupported,
    #[default]
    #[serde(other)]
    Unknown,
}

impl ProcsState {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Partial => "partial",
            Self::Off => "off",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }
}

/// Static inventory entry for one GPU reported on connect / hardware change
/// (`rc:agent.gpu_inventory`) and persisted on `Agent.gpu_inventory`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GpuInventoryItem {
    pub uuid: String,
    pub idx: u16,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_limit_w: Option<u16>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mig: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_bus: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unified: bool,
}

/// Full inventory snapshot persisted on `Agent.gpu_inventory`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GpuInventory {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(default)]
    pub gpus: Vec<GpuInventoryItem>,
    #[serde(default)]
    pub status: GpuHostStatus,
}

/// Host-level CPU / load / memory / disk / network counters merged by the
/// daemon (`sysinfo`, no driver calls) into every [`GpuReport`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HostLoad {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load1: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load5: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load15: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_used_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_used_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_total_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_root_used_gb: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_root_total_gb: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_rx_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_tx_bps: Option<u64>,
}

/// One process holding GPU resources (L1 metadata — NEVER argv/cmdline/env).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GpuProc {
    pub pid: u32,
    /// Linux / OS local account name (never mapped to MeshHarbor accounts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Executable basename, truncated to ≤ 32 chars.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sm_pct: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f32>,
    /// Process start timestamp (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<i64>,
    /// Container / systemd short attribution (`docker:<id>`, `k8s:<pod>`,
    /// `systemd:<unit>`), read from `/proc/<pid>/cgroup` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// `"compute"` | `"graphics"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// One GPU's live telemetry sample inside [`GpuReport`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GpuSample {
    pub uuid: String,
    pub idx: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_limit_w: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_bus: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub util_pct: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_used_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_c: Option<i16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_w: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fan_pct: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sm_clock_mhz: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttle: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecc_uncorrected: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remapped_rows: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xid_errors: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mig: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lost: bool,
    /// Unix seconds since util stayed continuously below 5%.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_since: Option<i64>,
    #[serde(default)]
    pub procs_state: ProcsState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procs: Option<Vec<GpuProc>>,
}

/// Full periodic GPU report emitted on `rc:agent.gpu_report`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GpuReport {
    pub seq: u64,
    pub interval_ms: u32,
    #[serde(default)]
    pub status: GpuHostStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(default)]
    pub host: HostLoad,
    #[serde(default)]
    pub gpus: Vec<GpuSample>,
}

/// Server-computed per-GPU classification (FR-139 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuState {
    Free,
    Busy,
    HeldIdle,
    Unattributed,
    Unknown,
}

impl GpuState {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Busy => "busy",
            Self::HeldIdle => "held_idle",
            Self::Unattributed => "unattributed",
            Self::Unknown => "unknown",
        }
    }
}

/// Server-computed host freshness tier (FR-139 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuFreshness {
    Fresh,
    Stale,
    Offline,
}

/// Configurable thresholds for server-side per-GPU state classification.
#[derive(Debug, Clone, Copy)]
pub struct GpuStateThresholds {
    /// Free memory ceiling (default 1024 MiB).
    pub free_mem_max_mb: u32,
    /// Utilization threshold below which a GPU is considered idle (default 5%).
    pub idle_util_pct: u8,
    /// Minimum continuous idle duration in seconds for `held_idle` (default 1800 s = 30 min).
    pub held_idle_secs: i64,
}

impl Default for GpuStateThresholds {
    fn default() -> Self {
        Self {
            free_mem_max_mb: 1024,
            idle_util_pct: 5,
            held_idle_secs: 30 * 60,
        }
    }
}

/// Compute server-side freshness purely from server receive time (`now_s`,
/// `received_at_s`), the reported `interval_ms`, and live control-WS presence.
///
/// Rule (FR-139 §7.2):
/// - `!ws_online` -> `Offline` immediately
/// - `age < 2 * interval` -> `Fresh`
/// - `2 * interval <= age < 5 * interval` -> `Stale`
/// - `age >= 5 * interval` -> `Offline`
pub fn compute_freshness(
    ws_online: bool,
    received_at_s: Option<i64>,
    now_s: i64,
    interval_ms: u32,
) -> GpuFreshness {
    if !ws_online {
        return GpuFreshness::Offline;
    }
    let Some(recv) = received_at_s else {
        return GpuFreshness::Offline;
    };
    let age_ms = now_s.saturating_sub(recv).max(0) as u64 * 1000;
    let iv = u64::from(interval_ms.max(1000));
    if age_ms < iv.saturating_mul(2) {
        GpuFreshness::Fresh
    } else if age_ms < iv.saturating_mul(5) {
        GpuFreshness::Stale
    } else {
        GpuFreshness::Offline
    }
}

/// Compute server-side [`GpuState`] for one GPU sample (FR-139 §7.2).
///
/// Key invariants:
/// - `status != Ok` or `lost` or `mem_used_mb.is_none()` -> `Unknown`
/// - `unattributed` (mem > threshold, `procs_state == Ok`, empty procs) is
///   NEVER classified as `Free`!
/// - `held_idle` requires `mem_used_mb > threshold`, `util < idle_util_pct`,
///   and `idle_since` older than `held_idle_secs`.
pub fn classify_gpu_state(
    host_status: GpuHostStatus,
    sample: &GpuSample,
    now_s: i64,
    t: GpuStateThresholds,
) -> GpuState {
    if host_status != GpuHostStatus::Ok || sample.lost {
        return GpuState::Unknown;
    }
    let Some(mem_used) = sample.mem_used_mb else {
        return GpuState::Unknown;
    };
    let procs_empty = sample.procs.as_ref().is_none_or(|p| p.is_empty());
    let has_procs = !procs_empty;

    if mem_used > t.free_mem_max_mb {
        if sample.procs_state == ProcsState::Ok && procs_empty {
            return GpuState::Unattributed;
        }
        if let (Some(util), Some(idle_since)) = (sample.util_pct, sample.idle_since)
            && util < t.idle_util_pct
            && now_s.saturating_sub(idle_since) >= t.held_idle_secs
        {
            return GpuState::HeldIdle;
        }
        return GpuState::Busy;
    }

    // Memory <= threshold (1 GiB): free ONLY when no processes are present and
    // either procs are visible (`Ok`/`Partial`) or unsupported (Apple unified /
    // when utilization is also low). If `procs_state == Off`, we cannot claim
    // "no processes" unless utilization is 0/low, so check `has_procs` first.
    if has_procs {
        return GpuState::Busy;
    }
    if sample.procs_state == ProcsState::Off || sample.procs_state == ProcsState::Unsupported {
        // Without process list, only mark Free if util is known and < idle_util_pct.
        return match sample.util_pct {
            Some(u) if u < t.idle_util_pct => GpuState::Free,
            Some(_) => GpuState::Busy,
            None => GpuState::Unknown,
        };
    }
    GpuState::Free
}

/// Wire payload for `ServerMsg::GpuAlert` (`rc:gpu.alert`) relayed to a device
/// owner's online agents with a live desktop companion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuAlertWire {
    pub seq: u64,
    pub at: i64,
    pub severity: String,
    pub title: String,
    pub body: String,
    pub link: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr139_freshness_respects_ws_and_server_receive_time() {
        assert_eq!(compute_freshness(false, Some(1000), 1001, 30_000), GpuFreshness::Offline);
        assert_eq!(compute_freshness(true, None, 1001, 30_000), GpuFreshness::Offline);
        assert_eq!(compute_freshness(true, Some(1000), 1059, 30_000), GpuFreshness::Fresh);
        assert_eq!(compute_freshness(true, Some(1000), 1060, 30_000), GpuFreshness::Stale);
        assert_eq!(compute_freshness(true, Some(1000), 1149, 30_000), GpuFreshness::Stale);
        assert_eq!(compute_freshness(true, Some(1000), 1150, 30_000), GpuFreshness::Offline);
    }

    #[test]
    fn fr139_classify_gpu_state_none_vs_zero_and_unattributed_never_free() {
        let t = GpuStateThresholds::default();
        let now = 10_000;

        // None mem_used_mb -> Unknown (NOT Free!)
        let s_none = GpuSample {
            uuid: "GPU-1".into(),
            procs_state: ProcsState::Ok,
            ..Default::default()
        };
        assert_eq!(classify_gpu_state(GpuHostStatus::Ok, &s_none, now, t), GpuState::Unknown);

        // 0 MB used, no procs -> Free
        let s_free = GpuSample {
            uuid: "GPU-1".into(),
            mem_used_mb: Some(0),
            util_pct: Some(0),
            procs_state: ProcsState::Ok,
            procs: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(classify_gpu_state(GpuHostStatus::Ok, &s_free, now, t), GpuState::Free);

        // > 1 GiB used, procs_state == Ok, empty procs -> Unattributed (NEVER Free!)
        let s_unattr = GpuSample {
            uuid: "GPU-1".into(),
            mem_used_mb: Some(2048),
            util_pct: Some(0),
            procs_state: ProcsState::Ok,
            procs: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Ok, &s_unattr, now, t),
            GpuState::Unattributed
        );

        // > 1 GiB used, proc present, util < 5%, idle_since >= 30 min -> HeldIdle
        let s_held = GpuSample {
            uuid: "GPU-1".into(),
            mem_used_mb: Some(38_000),
            util_pct: Some(1),
            idle_since: Some(now - 3600),
            procs_state: ProcsState::Ok,
            procs: Some(vec![GpuProc {
                pid: 42,
                user: Some("bob".into()),
                name: Some("jupyter".into()),
                mem_mb: Some(38_000),
                ..Default::default()
            }]),
            ..Default::default()
        };
        assert_eq!(classify_gpu_state(GpuHostStatus::Ok, &s_held, now, t), GpuState::HeldIdle);

        // Limited / WSL2 host status -> Unknown
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Limited, &s_free, now, t),
            GpuState::Unknown
        );
    }
}
