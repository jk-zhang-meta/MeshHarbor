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
    /// Optional human-readable host diagnosis (e.g. detected PCIe accelerator
    /// without kernel driver, missing NVML/npu-smi, WSL2 limitation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
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
    /// Unix seconds of the most recent Xid error observed on this card (used
    /// for edge-triggered alerting and age display).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xid_last_at: Option<i64>,
    /// True when NVML reports pending row remapping (GPU reset required).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remap_pending: bool,
    /// True when NVML reports a row-remapping failure (hardware RMA signal).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remap_failure: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mig: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lost: bool,
    /// Optional vendor-reported health string (e.g. Huawei Ascend `"OK"`,
    /// `"Warning"`, `"Alarm"`, `"Critical"`). Preserved separately from `lost`
    /// so a responding card with a warning is never falsely marked off-the-bus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_health: Option<String>,
    /// Per-card backend tag (e.g. `"nvml"`, `"ascend"`, `"amd"`, `"intel"`,
    /// `"apple"`, `"tpu"`, `"pci"`), enabling accurate mixed-vendor hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Vendor-native device ordinal (e.g. Ascend logical NPU ID for
    /// `ASCEND_RT_VISIBLE_DEVICES`), preserved even when mixed-backend hosts
    /// renumber display `idx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_index: Option<u16>,
    /// True when the card is observed via device-node/PCIe presence without
    /// hardware memory/utilization counters (e.g. Google TPU `/dev/vfio/*` or
    /// Ascend `/dev/davinci*` fallback without `npu-smi`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub presence_only: bool,
    /// Unix seconds since util stayed continuously below 5%.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_since: Option<i64>,
    /// Optional backend-reported idle firmware memory floor (MiB) for
    /// accelerators that reserve baseline HBM even with zero running processes
    /// (e.g. Huawei Ascend 910B reserves ~3.4 GiB out of 64 GiB). Server caps
    /// this to <= 12.5% of total memory and applies it only when `procs_state == Ok`,
    /// zero processes are running, and utilization is below `idle_util_pct`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_mem_floor_mb: Option<u32>,
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
    /// Optional human-readable host diagnosis explaining non-`ok` status
    /// (`driver_missing`, `limited`, `driver_reboot_pending`, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
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
/// - `age < max(3 * interval, 90 s)` -> `Fresh`
/// - `age < max(5 * interval, 150 s)` -> `Stale`
/// - `age >= max(5 * interval, 150 s)` -> `Offline`
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
    let fresh_cutoff_ms = iv.saturating_mul(3).max(90_000);
    let stale_cutoff_ms = iv.saturating_mul(5).max(150_000);
    if age_ms < fresh_cutoff_ms {
        GpuFreshness::Fresh
    } else if age_ms < stale_cutoff_ms {
        GpuFreshness::Stale
    } else {
        GpuFreshness::Offline
    }
}

/// Structured, machine- and human-readable fault explanation shared across
/// server DTOs, LocalAPI, CLI, Desktop, and Web SPA (FR-139).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuFaultReason {
    /// `"host"` | `"card"`.
    pub scope: String,
    /// `"critical"` | `"warning"`.
    pub severity: String,
    /// Stable code (`"lost"`, `"xid"`, `"ecc_uncorrected"`, `"remapped_rows"`,
    /// `"thermal_throttle"`, `"hw_slowdown"`, `"power_brake"`, `"vendor_health"`,
    /// `"driver_missing"`, `"driver_reboot_pending"`, `"driver_hung"`,
    /// `"sampler_stalled"`, `"unavailable"`).
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_idx: Option<u16>,
    /// Concise human-readable diagnostic summary.
    pub summary: String,
}

/// Data-cadence lag detector, independent of presence-based [`GpuFreshness`].
///
/// In live 2 s mode a frozen sampler would otherwise stay `Fresh` for 89 s
/// because of the 90 s offline-flicker floor. This function compares sample age
/// against `max(3 * interval_ms, 6_000)` when a live lease is active and
/// `max(3 * interval_ms, 90_000)` in standing 30 s mode.
pub fn is_lagging(age_ms: i64, interval_ms: u32, live_requested: bool) -> bool {
    if age_ms < 0 {
        return false;
    }
    let iv = i64::from(interval_ms.max(1000));
    let floor = if live_requested { 6_000 } else { 90_000 };
    age_ms > iv.saturating_mul(3).max(floor)
}

/// Application-caused NVIDIA Xid codes (classified as `warning` rather than
/// hardware-critical `critical` so user OOM/illegal-memory-access kernels do
/// not permanently fail hardware health checks).
pub const APP_LEVEL_XIDS: &[u32] = &[13, 31, 43, 45];

/// Decode common NVIDIA Xid error codes into a concise operational explanation.
pub fn decode_nvidia_xid(code: u32) -> Option<&'static str> {
    match code {
        13 => Some("Graphics engine exception"),
        31 => Some("GPU memory page fault"),
        32 => Some("Corrupted command/push buffer stream"),
        43 => Some("GPU stopped processing"),
        45 => Some("Preemptive cleanup after prior fault"),
        48 => Some("Double-bit ECC error (DBE)"),
        62 => Some("Internal micro-controller halt"),
        63 => Some("ECC page retirement / row remapping event"),
        64 => Some("ECC page retirement / row remapper failure"),
        74 => Some("NVLink error"),
        79 => Some("GPU fell off the bus"),
        92 => Some("High single-bit ECC error rate"),
        94 => Some("Contained ECC error"),
        95 => Some("Uncontained ECC error (GPU reset required)"),
        119 => Some("GSP RPC timeout"),
        120 => Some("GSP error"),
        _ => None,
    }
}

/// Canonical per-card fault evaluation shared across server, CLI, Web, and
/// Desktop. Routine training power capping (`power_cap`) and `sync_boost` are
/// NOT faults; hardware/thermal throttling, `lost`, Xid, uncorrected ECC,
/// remapped rows, and non-OK vendor health ARE surfaced with explicit reasons.
pub fn card_fault_reasons(sample: &GpuSample) -> Vec<GpuFaultReason> {
    let mut out = Vec::new();
    let uuid = Some(sample.uuid.clone());
    let idx = Some(sample.idx);

    if sample.lost {
        out.push(GpuFaultReason {
            scope: "card".into(),
            severity: "critical".into(),
            code: "lost".into(),
            device_uuid: uuid.clone(),
            device_idx: idx,
            summary: "Accelerator fell off the bus (lost)".into(),
        });
    }

    if let Some(xids) = sample.xid_errors.as_ref().filter(|v| !v.is_empty()) {
        let any_hw_critical = xids.iter().any(|c| !APP_LEVEL_XIDS.contains(c));
        let formatted: Vec<String> = xids
            .iter()
            .map(|&code| match decode_nvidia_xid(code) {
                Some(desc) => format!("Xid {code} ({desc})"),
                None => format!("Xid {code}"),
            })
            .collect();
        out.push(GpuFaultReason {
            scope: "card".into(),
            severity: if any_hw_critical { "critical" } else { "warning" }.into(),
            code: if any_hw_critical { "xid" } else { "xid_app" }.into(),
            device_uuid: uuid.clone(),
            device_idx: idx,
            summary: formatted.join(", "),
        });
    }

    if let Some(ecc) = sample.ecc_uncorrected
        && ecc > 0
    {
        out.push(GpuFaultReason {
            scope: "card".into(),
            severity: "critical".into(),
            code: "ecc_uncorrected".into(),
            device_uuid: uuid.clone(),
            device_idx: idx,
            summary: format!("Uncorrected ECC errors: {ecc}"),
        });
    }

    if sample.remap_failure {
        out.push(GpuFaultReason {
            scope: "card".into(),
            severity: "critical".into(),
            code: "remap_failure".into(),
            device_uuid: uuid.clone(),
            device_idx: idx,
            summary: "Memory row remapping failed (hardware RMA required)".into(),
        });
    } else if sample.remap_pending {
        out.push(GpuFaultReason {
            scope: "card".into(),
            severity: "critical".into(),
            code: "remap_pending".into(),
            device_uuid: uuid.clone(),
            device_idx: idx,
            summary: "Memory row remapping pending (GPU reset required)".into(),
        });
    } else if let Some(rem) = sample.remapped_rows
        && rem > 0
    {
        out.push(GpuFaultReason {
            scope: "card".into(),
            severity: "warning".into(),
            code: "remapped_rows".into(),
            device_uuid: uuid.clone(),
            device_idx: idx,
            summary: format!("Remapped memory rows: {rem}"),
        });
    }

    if let Some(vh) = sample
        .vendor_health
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("ok"))
    {
        let low = vh.to_ascii_lowercase();
        let severity = if low.contains("crit")
            || low.contains("fatal")
            || low.contains("error")
            || low.contains("alarm")
            || low.contains("fail")
            || low.contains("general")
        {
            "critical"
        } else {
            "warning"
        };
        out.push(GpuFaultReason {
            scope: "card".into(),
            severity: severity.into(),
            code: "vendor_health".into(),
            device_uuid: uuid.clone(),
            device_idx: idx,
            summary: format!("Vendor health: {vh}"),
        });
    }

    if let Some(reasons) = sample.throttle.as_ref() {
        let mut saw_thermal = false;
        let mut saw_hw = false;
        let mut saw_power_brake = false;
        for raw in reasons {
            match raw.to_ascii_lowercase().as_str() {
                "thermal" | "sw_thermal" if !saw_thermal => {
                    saw_thermal = true;
                    let temp_suffix = sample
                        .temp_c
                        .map(|c| format!(" ({c}°C)"))
                        .unwrap_or_default();
                    out.push(GpuFaultReason {
                        scope: "card".into(),
                        severity: "warning".into(),
                        code: "thermal_throttle".into(),
                        device_uuid: uuid.clone(),
                        device_idx: idx,
                        summary: format!("Thermal throttling{temp_suffix}"),
                    });
                }
                "hw_slowdown" if !saw_hw => {
                    saw_hw = true;
                    out.push(GpuFaultReason {
                        scope: "card".into(),
                        severity: "warning".into(),
                        code: "hw_slowdown".into(),
                        device_uuid: uuid.clone(),
                        device_idx: idx,
                        summary: "Hardware slowdown throttling".into(),
                    });
                }
                "power_brake" if !saw_power_brake => {
                    saw_power_brake = true;
                    out.push(GpuFaultReason {
                        scope: "card".into(),
                        severity: "warning".into(),
                        code: "power_brake".into(),
                        device_uuid: uuid.clone(),
                        device_idx: idx,
                        summary: "External power-brake throttling".into(),
                    });
                }
                _ => {}
            }
        }
    }

    out
}

/// Worst severity (`"critical"` > `"warning"`) among a slice of fault reasons.
pub fn worst_fault_severity(reasons: &[GpuFaultReason]) -> Option<&'static str> {
    if reasons.iter().any(|r| r.severity == "critical") {
        Some("critical")
    } else if !reasons.is_empty() {
        Some("warning")
    } else {
        None
    }
}

/// Whether `sample` has at least one canonical **critical** hardware fault
/// (used for KPI fault card counts and allocation blocking). Warnings such as
/// active thermal throttling or Ascend `"Warning"` health are surfaced as
/// warning badges without turning a working card into a critical fault.
pub fn card_has_critical_fault(sample: &GpuSample) -> bool {
    worst_fault_severity(&card_fault_reasons(sample)) == Some("critical")
}

/// Whether `sample` has any canonical card-level fault or warning reason.
pub fn card_has_fault(sample: &GpuSample) -> bool {
    !card_fault_reasons(sample).is_empty()
}

/// Canonical host-level fault predicate.
///
/// Only genuine driver/sampler failures count as host faults (`driver_missing`,
/// `driver_reboot_pending`, `driver_hung`, `sampler_stalled`, `unavailable`).
/// `ok`, `no_gpu`, `limited` (e.g. WSL2 or zero-package PCIe/TPU partial mode),
/// `off_local` (operator opted out locally), and `unknown` (awaiting first
/// sample) are NOT faults.
pub fn host_status_fault(
    status: GpuHostStatus,
    detail: Option<&str>,
) -> Option<GpuFaultReason> {
    let (severity, default_summary) = match status {
        GpuHostStatus::DriverMissing => (
            "critical",
            "Accelerator hardware detected without a working kernel driver",
        ),
        GpuHostStatus::DriverRebootPending => (
            "warning",
            "Driver/library version mismatch — host reboot or driver reload required",
        ),
        GpuHostStatus::DriverHung => (
            "critical",
            "GPU driver call hung in kernel — sampler child unresponsive",
        ),
        GpuHostStatus::SamplerStalled => (
            "warning",
            "GPU sampler missed its collection deadline and is backing off",
        ),
        GpuHostStatus::Unavailable => (
            "critical",
            "GPU sampler unavailable after repeated failures",
        ),
        GpuHostStatus::Ok
        | GpuHostStatus::NoGpu
        | GpuHostStatus::Limited
        | GpuHostStatus::OffLocal
        | GpuHostStatus::Unknown => return None,
    };
    let summary = detail
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default_summary)
        .to_string();
    Some(GpuFaultReason {
        scope: "host".into(),
        severity: severity.into(),
        code: status.wire().into(),
        device_uuid: None,
        device_idx: None,
        summary,
    })
}

/// Canonical allocation eligibility: true ONLY when the host is online with
/// fresh telemetry (`Fresh`), healthy sampler status (`Ok`), the card is
/// classified `Free`, and the card has zero active fault reasons.
pub fn is_card_eligible_free(
    is_online: bool,
    freshness: GpuFreshness,
    host_status: GpuHostStatus,
    card_state: GpuState,
    sample: &GpuSample,
) -> bool {
    is_online
        && freshness == GpuFreshness::Fresh
        && host_status == GpuHostStatus::Ok
        && card_state == GpuState::Free
        && !card_has_fault(sample)
}

/// Compute server-side [`GpuState`] for one GPU sample (FR-139 §7.2).
///
/// Key invariants:
/// - `lost` or non-`Ok`/`Limited` host status -> `Unknown`
/// - On `Limited` hosts (e.g. WSL2 or zero-package TPU/Ascend device-node
///   attribution), positively observed compute processes classify as `Busy`;
///   `presence_only` cards with complete `/proc` scan (`ProcsState::Ok`) and
///   zero open holders classify as `Free`, while partial/unknown scans stay
///   `Unknown` (never falsely `Free`).
/// - Active utilization (`util >= idle_util_pct`) NEVER classifies as `Free`,
///   even if memory usage is below `free_mem_max_mb`!
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
    if sample.lost {
        return GpuState::Unknown;
    }
    let procs_slice = sample.procs.as_deref().unwrap_or(&[]);
    let procs_empty = procs_slice.is_empty();
    let has_procs = !procs_empty;
    let has_compute_proc = procs_slice
        .iter()
        .any(|p| p.kind.as_deref() != Some("graphics"));

    if host_status == GpuHostStatus::Limited {
        if sample.presence_only {
            return match sample.procs_state {
                ProcsState::Ok if has_procs => GpuState::Busy,
                ProcsState::Ok => GpuState::Free,
                ProcsState::Partial if has_procs => GpuState::Busy,
                _ => GpuState::Unknown,
            };
        }
        if has_compute_proc || sample.util_pct.is_some_and(|u| u >= t.idle_util_pct) {
            return GpuState::Busy;
        }
        // WSL2 NVML reports valid VRAM & util with `ProcsState::Unsupported` —
        // let it classify normally instead of leaving every WSL2 card Unknown.
        if sample.procs_state == ProcsState::Unsupported
            && sample.mem_used_mb.is_some()
            && sample.util_pct.is_some()
        {
            // fall through to standard VRAM/util rules below
        } else {
            return GpuState::Unknown;
        }
    } else if host_status != GpuHostStatus::Ok {
        return GpuState::Unknown;
    }

    if sample.presence_only && sample.mem_used_mb.is_none() {
        return match sample.procs_state {
            ProcsState::Ok if has_procs => GpuState::Busy,
            ProcsState::Ok => GpuState::Free,
            ProcsState::Partial if has_procs => GpuState::Busy,
            _ => GpuState::Unknown,
        };
    }

    let Some(mem_used) = sample.mem_used_mb else {
        if has_compute_proc || sample.util_pct.is_some_and(|u| u >= t.idle_util_pct) {
            return GpuState::Busy;
        }
        return GpuState::Unknown;
    };

    // Effective free-memory ceiling: default 1 GiB, or for accelerators with
    // verified idle firmware HBM reservation (e.g. Huawei Ascend 910B ~3.4 GiB
    // out of 64 GiB), allow up to the backend-declared floor capped at 12.5% of
    // total memory — strictly when process listing succeeded with ZERO processes
    // and utilization is below `idle_util_pct`.
    let effective_free_max_mb = if sample.procs_state == ProcsState::Ok
        && procs_empty
        && sample.util_pct.is_some_and(|u| u < t.idle_util_pct)
    {
        if let Some(floor) = sample.free_mem_floor_mb {
            let cap = sample
                .mem_total_mb
                .map(|tot| (tot / 8).min(8192))
                .unwrap_or(4096);
            t.free_mem_max_mb.max(floor.min(cap))
        } else {
            t.free_mem_max_mb
        }
    } else {
        t.free_mem_max_mb
    };

    if mem_used > effective_free_max_mb {
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

    // Active compute utilization ALWAYS blocks `Free`, even with low VRAM usage.
    if sample.util_pct.is_some_and(|u| u >= t.idle_util_pct) {
        return GpuState::Busy;
    }

    // Memory <= free ceiling and idle/unknown util: free when no compute/blocking
    // processes are present. Ignore benign idle display-compositor graphics
    // processes (e.g. Xorg / gdm holding ~4 MiB VRAM with 0% utilization and
    // zero compute processes) so idle desktop-attached training cards classify
    // as Free.
    if has_procs {
        let only_idle_graphics = procs_slice
            .iter()
            .all(|p| p.kind.as_deref() == Some("graphics"))
            && procs_slice
                .iter()
                .map(|p| u64::from(p.mem_mb.unwrap_or(0)))
                .sum::<u64>()
                <= u64::from(t.free_mem_max_mb)
            && sample.util_pct.is_none_or(|u| u < t.idle_util_pct);
        if !only_idle_graphics {
            return GpuState::Busy;
        }
    }

    match sample.procs_state {
        ProcsState::Ok => {
            if sample.util_pct.is_some() || sample.mem_total_mb.is_some() {
                GpuState::Free
            } else {
                GpuState::Unknown
            }
        }
        ProcsState::Off | ProcsState::Unsupported => match sample.util_pct {
            Some(u) if u < t.idle_util_pct => GpuState::Free,
            Some(_) => GpuState::Busy,
            None => GpuState::Unknown,
        },
        ProcsState::Partial | ProcsState::Unknown => GpuState::Unknown,
    }
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
        // 30 s interval -> 90 s Fresh cutoff, 150 s Stale cutoff
        assert_eq!(compute_freshness(true, Some(1000), 1089, 30_000), GpuFreshness::Fresh);
        assert_eq!(compute_freshness(true, Some(1000), 1090, 30_000), GpuFreshness::Stale);
        assert_eq!(compute_freshness(true, Some(1000), 1149, 30_000), GpuFreshness::Stale);
        assert_eq!(compute_freshness(true, Some(1000), 1150, 30_000), GpuFreshness::Offline);
        // 2 s live lease ending -> 90 s / 150 s floors prevent false offline flash
        assert_eq!(compute_freshness(true, Some(1000), 1030, 2_000), GpuFreshness::Fresh);
        assert_eq!(compute_freshness(true, Some(1000), 1100, 2_000), GpuFreshness::Stale);
        assert_eq!(compute_freshness(true, Some(1000), 1150, 2_000), GpuFreshness::Offline);
        // Larger 60 s interval scales proportionally (180 s / 300 s)
        assert_eq!(compute_freshness(true, Some(1000), 1179, 60_000), GpuFreshness::Fresh);
        assert_eq!(compute_freshness(true, Some(1000), 1180, 60_000), GpuFreshness::Stale);
        assert_eq!(compute_freshness(true, Some(1000), 1300, 60_000), GpuFreshness::Offline);
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

        // Benign idle Xorg/gdm graphics process (4 MiB, 0% util, no compute) -> Free
        let s_xorg_idle = GpuSample {
            uuid: "GPU-xorg".into(),
            mem_used_mb: Some(4),
            mem_total_mb: Some(49_140),
            util_pct: Some(0),
            procs_state: ProcsState::Ok,
            procs: Some(vec![GpuProc {
                pid: 5648,
                user: Some("gdm".into()),
                name: Some("Xorg".into()),
                mem_mb: Some(4),
                kind: Some("graphics".into()),
                ..Default::default()
            }]),
            ..Default::default()
        };
        assert_eq!(classify_gpu_state(GpuHostStatus::Ok, &s_xorg_idle, now, t), GpuState::Free);

        // Low-VRAM compute process (even 200 MiB, 0% util) -> Busy (NOT Free)
        let s_small_compute = GpuSample {
            procs: Some(vec![GpuProc {
                pid: 777,
                user: Some("alice".into()),
                name: Some("python".into()),
                mem_mb: Some(200),
                kind: Some("compute".into()),
                ..Default::default()
            }]),
            mem_used_mb: Some(200),
            ..s_xorg_idle.clone()
        };
        assert_eq!(classify_gpu_state(GpuHostStatus::Ok, &s_small_compute, now, t), GpuState::Busy);

        // Huawei Ascend 910B idle firmware HBM baseline (3445/65536 MiB, 0% AICore, 0 procs) -> Free
        let s_ascend_free = GpuSample {
            uuid: "ASCEND-2-0-0000:81:00.0".into(),
            mem_used_mb: Some(3445),
            mem_total_mb: Some(65_536),
            util_pct: Some(0),
            free_mem_floor_mb: Some(5461),
            procs_state: ProcsState::Ok,
            procs: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(classify_gpu_state(GpuHostStatus::Ok, &s_ascend_free, now, t), GpuState::Free);

        // Ascend with large unattributed HBM (20000 MiB, 0 procs) -> STILL Unattributed
        let s_ascend_unattr = GpuSample {
            mem_used_mb: Some(20_000),
            ..s_ascend_free
        };
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Ok, &s_ascend_unattr, now, t),
            GpuState::Unattributed
        );

        // Active utilization (50%) MUST NEVER classify as Free even with <= 1024 MiB and empty procs!
        let s_active_low_mem = GpuSample {
            uuid: "GPU-active".into(),
            mem_used_mb: Some(1024),
            mem_total_mb: Some(24_576),
            util_pct: Some(50),
            procs_state: ProcsState::Ok,
            procs: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Ok, &s_active_low_mem, now, t),
            GpuState::Busy
        );

        // Partial/Unknown proc listing with 0 MiB used MUST NOT falsely claim Free
        let s_partial_empty = GpuSample {
            uuid: "GPU-partial".into(),
            mem_used_mb: Some(0),
            mem_total_mb: Some(24_576),
            util_pct: Some(0),
            procs_state: ProcsState::Partial,
            procs: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Ok, &s_partial_empty, now, t),
            GpuState::Unknown
        );

        // Limited host (e.g. zero-package TPU/Ascend fallback): positively observed compute proc -> Busy
        let s_tpu_busy = GpuSample {
            uuid: "TPU-0-0000:00:05.0".into(),
            procs_state: ProcsState::Ok,
            procs: Some(vec![GpuProc {
                pid: 9001,
                user: Some("trainer".into()),
                name: Some("python3".into()),
                kind: Some("compute".into()),
                ..Default::default()
            }]),
            ..Default::default()
        };
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Limited, &s_tpu_busy, now, t),
            GpuState::Busy
        );
    }

    #[test]
    fn fr139_canonical_fault_reasons_and_eligibility() {
        // Routine power_cap is NOT a fault
        let s_pcap = GpuSample {
            uuid: "GPU-0".into(),
            idx: 0,
            mem_used_mb: Some(0),
            mem_total_mb: Some(81_920),
            util_pct: Some(0),
            throttle: Some(vec!["power_cap".into(), "sync_boost".into()]),
            procs_state: ProcsState::Ok,
            procs: Some(vec![]),
            ..Default::default()
        };
        assert!(card_fault_reasons(&s_pcap).is_empty());
        assert!(is_card_eligible_free(
            true,
            GpuFreshness::Fresh,
            GpuHostStatus::Ok,
            GpuState::Free,
            &s_pcap
        ));
        // Stale freshness MUST block eligibility!
        assert!(!is_card_eligible_free(
            true,
            GpuFreshness::Stale,
            GpuHostStatus::Ok,
            GpuState::Free,
            &s_pcap
        ));

        // Xid 79 + ECC + remapped + Ascend warning + thermal throttle produce structured reasons
        let s_bad = GpuSample {
            uuid: "GPU-1".into(),
            idx: 1,
            temp_c: Some(91),
            xid_errors: Some(vec![79, 48]),
            ecc_uncorrected: Some(3),
            remapped_rows: Some(2),
            vendor_health: Some("Warning".into()),
            throttle: Some(vec!["thermal".into(), "power_cap".into()]),
            ..Default::default()
        };
        let reasons = card_fault_reasons(&s_bad);
        let codes: Vec<&str> = reasons.iter().map(|r| r.code.as_str()).collect();
        assert_eq!(
            codes,
            vec!["xid", "ecc_uncorrected", "remapped_rows", "vendor_health", "thermal_throttle"]
        );
        assert!(reasons[0].summary.contains("GPU fell off the bus"));
        assert!(reasons[0].summary.contains("Double-bit ECC"));
        assert!(!is_card_eligible_free(
            true,
            GpuFreshness::Fresh,
            GpuHostStatus::Ok,
            GpuState::Free,
            &s_bad
        ));

        // Host statuses: only real failures are host faults
        assert!(host_status_fault(GpuHostStatus::DriverMissing, Some("NVIDIA H100 at 0000:65:00.0")).is_some());
        assert!(host_status_fault(GpuHostStatus::DriverRebootPending, None).is_some());
        assert!(host_status_fault(GpuHostStatus::SamplerStalled, None).is_some());
        assert!(host_status_fault(GpuHostStatus::DriverHung, None).is_some());
        assert!(host_status_fault(GpuHostStatus::Unavailable, None).is_some());
        assert!(host_status_fault(GpuHostStatus::Ok, None).is_none());
        assert!(host_status_fault(GpuHostStatus::Limited, Some("WSL2")).is_none());
        assert!(host_status_fault(GpuHostStatus::NoGpu, None).is_none());
        assert!(host_status_fault(GpuHostStatus::OffLocal, None).is_none());
        assert!(host_status_fault(GpuHostStatus::Unknown, None).is_none());
    }
}
