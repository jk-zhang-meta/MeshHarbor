// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — LocalAPI wire types for GPU fleet, user attribution, and alerts.
//!
//! Kept plain-serde in `meshharbor-localapi` (leaf crate; zero transport or
//! server dependencies). Field names match the JSON emitted by
//! `/api/agent/self/gpu/fleet`, `/api/agent/self/gpu/users`, and the daemon's
//! `rc:gpu.alert` ring buffer.

use serde::{Deserialize, Serialize};

/// One GPU process row as returned by `/api/agent/self/gpu/fleet`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GpuProcView {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_s: Option<u64>,
    /// `"c"` (compute) | `"g"` (graphics) | `"cg"` | `"u"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Host-level CPU / RAM / swap / disk / network snapshot alongside GPU cards.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GpuHostLoadView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_1m: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_used_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_used_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_total_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_used_pct: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_rx_mbps: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_tx_mbps: Option<f32>,
}

/// One GPU card inside a [`GpuHostView`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GpuCardView {
    pub uuid: String,
    pub idx: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `"free"` | `"busy"` | `"held_idle"` | `"unattributed_busy"` | `"fault"` | `"unknown"`.
    #[serde(default)]
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_used_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub util_pct: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_c: Option<i16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_w: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_limit_w: Option<u16>,
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
    #[serde(default)]
    pub mig: bool,
    #[serde(default)]
    pub lost: bool,
    #[serde(default)]
    pub unified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_bus: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_since: Option<i64>,
    /// `"ok"` | `"off_local"` | `"unsupported"` | `"error"`.
    #[serde(default)]
    pub procs_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procs: Option<Vec<GpuProcView>>,
}

/// One GPU server row in [`GpuFleetPage`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GpuHostView {
    pub agent_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub os: String,
    /// `"org"` | `"invited"` | `"shared"`.
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub is_online: bool,
    /// `"live"` | `"stale"` | `"offline"`.
    #[serde(default)]
    pub freshness: String,
    /// `"ok"` | `"off_local"` | `"driver_hung"` | `"sampler_stalled"` | `"unavailable"` | `"no_gpu"` | `"unsupported"`.
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at_ms: Option<i64>,
    #[serde(default)]
    pub interval_ms: u32,
    #[serde(default)]
    pub free_count: usize,
    #[serde(default)]
    pub busy_count: usize,
    #[serde(default)]
    pub held_idle_count: usize,
    #[serde(default)]
    pub total_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<GpuHostLoadView>,
    #[serde(default)]
    pub gpus: Vec<GpuCardView>,
}

/// Fleet summary counters returned by `/api/agent/self/gpu/fleet`.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct GpuFleetSummary {
    #[serde(default)]
    pub hosts_total: usize,
    #[serde(default)]
    pub hosts_online: usize,
    #[serde(default)]
    pub gpus_total: usize,
    #[serde(default)]
    pub gpus_free: usize,
    #[serde(default)]
    pub gpus_busy: usize,
    #[serde(default)]
    pub gpus_held_idle: usize,
    #[serde(default)]
    pub gpus_fault: usize,
}

/// Answer to [`crate::Request::GpuFleet`].
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct GpuFleetPage {
    #[serde(default)]
    pub hosts: Vec<GpuHostView>,
    #[serde(default)]
    pub summary: GpuFleetSummary,
    #[serde(default)]
    pub server_time_ms: i64,
    /// Enrollment label that answered (filled by `SelfView`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub org: String,
}

/// One per-Linux-user GPU attribution row.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GpuUserRow {
    pub user: String,
    #[serde(default)]
    pub held_gpu_hours: f64,
    #[serde(default)]
    pub busy_gpu_hours: f64,
    #[serde(default)]
    pub live_gpus: u32,
    #[serde(default)]
    pub live_mem_mb: u64,
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// Answer to [`crate::Request::GpuUsers`].
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct GpuUsersPage {
    #[serde(default)]
    pub range: String,
    #[serde(default)]
    pub users: Vec<GpuUserRow>,
    /// Enrollment label that answered (filled by `SelfView`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub org: String,
}

/// One GPU alert pushed by the server over `rc:gpu.alert` and held in the
/// daemon's in-memory alert ring for desktop companion notifications.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GpuAlertItem {
    pub seq: u64,
    pub at: i64,
    pub severity: String,
    pub title: String,
    pub body: String,
    pub link: String,
}

/// Answer to [`crate::Request::GpuAlerts`].
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct GpuAlertsPage {
    #[serde(default)]
    pub alerts: Vec<GpuAlertItem>,
}
