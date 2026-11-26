// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — LocalAPI wire types for GPU fleet, user attribution, and alerts.
//!
//! Kept plain-serde in `meshharbor-localapi` (leaf crate; zero transport or
//! server dependencies). Field names match the JSON emitted by
//! `/api/agent/self/gpu/fleet`, `/api/agent/self/gpu/users`, and the daemon's
//! `rc:gpu.alert` ring buffer.

use serde::{Deserialize, Serialize};

/// One GPU process row as returned by `/api/agent/self/gpu/fleet` (matches
/// `meshharbor_remote_control::gpu::GpuProc`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GpuProcView {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Executable basename (truncated <= 32 chars; never argv/cmdline).
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// `"compute"` | `"graphics"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Host-level CPU / RAM / swap / disk / network snapshot alongside GPU cards
/// (matches `meshharbor_remote_control::gpu::HostLoad`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct GpuHostLoadView {
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

/// One GPU card inside a [`GpuHostView`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GpuCardView {
    pub uuid: String,
    pub idx: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `"free"` | `"busy"` | `"held_idle"` | `"unattributed"` | `"unknown"`.
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
    /// `"ok"` | `"partial"` | `"off"` | `"unsupported"` | `"unknown"`.
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
    /// `"fresh"` | `"stale"` | `"offline"`.
    #[serde(default)]
    pub freshness: String,
    /// `"ok"` | `"no_gpu"` | `"driver_missing"` | `"driver_reboot_pending"` | `"limited"` | `"off_local"` | `"sampler_stalled"` | `"driver_hung"` | `"unavailable"` | `"unknown"`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr139_localapi_deserializes_server_host_load_and_proc_wire_schema() {
        let raw = r#"{
            "hosts": [{
                "agent_id": "507f1f77bcf86cd799439011",
                "name": "gpu-box-01",
                "os": "linux",
                "source": "org",
                "is_online": true,
                "freshness": "fresh",
                "status": "ok",
                "interval_ms": 2000,
                "free_count": 0,
                "busy_count": 1,
                "held_idle_count": 0,
                "total_count": 1,
                "host": {
                    "cpu_pct": 22.5,
                    "load1": 1.42,
                    "load5": 1.1,
                    "load15": 0.9,
                    "cpu_count": 32,
                    "mem_used_mb": 65536,
                    "mem_total_mb": 262144,
                    "disk_root_used_gb": 120.5,
                    "disk_root_total_gb": 500.0,
                    "net_rx_bps": 1024000,
                    "net_tx_bps": 512000
                },
                "gpus": [{
                    "uuid": "GPU-0001",
                    "idx": 0,
                    "name": "A100",
                    "state": "unattributed",
                    "mem_used_mb": 40960,
                    "mem_total_mb": 81920,
                    "util_pct": 88,
                    "procs_state": "ok",
                    "procs": [{
                        "pid": 1234,
                        "user": "alice",
                        "name": "python3",
                        "mem_mb": 40960,
                        "sm_pct": 85,
                        "cpu_pct": 12.3,
                        "started_at": 1760000000,
                        "container": "docker:abc",
                        "kind": "compute"
                    }]
                }]
            }],
            "summary": {
                "hosts_total": 1,
                "hosts_online": 1,
                "gpus_total": 1,
                "gpus_free": 0,
                "gpus_busy": 1,
                "gpus_held_idle": 0,
                "gpus_fault": 0
            },
            "server_time_ms": 1760003600000
        }"#;
        let parsed: GpuFleetPage = serde_json::from_str(raw).expect("server fleet JSON must parse");
        let host = &parsed.hosts[0];
        assert_eq!(host.freshness, "fresh");
        assert_eq!(host.host.as_ref().unwrap().cpu_pct, Some(22.5));
        assert_eq!(host.host.as_ref().unwrap().load1, Some(1.42));
        assert_eq!(host.host.as_ref().unwrap().disk_root_used_gb, Some(120.5));
        let proc0 = &host.gpus[0].procs.as_ref().unwrap()[0];
        assert_eq!(proc0.name.as_deref(), Some("python3"));
        assert_eq!(proc0.started_at, Some(1_760_000_000));
        assert_eq!(proc0.container.as_deref(), Some("docker:abc"));
    }
}
