// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Apple Silicon GPU telemetry backend via `macmon` (no sudo; FR-139 §3).
//!
//! Reports `unified: true` and `procs_state: ProcsState::Unsupported` (macOS
//! provides no public per-process GPU attribution API). Guards broken zero
//! readings (e.g. macOS 27 IOReport regression) as `None` rather than `0`.

use meshharbor_remote_control::gpu::{
    GpuHostStatus, GpuInventory, GpuSample,
};
#[cfg(target_os = "macos")]
use meshharbor_remote_control::gpu::{GpuInventoryItem, ProcsState};

pub struct AppleBackend {
    #[cfg(target_os = "macos")]
    sampler: macmon::Sampler,
    #[cfg(target_os = "macos")]
    chip_name: String,
    #[cfg(target_os = "macos")]
    mem_total_mb: Option<u32>,
}

impl AppleBackend {
    pub fn try_init() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            let sampler = macmon::Sampler::new().ok()?;
            let sys = sysinfo::System::new_with_specifics(
                sysinfo::RefreshKind::nothing()
                    .with_memory(sysinfo::MemoryRefreshKind::nothing().with_ram()),
            );
            let mem_total_mb = (sys.total_memory() > 0)
                .then(|| (sys.total_memory() / (1024 * 1024)) as u32);
            let chip_name = "Apple Silicon GPU".to_string();
            Some(Self {
                sampler,
                chip_name,
                mem_total_mb,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub fn inventory(&self) -> GpuInventory {
        #[cfg(target_os = "macos")]
        {
            GpuInventory {
                backend: Some("apple".into()),
                driver_version: None,
                gpus: vec![GpuInventoryItem {
                    uuid: "apple-gpu-0".into(),
                    idx: 0,
                    name: self.chip_name.clone(),
                    mem_total_mb: self.mem_total_mb,
                    power_limit_w: None,
                    mig: false,
                    pci_bus: None,
                    unified: true,
                }],
                status: GpuHostStatus::Ok,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            GpuInventory::default()
        }
    }

    pub fn sample(&mut self, _include_procs: bool) -> (GpuHostStatus, Vec<GpuSample>) {
        #[cfg(target_os = "macos")]
        {
            let Ok(m) = self.sampler.get_metrics(100) else {
                return (GpuHostStatus::Unavailable, Vec::new());
            };
            // macOS 27 IOReport zero-guard: if both gpu freq & active ratio are
            // strictly 0 while power is also 0, treat util as None rather than
            // fabricating 0%.
            let util_pct =
                if m.gpu_freq_mhz == 0 && m.gpu_active_ratio <= 0.0 && m.gpu_power <= 0.0 {
                    None
                } else {
                    Some((m.gpu_active_ratio * 100.0).clamp(0.0, 100.0).round() as u8)
                };
            let temp_c = m
                .temp
                .gpu_temp_avg
                .filter(|&t| t > 0.0)
                .map(|t| t.round() as i16);
            let power_w = (m.gpu_power > 0.0).then(|| m.gpu_power.round() as u16);
            let sm_clock_mhz = (m.gpu_freq_mhz > 0)
                .then(|| u16::try_from(m.gpu_freq_mhz).unwrap_or(u16::MAX));
            let mem_used_mb = (m.memory.ram_usage > 0)
                .then(|| (m.memory.ram_usage / (1024 * 1024)) as u32);
            let mem_total_mb = (m.memory.ram_total > 0)
                .then(|| (m.memory.ram_total / (1024 * 1024)) as u32)
                .or(self.mem_total_mb);

            let sample = GpuSample {
                uuid: "apple-gpu-0".into(),
                idx: 0,
                name: Some(self.chip_name.clone()),
                mem_total_mb,
                power_limit_w: None,
                pci_bus: None,
                unified: true,
                util_pct,
                mem_used_mb,
                temp_c,
                power_w,
                fan_pct: None,
                sm_clock_mhz,
                throttle: None,
                ecc_uncorrected: None,
                remapped_rows: None,
                xid_errors: None,
                mig: false,
                lost: false,
                idle_since: None,
                free_mem_floor_mb: None,
                procs_state: ProcsState::Unsupported,
                procs: None,
            };
            (GpuHostStatus::Ok, vec![sample])
        }
        #[cfg(not(target_os = "macos"))]
        {
            (GpuHostStatus::NoGpu, Vec::new())
        }
    }
}
