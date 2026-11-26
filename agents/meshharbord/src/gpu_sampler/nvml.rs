// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! NVIDIA NVML telemetry backend (FR-139 §3).
//!
//! Runs EXCLUSIVELY inside the `meshharbord gpu-sampler` child process.
//! Key safety invariants:
//! - Loaded dynamically at runtime (`libnvidia-ml.so.1`, `/usr/lib/wsl/lib/libnvidia-ml.so.1`,
//!   `nvml.dll`). Non-NVIDIA hosts pay zero startup cost.
//! - Initialized ONCE and NEVER unloaded (`std::mem::forget` on drop) to avoid
//!   NVML's known fd leak across unload/reload cycles.
//! - Every per-field query degrades to `None` when unsupported (NEVER `0`).
//! - Per-process utilization samples > 100% or older than the previous timestamp
//!   are dropped; unknown PIDs are ignored.

use std::collections::HashMap;
use std::ffi::OsStr;

use meshharbor_remote_control::gpu::{
    GpuHostStatus, GpuInventory, GpuInventoryItem, GpuProc, GpuSample, ProcsState,
};
use nvml_wrapper::bitmasks::device::ThrottleReasons;
use nvml_wrapper::enum_wrappers::device::{Clock, EccCounter, MemoryError, TemperatureSensor};
use nvml_wrapper::enums::device::{SampleValue, UsedGpuMemory};
use nvml_wrapper::error::NvmlError;
use nvml_wrapper::structs::device::FieldId;
use nvml_wrapper::Nvml;

/// Canonical NVML v12 field IDs for correctable / uncorrectable remapped rows
/// (`nvml-wrapper` 0.13 translates these automatically for newer drivers).
const NVML_FI_DEV_REMAPPED_COR: u32 = 142;
const NVML_FI_DEV_REMAPPED_UNC: u32 = 143;
/// `NVML_DEVICE_MIG_ENABLE` constant from `nvml.h`.
const NVML_MIG_ENABLE: u32 = 1;

use super::proc_linux::{ProcLookup, truncate_proc_name};

pub struct NvmlBackend {
    // Wrapped in `Option` so Drop can `std::mem::forget` it without calling
    // `nvmlShutdown`/`dlclose`.
    nvml: Option<Nvml>,
    driver_version: Option<String>,
    is_wsl: bool,
    last_util_ts: HashMap<String, u64>,
}

impl Drop for NvmlBackend {
    fn drop(&mut self) {
        if let Some(nvml) = self.nvml.take() {
            std::mem::forget(nvml);
        }
    }
}

pub enum NvmlInitOutcome {
    Ready(Box<NvmlBackend>),
    Status(GpuHostStatus),
    NotPresent,
}

impl NvmlBackend {
    pub fn try_init() -> NvmlInitOutcome {
        #[cfg(windows)]
        let candidates: &[&str] = &["nvml.dll"];
        #[cfg(not(windows))]
        let candidates: &[&str] = &[
            "libnvidia-ml.so.1",
            "/usr/lib/wsl/lib/libnvidia-ml.so.1",
            "libnvidia-ml.so",
        ];

        let mut last_err: Option<NvmlError> = None;
        for path in candidates {
            match Nvml::builder().lib_path(OsStr::new(path)).init() {
                Ok(nvml) => {
                    let driver_version = nvml.sys_driver_version().ok();
                    let is_wsl = detect_wsl2();
                    return NvmlInitOutcome::Ready(Box::new(Self {
                        nvml: Some(nvml),
                        driver_version,
                        is_wsl,
                        last_util_ts: HashMap::new(),
                    }));
                }
                Err(NvmlError::LibRmVersionMismatch) => {
                    return NvmlInitOutcome::Status(GpuHostStatus::DriverRebootPending);
                }
                Err(NvmlError::DriverNotLoaded) => {
                    last_err = Some(NvmlError::DriverNotLoaded);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        match last_err {
            Some(NvmlError::DriverNotLoaded) => NvmlInitOutcome::Status(GpuHostStatus::DriverMissing),
            _ => NvmlInitOutcome::NotPresent,
        }
    }

    pub fn driver_version(&self) -> Option<String> {
        self.driver_version.clone()
    }

    pub fn host_status(&self) -> GpuHostStatus {
        if self.is_wsl {
            GpuHostStatus::Limited
        } else {
            GpuHostStatus::Ok
        }
    }

    pub fn inventory(&self) -> GpuInventory {
        let Some(nvml) = self.nvml.as_ref() else {
            return GpuInventory {
                backend: Some("nvml".into()),
                driver_version: self.driver_version.clone(),
                gpus: Vec::new(),
                status: GpuHostStatus::Unavailable,
            };
        };
        let count = nvml.device_count().unwrap_or(0);
        let mut gpus = Vec::with_capacity(count as usize);
        for idx in 0..count {
            let Ok(dev) = nvml.device_by_index(idx) else {
                continue;
            };
            let uuid = dev.uuid().unwrap_or_else(|_| format!("nvidia-{idx}"));
            let name = dev.name().unwrap_or_else(|_| format!("NVIDIA GPU {idx}"));
            let mem_total_mb = dev
                .memory_info()
                .ok()
                .map(|m| (m.total / (1024 * 1024)) as u32);
            let power_limit_w = dev
                .enforced_power_limit()
                .or_else(|_| dev.power_management_limit())
                .ok()
                .map(|mw| (mw / 1000) as u16);
            let pci_bus = dev.pci_info().ok().map(|p| p.bus_id);
            let mig = dev
                .mig_mode()
                .ok()
                .is_some_and(|m| m.current == NVML_MIG_ENABLE);
            gpus.push(GpuInventoryItem {
                uuid,
                idx: idx as u16,
                name,
                mem_total_mb,
                power_limit_w,
                mig,
                pci_bus,
                unified: false,
            });
        }
        GpuInventory {
            backend: Some("nvml".into()),
            driver_version: self.driver_version.clone(),
            gpus,
            status: self.host_status(),
        }
    }

    pub fn sample(
        &mut self,
        include_procs: bool,
        proc_lookup: &ProcLookup,
        #[cfg(windows)] pdh_vram: &HashMap<u32, u32>,
    ) -> (GpuHostStatus, Vec<GpuSample>) {
        let Some(nvml) = self.nvml.as_ref() else {
            return (GpuHostStatus::Unavailable, Vec::new());
        };
        let count = match nvml.device_count() {
            Ok(c) => c,
            Err(NvmlError::LibRmVersionMismatch) => {
                return (GpuHostStatus::DriverRebootPending, Vec::new());
            }
            Err(_) => return (GpuHostStatus::Unavailable, Vec::new()),
        };

        let mut samples = Vec::with_capacity(count as usize);
        for idx in 0..count {
            let dev = match nvml.device_by_index(idx) {
                Ok(d) => d,
                Err(NvmlError::GpuLost) => {
                    samples.push(GpuSample {
                        uuid: format!("nvidia-lost-{idx}"),
                        idx: idx as u16,
                        lost: true,
                        procs_state: ProcsState::Unknown,
                        ..Default::default()
                    });
                    continue;
                }
                Err(_) => continue,
            };

            let uuid = match dev.uuid() {
                Ok(u) => u,
                Err(NvmlError::GpuLost) => {
                    samples.push(GpuSample {
                        uuid: format!("nvidia-lost-{idx}"),
                        idx: idx as u16,
                        lost: true,
                        procs_state: ProcsState::Unknown,
                        ..Default::default()
                    });
                    continue;
                }
                Err(_) => format!("nvidia-{idx}"),
            };

            let name = dev.name().ok();
            let pci_bus = dev.pci_info().ok().map(|p| p.bus_id);
            let (mem_used_mb, mem_total_mb) = match dev.memory_info() {
                Ok(m) => (
                    Some((m.used / (1024 * 1024)) as u32),
                    Some((m.total / (1024 * 1024)) as u32),
                ),
                Err(NvmlError::GpuLost) => {
                    samples.push(GpuSample {
                        uuid,
                        idx: idx as u16,
                        name,
                        pci_bus,
                        lost: true,
                        procs_state: ProcsState::Unknown,
                        ..Default::default()
                    });
                    continue;
                }
                Err(_) => (None, None),
            };
            let util_pct = dev
                .utilization_rates()
                .ok()
                .and_then(|u| (u.gpu <= 100).then_some(u.gpu as u8));
            let temp_c = dev
                .temperature(TemperatureSensor::Gpu)
                .ok()
                .map(|t| t as i16);
            let power_w = dev.power_usage().ok().map(|mw| (mw / 1000) as u16);
            let power_limit_w = dev
                .enforced_power_limit()
                .or_else(|_| dev.power_management_limit())
                .ok()
                .map(|mw| (mw / 1000) as u16);
            let fan_pct = dev
                .fan_speed(0)
                .ok()
                .and_then(|f| (f <= 100).then_some(f as u8));
            let sm_clock_mhz = dev.clock_info(Clock::SM).ok().map(|c| c as u16);
            let throttle = dev
                .current_throttle_reasons()
                .ok()
                .map(map_throttle_reasons)
                .filter(|v| !v.is_empty());
            let ecc_uncorrected = dev
                .total_ecc_errors(MemoryError::Uncorrected, EccCounter::Volatile)
                .or_else(|_| dev.total_ecc_errors(MemoryError::Uncorrected, EccCounter::Aggregate))
                .ok();
            let remapped_rows = read_remapped_rows(&dev);
            let mig = dev
                .mig_mode()
                .ok()
                .is_some_and(|m| m.current == NVML_MIG_ENABLE);

            let (procs_state, procs) = if !include_procs {
                (ProcsState::Off, None)
            } else {
                // Per-process SM utilization map (drop > 100% and stale timestamps).
                let last_ts = self.last_util_ts.get(&uuid).copied().unwrap_or(0);
                let mut max_ts = last_ts;
                let mut sm_by_pid: HashMap<u32, u8> = HashMap::new();
                if let Ok(util_samples) = dev.process_utilization_stats(last_ts) {
                    for s in util_samples {
                        if s.timestamp <= last_ts || s.sm_util > 100 {
                            continue;
                        }
                        if s.timestamp > max_ts {
                            max_ts = s.timestamp;
                        }
                        sm_by_pid.insert(s.pid, s.sm_util as u8);
                    }
                }
                self.last_util_ts.insert(uuid.clone(), max_ts);

                let mut by_pid: HashMap<u32, GpuProc> = HashMap::new();
                let mut any_query_ok = false;
                let mut partial = false;

                if let Ok(list) = dev.running_compute_processes() {
                    any_query_ok = true;
                    for p in list {
                        let mem_mb = match p.used_gpu_memory {
                            UsedGpuMemory::Used(b) => Some((b / (1024 * 1024)) as u32),
                            UsedGpuMemory::Unavailable => {
                                #[cfg(windows)]
                                {
                                    pdh_vram.get(&p.pid).copied()
                                }
                                #[cfg(not(windows))]
                                {
                                    None
                                }
                            }
                        };
                        let attr = proc_lookup.lookup(p.pid);
                        if attr.access_denied {
                            partial = true;
                        }
                        by_pid.insert(
                            p.pid,
                            GpuProc {
                                pid: p.pid,
                                user: attr.user,
                                name: attr.name.map(|n| truncate_proc_name(&n)),
                                mem_mb,
                                sm_pct: sm_by_pid.get(&p.pid).copied(),
                                cpu_pct: None,
                                started_at: attr.started_at,
                                container: attr.container,
                                kind: Some("compute".into()),
                            },
                        );
                    }
                }
                if let Ok(list) = dev.running_graphics_processes() {
                    any_query_ok = true;
                    for p in list {
                        let mem_mb = match p.used_gpu_memory {
                            UsedGpuMemory::Used(b) => Some((b / (1024 * 1024)) as u32),
                            UsedGpuMemory::Unavailable => {
                                #[cfg(windows)]
                                {
                                    pdh_vram.get(&p.pid).copied()
                                }
                                #[cfg(not(windows))]
                                {
                                    None
                                }
                            }
                        };
                        by_pid
                            .entry(p.pid)
                            .and_modify(|existing| {
                                if existing.mem_mb.is_none() {
                                    existing.mem_mb = mem_mb;
                                }
                            })
                            .or_insert_with(|| {
                                let attr = proc_lookup.lookup(p.pid);
                                if attr.access_denied {
                                    partial = true;
                                }
                                GpuProc {
                                    pid: p.pid,
                                    user: attr.user,
                                    name: attr.name.map(|n| truncate_proc_name(&n)),
                                    mem_mb,
                                    sm_pct: sm_by_pid.get(&p.pid).copied(),
                                    cpu_pct: None,
                                    started_at: attr.started_at,
                                    container: attr.container,
                                    kind: Some("graphics".into()),
                                }
                            });
                    }
                }

                if !any_query_ok {
                    (ProcsState::Unsupported, None)
                } else {
                    let mut list: Vec<GpuProc> = by_pid.into_values().collect();
                    list.sort_by(|a, b| b.mem_mb.cmp(&a.mem_mb).then_with(|| a.pid.cmp(&b.pid)));
                    let state = if partial {
                        ProcsState::Partial
                    } else {
                        ProcsState::Ok
                    };
                    (state, Some(list))
                }
            };

            samples.push(GpuSample {
                uuid,
                idx: idx as u16,
                name,
                mem_total_mb,
                power_limit_w,
                pci_bus,
                unified: false,
                util_pct,
                mem_used_mb,
                temp_c,
                power_w,
                fan_pct,
                sm_clock_mhz,
                throttle,
                ecc_uncorrected,
                remapped_rows,
                xid_errors: None,
                mig,
                lost: false,
                idle_since: None,
                procs_state,
                procs,
            });
        }

        (self.host_status(), samples)
    }
}

fn read_remapped_rows(dev: &nvml_wrapper::Device<'_>) -> Option<u32> {
    let vals = dev
        .field_values_for(&[
            FieldId(NVML_FI_DEV_REMAPPED_COR),
            FieldId(NVML_FI_DEV_REMAPPED_UNC),
        ])
        .ok()?;
    let mut total: u32 = 0;
    let mut any = false;
    for entry in vals {
        if let Ok(sample) = entry
            && let Ok(v) = sample.value
        {
            let n = match v {
                SampleValue::U32(x) => Some(x),
                SampleValue::U64(x) => u32::try_from(x).ok(),
                SampleValue::I64(x) if x >= 0 => u32::try_from(x).ok(),
                _ => None,
            };
            if let Some(n) = n {
                total = total.saturating_add(n);
                any = true;
            }
        }
    }
    any.then_some(total)
}

fn map_throttle_reasons(r: ThrottleReasons) -> Vec<String> {
    let mut out = Vec::new();
    if r.contains(ThrottleReasons::HW_SLOWDOWN) {
        out.push("hw_slowdown".into());
    }
    if r.contains(ThrottleReasons::HW_THERMAL_SLOWDOWN) {
        out.push("thermal".into());
    }
    if r.contains(ThrottleReasons::HW_POWER_BRAKE_SLOWDOWN) {
        out.push("power_brake".into());
    }
    if r.contains(ThrottleReasons::SW_POWER_CAP) {
        out.push("power_cap".into());
    }
    if r.contains(ThrottleReasons::SW_THERMAL_SLOWDOWN) {
        out.push("sw_thermal".into());
    }
    if r.contains(ThrottleReasons::SYNC_BOOST) {
        out.push("sync_boost".into());
    }
    out
}

fn detect_wsl2() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(v) = std::fs::read_to_string("/proc/version") {
            let lower = v.to_ascii_lowercase();
            return lower.contains("microsoft") || lower.contains("wsl");
        }
    }
    false
}
