// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! NVIDIA NVML telemetry backend (FR-139 §3).
//!
//! Runs EXCLUSIVELY inside the `meshharbord gpu-sampler` child process.
//! Key safety invariants:
//! - Loaded dynamically at runtime (`libnvidia-ml.so.1`, `/usr/lib/wsl/lib/libnvidia-ml.so.1`,
//!   `nvml.dll`). Non-NVIDIA hosts pay zero startup cost.
//! - Initialized ONCE and leaked (`Box::leak`) so `nvmlShutdown`/`dlclose` is
//!   never called (avoids NVML's known fd leak across unload/reload cycles) AND
//!   enables a process-lifetime `EventSet<'static>` for Xid error collection.
//! - Every per-field query degrades to `None` when unsupported (NEVER `0`).
//! - ECC reports **volatile** uncorrectable errors only (never silently switches
//!   to lifetime Aggregate on transient read failure).
//! - Remapped rows separate uncorrectable count from `remap_pending` and
//!   `remap_failure`.
//! - Device identity `(uuid, name, pci_bus)` is cached per index so `GpuLost`
//!   attaches to the real GPU UUID rather than fabricating `nvidia-lost-{idx}`.

use std::collections::HashMap;
#[cfg(not(target_os = "macos"))]
use std::ffi::OsStr;

use meshharbor_remote_control::gpu::{
    GpuHostStatus, GpuInventory, GpuInventoryItem, GpuProc, GpuSample, ProcsState,
};
use nvml_wrapper::Nvml;
use nvml_wrapper::bitmasks::device::ThrottleReasons;
#[cfg(target_os = "linux")]
use nvml_wrapper::bitmasks::event::EventTypes;
use nvml_wrapper::enum_wrappers::device::{Clock, EccCounter, MemoryError, TemperatureSensor};
use nvml_wrapper::enums::device::{SampleValue, UsedGpuMemory};
#[cfg(target_os = "linux")]
use nvml_wrapper::enums::event::XidError;
use nvml_wrapper::error::NvmlError;
use nvml_wrapper::structs::device::FieldId;

/// Canonical NVML v12/v13 field IDs for uncorrectable / pending / failure row remapping.
const NVML_FI_DEV_REMAPPED_UNC: u32 = 143;
const NVML_FI_DEV_REMAPPED_PENDING: u32 = 144;
const NVML_FI_DEV_REMAPPED_FAILURE: u32 = 145;
/// `NVML_DEVICE_MIG_ENABLE` constant from `nvml.h`.
const NVML_MIG_ENABLE: u32 = 1;
/// Retain observed Xid events for 10 minutes so all leased orgs observe them.
#[cfg(target_os = "linux")]
const XID_RETENTION_SECS: i64 = 600;

use super::proc_linux::{ProcLookup, truncate_proc_name};

#[derive(Debug, Clone)]
struct RememberedIdentity {
    uuid: String,
    name: Option<String>,
    pci_bus: Option<String>,
}

pub struct NvmlBackend {
    // Leaked once for child lifetime so NVML is never unloaded and EventSet
    // can safely borrow `&'static Nvml`.
    nvml: &'static Nvml,
    driver_version: Option<String>,
    is_wsl: bool,
    last_util_ts: HashMap<String, u64>,
    last_identity: HashMap<u32, RememberedIdentity>,
    #[cfg(target_os = "linux")]
    xid_events: Option<nvml_wrapper::EventSet<'static>>,
    #[cfg(target_os = "linux")]
    recent_xids: HashMap<String, Vec<(u32, i64)>>,
}

/// Locate `nvml.dll` exclusively inside Windows `System32` using
/// `LOAD_LIBRARY_SEARCH_SYSTEM32` so a DLL planted in CWD or PATH can never be
/// loaded by the SYSTEM `gpu-sampler` child.
#[cfg(windows)]
fn resolve_windows_system32_nvml() -> Option<std::path::PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleFileNameW, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };

    let dll: Vec<u16> = "nvml.dll\0".encode_utf16().collect();
    // SAFETY: `dll` is NUL-terminated UTF-16; `LOAD_LIBRARY_SEARCH_SYSTEM32`
    // restricts search strictly to System32. NVML is intentionally never
    // unloaded across the lifetime of the child process.
    let module =
        unsafe { LoadLibraryExW(dll.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 512];
    // SAFETY: `module` is valid and `buf` holds `buf.len()` UTF-16 elements.
    let len = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 || len >= buf.len() {
        return None;
    }
    let path = std::path::PathBuf::from(OsString::from_wide(&buf[..len]));
    path.is_file().then_some(path)
}

pub enum NvmlInitOutcome {
    Ready(Box<NvmlBackend>),
    Status(GpuHostStatus, String),
    NotPresent,
}

#[cfg(not(target_os = "macos"))]
fn init_err_priority(err: &NvmlError) -> u8 {
    match err {
        NvmlError::LibRmVersionMismatch => 5,
        NvmlError::DriverNotLoaded => 4,
        NvmlError::NoPermission => 3,
        NvmlError::InsufficientPower | NvmlError::OperatingSystem => 2,
        NvmlError::LibloadingError(_) => 1,
        _ => 2,
    }
}

impl NvmlBackend {
    pub fn try_init() -> NvmlInitOutcome {
        // macOS has no NVIDIA NVML driver; never dlopen bare leaf names there.
        #[cfg(target_os = "macos")]
        {
            return NvmlInitOutcome::NotPresent;
        }

        // On Windows, `meshharbord gpu-sampler` runs as SYSTEM. Loading bare
        // `"nvml.dll"` falls through to CWD and PATH when no NVIDIA driver is
        // installed (DLL hijacking). Resolve strictly from System32 via
        // `LOAD_LIBRARY_SEARCH_SYSTEM32` and pass the verified absolute path.
        #[cfg(windows)]
        let candidates: Vec<std::path::PathBuf> = match resolve_windows_system32_nvml() {
            Some(p) => vec![p],
            None => return NvmlInitOutcome::NotPresent,
        };
        #[cfg(all(not(windows), not(target_os = "macos")))]
        let candidates: Vec<std::path::PathBuf> = [
            "libnvidia-ml.so.1",
            "/usr/lib/wsl/lib/libnvidia-ml.so.1",
            "libnvidia-ml.so",
        ]
        .into_iter()
        .map(std::path::PathBuf::from)
        .collect();

        #[cfg(not(target_os = "macos"))]
        {
            // Keep the STRONGEST diagnostic error across all candidates so a
            // later missing `.so` path never overwrites an earlier
            // `DriverNotLoaded` or `NoPermission`.
            let mut best_err: Option<NvmlError> = None;
            for path in &candidates {
                match Nvml::builder().lib_path(OsStr::new(path)).init() {
                    Ok(nvml) => {
                        let nvml_ref: &'static Nvml = Box::leak(Box::new(nvml));
                        let driver_version = nvml_ref.sys_driver_version().ok();
                        let is_wsl = detect_wsl2();
                        let mut last_identity = HashMap::new();
                        if let Ok(count) = nvml_ref.device_count() {
                            for idx in 0..count {
                                if let Ok(dev) = nvml_ref.device_by_index(idx)
                                    && let Ok(uuid) = dev.uuid()
                                {
                                    last_identity.insert(
                                        idx,
                                        RememberedIdentity {
                                            uuid,
                                            name: dev.name().ok(),
                                            pci_bus: dev.pci_info().ok().map(|p| p.bus_id),
                                        },
                                    );
                                }
                            }
                        }
                        #[cfg(target_os = "linux")]
                        let xid_events = if !is_wsl {
                            init_xid_event_set(nvml_ref)
                        } else {
                            None
                        };
                        return NvmlInitOutcome::Ready(Box::new(Self {
                            nvml: nvml_ref,
                            driver_version,
                            is_wsl,
                            last_util_ts: HashMap::new(),
                            last_identity,
                            #[cfg(target_os = "linux")]
                            xid_events,
                            #[cfg(target_os = "linux")]
                            recent_xids: HashMap::new(),
                        }));
                    }
                    Err(NvmlError::LibRmVersionMismatch) => {
                        return NvmlInitOutcome::Status(
                            GpuHostStatus::DriverRebootPending,
                            "NVML library/kernel driver version mismatch — reboot or reload nvidia kernel module"
                                .into(),
                        );
                    }
                    Err(e) => {
                        let replace = best_err
                            .as_ref()
                            .is_none_or(|cur| init_err_priority(&e) > init_err_priority(cur));
                        if replace {
                            best_err = Some(e);
                        }
                    }
                }
            }

            match best_err {
                Some(NvmlError::DriverNotLoaded) => NvmlInitOutcome::Status(
                    GpuHostStatus::DriverMissing,
                    "libnvidia-ml loaded, but nvidia kernel module is not loaded".into(),
                ),
                Some(NvmlError::NoPermission) => NvmlInitOutcome::Status(
                    GpuHostStatus::Limited,
                    "Permission denied accessing NVIDIA driver (/dev/nvidia* or NVML)".into(),
                ),
                _ => NvmlInitOutcome::NotPresent,
            }
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

    pub fn status_detail(&self) -> Option<String> {
        self.is_wsl
            .then(|| "WSL2 environment: per-process GPU attribution unavailable".to_string())
    }

    pub fn inventory(&self) -> GpuInventory {
        let count = self.nvml.device_count().unwrap_or(0);
        let mut gpus = Vec::with_capacity(count as usize);
        for idx in 0..count {
            let Ok(dev) = self.nvml.device_by_index(idx) else {
                if let Some(rem) = self.last_identity.get(&idx) {
                    gpus.push(GpuInventoryItem {
                        uuid: rem.uuid.clone(),
                        idx: idx as u16,
                        name: rem
                            .name
                            .clone()
                            .unwrap_or_else(|| format!("NVIDIA GPU {idx}")),
                        mem_total_mb: None,
                        power_limit_w: None,
                        mig: false,
                        pci_bus: rem.pci_bus.clone(),
                        unified: false,
                    });
                }
                continue;
            };
            let uuid = dev.uuid().unwrap_or_else(|_| {
                self.last_identity
                    .get(&idx)
                    .map(|r| r.uuid.clone())
                    .unwrap_or_else(|| format!("nvidia-{idx}"))
            });
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
            status_detail: self.status_detail(),
        }
    }

    pub fn sample(
        &mut self,
        include_procs: bool,
        proc_lookup: &ProcLookup,
        #[cfg(windows)] pdh_vram: &HashMap<(u32, String), u32>,
    ) -> (GpuHostStatus, Vec<GpuSample>) {
        let now_s = chrono::Utc::now().timestamp();
        #[cfg(target_os = "linux")]
        self.drain_xid_events(now_s);

        let count = match self.nvml.device_count() {
            Ok(c) => c,
            Err(NvmlError::LibRmVersionMismatch) => {
                return (GpuHostStatus::DriverRebootPending, Vec::new());
            }
            Err(_) => return (GpuHostStatus::Unavailable, Vec::new()),
        };

        let mut samples = Vec::with_capacity(count as usize);
        for idx in 0..count {
            let dev = match self.nvml.device_by_index(idx) {
                Ok(d) => d,
                Err(NvmlError::GpuLost) => {
                    let rem = self.last_identity.get(&idx);
                    samples.push(GpuSample {
                        uuid: rem
                            .map(|r| r.uuid.clone())
                            .unwrap_or_else(|| format!("nvidia-lost-{idx}")),
                        idx: idx as u16,
                        name: rem.and_then(|r| r.name.clone()),
                        pci_bus: rem.and_then(|r| r.pci_bus.clone()),
                        backend: Some("nvml".into()),
                        vendor_index: Some(idx as u16),
                        lost: true,
                        procs_state: ProcsState::Unknown,
                        ..Default::default()
                    });
                    continue;
                }
                Err(e) => {
                    if let Some(rem) = self.last_identity.get(&idx) {
                        samples.push(GpuSample {
                            uuid: rem.uuid.clone(),
                            idx: idx as u16,
                            name: rem.name.clone(),
                            pci_bus: rem.pci_bus.clone(),
                            backend: Some("nvml".into()),
                            vendor_index: Some(idx as u16),
                            vendor_health: Some(format!("nvml_error:{e:?}")),
                            procs_state: ProcsState::Unknown,
                            ..Default::default()
                        });
                    }
                    continue;
                }
            };

            let uuid = match dev.uuid() {
                Ok(u) => u,
                Err(NvmlError::GpuLost) => {
                    let rem = self.last_identity.get(&idx);
                    samples.push(GpuSample {
                        uuid: rem
                            .map(|r| r.uuid.clone())
                            .unwrap_or_else(|| format!("nvidia-lost-{idx}")),
                        idx: idx as u16,
                        name: rem.and_then(|r| r.name.clone()),
                        pci_bus: rem.and_then(|r| r.pci_bus.clone()),
                        backend: Some("nvml".into()),
                        vendor_index: Some(idx as u16),
                        lost: true,
                        procs_state: ProcsState::Unknown,
                        ..Default::default()
                    });
                    continue;
                }
                Err(_) => self
                    .last_identity
                    .get(&idx)
                    .map(|r| r.uuid.clone())
                    .unwrap_or_else(|| format!("nvidia-{idx}")),
            };

            let name = dev.name().ok().or_else(|| {
                self.last_identity
                    .get(&idx)
                    .and_then(|r| r.name.clone())
            });
            let pci_bus = dev.pci_info().ok().map(|p| p.bus_id).or_else(|| {
                self.last_identity
                    .get(&idx)
                    .and_then(|r| r.pci_bus.clone())
            });
            self.last_identity.insert(
                idx,
                RememberedIdentity {
                    uuid: uuid.clone(),
                    name: name.clone(),
                    pci_bus: pci_bus.clone(),
                },
            );

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
                        backend: Some("nvml".into()),
                        vendor_index: Some(idx as u16),
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
            // Volatile ECC ONLY — never silently switch to lifetime Aggregate
            // on a transient Volatile read error (which would spike alerts).
            let ecc_uncorrected = dev
                .total_ecc_errors(MemoryError::Uncorrected, EccCounter::Volatile)
                .ok();
            let (remapped_rows, remap_pending, remap_failure) = read_remapped_rows_detail(&dev);
            let mig = dev
                .mig_mode()
                .ok()
                .is_some_and(|m| m.current == NVML_MIG_ENABLE);

            #[cfg(target_os = "linux")]
            let (xid_errors, xid_last_at) = self.xids_for_uuid(&uuid, now_s);
            #[cfg(not(target_os = "linux"))]
            let (xid_errors, xid_last_at) = {
                let _ = now_s;
                (None, None)
            };

            let (procs_state, procs) = if !include_procs {
                (ProcsState::Off, None)
            } else if self.is_wsl {
                // WSL2 NVML exposes valid VRAM/util but omits host process PIDs.
                (ProcsState::Unsupported, None)
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
                let mut compute_ok = false;
                let mut graphics_ok = false;
                let mut partial = false;

                if let Ok(list) = dev.running_compute_processes() {
                    compute_ok = true;
                    for p in list {
                        let mem_mb = match p.used_gpu_memory {
                            UsedGpuMemory::Used(b) => Some((b / (1024 * 1024)) as u32),
                            UsedGpuMemory::Unavailable => {
                                #[cfg(windows)]
                                {
                                    super::windows_pdh::lookup_unambiguous_vram_mb(
                                        pdh_vram,
                                        p.pid,
                                        usize::try_from(count).unwrap_or(2),
                                    )
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
                    graphics_ok = true;
                    for p in list {
                        let mem_mb = match p.used_gpu_memory {
                            UsedGpuMemory::Used(b) => Some((b / (1024 * 1024)) as u32),
                            UsedGpuMemory::Unavailable => {
                                #[cfg(windows)]
                                {
                                    super::windows_pdh::lookup_unambiguous_vram_mb(
                                        pdh_vram,
                                        p.pid,
                                        usize::try_from(count).unwrap_or(2),
                                    )
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

                if !compute_ok && !graphics_ok {
                    (ProcsState::Unsupported, None)
                } else {
                    if !compute_ok || !graphics_ok {
                        // Compute or graphics enumeration failed on this tick.
                        partial = true;
                    }
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
                xid_errors,
                xid_last_at,
                remap_pending,
                remap_failure,
                mig,
                lost: false,
                vendor_health: None,
                backend: Some("nvml".into()),
                backend_status: None,
                vendor_index: Some(idx as u16),
                presence_only: false,
                idle_since: None,
                free_mem_floor_mb: None,
                procs_state,
                procs,
            });
        }

        (self.host_status(), samples)
    }

    #[cfg(target_os = "linux")]
    fn drain_xid_events(&mut self, now_s: i64) {
        let Some(set) = self.xid_events.as_ref() else {
            return;
        };
        // Non-blocking drain (timeout = 0 ms), capped at 64 events per tick.
        for _ in 0..64 {
            match set.wait(0) {
                Ok(ev) => {
                    if let Some(xid_err) = ev.event_data
                        && let Ok(uuid) = ev.device.uuid()
                    {
                        let code = match xid_err {
                            XidError::Value(v) => u32::try_from(v).unwrap_or(999),
                            XidError::Unknown => 999,
                        };
                        let list = self.recent_xids.entry(uuid).or_default();
                        if list.len() >= 32 {
                            list.remove(0);
                        }
                        list.push((code, now_s));
                    }
                }
                Err(NvmlError::Timeout) => break,
                Err(_) => break,
            }
        }
        // Evict entries older than XID_RETENTION_SECS.
        let cutoff = now_s.saturating_sub(XID_RETENTION_SECS);
        for entries in self.recent_xids.values_mut() {
            entries.retain(|(_, ts)| *ts >= cutoff);
        }
        self.recent_xids.retain(|_, v| !v.is_empty());
    }

    #[cfg(target_os = "linux")]
    fn xids_for_uuid(&self, uuid: &str, now_s: i64) -> (Option<Vec<u32>>, Option<i64>) {
        let Some(entries) = self.recent_xids.get(uuid) else {
            return (None, None);
        };
        let cutoff = now_s.saturating_sub(XID_RETENTION_SECS);
        let mut codes: Vec<u32> = Vec::new();
        let mut last_at: Option<i64> = None;
        for &(code, ts) in entries {
            if ts < cutoff {
                continue;
            }
            if !codes.contains(&code) {
                codes.push(code);
            }
            last_at = Some(last_at.map_or(ts, |p| p.max(ts)));
        }
        if codes.is_empty() {
            (None, None)
        } else {
            (Some(codes), last_at)
        }
    }
}

#[cfg(target_os = "linux")]
fn init_xid_event_set(nvml: &'static Nvml) -> Option<nvml_wrapper::EventSet<'static>> {
    let mut set = nvml.create_event_set().ok()?;
    let count = nvml.device_count().ok()?;
    let mut any_registered = false;
    for idx in 0..count {
        let Ok(dev) = nvml.device_by_index(idx) else {
            continue;
        };
        match dev.register_events(EventTypes::CRITICAL_XID_ERROR, set) {
            Ok(next_set) => {
                set = next_set;
                any_registered = true;
            }
            Err(_) => {
                // `register_events` consumed & freed `set` on error; recreate if
                // more devices remain or abort gracefully without affecting metrics.
                return None;
            }
        }
    }
    any_registered.then_some(set)
}

fn read_remapped_rows_detail(dev: &nvml_wrapper::Device<'_>) -> (Option<u32>, bool, bool) {
    let Ok(vals) = dev.field_values_for(&[
        FieldId(NVML_FI_DEV_REMAPPED_UNC),
        FieldId(NVML_FI_DEV_REMAPPED_PENDING),
        FieldId(NVML_FI_DEV_REMAPPED_FAILURE),
    ]) else {
        return (None, false, false);
    };
    let mut unc: Option<u32> = None;
    let mut pending = false;
    let mut failure = false;
    for entry in vals {
        let Ok(sample) = entry else { continue };
        let Ok(v) = sample.value else { continue };
        let n = match v {
            SampleValue::U32(x) => Some(u64::from(x)),
            SampleValue::U64(x) => Some(x),
            SampleValue::I64(x) if x >= 0 => Some(x as u64),
            _ => None,
        };
        let Some(val) = n else { continue };
        match sample.field.0 {
            NVML_FI_DEV_REMAPPED_UNC => unc = u32::try_from(val).ok(),
            NVML_FI_DEV_REMAPPED_PENDING => pending = val > 0,
            NVML_FI_DEV_REMAPPED_FAILURE => failure = val > 0,
            _ => {}
        }
    }
    (unc, pending, failure)
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
