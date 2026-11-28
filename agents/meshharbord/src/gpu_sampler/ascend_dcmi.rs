// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Direct runtime-loaded Huawei Ascend DCMI C API backend (`libdcmi.so`).
//!
//! Runs EXCLUSIVELY inside the isolated `meshharbord gpu-sampler` child process
//! on Linux. Uses `libloading` to dynamically open the host's installed
//! `libdcmi.so` with zero compile-time linkage and zero vendor package
//! installation. Samples all cards concurrently via `std::thread::scope` so an
//! 8-card Ascend 910B host completes a full tick (AICore utilization, HBM,
//! temperature, power, health, AICore clock, and running processes) in ~80 ms
//! instead of ~1.2 s via `npu-smi info`.
//!
//! If `libdcmi.so` is absent or fails initialization, `AscendBackend` falls
//! back automatically to `npu-smi` tool mode and then `/dev/davinci*` mode.

#[cfg(target_os = "linux")]
use std::ffi::{c_char, c_int, c_uint, c_ulong};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use meshharbor_remote_control::gpu::{
    GpuHostStatus, GpuInventory, GpuInventoryItem, GpuProc, GpuSample, ProcsState,
};

#[cfg(target_os = "linux")]
use super::ascend::ascend_free_mem_floor_mb;
#[cfg(target_os = "linux")]
use super::proc_linux::{ProcLookup, truncate_proc_name};

#[cfg(target_os = "linux")]
const DCMI_LIB_CANDIDATES: &[&str] = &[
    "/usr/local/Ascend/driver/lib64/driver/libdcmi.so",
    "/usr/local/Ascend/driver/lib64/libdcmi.so",
    "/usr/lib64/libdcmi.so",
    "/usr/lib/x86_64-linux-gnu/libdcmi.so",
    "/usr/lib/aarch64-linux-gnu/libdcmi.so",
];

#[cfg(target_os = "linux")]
const DCMI_UTILIZATION_RATE_AICORE: c_int = 2;
#[cfg(target_os = "linux")]
const DCMI_MAX_CARDS: usize = 64;
#[cfg(target_os = "linux")]
const DCMI_MAX_PROCS_PER_DEV: usize = 64;
#[cfg(target_os = "linux")]
const MAX_CHIP_NAME_LEN: usize = 32;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct DcmiChipInfo {
    chip_type: [u8; MAX_CHIP_NAME_LEN],
    chip_name: [u8; MAX_CHIP_NAME_LEN],
    chip_ver: [u8; MAX_CHIP_NAME_LEN],
    aicore_cnt: c_uint,
}

#[cfg(target_os = "linux")]
impl Default for DcmiChipInfo {
    fn default() -> Self {
        Self {
            chip_type: [0; MAX_CHIP_NAME_LEN],
            chip_name: [0; MAX_CHIP_NAME_LEN],
            chip_ver: [0; MAX_CHIP_NAME_LEN],
            aicore_cnt: 0,
        }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct DcmiChipInfoV2 {
    chip_type: [u8; MAX_CHIP_NAME_LEN],
    chip_name: [u8; MAX_CHIP_NAME_LEN],
    chip_ver: [u8; MAX_CHIP_NAME_LEN],
    aicore_cnt: c_uint,
    npu_name: [u8; MAX_CHIP_NAME_LEN],
}

#[cfg(target_os = "linux")]
impl Default for DcmiChipInfoV2 {
    fn default() -> Self {
        Self {
            chip_type: [0; MAX_CHIP_NAME_LEN],
            chip_name: [0; MAX_CHIP_NAME_LEN],
            chip_ver: [0; MAX_CHIP_NAME_LEN],
            aicore_cnt: 0,
            npu_name: [0; MAX_CHIP_NAME_LEN],
        }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DcmiPcieInfo {
    deviceid: c_uint,
    venderid: c_uint,
    subvenderid: c_uint,
    subdeviceid: c_uint,
    bdf_deviceid: c_uint,
    bdf_busid: c_uint,
    bdf_funcid: c_uint,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DcmiPcieInfoAll {
    venderid: c_uint,
    subvenderid: c_uint,
    deviceid: c_uint,
    subdeviceid: c_uint,
    domain: c_int,
    bdf_busid: c_uint,
    bdf_deviceid: c_uint,
    bdf_funcid: c_uint,
    reserve: [u8; 32],
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DcmiHbmInfo {
    memory_size: u64,
    freq: c_uint,
    memory_usage: u64,
    temp: c_int,
    bandwith_util_rate: c_uint,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DcmiMemoryInfoV2 {
    memory_size: u64,
    freq: c_uint,
    utiliza: c_uint,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct DcmiMemoryInfoV3 {
    memory_size: u64,
    memory_available: u64,
    freq: c_uint,
    hugepagesize: c_ulong,
    hugepages_total: c_ulong,
    hugepages_free: c_ulong,
    utiliza: c_uint,
    reserve: [u8; 60],
}

#[cfg(target_os = "linux")]
impl Default for DcmiMemoryInfoV3 {
    fn default() -> Self {
        Self {
            memory_size: 0,
            memory_available: 0,
            freq: 0,
            hugepagesize: 0,
            hugepages_total: 0,
            hugepages_free: 0,
            utiliza: 0,
            reserve: [0; 60],
        }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DcmiAicoreInfo {
    freq: c_uint,
    cur_freq: c_uint,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DcmiProcMemInfo {
    proc_id: c_int,
    proc_mem_usage: c_ulong,
}

#[cfg(target_os = "linux")]
type FnDcmiInit = unsafe extern "C" fn() -> c_int;
#[cfg(target_os = "linux")]
type FnGetDriverVersion = unsafe extern "C" fn(*mut c_char, c_uint) -> c_int;
#[cfg(target_os = "linux")]
type FnGetCardList = unsafe extern "C" fn(*mut c_int, *mut c_int, c_int) -> c_int;
#[cfg(target_os = "linux")]
type FnGetDeviceIdInCard = unsafe extern "C" fn(c_int, *mut c_int, *mut c_int, *mut c_int) -> c_int;
#[cfg(target_os = "linux")]
type FnGetChipInfo = unsafe extern "C" fn(c_int, c_int, *mut DcmiChipInfo) -> c_int;
#[cfg(target_os = "linux")]
type FnGetChipInfoV2 = unsafe extern "C" fn(c_int, c_int, *mut DcmiChipInfoV2) -> c_int;
#[cfg(target_os = "linux")]
type FnGetPcieInfo = unsafe extern "C" fn(c_int, c_int, *mut DcmiPcieInfo) -> c_int;
#[cfg(target_os = "linux")]
type FnGetPcieInfoV2 = unsafe extern "C" fn(c_int, c_int, *mut DcmiPcieInfoAll) -> c_int;
#[cfg(target_os = "linux")]
type FnGetUtilization = unsafe extern "C" fn(c_int, c_int, c_int, *mut c_uint) -> c_int;
#[cfg(target_os = "linux")]
type FnGetHbmInfo = unsafe extern "C" fn(c_int, c_int, *mut DcmiHbmInfo) -> c_int;
#[cfg(target_os = "linux")]
type FnGetMemInfoV2 = unsafe extern "C" fn(c_int, c_int, *mut DcmiMemoryInfoV2) -> c_int;
#[cfg(target_os = "linux")]
type FnGetMemInfoV3 = unsafe extern "C" fn(c_int, c_int, *mut DcmiMemoryInfoV3) -> c_int;
#[cfg(target_os = "linux")]
type FnGetTemperature = unsafe extern "C" fn(c_int, c_int, *mut c_int) -> c_int;
#[cfg(target_os = "linux")]
type FnGetPowerInfo = unsafe extern "C" fn(c_int, c_int, *mut c_int) -> c_int;
#[cfg(target_os = "linux")]
type FnGetHealth = unsafe extern "C" fn(c_int, c_int, *mut c_uint) -> c_int;
#[cfg(target_os = "linux")]
type FnGetAicoreInfo = unsafe extern "C" fn(c_int, c_int, *mut DcmiAicoreInfo) -> c_int;
#[cfg(target_os = "linux")]
type FnGetResourceInfo =
    unsafe extern "C" fn(c_int, c_int, *mut DcmiProcMemInfo, *mut c_int) -> c_int;

#[cfg(target_os = "linux")]
struct DcmiApi {
    _lib: libloading::Library,
    init: FnDcmiInit,
    get_driver_version: Option<FnGetDriverVersion>,
    get_card_list: FnGetCardList,
    get_device_id_in_card: FnGetDeviceIdInCard,
    get_chip_info: Option<FnGetChipInfo>,
    get_chip_info_v2: Option<FnGetChipInfoV2>,
    get_pcie_info: Option<FnGetPcieInfo>,
    get_pcie_info_v2: Option<FnGetPcieInfoV2>,
    get_utilization: Option<FnGetUtilization>,
    get_hbm_info: Option<FnGetHbmInfo>,
    get_mem_info_v2: Option<FnGetMemInfoV2>,
    get_mem_info_v3: Option<FnGetMemInfoV3>,
    get_temperature: Option<FnGetTemperature>,
    get_power_info: Option<FnGetPowerInfo>,
    get_health: Option<FnGetHealth>,
    get_aicore_info: Option<FnGetAicoreInfo>,
    get_resource_info: Option<FnGetResourceInfo>,
}

// SAFETY: `libdcmi.so` functions operate on independent `(card_id, device_id)`
// descriptors and `_lib` remains loaded for the lifetime of `DcmiApi`.
#[cfg(target_os = "linux")]
unsafe impl Send for DcmiApi {}
#[cfg(target_os = "linux")]
unsafe impl Sync for DcmiApi {}

#[cfg(target_os = "linux")]
impl DcmiApi {
    fn load() -> Result<Self, String> {
        let Some(path) = DCMI_LIB_CANDIDATES.iter().find(|p| Path::new(p).is_file()) else {
            return Err("libdcmi.so not found in standard Ascend driver paths".into());
        };
        // SAFETY: loading the host-installed Ascend DCMI shared library from a
        // fixed absolute path inside the isolated `gpu-sampler` child process.
        let lib = unsafe { libloading::Library::new(path) }
            .map_err(|e| format!("dlopen {path} failed: {e}"))?;

        unsafe fn load_req<T: Copy>(lib: &libloading::Library, name: &[u8]) -> Result<T, String> {
            let sym: libloading::Symbol<'_, T> = unsafe { lib.get(name) }
                .map_err(|e| format!("missing symbol {}: {e}", String::from_utf8_lossy(name)))?;
            Ok(*sym)
        }
        unsafe fn load_opt<T: Copy>(lib: &libloading::Library, name: &[u8]) -> Option<T> {
            unsafe { lib.get::<T>(name) }.ok().map(|s| *s)
        }

        // SAFETY: function signatures match Ascend `dcmi_interface_api.h`.
        unsafe {
            Ok(Self {
                init: load_req(&lib, b"dcmi_init\0")?,
                get_driver_version: load_opt(&lib, b"dcmi_get_driver_version\0"),
                get_card_list: load_req(&lib, b"dcmi_get_card_list\0")?,
                get_device_id_in_card: load_req(&lib, b"dcmi_get_device_id_in_card\0")?,
                get_chip_info: load_opt(&lib, b"dcmi_get_device_chip_info\0"),
                get_chip_info_v2: load_opt(&lib, b"dcmi_get_device_chip_info_v2\0"),
                get_pcie_info: load_opt(&lib, b"dcmi_get_device_pcie_info\0"),
                get_pcie_info_v2: load_opt(&lib, b"dcmi_get_device_pcie_info_v2\0"),
                get_utilization: load_opt(&lib, b"dcmi_get_device_utilization_rate\0"),
                get_hbm_info: load_opt(&lib, b"dcmi_get_device_hbm_info\0"),
                get_mem_info_v2: load_opt(&lib, b"dcmi_get_device_memory_info_v2\0"),
                get_mem_info_v3: load_opt(&lib, b"dcmi_get_device_memory_info_v3\0"),
                get_temperature: load_opt(&lib, b"dcmi_get_device_temperature\0"),
                get_power_info: load_opt(&lib, b"dcmi_get_device_power_info\0"),
                get_health: load_opt(&lib, b"dcmi_get_device_health\0"),
                get_aicore_info: load_opt(&lib, b"dcmi_get_device_aicore_info\0"),
                get_resource_info: load_opt(&lib, b"dcmi_get_device_resource_info\0"),
                _lib: lib,
            })
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct DcmiCardMeta {
    card_id: c_int,
    device_id: c_int,
    idx: u16,
    uuid: String,
    name: String,
    pci_bus: Option<String>,
    mem_total_mb: Option<u32>,
    is_hbm: bool,
}

#[cfg(target_os = "linux")]
pub(super) struct DcmiSession {
    api: Arc<DcmiApi>,
    driver_version: Option<String>,
    cards: Vec<DcmiCardMeta>,
}

#[cfg(target_os = "linux")]
impl DcmiSession {
    /// Attempt to initialize Ascend DCMI directly via `libdcmi.so`.
    pub(super) fn try_init() -> Result<Self, String> {
        let api = Arc::new(DcmiApi::load()?);
        let rc = unsafe { (api.init)() };
        if rc != 0 {
            return Err(format!("dcmi_init returned {rc}"));
        }

        let driver_version = api.get_driver_version.and_then(|f| {
            let mut buf = [0u8; 64];
            let r = unsafe { f(buf.as_mut_ptr().cast::<c_char>(), buf.len() as c_uint) };
            if r == 0 {
                let s = c_bytes_to_string(&buf);
                (!s.is_empty()).then_some(s)
            } else {
                None
            }
        });

        let mut card_num: c_int = 0;
        let mut card_list = [0 as c_int; DCMI_MAX_CARDS];
        let rc = unsafe {
            (api.get_card_list)(
                &mut card_num,
                card_list.as_mut_ptr(),
                DCMI_MAX_CARDS as c_int,
            )
        };
        if rc != 0 || card_num <= 0 {
            return Err(format!("dcmi_get_card_list rc={rc} num={card_num}"));
        }

        let count = (card_num as usize).min(DCMI_MAX_CARDS);
        let mut cards = Vec::new();
        for &card_id in &card_list[..count] {
            let mut dev_max: c_int = 0;
            let mut mcu_id: c_int = 0;
            let mut cpu_id: c_int = 0;
            let r = unsafe {
                (api.get_device_id_in_card)(card_id, &mut dev_max, &mut mcu_id, &mut cpu_id)
            };
            if r != 0 || dev_max <= 0 {
                continue;
            }
            for device_id in 0..dev_max.min(16) {
                let name = query_chip_name(&api, card_id, device_id);
                let pci_bus = query_pci_bdf(&api, card_id, device_id);
                let (mem_total_mb, is_hbm) = query_mem_total(&api, card_id, device_id);
                let uuid = format_dcmi_uuid(card_id, device_id, pci_bus.as_deref());
                let idx = cards.len() as u16;
                cards.push(DcmiCardMeta {
                    card_id,
                    device_id,
                    idx,
                    uuid,
                    name,
                    pci_bus,
                    mem_total_mb,
                    is_hbm,
                });
            }
        }

        if cards.is_empty() {
            return Err("dcmi discovered zero NPU devices".into());
        }

        Ok(Self {
            api,
            driver_version,
            cards,
        })
    }

    pub(super) fn driver_version(&self) -> Option<String> {
        self.driver_version.clone()
    }

    pub(super) fn pci_bdfs(&self) -> Vec<String> {
        self.cards
            .iter()
            .filter_map(|c| c.pci_bus.clone())
            .collect()
    }

    pub(super) fn inventory(&self) -> GpuInventory {
        let gpus = self
            .cards
            .iter()
            .map(|c| GpuInventoryItem {
                uuid: c.uuid.clone(),
                idx: c.idx,
                name: c.name.clone(),
                mem_total_mb: c.mem_total_mb,
                power_limit_w: None,
                mig: false,
                pci_bus: c.pci_bus.clone(),
                unified: false,
            })
            .collect();
        GpuInventory {
            backend: Some("ascend".into()),
            driver_version: self.driver_version.clone(),
            gpus,
            status: GpuHostStatus::Ok,
            status_detail: None,
        }
    }

    /// Sample every discovered Ascend card concurrently (bounded at 8 workers)
    /// so all per-card ~60 ms AICore utilization windows run in parallel (~80 ms
    /// total on an 8-card host).
    pub(super) fn sample(
        &self,
        include_procs: bool,
        proc_lookup: &ProcLookup,
    ) -> (GpuHostStatus, Vec<GpuSample>) {
        let workers = self.cards.len().clamp(1, 8);
        let chunk_size = self.cards.len().div_ceil(workers);
        let (raw_samples, any_panic): (Vec<RawDcmiCardSample>, bool) =
            std::thread::scope(|scope| {
                let handles: Vec<_> = self
                    .cards
                    .chunks(chunk_size)
                    .map(|chunk| {
                        let api = Arc::clone(&self.api);
                        scope.spawn(move || {
                            chunk
                                .iter()
                                .map(|meta| sample_card_raw(&api, meta, include_procs))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                let mut out = Vec::with_capacity(self.cards.len());
                let mut panicked = false;
                for h in handles {
                    match h.join() {
                        Ok(part) => out.extend(part),
                        Err(_) => panicked = true,
                    }
                }
                (out, panicked)
            });
        if any_panic {
            return (GpuHostStatus::SamplerStalled, Vec::new());
        }

        let has_multi_chip = self.cards.iter().any(|c| c.device_id > 0);
        let mut samples = Vec::with_capacity(raw_samples.len());
        let mut any_ok = false;
        for (i, raw) in raw_samples.into_iter().enumerate() {
            if !raw.lost {
                any_ok = true;
            }
            let logical_vendor_idx = if has_multi_chip {
                i as u16
            } else {
                raw.meta.card_id.max(0) as u16
            };
            let (procs_state, procs) = if !include_procs {
                (ProcsState::Off, None)
            } else if raw.lost {
                (ProcsState::Unknown, None)
            } else {
                match raw.procs {
                    Some(list) => {
                        let mut partial = false;
                        let mut out: Vec<GpuProc> = list
                            .into_iter()
                            .map(|(pid, mem_mb)| {
                                let attr = proc_lookup.lookup(pid);
                                if attr.access_denied {
                                    partial = true;
                                }
                                let name = attr
                                    .name
                                    .filter(|n| !n.is_empty())
                                    .map(|n| truncate_proc_name(&n));
                                GpuProc {
                                    pid,
                                    user: attr.user,
                                    name,
                                    mem_mb,
                                    sm_pct: None,
                                    cpu_pct: None,
                                    started_at: attr.started_at,
                                    container: attr.container,
                                    kind: Some("compute".into()),
                                }
                            })
                            .collect();
                        out.sort_by_key(|p| p.pid);
                        let st = if partial {
                            ProcsState::Partial
                        } else {
                            ProcsState::Ok
                        };
                        (st, Some(out))
                    }
                    None => (ProcsState::Unknown, None),
                }
            };

            let total_mb = raw.mem_total_mb.or(raw.meta.mem_total_mb);
            samples.push(GpuSample {
                uuid: raw.meta.uuid,
                idx: raw.meta.idx,
                name: Some(raw.meta.name),
                mem_total_mb: total_mb,
                power_limit_w: None,
                pci_bus: raw.meta.pci_bus,
                unified: false,
                util_pct: raw.util_pct,
                mem_used_mb: raw.mem_used_mb,
                temp_c: raw.temp_c,
                power_w: raw.power_w,
                fan_pct: None,
                sm_clock_mhz: raw.sm_clock_mhz,
                throttle: None,
                ecc_uncorrected: None,
                remapped_rows: None,
                xid_errors: None,
                mig: false,
                lost: raw.lost,
                vendor_health: raw.vendor_health,
                backend: Some("ascend".into()),
                vendor_index: Some(logical_vendor_idx),
                free_mem_floor_mb: ascend_free_mem_floor_mb(raw.is_hbm, total_mb),
                procs_state,
                procs,
                ..Default::default()
            });
        }

        let host_status = if any_ok {
            GpuHostStatus::Ok
        } else {
            GpuHostStatus::Unavailable
        };
        (host_status, samples)
    }
}

#[cfg(target_os = "linux")]
struct RawDcmiCardSample {
    meta: DcmiCardMeta,
    util_pct: Option<u8>,
    mem_used_mb: Option<u32>,
    mem_total_mb: Option<u32>,
    is_hbm: bool,
    temp_c: Option<i16>,
    power_w: Option<u16>,
    sm_clock_mhz: Option<u16>,
    vendor_health: Option<String>,
    lost: bool,
    procs: Option<Vec<(u32, Option<u32>)>>,
}

#[cfg(target_os = "linux")]
fn sample_card_raw(api: &DcmiApi, meta: &DcmiCardMeta, include_procs: bool) -> RawDcmiCardSample {
    let cid = meta.card_id;
    let did = meta.device_id;
    let mut any_metric_ok = false;

    let util_pct = api.get_utilization.and_then(|f| {
        let mut util: c_uint = 0;
        let rc = unsafe { f(cid, did, DCMI_UTILIZATION_RATE_AICORE, &mut util) };
        if rc == 0 && util <= 100 {
            any_metric_ok = true;
            Some(util as u8)
        } else {
            None
        }
    });

    let (mem_used_mb, mem_total_mb, is_hbm) = query_mem_live(api, cid, did, meta.is_hbm);
    if mem_used_mb.is_some() || mem_total_mb.is_some() {
        any_metric_ok = true;
    }

    let temp_c = api.get_temperature.and_then(|f| {
        let mut t: c_int = 0;
        let rc = unsafe { f(cid, did, &mut t) };
        if rc == 0 && (-40..=150).contains(&t) {
            any_metric_ok = true;
            Some(t as i16)
        } else {
            None
        }
    });

    let power_w = api.get_power_info.and_then(|f| {
        let mut p: c_int = 0;
        let rc = unsafe { f(cid, did, &mut p) };
        if rc == 0 {
            let w = dcmi_power_tenths_to_watts(p);
            if w.is_some() {
                any_metric_ok = true;
            }
            w
        } else {
            None
        }
    });

    let sm_clock_mhz = api.get_aicore_info.and_then(|f| {
        let mut info = DcmiAicoreInfo::default();
        let rc = unsafe { f(cid, did, &mut info) };
        if rc == 0 && info.cur_freq > 0 {
            any_metric_ok = true;
            u16::try_from(info.cur_freq).ok()
        } else {
            None
        }
    });

    let mut health_not_exist = false;
    let vendor_health = api.get_health.and_then(|f| {
        let mut h: c_uint = 0;
        let rc = unsafe { f(cid, did, &mut h) };
        if rc == 0 {
            any_metric_ok = true;
            if h == 0xffff_ffff {
                health_not_exist = true;
            }
            Some(dcmi_health_label(h))
        } else {
            None
        }
    });

    let procs = if include_procs {
        api.get_resource_info.and_then(|f| {
            let mut buf = [DcmiProcMemInfo::default(); DCMI_MAX_PROCS_PER_DEV];
            let mut num = DCMI_MAX_PROCS_PER_DEV as c_int;
            let rc = unsafe { f(cid, did, buf.as_mut_ptr(), &mut num) };
            if rc == 0 && num >= 0 {
                let n = (num as usize).min(DCMI_MAX_PROCS_PER_DEV);
                let rows = buf[..n]
                    .iter()
                    .filter(|p| p.proc_id > 0)
                    .map(|p| {
                        (
                            p.proc_id as u32,
                            dcmi_proc_mem_bytes_to_mb(p.proc_mem_usage),
                        )
                    })
                    .collect();
                Some(rows)
            } else {
                None
            }
        })
    } else {
        None
    };

    RawDcmiCardSample {
        meta: meta.clone(),
        util_pct,
        mem_used_mb,
        mem_total_mb,
        is_hbm,
        temp_c,
        power_w,
        sm_clock_mhz,
        vendor_health,
        lost: !any_metric_ok || health_not_exist,
        procs,
    }
}

#[cfg(target_os = "linux")]
fn query_chip_name(api: &DcmiApi, card_id: c_int, device_id: c_int) -> String {
    if let Some(f) = api.get_chip_info_v2 {
        let mut info = DcmiChipInfoV2::default();
        if unsafe { f(card_id, device_id, &mut info) } == 0 {
            return format_dcmi_chip_name(
                &c_bytes_to_string(&info.chip_type),
                &c_bytes_to_string(&info.chip_name),
                &c_bytes_to_string(&info.npu_name),
            );
        }
    }
    if let Some(f) = api.get_chip_info {
        let mut info = DcmiChipInfo::default();
        if unsafe { f(card_id, device_id, &mut info) } == 0 {
            return format_dcmi_chip_name(
                &c_bytes_to_string(&info.chip_type),
                &c_bytes_to_string(&info.chip_name),
                "",
            );
        }
    }
    format!("Ascend NPU #{card_id}")
}

#[cfg(target_os = "linux")]
fn query_pci_bdf(api: &DcmiApi, card_id: c_int, device_id: c_int) -> Option<String> {
    if let Some(f) = api.get_pcie_info_v2 {
        let mut info = DcmiPcieInfoAll::default();
        if unsafe { f(card_id, device_id, &mut info) } == 0 {
            return Some(format_dcmi_bdf(
                info.domain.max(0) as u32,
                info.bdf_busid,
                info.bdf_deviceid,
                info.bdf_funcid,
            ));
        }
    }
    if let Some(f) = api.get_pcie_info {
        let mut info = DcmiPcieInfo::default();
        if unsafe { f(card_id, device_id, &mut info) } == 0 {
            return Some(format_dcmi_bdf(
                0,
                info.bdf_busid,
                info.bdf_deviceid,
                info.bdf_funcid,
            ));
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn query_mem_total(api: &DcmiApi, card_id: c_int, device_id: c_int) -> (Option<u32>, bool) {
    let (_, tot, is_hbm) = query_mem_live(api, card_id, device_id, true);
    (tot, is_hbm)
}

#[cfg(target_os = "linux")]
fn query_mem_live(
    api: &DcmiApi,
    card_id: c_int,
    device_id: c_int,
    prefer_hbm: bool,
) -> (Option<u32>, Option<u32>, bool) {
    if prefer_hbm && let Some(f) = api.get_hbm_info {
        let mut hbm = DcmiHbmInfo::default();
        if unsafe { f(card_id, device_id, &mut hbm) } == 0 && hbm.memory_size > 0 {
            let total = u32::try_from(hbm.memory_size).ok();
            let used = u32::try_from(hbm.memory_usage).ok();
            return (used, total, true);
        }
    }
    if let Some(f) = api.get_mem_info_v3 {
        let mut mem = DcmiMemoryInfoV3::default();
        if unsafe { f(card_id, device_id, &mut mem) } == 0 && mem.memory_size > 0 {
            let total = u32::try_from(mem.memory_size).ok();
            let used = if mem.memory_available <= mem.memory_size {
                u32::try_from(mem.memory_size - mem.memory_available).ok()
            } else {
                u32::try_from((mem.memory_size.saturating_mul(u64::from(mem.utiliza))) / 100).ok()
            };
            return (used, total, false);
        }
    }
    if let Some(f) = api.get_mem_info_v2 {
        let mut mem = DcmiMemoryInfoV2::default();
        if unsafe { f(card_id, device_id, &mut mem) } == 0 && mem.memory_size > 0 {
            let total = u32::try_from(mem.memory_size).ok();
            let used =
                u32::try_from((mem.memory_size.saturating_mul(u64::from(mem.utiliza))) / 100).ok();
            return (used, total, false);
        }
    }
    (None, None, prefer_hbm)
}

// ─── Pure formatting/conversion helpers (tested on every platform) ──────────

#[cfg(any(target_os = "linux", test))]
fn c_bytes_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim().to_string()
}

#[cfg(any(target_os = "linux", test))]
fn format_dcmi_chip_name(chip_type: &str, chip_name: &str, npu_name: &str) -> String {
    let model = if !npu_name.trim().is_empty() {
        npu_name.trim()
    } else {
        chip_name.trim()
    };
    let prefix = chip_type.trim();
    if model.is_empty() {
        if prefix.is_empty() {
            "Ascend NPU".to_string()
        } else {
            prefix.to_string()
        }
    } else if model.to_ascii_lowercase().starts_with("ascend") {
        model.to_string()
    } else if !prefix.is_empty() {
        format!("{prefix} {model}")
    } else {
        format!("Ascend {model}")
    }
}

#[cfg(any(target_os = "linux", test))]
fn format_dcmi_bdf(domain: u32, bus: u32, dev: u32, func: u32) -> String {
    // Uppercase hex matches `npu-smi info` (`0000:C1:00.0`) so DCMI and
    // `npu-smi` produce the exact same frozen card UUID.
    format!("{domain:04X}:{bus:02X}:{dev:02X}.{func:X}")
}

#[cfg(any(target_os = "linux", test))]
fn format_dcmi_uuid(card_id: i32, device_id: i32, pci_bus: Option<&str>) -> String {
    if let Some(bus) = pci_bus.filter(|s| !s.is_empty()) {
        format!("ASCEND-{card_id}-{device_id}-{bus}")
    } else {
        format!("ASCEND-{card_id}-{device_id}")
    }
}

#[cfg(any(target_os = "linux", test))]
fn dcmi_power_tenths_to_watts(raw_tenths: i32) -> Option<u16> {
    if raw_tenths <= 0 {
        return None;
    }
    let watts = (raw_tenths as u32).saturating_add(5) / 10;
    u16::try_from(watts).ok()
}

#[cfg(any(target_os = "linux", test))]
fn dcmi_proc_mem_bytes_to_mb(bytes: u64) -> Option<u32> {
    if bytes == 0 {
        return None;
    }
    let mb = bytes / (1024 * 1024);
    u32::try_from(mb.max(1)).ok()
}

#[cfg(any(target_os = "linux", test))]
fn dcmi_health_label(code: u32) -> String {
    match code {
        0 => "OK".to_string(),
        1 => "Warning".to_string(),
        2 => "Error".to_string(),
        3 => "Critical".to_string(),
        0xffff_ffff => "NotExist".to_string(),
        other => format!("0x{other:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcmi_uuid_matches_npu_smi_frozen_identity() {
        let bdf = format_dcmi_bdf(0, 0xc1, 0, 0);
        assert_eq!(bdf, "0000:C1:00.0");
        assert_eq!(
            format_dcmi_uuid(0, 0, Some(&bdf)),
            "ASCEND-0-0-0000:C1:00.0"
        );
    }

    #[test]
    fn dcmi_unit_conversions_match_real_910b_readings() {
        assert_eq!(dcmi_power_tenths_to_watts(971), Some(97));
        assert_eq!(dcmi_power_tenths_to_watts(876), Some(88));
        assert_eq!(dcmi_power_tenths_to_watts(0), None);
        assert_eq!(dcmi_power_tenths_to_watts(-1), None);

        // 58468802560 bytes == 55760 MiB (real Ascend 910B4-1 vLLM process).
        assert_eq!(dcmi_proc_mem_bytes_to_mb(58_468_802_560), Some(55_760));
        assert_eq!(dcmi_proc_mem_bytes_to_mb(0), None);

        assert_eq!(dcmi_health_label(0), "OK");
        assert_eq!(dcmi_health_label(1), "Warning");
        assert_eq!(dcmi_health_label(2), "Error");
        assert_eq!(dcmi_health_label(3), "Critical");
        assert_eq!(dcmi_health_label(0xffff_ffff), "NotExist");

        assert_eq!(
            format_dcmi_chip_name("Ascend", "910B4-1", "910B4-1"),
            "Ascend 910B4-1"
        );
        assert_eq!(format_dcmi_chip_name("", "Ascend 910B", ""), "Ascend 910B");
    }
}
