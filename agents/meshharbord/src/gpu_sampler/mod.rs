// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Out-of-process GPU/NPU/TPU telemetry sampler (`meshharbord gpu-sampler`)
//! and parent-side [`supervisor::GpuSupervisor`].
//!
//! All vendor GPU/NPU/TPU driver calls (NVML, AMD sysfs/fdinfo/KFD, Intel
//! xe/i915, Apple macmon, Huawei Ascend `npu-smi` / `/dev/davinci*`, Google
//! Cloud TPU PCIe/VFIO/accel, Linux PCIe zero-package fallback, Windows PDH)
//! execute strictly inside the `gpu-sampler` child process so driver hangs,
//! faults, or library leaks never affect the daemon.

pub mod amd;
pub mod apple;
pub mod ascend;
pub mod fake;
pub mod intel;
pub mod metrics;
pub mod nvml;
pub mod pci_fallback;
pub mod proc_linux;
pub mod supervisor;
pub mod tpu;
pub mod windows_pdh;

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meshharbor_remote_control::gpu::{
    GpuHostStatus, GpuInventory, GpuInventoryItem, GpuReport, GpuSample, HostLoad,
};
use serde::{Deserialize, Serialize};

use self::amd::AmdBackend;
use self::apple::AppleBackend;
use self::ascend::AscendBackend;
use self::fake::{FakeBackend, FakeStep};
use self::intel::IntelBackend;
use self::nvml::{NvmlBackend, NvmlInitOutcome};
use self::pci_fallback::{
    PciScanOutcome, normalize_pci_bdf, scan_host_pci, synthesize_unmanaged_fallbacks,
};
use self::proc_linux::ProcLookup;
use self::tpu::TpuBackend;

/// Line prefix on child stdout distinguishing telemetry JSON from any stray
/// vendor driver stdout noise.
pub const FRAME_PREFIX: &str = "MESHHARBOR_GPU_JSON:";

/// Env var pointing to a JSON/JSONL fixture file for deterministic testing
/// without GPU hardware.
pub const FAKE_ENV: &str = "MESHHARBORD_GPU_FAKE";

/// Env var guarding against accidental recursive spawn.
pub const CHILD_ENV: &str = "MESHHARBORD_GPU_SAMPLER_CHILD";

/// Control command sent parent -> child as a single JSON line on stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlLine {
    /// Desired report emission cadence in milliseconds (`0` = pause reports,
    /// keep child warm until next lease or EOF).
    pub interval_ms: u32,
    /// Whether per-process attribution is enabled locally (`gpu_processes`).
    #[serde(default = "default_true")]
    pub include_procs: bool,
    /// Graceful shutdown request.
    #[serde(default)]
    pub stop: bool,
}

fn default_true() -> bool {
    true
}

/// One framed message sent child -> parent on stdout (`MESHHARBOR_GPU_JSON:<json>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChildFrame {
    Inventory { inventory: GpuInventory },
    Report { report: GpuReport },
}

struct HardwareBackends {
    denied: HashSet<String>,
    pci_scan: PciScanOutcome,
    nvml: Option<Box<NvmlBackend>>,
    nvml_diag: Option<(GpuHostStatus, String)>,
    amd: Option<AmdBackend>,
    intel: Option<IntelBackend>,
    apple: Option<AppleBackend>,
    ascend: Option<AscendBackend>,
    ascend_diag: Option<String>,
    tpu: Option<TpuBackend>,
}

enum ActiveBackend {
    Fake(FakeBackend),
    Hardware(Box<HardwareBackends>),
}

fn parse_denied_backends() -> HashSet<String> {
    let raw = tunnel_core::env::node_env("GPU_BACKENDS_DENY").unwrap_or_default();
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return HashSet::new();
    }
    trimmed
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Severity rank for aggregating multi-backend host status. Higher rank wins.
fn status_rank(st: GpuHostStatus) -> u8 {
    match st {
        GpuHostStatus::DriverHung => 9,
        GpuHostStatus::Unavailable => 8,
        GpuHostStatus::SamplerStalled => 7,
        GpuHostStatus::DriverRebootPending => 6,
        GpuHostStatus::DriverMissing => 5,
        GpuHostStatus::Limited => 4,
        GpuHostStatus::Ok => 3,
        GpuHostStatus::Unknown => 2,
        GpuHostStatus::OffLocal => 1,
        GpuHostStatus::NoGpu => 0,
    }
}

fn merge_status(current: GpuHostStatus, candidate: GpuHostStatus) -> GpuHostStatus {
    if status_rank(candidate) > status_rank(current) {
        candidate
    } else {
        current
    }
}

fn init_backend() -> anyhow::Result<ActiveBackend> {
    if let Ok(fake_path) = std::env::var(FAKE_ENV)
        && !fake_path.trim().is_empty()
    {
        let fb = FakeBackend::load(&PathBuf::from(fake_path.trim()))?;
        return Ok(ActiveBackend::Fake(fb));
    }

    let denied = parse_denied_backends();
    let pci_scan = scan_host_pci();
    let pci_devs = match &pci_scan {
        PciScanOutcome::Readable(v) => v.as_slice(),
        PciScanOutcome::Unreadable(_) => &[],
    };

    let has_nvidia_pci = matches!(&pci_scan, PciScanOutcome::Unreadable(_))
        || pci_devs
            .iter()
            .any(|d| d.vendor == pci_fallback::AccelVendor::Nvidia);
    let (nvml, nvml_diag) = if denied.contains("nvidia") {
        (None, None)
    } else {
        match NvmlBackend::try_init() {
            NvmlInitOutcome::Ready(b) => (Some(b), None),
            NvmlInitOutcome::Status(st, detail) => {
                // Only promote NVML init failure to a host fault when NVIDIA hardware
                // is actually present (or PCI scan is unreadable, or a live driver/lib
                // mismatch occurred). Prevents stale libnvidia-ml on AMD-only hosts
                // from marking the host faulty.
                if has_nvidia_pci || st == GpuHostStatus::DriverRebootPending {
                    (None, Some((st, detail)))
                } else {
                    (None, None)
                }
            }
            NvmlInitOutcome::NotPresent => (None, None),
        }
    };
    let amd = if denied.contains("amd") {
        None
    } else {
        AmdBackend::try_init()
    };
    let intel = if denied.contains("intel") {
        None
    } else {
        IntelBackend::try_init()
    };
    let apple = if denied.contains("apple") {
        None
    } else {
        AppleBackend::try_init()
    };
    let (ascend, ascend_diag) = if denied.contains("ascend") || denied.contains("npu") {
        (None, None)
    } else {
        AscendBackend::try_init_with_pci(pci_devs)
    };
    let tpu = if denied.contains("tpu") {
        None
    } else {
        TpuBackend::try_init_from_pci(pci_devs)
    };

    Ok(ActiveBackend::Hardware(Box::new(HardwareBackends {
        denied,
        pci_scan,
        nvml,
        nvml_diag,
        amd,
        intel,
        apple,
        ascend,
        ascend_diag,
        tpu,
    })))
}

fn emit_frame(stdout: &mut std::io::StdoutLock<'_>, frame: &ChildFrame) -> anyhow::Result<()> {
    let json = serde_json::to_string(frame)?;
    writeln!(stdout, "{FRAME_PREFIX}{json}")?;
    stdout.flush()?;
    Ok(())
}

/// Tracks continuous low-utilization (`util < 5%`) durations and first-seen
/// process start times across internal 5 s sub-samples.
struct SamplerTracker {
    idle_since: HashMap<String, i64>,
    proc_first_seen: HashMap<(String, u32), i64>,
}

impl SamplerTracker {
    fn new() -> Self {
        Self {
            idle_since: HashMap::new(),
            proc_first_seen: HashMap::new(),
        }
    }

    fn update(&mut self, samples: &mut [GpuSample], now_s: i64) {
        let mut live_uuids: HashSet<String> = HashSet::with_capacity(samples.len());
        let mut live_procs: HashSet<(String, u32)> = HashSet::new();
        for g in samples.iter_mut() {
            live_uuids.insert(g.uuid.clone());
            // Preserve pre-populated fake idle_since if present; otherwise track live.
            if g.idle_since.is_none() {
                match g.util_pct {
                    Some(u) if u < 5 => {
                        let since = *self.idle_since.entry(g.uuid.clone()).or_insert(now_s);
                        g.idle_since = Some(since);
                    }
                    _ => {
                        self.idle_since.remove(&g.uuid);
                    }
                }
            }
            if let Some(procs) = g.procs.as_mut() {
                for p in procs.iter_mut() {
                    let key = (g.uuid.clone(), p.pid);
                    live_procs.insert(key.clone());
                    let seen = *self.proc_first_seen.entry(key).or_insert(now_s);
                    if p.started_at.is_none() {
                        p.started_at = Some(seen);
                    }
                }
            }
        }
        self.idle_since.retain(|u, _| live_uuids.contains(u));
        self.proc_first_seen.retain(|k, _| live_procs.contains(k));
    }
}

/// Merge a live hardware [`GpuReport`] into the last-known [`GpuInventory`]
/// without ever substituting `"fake"` or shrinking known devices on a transient
/// collection error.
fn merge_hardware_inventory(prev: &GpuInventory, report: &GpuReport) -> GpuInventory {
    let mut by_key: HashMap<String, GpuInventoryItem> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for item in &prev.gpus {
        let k = item
            .pci_bus
            .as_deref()
            .map(normalize_pci_bdf)
            .unwrap_or_else(|| item.uuid.clone());
        if !by_key.contains_key(&k) {
            order.push(k.clone());
        }
        by_key.insert(k, item.clone());
    }
    for g in &report.gpus {
        let k = g
            .pci_bus
            .as_deref()
            .map(normalize_pci_bdf)
            .unwrap_or_else(|| g.uuid.clone());
        let entry = GpuInventoryItem {
            uuid: g.uuid.clone(),
            idx: g.idx,
            name: g.name.clone().unwrap_or_else(|| format!("GPU {}", g.idx)),
            mem_total_mb: g.mem_total_mb.or_else(|| by_key.get(&k).and_then(|o| o.mem_total_mb)),
            power_limit_w: g
                .power_limit_w
                .or_else(|| by_key.get(&k).and_then(|o| o.power_limit_w)),
            mig: g.mig,
            pci_bus: g.pci_bus.clone(),
            unified: g.unified,
        };
        if !by_key.contains_key(&k) {
            order.push(k.clone());
        }
        by_key.insert(k, entry);
    }
    let gpus = order
        .into_iter()
        .enumerate()
        .filter_map(|(i, k)| {
            let mut item = by_key.remove(&k)?;
            item.idx = i as u16;
            Some(item)
        })
        .collect();

    GpuInventory {
        backend: report.backend.clone().or_else(|| prev.backend.clone()),
        driver_version: report
            .driver_version
            .clone()
            .or_else(|| prev.driver_version.clone()),
        gpus,
        status: report.status,
        status_detail: report
            .status_detail
            .clone()
            .or_else(|| prev.status_detail.clone()),
    }
}

/// Entry point for the hidden `meshharbord gpu-sampler` child process.
pub fn run_child() -> anyhow::Result<()> {
    let mut backend = init_backend()?;

    #[derive(Clone)]
    struct ControlState {
        interval_ms: u32,
        include_procs: bool,
        stop: bool,
    }
    let ctrl = Arc::new(Mutex::new(ControlState {
        interval_ms: 0,
        include_procs: true,
        stop: false,
    }));
    let ctrl_reader = ctrl.clone();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let reader = stdin.lock();
        for line in reader.lines() {
            let Ok(line) = line else {
                break;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(cmd) = serde_json::from_str::<ControlLine>(trimmed)
                && let Ok(mut g) = ctrl_reader.lock()
            {
                g.interval_ms = cmd.interval_ms;
                g.include_procs = cmd.include_procs;
                if cmd.stop {
                    g.stop = true;
                    break;
                }
            }
        }
        if let Ok(mut g) = ctrl_reader.lock() {
            g.stop = true;
        }
    });

    let mut out = std::io::stdout().lock();

    // Emit initial static inventory immediately on boot.
    let initial_inv = collect_inventory(&backend);
    emit_frame(
        &mut out,
        &ChildFrame::Inventory {
            inventory: initial_inv.clone(),
        },
    )?;
    let mut last_inventory = initial_inv;

    let mut tracker = SamplerTracker::new();
    let mut seq: u64 = 0;
    let mut last_emit: Option<Instant> = None;
    let mut last_internal: Option<Instant> = None;

    loop {
        let state = ctrl
            .lock()
            .map(|g| g.clone())
            .unwrap_or(ControlState {
                interval_ms: 0,
                include_procs: true,
                stop: true,
            });
        if state.stop {
            break;
        }

        if state.interval_ms == 0 {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }

        let emit_every = Duration::from_millis(u64::from(state.interval_ms.max(50)));
        let internal_every = emit_every.min(Duration::from_secs(5));

        let now_inst = Instant::now();
        let need_emit = last_emit.is_none_or(|t| now_inst.duration_since(t) >= emit_every);
        let need_internal =
            last_internal.is_none_or(|t| now_inst.duration_since(t) >= internal_every);

        if !need_emit && !need_internal {
            let rem_emit = last_emit
                .map(|t| emit_every.saturating_sub(now_inst.duration_since(t)))
                .unwrap_or(Duration::ZERO);
            let rem_int = last_internal
                .map(|t| internal_every.saturating_sub(now_inst.duration_since(t)))
                .unwrap_or(Duration::ZERO);
            std::thread::sleep(rem_emit.min(rem_int).min(Duration::from_millis(100)));
            continue;
        }

        last_internal = Some(now_inst);
        let now_s = chrono::Utc::now().timestamp();

        let is_fake = matches!(backend, ActiveBackend::Fake(_));
        let report = match &mut backend {
            ActiveBackend::Fake(fb) => match fb.next_step() {
                FakeStep::SleepForever => loop {
                    std::thread::sleep(Duration::from_secs(3600));
                },
                FakeStep::Exit(code) => {
                    std::process::exit(code);
                }
                FakeStep::Report(boxed) => {
                    let mut r = *boxed;
                    seq += 1;
                    r.seq = seq;
                    r.interval_ms = state.interval_ms;
                    if !state.include_procs {
                        for g in &mut r.gpus {
                            g.procs_state = meshharbor_remote_control::gpu::ProcsState::Off;
                            g.procs = None;
                        }
                    }
                    tracker.update(&mut r.gpus, now_s);
                    r
                }
            },
            ActiveBackend::Hardware(hw) => {
                let HardwareBackends {
                    denied,
                    pci_scan,
                    nvml,
                    nvml_diag,
                    amd,
                    intel,
                    apple,
                    ascend,
                    ascend_diag,
                    tpu,
                } = &mut **hw;
                let proc_lookup = if state.include_procs {
                    ProcLookup::new()
                } else {
                    ProcLookup::default()
                };
                #[cfg(windows)]
                let pdh_vram = if state.include_procs && nvml.is_some() {
                    windows_pdh::sample_process_vram_mb()
                } else {
                    HashMap::new()
                };

                let mut gpus: Vec<GpuSample> = Vec::new();
                let mut active_bdfs: HashSet<String> = HashSet::new();
                let mut backend_names: Vec<&'static str> = Vec::new();
                let mut driver_version: Option<String> = None;
                let mut details: Vec<String> = Vec::new();
                let mut host_status = GpuHostStatus::NoGpu;

                if let Some(nv) = nvml.as_mut() {
                    backend_names.push("nvml");
                    driver_version = nv.driver_version();
                    if let Some(d) = nv.status_detail() {
                        details.push(d);
                    }
                    let (st, mut samples) = nv.sample(
                        state.include_procs,
                        &proc_lookup,
                        #[cfg(windows)]
                        &pdh_vram,
                    );
                    host_status = merge_status(host_status, st);
                    for s in &mut samples {
                        s.backend_status = Some(st);
                        if let Some(b) = s.pci_bus.as_deref() {
                            active_bdfs.insert(normalize_pci_bdf(b));
                        }
                    }
                    gpus.append(&mut samples);
                } else if let Some((st, detail)) = nvml_diag.as_ref() {
                    host_status = merge_status(host_status, *st);
                    details.push(detail.clone());
                }

                if let Some(a) = amd.as_ref() {
                    backend_names.push("amd");
                    let (st, mut samples) = a.sample(state.include_procs, &proc_lookup);
                    host_status = merge_status(host_status, st);
                    let offset = gpus.len() as u16;
                    for (i, s) in samples.iter_mut().enumerate() {
                        s.idx = offset + i as u16;
                        s.backend_status = Some(st);
                        if let Some(b) = s.pci_bus.as_deref() {
                            active_bdfs.insert(normalize_pci_bdf(b));
                        }
                    }
                    gpus.append(&mut samples);
                }

                if let Some(i_b) = intel.as_ref() {
                    backend_names.push("intel");
                    let (st, mut samples) = i_b.sample(state.include_procs, &proc_lookup);
                    host_status = merge_status(host_status, st);
                    let offset = gpus.len() as u16;
                    for (i, s) in samples.iter_mut().enumerate() {
                        s.idx = offset + i as u16;
                        s.backend_status = Some(st);
                        if let Some(b) = s.pci_bus.as_deref() {
                            active_bdfs.insert(normalize_pci_bdf(b));
                        }
                    }
                    gpus.append(&mut samples);
                }

                if let Some(ap) = apple.as_mut() {
                    backend_names.push("apple");
                    let (st, mut samples) = ap.sample(state.include_procs);
                    host_status = merge_status(host_status, st);
                    let offset = gpus.len() as u16;
                    for (i, s) in samples.iter_mut().enumerate() {
                        s.idx = offset + i as u16;
                        s.backend_status = Some(st);
                    }
                    gpus.append(&mut samples);
                }

                if let Some(asc) = ascend.as_mut() {
                    backend_names.push("ascend");
                    if driver_version.is_none() {
                        driver_version = asc.driver_version();
                    }
                    let (st, mut samples) = asc.sample(state.include_procs, &proc_lookup);
                    host_status = merge_status(host_status, st);
                    if let Some(d) = asc.status_detail() {
                        details.push(d);
                    }
                    let offset = gpus.len() as u16;
                    for (i, s) in samples.iter_mut().enumerate() {
                        s.idx = offset + i as u16;
                        s.backend_status = Some(st);
                        if let Some(b) = s.pci_bus.as_deref() {
                            active_bdfs.insert(normalize_pci_bdf(b));
                        }
                    }
                    gpus.append(&mut samples);
                }

                if let Some(tp) = tpu.as_ref() {
                    backend_names.push("tpu");
                    if driver_version.is_none() {
                        driver_version = tp.driver_version();
                    }
                    let (st, mut samples) = tp.sample(state.include_procs, &proc_lookup);
                    host_status = merge_status(host_status, st);
                    if let Some(d) = tp.status_detail() {
                        details.push(d);
                    }
                    let offset = gpus.len() as u16;
                    for (i, s) in samples.iter_mut().enumerate() {
                        s.idx = offset + i as u16;
                        s.backend_status = Some(st);
                        if let Some(b) = s.pci_bus.as_deref() {
                            active_bdfs.insert(normalize_pci_bdf(b));
                        }
                    }
                    gpus.append(&mut samples);
                }

                // Zero-package PCIe fallback for any hardware accelerator not
                // already covered by a full vendor backend.
                match pci_scan {
                    PciScanOutcome::Readable(pci_devs) => {
                        let fb = synthesize_unmanaged_fallbacks(
                            pci_devs,
                            &active_bdfs,
                            denied,
                            nvml_diag.as_ref().map(|(s, d)| (*s, d.as_str())),
                            ascend_diag.as_deref(),
                            gpus.len() as u16,
                        );
                        if let Some(st) = fb.status {
                            // Never let a presence-only `Limited` fallback (e.g. a sibling
                            // vfio-pci passthrough GPU or PCIe-only card) downgrade healthy
                            // cards from an `Ok` primary backend; per-card `backend_status`
                            // preserves the fallback card's own status.
                            if !(st == GpuHostStatus::Limited && host_status == GpuHostStatus::Ok) {
                                host_status = merge_status(host_status, st);
                            }
                        }
                        if let Some(d) = fb.status_detail {
                            details.push(d);
                        }
                        for tag in fb.backend_tags {
                            if !backend_names.contains(&tag) {
                                backend_names.push(tag);
                            }
                        }
                        let fb_card_status = fb.status;
                        for mut s in fb.samples {
                            if s.backend_status.is_none() {
                                s.backend_status = fb_card_status;
                            }
                            gpus.push(s);
                        }
                    }
                    PciScanOutcome::Unreadable(reason) => {
                        if gpus.is_empty() && host_status == GpuHostStatus::NoGpu {
                            host_status = GpuHostStatus::Unknown;
                            details.push(reason.clone());
                        }
                    }
                }

                tracker.update(&mut gpus, now_s);
                seq += 1;
                let status_detail = (!details.is_empty()).then(|| details.join(" | "));
                GpuReport {
                    seq,
                    interval_ms: state.interval_ms,
                    status: host_status,
                    status_detail,
                    backend: if backend_names.is_empty() {
                        None
                    } else {
                        Some(backend_names.join("+"))
                    },
                    driver_version,
                    host: HostLoad::default(),
                    gpus,
                }
            }
        };

        if need_emit {
            last_emit = Some(now_inst);
            let current_inv = if is_fake {
                fake::inventory_from_report(&report)
            } else {
                merge_hardware_inventory(&last_inventory, &report)
            };
            if current_inv != last_inventory {
                last_inventory = current_inv.clone();
                emit_frame(
                    &mut out,
                    &ChildFrame::Inventory {
                        inventory: current_inv,
                    },
                )?;
            }
            emit_frame(&mut out, &ChildFrame::Report { report })?;
        }
    }

    Ok(())
}

fn collect_inventory(backend: &ActiveBackend) -> GpuInventory {
    match backend {
        ActiveBackend::Fake(fb) => fb.inventory().unwrap_or(GpuInventory {
            backend: Some("fake".into()),
            driver_version: None,
            gpus: Vec::new(),
            status: GpuHostStatus::NoGpu,
            status_detail: None,
        }),
        ActiveBackend::Hardware(hw) => {
            let HardwareBackends {
                denied,
                pci_scan,
                nvml,
                nvml_diag,
                amd,
                intel,
                apple,
                ascend,
                ascend_diag,
                tpu,
            } = &**hw;
            let mut gpus: Vec<GpuInventoryItem> = Vec::new();
            let mut active_bdfs: HashSet<String> = HashSet::new();
            let mut names: Vec<&'static str> = Vec::new();
            let mut driver_version: Option<String> = None;
            let mut details: Vec<String> = Vec::new();
            let mut status = GpuHostStatus::NoGpu;

            if let Some(nv) = nvml {
                let inv = nv.inventory();
                names.push("nvml");
                driver_version = inv.driver_version;
                status = merge_status(status, inv.status);
                if let Some(d) = inv.status_detail {
                    details.push(d);
                }
                for g in &inv.gpus {
                    if let Some(b) = g.pci_bus.as_deref() {
                        active_bdfs.insert(normalize_pci_bdf(b));
                    }
                }
                gpus.extend(inv.gpus);
            } else if let Some((st, d)) = nvml_diag {
                status = merge_status(status, *st);
                details.push(d.clone());
            }
            if let Some(a) = amd {
                let inv = a.inventory();
                names.push("amd");
                if driver_version.is_none() {
                    driver_version = inv.driver_version;
                }
                status = merge_status(status, inv.status);
                let offset = gpus.len() as u16;
                for (i, mut g) in inv.gpus.into_iter().enumerate() {
                    g.idx = offset + i as u16;
                    if let Some(b) = g.pci_bus.as_deref() {
                        active_bdfs.insert(normalize_pci_bdf(b));
                    }
                    gpus.push(g);
                }
            }
            if let Some(i_b) = intel {
                let inv = i_b.inventory();
                names.push("intel");
                status = merge_status(status, inv.status);
                let offset = gpus.len() as u16;
                for (i, mut g) in inv.gpus.into_iter().enumerate() {
                    g.idx = offset + i as u16;
                    if let Some(b) = g.pci_bus.as_deref() {
                        active_bdfs.insert(normalize_pci_bdf(b));
                    }
                    gpus.push(g);
                }
            }
            if let Some(ap) = apple {
                let inv = ap.inventory();
                names.push("apple");
                status = merge_status(status, inv.status);
                let offset = gpus.len() as u16;
                for (i, mut g) in inv.gpus.into_iter().enumerate() {
                    g.idx = offset + i as u16;
                    gpus.push(g);
                }
            }
            if let Some(asc) = ascend {
                let inv = asc.inventory();
                names.push("ascend");
                if driver_version.is_none() {
                    driver_version = inv.driver_version;
                }
                status = merge_status(status, inv.status);
                if let Some(d) = inv.status_detail {
                    details.push(d);
                }
                for b in asc.pci_bdfs() {
                    active_bdfs.insert(normalize_pci_bdf(&b));
                }
                let offset = gpus.len() as u16;
                for (i, mut g) in inv.gpus.into_iter().enumerate() {
                    g.idx = offset + i as u16;
                    if let Some(b) = g.pci_bus.as_deref() {
                        active_bdfs.insert(normalize_pci_bdf(b));
                    }
                    gpus.push(g);
                }
            }
            if let Some(tp) = tpu {
                let inv = tp.inventory();
                names.push("tpu");
                if driver_version.is_none() {
                    driver_version = inv.driver_version;
                }
                status = merge_status(status, inv.status);
                if let Some(d) = inv.status_detail {
                    details.push(d);
                }
                for b in tp.pci_bdfs() {
                    active_bdfs.insert(normalize_pci_bdf(&b));
                }
                let offset = gpus.len() as u16;
                for (i, mut g) in inv.gpus.into_iter().enumerate() {
                    g.idx = offset + i as u16;
                    gpus.push(g);
                }
            }

            match pci_scan {
                PciScanOutcome::Readable(pci_devs) => {
                    let fb = synthesize_unmanaged_fallbacks(
                        pci_devs,
                        &active_bdfs,
                        denied,
                        nvml_diag.as_ref().map(|(s, d)| (*s, d.as_str())),
                        ascend_diag.as_deref(),
                        gpus.len() as u16,
                    );
                    if let Some(st) = fb.status {
                        status = merge_status(status, st);
                    }
                    if let Some(d) = fb.status_detail {
                        details.push(d);
                    }
                    for tag in fb.backend_tags {
                        if !names.contains(&tag) {
                            names.push(tag);
                        }
                    }
                    gpus.extend(fb.inventory_items);
                }
                PciScanOutcome::Unreadable(reason) => {
                    if gpus.is_empty() && status == GpuHostStatus::NoGpu {
                        status = GpuHostStatus::Unknown;
                        details.push(reason.clone());
                    }
                }
            }

            GpuInventory {
                backend: if names.is_empty() {
                    None
                } else {
                    Some(names.join("+"))
                },
                driver_version,
                gpus,
                status,
                status_detail: (!details.is_empty()).then(|| details.join(" | ")),
            }
        }
    }
}
