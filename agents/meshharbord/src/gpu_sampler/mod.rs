// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Out-of-process GPU telemetry sampler (`meshharbord gpu-sampler`)
//! and parent-side [`supervisor::GpuSupervisor`].
//!
//! All vendor GPU driver calls (NVML, AMD sysfs/fdinfo/KFD, Intel xe/i915,
//! Apple macmon, Windows PDH) execute strictly inside the `gpu-sampler` child
//! process so driver hangs, faults, or library leaks never affect the daemon.

pub mod amd;
pub mod apple;
pub mod ascend;
pub mod fake;
pub mod intel;
pub mod metrics;
pub mod nvml;
pub mod proc_linux;
pub mod supervisor;
pub mod windows_pdh;

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meshharbor_remote_control::gpu::{
    GpuHostStatus, GpuInventory, GpuReport, GpuSample, HostLoad,
};
use serde::{Deserialize, Serialize};

use self::amd::AmdBackend;
use self::apple::AppleBackend;
use self::ascend::AscendBackend;
use self::fake::{FakeBackend, FakeStep};
use self::intel::IntelBackend;
use self::nvml::{NvmlBackend, NvmlInitOutcome};
use self::proc_linux::ProcLookup;

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

enum ActiveBackend {
    Fake(FakeBackend),
    Hardware {
        nvml: Option<Box<NvmlBackend>>,
        nvml_status: Option<GpuHostStatus>,
        amd: Option<AmdBackend>,
        intel: Option<IntelBackend>,
        apple: Option<AppleBackend>,
        ascend: Option<AscendBackend>,
    },
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

fn init_backend() -> anyhow::Result<ActiveBackend> {
    if let Ok(fake_path) = std::env::var(FAKE_ENV)
        && !fake_path.trim().is_empty()
    {
        let fb = FakeBackend::load(&PathBuf::from(fake_path.trim()))?;
        return Ok(ActiveBackend::Fake(fb));
    }

    let denied = parse_denied_backends();
    let (nvml, nvml_status) = if denied.contains("nvidia") {
        (None, None)
    } else {
        match NvmlBackend::try_init() {
            NvmlInitOutcome::Ready(b) => (Some(b), None),
            NvmlInitOutcome::Status(st) => (None, Some(st)),
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
    let ascend = if denied.contains("ascend") || denied.contains("npu") {
        None
    } else {
        AscendBackend::try_init()
    };

    Ok(ActiveBackend::Hardware {
        nvml,
        nvml_status,
        amd,
        intel,
        apple,
        ascend,
    })
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
        let mut live_procs: HashSet<(String, u32)> = HashSet::new();
        for g in samples.iter_mut() {
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
        self.proc_first_seen.retain(|k, _| live_procs.contains(k));
    }
}

/// Entry point for the hidden `meshharbord gpu-sampler` child process.
pub fn run_child() -> anyhow::Result<()> {
    let mut backend = init_backend()?;

    // Shared control state updated by a dedicated stdin reader thread so the
    // sampling loop never blocks waiting on stdin and reacts immediately to
    // interval changes or parent EOF.
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
            ActiveBackend::Hardware {
                nvml,
                nvml_status,
                amd,
                intel,
                apple,
                ascend,
            } => {
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

                let mut gpus = Vec::new();
                let mut backend_names: Vec<&'static str> = Vec::new();
                let mut driver_version: Option<String> = None;
                let mut host_status = GpuHostStatus::NoGpu;

                if let Some(nv) = nvml.as_mut() {
                    backend_names.push("nvml");
                    driver_version = nv.driver_version();
                    let (st, mut samples) = nv.sample(
                        state.include_procs,
                        &proc_lookup,
                        #[cfg(windows)]
                        &pdh_vram,
                    );
                    host_status = st;
                    gpus.append(&mut samples);
                } else if let Some(st) = nvml_status {
                    host_status = *st;
                }

                if let Some(a) = amd.as_ref() {
                    backend_names.push("amd");
                    let (st, mut samples) = a.sample(state.include_procs, &proc_lookup);
                    if !samples.is_empty() {
                        let offset = gpus.len() as u16;
                        for (i, s) in samples.iter_mut().enumerate() {
                            s.idx = offset + i as u16;
                        }
                        if matches!(host_status, GpuHostStatus::NoGpu) {
                            host_status = st;
                        }
                        gpus.append(&mut samples);
                    }
                }

                if let Some(i_b) = intel.as_ref() {
                    backend_names.push("intel");
                    let (st, mut samples) = i_b.sample(state.include_procs, &proc_lookup);
                    if !samples.is_empty() {
                        let offset = gpus.len() as u16;
                        for (i, s) in samples.iter_mut().enumerate() {
                            s.idx = offset + i as u16;
                        }
                        if matches!(host_status, GpuHostStatus::NoGpu) {
                            host_status = st;
                        }
                        gpus.append(&mut samples);
                    }
                }

                if let Some(ap) = apple.as_mut() {
                    backend_names.push("apple");
                    let (st, mut samples) = ap.sample(state.include_procs);
                    if !samples.is_empty() {
                        let offset = gpus.len() as u16;
                        for (i, s) in samples.iter_mut().enumerate() {
                            s.idx = offset + i as u16;
                        }
                        if matches!(host_status, GpuHostStatus::NoGpu) {
                            host_status = st;
                        }
                        gpus.append(&mut samples);
                    }
                }

                if let Some(asc) = ascend.as_ref() {
                    backend_names.push("ascend");
                    if driver_version.is_none() {
                        driver_version = asc.driver_version();
                    }
                    let (st, mut samples) = asc.sample(state.include_procs, &proc_lookup);
                    if !samples.is_empty() {
                        let offset = gpus.len() as u16;
                        for (i, s) in samples.iter_mut().enumerate() {
                            s.idx = offset + i as u16;
                        }
                        if matches!(host_status, GpuHostStatus::NoGpu) {
                            host_status = st;
                        }
                        gpus.append(&mut samples);
                    }
                }

                tracker.update(&mut gpus, now_s);
                seq += 1;
                GpuReport {
                    seq,
                    interval_ms: state.interval_ms,
                    status: host_status,
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
            let current_inv = fake::inventory_from_report(&report);
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
        }),
        ActiveBackend::Hardware {
            nvml,
            nvml_status,
            amd,
            intel,
            apple,
            ascend,
        } => {
            let mut gpus = Vec::new();
            let mut names = Vec::new();
            let mut driver_version = None;
            let mut status = GpuHostStatus::NoGpu;

            if let Some(nv) = nvml {
                let inv = nv.inventory();
                names.push("nvml");
                driver_version = inv.driver_version;
                status = inv.status;
                gpus.extend(inv.gpus);
            } else if let Some(st) = nvml_status {
                status = *st;
            }
            if let Some(a) = amd {
                let inv = a.inventory();
                names.push("amd");
                if driver_version.is_none() {
                    driver_version = inv.driver_version;
                }
                let offset = gpus.len() as u16;
                for (i, mut g) in inv.gpus.into_iter().enumerate() {
                    g.idx = offset + i as u16;
                    gpus.push(g);
                }
                if matches!(status, GpuHostStatus::NoGpu) && !gpus.is_empty() {
                    status = inv.status;
                }
            }
            if let Some(i_b) = intel {
                let inv = i_b.inventory();
                names.push("intel");
                let offset = gpus.len() as u16;
                for (i, mut g) in inv.gpus.into_iter().enumerate() {
                    g.idx = offset + i as u16;
                    gpus.push(g);
                }
                if matches!(status, GpuHostStatus::NoGpu) && !gpus.is_empty() {
                    status = inv.status;
                }
            }
            if let Some(ap) = apple {
                let inv = ap.inventory();
                names.push("apple");
                let offset = gpus.len() as u16;
                for (i, mut g) in inv.gpus.into_iter().enumerate() {
                    g.idx = offset + i as u16;
                    gpus.push(g);
                }
                if matches!(status, GpuHostStatus::NoGpu) && !gpus.is_empty() {
                    status = inv.status;
                }
            }
            if let Some(asc) = ascend {
                let inv = asc.inventory();
                names.push("ascend");
                if driver_version.is_none() {
                    driver_version = inv.driver_version;
                }
                let offset = gpus.len() as u16;
                for (i, mut g) in inv.gpus.into_iter().enumerate() {
                    g.idx = offset + i as u16;
                    gpus.push(g);
                }
                if matches!(status, GpuHostStatus::NoGpu) && !gpus.is_empty() {
                    status = inv.status;
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
            }
        }
    }
}
