// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! AMD Linux sysfs + DRM fdinfo + KFD backend (FR-139 §3).
//!
//! Pure file reads under `/sys/class/drm/card*/device/`, hwmon, `/proc/<pid>/fdinfo`,
//! and `/sys/class/kfd/kfd/proc/<pid>/` (for ROCm compute). Never touches GRBM
//! registers so idle/suspended GPUs are never woken.

#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

use meshharbor_remote_control::gpu::{GpuHostStatus, GpuInventory, GpuSample};
#[cfg(target_os = "linux")]
use meshharbor_remote_control::gpu::{GpuInventoryItem, GpuProc, ProcsState};

use super::proc_linux::ProcLookup;

#[cfg(target_os = "linux")]
struct AmdCard {
    idx: u16,
    uuid: String,
    name: String,
    pci_bus: Option<String>,
    dev_dir: PathBuf,
    mem_total_mb: Option<u32>,
    power_limit_w: Option<u16>,
}

pub struct AmdBackend {
    #[cfg(target_os = "linux")]
    cards: Vec<AmdCard>,
}

impl AmdBackend {
    pub fn try_init() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            let cards = discover_cards();
            if cards.is_empty() {
                None
            } else {
                Some(Self { cards })
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    pub fn inventory(&self) -> GpuInventory {
        #[cfg(target_os = "linux")]
        {
            let gpus = self
                .cards
                .iter()
                .map(|c| GpuInventoryItem {
                    uuid: c.uuid.clone(),
                    idx: c.idx,
                    name: c.name.clone(),
                    mem_total_mb: c.mem_total_mb,
                    power_limit_w: c.power_limit_w,
                    mig: false,
                    pci_bus: c.pci_bus.clone(),
                    unified: false,
                })
                .collect();
            GpuInventory {
                backend: Some("amd".into()),
                driver_version: read_amdgpu_version(),
                gpus,
                status: GpuHostStatus::Ok,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            GpuInventory::default()
        }
    }

    pub fn sample(&self, include_procs: bool, proc_lookup: &ProcLookup) -> (GpuHostStatus, Vec<GpuSample>) {
        #[cfg(target_os = "linux")]
        {
            let (procs_by_pci, kfd_procs, partial) = if include_procs {
                collect_amd_procs(proc_lookup)
            } else {
                (HashMap::new(), HashMap::new(), false)
            };

            let mut out = Vec::with_capacity(self.cards.len());
            for c in &self.cards {
                let util_pct = read_u64(&c.dev_dir.join("gpu_busy_percent"))
                    .and_then(|v| (v <= 100).then_some(v as u8));
                let mem_used_mb = read_u64(&c.dev_dir.join("mem_info_vram_used"))
                    .map(|b| (b / (1024 * 1024)) as u32);
                let mem_total_mb = read_u64(&c.dev_dir.join("mem_info_vram_total"))
                    .map(|b| (b / (1024 * 1024)) as u32)
                    .or(c.mem_total_mb);
                let (temp_c, power_w, power_limit_w, fan_pct) = read_hwmon(&c.dev_dir);

                let (procs_state, procs) = if !include_procs {
                    (ProcsState::Off, None)
                } else {
                    let mut merged: HashMap<u32, GpuProc> = HashMap::new();
                    if let Some(pci) = c.pci_bus.as_deref()
                        && let Some(list) = procs_by_pci.get(pci)
                    {
                        for p in list {
                            merged.insert(p.pid, p.clone());
                        }
                    }
                    // Merge KFD ROCm processes (attribute to card when single-GPU or matching GPU id).
                    if self.cards.len() == 1 {
                        for p in kfd_procs.values() {
                            merged
                                .entry(p.pid)
                                .and_modify(|e| {
                                    if p.mem_mb.unwrap_or(0) > e.mem_mb.unwrap_or(0) {
                                        e.mem_mb = p.mem_mb;
                                    }
                                    e.kind = Some("compute".into());
                                })
                                .or_insert_with(|| p.clone());
                        }
                    }
                    let mut list: Vec<GpuProc> = merged.into_values().collect();
                    list.sort_by(|a, b| b.mem_mb.cmp(&a.mem_mb).then_with(|| a.pid.cmp(&b.pid)));
                    let state = if partial {
                        ProcsState::Partial
                    } else {
                        ProcsState::Ok
                    };
                    (state, Some(list))
                };

                out.push(GpuSample {
                    uuid: c.uuid.clone(),
                    idx: c.idx,
                    name: Some(c.name.clone()),
                    mem_total_mb,
                    power_limit_w: power_limit_w.or(c.power_limit_w),
                    pci_bus: c.pci_bus.clone(),
                    unified: false,
                    util_pct,
                    mem_used_mb,
                    temp_c,
                    power_w,
                    fan_pct,
                    sm_clock_mhz: None,
                    throttle: None,
                    ecc_uncorrected: None,
                    remapped_rows: None,
                    xid_errors: None,
                    mig: false,
                    lost: false,
                    idle_since: None,
                    free_mem_floor_mb: None,
                    procs_state,
                    procs,
                });
            }
            (GpuHostStatus::Ok, out)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (include_procs, proc_lookup);
            (GpuHostStatus::NoGpu, Vec::new())
        }
    }
}

#[cfg(target_os = "linux")]
fn discover_cards() -> Vec<AmdCard> {
    let Ok(entries) = fs::read_dir("/sys/class/drm") else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("card") && !n.contains('-'))
        })
        .collect();
    dirs.sort();

    let mut cards = Vec::new();
    for path in dirs {
        let dev = path.join("device");
        let vendor = fs::read_to_string(dev.join("vendor")).unwrap_or_default();
        if !vendor.trim().eq_ignore_ascii_case("0x1002") {
            continue;
        }
        let idx = cards.len() as u16;
        let pci_bus = read_pci_slot(&dev);
        let unique_id = fs::read_to_string(dev.join("unique_id"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let uuid = unique_id
            .map(|u| format!("amd-{u}"))
            .or_else(|| pci_bus.as_ref().map(|p| format!("amd-{p}")))
            .unwrap_or_else(|| format!("amd-{idx}"));
        let name = fs::read_to_string(dev.join("product_name"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("AMD GPU {idx}"));
        let mem_total_mb = read_u64(&dev.join("mem_info_vram_total"))
            .map(|b| (b / (1024 * 1024)) as u32);
        let (_, _, power_limit_w, _) = read_hwmon(&dev);

        cards.push(AmdCard {
            idx,
            uuid,
            name,
            pci_bus,
            dev_dir: dev,
            mem_total_mb,
            power_limit_w,
        });
    }
    cards
}

#[cfg(target_os = "linux")]
fn read_amdgpu_version() -> Option<String> {
    fs::read_to_string("/sys/module/amdgpu/version")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
pub(crate) fn read_pci_slot(dev_dir: &Path) -> Option<String> {
    let uevent = fs::read_to_string(dev_dir.join("uevent")).ok()?;
    for line in uevent.lines() {
        if let Some(slot) = line.strip_prefix("PCI_SLOT_NAME=") {
            let trimmed = slot.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub(crate) fn read_u64(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
pub(crate) fn read_hwmon(dev_dir: &Path) -> (Option<i16>, Option<u16>, Option<u16>, Option<u8>) {
    let hwmon_root = dev_dir.join("hwmon");
    let Ok(entries) = fs::read_dir(hwmon_root) else {
        return (None, None, None, None);
    };
    let Some(hwmon) = entries.flatten().map(|e| e.path()).next() else {
        return (None, None, None, None);
    };
    let temp_c = read_u64(&hwmon.join("temp1_input")).map(|mc| (mc / 1000) as i16);
    let power_w = read_u64(&hwmon.join("power1_average"))
        .or_else(|| read_u64(&hwmon.join("power1_input")))
        .map(|uw| (uw / 1_000_000) as u16);
    let power_limit_w = read_u64(&hwmon.join("power1_cap")).map(|uw| (uw / 1_000_000) as u16);
    let fan_pct = read_u64(&hwmon.join("pwm1")).map(|pwm| {
        let max = read_u64(&hwmon.join("pwm1_max")).unwrap_or(255).max(1);
        ((pwm * 100) / max).min(100) as u8
    });
    (temp_c, power_w, power_limit_w, fan_pct)
}

/// Parse one `/proc/<pid>/fdinfo/<fd>` entry for DRM client attribution.
#[cfg(any(target_os = "linux", test))]
pub fn parse_drm_fdinfo(text: &str) -> Option<(String, Option<String>, u64, bool)> {
    let mut pdev: Option<String> = None;
    let mut client_id: Option<String> = None;
    let mut vram_bytes: u64 = 0;
    let mut has_drm = false;
    let mut compute = false;

    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        match k {
            "drm-driver" => has_drm = true,
            "drm-pdev" => pdev = Some(v.to_string()),
            "drm-client-id" => client_id = Some(v.to_string()),
            "drm-memory-vram" | "drm-resident-vram" | "drm-resident-local0" => {
                vram_bytes = vram_bytes.max(parse_fdinfo_bytes(v));
            }
            "drm-engine-compute" | "drm-engine-ccs" => {
                compute = true;
            }
            _ => {}
        }
    }

    if !has_drm {
        return None;
    }
    Some((pdev?, client_id, vram_bytes, compute))
}

#[cfg(any(target_os = "linux", test))]
fn parse_fdinfo_bytes(val: &str) -> u64 {
    let mut parts = val.split_whitespace();
    let num: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    match parts.next().unwrap_or("") {
        "KiB" | "KB" | "kB" => num.saturating_mul(1024),
        "MiB" | "MB" => num.saturating_mul(1024 * 1024),
        "GiB" | "GB" => num.saturating_mul(1024 * 1024 * 1024),
        _ => num,
    }
}

#[cfg(target_os = "linux")]
fn collect_amd_procs(
    proc_lookup: &ProcLookup,
) -> (HashMap<String, Vec<GpuProc>>, HashMap<u32, GpuProc>, bool) {
    let mut by_pci: HashMap<String, HashMap<u32, GpuProc>> = HashMap::new();
    let mut kfd_procs: HashMap<u32, GpuProc> = HashMap::new();
    let mut partial = false;

    // 1. DRM fdinfo scan, deduplicated by `(pid, pdev, drm-client-id)`.
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let fdinfo_dir = entry.path().join("fdinfo");
            let fd_entries = match fs::read_dir(&fdinfo_dir) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    partial = true;
                    continue;
                }
                Err(_) => continue,
            };
            let mut seen_clients: HashSet<(String, String)> = HashSet::new();
            for fd in fd_entries.flatten() {
                let Ok(text) = fs::read_to_string(fd.path()) else {
                    continue;
                };
                let Some((pdev, client_id, vram_bytes, compute)) = parse_drm_fdinfo(&text) else {
                    continue;
                };
                if let Some(cid) = client_id
                    && !seen_clients.insert((pdev.clone(), cid))
                {
                    continue;
                }
                let mem_mb = (vram_bytes / (1024 * 1024)) as u32;
                if mem_mb == 0 {
                    continue;
                }
                let card_map = by_pci.entry(pdev).or_default();
                card_map
                    .entry(pid)
                    .and_modify(|p| {
                        p.mem_mb = Some(p.mem_mb.unwrap_or(0).saturating_add(mem_mb));
                    })
                    .or_insert_with(|| {
                        let attr = proc_lookup.lookup(pid);
                        if attr.access_denied {
                            partial = true;
                        }
                        GpuProc {
                            pid,
                            user: attr.user,
                            name: attr.name,
                            mem_mb: Some(mem_mb),
                            sm_pct: None,
                            cpu_pct: None,
                            started_at: attr.started_at,
                            container: attr.container,
                            kind: Some(if compute { "compute" } else { "graphics" }.into()),
                        }
                    });
            }
        }
    }

    // 2. KFD ROCm compute attribution (`/sys/class/kfd/kfd/proc/<pid>/vram_*`).
    if let Ok(entries) = fs::read_dir("/sys/class/kfd/kfd/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let mut total_bytes = 0u64;
            if let Ok(files) = fs::read_dir(entry.path()) {
                for f in files.flatten() {
                    if f.file_name().to_string_lossy().starts_with("vram_")
                        && let Some(v) = read_u64(&f.path())
                    {
                        total_bytes = total_bytes.saturating_add(v);
                    }
                }
            }
            if total_bytes > 0 {
                let attr = proc_lookup.lookup(pid);
                if attr.access_denied {
                    partial = true;
                }
                kfd_procs.insert(
                    pid,
                    GpuProc {
                        pid,
                        user: attr.user,
                        name: attr.name,
                        mem_mb: Some((total_bytes / (1024 * 1024)) as u32),
                        sm_pct: None,
                        cpu_pct: None,
                        started_at: attr.started_at,
                        container: attr.container,
                        kind: Some("compute".into()),
                    },
                );
            }
        }
    }

    let flattened = by_pci
        .into_iter()
        .map(|(pci, m)| (pci, m.into_values().collect()))
        .collect();
    (flattened, kfd_procs, partial)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr139_drm_fdinfo_parses_vram_and_client_id() {
        let sample = "\
pos:\t0
flags:\t02100002
drm-driver:\tamdgpu
drm-client-id:\t42
drm-pdev:\t0000:03:00.0
drm-memory-vram:\t1048576 KiB
drm-engine-compute:\t12345 ns
";
        let (pdev, cid, bytes, compute) = parse_drm_fdinfo(sample).expect("parses");
        assert_eq!(pdev, "0000:03:00.0");
        assert_eq!(cid.as_deref(), Some("42"));
        assert_eq!(bytes, 1024 * 1024 * 1024);
        assert!(compute);
    }
}
