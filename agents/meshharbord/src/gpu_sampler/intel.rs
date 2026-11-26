// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Intel Linux `xe` / `i915` sysfs + DRM fdinfo backend (FR-139 §3).
//!
//! Skips `perf_event_open` PMU when non-root so unprivileged daemons never
//! fail or log permission errors.

#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use meshharbor_remote_control::gpu::{GpuHostStatus, GpuInventory, GpuSample};
#[cfg(target_os = "linux")]
use meshharbor_remote_control::gpu::{GpuInventoryItem, GpuProc, ProcsState};

#[cfg(target_os = "linux")]
use super::amd::{parse_drm_fdinfo, read_hwmon, read_pci_slot};
use super::proc_linux::ProcLookup;

#[cfg(target_os = "linux")]
struct IntelCard {
    idx: u16,
    uuid: String,
    name: String,
    pci_bus: Option<String>,
    dev_dir: PathBuf,
    driver: String,
    power_limit_w: Option<u16>,
}

pub struct IntelBackend {
    #[cfg(target_os = "linux")]
    cards: Vec<IntelCard>,
}

impl IntelBackend {
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
            let driver = self.cards.first().map(|c| c.driver.clone());
            let gpus = self
                .cards
                .iter()
                .map(|c| GpuInventoryItem {
                    uuid: c.uuid.clone(),
                    idx: c.idx,
                    name: c.name.clone(),
                    mem_total_mb: None,
                    power_limit_w: c.power_limit_w,
                    mig: false,
                    pci_bus: c.pci_bus.clone(),
                    unified: false,
                })
                .collect();
            GpuInventory {
                backend: Some("intel".into()),
                driver_version: driver,
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
            let (procs_by_pci, partial) = if include_procs {
                collect_intel_procs(proc_lookup)
            } else {
                (HashMap::new(), false)
            };

            let mut out = Vec::with_capacity(self.cards.len());
            for c in &self.cards {
                let (temp_c, power_w, power_limit_w, fan_pct) = read_hwmon(&c.dev_dir);
                let (procs_state, procs) = if !include_procs {
                    (ProcsState::Off, None)
                } else {
                    let mut list = c
                        .pci_bus
                        .as_deref()
                        .and_then(|p| procs_by_pci.get(p))
                        .cloned()
                        .unwrap_or_default();
                    list.sort_by(|a, b| b.mem_mb.cmp(&a.mem_mb).then_with(|| a.pid.cmp(&b.pid)));
                    let state = if partial {
                        ProcsState::Partial
                    } else {
                        ProcsState::Ok
                    };
                    (state, Some(list))
                };

                let mem_used_mb = procs.as_ref().map(|list| {
                    list.iter().filter_map(|p| p.mem_mb).sum::<u32>()
                });

                out.push(GpuSample {
                    uuid: c.uuid.clone(),
                    idx: c.idx,
                    name: Some(c.name.clone()),
                    mem_total_mb: None,
                    power_limit_w: power_limit_w.or(c.power_limit_w),
                    pci_bus: c.pci_bus.clone(),
                    unified: false,
                    util_pct: None,
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
fn discover_cards() -> Vec<IntelCard> {
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
        if !vendor.trim().eq_ignore_ascii_case("0x8086") {
            continue;
        }
        let uevent = fs::read_to_string(dev.join("uevent")).unwrap_or_default();
        let driver = uevent
            .lines()
            .find_map(|l| l.strip_prefix("DRIVER="))
            .unwrap_or("i915")
            .trim()
            .to_string();
        if driver != "xe" && driver != "i915" {
            continue;
        }
        let idx = cards.len() as u16;
        let pci_bus = read_pci_slot(&dev);
        let uuid = pci_bus
            .as_ref()
            .map(|p| format!("intel-{p}"))
            .unwrap_or_else(|| format!("intel-{idx}"));
        let name = format!("Intel GPU ({driver}) #{idx}");
        let (_, _, power_limit_w, _) = read_hwmon(&dev);

        cards.push(IntelCard {
            idx,
            uuid,
            name,
            pci_bus,
            dev_dir: dev,
            driver,
            power_limit_w,
        });
    }
    cards
}

#[cfg(target_os = "linux")]
fn collect_intel_procs(proc_lookup: &ProcLookup) -> (HashMap<String, Vec<GpuProc>>, bool) {
    let mut by_pci: HashMap<String, HashMap<u32, GpuProc>> = HashMap::new();
    let mut partial = false;

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
                if !text.contains("drm-driver:\txe") && !text.contains("drm-driver:\ti915") {
                    continue;
                }
                let Some((pdev, client_id, vram_bytes, compute)) = parse_drm_fdinfo(&text) else {
                    continue;
                };
                if let Some(cid) = client_id
                    && !seen_clients.insert((pdev.clone(), cid))
                {
                    continue;
                }
                let mem_mb = (vram_bytes / (1024 * 1024)) as u32;
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
                            mem_mb: (mem_mb > 0).then_some(mem_mb),
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

    (
        by_pci
            .into_iter()
            .map(|(k, m)| (k, m.into_values().collect()))
            .collect(),
        partial,
    )
}
