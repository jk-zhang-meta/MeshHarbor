// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Zero-package Google Cloud TPU backend (Linux PCIe + `/dev/accel*` / `/dev/vfio/*` + `/proc` fd).
//!
//! Works without installing `tpu-info`, `libtpu`, or Python packages:
//! - Discovers ONLY genuine Google Cloud TPU PCIe devices (`vendor = 0x1ae0`
//!   matching known TPU device IDs or PCI class `0x12xxxx`, never gVNIC or
//!   non-Google `/dev/accel*` devices).
//! - Maps each chip to its kernel device node (`/dev/accelN` on v2/v3/v4 or
//!   `/dev/vfio/<iommu_group>` on v5e/v5p/v6e).
//! - Attributes occupying processes strictly via L1 `/proc/<pid>/fd/*` symlink
//!   targets + `ProcLookup` (never reads `cmdline`/`environ`).
//! - Leaves unavailable hardware metrics (duty cycle / HBM / temp / power) as
//!   `None` (NEVER fabricates `0`), and reports host status `Limited` with an
//!   actionable `status_detail` explaining that telemetry is PCIe/device-node
//!   based.

#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

use meshharbor_remote_control::gpu::{GpuHostStatus, GpuInventory, GpuSample};
#[cfg(target_os = "linux")]
use meshharbor_remote_control::gpu::{GpuInventoryItem, GpuProc, ProcsState};

use super::pci_fallback::{AccelVendor, PciAccelerator};
use super::proc_linux::ProcLookup;
#[cfg(target_os = "linux")]
use super::proc_linux::truncate_proc_name;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct TpuChip {
    idx: u16,
    uuid: String,
    name: String,
    pci_bus: String,
    driver: Option<String>,
    dev_nodes: Vec<String>,
}

pub struct TpuBackend {
    #[cfg(target_os = "linux")]
    chips: Vec<TpuChip>,
}

impl TpuBackend {
    /// Initialize from already-scanned host PCIe accelerators so we never scan
    /// `/sys/bus/pci/devices` twice and never misidentify non-Google `/dev/accel*`.
    pub fn try_init_from_pci(pci_devs: &[PciAccelerator]) -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            let mut chips = Vec::new();
            for dev in pci_devs.iter().filter(|d| d.vendor == AccelVendor::Tpu) {
                // Only bind devices that have an active kernel driver (`accel`,
                // `gasket`, `vfio-pci`, etc.); unbound TPU PCIe devices fall
                // through to `pci_fallback` as `DriverMissing`.
                if dev.driver.is_none() {
                    continue;
                }
                let idx = chips.len() as u16;
                let dev_nodes = resolve_tpu_dev_nodes(&dev.pci_bus, dev.iommu_group.as_deref());
                chips.push(TpuChip {
                    idx,
                    uuid: format!("TPU-{idx}-{}", dev.pci_bus.to_ascii_lowercase()),
                    name: dev.model_name.clone(),
                    pci_bus: dev.pci_bus.clone(),
                    driver: dev.driver.clone(),
                    dev_nodes,
                });
            }
            if chips.is_empty() {
                None
            } else {
                Some(Self { chips })
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pci_devs;
            None
        }
    }

    pub fn driver_version(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            self.chips.first().and_then(|c| c.driver.clone())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    pub fn status_detail(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let drv = self
                .chips
                .first()
                .and_then(|c| c.driver.as_deref())
                .unwrap_or("vfio/accel");
            Some(format!(
                "Google Cloud TPU ({} chip(s), driver {drv}): PCIe & process lock active; HBM/duty-cycle metrics require runtime telemetry",
                self.chips.len()
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    pub fn pci_bdfs(&self) -> Vec<String> {
        #[cfg(target_os = "linux")]
        {
            self.chips.iter().map(|c| c.pci_bus.clone()).collect()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }

    pub fn inventory(&self) -> GpuInventory {
        #[cfg(target_os = "linux")]
        {
            let gpus = self
                .chips
                .iter()
                .map(|c| GpuInventoryItem {
                    uuid: c.uuid.clone(),
                    idx: c.idx,
                    name: c.name.clone(),
                    mem_total_mb: None,
                    power_limit_w: None,
                    mig: false,
                    pci_bus: Some(c.pci_bus.clone()),
                    unified: false,
                })
                .collect();
            GpuInventory {
                backend: Some("tpu".into()),
                driver_version: self.driver_version(),
                gpus,
                status: GpuHostStatus::Limited,
                status_detail: self.status_detail(),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            GpuInventory::default()
        }
    }

    pub fn sample(
        &self,
        include_procs: bool,
        proc_lookup: &ProcLookup,
    ) -> (GpuHostStatus, Vec<GpuSample>) {
        #[cfg(target_os = "linux")]
        {
            let (procs_by_node, partial) = if include_procs {
                let wanted: HashSet<String> = self
                    .chips
                    .iter()
                    .flat_map(|c| c.dev_nodes.iter().cloned())
                    .collect();
                scan_open_device_nodes(&wanted, proc_lookup)
            } else {
                (HashMap::new(), false)
            };

            let mut out = Vec::with_capacity(self.chips.len());
            for c in &self.chips {
                let (procs_state, procs) = if !include_procs {
                    (ProcsState::Off, None)
                } else if c.dev_nodes.is_empty() {
                    (ProcsState::Unsupported, None)
                } else {
                    let mut by_pid: HashMap<u32, GpuProc> = HashMap::new();
                    for node in &c.dev_nodes {
                        if let Some(list) = procs_by_node.get(node) {
                            for p in list {
                                by_pid.entry(p.pid).or_insert_with(|| p.clone());
                            }
                        }
                    }
                    let mut list: Vec<GpuProc> = by_pid.into_values().collect();
                    list.sort_by_key(|p| p.pid);
                    let st = if partial {
                        ProcsState::Partial
                    } else {
                        ProcsState::Ok
                    };
                    (st, Some(list))
                };

                out.push(GpuSample {
                    uuid: c.uuid.clone(),
                    idx: c.idx,
                    name: Some(c.name.clone()),
                    pci_bus: Some(c.pci_bus.clone()),
                    backend: Some("tpu".into()),
                    vendor_index: Some(c.idx),
                    presence_only: true,
                    procs_state,
                    procs,
                    ..Default::default()
                });
            }
            (GpuHostStatus::Limited, out)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (include_procs, proc_lookup);
            (GpuHostStatus::NoGpu, Vec::new())
        }
    }
}

#[cfg(target_os = "linux")]
fn resolve_tpu_dev_nodes(pci_bus: &str, iommu_group: Option<&str>) -> Vec<String> {
    let mut nodes = Vec::new();
    let sys_dev = PathBuf::from("/sys/bus/pci/devices").join(pci_bus);

    // TPU v2/v3/v4 gasket/accel class: `/sys/bus/pci/devices/<bdf>/accel/accel*`
    if let Ok(entries) = fs::read_dir(sys_dev.join("accel")) {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                let direct = format!("/dev/{name}");
                let nested = format!("/dev/accel/{name}");
                if Path::new(&direct).exists() {
                    nodes.push(direct);
                }
                if Path::new(&nested).exists() {
                    nodes.push(nested);
                }
            }
        }
    }

    // TPU v5e/v5p/v6e user-space VFIO: `/dev/vfio/<iommu_group>`
    if let Some(grp) = iommu_group {
        let vfio = format!("/dev/vfio/{grp}");
        if Path::new(&vfio).exists() {
            nodes.push(vfio);
        }
    }
    nodes
}

/// Shared Linux `/proc/<pid>/fd/*` device-node attribution helper (reused by
/// both TPU backend and Ascend `/dev/davinci*` zero-package fallback).
#[cfg(target_os = "linux")]
pub(crate) fn scan_open_device_nodes(
    wanted_nodes: &HashSet<String>,
    proc_lookup: &ProcLookup,
) -> (HashMap<String, Vec<GpuProc>>, bool) {
    let mut by_node: HashMap<String, HashMap<u32, GpuProc>> = HashMap::new();
    let mut partial = false;
    if wanted_nodes.is_empty() {
        return (HashMap::new(), false);
    }
    let Ok(entries) = fs::read_dir("/proc") else {
        return (HashMap::new(), true);
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                partial = true;
                continue;
            }
            Err(_) => continue,
        };
        for fd_res in fds {
            let fd = match fd_res {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    partial = true;
                    continue;
                }
                Err(_) => continue,
            };
            let target = match fs::read_link(fd.path()) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    partial = true;
                    continue;
                }
                Err(_) => continue,
            };
            let target_s = target.to_string_lossy();
            let clean = target_s.strip_suffix(" (deleted)").unwrap_or(&target_s);
            if !wanted_nodes.contains(clean) {
                continue;
            }
            let node_map = by_node.entry(clean.to_string()).or_default();
            node_map.entry(pid).or_insert_with(|| {
                let attr = proc_lookup.lookup(pid);
                if attr.access_denied {
                    partial = true;
                }
                GpuProc {
                    pid,
                    user: attr.user,
                    name: attr.name.map(|n| truncate_proc_name(&n)),
                    mem_mb: None,
                    sm_pct: None,
                    cpu_pct: None,
                    started_at: attr.started_at,
                    container: attr.container,
                    kind: Some("compute".into()),
                }
            });
        }
    }
    (
        by_node
            .into_iter()
            .map(|(k, m)| (k, m.into_values().collect()))
            .collect(),
        partial,
    )
}
