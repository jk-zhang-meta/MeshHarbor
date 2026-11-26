// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Zero-package Linux PCIe sysfs accelerator discovery (FR-139).
//!
//! Reads ONLY static kernel sysfs attributes under `/sys/bus/pci/devices/*`
//! (`vendor`, `device`, `class`, `uevent`, `driver`, `iommu_group`) — zero
//! external binaries, zero vendor libraries, zero driver ioctls, never wakes
//! runtime-suspended GPUs.
//!
//! Used so hosts missing vendor packages or kernel drivers report accurate
//! hardware inventory and actionable diagnosis (`driver_missing` vs `limited`
//! vs `unknown`) instead of falsely reporting `no_gpu`.

use std::collections::HashSet;
#[cfg(any(target_os = "linux", test))]
use std::fs;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;

use meshharbor_remote_control::gpu::{
    GpuHostStatus, GpuInventoryItem, GpuSample, ProcsState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccelVendor {
    Nvidia,
    Ascend,
    Tpu,
    Amd,
    Intel,
}

impl AccelVendor {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Nvidia => "nvidia",
            Self::Ascend => "ascend",
            Self::Tpu => "tpu",
            Self::Amd => "amd",
            Self::Intel => "intel",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Nvidia => "NVIDIA GPU",
            Self::Ascend => "Huawei Ascend NPU",
            Self::Tpu => "Google Cloud TPU",
            Self::Amd => "AMD GPU",
            Self::Intel => "Intel GPU",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciAccelerator {
    pub vendor: AccelVendor,
    pub pci_bus: String,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u32,
    pub driver: Option<String>,
    pub model_name: String,
    pub iommu_group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PciScanOutcome {
    Readable(Vec<PciAccelerator>),
    Unreadable(String),
}

/// Normalize PCIe BDF strings so `00000000:65:00.0` (NVML 8-hex domain) and
/// `0000:65:00.0` (Linux sysfs 4-hex domain) compare equal.
pub fn normalize_pci_bdf(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if let Some((dom, rest)) = lower.split_once(':')
        && dom.len() == 8
        && let Some(short) = dom.strip_prefix("0000")
    {
        return format!("{short}:{rest}");
    }
    lower
}

/// Scan the host's Linux PCI sysfs tree. On non-Linux hosts returns an empty
/// readable list (platform-specific backends handle macOS/Windows).
pub fn scan_host_pci() -> PciScanOutcome {
    #[cfg(target_os = "linux")]
    {
        scan_pci_dir(Path::new("/sys/bus/pci/devices"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        PciScanOutcome::Readable(Vec::new())
    }
}

/// Pure sysfs directory scanner (unit-tested with synthetic directories).
#[cfg(any(target_os = "linux", test))]
pub fn scan_pci_dir(root: &Path) -> PciScanOutcome {
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(e) => {
            return PciScanOutcome::Unreadable(format!(
                "PCI sysfs inventory unreadable ({}): {e}",
                root.display()
            ));
        }
    };

    let mut dirs: Vec<(String, std::path::PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            Some((name, e.path()))
        })
        .collect();
    dirs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    for (bdf, dir) in dirs {
        let Some(vendor_id) = read_hex_u16(&dir.join("vendor")) else {
            continue;
        };
        let Some(device_id) = read_hex_u16(&dir.join("device")) else {
            continue;
        };
        let Some(class_code) = read_hex_u32(&dir.join("class")) else {
            continue;
        };
        let driver = read_bound_driver(&dir);
        let Some(vendor) = classify_pci_accelerator(vendor_id, device_id, class_code, driver.as_deref())
        else {
            continue;
        };
        let iommu_group = fs::read_link(dir.join("iommu_group"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        let model_name = lookup_pci_model_name(vendor, vendor_id, device_id);
        out.push(PciAccelerator {
            vendor,
            pci_bus: bdf,
            vendor_id,
            device_id,
            class_code,
            driver,
            model_name,
            iommu_group,
        });
    }
    PciScanOutcome::Readable(out)
}

#[cfg(any(target_os = "linux", test))]
fn read_hex_u16(path: &Path) -> Option<u16> {
    let raw = fs::read_to_string(path).ok()?;
    let hex = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(hex, 16).ok()
}

#[cfg(any(target_os = "linux", test))]
fn read_hex_u32(path: &Path) -> Option<u32> {
    let raw = fs::read_to_string(path).ok()?;
    let hex = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(hex, 16).ok()
}

#[cfg(any(target_os = "linux", test))]
fn read_bound_driver(dev_dir: &Path) -> Option<String> {
    if let Ok(target) = fs::read_link(dev_dir.join("driver"))
        && let Some(name) = target.file_name().and_then(|n| n.to_str())
        && !name.is_empty()
    {
        return Some(name.to_string());
    }
    // Fallback for synthetic test fixtures or sysfs trees where `uevent` carries `DRIVER=`.
    let uevent = fs::read_to_string(dev_dir.join("uevent")).ok()?;
    for line in uevent.lines() {
        if let Some(drv) = line.strip_prefix("DRIVER=") {
            let trimmed = drv.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Decide whether a PCI `(vendor_id, device_id, class_code)` represents an
/// AI/compute GPU, NPU, or TPU accelerator — strictly excluding NICs, audio
/// functions, USB controllers, and host bridges from the same PCI vendor.
#[cfg(any(target_os = "linux", test))]
pub fn classify_pci_accelerator(
    vendor_id: u16,
    device_id: u16,
    class_code: u32,
    driver: Option<&str>,
) -> Option<AccelVendor> {
    let base_class = (class_code >> 16) & 0xff;
    let sub_class = (class_code >> 8) & 0xff;
    let is_display = base_class == 0x03 && matches!(sub_class, 0x00 | 0x02 | 0x80);
    let is_accelerator = base_class == 0x12;

    match vendor_id {
        // NVIDIA (exclude HDMI audio 0x0403, USB 0x0c03, NVSwitch bridges 0x0680)
        0x10de if is_display || is_accelerator => Some(AccelVendor::Nvidia),
        // Huawei Ascend NPU (exclude Huawei NICs 0x0200 and SAS/RAID HBAs 0x01xx)
        0x19e5
            if is_accelerator
                || is_display
                || matches!(device_id, 0xd100 | 0xd105 | 0xd107 | 0xd500 | 0xd801..=0xd807) =>
        {
            Some(AccelVendor::Ascend)
        }
        // Google Cloud TPU (exclude gVNIC 0x0042 / virtual devices!)
        0x1ae0
            if is_accelerator
                || matches!(
                    device_id,
                    0x0027 | 0x0056 | 0x005e | 0x0062 | 0x0063 | 0x006f
                ) =>
        {
            Some(AccelVendor::Tpu)
        }
        // AMD Radeon / Instinct GPUs
        0x1002 if is_display || is_accelerator => Some(AccelVendor::Amd),
        // Intel discrete/compute GPUs (Arc, Flex, Max) or DRM-bound Intel GPUs
        0x8086
            if is_accelerator
                || (base_class == 0x03 && matches!(sub_class, 0x02 | 0x80))
                || (is_display
                    && (matches!(driver, Some("xe" | "i915"))
                        || matches!(device_id & 0xff00, 0x5600 | 0x0b00 | 0xe200))) =>
        {
            Some(AccelVendor::Intel)
        }
        _ => None,
    }
}

/// Human-friendly model name from static PCI device IDs (no `pci.ids` file
/// required). Unknown IDs still preserve the exact `vendor:device` hex pair so
/// operators know which hardware was detected.
pub fn lookup_pci_model_name(vendor: AccelVendor, vendor_id: u16, device_id: u16) -> String {
    let known: Option<&'static str> = match (vendor, device_id) {
        // NVIDIA datacenter & workstation GPUs
        (AccelVendor::Nvidia, 0x1db4 | 0x1db5 | 0x1db6 | 0x1db1) => Some("NVIDIA Tesla V100"),
        (AccelVendor::Nvidia, 0x1eb8) => Some("NVIDIA Tesla T4"),
        (AccelVendor::Nvidia, 0x20b0 | 0x20b2 | 0x20b5 | 0x20f1) => Some("NVIDIA A100"),
        (AccelVendor::Nvidia, 0x20b7) => Some("NVIDIA A30"),
        (AccelVendor::Nvidia, 0x20f3 | 0x20f5) => Some("NVIDIA A800"),
        (AccelVendor::Nvidia, 0x2230) => Some("NVIDIA RTX A6000"),
        (AccelVendor::Nvidia, 0x2235) => Some("NVIDIA A40"),
        (AccelVendor::Nvidia, 0x2236) => Some("NVIDIA A10"),
        (AccelVendor::Nvidia, 0x2324 | 0x2330 | 0x2331 | 0x2335) => Some("NVIDIA H100"),
        (AccelVendor::Nvidia, 0x2322 | 0x233a) => Some("NVIDIA H800"),
        (AccelVendor::Nvidia, 0x233b) => Some("NVIDIA H200"),
        (AccelVendor::Nvidia, 0x2329) => Some("NVIDIA H20"),
        (AccelVendor::Nvidia, 0x2684 | 0x2685) => Some("NVIDIA GeForce RTX 4090"),
        (AccelVendor::Nvidia, 0x26b1) => Some("NVIDIA RTX 6000 Ada"),
        (AccelVendor::Nvidia, 0x26b5) => Some("NVIDIA L40"),
        (AccelVendor::Nvidia, 0x26b9) => Some("NVIDIA L40S"),
        (AccelVendor::Nvidia, 0x27b8) => Some("NVIDIA L4"),
        (AccelVendor::Nvidia, 0x2900 | 0x2901) => Some("NVIDIA B200"),
        (AccelVendor::Nvidia, 0x2b85) => Some("NVIDIA GeForce RTX 5090"),
        // Huawei Ascend NPUs
        (AccelVendor::Ascend, 0xd100) => Some("Ascend 310"),
        (AccelVendor::Ascend, 0xd105 | 0xd500) => Some("Ascend 310P"),
        (AccelVendor::Ascend, 0xd107) => Some("Ascend 310B"),
        (AccelVendor::Ascend, 0xd801) => Some("Ascend 910A"),
        (AccelVendor::Ascend, 0xd802) => Some("Ascend 910B"),
        (AccelVendor::Ascend, 0xd803) => Some("Ascend 910C"),
        (AccelVendor::Ascend, 0xd804..=0xd807) => Some("Ascend 910"),
        // Google Cloud TPUs
        (AccelVendor::Tpu, 0x0027) => Some("Google Cloud TPU v2/v3"),
        (AccelVendor::Tpu, 0x0056) => Some("Google Cloud TPU v3/v4i"),
        (AccelVendor::Tpu, 0x005e) => Some("Google Cloud TPU v4"),
        (AccelVendor::Tpu, 0x0062) => Some("Google Cloud TPU v5p"),
        (AccelVendor::Tpu, 0x0063) => Some("Google Cloud TPU v5e"),
        (AccelVendor::Tpu, 0x006f) => Some("Google Cloud TPU v6e"),
        // AMD Instinct & Radeon
        (AccelVendor::Amd, 0x738c) => Some("AMD Instinct MI100"),
        (AccelVendor::Amd, 0x7408 | 0x740c | 0x740f) => Some("AMD Instinct MI210/MI250"),
        (AccelVendor::Amd, 0x74a0 | 0x74a1 | 0x74a2 | 0x74a5) => Some("AMD Instinct MI300"),
        (AccelVendor::Amd, 0x744c) => Some("AMD Radeon RX 7900"),
        _ => None,
    };
    match known {
        Some(name) => name.to_string(),
        None => format!("{} ({vendor_id:04x}:{device_id:04x})", vendor.display_name()),
    }
}

/// Result of synthesizing fallback inventory/samples for PCIe accelerators whose
/// full vendor telemetry backend could not initialize.
#[derive(Debug, Clone, Default)]
pub struct FallbackSynthesis {
    pub status: Option<GpuHostStatus>,
    pub status_detail: Option<String>,
    pub inventory_items: Vec<GpuInventoryItem>,
    pub samples: Vec<GpuSample>,
    pub backend_tags: Vec<&'static str>,
}

/// Build honest inventory & diagnostic samples for any discovered PCIe
/// accelerators NOT already covered by a working backend (`active_bdfs`).
pub fn synthesize_unmanaged_fallbacks(
    pci_devs: &[PciAccelerator],
    active_bdfs: &HashSet<String>,
    denied_backends: &HashSet<String>,
    nvml_diag: Option<(GpuHostStatus, &str)>,
    ascend_diag: Option<&str>,
    start_idx: u16,
) -> FallbackSynthesis {
    let mut out = FallbackSynthesis::default();
    let mut details: Vec<String> = Vec::new();
    let mut saw_driver_missing = false;
    let mut saw_reboot_pending = false;
    let mut saw_limited = false;
    let mut next_idx = start_idx;

    for dev in pci_devs {
        let norm = normalize_pci_bdf(&dev.pci_bus);
        if active_bdfs.contains(&norm) {
            continue;
        }
        // Respect explicit backend denylist.
        let is_denied = match dev.vendor {
            AccelVendor::Nvidia => denied_backends.contains("nvidia"),
            AccelVendor::Ascend => {
                denied_backends.contains("ascend") || denied_backends.contains("npu")
            }
            AccelVendor::Tpu => denied_backends.contains("tpu"),
            AccelVendor::Amd => denied_backends.contains("amd"),
            AccelVendor::Intel => denied_backends.contains("intel"),
        };
        if is_denied {
            continue;
        }

        let uuid = format!("pci-{}-{norm}", dev.vendor.slug());
        let (card_status, reason) = match (dev.vendor, dev.driver.as_deref()) {
            (AccelVendor::Nvidia, None) => {
                saw_driver_missing = true;
                (
                    GpuHostStatus::DriverMissing,
                    format!(
                        "{} at {} has no bound kernel driver (install NVIDIA driver + libnvidia-ml)",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Nvidia, Some("nouveau")) => {
                saw_driver_missing = true;
                (
                    GpuHostStatus::DriverMissing,
                    format!(
                        "{} at {} is bound to nouveau instead of nvidia (install proprietary/open NVIDIA driver)",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Nvidia, Some("vfio-pci")) => {
                saw_limited = true;
                (
                    GpuHostStatus::Limited,
                    format!(
                        "{} at {} is bound to vfio-pci (passed through to VM)",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Nvidia, Some(drv)) => {
                if let Some((GpuHostStatus::DriverRebootPending, msg)) = nvml_diag {
                    saw_reboot_pending = true;
                    (
                        GpuHostStatus::DriverRebootPending,
                        format!("{} at {}: {msg}", dev.model_name, dev.pci_bus),
                    )
                } else {
                    saw_limited = true;
                    let extra = nvml_diag.map(|(_, m)| m).unwrap_or("NVML library unavailable");
                    (
                        GpuHostStatus::Limited,
                        format!(
                            "{} at {} (driver {drv} bound): {extra}",
                            dev.model_name, dev.pci_bus
                        ),
                    )
                }
            }
            (AccelVendor::Ascend, None) => {
                saw_driver_missing = true;
                (
                    GpuHostStatus::DriverMissing,
                    format!(
                        "{} at {} has no bound Ascend kernel driver (install Ascend NPU driver + CANN toolbox)",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Ascend, Some(drv)) => {
                saw_limited = true;
                let extra = ascend_diag.unwrap_or("npu-smi unavailable");
                (
                    GpuHostStatus::Limited,
                    format!(
                        "{} at {} (driver {drv} bound): {extra}",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Tpu, None) => {
                saw_driver_missing = true;
                (
                    GpuHostStatus::DriverMissing,
                    format!(
                        "{} at {} has no bound accel/vfio driver",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Tpu, Some(drv)) => {
                saw_limited = true;
                (
                    GpuHostStatus::Limited,
                    format!(
                        "{} at {} (driver {drv} bound): PCIe inventory only (utilization/HBM unavailable)",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Amd, None) => {
                saw_driver_missing = true;
                (
                    GpuHostStatus::DriverMissing,
                    format!(
                        "{} at {} has no bound amdgpu driver",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Amd, Some(drv)) => {
                saw_limited = true;
                (
                    GpuHostStatus::Limited,
                    format!(
                        "{} at {} (driver {drv} bound): DRM sysfs sensors unavailable",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Intel, None) => {
                saw_driver_missing = true;
                (
                    GpuHostStatus::DriverMissing,
                    format!(
                        "{} at {} has no bound xe/i915 driver",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
            (AccelVendor::Intel, Some(drv)) => {
                saw_limited = true;
                (
                    GpuHostStatus::Limited,
                    format!(
                        "{} at {} (driver {drv} bound): DRM sysfs sensors unavailable",
                        dev.model_name, dev.pci_bus
                    ),
                )
            }
        };

        let _ = card_status;
        if details.len() < 4 {
            details.push(reason);
        }
        let tag = match dev.vendor {
            AccelVendor::Nvidia => "pci-nvidia",
            AccelVendor::Ascend => "pci-ascend",
            AccelVendor::Tpu => "pci-tpu",
            AccelVendor::Amd => "pci-amd",
            AccelVendor::Intel => "pci-intel",
        };
        if !out.backend_tags.contains(&tag) {
            out.backend_tags.push(tag);
        }

        out.inventory_items.push(GpuInventoryItem {
            uuid: uuid.clone(),
            idx: next_idx,
            name: dev.model_name.clone(),
            mem_total_mb: None,
            power_limit_w: None,
            mig: false,
            pci_bus: Some(dev.pci_bus.clone()),
            unified: false,
        });
        out.samples.push(GpuSample {
            uuid,
            idx: next_idx,
            name: Some(dev.model_name.clone()),
            pci_bus: Some(dev.pci_bus.clone()),
            backend: Some("pci".into()),
            presence_only: true,
            procs_state: ProcsState::Unsupported,
            ..Default::default()
        });
        next_idx = next_idx.saturating_add(1);
    }

    if saw_reboot_pending {
        out.status = Some(GpuHostStatus::DriverRebootPending);
    } else if saw_driver_missing {
        out.status = Some(GpuHostStatus::DriverMissing);
    } else if saw_limited {
        out.status = Some(GpuHostStatus::Limited);
    }
    if !details.is_empty() {
        out.status_detail = Some(details.join("; "));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_pci_dev(root: &Path, bdf: &str, vendor: &str, device: &str, class: &str, driver: Option<&str>) {
        let dir = root.join(bdf);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("vendor"), format!("{vendor}\n")).unwrap();
        fs::write(dir.join("device"), format!("{device}\n")).unwrap();
        fs::write(dir.join("class"), format!("{class}\n")).unwrap();
        if let Some(d) = driver {
            fs::write(dir.join("uevent"), format!("DRIVER={d}\nPCI_SLOT_NAME={bdf}\n")).unwrap();
        }
    }

    #[test]
    fn fr139_pci_scan_detects_gpu_npu_tpu_and_skips_nics_and_audio() {
        let td = tempfile::tempdir().unwrap();
        // NVIDIA H100 without driver -> DriverMissing
        mk_pci_dev(td.path(), "0000:65:00.0", "0x10de", "0x2330", "0x030200", None);
        // NVIDIA HDMI audio function -> MUST be ignored
        mk_pci_dev(td.path(), "0000:65:00.1", "0x10de", "0x22bd", "0x040300", Some("snd_hda_intel"));
        // Huawei Ascend 910B with bound driver
        mk_pci_dev(td.path(), "0000:81:00.0", "0x19e5", "0xd802", "0x120000", Some("drv_pcie_host"));
        // Huawei Ethernet NIC -> MUST be ignored
        mk_pci_dev(td.path(), "0000:82:00.0", "0x19e5", "0x0222", "0x020000", Some("hinic"));
        // Google TPU v6e
        mk_pci_dev(td.path(), "0000:00:05.0", "0x1ae0", "0x006f", "0x120000", Some("vfio-pci"));
        // Google gVNIC -> MUST be ignored
        mk_pci_dev(td.path(), "0000:00:04.0", "0x1ae0", "0x0042", "0x020000", Some("gve"));

        let PciScanOutcome::Readable(devs) = scan_pci_dir(td.path()) else {
            panic!("expected readable scan");
        };
        assert_eq!(devs.len(), 3);
        assert_eq!(devs[0].vendor, AccelVendor::Tpu);
        assert_eq!(devs[0].model_name, "Google Cloud TPU v6e");
        assert_eq!(devs[1].vendor, AccelVendor::Nvidia);
        assert_eq!(devs[1].model_name, "NVIDIA H100");
        assert!(devs[1].driver.is_none());
        assert_eq!(devs[2].vendor, AccelVendor::Ascend);
        assert_eq!(devs[2].model_name, "Ascend 910B");

        let fb = synthesize_unmanaged_fallbacks(
            &devs,
            &HashSet::new(),
            &HashSet::new(),
            None,
            Some("npu-smi not installed"),
            0,
        );
        assert_eq!(fb.status, Some(GpuHostStatus::DriverMissing));
        assert_eq!(fb.samples.len(), 3);
        assert!(fb.status_detail.as_deref().unwrap().contains("NVIDIA H100"));
        assert!(fb.status_detail.as_deref().unwrap().contains("npu-smi not installed"));
    }

    #[test]
    fn fr139_normalize_pci_bdf_matches_nvml_and_sysfs() {
        assert_eq!(normalize_pci_bdf("00000000:C1:00.0"), "0000:c1:00.0");
        assert_eq!(normalize_pci_bdf("0000:c1:00.0"), "0000:c1:00.0");
    }
}
