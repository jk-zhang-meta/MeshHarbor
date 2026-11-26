// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Huawei Ascend NPU telemetry backend via `npu-smi` with zero-package
//! `/dev/davinci*` + `/proc/<pid>/fd` fallback (FR-139).
//!
//! Runs EXCLUSIVELY inside the isolated `meshharbord gpu-sampler` child process
//! on Linux (x86_64 and aarch64):
//! - **Tool mode** (`npu-smi` installed): emits initial inventory immediately
//!   from a single `npu-smi info` call (never blocks startup on serial
//!   `info -t board` loops), lazily enriches board details (at most 2 cards
//!   per sample tick), preserves raw `vendor_health` without falsely setting
//!   `lost = true` on `Warning`, and marks `lost = true` ONLY when a previously
//!   present chip disappears from `npu-smi info`.
//! - **Device mode** (zero-package fallback when `/dev/davinci[0-9]+` exists
//!   without `npu-smi`): discovers every numbered `/dev/davinciN` device node,
//!   pairs with Huawei `0x19e5` PCIe BDFs when counts match, attributes
//!   occupying processes via `/proc/<pid>/fd/*`, leaves unavailable HBM/AICore
//!   metrics as `None`, and reports `Limited` with an actionable diagnostic.

#[cfg(any(target_os = "linux", test))]
use std::collections::{HashMap, HashSet};
#[cfg(any(target_os = "linux", test))]
use std::fs;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use meshharbor_remote_control::gpu::{GpuHostStatus, GpuInventory, GpuSample};
#[cfg(any(target_os = "linux", test))]
use meshharbor_remote_control::gpu::{GpuInventoryItem, GpuProc, ProcsState};

use super::pci_fallback::{AccelVendor, PciAccelerator};
use super::proc_linux::ProcLookup;
#[cfg(any(target_os = "linux", test))]
use super::proc_linux::truncate_proc_name;

#[cfg(target_os = "linux")]
const NPU_SMI_CANDIDATES: &[&str] = &[
    "/usr/local/sbin/npu-smi",
    "/usr/bin/npu-smi",
    "/usr/local/Ascend/driver/tools/npu-smi",
];

#[cfg(target_os = "linux")]
const NPU_SMI_TIMEOUT: Duration = Duration::from_secs(4);

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
struct AscendBoardInfo {
    full_name: Option<String>,
    pci_bus: Option<String>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
struct ParsedNpuCard {
    npu_id: u16,
    chip_id: u16,
    name: String,
    health: String,
    power_w: Option<u16>,
    temp_c: Option<i16>,
    pci_bus: Option<String>,
    aicore_pct: Option<u8>,
    mem_used_mb: Option<u32>,
    mem_total_mb: Option<u32>,
    is_hbm: bool,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
struct ParsedNpuProc {
    npu_id: u16,
    chip_id: u16,
    pid: u32,
    name: String,
    mem_mb: Option<u32>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
struct ParsedNpuInfo {
    driver_version: Option<String>,
    cards: Vec<ParsedNpuCard>,
    procs: Vec<ParsedNpuProc>,
    has_proc_section: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct DavinciDevCard {
    npu_id: u16,
    dev_node: String,
    name: String,
    pci_bus: Option<String>,
}

#[cfg(target_os = "linux")]
enum AscendMode {
    Dcmi(super::ascend_dcmi::DcmiSession),
    Tool {
        smi_path: PathBuf,
        driver_version: Option<String>,
        boards: HashMap<(u16, u16), AscendBoardInfo>,
        initial_cards: Vec<ParsedNpuCard>,
        board_probe_done: HashSet<(u16, u16)>,
        last_error: Option<String>,
    },
    DeviceOnly {
        cards: Vec<DavinciDevCard>,
        reason: String,
    },
}

pub struct AscendBackend {
    #[cfg(target_os = "linux")]
    mode: AscendMode,
}

impl AscendBackend {
    /// Initialize Ascend backend from `libdcmi.so` (fast parallel C API, ~80 ms
    /// for 8 cards), falling back to `npu-smi`, then `/dev/davinci*` + PCIe.
    pub fn try_init_with_pci(pci_devs: &[PciAccelerator]) -> (Option<Self>, Option<String>) {
        #[cfg(target_os = "linux")]
        {
            let davinci_nodes = discover_davinci_nodes(Path::new("/dev"));
            let pci_ascend: Vec<&PciAccelerator> = pci_devs
                .iter()
                .filter(|d| d.vendor == AccelVendor::Ascend)
                .collect();
            let has_manager = Path::new("/dev/davinci_manager").exists();

            if davinci_nodes.is_empty() && !has_manager {
                return (None, None);
            }

            if let Ok(dcmi) = super::ascend_dcmi::DcmiSession::try_init() {
                return (Some(Self { mode: AscendMode::Dcmi(dcmi) }), None);
            }

            let smi_path = NPU_SMI_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_file());

            if let Some(path) = smi_path {
                match run_with_timeout(&path, &["info"], NPU_SMI_TIMEOUT) {
                    Ok(out) => {
                        let parsed = parse_npu_smi_info(&out);
                        if !parsed.cards.is_empty() {
                            // Emit inventory immediately WITHOUT blocking startup on
                            // serial per-card `info -t board` calls; board metadata is
                            // enriched lazily in `sample()`.
                            return (
                                Some(Self {
                                    mode: AscendMode::Tool {
                                        smi_path: path,
                                        driver_version: parsed.driver_version,
                                        boards: HashMap::new(),
                                        initial_cards: parsed.cards,
                                        board_probe_done: HashSet::new(),
                                        last_error: None,
                                    },
                                }),
                                None,
                            );
                        }
                        let diag = "npu-smi returned no NPU rows".to_string();
                        if !davinci_nodes.is_empty() {
                            return (
                                Some(Self::device_only(&davinci_nodes, &pci_ascend, diag.clone())),
                                Some(diag),
                            );
                        }
                        return (None, Some(diag));
                    }
                    Err(err_reason) => {
                        let diag = format!("npu-smi failed ({err_reason})");
                        if !davinci_nodes.is_empty() {
                            return (
                                Some(Self::device_only(&davinci_nodes, &pci_ascend, diag.clone())),
                                Some(diag),
                            );
                        }
                        return (None, Some(diag));
                    }
                }
            }

            let diag = "Ascend /dev/davinci* present without npu-smi — process lock active; install CANN npu-smi for HBM/AICore/temp metrics".to_string();
            if !davinci_nodes.is_empty() {
                return (
                    Some(Self::device_only(&davinci_nodes, &pci_ascend, diag.clone())),
                    Some(diag),
                );
            }
            (None, Some("npu-smi not installed".into()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pci_devs;
            (None, None)
        }
    }

    #[cfg(target_os = "linux")]
    fn device_only(
        davinci_nodes: &[(u16, String)],
        pci_ascend: &[&PciAccelerator],
        reason: String,
    ) -> Self {
        let pair_pci = pci_ascend.len() == davinci_nodes.len();
        let cards = davinci_nodes
            .iter()
            .enumerate()
            .map(|(i, (npu_id, dev_node))| {
                let pci = pair_pci.then(|| pci_ascend[i]);
                DavinciDevCard {
                    npu_id: *npu_id,
                    dev_node: dev_node.clone(),
                    name: pci
                        .map(|p| p.model_name.clone())
                        .unwrap_or_else(|| format!("Ascend NPU #{npu_id}")),
                    pci_bus: pci.map(|p| p.pci_bus.clone()),
                }
            })
            .collect();
        Self {
            mode: AscendMode::DeviceOnly { cards, reason },
        }
    }

    pub fn driver_version(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        match &self.mode {
            AscendMode::Dcmi(dcmi) => dcmi.driver_version(),
            AscendMode::Tool { driver_version, .. } => driver_version.clone(),
            AscendMode::DeviceOnly { .. } => None,
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    pub fn status_detail(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        match &self.mode {
            AscendMode::Dcmi(_) => None,
            AscendMode::Tool { last_error, .. } => last_error.clone(),
            AscendMode::DeviceOnly { reason, .. } => Some(reason.clone()),
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    pub fn pci_bdfs(&self) -> Vec<String> {
        #[cfg(target_os = "linux")]
        match &self.mode {
            AscendMode::Dcmi(dcmi) => dcmi.pci_bdfs(),
            AscendMode::Tool {
                initial_cards,
                boards,
                ..
            } => initial_cards
                .iter()
                .filter_map(|c| {
                    boards
                        .get(&(c.npu_id, c.chip_id))
                        .and_then(|b| b.pci_bus.clone())
                        .or_else(|| c.pci_bus.clone())
                })
                .collect(),
            AscendMode::DeviceOnly { cards, .. } => {
                cards.iter().filter_map(|c| c.pci_bus.clone()).collect()
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }

    pub fn inventory(&self) -> GpuInventory {
        #[cfg(target_os = "linux")]
        match &self.mode {
            AscendMode::Dcmi(dcmi) => dcmi.inventory(),
            AscendMode::Tool {
                driver_version,
                boards,
                initial_cards,
                last_error,
                ..
            } => {
                let gpus = initial_cards
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        let board = boards.get(&(c.npu_id, c.chip_id));
                        GpuInventoryItem {
                            uuid: build_ascend_uuid(c, board),
                            idx: i as u16,
                            name: resolve_card_name(c, board),
                            mem_total_mb: c.mem_total_mb,
                            power_limit_w: None,
                            mig: false,
                            pci_bus: board
                                .and_then(|b| b.pci_bus.clone())
                                .or_else(|| c.pci_bus.clone()),
                            unified: false,
                        }
                    })
                    .collect();
                GpuInventory {
                    backend: Some("ascend".into()),
                    driver_version: driver_version.clone(),
                    gpus,
                    status: GpuHostStatus::Ok,
                    status_detail: last_error.clone(),
                }
            }
            AscendMode::DeviceOnly { cards, reason } => {
                let gpus = cards
                    .iter()
                    .enumerate()
                    .map(|(i, c)| GpuInventoryItem {
                        uuid: match c.pci_bus.as_deref() {
                            Some(b) => format!("ASCEND-{}-0-{}", c.npu_id, b),
                            None => format!("ASCEND-{}-0", c.npu_id),
                        },
                        idx: i as u16,
                        name: c.name.clone(),
                        mem_total_mb: None,
                        power_limit_w: None,
                        mig: false,
                        pci_bus: c.pci_bus.clone(),
                        unified: false,
                    })
                    .collect();
                GpuInventory {
                    backend: Some("ascend".into()),
                    driver_version: None,
                    gpus,
                    status: GpuHostStatus::Limited,
                    status_detail: Some(reason.clone()),
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            GpuInventory::default()
        }
    }

    pub fn sample(
        &mut self,
        include_procs: bool,
        proc_lookup: &ProcLookup,
    ) -> (GpuHostStatus, Vec<GpuSample>) {
        #[cfg(target_os = "linux")]
        match &mut self.mode {
            AscendMode::Dcmi(dcmi) => dcmi.sample(include_procs, proc_lookup),
            AscendMode::Tool {
                smi_path,
                boards,
                initial_cards,
                board_probe_done,
                last_error,
                ..
            } => {
                // Lazily enrich at most 2 unprobed cards per tick within a 2 s
                // budget so initial boot & live ticks never exceed supervisor deadlines.
                let enrich_deadline = Instant::now() + Duration::from_secs(2);
                let mut probed_this_tick = 0usize;
                for c in initial_cards.iter() {
                    if probed_this_tick >= 2 || Instant::now() >= enrich_deadline {
                        break;
                    }
                    let key = (c.npu_id, c.chip_id);
                    if board_probe_done.contains(&key) {
                        continue;
                    }
                    board_probe_done.insert(key);
                    probed_this_tick += 1;
                    let npu_s = c.npu_id.to_string();
                    let chip_s = c.chip_id.to_string();
                    let rem = enrich_deadline.saturating_duration_since(Instant::now());
                    if let Ok(board_out) = run_with_timeout(
                        smi_path,
                        &["info", "-t", "board", "-i", &npu_s, "-c", &chip_s],
                        rem.min(Duration::from_secs(2)),
                    ) {
                        boards.insert(key, parse_board_info(&board_out));
                    }
                }

                let out = match run_with_timeout(smi_path, &["info"], NPU_SMI_TIMEOUT) {
                    Ok(o) => o,
                    Err(reason) => {
                        *last_error = Some(format!("npu-smi info failed: {reason}"));
                        // Preserve known cards as metric-less samples rather than
                        // dropping all cards on transient timeout.
                        let fallback = initial_cards
                            .iter()
                            .enumerate()
                            .map(|(i, c)| {
                                let board = boards.get(&(c.npu_id, c.chip_id));
                                GpuSample {
                                    uuid: build_ascend_uuid(c, board),
                                    idx: i as u16,
                                    name: Some(resolve_card_name(c, board)),
                                    mem_total_mb: c.mem_total_mb,
                                    pci_bus: board
                                        .and_then(|b| b.pci_bus.clone())
                                        .or_else(|| c.pci_bus.clone()),
                                    backend: Some("ascend".into()),
                                    vendor_index: Some(c.npu_id),
                                    procs_state: ProcsState::Unknown,
                                    ..Default::default()
                                }
                            })
                            .collect();
                        return (GpuHostStatus::Unavailable, fallback);
                    }
                };
                let parsed = parse_npu_smi_info(&out);
                if parsed.cards.is_empty() {
                    *last_error = Some("npu-smi info returned zero NPU cards".into());
                    return (GpuHostStatus::Unavailable, Vec::new());
                }
                *last_error = None;
                let mut samples = build_samples(&parsed, boards, include_procs, proc_lookup);

                // If a card that was present at init disappeared from `npu-smi info`,
                // surface it with `lost = true` using its stable identity.
                let seen_keys: HashSet<(u16, u16)> =
                    parsed.cards.iter().map(|c| (c.npu_id, c.chip_id)).collect();
                for init_c in initial_cards.iter() {
                    let key = (init_c.npu_id, init_c.chip_id);
                    if !seen_keys.contains(&key) {
                        let board = boards.get(&key);
                        samples.push(GpuSample {
                            uuid: build_ascend_uuid(init_c, board),
                            idx: samples.len() as u16,
                            name: Some(resolve_card_name(init_c, board)),
                            mem_total_mb: init_c.mem_total_mb,
                            pci_bus: board
                                .and_then(|b| b.pci_bus.clone())
                                .or_else(|| init_c.pci_bus.clone()),
                            backend: Some("ascend".into()),
                            vendor_index: Some(init_c.npu_id),
                            lost: true,
                            procs_state: ProcsState::Unknown,
                            ..Default::default()
                        });
                    }
                }
                (GpuHostStatus::Ok, samples)
            }
            AscendMode::DeviceOnly { cards, .. } => {
                let wanted: HashSet<String> = cards.iter().map(|c| c.dev_node.clone()).collect();
                let (by_node, partial) = if include_procs {
                    super::tpu::scan_open_device_nodes(&wanted, proc_lookup)
                } else {
                    (HashMap::new(), false)
                };
                let samples = cards
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        let (procs_state, procs) = if !include_procs {
                            (ProcsState::Off, None)
                        } else {
                            let mut list = by_node.get(&c.dev_node).cloned().unwrap_or_default();
                            list.sort_by_key(|p| p.pid);
                            let st = if partial {
                                ProcsState::Partial
                            } else {
                                ProcsState::Ok
                            };
                            (st, Some(list))
                        };
                        GpuSample {
                            uuid: match c.pci_bus.as_deref() {
                                Some(b) => format!("ASCEND-{}-0-{}", c.npu_id, b),
                                None => format!("ASCEND-{}-0", c.npu_id),
                            },
                            idx: i as u16,
                            name: Some(c.name.clone()),
                            pci_bus: c.pci_bus.clone(),
                            backend: Some("ascend".into()),
                            vendor_index: Some(c.npu_id),
                            presence_only: true,
                            procs_state,
                            procs,
                            ..Default::default()
                        }
                    })
                    .collect();
                (GpuHostStatus::Limited, samples)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (include_procs, proc_lookup);
            (GpuHostStatus::NoGpu, Vec::new())
        }
    }
}

/// Discover all numbered `/dev/davinci[0-9]+` nodes (e.g. `/dev/davinci3` in a
/// single-card container), excluding `/dev/davinci_manager` and `/dev/davinci_svm*`.
#[cfg(any(target_os = "linux", test))]
fn discover_davinci_nodes(dev_root: &Path) -> Vec<(u16, String)> {
    let Ok(entries) = fs::read_dir(dev_root) else {
        return Vec::new();
    };
    let mut found: Vec<(u16, String)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            let rest = name.strip_prefix("davinci")?;
            if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let id = rest.parse::<u16>().ok()?;
            Some((id, dev_root.join(&name).to_string_lossy().into_owned()))
        })
        .collect();
    found.sort_by_key(|(id, _)| *id);
    found
}

#[cfg(target_os = "linux")]
fn run_with_timeout(path: &Path, args: &[&str], timeout: Duration) -> Result<String, String> {
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn error: {e}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "stdout unavailable".to_string())?;
    let reader = std::thread::spawn(move || {
        use std::io::Read as _;
        let mut buf = Vec::with_capacity(8192);
        let mut limited = stdout.take(512 * 1024);
        let _ = limited.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let bytes = reader
                    .join()
                    .map_err(|_| "stdout reader panicked".to_string())?;
                if !status.success() {
                    return Err(format!("exit status {status}"));
                }
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err("timeout".to_string());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(format!("wait error: {e}"));
            }
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn resolve_card_name(c: &ParsedNpuCard, board: Option<&AscendBoardInfo>) -> String {
    if let Some(full) = board.and_then(|b| b.full_name.as_deref())
        && !full.is_empty()
    {
        return full.to_string();
    }
    let trimmed = c.name.trim();
    if trimmed.to_ascii_lowercase().starts_with("ascend") {
        trimmed.to_string()
    } else if trimmed.is_empty() {
        "Ascend NPU".to_string()
    } else {
        format!("Ascend {trimmed}")
    }
}

#[cfg(any(target_os = "linux", test))]
fn build_ascend_uuid(c: &ParsedNpuCard, _board: Option<&AscendBoardInfo>) -> String {
    // Freeze a stable card identity strictly from `npu-smi info` discovery fields
    // (npu_id, chip_id, pci_bus) so lazy `info -t board` enrichment never mutates
    // an already-published card UUID mid-flight (which would split history/alerts).
    if let Some(bus) = c.pci_bus.as_deref().filter(|s| !s.is_empty()) {
        let clean: String = bus
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '.' | '-' | '_'))
            .collect();
        if !clean.is_empty() {
            return format!("ASCEND-{}-{}-{clean}", c.npu_id, c.chip_id);
        }
    }
    format!("ASCEND-{}-{}", c.npu_id, c.chip_id)
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn ascend_free_mem_floor_mb(is_hbm: bool, mem_total_mb: Option<u32>) -> Option<u32> {
    if is_hbm {
        mem_total_mb.map(|tot| (tot / 12).clamp(2048, 6144))
    } else {
        None
    }
}

#[cfg(any(target_os = "linux", test))]
fn build_samples(
    parsed: &ParsedNpuInfo,
    boards: &HashMap<(u16, u16), AscendBoardInfo>,
    include_procs: bool,
    proc_lookup: &ProcLookup,
) -> Vec<GpuSample> {
    let mut procs_by_card: HashMap<(u16, u16), Vec<&ParsedNpuProc>> = HashMap::new();
    for p in &parsed.procs {
        procs_by_card.entry((p.npu_id, p.chip_id)).or_default().push(p);
    }

    let has_multi_chip = parsed.cards.iter().any(|c| c.chip_id > 0);
    parsed
        .cards
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let board = boards.get(&(c.npu_id, c.chip_id));
            // On multi-chip Ascend cards (e.g. 910A/310P dual-die), `ASCEND_RT_VISIBLE_DEVICES`
            // addresses logical chip ordinals, NOT duplicate physical `npu_id`s.
            let logical_vendor_idx = if has_multi_chip { i as u16 } else { c.npu_id };
            // Preserve raw vendor health (`OK`, `Warning`, `Alarm`, `Critical`)
            // WITHOUT setting `lost = true` on a responding chip!
            let vendor_health = (!c.health.trim().is_empty()).then(|| c.health.trim().to_string());
            let free_mem_floor_mb = ascend_free_mem_floor_mb(c.is_hbm, c.mem_total_mb);

            let (procs_state, procs) = if !include_procs {
                (ProcsState::Off, None)
            } else if !parsed.has_proc_section {
                (ProcsState::Unknown, None)
            } else {
                let mut partial = false;
                let mut out = Vec::new();
                if let Some(list) = procs_by_card.get(&(c.npu_id, c.chip_id)) {
                    for p in list {
                        let attr = proc_lookup.lookup(p.pid);
                        if attr.access_denied {
                            partial = true;
                        }
                        let name = attr
                            .name
                            .filter(|n| !n.is_empty())
                            .unwrap_or_else(|| p.name.clone());
                        out.push(GpuProc {
                            pid: p.pid,
                            user: attr.user,
                            name: Some(truncate_proc_name(&name)),
                            mem_mb: p.mem_mb,
                            sm_pct: None,
                            cpu_pct: None,
                            started_at: attr.started_at,
                            container: attr.container,
                            kind: Some("compute".into()),
                        });
                    }
                }
                let st = if partial {
                    ProcsState::Partial
                } else {
                    ProcsState::Ok
                };
                (st, Some(out))
            };

            GpuSample {
                uuid: build_ascend_uuid(c, board),
                idx: i as u16,
                name: Some(resolve_card_name(c, board)),
                mem_total_mb: c.mem_total_mb,
                power_limit_w: None,
                pci_bus: board
                    .and_then(|b| b.pci_bus.clone())
                    .or_else(|| c.pci_bus.clone()),
                unified: false,
                util_pct: c.aicore_pct,
                mem_used_mb: c.mem_used_mb,
                temp_c: c.temp_c,
                power_w: c.power_w,
                fan_pct: None,
                sm_clock_mhz: None,
                throttle: None,
                ecc_uncorrected: None,
                remapped_rows: None,
                xid_errors: None,
                xid_last_at: None,
                remap_pending: false,
                remap_failure: false,
                mig: false,
                lost: false,
                vendor_health,
                backend: Some("ascend".into()),
                backend_status: None,
                vendor_index: Some(logical_vendor_idx),
                presence_only: false,
                idle_since: None,
                free_mem_floor_mb,
                procs_state,
                procs,
            }
        })
        .collect()
}

/// Parse `npu-smi info -t board -i <N> -c <C>` key-value lines.
#[cfg(any(target_os = "linux", test))]
fn parse_board_info(text: &str) -> AscendBoardInfo {
    let mut chip_type: Option<String> = None;
    let mut chip_name: Option<String> = None;
    let mut pci_bus: Option<String> = None;

    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        if val.is_empty() || val.eq_ignore_ascii_case("na") || val.eq_ignore_ascii_case("n/a") {
            continue;
        }
        match key {
            "Chip Type" => chip_type = Some(val.to_string()),
            "Chip Name" => chip_name = Some(val.to_string()),
            "PCIe Bus Info" => pci_bus = Some(val.to_string()),
            _ => {}
        }
    }

    let full_name = match (chip_type, chip_name) {
        (Some(t), Some(n)) => {
            if n.to_ascii_lowercase().starts_with(&t.to_ascii_lowercase()) {
                Some(n)
            } else {
                Some(format!("{t} {n}"))
            }
        }
        (None, Some(n)) => Some(format!("Ascend {n}")),
        (Some(t), None) => Some(t),
        (None, None) => None,
    };

    AscendBoardInfo { full_name, pci_bus }
}

/// Parse `npu-smi info` ASCII table output into driver version, cards, and processes.
#[cfg(any(target_os = "linux", test))]
fn parse_npu_smi_info(text: &str) -> ParsedNpuInfo {
    let mut driver_version: Option<String> = None;
    let mut cards: Vec<ParsedNpuCard> = Vec::new();
    let mut procs: Vec<ParsedNpuProc> = Vec::new();
    let mut in_procs = false;
    let mut has_proc_section = false;

    struct PendingNpuRow {
        npu_id: u16,
        name: String,
        health: String,
        power_w: Option<u16>,
        temp_c: Option<i16>,
    }
    let mut pending: Option<PendingNpuRow> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        let Some(inner) = line.strip_prefix('|').and_then(|s| s.strip_suffix('|')) else {
            continue;
        };

        if driver_version.is_none()
            && let Some(idx) = inner.find("Version:")
        {
            let rest = inner[idx + "Version:".len()..].trim();
            if let Some(tok) = rest.split_whitespace().next()
                && !tok.is_empty()
            {
                driver_version = Some(tok.to_string());
            }
            continue;
        }

        if inner.contains("Process id") && inner.contains("Process name") {
            in_procs = true;
            has_proc_section = true;
            pending = None;
            continue;
        }
        if inner.contains("No running processes found") {
            in_procs = true;
            has_proc_section = true;
            continue;
        }
        if inner.contains("NPU") && inner.contains("Health") && inner.contains("Power(W)") {
            continue;
        }
        if inner.contains("Chip") && inner.contains("Bus-Id") && inner.contains("AICore") {
            continue;
        }

        let cols: Vec<&str> = inner.split('|').map(str::trim).collect();
        if in_procs {
            if cols.len() >= 4 {
                let mut id_parts = cols[0].split_whitespace();
                let npu_id = id_parts.next().and_then(|s| s.parse::<u16>().ok());
                let chip_id = id_parts.next().and_then(|s| s.parse::<u16>().ok());
                let pid = cols[1].parse::<u32>().ok();
                let proc_name = cols[2].trim();
                let mem_mb = cols[3]
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u32>().ok());
                if let (Some(npu_id), Some(chip_id), Some(pid)) = (npu_id, chip_id, pid) {
                    procs.push(ParsedNpuProc {
                        npu_id,
                        chip_id,
                        pid,
                        name: proc_name.to_string(),
                        mem_mb,
                    });
                }
            }
            continue;
        }

        if cols.len() != 3 {
            continue;
        }

        if let Some(PendingNpuRow {
            npu_id,
            name,
            health,
            power_w,
            temp_c,
        }) = pending.take()
        {
            let chip_id = cols[0]
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            let pci_bus = (!cols[1].is_empty() && !cols[1].eq_ignore_ascii_case("na"))
                .then(|| cols[1].to_string());
            let (aicore_pct, mem_used_mb, mem_total_mb, is_hbm) = parse_card_line2_metrics(cols[2]);
            cards.push(ParsedNpuCard {
                npu_id,
                chip_id,
                name,
                health,
                power_w,
                temp_c,
                pci_bus,
                aicore_pct,
                mem_used_mb,
                mem_total_mb,
                is_hbm,
            });
        } else {
            let mut c0 = cols[0].split_whitespace();
            let Some(npu_id) = c0.next().and_then(|s| s.parse::<u16>().ok()) else {
                continue;
            };
            let name = c0.collect::<Vec<_>>().join(" ");
            let health = cols[1].to_string();
            let mut c2 = cols[2].split_whitespace();
            let power_w = c2
                .next()
                .and_then(|s| s.parse::<f32>().ok())
                .filter(|p| p.is_finite() && *p >= 0.0)
                .map(|p| p.round() as u16);
            let temp_c = c2.next().and_then(|s| s.parse::<i16>().ok());
            pending = Some(PendingNpuRow {
                npu_id,
                name,
                health,
                power_w,
                temp_c,
            });
        }
    }

    ParsedNpuInfo {
        driver_version,
        cards,
        procs,
        has_proc_section,
    }
}

/// Parse `<aicore%> <mem_used>/<mem_total> <hbm_used>/<hbm_total>` allowing
/// arbitrary whitespace around `/` (e.g. `62  0 / 0  59306/ 65536`).
#[cfg(any(target_os = "linux", test))]
fn parse_card_line2_metrics(col: &str) -> (Option<u8>, Option<u32>, Option<u32>, bool) {
    let normalized = col.replace('/', " / ");
    let toks: Vec<&str> = normalized.split_whitespace().collect();
    let aicore_pct = toks
        .first()
        .and_then(|s| s.parse::<u16>().ok())
        .map(|u| u.min(100) as u8);

    let mut pairs: Vec<(u32, u32)> = Vec::new();
    let mut i = 1;
    while i + 2 < toks.len() {
        if toks[i + 1] == "/" {
            if let (Ok(u), Ok(t)) = (toks[i].parse::<u32>(), toks[i + 2].parse::<u32>()) {
                pairs.push((u, t));
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    if let Some(&(used, total)) = pairs.get(1)
        && total > 0
    {
        return (aicore_pct, Some(used), Some(total), true);
    }
    if let Some(&(used, total)) = pairs.first()
        && total > 0
    {
        return (aicore_pct, Some(used), Some(total), false);
    }
    (aicore_pct, None, None, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::gpu::{
        GpuState, GpuStateThresholds, card_fault_reasons, classify_gpu_state,
    };

    const SAMPLE_910B: &str = r#"
+------------------------------------------------------------------------------------------------+
| npu-smi 25.3.rc1                 Version: 25.3.rc1                                             |
+---------------------------+---------------+----------------------------------------------------+
| NPU   Name                | Health        | Power(W)    Temp(C)           Hugepages-Usage(page)|
| Chip                      | Bus-Id        | AICore(%)   Memory-Usage(MB)  HBM-Usage(MB)        |
+===========================+===============+====================================================+
| 0     910B4-1             | OK            | 199.1       51                0    / 0             |
| 0                         | 0000:C1:00.0  | 62          0    / 0          59306/ 65536         |
+===========================+===============+====================================================+
| 1     910B4-1             | Warning       | 92.1        35                0    / 0             |
| 0                         | 0000:81:00.0  | 0           0    / 0          3445 / 65536         |
+===========================+===============+====================================================+
+---------------------------+---------------+----------------------------------------------------+
| NPU     Chip              | Process id    | Process name             | Process memory(MB)      |
+===========================+===============+====================================================+
| 0       0                 | 2755453       | VLLMEngineCor            | 55760                   |
+===========================+===============+====================================================+
| No running processes found in NPU 1                                                            |
+===========================+===============+====================================================+
"#;

    const SAMPLE_BOARD: &str = r#"
	NPU ID                         : 0
	Chip ID                        : 0
	Chip Type                      : Ascend
	Chip Name                      : 910B4-1
	VDie ID                        : D25BF66C 00C024B1 4F0DA293 82528485 104301E3
	PCIe Bus Info                  : 0000:C1:00.0
"#;

    #[test]
    fn fr139_ascend_910b_parser_warning_not_lost_and_free_classification() {
        let parsed = parse_npu_smi_info(SAMPLE_910B);
        assert_eq!(parsed.driver_version.as_deref(), Some("25.3.rc1"));
        assert_eq!(parsed.cards.len(), 2);
        assert!(parsed.has_proc_section);
        assert_eq!(parsed.procs.len(), 1);

        let before_probe = build_samples(&parsed, &HashMap::new(), true, &ProcLookup::default());
        let mut boards = HashMap::new();
        boards.insert((0, 0), parse_board_info(SAMPLE_BOARD));
        let samples = build_samples(&parsed, &boards, true, &ProcLookup::default());
        assert_eq!(samples.len(), 2);

        // Card 0: busy with VLLMEngineCor; UUID must stay invariant across lazy board probe!
        let c0 = &samples[0];
        assert_eq!(c0.uuid, "ASCEND-0-0-0000:C1:00.0");
        assert_eq!(c0.uuid, before_probe[0].uuid);
        assert_eq!(c0.name.as_deref(), Some("Ascend 910B4-1"));
        assert_eq!(c0.vendor_index, Some(0));
        assert_eq!(c0.vendor_health.as_deref(), Some("OK"));
        assert!(!c0.lost);
        assert!(card_fault_reasons(c0).is_empty());
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Ok, c0, 1000, GpuStateThresholds::default()),
            GpuState::Busy
        );

        // Card 1: responding chip with Health=Warning MUST NOT be marked lost=true!
        let c1 = &samples[1];
        assert_eq!(c1.uuid, "ASCEND-1-0-0000:81:00.0");
        assert_eq!(c1.vendor_index, Some(1));
        assert!(!c1.lost, "responding Ascend Warning must NOT set lost=true");
        assert_eq!(c1.vendor_health.as_deref(), Some("Warning"));
        let reasons = card_fault_reasons(c1);
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, "vendor_health");
        assert_eq!(reasons[0].severity, "warning");
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Ok, c1, 1000, GpuStateThresholds::default()),
            GpuState::Free
        );
    }

    #[test]
    fn fr139_discover_davinci_nodes_finds_sparse_numbered_devices() {
        let td = tempfile::tempdir().unwrap();
        fs::write(td.path().join("davinci_manager"), "").unwrap();
        fs::write(td.path().join("davinci_svm"), "").unwrap();
        fs::write(td.path().join("davinci3"), "").unwrap();
        fs::write(td.path().join("davinci7"), "").unwrap();
        let nodes = discover_davinci_nodes(td.path());
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].0, 3);
        assert_eq!(nodes[1].0, 7);
    }

    #[test]
    fn fr139_ascend_310p_memory_usage_fallback() {
        let (u, used, tot, is_hbm) = parse_card_line2_metrics("18  2400 / 24576  0 / 0");
        assert_eq!((u, used, tot, is_hbm), (Some(18), Some(2400), Some(24576), false));
    }
}
