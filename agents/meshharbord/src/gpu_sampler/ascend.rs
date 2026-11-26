// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Huawei Ascend NPU telemetry backend via `npu-smi` (FR-139).
//!
//! Runs EXCLUSIVELY inside the isolated `meshharbord gpu-sampler` child process
//! on Linux (x86_64 and aarch64). Uses fixed trusted absolute paths
//! (`/usr/local/sbin/npu-smi`, `/usr/bin/npu-smi` — never `$PATH`) and enforces
//! a hard per-invocation timeout so a wedged CANN driver never blocks the
//! sampler or daemon.

#[cfg(any(target_os = "linux", test))]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use meshharbor_remote_control::gpu::{GpuHostStatus, GpuInventory, GpuSample};
#[cfg(any(target_os = "linux", test))]
use meshharbor_remote_control::gpu::{GpuInventoryItem, GpuProc, ProcsState};

use super::proc_linux::ProcLookup;
#[cfg(any(target_os = "linux", test))]
use super::proc_linux::truncate_proc_name;

#[cfg(target_os = "linux")]
const NPU_SMI_CANDIDATES: &[&str] = &["/usr/local/sbin/npu-smi", "/usr/bin/npu-smi"];

#[cfg(target_os = "linux")]
const NPU_SMI_TIMEOUT: Duration = Duration::from_secs(4);

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
struct AscendBoardInfo {
    full_name: Option<String>,
    vdie_id: Option<String>,
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

pub struct AscendBackend {
    #[cfg(target_os = "linux")]
    smi_path: PathBuf,
    #[cfg(target_os = "linux")]
    driver_version: Option<String>,
    #[cfg(target_os = "linux")]
    boards: HashMap<(u16, u16), AscendBoardInfo>,
    #[cfg(target_os = "linux")]
    initial_cards: Vec<ParsedNpuCard>,
}

impl AscendBackend {
    pub fn try_init() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            if !Path::new("/dev/davinci_manager").exists() && !Path::new("/dev/davinci0").exists() {
                return None;
            }
            let smi_path = NPU_SMI_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())?;
            let out = run_with_timeout(&smi_path, &["info"], NPU_SMI_TIMEOUT)?;
            let parsed = parse_npu_smi_info(&out);
            if parsed.cards.is_empty() {
                return None;
            }
            let mut boards = HashMap::new();
            for c in &parsed.cards {
                let npu_s = c.npu_id.to_string();
                let chip_s = c.chip_id.to_string();
                if let Some(board_out) = run_with_timeout(
                    &smi_path,
                    &["info", "-t", "board", "-i", &npu_s, "-c", &chip_s],
                    NPU_SMI_TIMEOUT,
                ) {
                    boards.insert((c.npu_id, c.chip_id), parse_board_info(&board_out));
                }
            }
            Some(Self {
                smi_path,
                driver_version: parsed.driver_version,
                boards,
                initial_cards: parsed.cards,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    pub fn driver_version(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            self.driver_version.clone()
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
                .initial_cards
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let board = self.boards.get(&(c.npu_id, c.chip_id));
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
                driver_version: self.driver_version.clone(),
                gpus,
                status: GpuHostStatus::Ok,
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
            let Some(out) = run_with_timeout(&self.smi_path, &["info"], NPU_SMI_TIMEOUT) else {
                return (GpuHostStatus::Unavailable, Vec::new());
            };
            let parsed = parse_npu_smi_info(&out);
            if parsed.cards.is_empty() {
                return (GpuHostStatus::Unavailable, Vec::new());
            }
            let samples = build_samples(&parsed, &self.boards, include_procs, proc_lookup);
            (GpuHostStatus::Ok, samples)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (include_procs, proc_lookup);
            (GpuHostStatus::NoGpu, Vec::new())
        }
    }
}

#[cfg(target_os = "linux")]
fn run_with_timeout(path: &Path, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Drain stdout on a short-lived reader thread so large outputs never block
    // the child on a full OS pipe buffer while we wait with a timeout.
    let stdout = child.stdout.take()?;
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
                let bytes = reader.join().ok()?;
                if !status.success() {
                    return None;
                }
                return Some(String::from_utf8_lossy(&bytes).into_owned());
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return None;
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
fn build_ascend_uuid(c: &ParsedNpuCard, board: Option<&AscendBoardInfo>) -> String {
    if let Some(vdie) = board.and_then(|b| b.vdie_id.as_deref()) {
        let compact: String = vdie
            .chars()
            .filter(|ch| ch.is_ascii_hexdigit())
            .take(16)
            .collect();
        if compact.len() >= 8 {
            return format!("ASCEND-{}-{}-{compact}", c.npu_id, c.chip_id);
        }
    }
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

    parsed
        .cards
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let board = boards.get(&(c.npu_id, c.chip_id));
            let healthy = c.health.eq_ignore_ascii_case("ok") || c.health.is_empty();
            // Ascend 910B HBM reserves ~3.4 GiB system firmware baseline on a
            // 64 GiB card even when zero user processes are running. Set a
            // bounded idle floor (capped server-side to <= 12.5% of total mem)
            // so completely idle Ascend cards classify cleanly as Free while
            // genuine unattributed workloads still classify as Unattributed.
            let free_mem_floor_mb = if c.is_hbm {
                c.mem_total_mb.map(|tot| (tot / 12).clamp(2048, 6144))
            } else {
                None
            };

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
                mig: false,
                lost: !healthy,
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
    let mut vdie_id: Option<String> = None;
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
            "VDie ID" => vdie_id = Some(val.to_string()),
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

    AscendBoardInfo {
        full_name,
        vdie_id,
        pci_bus,
    }
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
        if !line.starts_with('|') || !line.ends_with('|') {
            continue;
        }
        let inner = &line[1..line.len() - 1];

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
            // Line 2: `| <chip_id> | <bus_id> | <aicore%> <mem_used>/<mem_total> <hbm_used>/<hbm_total> |`
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
            // Line 1: `| <npu_id> <name...> | <health> | <power_w> <temp_c> <hugepages> |`
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
            let temp_c = c2
                .next()
                .and_then(|s| s.parse::<i16>().ok());
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
    // Normalize `/` with surrounding spaces so tokens split cleanly into
    // `[aicore, mem_used, "/", mem_total, hbm_used, "/", hbm_total]`.
    let normalized = col.replace('/', " / ");
    let toks: Vec<&str> = normalized.split_whitespace().collect();
    let aicore_pct = toks
        .first()
        .and_then(|s| s.parse::<u16>().ok())
        .map(|u| u.min(100) as u8);

    // Collect every `<u32> / <u32>` pair in order: pair 0 = Memory-Usage(MB),
    // pair 1 = HBM-Usage(MB) (present on 910A/910B/910C).
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

    // Prefer HBM when total > 0; otherwise fall back to Memory-Usage (310P/310B).
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
    use meshharbor_remote_control::gpu::{GpuState, GpuStateThresholds, classify_gpu_state};

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
| 1     910B4-1             | OK            | 92.1        35                0    / 0             |
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
    fn fr139_ascend_910b_parser_and_free_classification() {
        let parsed = parse_npu_smi_info(SAMPLE_910B);
        assert_eq!(parsed.driver_version.as_deref(), Some("25.3.rc1"));
        assert_eq!(parsed.cards.len(), 2);
        assert!(parsed.has_proc_section);
        assert_eq!(parsed.procs.len(), 1);

        let mut boards = HashMap::new();
        boards.insert((0, 0), parse_board_info(SAMPLE_BOARD));
        let samples = build_samples(&parsed, &boards, true, &ProcLookup::default());
        assert_eq!(samples.len(), 2);

        // Card 0: busy with VLLMEngineCor
        let c0 = &samples[0];
        assert_eq!(c0.uuid, "ASCEND-0-0-D25BF66C00C024B1");
        assert_eq!(c0.name.as_deref(), Some("Ascend 910B4-1"));
        assert_eq!(c0.util_pct, Some(62));
        assert_eq!(c0.mem_used_mb, Some(59306));
        assert_eq!(c0.mem_total_mb, Some(65536));
        assert_eq!(c0.power_w, Some(199));
        assert_eq!(c0.temp_c, Some(51));
        assert_eq!(c0.procs_state, ProcsState::Ok);
        assert_eq!(c0.procs.as_ref().unwrap().len(), 1);
        assert_eq!(c0.procs.as_ref().unwrap()[0].pid, 2755453);
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Ok, c0, 1000, GpuStateThresholds::default()),
            GpuState::Busy
        );

        // Card 1: idle 910B4-1 with 3445 MiB HBM baseline, 0% AICore, 0 procs -> FREE!
        let c1 = &samples[1];
        assert_eq!(c1.uuid, "ASCEND-1-0-0000:81:00.0");
        assert_eq!(c1.name.as_deref(), Some("Ascend 910B4-1"));
        assert_eq!(c1.util_pct, Some(0));
        assert_eq!(c1.mem_used_mb, Some(3445));
        assert_eq!(c1.mem_total_mb, Some(65536));
        assert!(c1.procs.as_ref().unwrap().is_empty());
        assert_eq!(
            classify_gpu_state(GpuHostStatus::Ok, c1, 1000, GpuStateThresholds::default()),
            GpuState::Free
        );
    }

    #[test]
    fn fr139_ascend_310p_memory_usage_fallback() {
        let (u, used, tot, is_hbm) = parse_card_line2_metrics("18  2400 / 24576  0 / 0");
        assert_eq!((u, used, tot, is_hbm), (Some(18), Some(2400), Some(24576), false));
    }
}
