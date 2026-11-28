// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Linux `/proc/<pid>` attribution for GPU processes (FR-139 §3, §8).
//!
//! Strictly L1 metadata:
//! - Reads ONLY `/proc/<pid>/status` (`Uid`, `Name`, `NSpid`), `/proc/<pid>/cgroup`,
//!   and `/proc/<pid>/stat` (process start ticks for duration).
//! - NEVER reads `/proc/<pid>/cmdline`, `/proc/<pid>/environ`, `/proc/<pid>/cwd`,
//!   or any Docker/containerd/kubelet socket.
//! - Executable basename is truncated to <= 32 characters (UTF-8 safe).
//! - Permission failures (`EACCES`/`EPERM`, e.g. `hidepid=2`) mark the call as
//!   `partial = true` so callers emit `ProcsState::Partial` instead of claiming
//!   full visibility.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::ErrorKind;

/// Truncate an executable basename to at most 32 Unicode scalar values.
pub fn truncate_proc_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw).trim();
    let mut out = String::new();
    for ch in base.chars().take(32) {
        out.push(ch);
    }
    out
}

/// Parse `/proc/<pid>/cgroup` text into a short container or systemd label
/// (`docker:<id>`, `k8s:<pod>`, `systemd:<unit>`). Pure helper so tests run on
/// every platform.
pub fn parse_cgroup_attribution(cgroup_text: &str) -> Option<String> {
    let mut systemd_fallback: Option<String> = None;

    for line in cgroup_text.lines() {
        let path = line.rsplit_once(':').map(|(_, p)| p).unwrap_or(line).trim();
        if path.is_empty() || path == "/" {
            continue;
        }
        // Kubernetes pod slice (cgroup v1 & v2):
        // .../kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<cid>.scope
        // .../kubepods/burstable/pod<uid>/<cid>
        if path.contains("kubepods") {
            for seg in path.split('/') {
                if let Some(rest) = seg.strip_prefix("pod") {
                    let uid = rest.trim_end_matches(".slice");
                    let short: String = uid
                        .chars()
                        .filter(|c| *c != '_' && *c != '-')
                        .take(12)
                        .collect();
                    if !short.is_empty() {
                        return Some(format!("k8s:{short}"));
                    }
                }
                if let Some(pos) = seg.find("-pod") {
                    let uid = &seg[pos + 4..];
                    let uid = uid.trim_end_matches(".slice");
                    let short: String = uid
                        .chars()
                        .filter(|c| *c != '_' && *c != '-')
                        .take(12)
                        .collect();
                    if !short.is_empty() {
                        return Some(format!("k8s:{short}"));
                    }
                }
            }
        }
        // Docker / containerd / podman scopes:
        for seg in path.split('/') {
            if let Some(id) = seg
                .strip_prefix("docker-")
                .or_else(|| seg.strip_prefix("cri-containerd-"))
                .or_else(|| seg.strip_prefix("libpod-"))
            {
                let id = id.trim_end_matches(".scope");
                let short: String = id.chars().take(12).collect();
                if short.len() >= 8 && short.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(format!("docker:{short}"));
                }
            }
        }
        if let Some(pos) = path.find("/docker/") {
            let id = path[pos + 8..].split('/').next().unwrap_or("");
            let short: String = id.chars().take(12).collect();
            if short.len() >= 8 && short.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(format!("docker:{short}"));
            }
        }
        // Systemd service/scope unit fallback (skip user@.service boilerplate if a deeper unit exists).
        if systemd_fallback.is_none()
            && let Some(unit) = path
                .rsplit('/')
                .find(|s| s.ends_with(".service") || s.ends_with(".scope"))
            && !unit.starts_with("user@")
            && !unit.starts_with("session-")
        {
            let short = unit.trim_end_matches(".service").trim_end_matches(".scope");
            let truncated: String = short.chars().take(32).collect();
            if !truncated.is_empty() {
                systemd_fallback = Some(format!("systemd:{truncated}"));
            }
        }
    }

    systemd_fallback
}

/// Parsed L1 process info from `/proc/<pid>`.
#[derive(Debug, Clone, Default)]
pub struct ProcAttribution {
    pub user: Option<String>,
    pub name: Option<String>,
    pub container: Option<String>,
    pub started_at: Option<i64>,
    pub access_denied: bool,
}

/// Lightweight per-cycle cache of UID -> username + boot time so sampling N
/// GPU processes doesn't re-parse `/etc/passwd` or `/proc/stat` N times.
pub struct ProcLookup {
    #[cfg(target_os = "linux")]
    uid_map: HashMap<u32, String>,
    #[cfg(target_os = "linux")]
    boot_time_s: Option<i64>,
    #[cfg(target_os = "linux")]
    clk_tck: i64,
}

impl ProcLookup {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            let mut uid_map = HashMap::new();
            let users = sysinfo::Users::new_with_refreshed_list();
            for u in users.list() {
                uid_map.insert(**u.id(), u.name().to_string());
            }
            let boot_time_s = read_boot_time_s();
            // SAFETY: `sysconf(_SC_CLK_TCK)` is a standard POSIX query.
            let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            let clk_tck = if tck > 0 { tck as i64 } else { 100 };
            Self {
                uid_map,
                boot_time_s,
                clk_tck,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self {}
        }
    }

    pub fn lookup(&self, pid: u32) -> ProcAttribution {
        #[cfg(target_os = "linux")]
        {
            self.lookup_linux(pid)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            ProcAttribution::default()
        }
    }

    #[cfg(target_os = "linux")]
    fn lookup_linux(&self, pid: u32) -> ProcAttribution {
        let mut attr = ProcAttribution::default();

        match fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(text) => {
                for line in text.lines() {
                    if let Some(rest) = line.strip_prefix("Name:") {
                        let name = truncate_proc_name(rest.trim());
                        if !name.is_empty() {
                            attr.name = Some(name);
                        }
                    } else if let Some(rest) = line.strip_prefix("Uid:")
                        && let Some(uid_str) = rest.split_whitespace().next()
                        && let Ok(uid) = uid_str.parse::<u32>()
                    {
                        attr.user = Some(
                            self.uid_map
                                .get(&uid)
                                .cloned()
                                .unwrap_or_else(|| uid.to_string()),
                        );
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                attr.access_denied = true;
                return attr;
            }
            Err(_) => return attr,
        }

        if let Ok(cg) = fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            attr.container = parse_cgroup_attribution(&cg);
        }

        if let (Some(boot), Ok(stat)) = (
            self.boot_time_s,
            fs::read_to_string(format!("/proc/{pid}/stat")),
        ) && let Some(rparen) = stat.rfind(')')
        {
            // Field 22 (1-indexed) is starttime in clock ticks since boot;
            // after `)` field 3 is index 0, so starttime is index 19.
            if let Some(ticks_str) = stat[rparen + 1..].split_whitespace().nth(19)
                && let Ok(ticks) = ticks_str.parse::<i64>()
            {
                attr.started_at = Some(boot + (ticks / self.clk_tck));
            }
        }

        attr
    }
}

impl Default for ProcLookup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
fn read_boot_time_s() -> Option<i64> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse::<i64>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr139_cgroup_attribution_parses_docker_k8s_and_systemd() {
        assert_eq!(
            parse_cgroup_attribution(
                "0::/system.slice/docker-0123456789abcdef0123456789abcdef.scope\n"
            ),
            Some("docker:0123456789ab".into())
        );
        assert_eq!(
            parse_cgroup_attribution("12:memory:/docker/abcdef1234567890abcdef\n"),
            Some("docker:abcdef123456".into())
        );
        assert_eq!(
            parse_cgroup_attribution(
                "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod9f8e7d6c_1234_5678_9abc.slice/cri-containerd-1111222233334444.scope\n"
            ),
            Some("k8s:9f8e7d6c1234".into())
        );
        assert_eq!(
            parse_cgroup_attribution("0::/system.slice/vllm-worker.service\n"),
            Some("systemd:vllm-worker".into())
        );
        assert_eq!(parse_cgroup_attribution("0::/\n"), None);
    }

    #[test]
    fn fr139_proc_name_truncates_basename_to_32_chars() {
        assert_eq!(truncate_proc_name("/usr/bin/python3"), "python3");
        assert_eq!(
            truncate_proc_name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(truncate_proc_name("a").len(), 1);
    }
}
