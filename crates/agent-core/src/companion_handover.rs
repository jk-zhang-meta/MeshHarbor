// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Desktop companion singleton version handover.
//!
//! Pure semver parsing/comparison, handover decision logic, and per-user
//! instance state persistence live here in `meshharbor-node-core` so every
//! platform's test suite exercises them directly, while `meshharbor-desktop`
//! stays a thin OS caller around single-instance takeover and shutdown.

use crate::companion_autostart::{InstallScope, is_per_user_companion_path, windows_scope_for_exe};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::{Path, PathBuf};

/// Internal argument prefix forwarded over `tauri-plugin-single-instance` when
/// requesting a graceful handover from an older running companion.
pub const HANDOVER_VERSION_ARG_PREFIX: &str = "--handover-version=";

/// Per-user instance state file written by the live companion once it owns the
/// OS single-instance lock.
pub const INSTANCE_FILE_NAME: &str = "companion-instance.json";

/// Per-user cooperative handover file naming a PID asked to exit gracefully
/// before a newer companion takes over the single-instance lock.
pub const HANDOVER_PID_FILE_NAME: &str = "companion-handover.pid";

/// Persisted metadata of the currently running companion instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionInstanceRecord {
    pub pid: u32,
    pub version: String,
    pub exe_path: String,
}

/// Pre-release identifier per SemVer 2.0.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreIdent {
    Numeric(u64),
    AlphaNum(String),
}

impl Ord for PreIdent {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PreIdent::Numeric(a), PreIdent::Numeric(b)) => a.cmp(b),
            // SemVer 2.0.0 §11.4.4: numeric identifiers always have lower
            // precedence than non-numeric identifiers.
            (PreIdent::Numeric(_), PreIdent::AlphaNum(_)) => Ordering::Less,
            (PreIdent::AlphaNum(_), PreIdent::Numeric(_)) => Ordering::Greater,
            (PreIdent::AlphaNum(a), PreIdent::AlphaNum(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for PreIdent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Parsed semantic version (`major.minor.patch[-pre]`, ignoring `+build`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Empty = final release (ranks higher than any pre-release).
    pub pre: Vec<PreIdent>,
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // Final release > pre-release.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Parse a semantic version (`[v]MAJOR.MINOR.PATCH[-PRE][+BUILD]`).
pub fn parse_semver(raw: &str) -> Option<SemVer> {
    let trimmed = raw.trim();
    let without_v = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    let without_build = without_v.split('+').next().unwrap_or("");
    if without_build.is_empty() {
        return None;
    }
    let (core, pre_raw) = match without_build.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (without_build, None),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let pre = match pre_raw {
        None => Vec::new(),
        Some(p) => {
            if p.is_empty() {
                return None;
            }
            let mut idents = Vec::new();
            for seg in p.split('.') {
                if seg.is_empty() || !seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return None;
                }
                if seg.chars().all(|c| c.is_ascii_digit()) {
                    idents.push(PreIdent::Numeric(seg.parse::<u64>().ok()?));
                } else {
                    idents.push(PreIdent::AlphaNum(seg.to_string()));
                }
            }
            idents
        }
    };
    Some(SemVer {
        major,
        minor,
        patch,
        pre,
    })
}

/// Compare two version strings by SemVer 2.0.0 precedence. Returns `None` if
/// either string is not a valid semver.
pub fn compare_semver(a: &str, b: &str) -> Option<Ordering> {
    Some(parse_semver(a)?.cmp(&parse_semver(b)?))
}

/// Outcome of deciding whether an incoming companion launch should replace an
/// existing running companion or yield to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverDecision {
    /// Incoming instance should replace the running companion.
    TakeOver,
    /// Incoming instance should yield to the existing companion (never kill it).
    YieldToExisting,
}

/// Decide whether an incoming companion (`my_version`, `my_exe`) should take
/// over from a running companion (`running_version`, `running_exe`).
///
/// Takes over when:
/// - `my_version > running_version`, OR
/// - `running_version` is equal or unknown AND `my_exe` is a per-machine
///   install (`InstallScope::Machine`, under Program Files) while `running_exe`
///   is a stale per-user install (`%LOCALAPPDATA%\Programs\MeshHarbor\...`).
///
/// Yields in every other case (never kills a newer or same-scope equal instance).
pub fn decide_handover(
    my_version: &str,
    my_exe: &Path,
    running_version: Option<&str>,
    running_exe: Option<&Path>,
    program_files: &[PathBuf],
) -> HandoverDecision {
    decide_handover_with_local_app_data(
        my_version,
        my_exe,
        running_version,
        running_exe,
        program_files,
        None,
    )
}

/// [`decide_handover`] with an explicit `%LOCALAPPDATA%` root (handles
/// redirected LocalAppData folders on Windows).
pub fn decide_handover_with_local_app_data(
    my_version: &str,
    my_exe: &Path,
    running_version: Option<&str>,
    running_exe: Option<&Path>,
    program_files: &[PathBuf],
    local_app_data: Option<&Path>,
) -> HandoverDecision {
    let my_scope = windows_scope_for_exe(my_exe, program_files);
    let running_is_stale_per_user = running_exe
        .is_some_and(|p| is_per_user_companion_path(&p.to_string_lossy(), local_app_data));

    match running_version.and_then(|rv| compare_semver(my_version, rv)) {
        Some(Ordering::Greater) => HandoverDecision::TakeOver,
        Some(Ordering::Less) => HandoverDecision::YieldToExisting,
        Some(Ordering::Equal) | None => {
            if my_scope == InstallScope::Machine && running_is_stale_per_user {
                HandoverDecision::TakeOver
            } else {
                HandoverDecision::YieldToExisting
            }
        }
    }
}

/// Extract a valid semver value from `--handover-version=<ver>` in `args`
/// (`args[0]` is the executable name).
pub fn parse_handover_version<S: AsRef<str>>(args: &[S]) -> Option<String> {
    for arg in args.iter().skip(1).map(AsRef::as_ref) {
        if let Some(ver) = arg.strip_prefix(HANDOVER_VERSION_ARG_PREFIX) {
            let ver = ver.trim();
            if parse_semver(ver).is_some() {
                return Some(ver.to_string());
            }
        }
    }
    None
}

/// Should a running companion at `my_version` immediately exit in response to
/// forwarded single-instance `args` containing `--handover-version=<ver>`?
pub fn should_yield_to_handover_arg<S: AsRef<str>>(my_version: &str, args: &[S]) -> bool {
    parse_handover_version(args).and_then(|incoming| compare_semver(&incoming, my_version))
        == Some(Ordering::Greater)
}

/// Check whether a whitespace-delimited PID sentinel file targets `pid`.
pub fn pid_file_requests_pid(contents: &str, pid: u32) -> bool {
    contents
        .split_whitespace()
        .filter_map(|tok| tok.parse::<u32>().ok())
        .any(|target| target == pid)
}

/// `<per-user data dir>/desktop/companion-instance.json`.
pub fn default_instance_path() -> Option<PathBuf> {
    crate::appdirs::project_dirs()
        .map(|d| d.data_local_dir().join("desktop").join(INSTANCE_FILE_NAME))
}

/// `<per-user data dir>/desktop/companion-handover.pid`.
pub fn default_handover_pid_path() -> Option<PathBuf> {
    crate::appdirs::project_dirs().map(|d| {
        d.data_local_dir()
            .join("desktop")
            .join(HANDOVER_PID_FILE_NAME)
    })
}

/// Read the recorded companion instance; missing or corrupt ⇒ `None`.
pub fn load_instance_from(path: &Path) -> Option<CompanionInstanceRecord> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<CompanionInstanceRecord>(&raw).ok()
}

/// Atomically persist the companion instance record (temp file + rename).
pub fn save_instance_to(path: &Path, record: &CompanionInstanceRecord) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(record).map_err(std::io::Error::other)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Remove the instance record file ONLY when it still belongs to `expected_pid`.
/// Prevents an exiting older companion from erasing a newer companion's newly
/// written record.
pub fn remove_instance_if_pid(path: &Path, expected_pid: u32) {
    if load_instance_from(path).is_some_and(|rec| rec.pid == expected_pid) {
        let _ = std::fs::remove_file(path);
    }
}

/// Unix process liveness and graceful termination helpers for companion
/// handover, living here to reuse `meshharbor-node-core`'s `libc` dependency.
#[cfg(unix)]
pub mod unix_proc {
    use std::path::Path;
    use std::time::{Duration, Instant};

    /// Is `pid` currently alive (and owned/signalable by this user)?
    pub fn is_pid_alive(pid: u32) -> bool {
        let Ok(pid_i32) = i32::try_from(pid) else {
            return false;
        };
        if pid_i32 <= 0 {
            return false;
        }
        // SAFETY: `kill(pid, 0)` only checks process existence/permission.
        let rc = unsafe { libc::kill(pid_i32, 0) };
        if rc == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    /// Best-effort verification that `pid` is actually a `meshharbor-desktop`
    /// process so a stale record whose PID was reused never terminates an
    /// unrelated process.
    pub fn pid_looks_like_companion(pid: u32, expected_exe: &Path) -> bool {
        if !is_pid_alive(pid) {
            return false;
        }
        let expected_name = expected_exe
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_else(|| "meshharbor-desktop".to_string());

        #[cfg(target_os = "linux")]
        {
            if let Ok(link) = std::fs::read_link(format!("/proc/{pid}/exe")) {
                let s = link.to_string_lossy();
                let clean = s.strip_suffix(" (deleted)").unwrap_or(&s);
                return Path::new(clean)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase())
                    .is_some_and(|name| {
                        name == expected_name || name.contains("meshharbor-desktop")
                    });
            }
            false
        }

        #[cfg(not(target_os = "linux"))]
        {
            std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .to_ascii_lowercase()
                })
                .is_some_and(|comm| {
                    comm.contains(&expected_name) || comm.contains("meshharbor-desktop")
                })
        }
    }

    /// Send `SIGTERM` to `pid` (after verifying it looks like a companion) and
    /// wait up to `timeout` for exit. Returns `true` when the process is gone.
    pub fn terminate_verified_gracefully(pid: u32, expected_exe: &Path, timeout: Duration) -> bool {
        if !pid_looks_like_companion(pid, expected_exe) {
            return !is_pid_alive(pid);
        }
        let Ok(pid_i32) = i32::try_from(pid) else {
            return false;
        };
        // SAFETY: `pid_i32 > 0`, verified above to be our companion process.
        unsafe {
            libc::kill(pid_i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !is_pid_alive(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        !is_pid_alive(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pf() -> Vec<PathBuf> {
        vec![
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ]
    }

    #[test]
    fn semver_parsing_and_ordering() {
        assert_eq!(
            compare_semver("0.4.214", "0.4.171"),
            Some(Ordering::Greater)
        );
        assert_eq!(compare_semver("0.4.171", "0.4.214"), Some(Ordering::Less));
        assert_eq!(compare_semver("0.4.214", "0.4.214"), Some(Ordering::Equal));
        assert_eq!(compare_semver("v0.4.214", "0.4.214"), Some(Ordering::Equal));
        assert_eq!(
            compare_semver("0.4.214+meta.1", "0.4.214+meta.2"),
            Some(Ordering::Equal)
        );
        // Final release outranks pre-release.
        assert_eq!(
            compare_semver("0.4.214", "0.4.214-rc.1"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_semver("0.4.214-rc.10", "0.4.214-rc.2"),
            Some(Ordering::Greater)
        );
        assert_eq!(compare_semver("1.0.0", "0.99.99"), Some(Ordering::Greater));
        // Malformed inputs return None.
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("0.4"), None);
        assert_eq!(parse_semver("0.4.1.2"), None);
        assert_eq!(parse_semver("0.4.1-"), None);
        assert_eq!(parse_semver("0.4.1-rc..1"), None);
        assert_eq!(compare_semver("0.4.214", "bogus"), None);
    }

    #[test]
    fn decide_handover_newer_replaces_older() {
        let machine = Path::new(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe");
        let user =
            Path::new(r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe");
        assert_eq!(
            decide_handover("0.4.214", machine, Some("0.4.171"), Some(user), &pf()),
            HandoverDecision::TakeOver
        );
        assert_eq!(
            decide_handover("0.4.214", machine, Some("0.4.213"), Some(machine), &pf()),
            HandoverDecision::TakeOver
        );
        assert_eq!(
            decide_handover("0.4.214", user, Some("0.4.213"), Some(user), &pf()),
            HandoverDecision::TakeOver
        );
    }

    #[test]
    fn decide_handover_same_or_unknown_version_machine_replaces_stale_per_user() {
        let machine = Path::new(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe");
        let user =
            Path::new(r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe");
        // Same version: Program Files takes over from stale per-user tray.
        assert_eq!(
            decide_handover("0.4.214", machine, Some("0.4.214"), Some(user), &pf()),
            HandoverDecision::TakeOver
        );
        // Legacy pre-T11 companion (no companion-instance.json ⇒ version unknown).
        assert_eq!(
            decide_handover("0.4.214", machine, None, Some(user), &pf()),
            HandoverDecision::TakeOver
        );
        // Redirected LocalAppData works via the explicit variant too.
        let redirected_user =
            Path::new(r"D:\Profiles\ana\Local\Programs\MeshHarbor\meshharbor-desktop.exe");
        assert_eq!(
            decide_handover_with_local_app_data(
                "0.4.214",
                machine,
                None,
                Some(redirected_user),
                &pf(),
                Some(Path::new(r"D:\Profiles\ana\Local")),
            ),
            HandoverDecision::TakeOver
        );
    }

    #[test]
    fn decide_handover_older_or_same_scope_equal_yields() {
        let machine = Path::new(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe");
        let user =
            Path::new(r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe");
        // Older incoming ALWAYS yields — even if incoming is Machine and running is User.
        assert_eq!(
            decide_handover("0.4.171", machine, Some("0.4.214"), Some(user), &pf()),
            HandoverDecision::YieldToExisting
        );
        assert_eq!(
            decide_handover("0.4.171", user, Some("0.4.214"), Some(machine), &pf()),
            HandoverDecision::YieldToExisting
        );
        // Same-scope equal version yields (normal double-click / autostart).
        assert_eq!(
            decide_handover("0.4.214", machine, Some("0.4.214"), Some(machine), &pf()),
            HandoverDecision::YieldToExisting
        );
        assert_eq!(
            decide_handover("0.4.214", user, Some("0.4.214"), Some(user), &pf()),
            HandoverDecision::YieldToExisting
        );
        // Equal per-user NEVER kills per-machine.
        assert_eq!(
            decide_handover("0.4.214", user, Some("0.4.214"), Some(machine), &pf()),
            HandoverDecision::YieldToExisting
        );
        // Unknown version on same-scope Machine yields (never kills sibling Machine instance).
        assert_eq!(
            decide_handover("0.4.214", machine, None, Some(machine), &pf()),
            HandoverDecision::YieldToExisting
        );
        // Unknown running exe + unknown version yields.
        assert_eq!(
            decide_handover("0.4.214", machine, None, None, &pf()),
            HandoverDecision::YieldToExisting
        );
    }

    #[test]
    fn handover_version_arg_yields_only_for_strictly_newer_semver() {
        assert_eq!(
            parse_handover_version(&["meshharbor-desktop", "--handover-version=0.4.214"]),
            Some("0.4.214".into())
        );
        assert_eq!(
            parse_handover_version(&["--handover-version=0.4.214"]),
            None,
            "argv[0] is the program name"
        );
        assert_eq!(
            parse_handover_version(&["meshharbor-desktop", "--handover-version=not-semver"]),
            None
        );

        assert!(should_yield_to_handover_arg(
            "0.4.213",
            &["meshharbor-desktop", "--handover-version=0.4.214"]
        ));
        assert!(!should_yield_to_handover_arg(
            "0.4.214",
            &["meshharbor-desktop", "--handover-version=0.4.214"]
        ));
        assert!(!should_yield_to_handover_arg(
            "0.4.214",
            &["meshharbor-desktop", "--handover-version=0.4.171"]
        ));
        assert!(!should_yield_to_handover_arg(
            "0.4.214",
            &["meshharbor-desktop", "--autostart"]
        ));
    }

    #[test]
    fn instance_record_round_trips_and_guards_removal_by_pid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("desktop").join(INSTANCE_FILE_NAME);
        assert_eq!(load_instance_from(&path), None);

        let rec = CompanionInstanceRecord {
            pid: 4242,
            version: "0.4.214".into(),
            exe_path: r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe".into(),
        };
        save_instance_to(&path, &rec).unwrap();
        assert_eq!(load_instance_from(&path), Some(rec.clone()));

        // A different PID must NOT remove our record (race with exiting older tray).
        remove_instance_if_pid(&path, 9999);
        assert_eq!(load_instance_from(&path), Some(rec));

        // Our own PID removes it cleanly.
        remove_instance_if_pid(&path, 4242);
        assert_eq!(load_instance_from(&path), None);
    }

    #[test]
    fn pid_file_matches_exact_pid_tokens() {
        assert!(pid_file_requests_pid("1234\n", 1234));
        assert!(pid_file_requests_pid("100 200\n300", 200));
        assert!(!pid_file_requests_pid("12345\n", 1234));
        assert!(!pid_file_requests_pid("", 1234));
    }
}
