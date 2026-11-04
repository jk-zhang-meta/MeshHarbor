// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR-BEGIN
// This whole module EXISTS to clean up pre-rename installs. Every retired
// name in it is something it must still recognise on a host that has one: the
// legacy SCM service `MeshHarborAgentService`, the legacy Scheduled Task
// `MeshHarborAgent`, the pre-P4b `meshharbor-agent` install folders, the
// `meshharbor-agent` app segment, the inert `meshharbor-agent.exe` alias and the
// `meshharbor_agent_exe` MSI FileKey.
// INVARIANT: a retired name here must be one this cleanup has to FIND. If you add
// one that is not, that is a bug, not a new exemption. docs/fr/FR-21
//! Cross-flavour install cleanup (Plan rc.18 P2).
//!
//! Removes stale artifacts left behind when an operator switches
//! between the perUser and perMachine MSI flavours of the agent.
//! Invoked by the MSI's custom action just before `InstallFiles` so
//! the new install lands cleanly.
//!
//! ## What gets cleaned
//!
//! When installing **perUser**, the helper cleans **perMachine**
//! leftovers:
//! - SCM service `MeshHarborAgentService` (sc stop + sc delete) — needs
//!   admin; perUser MSI's CA runs Impersonated and inherits the user
//!   token, so this is best-effort. A non-admin user can't have a
//!   live perMachine install anyway, so failure here is benign.
//! - Service log dir `%PROGRAMDATA%\meshharbor\meshharbor-agent\service-logs\`
//!   (best-effort; may be ACL-locked).
//!
//! When installing **perMachine**, the helper cleans **perUser**
//! leftovers:
//! - Scheduled Task `MeshHarborAgent` (`schtasks /Delete /TN MeshHarborAgent
//!   /F`). Runs as SYSTEM, can see + delete the user-scope task.
//! - Active-session user's data dirs at `%LOCALAPPDATA%\meshharbor\
//!   meshharbor-agent\` and `%APPDATA%\meshharbor\meshharbor-agent\` (resolved
//!   via `system_context::user_profile::active_user_profile_root()`
//!   because SYSTEM context can't see `%LOCALAPPDATA%` of the
//!   interactive user directly).
//! - `needs-attention.txt` sentinel in the user's config dir.
//!
//! ## Vacated-dir sweep (P4b)
//!
//! P4b renamed the wxs `APPLICATIONFOLDER` from `meshharbor-agent` to
//! `MeshHarbor`, so every MajorUpgrade from ≤rc.194 vacates the old
//! directory: the perMachine wxs has no `RemoveFolder` entries, and
//! the perUser flavour leaves PendingFileRename residue whenever the
//! running agent's EXE was locked during `RemoveFiles` (deleting the
//! Scheduled Task does not kill the already-running process). The
//! sweep removes known product files from the old-named directory
//! for the TARGET flavour's scope, then the directory itself if
//! empty. It runs BEFORE the same-flavour fast path — see below for
//! why that is the only placement the MSI CA ever executes.
//!
//! ## Same-flavour fast path — and what the MSI CA actually reaches
//!
//! When the new install matches the existing install's flavour, this
//! helper exits 0 immediately (after the vacated-dir sweep).
//! Same-flavour upgrades go through WiX MajorUpgrade and don't need
//! any cross-flavour scrubbing.
//!
//! NB the flavour probe is `updater::current_install_flavour()`,
//! which classifies **this process's own exe path**. The MSI custom
//! actions shell the freshly-laid TARGET exe
//! (`FileKey='meshharbor_agent_exe'`), so in CA context current ==
//! target ALWAYS and the fast path fires on every CA invocation —
//! including genuine cross-flavour switches. The cross-flavour arms
//! below are therefore reachable ONLY via an operator manually
//! running `cleanup-legacy-install` from an oppositely-scoped exe;
//! the vacated-dir sweep is the single step with MSI-CA reach.
//! (Switching the probe to the registry-based `install_detect` would
//! make the arms CA-reachable but would also activate the user-data
//! -dir deletion — config + enrollment trees — on fleet flows;
//! deliberately NOT done in P4b.)
//!
//! ## Why a separate CLI subcommand
//!
//! WiX custom actions are easier to plumb when they shell out to a
//! deterministic exe. The CA does:
//!
//! ```text
//! "[INSTALLDIR]meshharbor-agent.exe" cleanup-legacy-install \
//!     --target-flavour {perUser|perMachine}
//! ```
//!
//! Return="ignore" on the CA so a cleanup failure doesn't sink the
//! whole install. We log + continue.
//!
//! ## Dry-run mode
//!
//! `--dry-run` prints what WOULD be removed without touching anything.
//! Used during MSI build smoke tests to validate the helper's logic
//! before flipping to the live path.

use anyhow::Result;
// Only the Windows cleanup paths construct PathBuf — gate the import
// behind cfg so Linux/macOS clippy doesn't flag it as unused.
#[cfg(target_os = "windows")]
use std::path::PathBuf;

/// Which MSI flavour is being INSTALLED. The helper cleans the
/// OPPOSITE flavour's artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetFlavour {
    PerUser,
    PerMachine,
}

impl TargetFlavour {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "peruser" | "per-user" | "user" => Some(Self::PerUser),
            "permachine" | "per-machine" | "machine" => Some(Self::PerMachine),
            _ => None,
        }
    }
}

/// Tally of what cleanup did (or would do, when `dry_run=true`).
/// Each `Vec<String>` is a list of human-readable artifact descriptions
/// — surfaced via the CLI's one-line summary print.
#[derive(Debug, Default)]
pub struct CleanupReport {
    pub removed: Vec<String>,
    pub skipped: Vec<String>,
    pub errors: Vec<String>,
}

impl CleanupReport {
    pub fn summary(&self) -> String {
        format!(
            "cleanup-legacy-install: removed {} skipped {} errors {} ({})",
            self.removed.len(),
            self.skipped.len(),
            self.errors.len(),
            self.removed
                .iter()
                .chain(self.skipped.iter())
                .chain(self.errors.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

/// Run cross-flavour cleanup for the given target flavour. When `dry_run`
/// is true, prints intent but doesn't mutate anything.
///
/// On non-Windows hosts this is a no-op returning an empty report —
/// only the Windows MSIs have cross-flavour ambiguity.
pub fn run_cleanup(target: TargetFlavour, dry_run: bool) -> Result<CleanupReport> {
    let mut report = CleanupReport::default();

    #[cfg(target_os = "windows")]
    {
        // P4b: sweep the vacated pre-rename install dir FIRST. The
        // same-flavour fast path below fires on EVERY MSI CA
        // invocation (see the module docs), so anything placed after
        // it never runs in CA context — this sweep is the one step
        // the installer actually reaches.
        cleanup_vacated_install_dir(target, &mut report, dry_run);

        // Same-flavour fast path: the new install matches what's
        // already on disk → no cross-flavour cleanup needed.
        let current = crate::updater::current_install_flavour();
        let cross_flavour_needed = !matches!(
            (current, target),
            (
                crate::updater::WindowsInstallFlavour::PerUser,
                TargetFlavour::PerUser,
            ) | (
                crate::updater::WindowsInstallFlavour::PerMachine,
                TargetFlavour::PerMachine,
            )
        );
        if !cross_flavour_needed {
            report
                .skipped
                .push("same-flavour install — no cross-flavour cleanup".to_string());
            return Ok(report);
        }
        match target {
            TargetFlavour::PerUser => cleanup_per_machine_artifacts(&mut report, dry_run),
            TargetFlavour::PerMachine => cleanup_per_user_artifacts(&mut report, dry_run),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (target, dry_run);
        report
            .skipped
            .push("non-Windows host — no cross-flavour cleanup".to_string());
    }

    Ok(report)
}

/// Filenames the MSIs have ever shipped into the install folder,
/// plus the tunnel CLI pair. The vacated-dir sweep deletes ONLY
/// these — never arbitrary files an operator parked there. The CLI
/// pair (`mh.exe` / `meshharbor-tunnel.exe`) is included even
/// though pre-P4b MSIs never shipped it: in the OLD dir those can
/// only be manually-copied tunnel CLIs (field-observed), they are
/// OUR binaries in OUR dead directory, and a stale copy in a
/// manually-PATH'd old dir is a version-skew hazard once the new
/// dir's `mh.exe` is authoritative.
#[cfg(target_os = "windows")]
const INSTALL_DIR_PRODUCT_FILES: &[&str] = &[
    "meshharbord.exe",
    "meshharbor-agent.exe",
    "mh.exe",
    "meshharbor-tunnel.exe",
    // S1a — the desktop companion + its refresh sidecars live beside the
    // daemon (placed by the wizard / companion-refresh, not the MSI);
    // without these entries the vacated-dir sweep strands a stale copy.
    "meshharbor-desktop.exe",
    "meshharbor-desktop.exe.version",
    "meshharbor-desktop.exe.old",
    "wintun.dll",
    "LICENSE.txt",
    "README.txt",
];

/// P4b: sweep the VACATED pre-rename install directory for the
/// TARGET flavour's scope (perUser →
/// `%LOCALAPPDATA%\Programs\meshharbor-agent`, perMachine →
/// `%ProgramFiles%\meshharbor-agent`).
///
/// Policy: conservative. Skip outright when the candidate IS the
/// directory this process runs from (paranoia guard — impossible
/// with the renamed wxs, but cheap insurance against a rebuilt
/// old-name MSI invoking a new exe). Delete only
/// [`INSTALL_DIR_PRODUCT_FILES`], then `remove_dir` NON-recursively:
/// foreign content survives and is reported; locked files fail soft
/// (the CA runs `Return='ignore'`; PendingFileRenameOperations
/// clears them on the next reboot, after which a later invocation
/// removes the then-empty dir).
#[cfg(target_os = "windows")]
fn cleanup_vacated_install_dir(target: TargetFlavour, report: &mut CleanupReport, dry_run: bool) {
    let flavour = match target {
        TargetFlavour::PerUser => crate::updater::WindowsInstallFlavour::PerUser,
        TargetFlavour::PerMachine => crate::updater::WindowsInstallFlavour::PerMachine,
    };
    let Some(dir) =
        crate::updater::install_dir_with_name(flavour, crate::updater::LEGACY_INSTALL_FOLDER_NAME)
    else {
        report
            .skipped
            .push("vacated-dir sweep: install root env var unset".to_string());
        return;
    };
    if !dir.is_dir() {
        report
            .skipped
            .push(format!("vacated dir {} not present", dir.display()));
        return;
    }
    // Paranoia guard: never sweep the directory we are running from.
    if let Ok(own) = std::env::current_exe()
        && let Some(own_dir) = own.parent()
        && same_dir(own_dir, &dir)
    {
        report.skipped.push(format!(
            "vacated-dir sweep: {} is the running exe's own directory — skipped",
            dir.display()
        ));
        return;
    }
    if dry_run {
        report.removed.push(format!(
            "[dry-run] sweep vacated install dir {} (known product files + rmdir-if-empty)",
            dir.display()
        ));
        return;
    }
    for name in INSTALL_DIR_PRODUCT_FILES {
        let file = dir.join(name);
        if file.is_file() {
            match std::fs::remove_file(&file) {
                Ok(()) => report.removed.push(format!("stale {}", file.display())),
                Err(e) => report
                    .errors
                    .push(format!("remove {}: {e}", file.display())),
            }
        }
    }
    match std::fs::remove_dir(&dir) {
        Ok(()) => report
            .removed
            .push(format!("vacated install dir {}", dir.display())),
        Err(e) => report.skipped.push(format!(
            "vacated dir {} left in place (non-product files or locks): {e}",
            dir.display()
        )),
    }
}

/// Case-insensitive same-directory check (Windows path semantics).
/// Falls back to lossy-string comparison when canonicalize fails —
/// the caller uses this as a skip-guard, so a false POSITIVE (skip
/// the sweep) is the safe failure mode.
#[cfg(target_os = "windows")]
fn same_dir(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy()),
    }
}

// ──────────────────────────────────────────────────────────────────
// perMachine → cleanup perUser artifacts (we are installing perMachine
// over a prior perUser install)
// ──────────────────────────────────────────────────────────────────
#[cfg(target_os = "windows")]
fn cleanup_per_user_artifacts(report: &mut CleanupReport, dry_run: bool) {
    // 1. Scheduled Task — registered by the perUser MSI's
    //    `RegisterAutostart` custom action: `MeshHarborAgent` pre-P3d,
    //    `MeshHarbor` since the P3d rename (P4b hygiene: both scrubbed).
    //    perMachine MSI's CA runs as SYSTEM so it can see + delete
    //    the task without impersonation. NB reachable via operator
    //    CLI only — the MSI CA always exits through the same-flavour
    //    fast path (module docs) — so this can never race the SAME
    //    install's freshly-registered task.
    for task_name in ["MeshHarborAgent", "MeshHarbor"] {
        if scheduled_task_exists(task_name) {
            if dry_run {
                report
                    .removed
                    .push(format!("[dry-run] schtasks /Delete /TN {task_name} /F"));
            } else {
                match delete_scheduled_task(task_name) {
                    Ok(()) => report.removed.push(format!("Scheduled Task {task_name}")),
                    Err(e) => report
                        .errors
                        .push(format!("schtasks /Delete {task_name}: {e}")),
                }
            }
        } else {
            report
                .skipped
                .push(format!("Scheduled Task {task_name} not present"));
        }
    }

    // 2. Active-session user's data dirs. SYSTEM context can't see the
    //    interactive user's %LOCALAPPDATA% / %APPDATA% directly; resolve
    //    via the WTSQueryUserToken-backed `active_user_profile_root()`
    //    (reuses the M3 A1 SystemContext plumbing).
    #[cfg(feature = "system-context")]
    {
        if let Some(profile_root) = crate::system_context::user_profile::active_user_profile_root()
        {
            // Clean BOTH the legacy `meshharbor-agent` app segment AND the new
            // `meshharbor` segment (the binary rename, `appdirs.rs`). A
            // cross-flavour switch must scrub whichever segment the OTHER
            // flavour landed on, so we enumerate both new-named and
            // legacy-named trees rather than routing through `appdirs`
            // (which resolves to only ONE segment per host).
            let candidates = [
                profile_root
                    .join("AppData")
                    .join("Local")
                    .join("meshharbor")
                    .join("meshharbor-agent"),
                profile_root
                    .join("AppData")
                    .join("Roaming")
                    .join("meshharbor")
                    .join("meshharbor-agent"),
                profile_root
                    .join("AppData")
                    .join("Local")
                    .join("meshharbor")
                    .join("meshharbor"),
                profile_root
                    .join("AppData")
                    .join("Roaming")
                    .join("meshharbor")
                    .join("meshharbor"),
            ];
            for path in candidates {
                if path.exists() {
                    if dry_run {
                        report
                            .removed
                            .push(format!("[dry-run] rmdir /s {}", path.display()));
                    } else {
                        match std::fs::remove_dir_all(&path) {
                            Ok(()) => report
                                .removed
                                .push(format!("user data dir {}", path.display())),
                            Err(e) => {
                                report
                                    .errors
                                    .push(format!("rmdir {}: {}", path.display(), e))
                            }
                        }
                    }
                } else {
                    report
                        .skipped
                        .push(format!("user data dir {} not present", path.display()));
                }
            }
        } else {
            // No active interactive session (headless install / no
            // logged-in user). Cleanup is a no-op; the orphan data
            // remains until a user logs in and runs `cleanup-legacy-
            // install` manually OR until the user's own uninstall.
            report
                .skipped
                .push("no active interactive session — user data dirs not reachable".to_string());
        }
    }

    // Without the system-context feature compiled in, the
    // active_user_profile_root helper isn't available; the cleanup
    // becomes a perUser-self-deletes-its-own-dirs operation. Since
    // perMachine MSI normally has the feature on, this branch only
    // matters for the default build used in headless CI tests.
    #[cfg(not(feature = "system-context"))]
    {
        report
            .skipped
            .push("system-context feature off — user data dir reach-through skipped".to_string());
    }
}

// ──────────────────────────────────────────────────────────────────
// perUser → cleanup perMachine artifacts (we are installing perUser
// over a prior perMachine install)
// ──────────────────────────────────────────────────────────────────
#[cfg(target_os = "windows")]
fn cleanup_per_machine_artifacts(report: &mut CleanupReport, dry_run: bool) {
    // 1. SCM service: `MeshHarborAgentService` pre-P3d, `MeshHarbor` since
    //    the P3d rename (P4b hygiene: both scrubbed). The perUser
    //    MSI's CA runs Impersonated (user token). Service control
    //    requires admin — so this is BEST-EFFORT. If the user isn't
    //    admin, sc fails and we surface it as an error (the operator
    //    must manually `sc delete <name>` from elevated PS). NB
    //    reachable via operator CLI only — the MSI CA always exits
    //    through the same-flavour fast path (module docs).
    for service_name in ["MeshHarborAgentService", "MeshHarbor"] {
        if service_exists(service_name) {
            if dry_run {
                report
                    .removed
                    .push(format!("[dry-run] sc stop + sc delete {service_name}"));
            } else {
                // stop is best-effort (service may already be stopped).
                let _ = run_quiet("sc", &["stop", service_name]);
                match run_quiet("sc", &["delete", service_name]) {
                    Ok(()) => report.removed.push(format!("SCM service {service_name}")),
                    Err(e) => report.errors.push(format!("sc delete {service_name}: {e}")),
                }
            }
        } else {
            report
                .skipped
                .push(format!("SCM service {service_name} not present"));
        }
    }

    // 2. Service log dir at %PROGRAMDATA%\meshharbor\<segment>\service-logs\.
    //    ACL'd to SYSTEM at create time; the perUser MSI's user-token CA
    //    may not be able to delete it. Scrub BOTH the legacy
    //    `meshharbor-agent` segment AND the new `meshharbor` segment (binary
    //    rename, `appdirs.rs`) so a cross-flavour switch doesn't leave the
    //    other segment's tree behind. Not routed through `appdirs` (which
    //    resolves to only ONE segment per host).
    if let Ok(program_data) = std::env::var("PROGRAMDATA") {
        for segment in ["meshharbor-agent", "meshharbor"] {
            let path = PathBuf::from(&program_data)
                .join("meshharbor")
                .join(segment)
                .join("service-logs");
            if path.exists() {
                if dry_run {
                    report
                        .removed
                        .push(format!("[dry-run] rmdir /s {}", path.display()));
                } else {
                    match std::fs::remove_dir_all(&path) {
                        Ok(()) => report
                            .removed
                            .push(format!("service log dir {}", path.display())),
                        Err(e) => report
                            .errors
                            .push(format!("rmdir {}: {}", path.display(), e)),
                    }
                }
            } else {
                report
                    .skipped
                    .push(format!("service log dir {} not present", path.display()));
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn scheduled_task_exists(name: &str) -> bool {
    // schtasks returns 0 when the task exists, non-zero otherwise.
    // We don't need the output — exit code suffices.
    std::process::Command::new("schtasks")
        .args(["/Query", "/TN", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn delete_scheduled_task(name: &str) -> Result<()> {
    let status = std::process::Command::new("schtasks")
        .args(["/Delete", "/TN", name, "/F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        anyhow::bail!("schtasks /Delete exited {:?}", status.code());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn service_exists(name: &str) -> bool {
    std::process::Command::new("sc")
        .args(["query", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn run_quiet(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        anyhow::bail!("{cmd} {:?} exited {:?}", args, status.code());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_flavour_parses_friendly_strings() {
        assert_eq!(
            TargetFlavour::parse("perUser"),
            Some(TargetFlavour::PerUser)
        );
        assert_eq!(
            TargetFlavour::parse("PERUSER"),
            Some(TargetFlavour::PerUser)
        );
        assert_eq!(
            TargetFlavour::parse("per-user"),
            Some(TargetFlavour::PerUser)
        );
        assert_eq!(TargetFlavour::parse("user"), Some(TargetFlavour::PerUser));
        assert_eq!(
            TargetFlavour::parse("perMachine"),
            Some(TargetFlavour::PerMachine)
        );
        assert_eq!(
            TargetFlavour::parse("per-machine"),
            Some(TargetFlavour::PerMachine)
        );
        assert_eq!(
            TargetFlavour::parse("machine"),
            Some(TargetFlavour::PerMachine)
        );
        assert_eq!(TargetFlavour::parse("bogus"), None);
        assert_eq!(TargetFlavour::parse(""), None);
    }

    #[test]
    fn cleanup_report_summary_includes_counts_and_items() {
        let mut r = CleanupReport::default();
        r.removed.push("task MeshHarborAgent".to_string());
        r.skipped.push("nothing else".to_string());
        let s = r.summary();
        assert!(s.contains("removed 1"));
        assert!(s.contains("skipped 1"));
        assert!(s.contains("errors 0"));
        assert!(s.contains("task MeshHarborAgent"));
        assert!(s.contains("nothing else"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn run_cleanup_on_non_windows_is_noop() {
        let report = run_cleanup(TargetFlavour::PerUser, true).unwrap();
        assert!(report.removed.is_empty());
        assert!(report.errors.is_empty());
        assert!(report.skipped.iter().any(|s| s.contains("non-Windows")));
    }

    // ── P4b vacated-dir sweep ─────────────────────────────────────

    /// The sweep targets the LEGACY folder name under the flavour's
    /// root. Env-var roots are always set on a real Windows session
    /// (and the Windows CI runners), so suffix asserts are
    /// host-state-independent.
    #[cfg(target_os = "windows")]
    #[test]
    fn vacated_dir_derives_legacy_name_per_flavour() {
        use crate::updater::{
            LEGACY_INSTALL_FOLDER_NAME, WindowsInstallFlavour, install_dir_with_name,
        };
        let pu = install_dir_with_name(WindowsInstallFlavour::PerUser, LEGACY_INSTALL_FOLDER_NAME)
            .expect("LOCALAPPDATA set");
        assert!(
            pu.ends_with(std::path::Path::new("Programs").join("meshharbor-agent")),
            "unexpected perUser dir {}",
            pu.display()
        );
        let pm = install_dir_with_name(
            WindowsInstallFlavour::PerMachine,
            LEGACY_INSTALL_FOLDER_NAME,
        )
        .expect("ProgramFiles set");
        assert!(
            pm.ends_with("meshharbor-agent"),
            "unexpected perMachine dir {}",
            pm.display()
        );
        assert!(
            pm.to_string_lossy()
                .to_lowercase()
                .contains("program files"),
            "perMachine dir must live under Program Files: {}",
            pm.display()
        );
    }

    /// Dry-run `run_cleanup` always records the sweep's verdict —
    /// whichever branch it takes (dir present / absent / own-dir
    /// guard), the report mentions the vacated dir. This is the lock
    /// that the sweep sits BEFORE the same-flavour fast path (the
    /// only placement the MSI CA ever executes).
    #[cfg(target_os = "windows")]
    #[test]
    fn dry_run_cleanup_reports_vacated_dir_sweep_before_fast_path() {
        let report = run_cleanup(TargetFlavour::PerUser, true).unwrap();
        assert!(
            report
                .removed
                .iter()
                .chain(report.skipped.iter())
                .any(|s| s.contains("vacated")),
            "sweep verdict missing from report: {}",
            report.summary()
        );
        // ... and the fast path still fired after it (this test
        // binary never runs from Program Files → current == PerUser
        // == target).
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.contains("same-flavour install")),
            "fast path missing from report: {}",
            report.summary()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn same_dir_is_case_insensitive_and_rejects_distinct_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let a = tmp.path().join("Alpha");
        let b = tmp.path().join("beta");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        assert!(same_dir(&a, &a));
        // Windows path semantics: differing case, same dir.
        let a_upper = tmp.path().join("ALPHA");
        assert!(same_dir(&a, &a_upper));
        assert!(!same_dir(&a, &b));
    }
}
// RETIRED-NAME-ANCHOR-END
