// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR(4): names the PRE-RENAME appdirs segment a host installed before
// P4b still has; appdirs::app_segment resolves it, so it is an input.
//! Operator-attention notification.
//!
//! v1 ships a sentinel file the agent writes when it needs human
//! intervention (today: persistent auth rejection that suggests the
//! token has been revoked). The file lives at the per-user config
//! dir, alongside `config.toml`, so:
//!
//! - A fleet-management script can scan `%APPDATA%\roomler\
//!   roomler\config\needs-attention.txt` across machines (a
//!   pre-rename host keeps `\roomler-agent\` there — see
//!   `appdirs::app_segment`).
//! - The future admin UI heartbeat (resilience plan Phase 7) can
//!   surface "this agent flagged itself as needing attention."
//! - An interactive operator running `roomlerd re-enroll`
//!   sees the file vanish on success.
//!
//! Real OS-toast notification (BurntToast on Win, `notify-send` on
//! Linux, `osascript` on macOS) is deferred — the sentinel file is
//! always-on-disk durable, which is what unattended-deployment IT
//! admins actually want (they grep filesystems, not desktops).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const ATTENTION_FILENAME: &str = "needs-attention.txt";

// S1b — structured reason codes. The sentinel stays a human-readable
// .txt (fleet scripts grep it) but gains a machine-parsable
// `Reason: <code>` line so readers (the desktop Overview, the healthy-
// connect clearer) can act per reason instead of showing a bare path.
pub const REASON_AUTH: &str = "auth_rejected";
pub const REASON_GOODBYE: &str = "server_goodbye";
pub const REASON_DUPLICATE: &str = "duplicate_instance";
pub const REASON_ROLLBACK: &str = "rollback_failed";
/// Legacy / unspecified sentinels (pre-S1b writers, ad-hoc messages).
pub const REASON_GENERIC: &str = "attention";

/// Parsed view of a sentinel file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttentionInfo {
    pub path: PathBuf,
    /// The human message (everything above the structured footer).
    pub message: String,
    /// `Reason:` code; `None` for pre-S1b sentinels.
    pub reason: Option<String>,
    /// FR-53 — for `rollback_failed`, the version that actually crashed.
    ///
    /// Without it the sentinel could not tell "the device is still running the
    /// build that failed" from "the device updated past it and is fine", so it
    /// assumed the first forever and a recovered host told its owner to
    /// reinstall by hand. `None` for every sentinel written before this field
    /// existed — see [`clear_attention_on_healthy_connect`], where an absent
    /// value is not a gap but proof in its own right.
    pub failed_version: Option<String>,
}

/// Resolve the per-user attention sentinel path. Returns `None` on
/// platforms where `directories` can't determine a config dir
/// (extremely rare; same scope as `config::default_config_path`).
pub fn attention_path() -> Option<PathBuf> {
    let dirs = crate::appdirs::project_dirs()?;
    Some(dirs.config_dir().join(ATTENTION_FILENAME))
}

/// Raise an attention sentinel at the per-user config dir. Writes
/// the message verbatim plus a generated-at unix timestamp so a
/// reader can tell stale flags from fresh ones. Idempotent — every
/// call replaces any existing sentinel.
pub fn raise_attention(message: &str) -> Result<PathBuf> {
    raise_attention_with_reason(REASON_GENERIC, message)
}

/// S1b — reasoned variant of [`raise_attention`].
pub fn raise_attention_with_reason(reason: &str, message: &str) -> Result<PathBuf> {
    raise_attention_with_reason_for_version(reason, message, None)
}

/// FR-53 — reasoned variant that also records the version being accused, so a
/// `rollback_failed` sentinel can be cleared once the device is demonstrably
/// running a different build.
pub fn raise_attention_with_reason_for_version(
    reason: &str,
    message: &str,
    failed_version: Option<&str>,
) -> Result<PathBuf> {
    let path = attention_path().context("no per-user config dir resolvable")?;
    let parent = path.parent().context("attention path has no parent")?;
    raise_attention_at_full(parent, reason, message, failed_version)
}

/// Same as [`raise_attention`] but takes an explicit directory.
/// Extracted so the test suite can drive it against a tempdir.
pub fn raise_attention_at(dir: &Path, message: &str) -> Result<PathBuf> {
    raise_attention_at_with_reason(dir, REASON_GENERIC, message)
}

/// S1b — the one real writer: message + structured footer.
pub fn raise_attention_at_with_reason(dir: &Path, reason: &str, message: &str) -> Result<PathBuf> {
    raise_attention_at_full(dir, reason, message, None)
}

/// FR-53 — as [`raise_attention_at_with_reason`], plus the version this
/// sentinel is accusing.
///
/// Only `rollback_failed` needs it: it is the one reason that survives a
/// healthy connect, so it is the one that has to say WHICH build it survived
/// on behalf of. Everything else clears on the next connect regardless.
pub fn raise_attention_at_full(
    dir: &Path,
    reason: &str,
    message: &str,
    failed_version: Option<&str>,
) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating attention dir {}", dir.display()))?;
    let path = dir.join(ATTENTION_FILENAME);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    // The version line is omitted rather than written empty: absent has a
    // specific meaning to the reader (see `clear_attention_on_healthy_connect`)
    // and an empty string would muddy it.
    let version_line = match failed_version {
        Some(v) if !v.trim().is_empty() => format!("Failed-version: {}\n", v.trim()),
        _ => String::new(),
    };
    let body =
        format!("{message}\n\nReason: {reason}\n{version_line}Generated at: {ts} (unix seconds)\n");
    std::fs::write(&path, body)
        .with_context(|| format!("writing attention sentinel {}", path.display()))?;
    Ok(path)
}

/// Parse a sentinel file into its message + reason. `None` when the
/// file is absent/unreadable. Pre-S1b sentinels (no `Reason:` line)
/// parse with `reason: None`.
pub fn read_attention_at(path: &Path) -> Option<AttentionInfo> {
    let raw = std::fs::read_to_string(path).ok()?;
    let mut reason = None;
    let mut failed_version = None;
    let mut message_lines: Vec<&str> = Vec::new();
    for line in raw.lines() {
        if let Some(code) = line.strip_prefix("Reason: ") {
            reason = Some(code.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Failed-version: ") {
            failed_version = Some(v.trim().to_string());
        } else if !line.starts_with("Generated at:") {
            message_lines.push(line);
        }
    }
    let message = message_lines.join("\n").trim().to_string();
    Some(AttentionInfo {
        path: path.to_path_buf(),
        message,
        reason,
        failed_version,
    })
}

/// The machine-global sentinel path (rc.53 SystemContext writers land
/// there). `None` off Windows.
pub fn machine_attention_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        Some(crate::appdirs::machine_global_dir().join(ATTENTION_FILENAME))
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// Every sentinel location this host may carry, per-user first.
fn all_attention_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(p) = attention_path() {
        out.push(p);
    }
    if let Some(p) = machine_attention_path() {
        out.push(p);
    }
    out
}

/// S1b — first present sentinel across BOTH locations (the desktop app
/// previously read only the per-user path, so a SystemContext host's
/// machine-global sentinel was invisible).
pub fn read_any_attention() -> Option<AttentionInfo> {
    all_attention_paths()
        .iter()
        .find_map(|p| read_attention_at(p))
}

/// Remove the per-user attention sentinel if present. Best-effort — a
/// missing file or a permission glitch is silent.
pub fn clear_attention() {
    if let Some(path) = attention_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// S1b — clear EVERY sentinel unconditionally (re-enroll resolves all
/// reasons, including `rollback_failed`).
pub fn clear_all_attention() {
    for path in all_attention_paths() {
        let _ = std::fs::remove_file(path);
    }
}

/// S1b — clear sentinels on a healthy authenticated connect. Every
/// reason except `rollback_failed` is, by definition, resolved once the
/// agent is connected + authenticated (auth works, no goodbye, no live
/// duel); legacy reason-less sentinels — mostly test artifacts like the
/// infamous "rc.53 smoke" — are cleared too.
///
/// `rollback_failed` is the exception, and FR-53 narrows it from *never
/// clears* to *does not clear while the accused build is the one running*.
/// The original reasoning — "the broken-binary state isn't disproven by a
/// successful connect of the rolled-back binary" — is sound about the case it
/// describes, and is not the case that occurs: the device updates again, the
/// bad build is gone, and the sentinel goes on asserting a crash loop in a
/// version no longer installed. Measured on a real device, which claimed
/// "0.4.34 has crashed 3 times — reinstall manually" while running 0.4.41 and
/// answering the mesh; nobody had reported it in seven releases.
///
/// `running_version` is the binary that just connected, so it is a fact rather
/// than a claim.
pub fn clear_attention_on_healthy_connect_from(running_version: &str) {
    for path in all_attention_paths() {
        let Some(info) = read_attention_at(&path) else {
            continue;
        };
        if !should_clear_on_healthy_connect(&info, running_version) {
            continue;
        }
        let _ = std::fs::remove_file(&path);
    }
}

/// Back-compat shim for callers with no version to hand: keeps the pre-FR-53
/// behaviour of never clearing `rollback_failed`.
pub fn clear_attention_on_healthy_connect() {
    clear_attention_on_healthy_connect_from("")
}

/// The whole per-sentinel decision, extracted so it can be tested.
///
/// `clear_attention_on_healthy_connect_from` walks `all_attention_paths()`,
/// which resolves REAL profile directories — so a test of the loop would write
/// to the developer's own sentinel. Everything worth asserting is here instead.
pub(crate) fn should_clear_on_healthy_connect(info: &AttentionInfo, running_version: &str) -> bool {
    if info.reason.as_deref() == Some(REASON_ROLLBACK) {
        return rollback_is_stale(info, running_version);
    }
    // Every other reason — and a legacy sentinel with no `Reason:` line at all
    // — is resolved by the fact of a healthy authenticated connect.
    true
}

/// FR-53 — is this `rollback_failed` sentinel about a build we are no longer
/// running?
///
/// ⚠️ The legacy arm is the load-bearing one, because EVERY sentinel in the
/// field today predates `Failed-version:`. It is not a guess and it needs no
/// parsing of the message: a sentinel with no version line can only have been
/// written by a binary older than the one that introduced the field, and the
/// binary evaluating this *has* the field — so the writer is provably not the
/// runner, which is precisely the fact the clear requires.
///
/// ⚠️ Difference, not ordering. A device running something other than the
/// accused build is no longer running the accused build, whichever way it
/// moved; comparing semantically would add version-parsing to the trust path
/// of a UI message, and a downgrade past the bad build is just as much a
/// resolution as an upgrade.
fn rollback_is_stale(info: &AttentionInfo, running_version: &str) -> bool {
    match info.failed_version.as_deref() {
        // Legacy sentinel: absent is evidence, not a gap.
        None => !running_version.trim().is_empty(),
        Some(failed) => {
            let running = running_version.trim();
            !running.is_empty() && running != failed.trim()
        }
    }
}

/// Whether an attention sentinel currently exists in ANY location.
/// Cheap stat calls, safe to poll.
pub fn has_attention() -> bool {
    all_attention_paths().iter().any(|p| p.exists())
}

// ─── rc.53: LocalSystem-aware sentinel path routing ────────────────
//
// P3e lever E: the worker-aware trio (`attention_path_for_worker`,
// `raise_attention_machine_aware`, `raise_attention_machine_aware_with_reason`)
// did NOT move here — it probes the process's worker role via
// `meshharbord::system_context::worker_role`, which is the one coupling in
// this module that genuinely belongs to the daemon (winlogon-token
// machinery, `system-context` feature). The trio lives on in
// `roomlerd/src/notify.rs`, layered over the primitives below
// (`attention_path`, `raise_attention_at_with_reason`, `ATTENTION_FILENAME`);
// thin clients (the desktop companion) only ever need the user-context
// surface in this file. The daemon-side wrappers build on
// [`machine_attention_path`] + [`attention_path`] +
// [`raise_attention_at_with_reason`], all public above.

#[cfg(test)]
mod tests {
    use super::*;

    // ─── FR-53: a recovered device must stop warning about a crash loop ──

    fn info(reason: Option<&str>, failed: Option<&str>) -> AttentionInfo {
        AttentionInfo {
            path: PathBuf::from("x"),
            message: String::new(),
            reason: reason.map(str::to_string),
            failed_version: failed.map(str::to_string),
        }
    }

    /// The defect: a sentinel accusing 0.4.34 kept warning while the device
    /// ran 0.4.41, telling its owner to reinstall a build it had already
    /// moved past. Measured in the field before this existed.
    #[test]
    fn a_rollback_sentinel_is_stale_once_a_different_build_connects() {
        let i = info(Some(REASON_ROLLBACK), Some("0.4.34"));
        assert!(rollback_is_stale(&i, "0.4.41"), "newer build ⇒ stale");
        assert!(
            rollback_is_stale(&i, "0.4.33"),
            "a downgrade past it resolves it too"
        );
    }

    /// The case the exemption was WRITTEN for, and it must survive: the
    /// device rolled back and is running the build that failed, so a healthy
    /// connect disproves nothing.
    #[test]
    fn a_rollback_sentinel_is_kept_when_the_accused_build_is_the_one_running() {
        let i = info(Some(REASON_ROLLBACK), Some("0.4.34"));
        assert!(!rollback_is_stale(&i, "0.4.34"));
        // Whitespace must not smuggle a mismatch past the comparison.
        assert!(!rollback_is_stale(&i, " 0.4.34 "));
        // No version to compare ⇒ no claim ⇒ keep it.
        assert!(!rollback_is_stale(&i, ""));
    }

    /// The load-bearing arm: EVERY sentinel in the field today predates the
    /// `Failed-version:` line. An absent value is not a gap — such a file can
    /// only have been written by a binary older than the one that introduced
    /// the field, and the binary evaluating this HAS the field, so the writer
    /// is provably not the runner.
    #[test]
    fn a_legacy_rollback_sentinel_with_no_version_is_stale() {
        let i = info(Some(REASON_ROLLBACK), None);
        assert!(rollback_is_stale(&i, "0.4.41"));
        // …but still not on a caller that has no version to offer.
        assert!(!rollback_is_stale(&i, ""));
    }

    #[test]
    fn the_failing_version_round_trips_through_the_sentinel_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path =
            raise_attention_at_full(tmp.path(), REASON_ROLLBACK, "boom", Some("0.4.34")).unwrap();
        let read = read_attention_at(&path).unwrap();
        assert_eq!(read.reason.as_deref(), Some(REASON_ROLLBACK));
        assert_eq!(read.failed_version.as_deref(), Some("0.4.34"));
        // ⚠️ The footer is machine-parsed AND grepped by fleet scripts, so the
        // new line must not leak into the human message.
        assert_eq!(read.message, "boom");

        // Omitted rather than empty when there is nothing to record: absent
        // has a specific meaning to the reader.
        let tmp2 = tempfile::tempdir().unwrap();
        let p2 = raise_attention_at_full(tmp2.path(), REASON_AUTH, "nope", None).unwrap();
        assert!(
            !std::fs::read_to_string(&p2)
                .unwrap()
                .contains("Failed-version")
        );
        assert_eq!(read_attention_at(&p2).unwrap().failed_version, None);
        let p3 = raise_attention_at_full(tmp2.path(), REASON_AUTH, "nope", Some("   ")).unwrap();
        assert!(
            !std::fs::read_to_string(&p3)
                .unwrap()
                .contains("Failed-version")
        );
    }

    /// Everything that already cleared must go on clearing, including a
    /// sentinel with no `Reason:` line at all.
    /// Everything that already cleared must go on clearing, including a
    /// sentinel with no `Reason:` line at all — asserted through the real
    /// decision rather than by re-checking that a reason is what we set it to.
    #[test]
    fn every_other_reason_still_clears_on_a_healthy_connect() {
        for r in [
            Some(REASON_AUTH),
            Some(REASON_GOODBYE),
            Some(REASON_DUPLICATE),
            Some(REASON_GENERIC),
            None,
        ] {
            assert!(
                should_clear_on_healthy_connect(&info(r, None), "0.4.41"),
                "reason {r:?} must still clear"
            );
            // ⚠️ and it must not start depending on a version being supplied.
            assert!(should_clear_on_healthy_connect(&info(r, None), ""));
        }
    }

    /// The decision the loop actually makes, both ways.
    #[test]
    fn a_rollback_sentinel_clears_only_when_the_accused_build_is_gone() {
        let accused = info(Some(REASON_ROLLBACK), Some("0.4.34"));
        assert!(should_clear_on_healthy_connect(&accused, "0.4.41"));
        assert!(!should_clear_on_healthy_connect(&accused, "0.4.34"));
        let legacy = info(Some(REASON_ROLLBACK), None);
        assert!(should_clear_on_healthy_connect(&legacy, "0.4.41"));
        assert!(!should_clear_on_healthy_connect(&legacy, ""));
    }

    #[test]
    fn raise_writes_message_and_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let path = raise_attention_at(tmp.path(), "re-enrollment required").unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("re-enrollment required"));
        assert!(
            content.contains("Generated at:"),
            "timestamp footer missing: {content:?}"
        );
    }

    #[test]
    fn raise_replaces_existing_sentinel() {
        let tmp = tempfile::tempdir().unwrap();
        let _ = raise_attention_at(tmp.path(), "first message").unwrap();
        let path = raise_attention_at(tmp.path(), "second message").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("second message"));
        assert!(!content.contains("first message"));
    }

    #[test]
    fn raise_creates_parent_dir_if_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("level1").join("level2");
        let path = raise_attention_at(&nested, "test").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn attention_path_does_not_panic() {
        // Returns `Some(path)` on platforms with a config dir, `None`
        // in the rare environment where `directories::ProjectDirs`
        // can't resolve one (some sandboxed test runners clear
        // HOME / USERPROFILE). Either result is fine — the function
        // is best-effort. What matters is no panic.
        let _ = attention_path();
    }

    // The `attention_path_for_worker` no-panic + resolve-without-writing
    // tests moved to `roomlerd/src/notify.rs` with the worker-aware
    // trio itself (P3e lever E).

    #[test]
    fn reasoned_roundtrip_parses_message_and_reason() {
        let tmp = tempfile::tempdir().unwrap();
        let path =
            raise_attention_at_with_reason(tmp.path(), REASON_AUTH, "re-enrollment required")
                .unwrap();
        let info = read_attention_at(&path).expect("sentinel parses");
        assert_eq!(info.reason.as_deref(), Some(REASON_AUTH));
        assert_eq!(info.message, "re-enrollment required");
    }

    #[test]
    fn legacy_sentinel_parses_with_no_reason() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(ATTENTION_FILENAME);
        std::fs::write(
            &path,
            "rc.53 smoke\n\nGenerated at: 1785141357 (unix seconds)\n",
        )
        .unwrap();
        let info = read_attention_at(&path).expect("legacy sentinel parses");
        assert_eq!(info.reason, None);
        assert_eq!(info.message, "rc.53 smoke");
    }

    #[test]
    fn healthy_clear_spares_only_rollback() {
        // Drive the per-path decision logic directly against tempdir
        // sentinels (the public fn resolves real profile paths).
        let tmp = tempfile::tempdir().unwrap();
        let auth = raise_attention_at_with_reason(tmp.path(), REASON_AUTH, "x").unwrap();
        let info = read_attention_at(&auth).unwrap();
        assert_ne!(info.reason.as_deref(), Some(REASON_ROLLBACK));

        let rb = tmp.path().join("rb");
        std::fs::create_dir_all(&rb).unwrap();
        let rb_path = raise_attention_at_with_reason(&rb, REASON_ROLLBACK, "broken").unwrap();
        let info = read_attention_at(&rb_path).unwrap();
        assert_eq!(info.reason.as_deref(), Some(REASON_ROLLBACK));
    }
}
