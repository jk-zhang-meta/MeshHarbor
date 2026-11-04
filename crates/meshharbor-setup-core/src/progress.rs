// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Unified install-progress events for the `meshharbor-setup` app.
//!
//! P4a DESIGN NOTE: this is the ONE wire shape the unified wizard's
//! SPA consumes. The two legacy wizards keep their OWN (frozen)
//! `ProgressEvent` enums in their own crates — the agent wizard's
//! `tag="kind"`/snake_case and the tunnel wizard's
//! `tag="type",content="data"`/PascalCase forks stay byte-identical
//! there until P4c retires them. Nothing re-exports THIS enum into
//! the legacy crates.
//!
//! Wire style: the tunnel wizard's convention won — adjacently
//! tagged (`{"type":"Started","data":null}` /
//! `{"type":"DownloadProgress","data":{"receivedBytes":12345}}`)
//! with camelCase payload fields.
//!
//! Vocabulary: the UNION of both legacy pipelines' LIVE variants —
//! 20 total. The agent wizard's `EnvVarWriting`/`EnvVarSet`/
//! `ServiceRestarting`/`ServiceRestarted` are deliberately NOT
//! imported: they have had zero emit sites since rc.44 moved the
//! SystemContext env-var + service-restart work into the WiX custom
//! action (their failure surface is `SystemContextError`).
//!
//! ## Why both a Channel AND a replay log
//!
//! Tauri 2's `ipc::Channel<T>` is the primary delivery path —
//! guaranteed ordering, no drops between Rust → JS once the front-
//! end attaches the listener. BUT events emitted by `cmd_install`
//! BEFORE the SPA's listener finishes attaching are not delivered.
//! [`ReplayLog`] mirrors every emit (minus per-chunk download ticks)
//! into an in-Rust `Vec` so the SPA can call the replay command on
//! first listener attach and fast-forward through anything it missed.

use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// One step transition in the unified install pipeline.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data", rename_all = "PascalCase")]
pub enum ProgressEvent {
    /// `cmd_install` started executing. Sent before any disk/network
    /// IO so the SPA can flip to the Install step UI.
    Started,

    /// Pre-flight probe (registry and/or config-file) began.
    PreflightStarted,
    /// Pre-flight finished. `existing` is a human-readable detection
    /// summary, e.g. `"clean"` / `"Detected: perUser 0.3.0-rc.194"`.
    #[serde(rename_all = "camelCase")]
    PreflightOk { existing: String },
    /// Non-fatal warning surfaced during pre-flight (cross-flavour
    /// switch, ambiguous install, reinstall-over-existing, …). SPA
    /// renders inline; install still proceeds.
    PreflightWarning { message: String },

    /// Resolving the artifact URL via the meshharbor.itachi.fans installer proxy.
    /// `artifact` is the discriminator being resolved — an MSI
    /// flavour (`"permachine"`) for daemon roles, a platform string
    /// (`"windows-x86_64"`) for the tunnel-client role.
    #[serde(rename_all = "camelCase")]
    AssetResolving { artifact: String },
    /// Asset resolved. `tag` is the GitHub tag the wizard pins to;
    /// `size_bytes` feeds the download progress bar's denominator.
    #[serde(rename_all = "camelCase")]
    AssetResolved {
        tag: String,
        size_bytes: u64,
        digest: Option<String>,
    },

    /// Download stream opened. `total_bytes` mirrors `size_bytes`
    /// from `AssetResolved` for SPA convenience.
    #[serde(rename_all = "camelCase")]
    DownloadStarted { total_bytes: u64 },
    /// One progress tick during download. Fires roughly per 64 KiB
    /// chunk; the SPA throttles UI updates client-side. NOT mirrored
    /// into the replay log.
    #[serde(rename_all = "camelCase")]
    DownloadProgress { received_bytes: u64 },
    /// Download complete; SHA256 verified (or `digest=None` and
    /// verification was skipped with `sha256_match=true`).
    #[serde(rename_all = "camelCase")]
    DownloadVerified { sha256_match: bool },

    /// msiexec launched (daemon roles, Windows). `pid` is the OS PID
    /// for operator diagnostics. SPA relabels Cancel to "Force-kill
    /// installer" once this fires.
    #[serde(rename_all = "camelCase")]
    MsiSpawned { pid: u32 },
    /// msiexec exited. `code` is the raw OS exit code; `decoded` is
    /// the human-friendly form from `msi_runner::decode_msi_exit`.
    #[serde(rename_all = "camelCase")]
    MsiCompleted { code: i32, decoded: String },

    /// Archive extraction phase started (tunnel-client role).
    #[serde(rename_all = "camelCase")]
    ExtractStarted { archive: String },
    /// Extraction complete; `tunnel_binary` is the absolute path of
    /// the located CLI executable.
    #[serde(rename_all = "camelCase")]
    ExtractDone { tunnel_binary: String },

    /// Per-platform integration (PATH / symlink) begun (tunnel-client
    /// role).
    IntegrationStarted,
    /// Integration finished. The flags let the SPA render an honest
    /// "what we did" summary.
    #[serde(rename_all = "camelCase")]
    IntegrationDone {
        path_updated: bool,
        shortcut_created: bool,
    },

    /// Enrollment request kicked off (agent enroll for daemon roles,
    /// `POST /api/tunnel-client/enroll` for the tunnel-client role).
    EnrollStarted,
    /// Enrollment succeeded. `principal_kind` is `"agent"` or
    /// `"tunnel_client"`; `principal_id` is the hex ObjectId of the
    /// enrolled row; both surface on the Done step.
    #[serde(rename_all = "camelCase")]
    EnrollOk {
        principal_kind: String,
        principal_id: String,
        tenant_id: String,
    },

    /// FR-104 — the elevated `meshharbord anchor create` started: the token may
    /// also anchor the device it just enrolled, and Windows shows a second
    /// administrator prompt for it.
    AnchorStarted,
    /// FR-104 — the device is anchored: commands can run as SYSTEM through
    /// its service.
    AnchorOk,
    /// FR-104 — the anchor step did not anchor the device. Never fatal: the
    /// install is complete and enrolled, and the Done page carries the manual
    /// command. `reason` is for the operator and never carries the token.
    #[serde(rename_all = "camelCase")]
    AnchorSkipped { reason: String },

    /// Whole install finished. SPA transitions to the Done step.
    Done,

    /// Fatal error at some step. SPA surfaces the recovery panel
    /// scoped to `step` (`"preflight"` / `"resolve"` / `"download"` /
    /// `"msi"` / `"extract"` / `"integration"` / `"enroll"`).
    Error { step: String, message: String },

    /// Daemon SystemContext role only: a WiX `EnableSystemContext` /
    /// `DisableSystemContext` custom action failed inside msiexec.
    /// The wizard reads the agent's last-attempt breadcrumb file and
    /// surfaces an actionable error scoped to the failing `stage`
    /// (`env_var_write` / `service_restart` / `unknown`); `hint` is
    /// an operator-actionable next step.
    #[serde(rename_all = "camelCase")]
    SystemContextError {
        stage: String,
        message: String,
        hint: String,
    },
}

/// Process-wide replay log. Every emit lands here (minus per-chunk
/// download ticks) so a late-attaching SPA listener catches up;
/// `reset` clears the log at the start of each install run.
pub struct ReplayLog {
    inner: Mutex<Vec<ProgressEvent>>,
}

impl Default for ReplayLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayLog {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
        }
    }

    /// Append one event. Per-chunk `DownloadProgress` ticks are
    /// skipped to keep the replay small (the live Channel carries
    /// them; only the terminal `DownloadVerified` is replayed).
    /// Lock-poisoning is recovered, not propagated — a panicking
    /// task that previously held the lock shouldn't lose events.
    pub fn push(&self, event: ProgressEvent) {
        if matches!(event, ProgressEvent::DownloadProgress { .. }) {
            return;
        }
        match self.inner.lock() {
            Ok(mut g) => g.push(event),
            Err(p) => {
                tracing::warn!("replay log mutex poisoned; recovering");
                p.into_inner().push(event);
            }
        }
    }

    /// Snapshot of all replayable events emitted so far.
    pub fn snapshot(&self) -> Vec<ProgressEvent> {
        match self.inner.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Clear the log at the start of a fresh install.
    pub fn reset(&self) {
        match self.inner.lock() {
            Ok(mut g) => g.clear(),
            Err(p) => p.into_inner().clear(),
        }
    }
}

/// Singleton accessor for the process-wide replay log.
pub fn replay_log() -> &'static ReplayLog {
    static LOG: OnceLock<ReplayLog> = OnceLock::new();
    LOG.get_or_init(ReplayLog::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn started_serialises_with_type_tag() {
        let json = serde_json::to_string(&ProgressEvent::Started).unwrap();
        assert!(json.contains(r#""type":"Started""#), "got {json}");
    }

    #[test]
    fn download_progress_uses_camel_case_payload_under_data() {
        let event = ProgressEvent::DownloadProgress {
            received_bytes: 1024,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""type":"DownloadProgress""#), "got {json}");
        assert!(
            json.contains(r#""data":{"receivedBytes":1024}"#),
            "got {json}"
        );
    }

    #[test]
    fn asset_resolving_carries_unified_artifact_field() {
        let event = ProgressEvent::AssetResolving {
            artifact: "permachine".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""artifact":"permachine""#), "got {json}");
    }

    #[test]
    fn enroll_ok_carries_principal_fields_camel_case() {
        let event = ProgressEvent::EnrollOk {
            principal_kind: "tunnel_client".to_string(),
            principal_id: "507f1f77bcf86cd799439011".to_string(),
            tenant_id: "507f191e810c19729de860ea".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains(r#""principalKind":"tunnel_client""#),
            "got {json}"
        );
        assert!(
            json.contains(r#""principalId":"507f1f77bcf86cd799439011""#),
            "got {json}"
        );
        assert!(
            json.contains(r#""tenantId":"507f191e810c19729de860ea""#),
            "got {json}"
        );
    }

    #[test]
    fn msi_completed_serialises_code_and_decoded() {
        let event = ProgressEvent::MsiCompleted {
            code: 1602,
            decoded: "UserCancel".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""type":"MsiCompleted""#), "got {json}");
        assert!(json.contains(r#""code":1602"#), "got {json}");
        assert!(json.contains(r#""decoded":"UserCancel""#), "got {json}");
    }

    #[test]
    fn system_context_error_serialises_stage_message_hint() {
        let event = ProgressEvent::SystemContextError {
            stage: "env_var_write".to_string(),
            message: "boom".to_string(),
            hint: "rerun restart-service".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""stage":"env_var_write""#), "got {json}");
        assert!(
            json.contains(r#""hint":"rerun restart-service""#),
            "got {json}"
        );
    }

    /// FR-104 — the anchor step's events, as the SPA reads them.
    #[test]
    fn anchor_events_serialise_with_their_reason() {
        let started = serde_json::to_string(&ProgressEvent::AnchorStarted).unwrap();
        assert!(
            started.contains(r#""type":"AnchorStarted""#),
            "got {started}"
        );
        let skipped = serde_json::to_string(&ProgressEvent::AnchorSkipped {
            reason: "the administrator prompt was declined".to_string(),
        })
        .unwrap();
        assert!(
            skipped.contains(r#""type":"AnchorSkipped""#),
            "got {skipped}"
        );
        assert!(
            skipped.contains(r#""reason":"the administrator prompt was declined""#),
            "got {skipped}"
        );
    }

    #[test]
    fn replay_log_skips_download_progress() {
        let log = ReplayLog::new();
        log.push(ProgressEvent::Started);
        log.push(ProgressEvent::DownloadProgress { received_bytes: 1 });
        log.push(ProgressEvent::DownloadProgress { received_bytes: 2 });
        log.push(ProgressEvent::Done);
        let snap = log.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(matches!(snap[0], ProgressEvent::Started));
        assert!(matches!(snap[1], ProgressEvent::Done));
    }

    #[test]
    fn replay_log_reset_clears() {
        let log = ReplayLog::new();
        log.push(ProgressEvent::Started);
        log.reset();
        assert!(log.snapshot().is_empty());
    }

    #[test]
    fn snapshot_is_a_copy_not_a_lock() {
        let log = ReplayLog::new();
        log.push(ProgressEvent::Started);
        let snap = log.snapshot();
        log.push(ProgressEvent::Done);
        assert_eq!(snap.len(), 1);
        assert_eq!(log.snapshot().len(), 2);
    }

    #[test]
    fn replay_log_singleton() {
        let a = replay_log();
        let b = replay_log();
        assert!(std::ptr::eq(a, b));
    }
}
