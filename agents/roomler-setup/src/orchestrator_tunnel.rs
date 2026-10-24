// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Tunnel-client install orchestrator (`cmd_install` with
//! [`Role::TunnelClient`]).
//!
//! Relocated (P4a) from the legacy tunnel wizard's
//! install_orchestrator.rs (crate retired in P4c-2) with these
//! adaptations: unified
//! `wizard_shared::progress::ProgressEvent` wire shape, mechanics via
//! `wizard_shared::{asset_resolver, extract, integration,
//! tunnel_enroll}` called directly with this app's identity
//! ([`crate::proxy`]), and the process-wide statics in [`crate`].
//! Pipeline behaviour (step order, error strings, cancel-check
//! points) is preserved verbatim.
//!
//! Owns the 6-step pipeline:
//!
//!   1. Preflight: detect existing tunnel-client install (probe the
//!      config.toml at the platform-default path).
//!   2. Resolve archive metadata via `/api/tunnel/installer/<platform>/health`.
//!   3. Stream archive bytes to `%TEMP%` with progress emits.
//!   4. Verify SHA256.
//!   5. Extract into per-user install dir; locate the CLI binary.
//!   6. Integrate (PATH on Windows, symlink on Unix); enroll via
//!      `/api/tunnel-client/enroll`; write config.toml.
//!
//! ## Cancel
//!
//! Cancellation is a per-await-point flag flip on the shared
//! [`crate::CANCEL_REQUESTED`]: each step calls `check_cancel()`
//! before the next async op, and the download step passes the REAL
//! flag into `wizard_shared::asset_resolver::download` so a cancel
//! also aborts an in-flight download between chunks. There's no
//! "force-kill" equivalent of the daemon orchestrator's msiexec
//! hammer — the tunnel pipeline owns its own threads + descriptors,
//! so the cancel flag is sufficient to unwind cleanly.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use anyhow::Context;
use roomler_ai_remote_control::setup_diagnostics::{ErrorCode, Step};
use tauri::ipc::Channel;
use wizard_shared::asset_resolver;
use wizard_shared::extract;
use wizard_shared::integration;
use wizard_shared::progress::{ProgressEvent, replay_log};
use wizard_shared::tunnel_enroll::{self, EnrollResult};

use crate::commands::DoneReport;
use crate::diagnostics::{Diagnostics, cancel_requested, enroll_error_code, failed};
use crate::role::Role;

/// Drive a full tunnel-client install end-to-end. Streams
/// ProgressEvent over the channel; mirrors every emit into the replay
/// log so a late-attached SPA listener catches up via
/// `cmd_install_progress_replay`.
pub async fn run_install(
    role: Role,
    server: String,
    token: String,
    device_name: String,
    on_event: Channel<ProgressEvent>,
) -> Result<DoneReport, String> {
    // Reset state for a fresh run. CANCEL_REQUESTED stays cleared
    // unless the operator hits Cancel mid-flow.
    crate::INSTALL_IN_PROGRESS.store(true, Ordering::SeqCst);
    crate::CANCEL_REQUESTED.store(false, Ordering::SeqCst);
    replay_log().reset();

    // FR-102 P3b — the server is known from here, read the way the enroll
    // below reads it (FR-101 P1b's TLS rule): the pages' buffered
    // boundaries flush to it and every step reports as it ends — only if
    // the Welcome box was ticked.
    let diag = Diagnostics::global();
    diag.server_known(&roomler_cli::config::enrollment_server_url(&server));
    diag.pipeline_started();

    let outcome = run_install_inner(role, server, token, device_name, &on_event).await;

    crate::INSTALL_IN_PROGRESS.store(false, Ordering::SeqCst);

    match outcome {
        Ok(r) => Ok(r),
        Err(e) => {
            // A step every error site closes itself; this catches one that
            // did not, so the run's last step is never left unrecorded.
            diag.abandon(ErrorCode::Other, cancel_requested());
            // Echo terminal failures into both the channel + the
            // replay log so a late-attached SPA listener sees them.
            emit(
                &on_event,
                ProgressEvent::Error {
                    step: "install".to_string(),
                    message: e.clone(),
                },
            );
            Err(e)
        }
    }
}

async fn run_install_inner(
    role: Role,
    server: String,
    token: String,
    device_name: String,
    on_event: &Channel<ProgressEvent>,
) -> Result<DoneReport, String> {
    emit(on_event, ProgressEvent::Started);
    let diag = Diagnostics::global();

    // --- Step 1: preflight -----------------------------------------------
    diag.begin(Step::Preflight);
    check_cancel()?;
    emit(on_event, ProgressEvent::PreflightStarted);
    let existing_label = detect_existing_install_label();
    emit(
        on_event,
        ProgressEvent::PreflightOk {
            existing: existing_label,
        },
    );
    diag.ok();

    // --- Step 2: resolve archive ---------------------------------------
    diag.begin(Step::Resolve);
    check_cancel()?;
    let platform = asset_resolver::current_platform().to_string();
    if platform == "unsupported" {
        return Err(failed(
            ErrorCode::UnsupportedPlatform,
            format!(
                "tunnel client is not supported on this OS+arch combination ({} / {})",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        ));
    }
    emit(
        on_event,
        ProgressEvent::AssetResolving {
            artifact: platform.clone(),
        },
    );
    let health = asset_resolver::resolve(
        &crate::proxy::tunnel_base(&server),
        &platform,
        "latest",
        crate::proxy::USER_AGENT,
    )
    .await
    .map_err(|e| failed(ErrorCode::Resolve, format!("resolve installer: {e}")))?;
    emit(
        on_event,
        ProgressEvent::AssetResolved {
            tag: health.tag.clone(),
            size_bytes: health.size,
            digest: health.digest.clone(),
        },
    );
    diag.ok();

    // --- Step 3: download ----------------------------------------------
    diag.begin(Step::Download);
    check_cancel()?;
    emit(
        on_event,
        ProgressEvent::DownloadStarted {
            total_bytes: health.size,
        },
    );
    let staged = std::env::temp_dir()
        .join("roomler-setup")
        .join(&health.tag)
        .join(&health.filename);
    let center_base = crate::proxy::origin_of(&crate::proxy::tunnel_base(&server));
    let url = format!("{}{}", center_base, health.uri);
    let spec = asset_resolver::DownloadSpec {
        center_base: &center_base,
        url: &url,
        dest: &staged,
        user_agent: crate::proxy::USER_AGENT,
        artifact_label: "CLI archive",
    };
    let signature_url =
        asset_resolver::release_signature_url(&center_base, &health.tag, &health.filename)
            .map_err(|e| failed(ErrorCode::Download, format!("release signature URL: {e}")))?;
    let progress_emitter = on_event.clone();
    asset_resolver::download_signed(
        &spec,
        &signature_url,
        &crate::CANCEL_REQUESTED,
        roomlerd::pgp_verify::verify_release_artifact,
        move |received| {
            // DownloadProgress fires many times per MB; skip the replay
            // log mirror — the SPA's live listener catches the stream.
            let _ = progress_emitter.send(ProgressEvent::DownloadProgress {
                received_bytes: received,
            });
        },
    )
    .await
    .map_err(|e| failed(ErrorCode::Download, format!("download installer: {e}")))?;
    diag.ok();

    // --- Step 4: verify SHA256 ------------------------------------------
    diag.begin(Step::Verify);
    check_cancel()?;
    let sha256_match = match health.digest.as_deref() {
        Some(digest) => asset_resolver::verify_sha256(&staged, digest)
            .map_err(|e| failed(ErrorCode::Other, format!("sha256 verify: {e}")))?,
        None => {
            tracing::warn!(
                tag = %health.tag,
                "wizard archive lacks sha256 digest — skipping verification"
            );
            true
        }
    };
    emit(on_event, ProgressEvent::DownloadVerified { sha256_match });
    if !sha256_match {
        let _ = std::fs::remove_file(&staged);
        return Err(failed(
            ErrorCode::Sha256Mismatch,
            format!(
                "SHA256 mismatch for {} — staged file deleted; please retry",
                staged.display()
            ),
        ));
    }
    diag.ok();

    // --- Step 5: extract -------------------------------------------------
    diag.begin(Step::Extract);
    check_cancel()?;
    emit(
        on_event,
        ProgressEvent::ExtractStarted {
            archive: staged.display().to_string(),
        },
    );
    let install_root = default_install_root()
        .map_err(|e| failed(ErrorCode::Extract, format!("install root: {e}")))?;
    extract::extract_archive(&staged, &install_root)
        .map_err(|e| failed(ErrorCode::Extract, format!("extract archive: {e}")))?;
    let tunnel_binary = extract::find_tunnel_binary(&install_root)
        .map_err(|e| failed(ErrorCode::Extract, format!("locate tunnel binary: {e}")))?;
    emit(
        on_event,
        ProgressEvent::ExtractDone {
            tunnel_binary: tunnel_binary.display().to_string(),
        },
    );
    diag.ok();

    // --- Step 6: integrate + enroll -------------------------------------
    diag.begin(Step::Integrate);
    check_cancel()?;
    emit(on_event, ProgressEvent::IntegrationStarted);
    let integration_report = integration::integrate(&install_root, &tunnel_binary)
        .map_err(|e| failed(ErrorCode::Integrate, format!("integrate: {e}")))?;
    emit(
        on_event,
        ProgressEvent::IntegrationDone {
            path_updated: integration_report.path_updated,
            shortcut_created: integration_report.shortcut_created,
        },
    );
    diag.ok();

    diag.begin(Step::Enroll);
    check_cancel()?;
    emit(on_event, ProgressEvent::EnrollStarted);
    // FR-101 P1b — the token travels over TLS, as `roomler enroll` sends it:
    // a remote `http://` is posted to, and saved, as `https://`.
    let server = roomler_cli::config::enrollment_server_url(&server);
    // The wizard's own crate version is the closest stand-in for the
    // CLI's wire-reported "client_version" — by build-time both
    // crates share workspace.version so the value is consistent.
    let result = tunnel_enroll::enroll(
        &server,
        &token,
        &device_name,
        env!("CARGO_PKG_VERSION"),
        crate::proxy::USER_AGENT,
    )
    .await
    .map_err(|e| failed(enroll_error_code(&e), format!("enrollment: {e}")))?;
    let config_path = write_config(&result, None)
        .map_err(|e| failed(ErrorCode::ConfigWrite, format!("write config: {e}")))?;
    emit(
        on_event,
        ProgressEvent::EnrollOk {
            principal_kind: "tunnel_client".into(),
            principal_id: result.tunnel_client_id.clone(),
            tenant_id: result.tenant_id.clone(),
        },
    );
    diag.ok();

    // --- Step 7: done ----------------------------------------------------
    emit(on_event, ProgressEvent::Done);
    diag.done();

    Ok(DoneReport {
        principal_kind: "tunnel_client".to_string(),
        principal_id: result.tunnel_client_id,
        tenant_id: result.tenant_id,
        tag: health.tag,
        role,
        flavour: None,
        binary_path: Some(integration_report.binary_path.display().to_string()),
        config_path: Some(config_path.display().to_string()),
        path_updated: Some(integration_report.path_updated),
        shortcut_created: Some(integration_report.shortcut_created),
        // Daemon-role concept ("the MSI also delivered the CLI") —
        // not applicable when the CLI IS the install.
        cli_included: None,
        // roomler-desktop is a daemon-role companion; the tunnel role
        // doesn't place it.
        desktop_installed: None,
        // FR-104 — a tunnel client has no SYSTEM service to anchor.
        anchored: None,
    })
}

/// Persist the enroll result to the tunnel CLI's config path. Returns
/// the path written so the orchestrator can surface it in the Done
/// step. Thin `roomler_cli`-coupled half of enrollment (the HTTP
/// half lives in `wizard_shared::tunnel_enroll` — the shared core
/// stays free of the tunnel dep).
///
/// `override_path` lets unit tests redirect the write to a tempdir
/// without touching the operator's real %APPDATA% layout.
fn write_config(result: &EnrollResult, override_path: Option<&Path>) -> anyhow::Result<PathBuf> {
    let cfg = roomler_cli::config::TunnelConfig {
        server_url: result.server_url.clone(),
        tunnel_client_token: result.tunnel_client_token.clone(),
        machine_name: result.machine_name.clone(),
        allow_plaintext_server: false,
    };
    let path =
        roomler_cli::config::save(&cfg, override_path).context("writing tunnel config.toml")?;
    Ok(path)
}

fn emit(channel: &Channel<ProgressEvent>, event: ProgressEvent) {
    // Replay log first so a late-attaching listener can catch up via
    // cmd_install_progress_replay; channel send is best-effort
    // (errs only when the receiver has been closed = SPA moved on).
    replay_log().push(event.clone());
    let _ = channel.send(event);
}

fn check_cancel() -> Result<(), String> {
    if crate::CANCEL_REQUESTED.load(Ordering::SeqCst) {
        // P3b — the step that was about to run (opened just before this
        // check) ends `cancelled`.
        Diagnostics::global().cancelled();
        Err("install cancelled by operator".to_string())
    } else {
        Ok(())
    }
}

/// Probe the tunnel CLI's config path to surface "clean" vs "already
/// installed" on the Welcome step.
fn detect_existing_install_label() -> String {
    let Ok(path) = roomler_cli::config::default_config_path() else {
        return "clean".to_string();
    };
    if path.exists() {
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str::<roomler_cli::config::TunnelConfig>(&s).ok())
        {
            Some(cfg) => format!("installed ({} @ {})", cfg.machine_name, path.display()),
            None => format!("installed (config at {} unreadable)", path.display()),
        }
    } else {
        "clean".to_string()
    }
}

/// Resolve the per-user install dir. Windows:
// RETIRED-NAME-ANCHOR-BEGIN
// The install directory and the ProjectDirs segment below are the layout
// that ALREADY EXISTS on installed hosts, and the segment holds the enrolled
// credential on tunnel-only ones. Moving either is a migration, not a
// rename — see roomler-setup-core::integration, tracked as an FR-21 followup.
/// `%LOCALAPPDATA%\roomler\roomler-tunnel\Programs\roomler-tunnel`.
/// Linux: `~/.local/opt/roomler-tunnel`. macOS:
/// `~/Applications/RoomlerTunnel`.
///
/// The `ROOMLER_TUNNEL_WIZARD_INSTALL_ROOT` env override is kept
/// verbatim from the legacy wizard so tests (and any staged fixture)
/// can substitute a tempdir.
pub fn default_install_root() -> anyhow::Result<PathBuf> {
    if let Ok(override_path) = std::env::var("ROOMLER_TUNNEL_WIZARD_INSTALL_ROOT") {
        return Ok(PathBuf::from(override_path));
    }
    #[cfg(target_os = "windows")]
    {
        let dirs = directories::ProjectDirs::from("ai", "roomler", "roomler-tunnel")
            .ok_or_else(|| anyhow::anyhow!("no Windows local-app-data dir resolvable"))?;
        // ProjectDirs::data_local_dir on Windows returns
        // %LOCALAPPDATA%\roomler\roomler-tunnel — close enough; we
        // append `Programs` for clarity in the UI ("look under
        // Programs\roomler-tunnel"). Same dir is used for the .lnk
        // shortcut target in Phase B.
        Ok(dirs
            .data_local_dir()
            .join("Programs")
            // RETIRED-NAME-ANCHOR: the tunnel wizard's per-user INSTALL dir.
            //
            // ⚠️ FR-46 CORRECTION. This anchor used to read "the tunnel CLI's
            // enrolled-config segment; see agents/roomler-cli/src/config.rs.
            // Frozen together." That reason is false, and it mattered, because it
            // described this rename as blocked on a CREDENTIAL migration it is not
            // blocked on. They are independent call sites: the credential resolves
            // through `ProjectDirs::config_dir()`, this resolves through
            // `data_local_dir()`, and nothing derives the config path from the
            // binary's location — so renaming this directory cannot orphan an
            // enrollment. The config segment IS frozen, for its own reason, and
            // carries its own anchor.
            //
            // What actually blocks it is smaller and different, and both halves
            // are real: (1) a pre-rename install strands a stale HKCU PATH entry,
            // and PATH ORDER decides which `roomler.exe` wins — so the rename
            // needs a `remove_user_path_segment` beside it, exactly as the Unix
            // arm needed `retire_legacy_symlink`; (2) the retired name appears
            // TWICE on this path — the ProjectDirs application segment and this
            // leaf — so finishing it is a layout decision, not a string swap.
            // docs/fr/FR-46
            .join("roomler-tunnel"))
    }
    #[cfg(target_os = "linux")]
    {
        let dirs = directories::UserDirs::new()
            .ok_or_else(|| anyhow::anyhow!("no Linux home dir resolvable"))?;
        Ok(dirs
            .home_dir()
            .join(".local")
            .join("opt")
            .join("roomler-tunnel"))
    }
    #[cfg(target_os = "macos")]
    {
        let dirs = directories::UserDirs::new()
            .ok_or_else(|| anyhow::anyhow!("no macOS home dir resolvable"))?;
        Ok(dirs.home_dir().join("Applications").join("RoomlerTunnel"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(anyhow::anyhow!("install root not defined for this OS"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NB: no `request_cancel` twin test here — the legacy tunnel
    // wizard had one, but CANCEL_REQUESTED is now a process-wide
    // static shared with orchestrator_agent, and two parallel tests
    // swapping the same atomic race. The single lock lives in
    // orchestrator_agent::tests::request_cancel_then_check_cancel_returns_err.

    #[test]
    fn write_config_creates_file_at_override_path() {
        use tempfile::TempDir;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        let r = EnrollResult {
            tunnel_client_id: "507f1f77bcf86cd799439011".to_string(),
            tenant_id: "507f191e810c19729de860ea".to_string(),
            tunnel_client_token: "tok".to_string(),
            server_url: "https://roomler.ai".to_string(),
            machine_name: "lap".to_string(),
        };
        let written = write_config(&r, Some(&path)).unwrap();
        assert_eq!(written, path);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("server_url"));
        assert!(contents.contains("tunnel_client_token"));
        assert!(contents.contains("lap"));
        // Token bytes themselves should be present too (we wrote them).
        assert!(contents.contains("tok"));
    }

    #[test]
    fn default_install_root_respects_env_override() {
        // SAFETY: this test mutates a process-wide env var; it is the
        // only test in this crate touching
        // ROOMLER_TUNNEL_WIZARD_INSTALL_ROOT, and it restores the
        // previous value before asserting.
        let saved = std::env::var("ROOMLER_TUNNEL_WIZARD_INSTALL_ROOT").ok();
        // SAFETY: process-wide env mutation is OK here — the test is
        // self-contained and restores the previous value below.
        unsafe { std::env::set_var("ROOMLER_TUNNEL_WIZARD_INSTALL_ROOT", "/tmp/wizard-tests") };
        let resolved = default_install_root().unwrap();
        // Restore BEFORE assert so a panic doesn't leak the override.
        match saved {
            Some(v) => unsafe { std::env::set_var("ROOMLER_TUNNEL_WIZARD_INSTALL_ROOT", v) },
            None => unsafe { std::env::remove_var("ROOMLER_TUNNEL_WIZARD_INSTALL_ROOT") },
        }
        assert_eq!(resolved, PathBuf::from("/tmp/wizard-tests"));
    }

    #[test]
    fn detect_existing_install_label_returns_clean_or_installed() {
        // Test box may have a real %APPDATA%\roomler\roomler-tunnel\
        // config.toml from a prior run; we can't unconditionally
        // assert "clean" here. The contract is just "returns a non-
        // empty human label" — and the value falls into the small set
        // of expected prefixes.
        let label = detect_existing_install_label();
        assert!(
            label == "clean" || label.starts_with("installed ("),
            "unexpected label: {label:?}"
        );
    }
}
// RETIRED-NAME-ANCHOR-END
