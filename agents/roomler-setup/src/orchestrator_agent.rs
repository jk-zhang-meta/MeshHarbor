// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Daemon-role install orchestrator (`cmd_install` with a daemon
//! [`Role`]) + force-kill plumbing.
//!
//! Relocated (P4a) from the legacy agent wizard's
//! install_orchestrator.rs (rc.28 W6b pipeline; crate retired in
//! P4c-2) with these adaptations: unified
//! `wizard_shared::progress::ProgressEvent` wire shape, mechanics via
//! `wizard_shared::{asset_resolver, msi_runner}` called directly with
//! this app's identity ([`crate::proxy`]), the process-wide statics in
//! [`crate`], and the typed [`Role`] replacing the SPA flavour string.
//! Pipeline behaviour (step order, error strings, cancel-check
//! points, the 15-min MSI wait budget) is preserved verbatim.
//!
//! Owns the 7-step pipeline:
//!
//!   1. Preflight: probe registry, surface cross-flavour warnings
//!   2. Resolve installer metadata via the roomler.ai proxy (rc.27)
//!   3. Stream MSI bytes to `%TEMP%` with progress emits
//!   4. Verify SHA256
//!   5. Spawn msiexec via `roomlerd::updater::
//!      spawn_installer_for_flavour_with_properties` (perMachine gets
//!      UAC via ShellExecuteExW + verb=runas)
//!   6. Attach `MsiRunner` to the spawned PID + wait for exit (caller's
//!      Tauri-future cancel propagates through 250 ms-slice polling)
//!   7. Enroll the agent against the configured server, persist
//!      `config.toml`. Emits `EnrollOk` then `Done`.
//!
//! ## Cancel + force-kill
//!
//! Two cancellation modes, surfaced by separate commands per the
//! rc.28 plan's H4 split:
//!   - `cmd_cancel_in_progress` flips [`crate::CANCEL_REQUESTED`] —
//!     the orchestrator checks the flag at each await point and bails
//!     with "install cancelled by operator". Polite, leaves no
//!     residue. Unlike the legacy wizard, the download step passes
//!     the REAL flag into `wizard_shared::asset_resolver::download`,
//!     so a cancel also aborts an in-flight download between chunks.
//!   - `cmd_force_kill_msi` calls `TerminateProcess(pid)` on the
//!     stored [`crate::ACTIVE_MSI_PID`]. May leave a partial MSI
//!     install; the SPA warns the operator before exposing this
//!     button.

use std::sync::atomic::Ordering;
use std::time::Duration;

use roomler_ai_remote_control::setup_diagnostics::{ErrorCode, Step};
use roomlerd::install_detect::{ExistingInstall, detect_existing_install};
use roomlerd::updater::{WindowsInstallFlavour, spawn_installer_for_flavour_with_properties};
use tauri::ipc::Channel;
use wizard_shared::asset_resolver;
use wizard_shared::msi_runner::{MsiExitDecoded, MsiRunner};
use wizard_shared::progress::{ProgressEvent, replay_log};

use crate::commands::DoneReport;
use crate::diagnostics::{Diagnostics, cancel_requested, enroll_error_code, failed};
use crate::role::Role;

/// S2 — optional advanced daemon options from the wizard's collapsed
/// "Advanced options" section, written into the enrolled config.toml
/// right where the orchestrator saves it. `None`/empty fields keep the
/// agent's defaults; route lists are validated BEFORE the MSI runs so a
/// typo can't burn the single-use enrollment token.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AdvancedOptions {
    pub overlay_enabled: Option<bool>,
    pub advertise_local_subnets: Option<bool>,
    pub auto_grant_session: Option<bool>,
    /// Comma-separated CIDRs → `overlay_advertised_routes`.
    pub overlay_advertised_routes: Option<String>,
    /// Comma-separated CIDRs → `advertise_routes` (tunnel/SOCKS mesh).
    pub advertise_routes: Option<String>,
}

impl AdvancedOptions {
    /// The two free-text route lists, with empties normalised away —
    /// shared by pre-MSI validation and the post-enroll apply.
    fn route_fields(&self) -> [(&'static str, Option<&str>); 2] {
        fn norm(v: &Option<String>) -> Option<&str> {
            v.as_deref().map(str::trim).filter(|s| !s.is_empty())
        }
        [
            (
                "overlay_advertised_routes",
                norm(&self.overlay_advertised_routes),
            ),
            ("advertise_routes", norm(&self.advertise_routes)),
        ]
    }

    /// Fail fast on bad route CIDRs (called pre-MSI). Bool options
    /// can't be invalid.
    fn validate(&self) -> Result<(), String> {
        for (key, val) in self.route_fields() {
            if let Some(v) = val {
                roomlerd::config_surface::validate_cidr_list(v)
                    .map_err(|e| format!("advanced option {key}: {e}"))?;
            }
        }
        Ok(())
    }

    /// FR-84 S2 — resolve the options the SPA left unset from the install
    /// flavour, before [`Self::apply_to`]. Today that is one key: the
    /// overlay follows the flavour (see [`overlay_enabled_default`]). The
    /// SPA sends the box as the operator saw it, so this is a belt for a
    /// caller that never sent the field — and a second place the default
    /// is written down, next to the one that consumes it.
    fn with_flavour_defaults(mut self, flavour: WindowsInstallFlavour) -> Self {
        self.overlay_enabled = overlay_enabled_default(self.overlay_enabled, flavour);
        self
    }

    /// Write the selected options into the freshly-enrolled config via
    /// the same per-key registry the desktop editor uses.
    fn apply_to(&self, cfg: &mut roomlerd::config::AgentConfig) -> Result<(), String> {
        use roomlerd::config_surface::apply;
        let bools = [
            ("overlay_enabled", self.overlay_enabled),
            ("advertise_local_subnets", self.advertise_local_subnets),
            ("auto_grant_session", self.auto_grant_session),
        ];
        for (key, val) in bools {
            if let Some(v) = val {
                apply(cfg, key, Some(if v { "true" } else { "false" }))
                    .map_err(|e| format!("advanced option {key}: {e}"))?;
            }
        }
        for (key, val) in self.route_fields() {
            if let Some(v) = val {
                apply(cfg, key, Some(v)).map_err(|e| format!("advanced option {key}: {e}"))?;
            }
        }
        Ok(())
    }
}

/// Drive a full daemon install end-to-end. Streams ProgressEvent over
/// the channel; mirrors every emit into the replay log.
pub async fn run_install(
    role: Role,
    server: String,
    token: String,
    device_name: String,
    advanced: AdvancedOptions,
    on_event: Channel<ProgressEvent>,
) -> Result<DoneReport, String> {
    // Reset state for a fresh run. CANCEL_REQUESTED stays cleared
    // unless the operator hits Cancel mid-flow.
    crate::INSTALL_IN_PROGRESS.store(true, Ordering::SeqCst);
    crate::CANCEL_REQUESTED.store(false, Ordering::SeqCst);
    crate::ACTIVE_MSI_PID.store(0, Ordering::SeqCst);
    replay_log().reset();

    // FR-102 P3b — the server is known from here: the diagnostics go to
    // the server being enrolled into, exactly where the enroll's POST goes
    // (the same TLS rule, `enrollment::normalize_server_url`'s), so the
    // pages' buffered boundaries flush now and every step below reports
    // as it ends. Nothing is sent unless the Welcome box was ticked.
    let diag = Diagnostics::global();
    diag.server_known(&diagnostics_server(&server));
    diag.pipeline_started();

    // Outer Result so we can always clear INSTALL_IN_PROGRESS on
    // any exit path.
    let outcome = run_install_inner(role, server, token, device_name, advanced, &on_event).await;

    crate::INSTALL_IN_PROGRESS.store(false, Ordering::SeqCst);
    crate::ACTIVE_MSI_PID.store(0, Ordering::SeqCst);

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

/// FR-102 P3b — the origin the diagnostics are posted to: the server as the
/// enroll will reach it (a remote `http://` is upgraded to `https://`, a
/// loopback one left alone), without a trailing slash.
fn diagnostics_server(server: &str) -> String {
    roomler_ai_remote_control::server_url::secure(server, false)
        .url
        .trim_end_matches('/')
        .to_string()
}

async fn run_install_inner(
    role: Role,
    server: String,
    token: String,
    device_name: String,
    advanced: AdvancedOptions,
    on_event: &Channel<ProgressEvent>,
) -> Result<DoneReport, String> {
    emit(on_event, ProgressEvent::Started);
    let diag = Diagnostics::global();

    // --- Step 1: preflight -----------------------------------------------
    // (P3b: the step opens before the checks below, so a CIDR typo or a
    // cancel before any IO is a preflight outcome, not an unrecorded one.)
    diag.begin(Step::Preflight);
    check_cancel()?;

    // S2 — validate the advanced route lists FIRST: a CIDR typo must
    // fail here, before the MSI runs and before the single-use
    // enrollment token is burned.
    advanced
        .validate()
        .map_err(|e| failed(ErrorCode::AdvancedOptions, e))?;

    // --- Role → flavour (was: parse_flavour on the SPA string) ----------
    let flavour_str = role
        .msi_flavour()
        .ok_or_else(|| {
            failed(
                ErrorCode::UnsupportedPlatform,
                format!("role {role:?} has no MSI flavour — not a daemon role"),
            )
        })?
        .to_string();
    let (wfx, is_system_context) =
        flavour_parts(role).map_err(|e| failed(ErrorCode::UnsupportedPlatform, e))?;

    emit(on_event, ProgressEvent::PreflightStarted);
    let detected = detect_existing_install();
    let existing_label = label_existing(&detected);
    emit(
        on_event,
        ProgressEvent::PreflightOk {
            existing: existing_label.clone(),
        },
    );
    diag.ok();

    // Surface cross-flavour switch as a warning. The SPA gates the
    // Continue button on an operator-acknowledgement checkbox per
    // BLOCKER-7 of the rc.28 plan critique; by the time cmd_install
    // runs, that gate is passed.
    if let Some(warning) = cross_flavour_warning(&detected, &flavour_str) {
        emit(
            on_event,
            ProgressEvent::PreflightWarning { message: warning },
        );
    }

    // rc.44 SystemContext automation. The wizard passes the
    // ENABLE_SYSTEM_CONTEXT public property to msiexec; the WiX CA in
    // wix-perMachine/main.wxs (rc.44 P2) fires `EnableSystemContext`
    // when "1" and `DisableSystemContext` when "0". The agent's
    // composite subcommands (rc.44 P1.5) write a single-entry telemetry
    // record to %PROGRAMDATA%\roomler\last-system-context-attempt.json
    // that the wizard reads on MSI failure (rc.44 P3) to surface an
    // actionable error to the operator.
    //
    // perUser flavour: no property — wix/main.wxs doesn't declare it.
    // perMachine plain: ENABLE_SYSTEM_CONTEXT=0 (explicit) so the
    //   DisableSystemContext CA fires on a downgrade from SC-on host.
    // perMachine+SC: ENABLE_SYSTEM_CONTEXT=1.

    // --- Step 2: resolve installer ---------------------------------------
    diag.begin(Step::Resolve);
    check_cancel()?;
    let flavour_for_proxy = match wfx {
        WindowsInstallFlavour::PerUser => "peruser",
        WindowsInstallFlavour::PerMachine => "permachine",
    };
    emit(
        on_event,
        ProgressEvent::AssetResolving {
            artifact: flavour_for_proxy.to_string(),
        },
    );
    let health = asset_resolver::resolve(
        &crate::proxy::agent_base(&server),
        flavour_for_proxy,
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

    // --- Step 3: download ------------------------------------------------
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
    let center_base = crate::proxy::origin_of(&crate::proxy::agent_base(&server));
    let url = format!("{}{}", center_base, health.uri);
    let spec = asset_resolver::DownloadSpec {
        center_base: &center_base,
        url: &url,
        dest: &staged,
        user_agent: crate::proxy::USER_AGENT,
        artifact_label: "installer",
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
            // Skip the replay-log mirror here — DownloadProgress fires
            // hundreds of times per MB and would balloon the log. The
            // SPA's primary listener catches the live stream.
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
            // Pre-Oct-2024 releases lack the digest field. Accept
            // the PGP-authenticated download but flag the missing SHA digest.
            tracing::warn!(
                tag = %health.tag,
                "installer asset lacks sha256 digest — skipping verification"
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

    // --- Step 5: spawn msiexec ------------------------------------------
    //
    // Pass the OPERATOR-SELECTED flavour (mapped from the role picked
    // on the SPA's Welcome cards) explicitly. DO NOT delegate to
    // `spawn_installer_inner` — that classifies the wizard EXE's own
    // location via `current_install_flavour`, which always resolves
    // to PerUser inside the wizard (the EXE runs from wherever the
    // operator double-clicked, never `\Program Files\`). A perMachine
    // MSI launched on the perUser branch (`/qn`, no ShellExecuteExW
    // runas) gets rejected by Windows Installer with exit code 1625
    // ERROR_INSTALL_PACKAGE_REJECTED. Field repro 2026-05-15 on a
    // Windows field-test host; BLOCKER B6 from the rc.27/rc.28 master
    // plan.
    diag.begin(Step::Msi);
    check_cancel()?;
    // rc.44: build the property table from the parsed flavour.
    //   peruser              → no property (wix/main.wxs doesn't declare it)
    //   permachine plain     → ENABLE_SYSTEM_CONTEXT=0 (explicit, so the
    //                          WiX DisableSystemContext CA fires on a
    //                          downgrade from a SC-on host)
    //   permachine+SC        → ENABLE_SYSTEM_CONTEXT=1
    let properties: Vec<(&str, &str)> = match wfx {
        WindowsInstallFlavour::PerUser => Vec::new(),
        WindowsInstallFlavour::PerMachine => {
            vec![(
                "ENABLE_SYSTEM_CONTEXT",
                if is_system_context { "1" } else { "0" },
            )]
        }
    };
    let pid = spawn_installer_for_flavour_with_properties(&staged, wfx, &properties)
        .map_err(|e| failed(ErrorCode::MsiSpawn, format!("spawn msiexec: {e}")))?;
    crate::ACTIVE_MSI_PID.store(pid, Ordering::SeqCst);
    emit(on_event, ProgressEvent::MsiSpawned { pid });

    // --- Step 6: attach + wait + decode ----------------------------------
    let runner = MsiRunner::attach(pid)
        .map_err(|e| failed(ErrorCode::MsiWait, format!("attach msiexec: {e}")))?;
    // 15-min budget covers slow corporate disks + Defender scans.
    let outcome = runner
        .wait_for_exit(Duration::from_secs(15 * 60))
        .await
        .map_err(|e| failed(ErrorCode::MsiWait, format!("wait for msiexec: {e}")))?;
    let outcome_str = format!("{outcome:?}");
    emit(
        on_event,
        ProgressEvent::MsiCompleted {
            code: msi_exit_code(&outcome),
            decoded: outcome_str.clone(),
        },
    );

    match outcome {
        MsiExitDecoded::Success | MsiExitDecoded::RebootRequired => {
            // Carry on to enrollment. RebootRequired is OK because the
            // agent's first start can pick up the new install state
            // after the OS reboots; enrollment is just an HTTP call
            // that doesn't depend on the agent binary running.
            diag.ok();
        }
        MsiExitDecoded::UserCancel => {
            // rc.44: branch on is_system_context. SystemContext mode
            // REQUIRES perMachine + admin (SCM Environment write +
            // service restart), so "pick perUser mode" advice doesn't
            // apply — the operator must either get admin rights or
            // back off to plain perMachine.
            let msg = if is_system_context {
                "Installation cancelled (you clicked No on the UAC prompt). \
                 SystemContext mode requires admin rights — it writes to the \
                 service's Environment block and restarts the service. Try \
                 again and approve the UAC prompt, or pick plain perMachine \
                 mode (without SystemContext) if you only need user-context \
                 remote control."
            } else {
                "Installation cancelled (you clicked No on the UAC prompt). \
                 Try again or pick perUser mode if you can't get admin rights."
            };
            return Err(failed(ErrorCode::MsiUserCancel, msg.to_string()));
        }
        MsiExitDecoded::AnotherInstall => {
            return Err(failed(
                ErrorCode::MsiAnotherInstall,
                "Another Windows Installer operation is already running on this \
                 host. Wait for it to finish (check Get-Process msiexec), \
                 then click Retry."
                    .to_string(),
            ));
        }
        MsiExitDecoded::FatalError => {
            // rc.44: on SystemContext flavour, the WiX CA may have
            // failed inside the env-var write or service-restart
            // stage. The composite subcommand writes a single-entry
            // JSON to %PROGRAMDATA%\roomler\last-system-context-attempt.json
            // on every invocation; read it back to surface an
            // actionable error scoped to the failing stage.
            if is_system_context && let Some(attempt) = read_last_system_context_attempt() {
                emit(
                    on_event,
                    ProgressEvent::SystemContextError {
                        stage: attempt.stage,
                        message: attempt.message,
                        hint: attempt.hint,
                    },
                );
            }
            return Err(failed(
                ErrorCode::MsiFatal,
                "MSI installer failed (exit 1603). Check the MSI log at %TEMP%\\MSI*.LOG for details."
                    .to_string(),
            ));
        }
        MsiExitDecoded::Other(code) => {
            return Err(failed(
                ErrorCode::MsiOther,
                format!("MSI installer exited with unexpected code {code}"),
            ));
        }
    }

    // --- Step 7: enroll --------------------------------------------------
    diag.begin(Step::Enroll);
    check_cancel()?;
    emit(on_event, ProgressEvent::EnrollStarted);
    // rc.52: the SystemContext flavour writes its config to the
    // machine-global %PROGRAMDATA% path so the LocalSystem worker can
    // load it pre-logon. plain perMachine + perUser keep the per-user
    // %APPDATA% default. machine_id is derived from whichever path the
    // config is written to, so it stays internally consistent.
    //
    // rc.53 CI hotfix (fix to rc.52 tech debt): `machine_global_config_path`
    // is `#[cfg(target_os = "windows")]` in the agent crate, so the
    // workspace's Linux CI (`cargo clippy --workspace`) fails to build
    // this crate unless the call site is itself cfg-gated. The
    // SystemContext flavour is logically Windows-only — there is no
    // %PROGRAMDATA% on Linux/macOS — so a non-Windows fallback that
    // hard-errors is the right semantic (the daemon roles only ship
    // on Windows; this branch is unreachable in practice but keeps
    // the workspace buildable).
    let config_path = if is_system_context {
        #[cfg(target_os = "windows")]
        {
            roomlerd::config::machine_global_config_path()
        }
        #[cfg(not(target_os = "windows"))]
        {
            return Err(failed(
                ErrorCode::UnsupportedPlatform,
                "SystemContext flavour is Windows-only".to_string(),
            ));
        }
    } else {
        roomlerd::config::default_config_path()
            .map_err(|e| failed(ErrorCode::ConfigWrite, format!("resolve config path: {e}")))?
    };
    // rc.52: for the SystemContext flavour, lock down
    // %PROGRAMDATA%\roomler\ with an inheritable SYSTEM+Administrators
    // DACL BEFORE the config (carrying the Agent JWT) is written —
    // %PROGRAMDATA% is world-readable by default. The orchestrator
    // runs inside the wizard's already-elevated context so `icacls`
    // has the rights. Best-effort: a failure is logged + surfaced but
    // doesn't abort the install (the config still lands; the operator
    // can re-tighten). See harden_machine_global_dir.
    if is_system_context && let Err(e) = harden_machine_global_dir(&config_path) {
        emit(
            on_event,
            ProgressEvent::PreflightWarning {
                message: format!(
                    "could not restrict permissions on the machine-global \
                     config directory ({e}); the Agent token file may be \
                     readable by non-admin users until corrected"
                ),
            },
        );
    }
    let machine_id = roomlerd::machine::derive_machine_id(&config_path);
    // FR-102 P3 — the wizard says so itself, in-process: `wizard`, with the
    // scope its role installs (`Role::install_scope`). A daemon role always
    // has one; the `None` arm is the tunnel role, which never reaches here.
    // P3b — a ticked run's id rides along (`install.run`), so the device
    // joins its diagnostics; unticked, `run_id()` is `None` and nothing is
    // added to the body.
    let mut install = roomlerd::enrollment::InstallInfo::new(
        roomlerd::enrollment::InstallMethod::Wizard,
        role.install_scope()
            .unwrap_or(roomlerd::enrollment::InstallScope::Unknown),
    );
    install.run = diag.run_id();
    let inputs = roomlerd::enrollment::EnrollInputs {
        server_url: &server,
        enrollment_token: &token,
        machine_id: &machine_id,
        machine_name: &device_name,
        install: Some(install),
    };
    let mut cfg = roomlerd::enrollment::enroll(inputs)
        .await
        .map_err(|e| failed(enroll_error_code(&e), format!("enrollment: {e}")))?;
    // FR-99 decision 3 — the SystemContext flavour is a Windows service
    // install, and the wizard always writes a fresh config: it starts at
    // `lock_on_end = auto` (`enrollment::apply_service_install_defaults`).
    if is_system_context {
        roomlerd::enrollment::apply_service_install_defaults(&mut cfg);
    }
    // S2 — fold the wizard's advanced options into the enrolled config
    // before it's written (route lists already validated pre-MSI). An
    // overlay choice the SPA did not send follows the flavour (FR-84 S2).
    advanced
        .with_flavour_defaults(wfx)
        .apply_to(&mut cfg)
        .map_err(|e| failed(ErrorCode::AdvancedOptions, e))?;
    let agent_id = cfg.agent_id.clone();
    let tenant_id = cfg.tenant_id.clone();
    roomlerd::config::save(&config_path, &cfg)
        .map_err(|e| failed(ErrorCode::ConfigWrite, format!("write config.toml: {e}")))?;
    emit(
        on_event,
        ProgressEvent::EnrollOk {
            principal_kind: "agent".into(),
            principal_id: agent_id.clone(),
            tenant_id: tenant_id.clone(),
        },
    );
    diag.ok();

    // --- Step 7b: place the roomler-desktop GUI companion (GAP-A / P6) ---
    // The desktop EXE is NOT in the MSI (it's a standalone release
    // asset), so a daemon install would otherwise land only roomlerd +
    // roomler. Fetch + place it beside the daemon so all three ship
    // together. Best-effort — a failure never sinks the enrolled
    // install; the operator can always grab it later.
    // (P3b: recorded as its own step — `ok`, or `failed: companion` — and
    // not at all where it does not apply.)
    diag.begin(Step::Companion);
    let desktop_installed = place_desktop_companion(wfx, &server, on_event).await;
    best_effort_outcome(diag, desktop_installed, ErrorCode::Companion);

    // --- Step 7b': anchor the device for SYSTEM exec (FR-104) -----------
    // Only for a token the admin minted to anchor, on a machine-wide install
    // (the only flavours with a SYSTEM service). Best-effort, like the
    // companion step: a declined prompt or a failure leaves an enrolled
    // install, and the Done page carries the manual command.
    diag.begin(Step::Anchor);
    let anchored = anchor_device(role, wfx, &server, &token, &agent_id, on_event).await;
    best_effort_outcome(diag, anchored, ErrorCode::Anchor);

    // --- Step 7c: start a per-user daemon now (FR-84 D6) -----------------
    // The perUser MSI registers the Scheduled Task for the NEXT logon only,
    // so until now a wizard install ran nothing — and nothing could open the
    // companion — until the person signed out and back in. `install.ps1`
    // has always kicked the task here; the wizard now does the same. The
    // daemon then opens the companion once (the Welcome tour). A perMachine
    // install needs nothing: its service is already running, and its host
    // opens the companion as soon as the enrollment and the EXE are in place.
    if matches!(wfx, WindowsInstallFlavour::PerUser) {
        start_user_task();
    }

    // --- Step 8: done ----------------------------------------------------
    emit(on_event, ProgressEvent::Done);
    diag.done();

    // P4b (role→action composition): the MSI carries the `roomler`
    // CLI, so a daemon install subsumes the tunnel client. Existence-
    // check rather than assume — an old pre-P4b MSI served by a stale
    // server degrades to cli_included=Some(false) and the SPA doesn't
    // promise a CLI it didn't deliver.
    let (cli_binary_path, cli_included, cli_path_updated) = cli_done_surface(wfx);

    Ok(DoneReport {
        principal_kind: "agent".to_string(),
        principal_id: agent_id,
        tenant_id,
        tag: health.tag,
        role,
        flavour: Some(flavour_str),
        binary_path: cli_binary_path,
        config_path: Some(config_path.display().to_string()),
        path_updated: cli_path_updated,
        shortcut_created: None,
        cli_included,
        desktop_installed,
        anchored,
    })
}

/// FR-102 P3b — a best-effort step's diagnostics outcome from its report:
/// `Some(true)` passed, `Some(false)` failed with `code` (the install
/// stands either way), `None` did not apply, so no record at all.
fn best_effort_outcome(diag: &Diagnostics, report: Option<bool>, code: ErrorCode) {
    match report {
        Some(true) => diag.ok(),
        Some(false) => diag.fail(code, false),
        None => diag.discard(),
    }
}

/// FR-104 — does an install of `role` have a SYSTEM service an anchor is
/// for? The two machine-wide Windows roles; a per-user install has none.
pub fn role_anchors(role: Role) -> bool {
    cfg!(target_os = "windows") && matches!(role, Role::DaemonSystem | Role::DaemonMachine)
}

/// How long the elevated anchor step may take, the administrator prompt
/// included: a person has to answer it.
#[cfg(target_os = "windows")]
const ANCHOR_BUDGET: Duration = Duration::from_secs(5 * 60);

/// FR-104 — anchor the device this install just enrolled, when its token
/// allows it, by running `roomlerd anchor create` ELEVATED: a second
/// administrator prompt. The anchor's POST, and the SYSTEM service's
/// credential it returns, stay inside that elevated process (FR-94 §4); the
/// wizard runs at Medium integrity and never holds the credential.
///
/// `--force` because the wizard enrolled this very host a moment ago by id,
/// under a name the operator may have changed from the host name.
///
/// ⚠️ The token travels on the elevated child's command line. That exposes it
/// only to the installing administrator's own processes for the child's few
/// seconds, the same processes that can already read the wizard holding it.
/// It is never logged, emitted or shown.
///
/// `None` = not applicable (a plain token, a per-user role); `Some(true)` =
/// anchored; `Some(false)` = attempted and not.
#[cfg(target_os = "windows")]
async fn anchor_device(
    role: Role,
    flavour: WindowsInstallFlavour,
    server: &str,
    token: &str,
    agent_id: &str,
    on_event: &Channel<ProgressEvent>,
) -> Option<bool> {
    if !role_anchors(role) || !wizard_shared::token_peek::parse_anchor_claim(token) {
        return None;
    }
    let skipped = |reason: String| {
        tracing::warn!(%reason, "FR-104: the device was not anchored");
        emit(on_event, ProgressEvent::AnchorSkipped { reason });
        Some(false)
    };
    let Some(dir) =
        roomlerd::updater::install_dir_with_name(flavour, roomlerd::updater::INSTALL_FOLDER_NAME)
    else {
        return skipped("the install folder could not be found".to_string());
    };
    let exe = dir.join("roomlerd.exe");
    if !exe.exists() {
        return skipped(format!("{} is missing", exe.display()));
    }
    emit(on_event, ProgressEvent::AnchorStarted);
    let argv: Vec<String> = [
        "anchor",
        "create",
        "--server",
        server.trim().trim_end_matches('/'),
        "--token",
        token,
        "--device",
        agent_id,
        "--force",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let pid = match roomlerd::updater::spawn_elevated(&exe.display().to_string(), &argv) {
        Ok(pid) => pid,
        Err(e) => return skipped(format!("{e:#}")),
    };
    let runner = match MsiRunner::attach(pid) {
        Ok(r) => r,
        Err(e) => return skipped(format!("could not follow the anchor step: {e}")),
    };
    match runner.wait_for_exit(ANCHOR_BUDGET).await {
        Ok(MsiExitDecoded::Success) => {
            emit(on_event, ProgressEvent::AnchorOk);
            Some(true)
        }
        Ok(other) => skipped(format!(
            "roomlerd anchor create did not succeed ({other:?})"
        )),
        Err(e) => skipped(format!("waiting for the anchor step: {e}")),
    }
}

/// FR-104 — the daemon roles exist only on Windows.
#[cfg(not(target_os = "windows"))]
async fn anchor_device(
    _role: Role,
    _flavour: WindowsInstallFlavour,
    _server: &str,
    _token: &str,
    _agent_id: &str,
    _on_event: &Channel<ProgressEvent>,
) -> Option<bool> {
    None
}

/// Fetch + place the `roomler-desktop` GUI companion beside the daemon
/// (GAP-A / P6). The GUI EXE ships as a standalone release asset
/// (`roomler-desktop-*-x86_64-pc-windows-msvc*.exe`), not inside the
/// MSI, so a daemon install needs this extra step to land all three
/// binaries. Best-effort: `Some(true)` placed, `Some(false)` on any
/// failure or a server with no desktop asset, `None` on non-Windows.
/// Never errors the install — mirrors the terminal `install.ps1`
/// `Install-Desktop` try/catch.
#[cfg(target_os = "windows")]
async fn place_desktop_companion(
    flavour: WindowsInstallFlavour,
    server: &str,
    on_event: &Channel<ProgressEvent>,
) -> Option<bool> {
    let dir =
        roomlerd::updater::install_dir_with_name(flavour, roomlerd::updater::INSTALL_FOLDER_NAME)?;
    emit(
        on_event,
        ProgressEvent::AssetResolving {
            artifact: "roomler-desktop".to_string(),
        },
    );
    let origin = crate::proxy::origin_of(&crate::proxy::agent_base(server));
    let lr_url = format!("{origin}/api/agent/latest-release");
    let asset = match asset_resolver::find_release_asset(
        &lr_url,
        "agent-v",
        "roomler-desktop",
        ".exe",
        crate::proxy::USER_AGENT,
    )
    .await
    {
        Ok(Some(a)) => a,
        Ok(None) => {
            tracing::warn!(
                "no roomler-desktop asset in the latest agent release — companion skipped"
            );
            return Some(false);
        }
        Err(e) => {
            tracing::warn!(error = %e, "resolving roomler-desktop failed — companion skipped");
            return Some(false);
        }
    };
    let staged = std::env::temp_dir()
        .join("roomler-setup")
        .join(&asset.filename);
    let spec = asset_resolver::DownloadSpec {
        center_base: &origin,
        url: &asset.url,
        dest: &staged,
        user_agent: crate::proxy::USER_AGENT,
        artifact_label: "desktop companion",
    };
    let signature_url = match asset_resolver::detached_signature_url(&origin, &asset.url) {
        Ok(url) => url,
        Err(e) => {
            tracing::warn!(error = %e, "desktop signature URL refused — companion skipped");
            return Some(false);
        }
    };
    if let Err(e) = asset_resolver::download_signed(
        &spec,
        &signature_url,
        &crate::CANCEL_REQUESTED,
        roomlerd::pgp_verify::verify_release_artifact,
        |_| {},
    )
    .await
    {
        tracing::warn!(error = %e, "downloading roomler-desktop failed — companion skipped");
        return Some(false);
    }
    if let Some(digest) = asset.digest.as_deref() {
        match asset_resolver::verify_sha256(&staged, digest) {
            Ok(true) => {}
            _ => {
                tracing::warn!("roomler-desktop sha256 mismatch — companion skipped");
                let _ = std::fs::remove_file(&staged);
                return Some(false);
            }
        }
    }
    let target = dir.join("roomler-desktop.exe");
    // FR-84 D6 — the companion may already be RUNNING from `target`: the
    // service's own refresh can place it during the MSI, and its post-install
    // launch opens it as soon as the enrollment above lands. Windows refuses
    // to overwrite a running EXE but lets it be renamed, so move it aside
    // first — the rename-swap the daemon's companion refresh uses. The open
    // window keeps running from the renamed file; every later start uses the
    // new one.
    let old = dir.join("roomler-desktop.exe.old");
    let _ = std::fs::remove_file(&old);
    if target.exists()
        && let Err(e) = std::fs::rename(&target, &old)
    {
        tracing::warn!(error = %e, path = %target.display(), "could not move the old roomler-desktop aside");
    }
    match std::fs::copy(&staged, &target) {
        Ok(_) => {
            // Best-effort: still locked while the window it backs is open.
            let _ = std::fs::remove_file(&old);
            Some(true)
        }
        Err(e) => {
            // Never leave the host with NO companion.
            if !target.exists() && old.exists() {
                let _ = std::fs::rename(&old, &target);
            }
            tracing::warn!(error = %e, path = %target.display(), "placing roomler-desktop failed");
            Some(false)
        }
    }
}

/// FR-84 D6 — start the per-user daemon now instead of at the next logon,
/// best-effort, through the same `meshharbord service start` FR-84 D3's Apply
/// now uses (the Scheduled Task, legacy name included).
#[cfg(target_os = "windows")]
fn start_user_task() {
    match roomlerd::service::start() {
        Ok(()) => tracing::info!("started the per-user Roomler task"),
        Err(e) => tracing::warn!(
            error = %format!("{e:#}"),
            "could not start the per-user Roomler task; it starts at the next logon"
        ),
    }
}

#[cfg(not(target_os = "windows"))]
fn start_user_task() {}

/// Non-Windows: daemon roles don't run a real install here, and the
/// desktop companion is Windows-only.
#[cfg(not(target_os = "windows"))]
async fn place_desktop_companion(
    _flavour: WindowsInstallFlavour,
    _server: &str,
    _on_event: &Channel<ProgressEvent>,
) -> Option<bool> {
    None
}

/// Post-install probe for the MSI-carried tunnel CLI: derive the
/// flavour's install dir (perUser `%LOCALAPPDATA%\Programs\Roomler`,
/// perMachine `%ProgramFiles%\Roomler`) and check `roomler.exe`
/// landed. `path_updated=Some(true)` piggybacks on the same check —
/// the wxs `TunnelExe` component carries both the file AND the PATH
/// append, so they land (or don't) together.
#[cfg(target_os = "windows")]
fn cli_done_surface(
    flavour: WindowsInstallFlavour,
) -> (Option<String>, Option<bool>, Option<bool>) {
    let Some(dir) =
        roomlerd::updater::install_dir_with_name(flavour, roomlerd::updater::INSTALL_FOLDER_NAME)
    else {
        return (None, Some(false), None);
    };
    let cli = dir.join("roomler.exe");
    if cli.is_file() {
        (Some(cli.display().to_string()), Some(true), Some(true))
    } else {
        (None, Some(false), None)
    }
}

/// Daemon installs are Windows-only (MSI); on other hosts the daemon
/// orchestrator never runs a real install, so there is no CLI probe.
#[cfg(not(target_os = "windows"))]
fn cli_done_surface(
    _flavour: WindowsInstallFlavour,
) -> (Option<String>, Option<bool>, Option<bool>) {
    (None, None, None)
}

/// Force-kill the currently-running msiexec. Returns `Ok(())` if a
/// PID was stored + TerminateProcess succeeded; `Err` otherwise.
/// Leaves Windows Installer in a potentially-rolled-back state; the
/// SPA must surface "may leave partial install" before invoking
/// this. Non-Windows builds return `Err("not applicable")` — there is
/// no msiexec to hammer (the tunnel pipeline owns its own threads +
/// fds and unwinds via the cancel flag).
pub fn force_kill_msi() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let pid = crate::ACTIVE_MSI_PID.load(Ordering::SeqCst);
        if pid == 0 {
            return Err("no msiexec currently running".to_string());
        }
        let runner = MsiRunner::attach(pid).map_err(|e| format!("attach msiexec({pid}): {e}"))?;
        runner
            .terminate()
            .map_err(|e| format!("terminate msiexec({pid}): {e}"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("not applicable on this platform".to_string())
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// FR-84 S2 — the overlay default when the wizard sent no explicit choice.
///
/// A perMachine install runs the daemon as an SCM service, which can create
/// the overlay's Wintun adapter, so the private network is ON unless the
/// operator turned it off: the mesh is the reason the always-on daemon
/// exists, and an install that leaves it off by default was the first thing
/// every operator had to go back and fix. A perUser install's worker runs
/// with the interactive user's UAC-filtered token (`RunLevel` LeastPrivilege
/// on its Scheduled Task) and `WintunCreateAdapter` refuses it, so the key
/// is left UNTOUCHED there — the agent's own default (off) — rather than
/// written as a promise the daemon cannot keep. An explicit choice always
/// wins: the box the operator saw is the box that lands in config.toml.
fn overlay_enabled_default(explicit: Option<bool>, flavour: WindowsInstallFlavour) -> Option<bool> {
    explicit.or(match flavour {
        WindowsInstallFlavour::PerMachine => Some(true),
        WindowsInstallFlavour::PerUser => None,
    })
}

/// Map a daemon [`Role`] to the agent's install-flavour enum + the
/// SystemContext flag — the typed successor of the legacy
/// `parse_flavour` string matcher.
fn flavour_parts(role: Role) -> Result<(WindowsInstallFlavour, bool), String> {
    match role {
        Role::DaemonUser => Ok((WindowsInstallFlavour::PerUser, false)),
        Role::DaemonMachine => Ok((WindowsInstallFlavour::PerMachine, false)),
        Role::DaemonSystem => Ok((WindowsInstallFlavour::PerMachine, true)),
        Role::TunnelClient => Err(
            "tunnel-client role has no MSI flavour; dispatch bug — should route to the tunnel orchestrator"
                .to_string(),
        ),
    }
}

/// rc.52: apply a restrictive, inheritable DACL to the machine-global
/// config directory so the Agent-JWT-bearing `config.toml` (and the
/// crash sidecars under `crashes\`) are readable only by SYSTEM +
/// Administrators. `%PROGRAMDATA%` is world-readable by default — a
/// non-admin local user could otherwise read the long-lived agent
/// token and impersonate the host to the Roomler server.
///
/// `config_path` is `…\roomler\<segment>\config.toml` (the
/// segment is whatever `appdirs::app_segment` picked); we harden its
/// grandparent `…\roomler\` so that segment, `crashes\`, and
/// every future child inherit the ACL — the directory-inheritance
/// pattern (one `icacls` at install time) rather than a per-file ACL
/// that has a create→ACL TOCTOU and gets re-widened by every later
/// plain `config::save`. The directory is created first (icacls
/// needs an existing target).
///
/// Well-known SIDs are used instead of the names `SYSTEM` /
/// `Administrators` because those are localised on non-English
/// Windows (`Administratoren`, etc.) and a name-based grant would
/// fail there. `*S-1-5-18` = LocalSystem, `*S-1-5-32-544` =
/// Administrators.
fn harden_machine_global_dir(config_path: &std::path::Path) -> Result<(), String> {
    let roomler_dir = config_path
        .parent() // …\roomler\<segment>
        .and_then(|p| p.parent()) // …\roomler
        .ok_or_else(|| {
            format!(
                "machine-global config path {} has no grandparent dir to harden",
                config_path.display()
            )
        })?;
    std::fs::create_dir_all(roomler_dir)
        .map_err(|e| format!("create {}: {e}", roomler_dir.display()))?;
    let output = std::process::Command::new("icacls")
        .arg(roomler_dir)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:(OI)(CI)F")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(OI)(CI)F")
        .output()
        .map_err(|e| format!("spawn icacls: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "icacls exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Projection of [`roomlerd::win_service::system_context_attempt::Attempt`]
/// into the shape `ProgressEvent::SystemContextError` consumes. Kept
/// local to this module so the orchestrator doesn't leak the agent's
/// telemetry type into the SPA wire format.
struct SystemContextAttemptView {
    stage: String,
    message: String,
    hint: String,
}

/// Read `%PROGRAMDATA%\roomler\last-system-context-attempt.json` and
/// project it into the wire-shape the SPA receives. Returns `None`
/// when:
///   - the file doesn't exist (CA never ran — happens on plain
///     perMachine installs that go through the `DisableSystemContext`
///     path with no prior SC enabled);
///   - the JSON is malformed (best-effort — don't fail the whole
///     install just because telemetry is corrupt);
///   - the recorded attempt was a success (Stage::Ok — no error to
///     surface; whatever caused the MSI 1603 was outside the CA).
///
/// Windows-only because the underlying win_service module is
/// Windows-gated. On non-Windows the function always returns None,
/// which keeps the orchestrator unit tests cross-platform.
fn read_last_system_context_attempt() -> Option<SystemContextAttemptView> {
    #[cfg(target_os = "windows")]
    {
        use roomlerd::win_service::system_context_attempt::{Stage, read_last};
        match read_last() {
            Ok(Some(attempt)) => {
                // Surface failures only — a successful prior attempt
                // (e.g. a prior install that flipped SC on cleanly,
                // then a later non-SC install failed for an unrelated
                // reason) shouldn't be surfaced as a SystemContext
                // error.
                if matches!(attempt.stage, Stage::Ok) {
                    return None;
                }
                let stage_str = match attempt.stage {
                    Stage::Ok => "ok",
                    Stage::EnvVarWrite => "env_var_write",
                    Stage::ServiceRestart => "service_restart",
                    Stage::Unknown => "unknown",
                };
                Some(SystemContextAttemptView {
                    stage: stage_str.to_string(),
                    message: attempt.stderr,
                    hint: attempt.hint,
                })
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "failed to read system-context attempt JSON");
                None
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

fn emit(channel: &Channel<ProgressEvent>, event: ProgressEvent) {
    // Replay log first so a late-attaching listener can catch up
    // via cmd_install_progress_replay; the channel's send is best-
    // effort (Tauri 2 returns Err only when the receiver has been
    // closed, which means the SPA already moved on).
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

fn label_existing(detected: &ExistingInstall) -> String {
    match detected {
        ExistingInstall::Clean => "clean".to_string(),
        ExistingInstall::PerUser(info) => format!(
            "perUser {}",
            info.version.as_deref().unwrap_or("(unknown version)")
        ),
        ExistingInstall::PerMachine(info) => format!(
            "perMachine {}",
            info.version.as_deref().unwrap_or("(unknown version)")
        ),
        ExistingInstall::Ambiguous {
            peruser,
            permachine,
        } => format!(
            "ambiguous (perUser {} + perMachine {})",
            peruser.version.as_deref().unwrap_or("?"),
            permachine.version.as_deref().unwrap_or("?"),
        ),
    }
}

/// Detect a cross-flavour switch; return a warning string the SPA
/// renders in a yellow banner. `requested` is the flavour string from
/// [`Role::msi_flavour`].
pub fn cross_flavour_warning(detected: &ExistingInstall, requested: &str) -> Option<String> {
    let requested_is_permachine = requested.starts_with("permachine");
    let requested_is_peruser = requested == "peruser";
    match detected {
        ExistingInstall::PerUser(_) if requested_is_permachine => Some(
            "Switching from perUser → perMachine. Your existing enrollment will be lost; you'll need a fresh enrollment token from your administrator."
                .to_string(),
        ),
        ExistingInstall::PerMachine(_) if requested_is_peruser => Some(
            "Switching from perMachine → perUser. Your existing enrollment will be lost; you'll need a fresh enrollment token from your administrator."
                .to_string(),
        ),
        ExistingInstall::Ambiguous { .. } => Some(
            "Both perUser and perMachine installs detected. The MSI's cleanup custom action will remove the one not selected."
                .to_string(),
        ),
        _ => None,
    }
}

/// Reverse-map a `MsiExitDecoded` back to a numeric code so
/// `ProgressEvent::MsiCompleted` carries both surfaces.
fn msi_exit_code(decoded: &MsiExitDecoded) -> i32 {
    match decoded {
        MsiExitDecoded::Success => 0,
        MsiExitDecoded::UserCancel => 1602,
        MsiExitDecoded::FatalError => 1603,
        MsiExitDecoded::AnotherInstall => 1618,
        MsiExitDecoded::RebootRequired => 3010,
        MsiExitDecoded::Other(code) => *code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roomlerd::install_detect::InstallInfo;

    fn info(version: &str) -> InstallInfo {
        InstallInfo {
            version: Some(version.to_string()),
            install_location: None,
        }
    }

    #[test]
    fn flavour_parts_maps_daemon_roles() {
        assert_eq!(
            flavour_parts(Role::DaemonUser).unwrap(),
            (WindowsInstallFlavour::PerUser, false)
        );
        assert_eq!(
            flavour_parts(Role::DaemonMachine).unwrap(),
            (WindowsInstallFlavour::PerMachine, false)
        );
        assert_eq!(
            flavour_parts(Role::DaemonSystem).unwrap(),
            (WindowsInstallFlavour::PerMachine, true)
        );
    }

    #[test]
    fn flavour_parts_rejects_tunnel_client() {
        assert!(flavour_parts(Role::TunnelClient).is_err());
    }

    #[test]
    fn cross_flavour_warning_peruser_to_permachine() {
        let w = cross_flavour_warning(&ExistingInstall::PerUser(info("0.3.0-rc.26")), "permachine");
        assert!(w.is_some());
        let msg = w.unwrap();
        assert!(msg.contains("perUser"));
        assert!(msg.contains("perMachine"));
        assert!(msg.contains("fresh enrollment token"));
    }

    #[test]
    fn cross_flavour_warning_permachine_to_peruser() {
        let w = cross_flavour_warning(&ExistingInstall::PerMachine(info("0.3.0-rc.26")), "peruser");
        assert!(w.is_some());
    }

    #[test]
    fn cross_flavour_warning_silent_for_same_flavour() {
        // peruser → peruser is a same-flavour upgrade; no warning.
        let w = cross_flavour_warning(&ExistingInstall::PerUser(info("0.3.0-rc.26")), "peruser");
        assert!(w.is_none());
        let w = cross_flavour_warning(
            &ExistingInstall::PerMachine(info("0.3.0-rc.26")),
            "permachine",
        );
        assert!(w.is_none());
    }

    #[test]
    fn cross_flavour_warning_silent_for_clean() {
        let w = cross_flavour_warning(&ExistingInstall::Clean, "peruser");
        assert!(w.is_none());
    }

    #[test]
    fn cross_flavour_warning_for_ambiguous() {
        let w = cross_flavour_warning(
            &ExistingInstall::Ambiguous {
                peruser: info("0.3.0-rc.18"),
                permachine: info("0.3.0-rc.26"),
            },
            "permachine",
        );
        assert!(w.is_some());
        assert!(w.unwrap().contains("Both"));
    }

    #[test]
    fn label_existing_renders_each_variant() {
        assert_eq!(label_existing(&ExistingInstall::Clean), "clean");
        assert_eq!(
            label_existing(&ExistingInstall::PerUser(info("0.3.0-rc.26"))),
            "perUser 0.3.0-rc.26"
        );
        assert_eq!(
            label_existing(&ExistingInstall::PerMachine(info("0.3.0-rc.26"))),
            "perMachine 0.3.0-rc.26"
        );
    }

    #[test]
    fn label_existing_handles_missing_version() {
        assert_eq!(
            label_existing(&ExistingInstall::PerUser(InstallInfo::default())),
            "perUser (unknown version)"
        );
    }

    #[test]
    fn msi_exit_code_roundtrip() {
        assert_eq!(msi_exit_code(&MsiExitDecoded::Success), 0);
        assert_eq!(msi_exit_code(&MsiExitDecoded::UserCancel), 1602);
        assert_eq!(msi_exit_code(&MsiExitDecoded::FatalError), 1603);
        assert_eq!(msi_exit_code(&MsiExitDecoded::AnotherInstall), 1618);
        assert_eq!(msi_exit_code(&MsiExitDecoded::RebootRequired), 3010);
        assert_eq!(msi_exit_code(&MsiExitDecoded::Other(42)), 42);
    }

    #[test]
    fn request_cancel_then_check_cancel_returns_err() {
        // SAFETY: this test mutates a process-wide AtomicBool, so it
        // would race with any other test that does the same — keep
        // this the ONLY test in the whole app crate touching
        // CANCEL_REQUESTED (the tunnel orchestrator shares the same
        // static, so its legacy twin test is deliberately not
        // duplicated there). We restore the flag at end so subsequent
        // tests see a clean slate.
        let saved = crate::CANCEL_REQUESTED.swap(false, Ordering::SeqCst);
        crate::CANCEL_REQUESTED.store(true, Ordering::SeqCst);
        let result = check_cancel();
        // Restore the saved value before asserting (so the assertion
        // never short-circuits the cleanup).
        crate::CANCEL_REQUESTED.store(saved, Ordering::SeqCst);
        assert!(result.is_err());
    }

    #[test]
    fn force_kill_msi_without_active_pid_returns_err() {
        let saved = crate::ACTIVE_MSI_PID.swap(0, Ordering::SeqCst);
        let result = force_kill_msi();
        crate::ACTIVE_MSI_PID.store(saved, Ordering::SeqCst);
        // Windows: "no msiexec currently running"; non-Windows:
        // "not applicable". Either way the command must reject.
        assert!(result.is_err());
    }

    // ----- B6 regression (1625 ERROR_INSTALL_PACKAGE_REJECTED) ---------

    #[test]
    fn daemon_machine_role_resolves_to_permachine_enum() {
        // Lock the contract that drives B6's fix: the role picked on
        // the SPA cards deterministically becomes
        // `WindowsInstallFlavour::PerMachine`, which is what the
        // orchestrator passes to
        // `spawn_installer_for_flavour_with_properties`. If this
        // drifts (e.g. someone introduces a new wrapper enum or adds
        // a fallback to `current_install_flavour`), the wizard's
        // perMachine spawn breaks again with 1625.
        let (wfx, sysctx) = flavour_parts(Role::DaemonMachine).expect("map");
        assert_eq!(wfx, WindowsInstallFlavour::PerMachine);
        assert!(!sysctx);
        let (wfx, sysctx) = flavour_parts(Role::DaemonSystem).expect("map");
        assert_eq!(wfx, WindowsInstallFlavour::PerMachine);
        assert!(sysctx);
    }

    // ----- FR-84 S2: the overlay default follows the install flavour -----

    #[test]
    fn permachine_without_a_choice_turns_the_overlay_on() {
        assert_eq!(
            overlay_enabled_default(None, WindowsInstallFlavour::PerMachine),
            Some(true)
        );
    }

    #[test]
    fn peruser_without_a_choice_leaves_the_overlay_untouched() {
        // Untouched, not `Some(false)`: the wizard writes no promise the
        // per-user daemon cannot keep, and the agent's own default (off)
        // stays the one source of that answer.
        assert_eq!(
            overlay_enabled_default(None, WindowsInstallFlavour::PerUser),
            None
        );
    }

    #[test]
    fn an_explicit_overlay_choice_wins_over_the_flavour_default() {
        assert_eq!(
            overlay_enabled_default(Some(false), WindowsInstallFlavour::PerMachine),
            Some(false)
        );
        assert_eq!(
            overlay_enabled_default(Some(true), WindowsInstallFlavour::PerUser),
            Some(true)
        );
    }

    #[test]
    fn overlay_flavour_default_lands_in_the_enrolled_config() {
        // Through the real apply path on a real config: the belt is only
        // worth having if the key actually reaches config.toml.
        let mut cfg = roomlerd::config::test_fixture();
        cfg.overlay_enabled = false;
        AdvancedOptions::default()
            .with_flavour_defaults(WindowsInstallFlavour::PerMachine)
            .apply_to(&mut cfg)
            .expect("apply");
        assert!(cfg.overlay_enabled, "perMachine + no choice → overlay on");

        let mut cfg = roomlerd::config::test_fixture();
        cfg.overlay_enabled = false;
        AdvancedOptions::default()
            .with_flavour_defaults(WindowsInstallFlavour::PerUser)
            .apply_to(&mut cfg)
            .expect("apply");
        assert!(
            !cfg.overlay_enabled,
            "perUser + no choice → untouched (off)"
        );

        let mut cfg = roomlerd::config::test_fixture();
        cfg.overlay_enabled = false;
        AdvancedOptions {
            overlay_enabled: Some(false),
            ..Default::default()
        }
        .with_flavour_defaults(WindowsInstallFlavour::PerMachine)
        .apply_to(&mut cfg)
        .expect("apply");
        assert!(
            !cfg.overlay_enabled,
            "an explicit off on perMachine is respected"
        );
    }
}
