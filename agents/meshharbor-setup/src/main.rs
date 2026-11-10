// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR(4): names the two wizards retired in P4c-2 — history, not a live
// path.
//! MeshHarbor Setup — the unified 5-step Tauri 2 wizard.
//!
//! ONE downloadable EXE replacing the two legacy wizards retired in
//! P4c-2 (`meshharbor-installer` drove the daemon MSIs,
//! `meshharbor-tunnel-installer` the tunnel CLI). The operator picks a
//! role on the Welcome step
//! — three daemon flavours (Windows) or the tunnel client (any OS) —
//! and the wizard drives the matching install pipeline end-to-end:
//! detect → server + device → token → install (download / MSI or
//! extract / enroll) → done.
//!
//! Architecture mirrors the rc.28 wizard lineage:
//!
//! - **Window-only**, no system-tray icon. Wizard exits on Finish or
//!   Cancel; it doesn't sit around after install.
//! - **Single-instance** via `tauri-plugin-single-instance`: a second
//!   launch focuses the existing window. While `cmd_install` is in
//!   flight (B9 + H4 from the rc.28 plan critique), the second launch
//!   instead surfaces a snackbar event and exits without flashing a
//!   window, so the operator can't accidentally double-trigger the
//!   MSI / download.
//! - **State persistence** via `wizard_shared::wizard_state` so a
//!   force-killed wizard resumes mid-flow. Token is NEVER persisted
//!   (H5).
//! - **Progress streaming** via `tauri::ipc::Channel<ProgressEvent>`
//!   (the unified `wizard_shared::progress` wire shape) from inside
//!   `cmd_install`; the replay log catches any events emitted before
//!   the listener attached (H1).
//!
//! See `wizard_app::{orchestrator_agent, orchestrator_tunnel}` for
//! the two pipelines and `src/front/app.js` for the SPA driver.

#![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use tauri::{Emitter, Manager};
use wizard_app::{INSTALL_IN_PROGRESS, commands};

fn main() {
    // Stderr-only tracing. The wizard is a foreground EXE the
    // operator launches manually; persistent logging is the daemon's
    // job, not ours. Operators who want wizard-side logs run from a
    // terminal and observe stderr.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Per the rc.28 plan's B9 fix: differentiate "install in
            // flight" from "idle re-launch". An in-flight cmd_install
            // must NOT pop a fresh window — operator could
            // accidentally trigger a duplicate msiexec / download via
            // Cancel-then-Retry.
            //
            // Callback runs in the FIRST process per
            // `tauri-plugin-single-instance` docs, so the atomic load
            // here observes the first-process's flag.
            if INSTALL_IN_PROGRESS.load(std::sync::atomic::Ordering::SeqCst) {
                // Surface a snackbar on the existing window via the
                // SPA's `installer-already-running` listener (event
                // name kept identical to both legacy wizards).
                // Front-end shows "Wizard already running"; new EXE
                // exits silently.
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.emit("installer-already-running", ());
                }
                return;
            }
            // Idle: focus the existing window + leave the persisted
            // step intact. Wizard state JSON drives the resume.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::cmd_detect_install,
            commands::cmd_default_device_name,
            commands::cmd_default_server_url,
            commands::cmd_validate_token,
            commands::cmd_load_state,
            commands::cmd_save_state,
            commands::cmd_install,
            commands::cmd_cancel_in_progress,
            commands::cmd_force_kill_msi,
            commands::cmd_install_progress_replay,
            commands::cmd_exit_wizard,
            // FR-102 P3b — the opt-in diagnostics box and the page boundaries.
            commands::cmd_diagnostics_opt_in,
            commands::cmd_diagnostics_page,
        ])
        .run(tauri::generate_context!())
        .expect("error while running meshharbor-setup");
}
