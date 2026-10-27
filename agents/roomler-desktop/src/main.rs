// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// Clippy's `doc_lazy_continuation` / `doc_list_item_indent` lints flag
// rustdoc indentation we wrote for prose continuation lines (slash-
// separated menu items, signatures). The intent is plain English
// rather than nested markdown lists; silencing avoids reformatting
// every module-level doc-comment in the crate.
#![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]

//! Roomler desktop (`roomler-desktop`) — the node stack's control
//! surface. Tauri 2, lives in the system tray, one window with a
//! sidebar SPA (`src/front/`): Overview / Devices / Tunnels /
//! Settings / Onboarding + the remote-control consent modal.
//!
//! Architecture:
//! - The desktop app is a **thin client**: live node/peer/flow/route
//!   state comes from the running daemon over the LocalAPI
//!   (`roomler_localapi::Client`); consent decisions go the same
//!   way (P2b — the daemon owns the profile-correct sentinel dir).
//! - Enrollment goes through `roomler_node_core::enrollment::enroll` as a
//!   direct lib call (no subprocess).
//! - Service control / self-update shell out to the daemon CLI
//!   (`meshharbord service install`, `roomlerd self-update`).
//! - Closing the window HIDES it (close-to-hide below) — the tray icon
//!   and the consent watcher must outlive the window, since surfacing
//!   consent prompts is this app's safety-relevant job.
//!
//! See `agents/roomler-desktop/Cargo.toml` for the dep wiring (the
//! package keeps its historical name; the output binary is
//! `roomler-desktop` since P3d).

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod account_window;
mod commands;
mod desktop_log;
mod editor;
mod first_run;
mod panels;
#[cfg(target_os = "linux")]
mod pin;
mod tray;

use tauri::Manager;

fn main() {
    // #2286 — FIRST, before GTK starts and before any thread exists: on GNOME
    // the companion runs under Xwayland, the only way its banner can sit at
    // the top of the screen there.
    #[cfg(target_os = "linux")]
    pin::prefer_x11();

    // Lightweight logging (the agent has its own persistent rolling log;
    // this one is for companion-side issues — a failed enrollment HTTP call,
    // a refresh the daemon refused). FR-84 D1: stderr PLUS a small
    // size-capped file under the per-user data dir, because a tray app's
    // stderr is read by nobody and the errors it swallowed were invisible.
    let log_path = desktop_log::init();
    match &log_path {
        Some(p) => tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            log = %p.display(),
            "roomler-desktop starting"
        ),
        None => tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            "roomler-desktop starting (no data dir — stderr only)"
        ),
    }

    // FR-84 D6 — the FIRST process reads its own argv too (before D6 only
    // the single-instance callback below did), and the per-user state says
    // whether this person has been through the Welcome tour. A login start
    // for someone who switched it off ends here, before any window or tray.
    let argv: Vec<String> = std::env::args().collect();
    let launch = first_run::parse_launch_args(&argv);
    let state = roomler_node_core::desktop_state::load();
    let action = first_run::decide_startup(&launch, state.first_run_done, state.autostart_opt_out);
    tracing::info!(
        ?launch,
        ?action,
        first_run_done = state.first_run_done,
        "startup"
    );
    if action == first_run::StartupAction::Exit {
        return;
    }
    let show_view = match &action {
        first_run::StartupAction::Show(view) => Some(view.clone()),
        _ => None,
    };
    first_run::set_launch_view(show_view.clone());

    tauri::Builder::default()
        .manage(account_window::CenterPolicy::default())
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // Second invocation: focus the existing window instead
            // of starting a new tray. Prevents "10 trays running"
            // when an operator double-clicks the launcher.
            //
            // FR-84 D6 — what the forwarded launch asked for decides: a
            // login start (`--autostart`) never pops the window of a
            // companion that is already up; `--first-run` opens the tour (or
            // the Overview once it is done); `--view=<name>` routes there.
            let launch = first_run::parse_launch_args(&args);
            let done = roomler_node_core::desktop_state::load().first_run_done;
            let view = match first_run::decide_second_instance(&launch, done) {
                first_run::SecondLaunch::Ignore => return,
                first_run::SecondLaunch::Show => None,
                first_run::SecondLaunch::ShowView(view) => Some(view),
            };
            if let Some(window) = app.get_webview_window("main") {
                // The name is whitelisted to ascii-alphanumeric by the parser
                // before it goes near eval; the router maps anything unknown
                // to Overview.
                if let Some(view) = view {
                    let _ = window.eval(format!("window.location.hash = '#/{view}'"));
                }
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::cmd_status,
            commands::cmd_device_view,
            commands::cmd_ping,
            commands::cmd_enroll,
            commands::cmd_re_enroll,
            commands::cmd_set_device_name,
            commands::cmd_default_device_name,
            commands::cmd_check_update,
            commands::cmd_apply_update,
            commands::cmd_service_install,
            commands::cmd_service_uninstall,
            commands::cmd_service_status,
            // FR-84 D3 — Apply now.
            commands::cmd_restart_daemon,
            commands::cmd_restart_wait,
            commands::cmd_permissions,
            commands::cmd_request_permission,
            commands::cmd_open_log_dir,
            commands::cmd_open_config_dir,
            commands::cmd_consent_approve,
            commands::cmd_consent_deny,
            commands::cmd_get_pending_consents,
            commands::cmd_rc_sessions,
            commands::cmd_rc_disconnect,
            commands::cmd_tunnels_view,
            commands::cmd_route_add,
            commands::cmd_route_update,
            commands::cmd_route_remove,
            commands::cmd_route_set_enabled,
            commands::cmd_config_cleanup,
            commands::cmd_config_entries,
            commands::cmd_config_set,
            commands::cmd_encoder_caps,
            commands::cmd_files_dir_view,
            commands::cmd_pick_files_dir,
            commands::cmd_files_dir_default,
            commands::cmd_open_files_dir,
            commands::cmd_tail_log,
            commands::cmd_open_remote,
            commands::cmd_open_roomler,
            commands::cmd_open_account,
            // FR-85 — the Recordings view.
            commands::cmd_recordings_view,
            commands::cmd_record_start,
            commands::cmd_record_stop,
            commands::cmd_recording_delete,
            commands::cmd_recording_open,
            commands::cmd_pick_record_dir,
            // FR-85 P5c — the Edit view.
            editor::cmd_media_available,
            editor::cmd_media_probe,
            editor::cmd_edit_load,
            editor::cmd_edit_save,
            editor::cmd_export_start,
            editor::cmd_export_status,
            editor::cmd_export_cancel,
            editor::cmd_pick_music,
            editor::cmd_preview_src,
            // FR-84 D5c — the Devices page's grid and mesh.
            commands::cmd_devices,
            commands::cmd_mesh,
            // FR-84 D6 — the Welcome tour and the login start.
            first_run::cmd_launch_intent,
            first_run::cmd_desktop_state,
            first_run::cmd_first_run_done,
            first_run::cmd_autostart_get,
            first_run::cmd_autostart_set,
            first_run::cmd_free_port,
        ])
        .on_window_event(|window, event| {
            // Close-to-hide: the MAIN window is a view over a resident tray
            // app. Letting its close destroy the last window would exit the
            // process (Tauri default) and take the consent watcher down with
            // it — remote-control prompts would silently stop surfacing.
            //
            // S7: label-gated — the embedded Roomler web window must really
            // close (default destroy), else it becomes a hidden WebView2
            // zombie holding memory. The main window stays alive, so window
            // count never hits zero and the app keeps running.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event
                && window.label() == "main"
            {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(move |app| {
            // Install the tray icon + menu. The main window starts
            // hidden (visible:false in tauri.conf.json); operator
            // opens it from the tray menu.
            tray::install(app.handle())?;
            // FR-84 D6 — a launch that asked for a view (the Welcome on a
            // first run, `--first-run`, `--view=`) shows the window at once;
            // the page routes itself from `cmd_launch_intent` when it loads.
            if show_view.is_some()
                && let Some(window) = app.get_webview_window("main")
            {
                let _ = window.show();
                let _ = window.set_focus();
            }
            if launch.autostart || !state.first_run_done {
                tauri::async_runtime::spawn(first_run::startup_checks(
                    app.handle().clone(),
                    launch.autostart,
                    state.first_run_done,
                ));
            }
            // Phase 3 — watch the shared consent dir; when the agent drops a new
            // `.pending` marker (a remote session awaiting approval), surface the
            // window so the operator sees the Approve/Deny modal the SPA renders
            // from `cmd_get_pending_consents`.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(consent_watch_loop(handle));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running roomler-desktop");
}

/// Ask the daemon (over the LocalAPI) which sessions await consent; when a NEW
/// one appears (not shown yet), surface the tray window so the SPA's consent
/// modal is visible. P2b: polling the daemon — not a profile-specific sentinel
/// dir — means this also works when the agent runs as SYSTEM (the dir would be
/// in the SYSTEM profile, unreachable to this interactive-user process). Runs on
/// Tauri's async runtime; a 750 ms poll over the local pipe is cheap. The SPA
/// does the actual render/approve/deny via `cmd_get_pending_consents` + the
/// approve/deny commands; this loop's only job is "bring the window forward when
/// something new needs a decision."
async fn consent_watch_loop(app: tauri::AppHandle) {
    use std::collections::HashSet;

    let mut seen: HashSet<String> = HashSet::new();
    let mut banner_up = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        let (pending, live) = match roomler_localapi::connect().await {
            Ok(mut c) => {
                let pending: HashSet<String> = c
                    .consent_pending()
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    // FR-27 — ignore anything the DAEMON is already showing
                    // natively. It still writes a marker for those (that list
                    // is also what `roomlerd consent --list` reads), so without
                    // this filter a host with a native overlay would get two
                    // Approve buttons for one decision.
                    .filter(|p| p.surface != "native")
                    .map(|p| p.session_id)
                    .collect();
                let live = c.rc_sessions().await;
                // FR-85 — the tray turns red with the banner, from this same
                // answer; a failed poll leaves it as the last answer said.
                tray::sessions_answered(&app, live.as_deref().ok());
                (pending, live.unwrap_or_default())
            }
            // Daemon down / pipe absent ⇒ nothing pending, nothing live.
            Err(e) => {
                // FR-85 — for the tray, no service at all is an answer:
                // nothing records without it (a busy pipe is not).
                if tray::no_service(&e) {
                    tray::sessions_answered(&app, Some(&[]));
                }
                (HashSet::new(), Vec::new())
            }
        };

        // FR-27 — a newly-appeared prompt opens the small always-on-top CONSENT
        // window, not the whole 1100×740 app. The old behaviour showed the
        // entire SPA over whatever the person was doing, to ask one yes/no.
        if pending.difference(&seen).next().is_some() {
            panels::show_consent(&app);
        } else if pending.is_empty() {
            panels::hide(&app, panels::CONSENT);
        }
        seen = pending;

        // FR-27 — the "Being viewed by …" banner. Windows has a native,
        // capture-excluded overlay for this and keeps it; everywhere else this
        // is the only such indicator there has ever been.
        let want_banner = wants_banner(&live) && panels::banner_enabled();
        if want_banner != banner_up {
            if want_banner {
                panels::show_banner(&app);
            } else {
                panels::hide(&app, panels::VIEWING);
            }
            banner_up = want_banner;
        }
    }
}

/// FR-93 P6h — the banner is for a session that sees the screen. One whose
/// capture still waits on the desktop's own dialog (`asking`) shares nothing
/// yet: saying "Being viewed" then is untrue, and on a desktop that centres
/// new windows the banner lands on the dialog the person has to answer.
fn wants_banner(live: &[roomler_localapi::RcSessionInfo]) -> bool {
    live.iter().any(|s| !s.asking)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-93 P6h — the banner waits while the desktop's own dialog is still
    /// asking about every session, and comes up as soon as one of them sees
    /// the screen.
    #[test]
    fn the_banner_waits_while_the_desktop_asks() {
        let session = |asking| roomler_localapi::RcSessionInfo {
            session_id: "0".repeat(24),
            asking,
            ..Default::default()
        };
        assert!(!wants_banner(&[]), "no session, no banner");
        assert!(
            !wants_banner(&[session(true)]),
            "the dialog still asks: nothing is shared yet"
        );
        assert!(wants_banner(&[session(false)]));
        assert!(
            wants_banner(&[session(true), session(false)]),
            "one session that sees the screen is enough"
        );
    }
}
