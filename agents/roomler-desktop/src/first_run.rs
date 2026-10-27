// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D6 — how the companion starts: what its own command line asks for,
//! whether this person has seen the Welcome tour, and whether a login start
//! should stay in the tray, open the tour, or leave again at once.
//!
//! Before D6 only the SECOND instance read argv (the single-instance
//! callback in `main.rs`): the first process ignored `--view=` entirely, and
//! nothing could tell a login start from a person opening the app.
//!
//! Also the Tauri commands behind the Welcome view and the "Start at login"
//! card: the launch intent, the per-user state, the login start itself, and
//! a free loopback port for userspace mode.

use roomler_node_core::companion_autostart::{AUTOSTART_ARG, FIRST_RUN_ARG};
use roomler_node_core::desktop_state;
use serde::Serialize;
use std::sync::Mutex;

/// What the command line asked for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchArgs {
    /// `--view=<name>`: open on this view. Whitelisted to ASCII alphanumerics
    /// (it is routed into the page), else ignored.
    pub view: Option<String>,
    /// `--autostart`: a login start.
    pub autostart: bool,
    /// `--first-run`: the daemon's one-shot post-install launch.
    pub first_run: bool,
}

/// Parse the companion's own arguments (`args[0]` is the program).
pub fn parse_launch_args<S: AsRef<str>>(args: &[S]) -> LaunchArgs {
    let mut out = LaunchArgs::default();
    for arg in args.iter().skip(1).map(AsRef::as_ref) {
        if arg == AUTOSTART_ARG {
            out.autostart = true;
        } else if arg == FIRST_RUN_ARG {
            out.first_run = true;
        } else if let Some(view) = arg.strip_prefix("--view=")
            && !view.is_empty()
            && view.chars().all(|c| c.is_ascii_alphanumeric())
        {
            out.view = Some(view.to_string());
        }
    }
    out
}

/// What the FIRST process does at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupAction {
    /// Leave at once: a login start for a person who switched it off.
    Exit,
    /// Stay in the tray, window hidden (today's behaviour).
    Tray,
    /// Show the window on this view.
    Show(String),
}

/// Decide the first process's start. `first_run_done` / `opted_out` come
/// from the per-user desktop state.
pub fn decide_startup(args: &LaunchArgs, first_run_done: bool, opted_out: bool) -> StartupAction {
    // An explicit view is a person (or a script) asking for exactly that.
    if let Some(view) = &args.view {
        return StartupAction::Show(view.clone());
    }
    // The tour shows until it is finished or skipped, however this started —
    // a login start included: an install done over RMM with nobody logged on
    // meets its person at their first login.
    if !first_run_done {
        return StartupAction::Show("welcome".to_string());
    }
    if args.first_run {
        return StartupAction::Show("overview".to_string());
    }
    if args.autostart && opted_out {
        return StartupAction::Exit;
    }
    StartupAction::Tray
}

/// What a SECOND launch, forwarded to the running instance, does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondLaunch {
    /// Nothing at all: a login start must not pop the window of a companion
    /// that is already up.
    Ignore,
    /// Show and focus the window where it is (a double-click).
    Show,
    /// Show the window on this view.
    ShowView(String),
}

/// Decide a forwarded launch.
pub fn decide_second_instance(args: &LaunchArgs, first_run_done: bool) -> SecondLaunch {
    if let Some(view) = &args.view {
        return SecondLaunch::ShowView(view.clone());
    }
    if args.first_run {
        let view = if first_run_done {
            "overview"
        } else {
            "welcome"
        };
        return SecondLaunch::ShowView(view.to_string());
    }
    if args.autostart {
        return SecondLaunch::Ignore;
    }
    SecondLaunch::Show
}

/// The first port in `start..start+span` that is not in `exclude` and that
/// `can_bind` accepts. Userspace mode's SOCKS front needs a loopback port
/// that is free NOW and not claimed by a declared route that is merely down
/// at the moment — 1080 is exactly the port such a route tends to hold.
pub fn pick_free_port(
    start: u16,
    span: u16,
    exclude: &[u16],
    can_bind: impl Fn(u16) -> bool,
) -> Option<u16> {
    (0..span)
        .map_while(|i| start.checked_add(i))
        .find(|p| *p != 0 && !exclude.contains(p) && can_bind(*p))
}

// ─── the launch intent ─────────────────────────────────────────────────────

/// The view this process was launched on, handed to the page ONCE. Set in
/// `main` before the window exists; the page asks for it on load, which is
/// the one moment it is certain to be listening (an eval from `setup` can run
/// against a page that is not there yet).
static LAUNCH_VIEW: Mutex<Option<String>> = Mutex::new(None);

pub fn set_launch_view(view: Option<String>) {
    *LAUNCH_VIEW.lock().unwrap_or_else(|p| p.into_inner()) = view;
}

#[derive(Debug, Serialize)]
pub struct LaunchIntent {
    pub view: Option<String>,
}

/// Taken, not read: a reload of the page must not jump back to the launch
/// view after the person moved on.
#[tauri::command]
pub fn cmd_launch_intent() -> LaunchIntent {
    LaunchIntent {
        view: LAUNCH_VIEW.lock().unwrap_or_else(|p| p.into_inner()).take(),
    }
}

// ─── per-user state ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DesktopStateView {
    pub first_run_done: bool,
    pub autostart_opt_out: bool,
    /// `windows` | `linux` | `macos` — the tour words the private-network
    /// step per platform.
    pub platform: &'static str,
    /// macOS: the privileged half (`com.roomler.daemon`, root) is installed.
    /// On a Mac the MESH belongs to that half — its own enrollment — while
    /// this app talks to the per-user capture half; offering to put THIS half
    /// on the mesh too would make the Mac two nodes.
    pub macos_privileged_half: bool,
}

#[tauri::command]
pub fn cmd_desktop_state() -> DesktopStateView {
    let s = desktop_state::load();
    DesktopStateView {
        first_run_done: s.first_run_done,
        autostart_opt_out: s.autostart_opt_out,
        platform: if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "linux"
        },
        // The plist is world-readable; `/etc/meshharbor` (0700) is not.
        macos_privileged_half: cfg!(target_os = "macos")
            && std::path::Path::new("/Library/LaunchDaemons/com.roomler.daemon.plist").exists(),
    }
}

/// The tour is finished (or skipped): it stops opening by itself.
#[tauri::command]
pub fn cmd_first_run_done() -> Result<(), String> {
    let mut s = desktop_state::load();
    if s.first_run_done {
        return Ok(());
    }
    s.first_run_done = true;
    desktop_state::save(&s).map_err(|e| format!("saving the desktop state: {e}"))
}

// ─── free port for userspace mode ──────────────────────────────────────────

/// A loopback port for userspace mode's SOCKS5 front: free right now and not
/// one of `exclude` (the declared routes' local ports). Probed upward from
/// `preferred`, never at 1080 by default.
#[tauri::command]
pub fn cmd_free_port(preferred: Option<u16>, exclude: Option<Vec<u16>>) -> Result<u16, String> {
    let start = preferred.filter(|p| *p >= 1024).unwrap_or(41080);
    let exclude = exclude.unwrap_or_default();
    pick_free_port(start, 200, &exclude, |p| {
        std::net::TcpListener::bind(("127.0.0.1", p)).is_ok()
    })
    .ok_or_else(|| {
        format!(
            "no free loopback port in {start}..{}",
            start.saturating_add(200)
        )
    })
}

// ─── start at login ────────────────────────────────────────────────────────

/// What the "Start at login" toggle shows.
#[derive(Debug, Serialize)]
pub struct AutostartState {
    /// The toggle can be changed here.
    pub supported: bool,
    /// Roomler starts when this person signs in.
    pub enabled: bool,
    /// `machine` | `user` | `xdg` | `macos` | `none`.
    pub scope: String,
    /// One line under the toggle.
    pub note: String,
}

/// The device's `companion_autostart`, asked of the running daemon; `None`
/// when the daemon is not reachable or predates the key (treated as ON).
pub async fn device_autostart_switch() -> Option<bool> {
    let ask = async {
        let mut client = roomler_localapi::connect().await.ok()?;
        let entries = client.config_entries().await.ok()?;
        entries
            .into_iter()
            .find(|e| e.key == "companion_autostart")
            .and_then(|e| e.value)
            .map(|v| v == "true")
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), ask)
        .await
        .ok()
        .flatten()
}

// macOS never shows it: Login Items are the OS's, not ours.
#[cfg(not(target_os = "macos"))]
const DEVICE_OFF_NOTE: &str = "Turned off for this device (the companion_autostart setting). \
     An administrator can turn it back on in Settings → Device configuration.";

/// Checks that need the daemon, run once after start:
///
/// * a LOGIN start on a device whose `companion_autostart` is off leaves —
///   the device's switch governs every login-start mechanism, including the
///   Linux package's XDG entry, which the daemon does not own and so cannot
///   remove;
/// * a first run registers the per-user login start (the belt behind the
///   worker's own registration).
pub async fn startup_checks<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    autostart: bool,
    first_run_done: bool,
) {
    let device = device_autostart_switch().await;
    if autostart && device == Some(false) {
        tracing::info!("login start on a device whose companion_autostart is off — leaving");
        app.exit(0);
        return;
    }
    if !first_run_done && device != Some(false) {
        let _ = tokio::task::spawn_blocking(ensure_user_login_start).await;
    }
}

#[tauri::command]
pub async fn cmd_autostart_get() -> AutostartState {
    let device_on = device_autostart_switch().await != Some(false);
    tokio::task::spawn_blocking(move || autostart_state(device_on))
        .await
        .unwrap_or_else(|e| AutostartState {
            supported: false,
            enabled: false,
            scope: "none".into(),
            note: format!("Unavailable: {e}"),
        })
}

#[tauri::command]
pub async fn cmd_autostart_set(enabled: bool) -> Result<AutostartState, String> {
    let device_on = device_autostart_switch().await != Some(false);
    tokio::task::spawn_blocking(move || {
        set_autostart(enabled, device_on)?;
        Ok(autostart_state(device_on))
    })
    .await
    .map_err(|e| format!("task join: {e}"))?
}

/// Record a person's choice in their desktop state.
#[cfg(not(target_os = "macos"))]
fn record_opt_out(opted_out: bool) -> Result<(), String> {
    let mut s = desktop_state::load();
    s.autostart_opt_out = opted_out;
    desktop_state::save(&s).map_err(|e| format!("saving the desktop state: {e}"))
}

#[cfg(windows)]
fn autostart_state(device_on: bool) -> AutostartState {
    use roomler_node_core::companion_autostart::{
        InstallScope, WINDOWS_RUN_SUBKEY, WINDOWS_RUN_VALUE_NAME, program_files_dirs,
        registry::{Hive, read_value},
        windows_scope_for_exe,
    };
    let opted_out = desktop_state::load().autostart_opt_out;
    let Ok(exe) = std::env::current_exe() else {
        return AutostartState {
            supported: false,
            enabled: false,
            scope: "none".into(),
            note: "Cannot locate this app.".into(),
        };
    };
    match windows_scope_for_exe(&exe, &program_files_dirs()) {
        InstallScope::Machine => {
            let registered = read_value(
                Hive::LocalMachine,
                WINDOWS_RUN_SUBKEY,
                WINDOWS_RUN_VALUE_NAME,
            )
            .ok()
            .flatten()
            .is_some();
            AutostartState {
                supported: registered && device_on,
                enabled: registered && device_on && !opted_out,
                scope: "machine".into(),
                note: if !device_on || !registered {
                    DEVICE_OFF_NOTE.into()
                } else {
                    "Roomler is installed for everyone on this computer; this choice is for your \
                     account only."
                        .into()
                },
            }
        }
        InstallScope::User => {
            let registered = read_value(
                Hive::CurrentUser,
                WINDOWS_RUN_SUBKEY,
                WINDOWS_RUN_VALUE_NAME,
            )
            .ok()
            .flatten()
            .is_some();
            AutostartState {
                supported: device_on,
                enabled: device_on && registered && !opted_out,
                scope: "user".into(),
                note: if device_on {
                    "Installed for your account only.".into()
                } else {
                    DEVICE_OFF_NOTE.into()
                },
            }
        }
    }
}

#[cfg(windows)]
fn set_autostart(enabled: bool, device_on: bool) -> Result<(), String> {
    use roomler_node_core::companion_autostart::{
        InstallScope, WINDOWS_RUN_SUBKEY, WINDOWS_RUN_VALUE_NAME, program_files_dirs,
        registry::{Hive, delete_value, write_value},
        windows_run_command, windows_scope_for_exe,
    };
    if !device_on && enabled {
        return Err(DEVICE_OFF_NOTE.into());
    }
    let exe = std::env::current_exe().map_err(|e| format!("locating this app: {e}"))?;
    if windows_scope_for_exe(&exe, &program_files_dirs()) == InstallScope::User {
        // Per-user: the value is this person's to write or delete.
        if enabled {
            write_value(
                Hive::CurrentUser,
                WINDOWS_RUN_SUBKEY,
                WINDOWS_RUN_VALUE_NAME,
                &windows_run_command(&exe),
            )
            .map_err(|e| format!("registering the login start: {e}"))?;
        } else {
            delete_value(
                Hive::CurrentUser,
                WINDOWS_RUN_SUBKEY,
                WINDOWS_RUN_VALUE_NAME,
            )
            .map_err(|e| format!("removing the login start: {e}"))?;
        }
    }
    // Machine-wide: the HKLM value stays (other accounts), and the choice is
    // honoured at `--autostart`. Recorded either way, so `service install` on
    // a per-user host does not put back what the person took out.
    record_opt_out(!enabled)
}

/// The first run's belt for a per-user install: the worker registers the
/// login start at each start, but the companion may exist before the worker
/// next runs.
#[cfg(windows)]
pub fn ensure_user_login_start() {
    use roomler_node_core::companion_autostart::{
        InstallScope, WINDOWS_RUN_SUBKEY, WINDOWS_RUN_VALUE_NAME, desired_run_value,
        program_files_dirs,
        registry::{Hive, sync_value},
        windows_scope_for_exe,
    };
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    if windows_scope_for_exe(&exe, &program_files_dirs()) != InstallScope::User {
        return;
    }
    let opted_out = desktop_state::load().autostart_opt_out;
    let desired = desired_run_value(true, &exe, true, opted_out);
    match sync_value(
        Hive::CurrentUser,
        WINDOWS_RUN_SUBKEY,
        WINDOWS_RUN_VALUE_NAME,
        desired.as_deref(),
    ) {
        Ok(action) => tracing::debug!(?action, "login start (HKCU) checked"),
        Err(e) => tracing::warn!(error = %e, "login start (HKCU): could not register"),
    }
}

#[cfg(not(windows))]
pub fn ensure_user_login_start() {}

#[cfg(all(unix, not(target_os = "macos")))]
fn xdg_user_file() -> Option<std::path::PathBuf> {
    use roomler_node_core::companion_autostart::{XDG_ENTRY_FILE, xdg_user_autostart_dir};
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let cfg = std::env::var("XDG_CONFIG_HOME").ok();
    xdg_user_autostart_dir(cfg.as_deref(), home.as_deref()).map(|d| d.join(XDG_ENTRY_FILE))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn autostart_state(device_on: bool) -> AutostartState {
    use roomler_node_core::companion_autostart::{XDG_SYSTEM_AUTOSTART, xdg_entry_hidden};
    let system = std::path::Path::new(XDG_SYSTEM_AUTOSTART).exists();
    let user = xdg_user_file().and_then(|p| std::fs::read_to_string(p).ok());
    let enabled = match &user {
        Some(content) => !xdg_entry_hidden(content),
        None => system,
    };
    AutostartState {
        supported: device_on && xdg_user_file().is_some(),
        enabled: device_on && enabled,
        scope: "xdg".into(),
        note: if device_on {
            "Your desktop's autostart list, for your account only.".into()
        } else {
            DEVICE_OFF_NOTE.into()
        },
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn set_autostart(enabled: bool, device_on: bool) -> Result<(), String> {
    use roomler_node_core::companion_autostart::{XDG_SYSTEM_AUTOSTART, xdg_user_entry};
    if !device_on && enabled {
        return Err(DEVICE_OFF_NOTE.into());
    }
    let path = xdg_user_file().ok_or("no home directory")?;
    let system = std::path::Path::new(XDG_SYSTEM_AUTOSTART).exists();
    let ours = std::fs::read_to_string(&path)
        .map(|c| c.contains("X-Roomler-Managed=true"))
        .unwrap_or(false);
    if enabled && system && (ours || !path.exists()) {
        // The package's entry applies again once our override is gone.
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("removing {}: {e}", path.display()))?;
        }
    } else {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "/usr/bin/roomler-desktop".to_string());
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        }
        std::fs::write(&path, xdg_user_entry(&exe, !enabled))
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    record_opt_out(!enabled)
}

#[cfg(target_os = "macos")]
fn autostart_state(_device_on: bool) -> AutostartState {
    AutostartState {
        supported: false,
        enabled: true,
        scope: "macos".into(),
        note: "macOS manages this: System Settings → General → Login Items.".into(),
    }
}

#[cfg(target_os = "macos")]
fn set_autostart(_enabled: bool, _device_on: bool) -> Result<(), String> {
    Err("macOS manages this: System Settings → General → Login Items.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        std::iter::once("roomler-desktop")
            .chain(v.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn argv_is_parsed_for_the_first_process_too() {
        assert_eq!(parse_launch_args(&args(&[])), LaunchArgs::default());
        assert_eq!(
            parse_launch_args(&args(&["--autostart"])),
            LaunchArgs {
                autostart: true,
                ..LaunchArgs::default()
            }
        );
        assert_eq!(
            parse_launch_args(&args(&["--first-run"])),
            LaunchArgs {
                first_run: true,
                ..LaunchArgs::default()
            }
        );
        assert_eq!(
            parse_launch_args(&args(&["--view=devices", "--autostart"])),
            LaunchArgs {
                view: Some("devices".into()),
                autostart: true,
                ..LaunchArgs::default()
            }
        );
        // The view goes into the page: anything but ASCII alphanumerics is
        // dropped, not escaped.
        for bad in [
            "--view=",
            "--view=a'b",
            "--view=../x",
            "--view=welcome;alert(1)",
            "--view=wélcome",
        ] {
            assert_eq!(parse_launch_args(&args(&[bad])).view, None, "{bad}");
        }
        // The program name is never an argument, whatever it is.
        assert_eq!(
            parse_launch_args(&["--first-run".to_string()]),
            LaunchArgs::default()
        );
    }

    #[test]
    fn startup_table() {
        use StartupAction::*;
        let a = |v: &[&str]| parse_launch_args(&args(v));
        let welcome = || Show("welcome".to_string());
        // (args, first_run_done, opted_out) → action
        let table: Vec<(Vec<&str>, bool, bool, StartupAction)> = vec![
            // A person who never finished the tour sees it, however launched.
            (vec![], false, false, welcome()),
            (vec!["--autostart"], false, false, welcome()),
            (vec!["--autostart"], false, true, welcome()),
            (vec!["--first-run"], false, false, welcome()),
            // After the tour: login starts stay in the tray…
            (vec!["--autostart"], true, false, Tray),
            // …or leave at once for a person who switched login start off.
            (vec!["--autostart"], true, true, Exit),
            // A plain start (a daemon respawn, a double-click) keeps today's
            // tray-only behaviour.
            (vec![], true, false, Tray),
            (vec![], true, true, Tray),
            // The installer's launch on an account that already did the tour
            // still opens the window — something was just installed.
            (
                vec!["--first-run"],
                true,
                false,
                Show("overview".to_string()),
            ),
            // An explicit view always wins, even over the tour.
            (
                vec!["--view=devices"],
                false,
                false,
                Show("devices".to_string()),
            ),
            (
                vec!["--view=settings", "--autostart"],
                true,
                true,
                Show("settings".to_string()),
            ),
        ];
        for (v, done, opted_out, want) in table {
            assert_eq!(
                decide_startup(&a(&v), done, opted_out),
                want,
                "{v:?} done={done} opted_out={opted_out}"
            );
        }
    }

    #[test]
    fn a_forwarded_launch_never_pops_a_login_start() {
        use SecondLaunch::*;
        let a = |v: &[&str]| parse_launch_args(&args(v));
        assert_eq!(decide_second_instance(&a(&["--autostart"]), true), Ignore);
        assert_eq!(decide_second_instance(&a(&["--autostart"]), false), Ignore);
        assert_eq!(
            decide_second_instance(&a(&["--view=devices"]), true),
            ShowView("devices".into())
        );
        assert_eq!(
            decide_second_instance(&a(&["--first-run"]), false),
            ShowView("welcome".into())
        );
        assert_eq!(
            decide_second_instance(&a(&["--first-run"]), true),
            ShowView("overview".into())
        );
        // A plain second launch (a double-click) shows the window where it is.
        assert_eq!(decide_second_instance(&a(&[]), true), Show);
    }

    #[test]
    fn free_port_skips_excluded_and_taken_ports() {
        // Fake binder: 41080 and 41081 are taken by someone.
        let taken = [41080u16, 41081];
        let can_bind = |p: u16| !taken.contains(&p);
        assert_eq!(pick_free_port(41080, 10, &[], can_bind), Some(41082));
        // 41082 is a declared route's port (down right now, so bindable) —
        // still not ours to take.
        assert_eq!(pick_free_port(41080, 10, &[41082], can_bind), Some(41083));
        assert_eq!(
            pick_free_port(41080, 2, &[], can_bind),
            None,
            "span exhausted"
        );
        // Never wraps past 65535.
        assert_eq!(pick_free_port(65535, 10, &[], |_| false), None);
        assert_eq!(pick_free_port(65535, 10, &[], |_| true), Some(65535));
    }

    #[test]
    fn free_port_really_skips_a_bound_port() {
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        let got = pick_free_port(port, 50, &[], |p| {
            std::net::TcpListener::bind(("127.0.0.1", p)).is_ok()
        })
        .expect("a free port in the span");
        assert_ne!(got, port, "the held port must be skipped");
        assert!(
            got > port && u32::from(got) < u32::from(port) + 50,
            "{got} is not inside the requested span starting at {port}"
        );
    }
}
