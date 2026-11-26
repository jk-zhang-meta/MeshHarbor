// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! System-tray icon + right-click menu. Built atop Tauri 2's
//! `TrayIcon` API (which wraps the `tray-icon` crate on the OS
//! layer).
//!
//! Menu items:
//!   - Open MeshHarbor       — show the main window (Overview view)
//!   - Start/Stop recording — FR-85: record this screen through the device
//!                           service; the label and the tray tooltip follow
//!                           the recorder (a light poll, every 3 s), and
//!                           the ICON turns red while any recording runs,
//!                           this device's own or a controller's
//!   - Start/Stop keep busy — FR-92: "Stop keep busy (pattern · phase)" while
//!                           it is on, whoever turned it on; "Start keep
//!                           busy" while it is off (P10: the person at the
//!                           computer may turn it on here); disabled where it
//!                           cannot run. A light poll, every 3 s
//!   - Onboarding…        — show the main window on the Onboarding view
//!   - Welcome tour…      — FR-84 D6: the first-run tour, again
//!   - Check for Updates  — invoke `cmd_check_update` and surface
//!                           the result in the Overview's update panel
//!   - Open Logs Folder   — invoke `cmd_open_log_dir`
//!   - Quit                — exit the desktop app; the device service
//!                           keeps running unaffected.
//!
//! Navigation: the SPA is one page with a hash router (`app.js`), so
//! `show_window` navigates by evaluating `location.hash = '#/<view>'`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Runtime};

use crate::tray_i18n::{self, Lang};

/// Static tray menu items whose text updates immediately on language switch.
struct TrayStaticItems<R: Runtime> {
    sign_out: MenuItem<R>,
    join: MenuItem<R>,
    devices: Submenu<R>,
    invites: Submenu<R>,
    open_status: MenuItem<R>,
    open_globe: MenuItem<R>,
    open_web: MenuItem<R>,
    check_updates: MenuItem<R>,
    open_logs: MenuItem<R>,
    quit: MenuItem<R>,
}

static RECORD_WATCH_WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();
static KEEP_BUSY_WATCH_WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();
static UPDATE_WATCH_WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();
static GPU_WATCH_WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Refresh every tray label immediately after the user switches UI language.
pub fn refresh_language<R: Runtime>(app: &AppHandle<R>) {
    let lang = tray_i18n::current_lang();
    if let Some(items) = app.try_state::<TrayStaticItems<R>>() {
        let _ = items.sign_out.set_text(tray_i18n::sign_out_account(lang));
        let _ = items.join.set_text(tray_i18n::join_invite(lang));
        let _ = items.devices.set_text(tray_i18n::network_devices(lang));
        let _ = items.invites.set_text(tray_i18n::invitations(lang));
        let _ = items.open_status.set_text(tray_i18n::open_meshharbor(lang));
        let _ = items.open_globe.set_text(tray_i18n::open_globe(lang));
        let _ = items.open_web.set_text(tray_i18n::admin_console(lang));
        let _ = items.check_updates.set_text(tray_i18n::check_updates(lang));
        let _ = items.open_logs.set_text(tray_i18n::open_logs(lang));
        let _ = items.quit.set_text(tray_i18n::quit(lang));
    }
    ACCOUNT_WATCH_WAKE.notify_one();
    RECORD_WATCH_WAKE.notify_one();
    KEEP_BUSY_WATCH_WAKE.notify_one();
    UPDATE_WATCH_WAKE.notify_one();
    GPU_WATCH_WAKE.notify_one();
}

pub fn install<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let lang = tray_i18n::current_lang();
    // Build the menu. IDs are inspected in `on_menu_event` below.
    // Account rows first, as Tailscale has them: who/what this device is,
    // Log in…, and the network's devices. `spawn_account_watch` keeps them
    // current.
    let account_status = MenuItem::with_id(
        app,
        "account_status",
        tray_i18n::app_name(lang),
        false,
        None::<&str>,
    )?;
    let login = MenuItem::with_id(
        app,
        LOGIN_ITEM_ID,
        tray_i18n::login_ellipsis(lang),
        false,
        None::<&str>,
    )?;
    // Unlike `tailscale logout`, this ends only the account session (shares,
    // permissions, the web hand-off): the device keeps its own credential, so
    // it stays on the network and its Devices list stays. Said in the label,
    // because the operator read the list staying as sign-out not working.
    let sign_out = MenuItem::with_id(
        app,
        "user_sign_out",
        tray_i18n::sign_out_account(lang),
        false,
        None::<&str>,
    )?;
    let join = MenuItem::with_id(
        app,
        JOIN_ITEM_ID,
        tray_i18n::join_invite(lang),
        false,
        None::<&str>,
    )?;
    let devices = Submenu::with_id(app, "devices", tray_i18n::network_devices(lang), true)?;
    // Every invitation this machine holds, each with its own leave.
    let invites = Submenu::with_id(app, "invites", tray_i18n::invitations(lang), false)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let open_status = MenuItem::with_id(
        app,
        "open_status",
        tray_i18n::open_meshharbor(lang),
        true,
        None::<&str>,
    )?;
    // T8b — open the primary org's live 3D globe in the embedded web window
    // (Windows) or Chromium app window / default browser (macOS & Linux).
    let open_globe = MenuItem::with_id(
        app,
        "open_globe",
        tray_i18n::open_globe(lang),
        true,
        None::<&str>,
    )?;
    // S7 — the embedded web-app window (WebView2 on Windows; browser
    // elsewhere). Distinct from the LOCAL status window above.
    let open_web = MenuItem::with_id(
        app,
        "open_web",
        tray_i18n::admin_console(lang),
        true,
        None::<&str>,
    )?;
    // FR-85 — disabled until the service says it has a recorder.
    let record = MenuItem::with_id(
        app,
        RECORD_ITEM_ID,
        tray_i18n::start_recording(lang),
        false,
        None::<&str>,
    )?;
    // FR-92 — disabled until the service says what keep busy is doing.
    let keep_busy = MenuItem::with_id(
        app,
        KEEP_BUSY_ITEM_ID,
        tray_i18n::keep_busy_off(lang),
        false,
        None::<&str>,
    )?;
    let onboarding = MenuItem::with_id(
        app,
        "onboarding",
        tray_i18n::onboarding(lang),
        true,
        None::<&str>,
    )?;
    let welcome = MenuItem::with_id(
        app,
        "welcome",
        tray_i18n::welcome_tour(lang),
        true,
        None::<&str>,
    )?;
    let check_updates_item = MenuItem::with_id(
        app,
        "check_updates",
        tray_i18n::check_updates(lang),
        true,
        None::<&str>,
    )?;
    let open_logs = MenuItem::with_id(
        app,
        "open_logs",
        tray_i18n::open_logs(lang),
        true,
        None::<&str>,
    )?;
    // FR-139 — GPU summary line; inserted into the menu only when the org has
    // at least one visible marked GPU server (`spawn_gpu_watch`).
    let gpu_item = MenuItem::with_id(
        app,
        GPU_ITEM_ID,
        tray_i18n::gpu_servers_free(lang, 0, 0),
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", tray_i18n::quit(lang), true, None::<&str>)?;
    app.manage(TrayStaticItems {
        sign_out: sign_out.clone(),
        join: join.clone(),
        devices: devices.clone(),
        invites: invites.clone(),
        open_status: open_status.clone(),
        open_globe: open_globe.clone(),
        open_web: open_web.clone(),
        check_updates: check_updates_item.clone(),
        open_logs: open_logs.clone(),
        quit: quit.clone(),
    });
    // `onboarding` / `welcome` stay reachable from the window; the tray keeps
    // to the account rows and the everyday actions.
    let _ = (&onboarding, &welcome);
    let menu = Menu::with_items(
        app,
        &[
            &account_status,
            &login,
            &sign_out,
            &join,
            &invites,
            &devices,
            &sep,
            &open_status,
            &open_globe,
            &open_web,
            &record,
            &keep_busy,
            &check_updates_item,
            &open_logs,
            &quit,
        ],
    )?;

    let on_menu = |app: &AppHandle<R>, event: tauri::menu::MenuEvent| match event.id.as_ref() {
        "open_status" => show_window(app, "/overview"),
        "open_globe" => open_network_globe(app),
        "open_web" => open_meshharbor_web(app),
        GPU_ITEM_ID => open_gpu_servers(app),
        "user_sign_out" => {
            tauri::async_runtime::spawn(async {
                let result = async {
                    let server = crate::commands::server_origin().await?;
                    crate::user_account::sign_out(&server).await
                }
                .await;
                if let Err(error) = result {
                    LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner()).error =
                        Some((error, std::time::Instant::now()));
                }
            });
        }
        RECORD_ITEM_ID => toggle_recording(app),
        KEEP_BUSY_ITEM_ID => toggle_keep_busy(app),
        "onboarding" => show_window(app, "/onboarding"),
        "welcome" => show_window(app, "/welcome"),
        "check_updates" => check_updates(app),
        "open_logs" => {
            // The resolve probes the service flavour (CLI spawns) — keep
            // it off the menu/UI thread.
            tauri::async_runtime::spawn_blocking(|| {
                let _ = crate::commands::open_log_dir_blocking();
            });
        }
        "quit" => {
            crate::companion_hello::notify_bye_and_exit(app);
        }
        LOGIN_ITEM_ID => start_login(app),
        JOIN_ITEM_ID => show_window(app, "/onboarding"),
        "invite-features" => show_window(app, "/onboarding"),
        id if id.starts_with(INVITE_ITEM_PREFIX) => {
            start_leave(app, id[INVITE_ITEM_PREFIX.len()..].to_string())
        }
        id if id.starts_with(DEVICE_ITEM_PREFIX) => show_window(app, "/devices"),
        _ => {}
    };
    let on_icon = |tray: &tauri::tray::TrayIcon<R>, event: tauri::tray::TrayIconEvent| {
        // Left-click on the tray icon opens the status window for parity with
        // operators who expect the icon itself to do something useful.
        if let tauri::tray::TrayIconEvent::Click {
            button: tauri::tray::MouseButton::Left,
            button_state: tauri::tray::MouseButtonState::Up,
            ..
        } = event
        {
            show_window(tray.app_handle(), "/overview");
        }
    };

    spawn_account_watch(
        app.clone(),
        AccountMenuItems {
            status: account_status,
            login,
            sign_out,
            join,
            invites,
            devices,
            open_globe: open_globe.clone(),
            admin: open_web.clone(),
        },
    );
    spawn_recording_watch(app.clone(), record);
    spawn_keep_busy_watch(keep_busy);
    spawn_update_watch(check_updates_item);
    spawn_gpu_watch(menu.clone(), gpu_item);
    spawn_gpu_alert_watch();

    // FR-27 — ADOPT the tray Tauri already created from `app.trayIcon` in
    // tauri.conf.json instead of building a second one.
    //
    // Tauri 2 auto-creates a tray from that config block during `build()`,
    // carrying the icon and NO menu. This function then built its own with
    // `TrayIconBuilder` — menu, handlers, and (because nothing ever called
    // `.icon()`) no image at all. The result was two tray entries: one that
    // looked right and did nothing, and one that was blank and held the whole
    // menu. That blank one is what the operator was clicking.
    //
    // Adopting also keeps ONE source of truth for the image: `iconPath` in the
    // config, embedded at build time by `tauri-build`.
    if let Some(tray) = app.tray_by_id(CONFIG_TRAY_ID) {
        tray.set_menu(Some(menu))?;
        tray.set_show_menu_on_left_click(false)?;
        tray.on_menu_event(on_menu);
        tray.on_tray_icon_event(on_icon);
        return Ok(());
    }

    // Fallback: the config block is missing or its id changed. Build one, but
    // give it an EXPLICIT icon — a tray with no image is indistinguishable
    // from a broken install, and that is precisely the bug above.
    tracing::warn!(
        id = CONFIG_TRAY_ID,
        "no config-declared tray icon found — building one with the embedded fallback image"
    );
    let mut builder = TrayIconBuilder::with_id(FALLBACK_TRAY_ID)
        .tooltip("MeshHarbor")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(on_menu)
        .on_tray_icon_event(on_icon);
    // The app icon is already embedded (`bundle.icon`) and needs no PNG
    // decoder at runtime, unlike `Image::from_bytes`, which is behind tauri's
    // `image-png` feature. Wrong shape for a macOS menu bar — it is not a
    // template — but VISIBLE, which is the entire job of a fallback here.
    match app.default_window_icon() {
        Some(icon) => builder = builder.icon(icon.clone()),
        // Never silently ship a blank tray. The symptom reads to a user as
        // "the app did not start", which is how this went unnoticed.
        None => tracing::error!(
            "no embedded app icon either — the tray will be BLANK; \
             check `app.trayIcon` and `bundle.icon` in tauri.conf.json"
        ),
    }
    builder.build(app)?;
    Ok(())
}

/// The id Tauri gives the tray it creates from `app.trayIcon`. Set explicitly
/// in `tauri.conf.json` so this lookup does not depend on Tauri's default.
const CONFIG_TRAY_ID: &str = "meshharbor";
/// The fallback tray's id (see `install`).
const FALLBACK_TRAY_ID: &str = "meshharbor-desktop-tray";

/// FR-85 — the Start/Stop recording menu item.
const RECORD_ITEM_ID: &str = "record_toggle";
/// FR-92 — the keep-busy item: its state, Start and Stop.
const KEEP_BUSY_ITEM_ID: &str = "keep_busy_toggle";
/// FR-139 — the GPU Servers summary line (hidden when 0 GPU servers).
const GPU_ITEM_ID: &str = "open_gpu";

/// FR-92 — the tray's keep-busy item: `(text, enabled)`.
/// - On, whoever turned it on: a Stop. The person at the device must always
///   be able to end what is moving their pointer.
/// - Off where it can run: a Start (P10, the person's own "on").
/// - Off where it cannot (the owner switched it off, the org denies it, no
///   permission, an unsupported desktop): disabled. The agent's reason is in
///   `mh keep-busy status`.
/// - `None` (no service answered yet, or one older than FR-92): disabled.
#[cfg(test)]
fn keep_busy_labels(state: Option<&meshharbor_localapi::KeepBusyInfo>) -> (String, bool) {
    keep_busy_labels_in(state, Lang::En)
}

fn keep_busy_labels_in(
    state: Option<&meshharbor_localapi::KeepBusyInfo>,
    lang: Lang,
) -> (String, bool) {
    match state {
        Some(s) if s.on => {
            let pattern = {
                let mut c = s.pattern.chars();
                match c.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    None => tray_i18n::keep_busy_pattern_fallback(lang).into(),
                }
            };
            (tray_i18n::stop_keep_busy(lang, &pattern, &s.phase), true)
        }
        Some(s) if s.available => (tray_i18n::start_keep_busy(lang).into(), true),
        Some(_) => (tray_i18n::keep_busy_unavailable(lang).into(), false),
        None => (tray_i18n::keep_busy_off(lang).into(), false),
    }
}

/// FR-92 — keep the item in step with the device, every 3 s (the same
/// cadence and connection pool as the recording item).
fn spawn_keep_busy_watch<R: Runtime>(item: MenuItem<R>) {
    tauri::async_runtime::spawn(async move {
        let mut shown: Option<(String, bool)> = None;
        loop {
            let answer = match meshharbor_localapi::connect().await {
                Ok(mut c) => c.keep_busy_status().await.ok(),
                Err(_) => None,
            };
            let labels = keep_busy_labels_in(answer.as_ref(), tray_i18n::current_lang());
            if shown.as_ref() != Some(&labels) {
                let _ = item.set_text(&labels.0);
                let _ = item.set_enabled(labels.1);
                if let Some(s) = answer.as_ref()
                    && s.on
                {
                    tracing::info!(
                        pattern = %s.pattern,
                        set_by = s.set_by.as_deref().unwrap_or("-"),
                        "tray: keep busy is on"
                    );
                }
                shown = Some(labels);
            }
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
                _ = KEEP_BUSY_WATCH_WAKE.notified() => {}
            }
        }
    });
}

/// FR-92 — the person at the device starts or stops keep busy: whatever it
/// is NOW, read at the click (the label may be up to 3 s old). Off starts it
/// with the product defaults (P10); anything on stops it.
fn toggle_keep_busy<R: Runtime>(_app: &AppHandle<R>) {
    tauri::async_runtime::spawn(async move {
        let outcome: std::io::Result<(bool, meshharbor_localapi::KeepBusyInfo)> = async {
            let mut c = meshharbor_localapi::connect().await?;
            let stopping = c.keep_busy_status().await?.on;
            let s = if stopping {
                c.keep_busy_off().await?
            } else {
                c.keep_busy_on(Default::default()).await?
            };
            Ok((stopping, s))
        }
        .await;
        let (stopping, s) = match outcome {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(%e, "tray: could not toggle keep busy");
                return;
            }
        };
        let reason = s.reason.as_deref().unwrap_or("-");
        match keep_busy_click(stopping, &s) {
            KeepBusyClick::Stopped => tracing::info!(reason, "tray: keep busy stopped"),
            KeepBusyClick::DidNotStop => tracing::warn!(
                phase = %s.phase,
                reason,
                "tray: keep busy did not stop"
            ),
            KeepBusyClick::Started => tracing::info!(phase = %s.phase, "tray: keep busy started"),
            KeepBusyClick::DidNotStart => tracing::warn!(
                phase = %s.phase,
                reason,
                sentence = s.sentence.as_deref().unwrap_or("-"),
                "tray: keep busy did not start"
            ),
        }
    });
}

/// FR-92 — what a click on the keep-busy item did, named by the action
/// taken. Reading it off the answer's shape alone logged every successful
/// Stop as "did not start": a stop answers `on: false` WITH a reason
/// (`stopped_locally`), exactly like a refused start (field, row 49).
#[derive(Debug, PartialEq, Eq)]
enum KeepBusyClick {
    Stopped,
    DidNotStop,
    Started,
    /// Refused (`on: false`), or accepted but unable to move the pointer
    /// (`phase: unavailable`, e.g. `no_permission` on a Mac without the
    /// Accessibility grant, which answers `on: true`).
    DidNotStart,
}

fn keep_busy_click(stopping: bool, s: &meshharbor_localapi::KeepBusyInfo) -> KeepBusyClick {
    match (stopping, s.on) {
        (true, false) => KeepBusyClick::Stopped,
        (true, true) => KeepBusyClick::DidNotStop,
        (false, true) if s.phase != "unavailable" => KeepBusyClick::Started,
        (false, _) => KeepBusyClick::DidNotStart,
    }
}

/// FR-85 — the configured tray's icon while nothing records: the menu-bar
/// template `app.trayIcon` names.
const TRAY_IDLE: tauri::image::Image<'static> = tauri::include_image!("icons/tray.png");
/// FR-85 — the tray while a recording runs: the mark in full colour with a
/// red dot (`scripts/gen-tray-icons.py`).
const TRAY_RECORDING: tauri::image::Image<'static> =
    tauri::include_image!("icons/tray-recording.png");

/// The idle tray for a DARK taskbar (Windows): the approved white template
/// (`design/x18/assets/template/tray/white-48.png`). macOS needs none — it
/// tints the black template to the menu bar itself.
const TRAY_IDLE_WHITE: tauri::image::Image<'static> = tauri::include_image!("icons/tray-white.png");

/// Is the Windows taskbar dark? Read each time the tray refreshes, so a
/// theme switch shows within a poll. `SystemUsesLightTheme` = 0 is dark; an
/// absent value is a Windows 10 before 1903, whose taskbar is always dark.
#[cfg(target_os = "windows")]
fn taskbar_dark() -> bool {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
    let sub: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\0"
        .encode_utf16()
        .collect();
    let name: Vec<u16> = "SystemUsesLightTheme\0".encode_utf16().collect();
    let mut data: u32 = 1;
    let mut size: u32 = std::mem::size_of::<u32>() as u32;
    // SAFETY: both names are NUL-terminated UTF-16 that outlive the call;
    // `data` / `size` describe a live, correctly sized DWORD buffer.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            sub.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    if rc == 0 { data == 0 } else { true }
}

#[cfg(not(target_os = "windows"))]
fn taskbar_dark() -> bool {
    false
}

/// FR-85 — the configured tray's icon for the recorder's state, and whether
/// it is a macOS template. ⚠️ The red one is never a template: the system
/// tints a template to the menu bar's colour, and a recording must read as
/// red (docs/remote-control.md §11.3). Idle on a dark Windows taskbar: the
/// white mark (the black one is all but invisible there).
fn tray_look_for(recording: bool, dark: bool) -> (tauri::image::Image<'static>, bool) {
    if recording {
        (TRAY_RECORDING, false)
    } else if dark {
        (TRAY_IDLE_WHITE, true)
    } else {
        (TRAY_IDLE, true)
    }
}

fn tray_look(recording: bool) -> (tauri::image::Image<'static>, bool) {
    tray_look_for(recording, taskbar_dark())
}

/// FR-85 — the two things that turn the tray red, each learned by a poll:
/// - a controller's recording MARKED on a session (the session watch in
///   `main.rs`, every 750 ms, the poll the "being viewed" banner rides). The
///   daemon marks a remote recording before its first frame is written, so
///   the red comes up with the banner (AC5: "the host's banner and red dot");
/// - the recorder RUNNING (`spawn_recording_watch`, every 3 s), which also
///   covers a recording the person started here.
///
/// ⚠️ Each changes only when its poll is ANSWERED. A poll that failed (the
/// pipe busy for a moment) keeps what the last answer said, so the red never
/// drops off a recording that is still running; a recording that ended
/// answers so. (The FR-84 D1 rule: a failed refresh keeps the last good
/// data. For an indicator of recording, the wrong way to fail is to say
/// nothing is.) A service that is not there at all IS an answer
/// ([`no_service`]): nothing records without it, and the banner comes down
/// with it, so the tray must too.
static REMOTE_MARKED: AtomicBool = AtomicBool::new(false);
static RECORDER_RUNNING: AtomicBool = AtomicBool::new(false);
/// Whether the tray is red now. Both watches apply it; the lock makes one
/// change at a time.
/// What the tray shows: (recording red, dark-taskbar white). Starts as the
/// configured icon: black, not red.
static SHOWN_RED: Mutex<(bool, bool)> = Mutex::new((false, false));

/// FR-85 — the device service is not there at all: its pipe or socket is
/// missing, or nobody listens on it. That is an ANSWER (nothing records
/// without it), unlike a busy or failing one.
pub fn no_service(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

/// FR-85 — the recorder's input after a poll. `Some(answer)`: the service
/// answered, and `Some(None)` is no service at all, so nothing records.
/// `None`: the poll failed; what the last answer said stands.
fn recorder_running(
    answer: Option<Option<&meshharbor_localapi::RecordingState>>,
    was: bool,
) -> bool {
    match answer {
        Some(state) => state.is_some_and(|s| s.active),
        None => was,
    }
}

/// FR-85 — whether any session carries a recording mark, or what the last
/// answer said when the poll failed (`None`).
fn remote_marked(answer: Option<&[meshharbor_localapi::RcSessionInfo]>, was: bool) -> bool {
    answer.map_or(was, |sessions| sessions.iter().any(|s| s.recording))
}

/// FR-85 — the session watch's answer (`main.rs`): `None` when the poll
/// failed.
pub fn sessions_answered<R: Runtime>(
    app: &AppHandle<R>,
    answer: Option<&[meshharbor_localapi::RcSessionInfo]>,
) {
    let was = REMOTE_MARKED.load(Ordering::Acquire);
    REMOTE_MARKED.store(remote_marked(answer, was), Ordering::Release);
    apply_red(app);
}

/// FR-27 P9 — whether a recording runs, by the same two watches that turn the
/// tray red. The session banner stays up for as long as this says yes.
pub fn recording_now() -> bool {
    REMOTE_MARKED.load(Ordering::Acquire) || RECORDER_RUNNING.load(Ordering::Acquire)
}

/// Red while either says a recording runs; back after.
fn apply_red<R: Runtime>(app: &AppHandle<R>) {
    let Ok(mut shown) = SHOWN_RED.lock() else {
        return;
    };
    // Read UNDER the lock: read before it, a watch holding a stale pair
    // could apply it after the other watch had applied the fresh one.
    let want = REMOTE_MARKED.load(Ordering::Acquire) || RECORDER_RUNNING.load(Ordering::Acquire);
    // The taskbar's colour only matters to the idle icon.
    let dark = !want && taskbar_dark();
    if *shown == (want, dark) {
        return;
    }
    let mut applied = false;
    for id in [CONFIG_TRAY_ID, FALLBACK_TRAY_ID] {
        if let Some(tray) = app.tray_by_id(id) {
            applied |= set_tray_look(app, &tray, id == CONFIG_TRAY_ID, want);
        }
    }
    // Only a change that took counts as shown: one that failed (Explorer
    // restarting, a temp file that could not be written) is tried again at
    // the next poll, rather than leave a whole recording without the red.
    if applied {
        tracing::info!(recording = want, dark_taskbar = dark, "tray: icon updated");
        *shown = (want, dark);
    }
}

/// What the tray shows for the recorder's state. Pure, so the wording is
/// tested: a service without a recorder answers `available: false` and the
/// item is disabled; `None` (nothing has answered yet) is the tray as
/// `install` builds it, the item disabled too. A controller's recording
/// names them: the person at the device sees who is recording their screen.
#[cfg(test)]
fn record_labels(state: Option<&meshharbor_localapi::RecordingState>) -> (String, bool, String) {
    record_labels_in(state, Lang::En)
}

fn record_labels_in(
    state: Option<&meshharbor_localapi::RecordingState>,
    lang: Lang,
) -> (String, bool, String) {
    match state {
        Some(s) if s.active => {
            let secs = s.duration_ms / 1000;
            let t = format!("{}:{:02}", secs / 60, secs % 60);
            let tooltip = match s.remote_controller.as_deref() {
                Some(who) => tray_i18n::tooltip_remote_recording(lang, who, &t),
                None => tray_i18n::tooltip_recording(lang, &t),
            };
            (tray_i18n::stop_recording(lang, &t), true, tooltip)
        }
        // Start only where the service says a recording can start at all.
        Some(s) => (
            tray_i18n::start_recording(lang).into(),
            s.available,
            tray_i18n::app_name(lang).into(),
        ),
        None => (
            tray_i18n::start_recording(lang).into(),
            false,
            tray_i18n::app_name(lang).into(),
        ),
    }
}

/// Keep the menu item, the tooltip and the icon in step with the recorder,
/// started by this item, the Recordings view, `mh record` or a
/// controller alike. One LocalAPI request every 3 s — the listener keeps a
/// pool of instances (FR-84 D1).
fn spawn_recording_watch<R: Runtime>(app: AppHandle<R>, item: MenuItem<R>) {
    tauri::async_runtime::spawn(async move {
        let mut shown: Option<(String, bool, String)> = None;
        let mut last_answer: Option<Option<meshharbor_localapi::RecordingState>> = None;
        let mut shown_gen = tray_i18n::language_generation();
        loop {
            // `Some(Some(state))` answered; `Some(None)` there is no service
            // at all; `None` the poll failed.
            let answer = match meshharbor_localapi::connect().await {
                Ok(mut c) => c.record_status().await.ok().map(Some),
                Err(e) if no_service(&e) => Some(None),
                Err(_) => None,
            };
            if answer.is_some() {
                last_answer = answer.clone();
            }
            let cur_gen = tray_i18n::language_generation();
            let effective = answer.as_ref().or(last_answer.as_ref());
            // Only an answer changes the tray, the words as well as the icon
            // (`recorder_running`), so the two never disagree. Until the
            // first answer it stays as `install` built it: the item disabled,
            // refreshed if the user switches language before any answer.
            if let Some(state) = effective {
                let labels = record_labels_in(state.as_ref(), tray_i18n::current_lang());
                if shown.as_ref() != Some(&labels) {
                    let _ = item.set_text(&labels.0);
                    let _ = item.set_enabled(labels.1);
                    for id in [CONFIG_TRAY_ID, FALLBACK_TRAY_ID] {
                        if let Some(tray) = app.tray_by_id(id) {
                            let _ = tray.set_tooltip(Some(&labels.2));
                        }
                    }
                    shown = Some(labels);
                }
            } else if cur_gen != shown_gen {
                let labels = record_labels_in(None, tray_i18n::current_lang());
                let _ = item.set_text(&labels.0);
                let _ = item.set_enabled(labels.1);
            }
            shown_gen = cur_gen;
            let was = RECORDER_RUNNING.load(Ordering::Acquire);
            RECORDER_RUNNING.store(
                recorder_running(answer.as_ref().map(Option::as_ref), was),
                Ordering::Release,
            );
            apply_red(&app);
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
                _ = RECORD_WATCH_WAKE.notified() => {}
            }
        }
    });
}

/// FR-85 — turn the tray red while a recording runs, and back after. The
/// fallback tray (built when `app.trayIcon` names none) idles on the app
/// icon, as `install` built it. `true` = the icon changed.
fn set_tray_look<R: Runtime>(
    app: &AppHandle<R>,
    tray: &tauri::tray::TrayIcon<R>,
    configured: bool,
    recording: bool,
) -> bool {
    let (icon, template) = if configured || recording {
        tray_look(recording)
    } else {
        match app.default_window_icon() {
            Some(icon) => (icon.clone(), false),
            None => return false,
        }
    };
    // The icon and its template flag in ONE step: set apart, macOS draws
    // the idle template untinted for a moment, invisible on a dark menu bar.
    // Elsewhere this is `set_icon`.
    match tray.set_icon_with_as_template(Some(icon), template) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(%e, recording, "tray: could not change the icon");
            false
        }
    }
}

/// Start or stop a recording from the tray. A refusal (not the console
/// user, no encoder, a SYSTEM/root service) is shown in the Recordings view,
/// where it can be read — a tray has nowhere to put a sentence.
fn toggle_recording<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let outcome: Result<(), String> = async {
            let mut client = meshharbor_localapi::connect()
                .await
                .map_err(|e| format!("connecting to the device service: {e}"))?;
            let state = client.record_status().await.map_err(|e| e.to_string())?;
            if state.active {
                client.record_stop().await.map(|_| ())
            } else {
                client.record_start(Default::default()).await.map(|_| ())
            }
            .map_err(|e| {
                let m = e.to_string();
                m.strip_prefix("localapi error: ").unwrap_or(&m).to_string()
            })
        }
        .await;
        if let Err(message) = outcome {
            tracing::warn!(%message, "tray: recording toggle refused");
            show_window(&app, "/recordings");
            if let Some(window) = app.get_webview_window("main") {
                let text = serde_json::to_string(&message).unwrap_or_else(|_| "\"\"".into());
                let _ = window.eval(format!(
                    "window.MeshHarborRecordings && window.MeshHarborRecordings.showError({text})"
                ));
            }
        }
    });
}

/// Show + focus the main window and route the SPA to `path` (a hash-router
/// path like `/overview`). The router treats an unknown hash as `/overview`,
/// so a stale path can't strand the window on a blank page.
fn show_window<R: Runtime>(app: &AppHandle<R>, path: &str) {
    if let Some(window) = app.get_webview_window("main") {
        // Navigate (no-op when already on the same path).
        let _ = window.eval(format!("window.location.hash = '#{path}'"));
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// T8b — open the primary org's 3D network globe from the tray menu using the
/// active persisted UI language (with OS fallback) and `theme=system`.
fn open_network_globe<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(error) =
            crate::commands::open_network_globe_impl(&app, None, Some("system".to_string())).await
        {
            tracing::warn!(%error, "tray: could not open network globe");
            LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner()).error =
                Some((error, std::time::Instant::now()));
        }
    });
}

/// S7 — resolve the server origin OFF the menu thread (config load +
/// service-flavour probe spawn), then open the web window ON the main
/// thread (window creation is main-thread-only on Windows).
fn open_meshharbor_web<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let result = async {
            let server = crate::commands::server_origin().await?;
            crate::commands::open_authenticated_web(
                &app,
                &server,
                meshharbor_node_core::user_session::WebTarget::Dashboard,
            )
            .await
            .map(|_| ())
        }
        .await;
        if let Err(error) = result {
            LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner()).error =
                Some((error, std::time::Instant::now()));
        }
    });
}

fn update_menu_label(
    info: Option<&meshharbor_localapi::UpdateStatusInfo>,
    lang: tray_i18n::Lang,
) -> String {
    if let Some(s) = info
        && s.update_available
        && let Some(ver) = s.latest.as_deref()
    {
        if s.staged_ready || s.stage == "ready" {
            return tray_i18n::update_ready(lang, ver);
        }
        return tray_i18n::update_available(lang, ver);
    }
    tray_i18n::check_updates(lang).to_string()
}

/// Poll `LocalAPI::UpdateStatus` every 30 s (zero network I/O) so when the
/// daemon silently pre-downloads a verified update in the background, the tray
/// item gently advertises `"Update Ready (x.y.z) — Install"`.
fn spawn_update_watch<R: Runtime>(item: MenuItem<R>) {
    tauri::async_runtime::spawn(async move {
        let mut shown: Option<String> = None;
        loop {
            let answer = match meshharbor_localapi::connect().await {
                Ok(mut c) => c.update_status().await.ok(),
                Err(_) => None,
            };
            let label = update_menu_label(answer.as_ref(), tray_i18n::current_lang());
            if shown.as_deref() != Some(label.as_str()) {
                let _ = item.set_text(&label);
                shown = Some(label);
            }
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                _ = UPDATE_WATCH_WAKE.notified() => {}
            }
        }
    });
}

fn check_updates<R: Runtime>(app: &AppHandle<R>) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let payload = match crate::commands::cmd_check_update().await {
            Ok(info) => {
                UPDATE_WATCH_WAKE.notify_one();
                serde_json::json!({ "status": info })
            }
            Err(e) => {
                tracing::warn!(%e, "check-update failed");
                serde_json::json!({ "error": e })
            }
        };
        if let Some(window) = handle.get_webview_window("main") {
            let json = payload.to_string();
            let _ = window.eval(format!(
                "window.__meshharbor_check_update_result = {json}; window.dispatchEvent(new Event('meshharbor-update-check'))"
            ));
            let _ = window.show();
            let _ = window.set_focus();
        }
    });
}

/// FR-139 — open the primary org's GPU Servers page in the default browser
/// (falling back to the authenticated dashboard if tenant/server is unknown).
fn open_gpu_servers<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let target_url = async {
            let server = crate::commands::server_origin().await.ok()?;
            let mut client = meshharbor_localapi::connect().await.ok()?;
            let status = client.status().await.ok()?;
            let tid = status.tenant_id.filter(|s| !s.trim().is_empty())?;
            let base = server.trim_end_matches('/');
            Some(format!("{base}/tenant/{tid}/gpu"))
        }
        .await;
        if let Some(url) = target_url {
            use tauri_plugin_shell::ShellExt as _;
            #[allow(deprecated)]
            let opened = app.shell().open(&url, None);
            if let Err(err) = opened {
                tracing::warn!(%err, "tray: failed to open GPU servers URL");
                open_meshharbor_web(&app);
            }
        } else {
            open_meshharbor_web(&app);
        }
    });
}

/// Compute `(visible, label)` for the FR-139 GPU tray item.
fn gpu_menu_state(
    fleet: Option<&meshharbor_localapi::GpuFleetPage>,
    lang: tray_i18n::Lang,
) -> (bool, String) {
    match fleet {
        Some(page) if page.summary.hosts_total > 0 => (
            true,
            tray_i18n::gpu_servers_free(lang, page.summary.gpus_free, page.summary.gpus_total),
        ),
        _ => (false, tray_i18n::gpu_servers_free(lang, 0, 0)),
    }
}

/// FR-139 — poll LocalAPI `GpuFleet { live: false }` every 30 s when GPU
/// servers exist, backing off to 5 min when 0 GPU servers are marked (and
/// hiding the menu item completely while count is 0).
fn spawn_gpu_watch<R: Runtime>(menu: Menu<R>, item: MenuItem<R>) {
    const MENU_INSERT_POS: usize = 6; // immediately after `devices`, before `sep`
    tauri::async_runtime::spawn(async move {
        let mut inserted = false;
        let mut last_label: Option<String> = None;
        loop {
            let answer = match meshharbor_localapi::connect().await {
                Ok(mut c) => c.gpu_fleet("", false, 0, &[]).await.ok(),
                Err(_) => None,
            };
            let (visible, label) = gpu_menu_state(answer.as_ref(), tray_i18n::current_lang());
            if visible {
                if last_label.as_deref() != Some(label.as_str()) {
                    let _ = item.set_text(&label);
                    last_label = Some(label);
                }
                if !inserted && menu.insert(&item, MENU_INSERT_POS).is_ok() {
                    inserted = true;
                }
            } else if inserted {
                let _ = menu.remove(&item);
                inserted = false;
                last_label = None;
            }
            let sleep_secs = if visible { 30 } else { 300 };
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)) => {}
                _ = GPU_WATCH_WAKE.notified() => {}
            }
        }
    });
}

/// Filter incoming GPU alert items, advancing `last_seq` monotonically and
/// skipping stale historical alerts (> 5 min old) on the very first poll.
fn select_new_gpu_alerts(
    items: &[meshharbor_localapi::GpuAlertItem],
    last_seq: &mut u64,
    first_poll: bool,
    now_s: i64,
) -> Vec<meshharbor_localapi::GpuAlertItem> {
    let mut out = Vec::new();
    for item in items {
        if item.seq <= *last_seq {
            continue;
        }
        *last_seq = item.seq;
        if first_poll && item.at > 0 && now_s.saturating_sub(item.at) > 300 {
            continue;
        }
        out.push(item.clone());
    }
    out
}

/// FR-139 — poll LocalAPI `GpuAlerts { after_seq }` every 15 s (pure daemon
/// memory read; zero network traffic) and raise OS desktop notifications.
fn spawn_gpu_alert_watch() {
    tauri::async_runtime::spawn(async move {
        let mut last_seq: u64 = 0;
        let mut first_poll = true;
        loop {
            if let Ok(mut client) = meshharbor_localapi::connect().await
                && let Ok(page) = client.gpu_alerts(last_seq).await
            {
                let now_s = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let fresh = select_new_gpu_alerts(&page.alerts, &mut last_seq, first_poll, now_s);
                first_poll = false;
                for alert in fresh {
                    let title = alert.title;
                    let body = alert.body;
                    let _ = tokio::task::spawn_blocking(move || {
                        notify_os_gpu_alert(&title, &body);
                    })
                    .await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
    });
}

/// Best-effort native OS desktop notification for a GPU alert (injection-safe:
/// title/body passed via argv or env, never interpolated into shell/script).
fn notify_os_gpu_alert(title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .args(["--app-name=MeshHarbor", "--", title, body])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("osascript")
            .args([
                "-e",
                "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run",
                "--",
                title,
                body,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let script = r#"
Add-Type -AssemblyName System.Windows.Forms
$n = New-Object System.Windows.Forms.NotifyIcon
$n.Icon = [System.Drawing.SystemIcons]::Information
$n.Visible = $true
$n.ShowBalloonTip(5000, $env:MH_GPU_TITLE, $env:MH_GPU_BODY, [System.Windows.Forms.ToolTipIcon]::Info)
Start-Sleep -Seconds 6
$n.Dispose()
"#;
        let _ = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", script])
            .env("MH_GPU_TITLE", title)
            .env("MH_GPU_BODY", body)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-92 — the item is a Stop exactly while keep busy is on; off, an
    /// older service, or no answer at all leave it disabled (there is no
    /// local "on" to offer).
    #[test]
    fn fr139_gpu_menu_state_hides_when_zero_and_formats_bilingual() {
        let empty = meshharbor_localapi::GpuFleetPage::default();
        assert_eq!(gpu_menu_state(None, tray_i18n::Lang::En).0, false);
        assert_eq!(gpu_menu_state(Some(&empty), tray_i18n::Lang::En).0, false);

        let mut active = meshharbor_localapi::GpuFleetPage::default();
        active.summary.hosts_total = 2;
        active.summary.gpus_total = 8;
        active.summary.gpus_free = 3;
        assert_eq!(
            gpu_menu_state(Some(&active), tray_i18n::Lang::En),
            (true, "GPU: 3/8 free".into())
        );
        assert_eq!(
            gpu_menu_state(Some(&active), tray_i18n::Lang::ZhCn),
            (true, "GPU：3/8 空闲".into())
        );
    }

    #[test]
    fn fr139_select_new_gpu_alerts_advances_seq_and_skips_stale_first_poll() {
        let now = 1_760_000_000i64;
        let items = vec![
            meshharbor_localapi::GpuAlertItem {
                seq: 1,
                at: now - 900, // stale (> 5 min)
                severity: "info".into(),
                title: "old".into(),
                body: "old".into(),
                link: "/gpu".into(),
            },
            meshharbor_localapi::GpuAlertItem {
                seq: 2,
                at: now - 30, // fresh
                severity: "warning".into(),
                title: "fresh".into(),
                body: "body".into(),
                link: "/gpu".into(),
            },
        ];
        let mut last = 0;
        let first = select_new_gpu_alerts(&items, &mut last, true, now);
        assert_eq!(last, 2);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].seq, 2);

        // Re-polling same batch emits nothing.
        let second = select_new_gpu_alerts(&items, &mut last, false, now);
        assert!(second.is_empty());
    }

    #[test]
    fn keep_busy_item_is_a_stop_while_on_and_a_start_where_it_can_run() {
        assert_eq!(keep_busy_labels(None), ("Keep busy: off".into(), false));
        let mut s = meshharbor_localapi::KeepBusyInfo {
            available: true,
            on: true,
            phase: "paused".into(),
            pattern: "heart".into(),
            ..Default::default()
        };
        assert_eq!(
            keep_busy_labels(Some(&s)),
            ("Stop keep busy (Heart · paused)".into(), true)
        );
        // FR-92 P10 — off where it can run: the person's own Start.
        s.on = false;
        assert_eq!(keep_busy_labels(Some(&s)), ("Start keep busy".into(), true));
        // Off where it cannot (owner, org, permission, desktop): no Start.
        assert_eq!(
            keep_busy_labels(Some(&meshharbor_localapi::KeepBusyInfo::unavailable())),
            ("Keep busy: unavailable".into(), false)
        );
    }

    /// FR-92 field row 49 — a click is named by what it did. A successful
    /// Stop answers `on: false` with `reason: stopped_locally`, the same shape
    /// as a refused Start, and used to be logged as "did not start".
    #[test]
    fn a_keep_busy_click_is_named_by_the_action_taken() {
        let stopped = meshharbor_localapi::KeepBusyInfo {
            available: true,
            on: false,
            phase: "off".into(),
            reason: Some("stopped_locally".into()),
            ..Default::default()
        };
        assert_eq!(keep_busy_click(true, &stopped), KeepBusyClick::Stopped);
        // The same answer to a Start is a refusal.
        assert_eq!(keep_busy_click(false, &stopped), KeepBusyClick::DidNotStart);
        let running = meshharbor_localapi::KeepBusyInfo {
            available: true,
            on: true,
            phase: "running".into(),
            ..Default::default()
        };
        assert_eq!(keep_busy_click(false, &running), KeepBusyClick::Started);
        assert_eq!(keep_busy_click(true, &running), KeepBusyClick::DidNotStop);
        // Accepted but unable to move the pointer (a Mac without the
        // Accessibility grant answers `on: true`, `phase: unavailable`).
        let no_permission = meshharbor_localapi::KeepBusyInfo {
            on: true,
            phase: "unavailable".into(),
            reason: Some("no_permission".into()),
            ..Default::default()
        };
        assert_eq!(
            keep_busy_click(false, &no_permission),
            KeepBusyClick::DidNotStart
        );
    }

    /// FR-85 — the tray says what the recorder is doing, and a service
    /// without a recorder (or none at all) leaves the item disabled rather
    /// than offering a Start that can only fail.
    #[test]
    fn the_record_item_follows_the_recorder() {
        let idle = meshharbor_localapi::RecordingState {
            available: true,
            ..Default::default()
        };
        assert_eq!(
            record_labels(Some(&idle)),
            ("Start recording".into(), true, "MeshHarbor".into())
        );
        // A service that cannot record here (no recorder, or SYSTEM/root
        // until P1e) answers idle — and the item stays greyed out.
        let cannot =
            meshharbor_localapi::RecordingState::unavailable(meshharbor_localapi::NO_RECORDER);
        assert!(!record_labels(Some(&cannot)).1);
        let live = meshharbor_localapi::RecordingState {
            available: true,
            active: true,
            duration_ms: 83_900,
            ..Default::default()
        };
        assert_eq!(
            record_labels(Some(&live)),
            (
                "Stop recording (1:23)".into(),
                true,
                "MeshHarbor — recording 1:23".into()
            )
        );
        assert_eq!(
            record_labels(None),
            ("Start recording".into(), false, "MeshHarbor".into())
        );
        // A controller's recording names them: the person at the device sees
        // who is recording, not just that something is.
        let remote = meshharbor_localapi::RecordingState {
            available: true,
            active: true,
            duration_ms: 5_000,
            remote_controller: Some("Tester".into()),
            ..Default::default()
        };
        assert_eq!(
            record_labels(Some(&remote)),
            (
                "Stop recording (0:05)".into(),
                true,
                "MeshHarbor — Tester is recording, 0:05".into()
            )
        );
    }

    /// FR-85 — the red follows the service's answers, and a poll that fails
    /// changes nothing: a busy pipe mid-recording must not take the red off
    /// (nor put it on). Both inputs: the recorder, and a controller's mark on
    /// a session, which only a session RECORDING sets (a viewer's does not).
    #[test]
    fn only_an_answer_moves_the_red() {
        let idle = meshharbor_localapi::RecordingState {
            available: true,
            ..Default::default()
        };
        let live = meshharbor_localapi::RecordingState {
            available: true,
            active: true,
            ..Default::default()
        };
        assert!(
            recorder_running(Some(Some(&live)), false),
            "a recording started"
        );
        assert!(
            !recorder_running(Some(Some(&idle)), true),
            "a recording ended"
        );
        assert!(
            recorder_running(None, true),
            "a failed poll took the red off"
        );
        assert!(
            !recorder_running(None, false),
            "a failed poll turned it red"
        );
        // No service at all is an answer: nothing records without it.
        assert!(
            !recorder_running(Some(None), true),
            "the red outlived the device service"
        );
        use std::io::{Error, ErrorKind};
        assert!(no_service(&Error::from(ErrorKind::NotFound)));
        assert!(no_service(&Error::from(ErrorKind::ConnectionRefused)));
        for busy in [ErrorKind::TimedOut, ErrorKind::WouldBlock, ErrorKind::Other] {
            assert!(
                !no_service(&Error::from(busy)),
                "{busy:?} read as no service"
            );
        }

        let session = |recording| meshharbor_localapi::RcSessionInfo {
            session_id: "0".repeat(24),
            recording,
            ..Default::default()
        };
        let watched = [session(false)];
        let recorded = [session(false), session(true)];
        assert!(
            remote_marked(Some(&recorded), false),
            "a controller records"
        );
        assert!(!remote_marked(Some(&watched), true), "a viewer is not red");
        assert!(!remote_marked(Some(&[]), true), "no session is not red");
        assert!(remote_marked(None, true), "a failed poll took the red off");
        assert!(!remote_marked(None, false), "a failed poll turned it red");
    }

    /// The red, fully opaque pixels of `img`, anywhere or only in its
    /// bottom-right quarter.
    fn red_pixels(img: &tauri::image::Image<'_>, bottom_right_only: bool) -> usize {
        let (w, h) = (img.width() as usize, img.height() as usize);
        img.rgba()
            .chunks_exact(4)
            .enumerate()
            .filter(|(i, p)| {
                let (x, y) = (i % w, i / w);
                (!bottom_right_only || (x >= w / 2 && y >= h / 2))
                    && p[0] > 200
                    && p[1] < 100
                    && p[2] < 100
                    && p[3] > 200
            })
            .count()
    }

    /// FR-85 — a recording turns the tray red (docs/remote-control.md
    /// §11.3). The icon swapped in has a red dot, in its bottom-right corner
    /// and nowhere else; the idle one has no red at all; the red one is never
    /// a macOS template (the system would tint it) and is the idle one's
    /// size, so the menu bar does not jump.
    /// A dark Windows taskbar gets the white mark, a light one the black;
    /// a recording is red on either.
    #[test]
    fn the_idle_mark_follows_the_taskbar_and_the_recording_stays_red() {
        fn lightness(img: &tauri::image::Image<'_>) -> u64 {
            let (mut sum, mut n) = (0u64, 0u64);
            for px in img.rgba().chunks(4) {
                if px[3] > 128 {
                    sum += u64::from(px[0]) + u64::from(px[1]) + u64::from(px[2]);
                    n += 1;
                }
            }
            sum / (3 * n.max(1))
        }
        let (dark, dark_template) = tray_look_for(false, true);
        let (light, _) = tray_look_for(false, false);
        assert!(dark_template);
        assert!(lightness(&dark) > 200, "white on a dark taskbar");
        assert!(lightness(&light) < 60, "black on a light one");
        let (rec, rec_template) = tray_look_for(true, true);
        assert!(!rec_template && red_pixels(&rec, true) > 100);
    }

    #[test]
    fn a_recording_turns_the_tray_red() {
        let (rec, rec_template) = tray_look_for(true, false);
        let (idle, idle_template) = tray_look_for(false, false);
        assert!(!rec_template, "a template would be tinted, never red");
        assert!(idle_template, "the idle tray is the menu-bar template");
        assert!(
            red_pixels(&rec, true) > 100,
            "the recording icon has no red dot"
        );
        assert_eq!(
            red_pixels(&rec, false),
            red_pixels(&rec, true),
            "red outside the dot's corner"
        );
        assert_eq!(red_pixels(&idle, false), 0, "the idle icon has red in it");
        assert_eq!((rec.width(), rec.height()), (idle.width(), idle.height()));
    }
}

// ─── account: status line, Log in…, Network devices (Tailscale-style) ─────

/// What the tray's sign-in is doing right now (one at a time).
#[derive(Default)]
struct LoginUi {
    busy: bool,
    login_waiting: bool,
    code: Option<String>,
    error: Option<(String, std::time::Instant)>,
}

static LOGIN_UI: Mutex<LoginUi> = Mutex::new(LoginUi {
    busy: false,
    login_waiting: false,
    code: None,
    error: None,
});

static ACCOUNT_WATCH_WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

pub(crate) const LOGIN_ITEM_ID: &str = "login";
pub(crate) const JOIN_ITEM_ID: &str = "join";
const DEVICE_ITEM_PREFIX: &str = "dev:";
/// `inv:<invitation id>` — leave that invitation.
const INVITE_ITEM_PREFIX: &str = "inv:";

/// `Log in…`: start a device login, open the approval page in the browser,
/// wait for the decision, enroll. The status line shows the code meanwhile.
fn start_login<R: Runtime>(app: &AppHandle<R>) {
    {
        let mut ui = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner());
        if ui.login_waiting {
            tauri::async_runtime::spawn(async move {
                let _ = crate::commands::cmd_login_cancel().await;
                ACCOUNT_WATCH_WAKE.notify_one();
            });
            return;
        }
        if ui.busy {
            return;
        }
        ui.busy = true;
        ui.login_waiting = true;
        ui.error = None;
    }
    ACCOUNT_WATCH_WAKE.notify_one();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let name = crate::commands::cmd_default_device_name();
        let outcome = match crate::commands::cmd_login_start(String::new(), name.clone()).await {
            Ok(started) => {
                LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner()).code =
                    Some(started.user_code.clone());
                ACCOUNT_WATCH_WAKE.notify_one();
                if !started.opened {
                    // No browser could be opened: the window shows the link.
                    show_window(&app, "/onboarding");
                }
                crate::commands::cmd_login_wait(name.clone()).await.map(|_| ())
            }
            Err(e) => Err(e),
        };
        let signed_in = outcome.is_ok();
        {
            let mut ui = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner());
            ui.busy = signed_in;
            ui.login_waiting = false;
            ui.code = None;
            match outcome {
                Ok(()) => tracing::info!("tray: signed in"),
                Err(e) if e == meshharbor_node_core::device_login::CANCELLED_ERROR => {
                    tracing::info!("tray: sign-in cancelled");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "tray: sign-in did not complete");
                    ui.error = Some((e, std::time::Instant::now()));
                }
            }
        }
        ACCOUNT_WATCH_WAKE.notify_one();
        if signed_in {
            // FR-133 — a person from another organization: offer the move.
            offer_move(&app, name).await;
            LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner()).busy = false;
            ACCOUNT_WATCH_WAKE.notify_one();
        }
    });
}

/// A native message box, off the async runtime (it blocks until answered).
/// `buttons` = `Some((yes, no))` asks and answers which; `None` only tells.
async fn message_box<R: Runtime>(
    app: &AppHandle<R>,
    title: &str,
    text: String,
    buttons: Option<(&str, &str)>,
) -> bool {
    use tauri_plugin_dialog::{DialogExt as _, MessageDialogButtons, MessageDialogKind};
    let app = app.clone();
    let title = title.to_string();
    let buttons = buttons.map(|(y, n)| (y.to_string(), n.to_string()));
    tauri::async_runtime::spawn_blocking(move || {
        let mut d = app
            .dialog()
            .message(text)
            .title(title)
            .kind(MessageDialogKind::Info);
        if let Some((yes, no)) = buttons {
            d = d.buttons(MessageDialogButtons::OkCancelCustom(yes, no));
        }
        d.blocking_show()
    })
    .await
    .unwrap_or(false)
}

/// FR-133 — after a sign-in by someone who is not a member of this device's
/// organization: ask "Move it to your organization?". Keep changes nothing
/// (the sign-in stands, as today); Move runs a second, enrollment approval in
/// the browser and rebinds the device's primary enrollment there.
async fn offer_move<R: Runtime>(app: &AppHandle<R>, name: String) {
    let Some(offer) = crate::commands::move_offer_after_sign_in().await else {
        return;
    };
    let lang = crate::tray_i18n::current_lang();
    let title = crate::tray_i18n::move_title(lang);
    let org_label = offer.org_label();
    if let Some(why) = &offer.refusal {
        let text = format!(
            "{}\n\n{why}",
            crate::tray_i18n::move_belongs_to(lang, &org_label)
        );
        message_box(app, title, text, None).await;
        return;
    }
    if !message_box(
        app,
        title,
        crate::tray_i18n::move_question(lang, &org_label),
        Some((
            crate::tray_i18n::move_yes(lang),
            crate::tray_i18n::move_no(lang),
        )),
    )
    .await
    {
        tracing::info!("tray: kept the device in its organization");
        return;
    }
    {
        let mut ui = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner());
        ui.login_waiting = true;
        ui.error = None;
    }
    ACCOUNT_WATCH_WAKE.notify_one();
    let outcome = match crate::commands::move_start(&offer, &name).await {
        Ok(started) => {
            LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner()).code =
                Some(started.user_code.clone());
            ACCOUNT_WATCH_WAKE.notify_one();
            if !started.opened {
                let text = crate::tray_i18n::move_open_link(lang, &started.user_code, &started.url);
                message_box(app, title, text, None).await;
            }
            crate::commands::move_wait(name).await
        }
        Err(e) => Err(e),
    };
    {
        let mut ui = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner());
        ui.login_waiting = false;
        ui.code = None;
    }
    ACCOUNT_WATCH_WAKE.notify_one();
    match outcome {
        Ok(notice) => {
            tracing::info!(kept = notice.is_some(), "tray: device moved to the signed-in organization");
            let body = if matches!(lang, crate::tray_i18n::Lang::En) {
                offer.done(notice.as_deref())
            } else {
                crate::tray_i18n::move_done_body(lang, &org_label, notice.as_deref())
            };
            message_box(app, crate::tray_i18n::move_done_title(lang), body, None).await;
        }
        Err(e) if e == meshharbor_node_core::device_login::CANCELLED_ERROR => {
            tracing::info!("tray: move cancelled");
        }
        Err(e) => {
            tracing::warn!(error = %e, "tray: move did not complete");
            message_box(
                app,
                crate::tray_i18n::move_failed_title(lang),
                e.clone(),
                None,
            )
            .await;
            LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner()).error =
                Some((e, std::time::Instant::now()));
        }
    }
}

/// `Leave · <who>` in the Invitations menu: the daemon's `leave --invite`
/// (an empty id: a server older than several per device — the only one).
fn start_leave<R: Runtime>(app: &AppHandle<R>, invite_id: String) {
    {
        let mut ui = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner());
        if ui.busy {
            return;
        }
        ui.busy = true;
        ui.error = None;
    }
    let _ = app;
    tauri::async_runtime::spawn(async move {
        let outcome =
            crate::commands::cmd_leave((!invite_id.is_empty()).then_some(invite_id)).await;
        let mut ui = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner());
        ui.busy = false;
        ui.code = None;
        match outcome {
            Ok(()) => tracing::info!("tray: left an invitation"),
            Err(e) => {
                tracing::warn!(error = %e, "tray: leave did not complete");
                ui.error = Some((e, std::time::Instant::now()));
            }
        }
    });
}

/// One poll's view of the account, for the account rows.
#[derive(Clone, PartialEq, Eq)]
struct AccountView {
    status: String,
    login_text: String,
    login_enabled: bool,
    sign_out_enabled: bool,
    join_enabled: bool,
    /// The machine holds only invitations (no account of its own): no device
    /// list and no admin console.
    temporary: bool,
    devices: Vec<String>,
    /// (invitation id, menu text), soonest end first.
    invitations: Vec<(String, String)>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn who(g: &meshharbor_node_core::device_invite::GrantInfo, lang: Lang) -> String {
    match (g.inviter.is_empty(), g.org.is_empty()) {
        (false, false) => format!("{} ({})", g.inviter, g.org),
        (false, true) => g.inviter.clone(),
        (true, false) => g.org.clone(),
        (true, true) => tray_i18n::an_organization(lang).to_string(),
    }
}

fn resolve_tray_server(
    file_enrolled: bool,
    file_server: String,
    node: Option<&meshharbor_localapi::NodeStatus>,
) -> String {
    if file_enrolled {
        return file_server;
    }
    node.and_then(|n| n.orgs.iter().find(|o| o.primary))
        .map(|o| o.server_url.trim().trim_end_matches('/').to_string())
        .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
        .unwrap_or(file_server)
}

#[cfg(test)]
fn account_view_at(
    enrolled: bool,
    node: Option<&meshharbor_localapi::NodeStatus>,
    peers: &[meshharbor_localapi::PeerInfo],
    invitations: Option<crate::commands::Invitations>,
    now_ms: i64,
) -> AccountView {
    account_view_at_in(enrolled, node, peers, invitations, now_ms, Lang::En)
}

fn account_view_at_in(
    enrolled: bool,
    node: Option<&meshharbor_localapi::NodeStatus>,
    peers: &[meshharbor_localapi::PeerInfo],
    invitations: Option<crate::commands::Invitations>,
    now_ms: i64,
    lang: Lang,
) -> AccountView {
    let daemon_enrolled = node.is_some_and(|n| {
        !n.node_id.is_empty() && n.tenant_id.as_deref().is_some_and(|t| !t.is_empty())
    });
    let file_enrolled = enrolled;
    let enrolled = file_enrolled || daemon_enrolled;
    let invitations = invitations.filter(|_| file_enrolled);
    let grants = invitations
        .as_ref()
        .map(|i| i.grants.clone())
        .unwrap_or_default();
    // Signed in nowhere but by invitations (either from readable temporary.json
    // or reported over LocalAPI by a root/SYSTEM daemon whose config is 0600).
    let temporary = invitations.as_ref().is_some_and(|i| !i.own_account)
        || (!file_enrolled && node.is_some_and(|n| n.personal_enrolled == Some(false)));
    let ui = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner());
    let recent_error = ui
        .error
        .as_ref()
        .filter(|(_, at)| at.elapsed() < std::time::Duration::from_secs(60))
        .map(|(e, _)| e.clone());
    let status = if ui.busy {
        match &ui.code {
            Some(code) => tray_i18n::approve_in_browser(lang, code),
            None => tray_i18n::working(lang).to_string(),
        }
    } else if let Some(e) = recent_error {
        let mut e = e;
        e.truncate(80);
        tray_i18n::failed(lang, &e)
    } else if !enrolled {
        tray_i18n::not_signed_in(lang).to_string()
    } else if temporary && grants.len() == 1 {
        let g = &grants[0].1;
        let left = tray_i18n::format_remaining(lang, g.access_until_ms, now_ms);
        if g.inviter.is_empty() {
            tray_i18n::temporary_device_left(lang, &left)
        } else {
            tray_i18n::managed_by_left(lang, &g.inviter, &left)
        }
    } else if temporary {
        let next = grants
            .iter()
            .map(|(_, g)| g.access_until_ms)
            .min()
            .unwrap_or(now_ms);
        let left = tray_i18n::format_remaining(lang, next, now_ms);
        tray_i18n::invitations_next_ends(lang, grants.len(), &left)
    } else {
        match node {
            None => tray_i18n::service_not_running(lang).to_string(),
            Some(n) => {
                let ip = n
                    .overlay_ip
                    .as_deref()
                    .unwrap_or_else(|| tray_i18n::no_address_yet(lang));
                if n.connected {
                    format!("{} · {ip}", n.name)
                } else {
                    tray_i18n::device_status_offline(lang, &n.name, ip)
                }
            }
        }
    };
    let (login_text, login_enabled) = if ui.login_waiting {
        let label = match &ui.code {
            Some(c) => tray_i18n::waiting_code_cancel(lang, c),
            None => tray_i18n::waiting_cancel(lang).to_string(),
        };
        (label, true)
    } else if ui.busy {
        (tray_i18n::working(lang).to_string(), false)
    } else if enrolled && !temporary {
        (tray_i18n::signed_in(lang).to_string(), false)
    } else {
        // Signing in keeps every invitation this machine holds.
        (tray_i18n::login_ellipsis(lang).to_string(), true)
    };
    let shown_peers: &[meshharbor_localapi::PeerInfo] = if temporary { &[] } else { peers };
    let mut devices: Vec<String> = shown_peers
        .iter()
        .map(|p| {
            let ip = p.overlay_ip.as_deref().unwrap_or("-");
            let mark = if p.online { "●" } else { "○" };
            format!("{mark} {}  {ip}", p.name)
        })
        .collect();
    devices.sort_by(|a, b| a.get(4..).cmp(&b.get(4..)));
    let invitations = grants
        .iter()
        .map(|(_, g)| {
            (
                g.invite_id.clone(),
                tray_i18n::leave_invite(
                    lang,
                    &who(g, lang),
                    &tray_i18n::format_remaining(lang, g.access_until_ms, now_ms),
                ),
            )
        })
        .collect();
    AccountView {
        status,
        login_text,
        login_enabled,
        sign_out_enabled: false,
        join_enabled: !ui.busy,
        temporary,
        devices,
        invitations,
    }
}

struct AccountMenuItems<R: Runtime> {
    status: MenuItem<R>,
    login: MenuItem<R>,
    sign_out: MenuItem<R>,
    join: MenuItem<R>,
    invites: tauri::menu::Submenu<R>,
    devices: tauri::menu::Submenu<R>,
    open_globe: MenuItem<R>,
    admin: MenuItem<R>,
}

fn spawn_account_watch<R: Runtime>(app: AppHandle<R>, items: AccountMenuItems<R>) {
    let AccountMenuItems {
        status,
        login,
        sign_out,
        join,
        invites,
        devices,
        open_globe,
        admin,
    } = items;
    tauri::async_runtime::spawn(async move {
        let mut shown: Option<AccountView> = None;
        let mut shown_lang: Option<Lang> = None;
        loop {
            let lang = tray_i18n::current_lang();
            let (enrolled, active_invites, server) =
                tokio::task::spawn_blocking(crate::commands::active_account_probe)
                    .await
                    .unwrap_or_else(|_| {
                        (
                            false,
                            None,
                            meshharbor_node_core::device_login::DEFAULT_SERVER.to_string(),
                        )
                    });
            let (node, peers) = match meshharbor_localapi::connect().await {
                Ok(mut c) => {
                    let node = c.status().await.ok();
                    let peers = if node.is_some() {
                        c.peers().await.unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    (node, peers)
                }
                Err(_) => (None, Vec::new()),
            };
            let server = resolve_tray_server(enrolled, server, node.as_ref());
            let mut view = account_view_at_in(
                enrolled,
                node.as_ref(),
                &peers,
                active_invites,
                now_ms(),
                lang,
            );
            let busy_now = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner()).busy;
            if !view.temporary {
                crate::user_account::load_cached_identity(server.clone()).await;
                if !busy_now {
                    let (label, enabled) = crate::user_account::label_in(
                        &server,
                        node.as_ref().is_some_and(|n| n.connected),
                        lang,
                    );
                    view.login_text = label;
                    view.login_enabled = enabled;
                }
            }
            view.sign_out_enabled =
                !busy_now && !view.temporary && crate::user_account::has_identity(&server);
            let lang_changed = shown_lang != Some(lang);
            if shown.as_ref() != Some(&view) || lang_changed {
                let _ = status.set_text(&view.status);
                let _ = login.set_text(&view.login_text);
                let _ = login.set_enabled(view.login_enabled);
                let _ = sign_out.set_enabled(view.sign_out_enabled);
                let _ = join.set_enabled(view.join_enabled);
                let _ = devices.set_enabled(!view.temporary);
                let _ = open_globe.set_enabled(!view.temporary);
                let _ = admin.set_enabled(!view.temporary);
                let _ = invites.set_enabled(!view.invitations.is_empty());
                if shown.as_ref().map(|s| &s.invitations) != Some(&view.invitations) || lang_changed
                {
                    if let Ok(items) = invites.items() {
                        for item in items {
                            let _ = invites.remove(&item);
                        }
                    }
                    for (id, label) in &view.invitations {
                        if let Ok(item) = MenuItem::with_id(
                            &app,
                            format!("{INVITE_ITEM_PREFIX}{id}"),
                            label,
                            true,
                            None::<&str>,
                        ) {
                            let _ = invites.append(&item);
                        }
                    }
                    if !view.invitations.is_empty()
                        && let Ok(item) = MenuItem::with_id(
                            &app,
                            "invite-features",
                            tray_i18n::choose_exposed_features(lang),
                            true,
                            None::<&str>,
                        )
                    {
                        let _ = invites.append(&item);
                    }
                }
                if shown.as_ref().map(|s| &s.devices) != Some(&view.devices) || lang_changed {
                    if let Ok(items) = devices.items() {
                        for item in items {
                            let _ = devices.remove(&item);
                        }
                    }
                    if view.devices.is_empty()
                        && let Ok(none) = MenuItem::with_id(
                            &app,
                            "dev:none",
                            tray_i18n::no_devices_yet(lang),
                            false,
                            None::<&str>,
                        )
                    {
                        let _ = devices.append(&none);
                    }
                    for (i, label) in view.devices.iter().enumerate() {
                        if let Ok(item) = MenuItem::with_id(
                            &app,
                            format!("{DEVICE_ITEM_PREFIX}{i}"),
                            label,
                            true,
                            None::<&str>,
                        ) {
                            let _ = devices.append(&item);
                        }
                    }
                }
                shown = Some(view);
                shown_lang = Some(lang);
            }
            let busy = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner()).busy;
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(if busy { 1 } else { 4 })) => {}
                _ = ACCOUNT_WATCH_WAKE.notified() => {}
            }
        }
    });
}

#[cfg(test)]
mod account_tests {
    use super::*;

    #[test]
    fn root_or_system_daemon_with_unreadable_config_still_shows_signed_in() {
        let mut st: meshharbor_localapi::NodeStatus = serde_json::from_value(serde_json::json!({
            "node_id": "65f000000000000000000099",
            "name": "root-workstation",
            "version": "0.4.162",
            "mode": "service",
            "privileged": true,
            "personal_enrolled": true,
            "system_privileged": true,
            "tenant_id": "65f000000000000000000001",
            "overlay_ip": "100.64.0.42",
            "connected": true,
            "orgs": [{
                "label": "primary",
                "server_url": "https://custom.meshharbor.example/",
                "tenant_id": "65f000000000000000000001",
                "agent_id": "65f000000000000000000099",
                "primary": true,
                "enabled": true,
                "connected": true,
                "updates_ignored": 0,
                "overlay_mode": "tun"
            }]
        }))
        .unwrap();
        let v = account_view_at(false, Some(&st), &[], None, 0);
        assert_eq!(v.status, "root-workstation · 100.64.0.42");
        assert!(!v.temporary);
        assert_eq!(v.login_text, "Signed in");
        assert_eq!(
            resolve_tray_server(
                false,
                "https://www.itachi.fans/meshharbor".into(),
                Some(&st)
            ),
            "https://custom.meshharbor.example"
        );

        st.personal_enrolled = Some(false);
        let v_temp = account_view_at(false, Some(&st), &[], None, 0);
        assert!(v_temp.temporary);
        assert_eq!(v_temp.login_text, "Log in…");
        assert!(v_temp.login_enabled);
    }

    #[test]
    fn login_waiting_exposes_clickable_cancel_label_in_tray() {
        {
            let mut ui = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner());
            ui.busy = true;
            ui.login_waiting = true;
            ui.code = Some("BCDFG-HJKLM".to_string());
        }
        let v = account_view_at(false, None, &[], None, 0);
        {
            let mut ui = LOGIN_UI.lock().unwrap_or_else(|e| e.into_inner());
            ui.busy = false;
            ui.login_waiting = false;
            ui.code = None;
        }
        assert_eq!(v.login_text, "Waiting (BCDFG-HJKLM) · click to cancel");
        assert!(v.login_enabled, "waiting row must be clickable to cancel");
    }

    #[test]
    fn the_status_line_follows_the_account_like_tailscale() {
        let v = account_view_at(false, None, &[], None, 0);
        assert_eq!(v.status, "Not signed in");
        assert_eq!((v.login_text.as_str(), v.login_enabled), ("Log in…", true));
        assert!(v.devices.is_empty());
        let v = account_view_at(true, None, &[], None, 0);
        assert_eq!(v.status, "MeshHarbor service is not running");
        assert_eq!(
            (v.login_text.as_str(), v.login_enabled),
            ("Signed in", false)
        );
        assert!(
            v.join_enabled && !v.temporary,
            "a signed-in machine may still accept an invitation"
        );
    }

    fn grant(
        id: &str,
        who: &str,
        until: i64,
    ) -> (String, meshharbor_node_core::device_invite::GrantInfo) {
        (
            "agent".into(),
            meshharbor_node_core::device_invite::GrantInfo {
                invite_id: id.into(),
                inviter: who.into(),
                org: "Acme".into(),
                access_until_ms: until,
                features: None,
                features_revision: 0,
                revocation_pending: false,
            },
        )
    }

    #[test]
    fn a_temporary_device_shows_its_manager_and_time_and_no_devices() {
        let t = crate::commands::Invitations {
            own_account: false,
            grants: vec![grant("aa", "Alex", 50 * 3_600_000)],
        };
        let v = account_view_at(true, None, &[], Some(t.clone()), 0);
        assert_eq!(v.status, "Managed by Alex · 2 d 2 h left");
        assert_eq!(
            (v.login_text.as_str(), v.login_enabled),
            ("Log in…", true),
            "signing in keeps it"
        );
        assert!(v.temporary && v.join_enabled && v.devices.is_empty());
        assert_eq!(
            v.invitations,
            vec![(
                "aa".to_string(),
                "Leave · Alex (Acme) · 2 d 2 h left".to_string()
            )]
        );
        // A marker left behind on a machine that is no longer enrolled is
        // not a temporary device.
        let v = account_view_at(false, None, &[], Some(t), 0);
        assert_eq!(v.status, "Not signed in");
        assert!(v.join_enabled && !v.temporary && v.invitations.is_empty());
    }

    #[test]
    fn several_invitations_are_listed_and_the_owners_account_stays_in_charge() {
        let only = crate::commands::Invitations {
            own_account: false,
            grants: vec![
                grant("aa", "Alex", 3_600_000),
                grant("bb", "Bo", 50 * 3_600_000),
            ],
        };
        let v = account_view_at(true, None, &[], Some(only), 0);
        assert_eq!(v.status, "2 invitations · next ends in 1 h 0 min");
        assert_eq!(v.invitations.len(), 2);
        // Signed in with its own account: the account rows are the owner's,
        // the invitations are still listed with their leave.
        let own = crate::commands::Invitations {
            own_account: true,
            grants: vec![grant("aa", "Alex", 3_600_000)],
        };
        let v = account_view_at(true, None, &[], Some(own), 0);
        assert_eq!(v.status, "MeshHarbor service is not running");
        assert_eq!(
            (v.login_text.as_str(), v.login_enabled),
            ("Signed in", false)
        );
        assert!(!v.temporary && v.join_enabled && v.invitations.len() == 1);
    }

    #[test]
    fn localized_zh_cn_tray_labels_cover_account_recording_and_keep_busy() {
        let v = account_view_at_in(false, None, &[], None, 0, Lang::ZhCn);
        assert_eq!(v.status, "未登录");
        assert_eq!((v.login_text.as_str(), v.login_enabled), ("登录…", true));

        let temp = crate::commands::Invitations {
            own_account: false,
            grants: vec![grant("aa", "Alex", 50 * 3_600_000)],
        };
        let vt = account_view_at_in(true, None, &[], Some(temp), 0, Lang::ZhCn);
        assert_eq!(vt.status, "由 Alex 管理 · 剩余 2 天 2 小时");
        assert_eq!(
            vt.invitations,
            vec![("aa".to_string(), "退出邀请 · Alex (Acme) · 剩余 2 天 2 小时".to_string())]
        );

        let rec = meshharbor_localapi::RecordingState {
            available: true,
            active: true,
            duration_ms: 83_900,
            ..Default::default()
        };
        assert_eq!(
            record_labels_in(Some(&rec), Lang::ZhCn),
            (
                "停止录制 (1:23)".into(),
                true,
                "MeshHarbor — 正在录制 1:23".into()
            )
        );

        let kb = meshharbor_localapi::KeepBusyInfo {
            available: true,
            on: true,
            phase: "paused".into(),
            pattern: "heart".into(),
            ..Default::default()
        };
        assert_eq!(
            keep_busy_labels_in(Some(&kb), Lang::ZhCn),
            ("停止保持活跃（Heart · paused）".into(), true)
        );
    }

    #[test]
    fn update_menu_label_reflects_ready_available_and_idle_states() {
        assert_eq!(update_menu_label(None, Lang::En), "Check for Updates");
        assert_eq!(update_menu_label(None, Lang::ZhCn), "检查更新");

        let ready = meshharbor_localapi::UpdateStatusInfo {
            current: "0.4.216".into(),
            latest: Some("agent-v0.4.217".into()),
            stage: "ready".into(),
            update_available: true,
            staged_ready: true,
            ..Default::default()
        };
        assert_eq!(
            update_menu_label(Some(&ready), Lang::En),
            "Update Ready (0.4.217) — Install"
        );
        assert_eq!(
            update_menu_label(Some(&ready), Lang::ZhCn),
            "有新版本（0.4.217）· 点击升级"
        );

        let avail = meshharbor_localapi::UpdateStatusInfo {
            current: "0.4.216".into(),
            latest: Some("agent-v0.4.217".into()),
            stage: "available".into(),
            update_available: true,
            staged_ready: false,
            ..Default::default()
        };
        assert_eq!(
            update_menu_label(Some(&avail), Lang::En),
            "Update Available (0.4.217)"
        );
        assert_eq!(
            update_menu_label(Some(&avail), Lang::ZhCn),
            "发现新版本（0.4.217）"
        );
    }
}
