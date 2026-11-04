// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Remote **app selection & launch** for virtual-desktop hosts.
//!
//! When a browser controls a headless agent that runs in built-in
//! virtual-desktop mode (`ROOMLERD_VIRTUAL_DESKTOP=1` →
//! Xvfb + WM + startup apps, see [`crate::virtual_desktop`]), the
//! operator has no way to see what's running on that desktop, focus a
//! specific window, **attach to an existing shell session**, or **start
//! a new one**. This module adds that: list windows, focus one, and
//! launch a new *allowlisted* app.
//!
//! ## Transport
//! Pure P2P over the existing WebRTC `control` data channel — no server
//! change. [`crate::peer::attach_control_handler`] routes three
//! envelopes here and sends the returned reply back over the same DC,
//! mirroring the `rc:logs-fetch` request/response precedent:
//!
//! ```text
//! rc:apps.list   {id}                    → rc:apps.list.reply   {id, ok, supported, windows, launchable, coverage?, unavailable?}
//! rc:apps.focus  {id, window_id}         → rc:apps.focus.reply  {id, ok, error?, unavailable?}
//! rc:apps.launch {id, app_key}           → rc:apps.launch.reply {id, ok, window_id?, session?, error?, unavailable?}
//! ```
//!
//! Two additive objects carry the honesty (FR-56): `coverage` says what a
//! listing could and could not see on a host where the feature works
//! ([`Coverage`]), and `unavailable` says WHY on a host where it does not
//! ([`Unavailable`]) — the reason rides the reply, not only the daemon log.
//!
//! `window_id` is an **opaque string** the browser only round-trips
//! (X11 hex on Linux, HWND decimal on Windows). Launch takes an
//! allowlist **key** only — never a command line — so a compromised
//! browser can start only operator-approved apps, and `command` is run
//! as argv (no shell), so there is no injection surface.
//!
//! ## Platform backends
//! * `linux` — `wmctrl` (list/focus) + `tmux` (bash sessions) + `xterm`.
//!   The flagship: a bash "session" is a tmux session, surfaced as an
//!   xterm attached to it — survives agent restart/disconnect and is
//!   ssh-attachable. Windows are matched back to their session/app via a
//!   `roomler:tmux:<s>` / `roomler:app:<key>` xterm-title convention.
//! * `windows` — Phase 2 (`EnumWindows` / `SetForegroundWindow` /
//!   `CreateProcessAsUser` in the active session). Not built yet.
//!
//! The pure parsers + resolvers live here (portable, unit-tested); the
//! platform I/O lives in the cfg-gated submodules.

use std::sync::OnceLock;

use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};

#[cfg(target_os = "linux")]
mod linux;
/// FR-85 P1e-unix — the recorder, launched into a person's X session, needs
/// the same cookie the window list does. Gated to that one consumer, so a
/// build without the recorder has no unused re-export.
#[cfg(all(target_os = "linux", feature = "recording"))]
pub(crate) use linux::find_xauthority;
#[cfg(target_os = "windows")]
mod windows;

// ---------------------------------------------------------------------------
// Wire types (agent → browser)
// ---------------------------------------------------------------------------

/// One enumerated desktop window (an entry in `rc:apps.list.reply`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowInfo {
    /// Opaque window handle: X11 hex id (`0x03400007`) on Linux, HWND
    /// decimal on Windows. The browser round-trips it in `rc:apps.focus`.
    pub window_id: String,
    /// Human-friendly title (our `roomler:*` prefix stripped).
    pub title: String,
    /// Matched allowlist key, when the window is a known launched app.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_key: Option<String>,
    /// tmux session name (Linux bash flagship); absent for GUI windows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Whether this is the active window on the desktop.
    pub focused: bool,
}

/// An allowlisted app the browser may launch (an entry in `launchable`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LaunchableApp {
    pub key: String,
    pub label: String,
}

/// Outcome of a launch, used to build `rc:apps.launch.reply`. Both
/// fields are best-effort — a backend that can't resolve the new
/// window synchronously returns `None` and the browser re-lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchOutcome {
    pub window_id: Option<String>,
    pub session: Option<String>,
}

/// An allowlist entry resolved from config by [`resolve_app`] and handed
/// to a backend's [`WindowManager::launch`]. The command is already
/// validated to be non-empty; it is run as argv (never via a shell).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApp {
    pub key: String,
    pub command: Vec<String>,
    /// Wrap the command in a terminal (Linux `xterm -e …`) — for TUIs.
    pub terminal: bool,
    /// This entry is a tmux-backed shell: launch creates/attaches a
    /// persistent tmux session instead of a bare process.
    pub tmux: bool,
}

/// Platform window-manager backend. All methods block (shell-out / FFI),
/// so [`crate::peer`] invokes [`handle_control_message`] from
/// `tokio::task::spawn_blocking`.
/// What a listing actually covers — FR-56 P2.
///
/// `supported: bool` cannot express **"X11 windows only"**, and on a Wayland
/// host that is the truth: `wmctrl` sees Xwayland clients and is blind to
/// native Wayland ones, so a short list looks exactly like a quiet desktop.
/// This is the `Some([])` vs `None` distinction — an empty list and an
/// unenumerable source are different facts — on its fourth surface in this
/// codebase (overlay ACL ingress rules, `ssh_activity`, FR-49's dark org).
///
/// ⚠️ `unlisted` is the load-bearing half. Without it the reply is *shorter*
/// than reality and says nothing about the gap, which is the failure mode the
/// other three taught: silence reads as absence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Coverage {
    /// Window sources this listing enumerated: `x11`, `wayland`.
    pub sources: Vec<&'static str>,
    /// A source that exists on this host but could NOT be enumerated, with
    /// the reason. `None` when the listing is complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlisted: Option<String>,
    /// FR-56 P5 — helper binaries this backend shells out to that are **not
    /// installed here**, each with what stops working without it.
    ///
    /// ⚠️ This exists because `supported: true` was measured to be a lie:
    /// on a GNOME Wayland host with no `tmux`, the panel reported the feature
    /// supported, offered the button, and only failed once somebody clicked
    /// it. A capability is not "supported" because the desktop was found; it
    /// is supported because the thing behind the button can actually run.
    ///
    /// ⚠️ Empty means "nothing missing", NOT "not checked" — the same
    /// `Some([])`-vs-`None` distinction [`Self::unlisted`] exists for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_tools: Vec<MissingTool>,
}

/// One helper binary this host does not have (FR-56 P5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MissingTool {
    /// The binary that could not be found on `PATH`.
    pub tool: &'static str,
    /// What stops working without it, in the operator's terms.
    pub blocks: &'static str,
    /// How to get it, so the reply is actionable and not just a complaint.
    pub install: &'static str,
}

/// FR-56 AC10 — why Remote Apps is **not** available on this host, when the
/// answer is knowable.
///
/// Rides the wire as `unavailable: {code, reason}` beside every
/// `supported: false`, and on a focus/launch refusal that had no backend to
/// hand the request to. Before it, every one of these collapsed into one bare
/// `supported: false`, and the reason lived in the daemon log at `debug!` — or
/// nowhere: a failed privilege drop was swallowed inside the display probe, and
/// the log line that followed blamed Xwayland for it.
///
/// ⚠️ A CLOSED set, and `code` is a compatibility surface like every other
/// `rc:*` string (FR-80's rule): renaming one does not fail loudly, it changes
/// what an operator reads on a screen that exists to explain a refusal. The
/// sentence is composed HERE, not in the viewer, because only the agent knows
/// which arm it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// `[virtual_desktop_apps] enabled = false` on this device — the owner's
    /// choice, reported as such rather than as a missing desktop.
    Disabled,
    /// No active graphical login session: nobody is at the screen. The normal
    /// state of a headless server, and of a desktop parked at the greeter.
    NoSession { detail: String },
    /// A session exists but no X display on it answered — a Wayland
    /// compositor running without Xwayland, which this X11 backend cannot
    /// manage (native Wayland windows can only be enumerated where the
    /// compositor exposes a foreign-toplevel protocol, which GNOME does not;
    /// the FR-56 spec's P3 has the measurements).
    NoXDisplay { user: String, tried: Vec<String> },
    /// The session's owner was found but commands cannot be run as them — the
    /// privilege drop failed. Running them as root instead is never the
    /// answer: that would put a root shell on somebody's own desktop.
    CannotRunAs { user: String, detail: String },
    /// `wmctrl`, the binary `list` and `focus` ARE, is not installed on the
    /// host. ⚠️ Deliberately NOT a [`MissingTool`] in [`Coverage`]: without it
    /// there is no backend at all, so it must not read as a footnote on a
    /// reply that otherwise looks like success.
    ToolMissing {
        tool: &'static str,
        install: &'static str,
    },
    /// This platform has no Remote Apps backend (macOS, the BSDs).
    Platform,
}

impl Unavailable {
    /// The wire spelling. Locked by a test that every code is distinct and
    /// that no code is a prefix of another — the `ssh` / `ssh-consent` lesson,
    /// so an equality match can never be "simplified" into `starts_with`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::NoSession { .. } => "no_session",
            Self::NoXDisplay { .. } => "no_x_display",
            Self::CannotRunAs { .. } => "cannot_run_as",
            Self::ToolMissing { .. } => "tool_missing",
            Self::Platform => "platform",
        }
    }

    /// The operator-facing sentence: what is true, and what would change it.
    pub fn reason(&self) -> String {
        match self {
            Self::Disabled => "Remote apps are disabled on this device \
                               (`[virtual_desktop_apps] enabled = false` in its config). \
                               Enable them there and restart the daemon."
                .to_string(),
            Self::NoSession { detail } => format!(
                "No active graphical login session on this host — nobody is at its screen — \
                 so there is no desktop to list windows on or launch into. Remote shell and \
                 file transfer still work. ({detail})"
            ),
            Self::NoXDisplay { user, tried } => format!(
                "{user} has a graphical session but no X display on it answered (tried {}): \
                 a Wayland compositor without Xwayland. This backend lists and focuses X11 \
                 windows only; native Wayland windows can be managed only where the \
                 compositor exposes a foreign-toplevel protocol, which GNOME does not.",
                tried.join(", ")
            ),
            Self::CannotRunAs { user, detail } => format!(
                "A desktop was found, but commands cannot be run as its owner {user} \
                 ({detail}). They are never run as root on a user's session instead."
            ),
            Self::ToolMissing { tool, install } => format!(
                "`{tool}` is not installed on the agent host ({install}); this backend \
                 needs it to find and manage the desktop."
            ),
            Self::Platform => "Remote apps have no backend on this platform — they exist for \
                               Linux desktops (X11, or Wayland through Xwayland) and Windows."
                .to_string(),
        }
    }

    /// The `unavailable` wire object.
    pub fn to_json(&self) -> Value {
        json!({ "code": self.code(), "reason": self.reason() })
    }
}

pub trait WindowManager: Send + Sync {
    /// Enumerate the desktop's windows (already classified against the
    /// title convention / allowlist).
    fn list(&self) -> Result<Vec<WindowInfo>>;
    /// What [`Self::list`] can and cannot see on this host.
    fn coverage(&self) -> Coverage;
    /// Raise + focus a previously-enumerated window by its opaque id.
    fn focus(&self, window_id: &str) -> Result<()>;
    /// Launch (or, for a tmux entry, create+attach) an allowlisted app.
    fn launch(&self, app: &ResolvedApp) -> Result<LaunchOutcome>;
}

// ---------------------------------------------------------------------------
// Config (`[virtual_desktop_apps]` in the agent config.toml)
// ---------------------------------------------------------------------------

// The serde shapes moved to `meshharbor-node-core::apps_config` in P3e lever E
// (AgentConfig embeds them, and AgentConfig lives there now); the launch
// machinery around them stays HERE. Re-exported under the old paths so
// `crate::apps::VirtualDesktopAppsConfig` remains valid everywhere.
pub use meshharbor_node_core::apps_config::{AppSpec, VirtualDesktopAppsConfig};

// ---------------------------------------------------------------------------
// Process-global config install (mirrors `files::set_remote_browse_enabled`)
// ---------------------------------------------------------------------------

static APPS_CONFIG: OnceLock<VirtualDesktopAppsConfig> = OnceLock::new();

/// Install the config once at startup (from `main::run_cmd`). Later calls
/// are ignored — the config is immutable for the process lifetime, same
/// as the remote-browse flag.
pub fn set_apps_config(cfg: VirtualDesktopAppsConfig) {
    let _ = APPS_CONFIG.set(cfg);
}

/// The installed config, or the default (seeded bash entry) if
/// `set_apps_config` was never called (e.g. unit tests, old flows).
pub fn apps_config() -> VirtualDesktopAppsConfig {
    APPS_CONFIG.get().cloned().unwrap_or_default()
}

/// Can this process manage a desktop right now — and if not, why not.
///
/// Linux: virtual-desktop mode, **or** a logged-in user's session whose X
/// display answers (FR-56 P1 — including a Wayland session, because its
/// compositor runs Xwayland). Windows: the agent always drives the active
/// user's desktop.
///
/// The hello advertises `list`/`focus`/`launch` on `Ok` (`encode::caps::detect`
/// assigns them from [`availability_for`] with the installed config, in the
/// daemon — never in the caps-probe child, which loads no config); the
/// `rc:apps.list` reply carries the `Err` as `unavailable`. Both go through
/// [`availability_for`], so the two can disagree only by TIME — the hello is
/// a boot-time snapshot (`detect` memoizes it), the reply is live — never by
/// logic, and never by which process asked.
pub fn availability() -> Result<(), Unavailable> {
    availability_for(&apps_config())
}

/// [`availability`] against an explicit config — the seam the hello builder
/// uses (so its answer is testable without installing a process-global
/// config) and the one the reply path shares.
pub fn availability_for(cfg: &VirtualDesktopAppsConfig) -> Result<(), Unavailable> {
    if !cfg.enabled {
        return Err(Unavailable::Disabled);
    }
    #[cfg(target_os = "linux")]
    {
        // ⚠️ NOT `env::var_os("DISPLAY").is_some()` any more. That asked
        // whether the DAEMON has a display, which is true only in
        // virtual-desktop mode — so every Wayland host answered
        // `supported:false` and the feature never engaged. `discover()` keeps
        // that path first and unchanged, then looks for whoever is at the
        // screen.
        linux::discover().map(|_| ())
    }
    #[cfg(target_os = "windows")]
    {
        // Windows: the agent always drives the active user's desktop.
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(Unavailable::Platform)
    }
}

/// True when this process can actually manage a desktop AND apps are
/// enabled — the signal the caps builder advertises to the browser.
pub fn apps_supported() -> bool {
    availability().is_ok()
}

/// FR-56 AC10 — whether this BUILD has a Remote Apps backend at all, whatever
/// the host is doing right now. The hello advertises `status` on it: "ask me,
/// and I will say whether Remote Apps work here — and if not, why". A platform
/// with no backend stays silent, exactly as before: there is nothing a reason
/// could change there, and a permanently disabled button is noise.
pub const fn has_backend() -> bool {
    cfg!(any(target_os = "linux", target_os = "windows"))
}

/// Construct the platform backend, or say why apps can't be managed on this
/// host/build.
///
/// FR-56 P1: the Linux arm now takes a discovered [`linux::Target`] rather
/// than a display string, because "which display" and "as whom" are two
/// answers and only the first was being carried.
pub fn backend() -> Result<Box<dyn WindowManager>, Unavailable> {
    #[cfg(target_os = "linux")]
    {
        linux::discover().map(|t| Box::new(linux::LinuxWm::new(t)) as Box<dyn WindowManager>)
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsWm) as Box<dyn WindowManager>)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(Unavailable::Platform)
    }
}

// ---------------------------------------------------------------------------
// Control-DC entrypoint
// ---------------------------------------------------------------------------

/// Handle one `rc:apps.*` control-DC envelope and return the reply
/// `Value` to send back. Blocking (shells out / FFI) — call from
/// `spawn_blocking`. Never panics: every path returns a well-formed
/// `*.reply`.
pub fn handle_control_message(val: &Value) -> Value {
    let cfg = apps_config();
    // FR-56 P1: the backend discovers its own target — the daemon's `DISPLAY`
    // (virtual-desktop mode, unchanged and still first) or the display of
    // whoever is at the screen. When apps are disabled we build no backend →
    // replies say `supported:false`, and (AC10) why.
    let be = if cfg.enabled {
        backend()
    } else {
        Err(Unavailable::Disabled)
    };
    match &be {
        Ok(b) => dispatch(val, &cfg, Ok(b.as_ref())),
        Err(why) => dispatch(val, &cfg, Err(why)),
    }
}

/// Pure dispatch over a supplied (possibly fake) backend — the unit-test
/// seam. `Err` is "no backend, and this is why"; every reply built from it
/// carries the reason.
fn dispatch(
    val: &Value,
    cfg: &VirtualDesktopAppsConfig,
    backend: Result<&dyn WindowManager, &Unavailable>,
) -> Value {
    let id = msg_id(val);
    match val.get("t").and_then(|v| v.as_str()).unwrap_or("") {
        "rc:apps.list" => build_list_reply(id, cfg, backend),
        "rc:apps.focus" => build_focus_reply(id, backend, val),
        "rc:apps.launch" => build_launch_reply(id, cfg, backend, val),
        other => json!({
            "t": "rc:apps.error", "id": id, "ok": false,
            "error": format!("unknown apps message: {other}"),
        }),
    }
}

fn msg_id(val: &Value) -> Option<String> {
    val.get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn build_list_reply(
    id: Option<String>,
    cfg: &VirtualDesktopAppsConfig,
    backend: Result<&dyn WindowManager, &Unavailable>,
) -> Value {
    let backend = match backend {
        Ok(b) => b,
        Err(why) => {
            return json!({
                "t": "rc:apps.list.reply", "id": id, "ok": true, "supported": false,
                "windows": [], "launchable": [],
                // FR-56 AC10 — the reason rides the reply. Before this the
                // panel received a bare `supported: false`, cleared its error
                // and showed "No windows reported": a calm desktop, where the
                // truth was a refusal with a cause the operator could act on.
                "unavailable": why.to_json(),
            });
        }
    };
    match backend.list() {
        Ok(mut windows) => {
            // Defensive bound so a pathological desktop can't blow the
            // 65536 SCTP single-message limit (200 × ~120 B ≈ 24 KB).
            windows.truncate(200);
            json!({
                "t": "rc:apps.list.reply", "id": id, "ok": true, "supported": true,
                "windows": windows, "launchable": launchable_list(cfg),
                "coverage": backend.coverage(),
            })
        }
        Err(e) => json!({
            "t": "rc:apps.list.reply", "id": id, "ok": false, "supported": true,
            "windows": [], "launchable": launchable_list(cfg), "error": format!("{e:#}"),
            "coverage": backend.coverage(),
        }),
    }
}

fn build_focus_reply(
    id: Option<String>,
    backend: Result<&dyn WindowManager, &Unavailable>,
    val: &Value,
) -> Value {
    let backend = match backend {
        Ok(b) => b,
        Err(why) => return unavailable_reply("rc:apps.focus.reply", id, why),
    };
    let Some(window_id) = val.get("window_id").and_then(|v| v.as_str()) else {
        return action_error("rc:apps.focus.reply", id, "missing window_id");
    };
    match backend.focus(window_id) {
        Ok(()) => json!({ "t": "rc:apps.focus.reply", "id": id, "ok": true }),
        Err(e) => action_error("rc:apps.focus.reply", id, &format!("{e:#}")),
    }
}

fn build_launch_reply(
    id: Option<String>,
    cfg: &VirtualDesktopAppsConfig,
    backend: Result<&dyn WindowManager, &Unavailable>,
    val: &Value,
) -> Value {
    let backend = match backend {
        Ok(b) => b,
        Err(why) => return unavailable_reply("rc:apps.launch.reply", id, why),
    };
    let Some(app_key) = val.get("app_key").and_then(|v| v.as_str()) else {
        return action_error("rc:apps.launch.reply", id, "missing app_key");
    };
    let Some(resolved) = resolve_app(cfg, app_key) else {
        return action_error("rc:apps.launch.reply", id, "app_key not in allowlist");
    };
    match backend.launch(&resolved) {
        Ok(outcome) => json!({
            "t": "rc:apps.launch.reply", "id": id, "ok": true,
            "app_key": app_key, "window_id": outcome.window_id, "session": outcome.session,
        }),
        Err(e) => action_error("rc:apps.launch.reply", id, &format!("{e:#}")),
    }
}

fn action_error(t: &str, id: Option<String>, error: &str) -> Value {
    json!({ "t": t, "id": id, "ok": false, "error": error })
}

/// FR-56 AC10 — a focus/launch refused because there is no backend. The
/// `error` string keeps the pre-AC10 shape for viewers that only read that
/// field; `unavailable` carries the code for the ones that key off it.
fn unavailable_reply(t: &str, id: Option<String>, why: &Unavailable) -> Value {
    json!({
        "t": t, "id": id, "ok": false,
        "error": format!("apps not available on this host: {}", why.reason()),
        "unavailable": why.to_json(),
    })
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested; portable so they run on the Windows dev box)
// ---------------------------------------------------------------------------

/// Resolve a browser-supplied allowlist **key** to a runnable spec, or
/// `None` when apps are disabled / the key is unknown / the command is
/// empty. This is the security gate: the browser never sends a command.
pub fn resolve_app(cfg: &VirtualDesktopAppsConfig, key: &str) -> Option<ResolvedApp> {
    if !cfg.enabled {
        return None;
    }
    let spec = cfg.allowlist.get(key)?;
    if spec.command.is_empty() {
        return None;
    }
    Some(ResolvedApp {
        key: key.to_string(),
        command: spec.command.clone(),
        terminal: spec.terminal,
        tmux: spec.tmux,
    })
}

/// The `launchable` list for `rc:apps.list.reply` — stable order
/// (BTreeMap), skipping empty-command entries, label falling back to key.
pub fn launchable_list(cfg: &VirtualDesktopAppsConfig) -> Vec<LaunchableApp> {
    if !cfg.enabled {
        return Vec::new();
    }
    cfg.allowlist
        .iter()
        .filter(|(_, s)| !s.command.is_empty())
        .map(|(k, s)| LaunchableApp {
            key: k.clone(),
            label: s.label.clone().unwrap_or_else(|| k.clone()),
        })
        .collect()
}

/// First free `s<N>` tmux session name not already present.
pub fn next_tmux_session_name(existing: &[String]) -> String {
    for n in 1..=100_000u32 {
        let cand = format!("s{n}");
        if !existing.iter().any(|e| e == &cand) {
            return cand;
        }
    }
    // Astronomically unreachable (100k live sessions); keep total.
    "s0".to_string()
}

/// A raw `wmctrl -l` row before title classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawWindow {
    pub window_id: String,
    pub title: String,
}

/// Parse `wmctrl -l` output. Format per line:
/// `<hex-id> <desktop> <client-host> <title with spaces…>`. Blank lines
/// skipped; a window with an empty title yields `title == ""`.
pub fn parse_wmctrl_list(out: &str) -> Vec<RawWindow> {
    let mut v = Vec::new();
    for line in out.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((wid, rest)) = split_first_token(line) else {
            continue;
        };
        let Some((_desktop, rest)) = split_first_token(rest) else {
            continue;
        };
        let Some((_host, rest)) = split_first_token(rest) else {
            continue;
        };
        v.push(RawWindow {
            window_id: wid.to_string(),
            title: rest.trim_start().to_string(),
        });
    }
    v
}

/// Split off the first whitespace-delimited token, returning
/// `(token, remainder)`. Leading whitespace is trimmed first.
fn split_first_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.split_once(|c: char| c.is_whitespace()) {
        Some((tok, rest)) => Some((tok, rest)),
        None => Some((s, "")),
    }
}

/// Parse `tmux list-sessions -F '#{session_name}'` output → session names.
pub fn parse_tmux_sessions(out: &str) -> Vec<String> {
    out.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

/// A window title classified against the `roomler:*` convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedTitle {
    /// Friendly title (our prefix stripped/prettified).
    pub title: String,
    pub session: Option<String>,
    pub app_key: Option<String>,
}

/// Classify a raw window title. We launch our own windows with a known
/// title so the list can map a window back to its tmux session or
/// allowlist key without fragile pid/xprop correlation:
/// * `roomler:tmux:<s>` → a bash/tmux session
/// * `roomler:app:<key>` → an allowlisted app
/// * anything else → an unmanaged window (reported as-is).
pub fn classify_title(raw: &str) -> ClassifiedTitle {
    if let Some(s) = raw.strip_prefix("roomler:tmux:") {
        let s = s.trim();
        return ClassifiedTitle {
            title: format!("Terminal ({s})"),
            session: Some(s.to_string()),
            app_key: None,
        };
    }
    if let Some(k) = raw.strip_prefix("roomler:app:") {
        let k = k.trim();
        return ClassifiedTitle {
            title: k.to_string(),
            session: None,
            app_key: Some(k.to_string()),
        };
    }
    ClassifiedTitle {
        title: raw.to_string(),
        session: None,
        app_key: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cfg_with(keys: &[(&str, bool)]) -> VirtualDesktopAppsConfig {
        let mut allowlist = BTreeMap::new();
        for (k, tmux) in keys {
            allowlist.insert(
                k.to_string(),
                AppSpec {
                    command: vec![k.to_string()],
                    label: None,
                    terminal: *tmux,
                    tmux: *tmux,
                },
            );
        }
        VirtualDesktopAppsConfig {
            enabled: true,
            allowlist,
        }
    }

    /// A canned backend so the reply-envelope shapes are asserted with no
    /// real X server.
    struct FakeWm {
        windows: Vec<WindowInfo>,
        fail: bool,
    }
    impl WindowManager for FakeWm {
        fn coverage(&self) -> Coverage {
            Coverage {
                sources: vec!["x11"],
                unlisted: Some("native Wayland windows: fake backend".to_string()),
                missing_tools: vec![MissingTool {
                    tool: "tmux",
                    blocks: "persistent shell sessions",
                    install: "apt install tmux",
                }],
            }
        }
        fn list(&self) -> Result<Vec<WindowInfo>> {
            if self.fail {
                anyhow::bail!("no display");
            }
            Ok(self.windows.clone())
        }
        fn focus(&self, window_id: &str) -> Result<()> {
            if window_id == "0xBAD" {
                anyhow::bail!("no such window");
            }
            Ok(())
        }
        fn launch(&self, app: &ResolvedApp) -> Result<LaunchOutcome> {
            Ok(LaunchOutcome {
                window_id: Some("0xNEW".to_string()),
                session: app.tmux.then(|| "s2".to_string()),
            })
        }
    }

    #[test]
    fn default_config_seeds_a_shell() {
        let cfg = VirtualDesktopAppsConfig::default();
        assert!(cfg.enabled);
        #[cfg(target_os = "windows")]
        {
            let cmd = cfg.allowlist.get("cmd").expect("cmd seeded");
            assert_eq!(cmd.command, vec!["cmd.exe".to_string()]);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let bash = cfg.allowlist.get("bash").expect("bash seeded");
            assert_eq!(bash.command, vec!["bash".to_string()]);
            assert!(bash.tmux && bash.terminal);
        }
    }

    #[test]
    fn resolve_app_gates_on_allowlist_and_enabled() {
        let cfg = cfg_with(&[("bash", true), ("htop", false)]);
        assert_eq!(resolve_app(&cfg, "bash").unwrap().key, "bash");
        assert!(resolve_app(&cfg, "htop").is_some());
        assert!(resolve_app(&cfg, "rm-rf").is_none(), "unknown key rejected");

        let mut disabled = cfg.clone();
        disabled.enabled = false;
        assert!(
            resolve_app(&disabled, "bash").is_none(),
            "disabled → nothing launches"
        );
    }

    #[test]
    fn resolve_app_rejects_empty_command() {
        let mut cfg = cfg_with(&[]);
        cfg.allowlist.insert(
            "empty".to_string(),
            AppSpec {
                command: vec![],
                label: None,
                terminal: false,
                tmux: false,
            },
        );
        assert!(resolve_app(&cfg, "empty").is_none());
    }

    #[test]
    fn launchable_list_stable_and_labelled() {
        let mut cfg = cfg_with(&[("zed", false), ("bash", true)]);
        cfg.allowlist.get_mut("bash").unwrap().label = Some("New bash session".to_string());
        let list = launchable_list(&cfg);
        // BTreeMap → alphabetical: bash, zed
        assert_eq!(list[0].key, "bash");
        assert_eq!(list[0].label, "New bash session");
        assert_eq!(list[1].key, "zed");
        assert_eq!(list[1].label, "zed", "label falls back to key");
    }

    #[test]
    fn next_tmux_session_name_picks_first_free() {
        assert_eq!(next_tmux_session_name(&[]), "s1");
        assert_eq!(
            next_tmux_session_name(&["s1".to_string(), "s2".to_string()]),
            "s3"
        );
        assert_eq!(
            next_tmux_session_name(&["s1".to_string(), "s3".to_string()]),
            "s2",
            "fills gaps"
        );
        assert_eq!(
            next_tmux_session_name(&["main".to_string()]),
            "s1",
            "ignores non-s<N> names"
        );
    }

    #[test]
    fn parse_wmctrl_list_handles_spaces_and_blanks() {
        let out = "0x03400007  0 host roomler:tmux:main\n\
                   0x03600004 0 host  a title with spaces\n\
                   \n\
                   0x03800009 -1 host \n"; // empty title
        let ws = parse_wmctrl_list(out);
        assert_eq!(ws.len(), 3);
        assert_eq!(ws[0].window_id, "0x03400007");
        assert_eq!(ws[0].title, "roomler:tmux:main");
        assert_eq!(ws[1].title, "a title with spaces");
        assert_eq!(ws[2].title, "", "empty title tolerated");
    }

    #[test]
    fn parse_tmux_sessions_trims_and_filters() {
        assert_eq!(
            parse_tmux_sessions("main\n s2 \n\n"),
            vec!["main".to_string(), "s2".to_string()]
        );
        assert!(parse_tmux_sessions("").is_empty(), "no server → empty");
    }

    #[test]
    fn classify_title_maps_convention() {
        let t = classify_title("roomler:tmux:main");
        assert_eq!(t.session.as_deref(), Some("main"));
        assert!(t.app_key.is_none());
        assert_eq!(t.title, "Terminal (main)");

        let a = classify_title("roomler:app:htop");
        assert_eq!(a.app_key.as_deref(), Some("htop"));
        assert!(a.session.is_none());
        assert_eq!(a.title, "htop");

        let p = classify_title("Mozilla Firefox");
        assert!(p.session.is_none() && p.app_key.is_none());
        assert_eq!(p.title, "Mozilla Firefox");
    }

    #[test]
    fn dispatch_list_unsupported_when_no_backend() {
        let cfg = VirtualDesktopAppsConfig::default();
        let why = Unavailable::NoSession {
            detail: "no active graphical session".to_string(),
        };
        let reply = dispatch(&json!({"t": "rc:apps.list", "id": "a1"}), &cfg, Err(&why));
        assert_eq!(reply["t"], "rc:apps.list.reply");
        assert_eq!(reply["id"], "a1");
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["supported"], false);
        assert_eq!(reply["windows"].as_array().unwrap().len(), 0);
        // FR-56 AC10 — `supported: false` carries WHY. Without this the panel
        // rendered a calm "No windows reported" for every host with no
        // desktop, and the cause lived only in the daemon log.
        assert_eq!(reply["unavailable"]["code"], "no_session");
        let reason = reply["unavailable"]["reason"].as_str().unwrap();
        assert!(reason.contains("no active graphical session"), "{reason}");
    }

    /// FR-56 AC10 — every refusal arm names its reason on every verb, so a
    /// viewer never has to guess which of six situations produced a bare
    /// `supported: false` (or a bare "not supported" on focus/launch).
    #[test]
    fn every_refusal_names_its_reason_on_the_wire() {
        let cfg = cfg_with(&[("bash", true)]);
        for why in unavailable_examples() {
            let list = dispatch(&json!({"t": "rc:apps.list", "id": "l"}), &cfg, Err(&why));
            assert_eq!(
                list["ok"], true,
                "{why:?}: a refusal is a well-formed reply"
            );
            assert_eq!(list["supported"], false, "{why:?}");
            assert_eq!(list["unavailable"]["code"], why.code(), "{why:?}");
            assert_eq!(list["unavailable"]["reason"], why.reason(), "{why:?}");

            let actions = [
                json!({"t": "rc:apps.focus", "id": "x", "window_id": "0x1"}),
                json!({"t": "rc:apps.launch", "id": "x", "app_key": "bash"}),
            ];
            for msg in actions {
                let reply = dispatch(&msg, &cfg, Err(&why));
                let t = msg["t"].as_str().unwrap();
                assert_eq!(reply["t"], format!("{t}.reply"));
                assert_eq!(reply["ok"], false, "{t} {why:?}");
                assert_eq!(reply["unavailable"]["code"], why.code(), "{t} {why:?}");
                let err = reply["error"].as_str().unwrap();
                assert!(
                    err.contains(&why.reason()),
                    "{t}: the legacy `error` string must carry the reason too, for viewers \
                     that read nothing else: {err}"
                );
            }
        }
    }

    /// The code set is a compatibility surface: distinct, snake_case, and no
    /// code a prefix of another — so an equality match can never be
    /// "simplified" into `starts_with` (the `ssh` / `ssh-consent` lesson).
    /// And a reason is a sentence, never the code restated.
    #[test]
    fn unavailable_codes_are_distinct_and_never_a_prefix_of_another() {
        let all = unavailable_examples();
        let codes: Vec<&str> = all.iter().map(|u| u.code()).collect();
        for (i, a) in codes.iter().enumerate() {
            assert!(!a.is_empty());
            assert!(
                a.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{a}: wire codes are snake_case"
            );
            for (j, b) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "duplicate code");
                    assert!(!b.starts_with(a), "{a} is a prefix of {b}");
                }
            }
        }
        for u in &all {
            let r = u.reason();
            assert!(
                r.len() > 40,
                "{}: a reason is a sentence the operator can act on, not a code: {r}",
                u.code()
            );
            assert_ne!(r, u.code());
            let j = u.to_json();
            assert_eq!(j["code"], u.code());
            assert_eq!(j["reason"], r);
        }
    }

    /// One of every variant. ⚠️ A variant added to `Unavailable` without a row
    /// here still compiles — `code()`'s match is exhaustive, this list is not —
    /// so keep the two together.
    fn unavailable_examples() -> Vec<Unavailable> {
        vec![
            Unavailable::Disabled,
            Unavailable::NoSession {
                detail: "loginctl: no active graphical session".into(),
            },
            Unavailable::NoXDisplay {
                user: "someone".into(),
                tried: vec![":0".into(), ":1".into()],
            },
            Unavailable::CannotRunAs {
                user: "someone".into(),
                detail: "looking up local account failed".into(),
            },
            Unavailable::ToolMissing {
                tool: "wmctrl",
                install: "apt install wmctrl",
            },
            Unavailable::Platform,
        ]
    }

    #[test]
    fn dispatch_list_ok_with_backend() {
        let cfg = cfg_with(&[("bash", true)]);
        let wm = FakeWm {
            windows: vec![WindowInfo {
                window_id: "0x1".to_string(),
                title: "Terminal (main)".to_string(),
                app_key: None,
                session: Some("main".to_string()),
                focused: true,
            }],
            fail: false,
        };
        let reply = dispatch(&json!({"t": "rc:apps.list", "id": "a2"}), &cfg, Ok(&wm));
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["supported"], true);
        assert_eq!(reply["windows"][0]["window_id"], "0x1");
        assert_eq!(reply["windows"][0]["session"], "main");
        assert_eq!(reply["launchable"][0]["key"], "bash");
    }

    #[test]
    fn dispatch_list_error_is_wellformed() {
        let cfg = cfg_with(&[("bash", true)]);
        let wm = FakeWm {
            windows: vec![],
            fail: true,
        };
        let reply = dispatch(&json!({"t": "rc:apps.list", "id": "a3"}), &cfg, Ok(&wm));
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["supported"], true);
        assert!(reply["error"].as_str().unwrap().contains("no display"));
        // FR-56 P2: coverage rides the ERROR arm too. A failed listing is the
        // case most likely to be read as "nothing there", so dropping the
        // caveat here would be dropping it exactly where it matters most.
        assert_eq!(reply["coverage"]["sources"][0], "x11");
        assert!(reply["coverage"]["unlisted"].is_string());
    }

    /// FR-56 P2 — the reply must distinguish "the desktop has no windows" from
    /// "there is a whole class of window we cannot see".
    ///
    /// ⚠️ `supported: true` + `windows: []` is ambiguous on a Wayland host and
    /// reads as the reassuring one. `coverage` is what makes the two
    /// distinguishable — the `Some([])` vs `None` lesson, fourth surface.
    #[test]
    fn an_empty_list_still_declares_what_it_could_not_enumerate() {
        let cfg = cfg_with(&[("bash", true)]);
        let wm = FakeWm {
            windows: vec![],
            fail: false,
        };
        let reply = dispatch(&json!({"t": "rc:apps.list", "id": "a4"}), &cfg, Ok(&wm));
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["windows"].as_array().unwrap().len(), 0);
        assert_eq!(reply["coverage"]["sources"][0], "x11");
        assert!(
            reply["coverage"]["unlisted"].is_string(),
            "an empty list must still say which source went unenumerated"
        );
    }

    #[test]
    fn dispatch_focus_roundtrips_and_errors() {
        let cfg = cfg_with(&[]);
        let wm = FakeWm {
            windows: vec![],
            fail: false,
        };
        let ok = dispatch(
            &json!({"t": "rc:apps.focus", "id": "f1", "window_id": "0x5"}),
            &cfg,
            Ok(&wm),
        );
        assert_eq!(ok["t"], "rc:apps.focus.reply");
        assert_eq!(ok["ok"], true);

        let bad = dispatch(
            &json!({"t": "rc:apps.focus", "id": "f2", "window_id": "0xBAD"}),
            &cfg,
            Ok(&wm),
        );
        assert_eq!(bad["ok"], false);
        assert!(bad["error"].as_str().unwrap().contains("no such window"));

        let missing = dispatch(&json!({"t": "rc:apps.focus", "id": "f3"}), &cfg, Ok(&wm));
        assert_eq!(missing["ok"], false);
        assert!(missing["error"].as_str().unwrap().contains("window_id"));
    }

    #[test]
    fn dispatch_launch_allowlist_gate() {
        let cfg = cfg_with(&[("bash", true)]);
        let wm = FakeWm {
            windows: vec![],
            fail: false,
        };
        let ok = dispatch(
            &json!({"t": "rc:apps.launch", "id": "l1", "app_key": "bash"}),
            &cfg,
            Ok(&wm),
        );
        assert_eq!(ok["t"], "rc:apps.launch.reply");
        assert_eq!(ok["ok"], true);
        assert_eq!(ok["window_id"], "0xNEW");
        assert_eq!(ok["session"], "s2");

        let denied = dispatch(
            &json!({"t": "rc:apps.launch", "id": "l2", "app_key": "evil"}),
            &cfg,
            Ok(&wm),
        );
        assert_eq!(denied["ok"], false);
        assert!(denied["error"].as_str().unwrap().contains("allowlist"));
    }

    #[test]
    fn dispatch_focus_unsupported_without_backend() {
        let cfg = VirtualDesktopAppsConfig::default();
        let reply = dispatch(
            &json!({"t": "rc:apps.focus", "id": "x", "window_id": "0x1"}),
            &cfg,
            Err(&Unavailable::Disabled),
        );
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("disabled"));
        assert_eq!(reply["unavailable"]["code"], "disabled");
    }

    #[test]
    fn dispatch_null_id_tolerated() {
        let cfg = cfg_with(&[]);
        let reply = dispatch(
            &json!({"t": "rc:apps.list"}),
            &cfg,
            Err(&Unavailable::Platform),
        );
        assert!(reply["id"].is_null());
        assert_eq!(reply["ok"], true);
    }
}
