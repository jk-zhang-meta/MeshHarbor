// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-93 P1 — can a controller's input reach this desktop at all?
//!
//! An injector that reaches nothing does not fail. XTest into Xwayland
//! SUCCEEDS and moves Xwayland's own pointer, which the compositor ignores.
//! Where Xwayland sends XTest through EI it reaches no window at all. GNOME 49
//! and later start it with `-enable-ei-portal`. KWin hands it an EI socket in
//! its environment (`LIBEI_SOCKET`) instead, and gates it behind its own prompt.
//! Both measured on the FR-93 lab: GNOME 50, and Plasma 6.7, where xdotool moved
//! nothing and clicked nothing even in an X11 window. Before this, a session on
//! such a host looked fully interactive and silently did nothing.
//!
//! So each session is told what its input will reach (`rc:input-reach` over
//! the control channel, only when that is less than everything), decided from
//! the same facts `input::open_default`'s cascade decides from. The decision is
//! pure ([`decide`]) so its table is testable; [`told`] gathers the facts,
//! unless P1's kill switch is off on Linux, which tells nothing (P1a).

/// How far a controller's input reaches on this desktop. Additive on the
/// wire: an older viewer ignores the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Everything the person at the screen could touch.
    Full,
    /// Only X11 apps running on Xwayland; native Wayland windows ignore it.
    XwaylandOnly,
    /// Nothing at all.
    None,
}

impl Reach {
    /// The wire spelling. A compatibility surface: renaming one changes what
    /// every deployed viewer reads.
    pub fn wire(self) -> &'static str {
        match self {
            Reach::Full => "full",
            Reach::XwaylandOnly => "xwayland_only",
            Reach::None => "none",
        }
    }
}

/// The verdict for one session, with the reason in operator words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputReach {
    pub reach: Reach,
    pub reason: String,
}

/// The X server the enigo injector would talk to.
///
/// Allowed dead: a build without enigo (or off Linux) only ever finds `Absent`.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XServer {
    /// No `DISPLAY`, or none that answers on its Unix socket.
    Absent,
    /// A real X server: Xorg, or the daemon's own Xvfb.
    Real,
    /// Xwayland: XTest reaches its own clients only.
    Xwayland,
    /// Xwayland sends XTest through EI: it reaches nothing, unless KWin lets
    /// this agent through.
    XwaylandEi(EiRoute),
}

/// How an Xwayland reaches EI.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EiRoute {
    /// `-enable-ei-portal` on its command line: GNOME 49 and later.
    Portal,
    /// An EI socket handed over by KWin (6.1 and later), which gates XTest
    /// behind its own prompt. `granted`: the person let this agent through
    /// without one, in Legacy X11 App Support. Measured on Plasma 6.7 with
    /// `XwaylandEisNoPromptApps=roomlerd`: the viewer's pointer, click, wheel
    /// and typing all reached a native Wayland window.
    Compositor { granted: bool },
}

/// Allowed dead: each build constructs only its own platform.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Platform {
    Linux,
    Windows,
    MacOs { accessibility: bool },
}

/// Whose RemoteDesktop session a live input route feeds (FR-45 P4, FR-93 P4).
/// While one is live it owns injection, whatever the OS injector would reach.
#[cfg_attr(
    not(all(target_os = "linux", feature = "portal-capture")),
    allow(dead_code)
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// xdg-desktop-portal's RemoteDesktop, granted at the screen.
    Portal,
    /// mutter's own RemoteDesktop (GNOME), which asks nobody.
    Mutter,
}

/// What the injector cascade would find, as data.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Facts {
    pub platform: Platform,
    /// A live RemoteDesktop route, and whose: it then owns injection.
    pub route: Option<RouteKind>,
    /// `uinput` is switched on, and `/dev/uinput` opens.
    pub uinput_on: bool,
    pub uinput_ok: bool,
    /// This build carries the enigo injector at all.
    pub enigo_built: bool,
    pub x: XServer,
}

const WAYLAND_FIX: &str = "On a system install switch on uinput. A per-user one asks \
     the person at the screen for remote control by itself, unless portal_input or \
     mutter_input is set to false: reconnect, and allow remote control when the \
     desktop asks.";

/// The fix where KWin gates XTest. First the remote control a per-user
/// install's automatic portal asks for (FR-93 P4b): a session lands here when
/// the person refused it, or `portal_input = false`. Then the narrow grant, not
/// the global switch: it names this agent and nothing else. KWin reads it when
/// Xwayland starts, hence the new login.
const KWIN_FIX: &str = "A per-user install asks the person at the screen for remote \
     control by itself, unless portal_input is set to false: reconnect, and allow \
     remote control when the desktop asks. Or the person at the screen allows \
     roomlerd once in System Settings, Legacy X11 App Support (kwinrc [Xwayland] \
     XwaylandEisNoPromptApps=roomlerd), then logs in again. On a system install, \
     switch on uinput.";

/// The reach `input::open_default` would give a session with these facts.
pub(crate) fn decide(f: &Facts) -> InputReach {
    let verdict = |reach, reason: String| InputReach { reach, reason };
    match f.platform {
        Platform::Windows => {
            return if f.enigo_built {
                verdict(Reach::Full, "SendInput".into())
            } else {
                verdict(
                    Reach::None,
                    "this agent was built without an input backend".into(),
                )
            };
        }
        Platform::MacOs { accessibility } => {
            return if !f.enigo_built {
                verdict(
                    Reach::None,
                    "this agent was built without an input backend".into(),
                )
            } else if accessibility {
                verdict(Reach::Full, "CGEvent, with Accessibility granted".into())
            } else {
                verdict(
                    Reach::None,
                    "macOS Accessibility is not granted to this agent: grant it in System \
                     Settings, Privacy & Security, Accessibility, then restart the agent"
                        .into(),
                )
            };
        }
        Platform::Linux => {}
    }
    if let Some(route) = f.route {
        return verdict(
            Reach::Full,
            match route {
                RouteKind::Portal => "the desktop portal's RemoteDesktop session",
                RouteKind::Mutter => "mutter's own RemoteDesktop session (GNOME)",
            }
            .into(),
        );
    }
    if f.uinput_on && f.uinput_ok {
        return verdict(Reach::Full, "uinput, below the compositor".into());
    }
    let uinput_note = if f.uinput_on {
        " (uinput is switched on, but /dev/uinput did not open: it needs root or the \
         input group)"
    } else {
        ""
    };
    if !f.enigo_built {
        return verdict(
            Reach::None,
            format!("this agent was built without an X11 input backend{uinput_note}"),
        );
    }
    match f.x {
        XServer::Real => verdict(Reach::Full, "XTest on a real X server".into()),
        XServer::Xwayland => verdict(
            Reach::XwaylandOnly,
            format!(
                "this is a Wayland desktop, and XTest reaches only apps running on \
                 Xwayland{uinput_note}. {WAYLAND_FIX}"
            ),
        ),
        XServer::XwaylandEi(EiRoute::Compositor { granted: true }) => verdict(
            Reach::Full,
            "XTest through KWin's input-emulation gate, which lets this agent \
             through without asking (Legacy X11 App Support)"
                .into(),
        ),
        XServer::XwaylandEi(route) => {
            let (why, fix) = match route {
                EiRoute::Portal => (
                    "the EI portal (GNOME 49 and later), so it reaches no window at all",
                    WAYLAND_FIX,
                ),
                EiRoute::Compositor { .. } => (
                    "KWin's input-emulation gate (KDE Plasma 6.1 and later), which asks \
                     the person at the screen first: unattended, it reaches no window at \
                     all",
                    KWIN_FIX,
                ),
            };
            verdict(
                Reach::None,
                format!(
                    "this is a Wayland desktop whose Xwayland sends XTest through \
                     {why}{uinput_note}. {fix}"
                ),
            )
        }
        XServer::Absent => verdict(
            Reach::None,
            format!(
                "no input path reaches this desktop: no X display, no uinput{uinput_note}. {WAYLAND_FIX}"
            ),
        ),
    }
}

/// What a session starting now is told: its verdict, or `None` for nothing at
/// all. Call it AFTER capture opened: a portal capture registers its input
/// route as it opens.
///
/// FR-93 P1a: on Linux this notice is part of P1, so P1's kill switch
/// (`wayland_aware = false`) tells nothing, as the agent did before FR-93.
/// Before P1a it still did: the FR-93 lab's GNOME guest on 0.4.135, with the
/// switch off, streamed the old black XShm picture under a warning that
/// 0.4.124 never sent (AC11: the kill switch restores the old behaviour
/// exactly). The switch is a Linux key, so macOS and Windows are always told.
pub fn told() -> Option<InputReach> {
    #[cfg(target_os = "linux")]
    let aware = crate::capture::wayland_aware();
    #[cfg(not(target_os = "linux"))]
    let aware = true;
    told_with(aware, gather)
}

/// [`told`] with P1's switch and the facts given. Off gathers nothing, so the
/// X server is not even asked, just as the capture's own Xwayland guard does
/// not ask it.
fn told_with(aware: bool, facts: impl FnOnce() -> Facts) -> Option<InputReach> {
    aware.then(|| decide(&facts()))
}

/// FR-93 P2b — the verdict a session opened now would get, for the desktop
/// brief. An input route registers only as a capture opens, so outside a
/// session it is predicted: `route` is the one the planned arm would open
/// (`capture::planned_input_route`).
///
/// ⚠️ `wayland_session`: there the X server is Xwayland, and GNOME starts it
/// **on demand** when a client connects, so a read that connects can itself be
/// what starts one. The brief reads every minute, so on a Wayland desktop it
/// connects only to an Xwayland already running (found in `/proc`), and with
/// none it reads "no X server". An X11 session cannot exist without its
/// server, so there connecting starts nothing. (Measured on GNOME 50: a daemon
/// RESTART starts an Xwayland on 0.4.129 and on this build alike, because the
/// x11 consent panel connects at start, `indicator/x11.rs`. A boot does not.
/// This rule keeps the brief from adding to that.)
///
/// #2473 — `auto_system`: the plan says a root daemon's automatic system
/// capture (FR-95, FR-113) would open (`capture::ArmFacts::auto_system`). Its
/// `uinput` is the injector a session would get, so it counts here although no
/// capture is live yet: the brief runs once a minute, mostly with none, and
/// before this it predicted `none` for every such host.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn predicted(route: Option<RouteKind>, wayland_session: bool, auto_system: bool) -> InputReach {
    let mut facts = gather_with(
        if wayland_session {
            x_server_if_running
        } else {
            x_server
        },
        auto_system,
    );
    facts.route = facts.route.or(route);
    decide(&facts)
}

fn gather() -> Facts {
    gather_with(x_server, false)
}

/// FR-95 P2 / #2473 — whether the automatic `uinput` is the injector: never with
/// `uinput` set either way (`unset`), and only while an automatic system
/// capture is `live`, or, for the brief's prediction, `planned`.
#[cfg_attr(
    not(all(target_os = "linux", feature = "uinput-input", feature = "drm-capture")),
    allow(dead_code)
)]
fn automatic_uinput(unset: bool, live: bool, planned: bool) -> bool {
    unset && (live || planned)
}

/// [`gather`], with the X server read by `x`; `planned_auto` as [`predicted`]'s
/// `auto_system`.
fn gather_with(x: fn() -> XServer, planned_auto: bool) -> Facts {
    #[cfg(target_os = "windows")]
    let platform = Platform::Windows;
    #[cfg(target_os = "macos")]
    let platform = Platform::MacOs {
        accessibility: crate::tcc::accessibility_trusted(),
    };
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let platform = Platform::Linux;

    #[cfg(all(target_os = "linux", feature = "portal-capture"))]
    let route = crate::capture::portal::input_route::active();
    #[cfg(not(all(target_os = "linux", feature = "portal-capture")))]
    let route = None;

    #[cfg(all(target_os = "linux", feature = "uinput-input"))]
    let (uinput_on, uinput_ok) = {
        // FR-95 P2 — or switched on by itself, for an automatic system
        // capture (`input::open_default`): live, or (#2473) planned.
        #[cfg(feature = "drm-capture")]
        let auto = automatic_uinput(
            super::uinput_unset(),
            crate::capture::seat_guard::live(),
            planned_auto,
        );
        #[cfg(not(feature = "drm-capture"))]
        let auto = {
            let _ = planned_auto;
            false
        };
        let on = super::uinput_backend::env_enabled() || auto;
        (on, on && super::uinput_backend::available())
    };
    #[cfg(not(all(target_os = "linux", feature = "uinput-input")))]
    let (uinput_on, uinput_ok) = {
        let _ = planned_auto;
        (false, false)
    };

    Facts {
        platform,
        route,
        uinput_on,
        uinput_ok,
        enigo_built: cfg!(feature = "enigo-input"),
        x: x(),
    }
}

/// [`x_server`], but only when an Xwayland already serves `DISPLAY`: never the
/// connection that starts one (see [`predicted`]).
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn x_server_if_running() -> XServer {
    let running = std::env::var("DISPLAY")
        .ok()
        .as_deref()
        .and_then(display_number)
        .is_some_and(xwayland_serves);
    if running { x_server() } else { XServer::Absent }
}

#[cfg(not(all(target_os = "linux", feature = "enigo-input")))]
fn x_server_if_running() -> XServer {
    XServer::Absent
}

/// Is an Xwayland process serving display `:number`? Read from `/proc` (its
/// `comm` and command line, which a sandboxed daemon may read), never by
/// connecting.
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn xwayland_serves(number: &str) -> bool {
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return false;
    };
    procs.flatten().any(|p| {
        let path = p.path();
        std::fs::read_to_string(path.join("comm")).is_ok_and(|c| c.trim() == "Xwayland")
            && std::fs::read(path.join("cmdline")).is_ok_and(|c| cmdline_serves(&c, number))
    })
}

#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn x_server() -> XServer {
    let Some(display) = std::env::var_os("DISPLAY") else {
        return XServer::Absent;
    };
    let display = display.to_string_lossy().into_owned();
    match crate::capture::x_server_xwayland(&display) {
        None => XServer::Absent,
        Some(false) => XServer::Real,
        Some(true) => match xwayland_ei_route(&display) {
            Some(route) => XServer::XwaylandEi(route),
            None => XServer::Xwayland,
        },
    }
}

#[cfg(not(all(target_os = "linux", feature = "enigo-input")))]
fn x_server() -> XServer {
    XServer::Absent
}

/// Does the Xwayland serving `display` send XTest through EI, and how? Read
/// from that process. GNOME starts it as `Xwayland :0 -rootless …
/// -enable-ei-portal`. KWin starts it as `Xwayland :0 -auth … -rootless`, with
/// a `LIBEI_SOCKET=/proc/self/fd/N` in its environment.
///
/// ⚠️ A sandboxed per-user daemon may not read that environment. Its unit's
/// sandbox puts it in a user namespace of its own, and the kernel refuses
/// another namespace's `/proc/<pid>/environ` (measured on Fedora 44:
/// *Permission denied*, while `cmdline` reads fine). Then two facts it CAN
/// read stand in: Xwayland's parent is `kwin_wayland`, and that KWin is 6.1
/// or later, the release that hands every Xwayland an EI socket. No process
/// found means no EI.
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn xwayland_ei_route(display: &str) -> Option<EiRoute> {
    let number = display_number(display)?;
    let procs = std::fs::read_dir("/proc").ok()?;
    procs.flatten().find_map(|p| {
        let path = p.path();
        let is_xwayland = std::fs::read_to_string(path.join("comm"))
            .map(|c| c.trim() == "Xwayland")
            .unwrap_or(false);
        if !is_xwayland {
            return None;
        }
        let cmdline = std::fs::read(path.join("cmdline")).ok()?;
        if !cmdline_serves(&cmdline, number) {
            return None;
        }
        let compositor_ei = match std::fs::read(path.join("environ")) {
            Ok(environ) => environ_has_libei_socket(&environ),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                parent_is_kwin(&path) && kwin_version().is_some_and(|v| v >= KWIN_EI_SINCE)
            }
            Err(_) => false,
        };
        ei_route(&cmdline, compositor_ei, kwin_granted)
    })
}

/// Is this Xwayland's parent KWin? From `/proc/<pid>/status`, world-readable,
/// and the parent's `comm`, also world-readable even though KWin itself is
/// not dumpable (it holds CAP_SYS_NICE).
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn parent_is_kwin(xwayland: &std::path::Path) -> bool {
    std::fs::read_to_string(xwayland.join("status"))
        .ok()
        .and_then(|s| status_ppid(&s))
        .and_then(|ppid| std::fs::read_to_string(format!("/proc/{ppid}/comm")).ok())
        .is_some_and(|comm| comm.trim().starts_with("kwin_wayland"))
}

/// The KWin release that started handing every Xwayland an EI socket: Plasma
/// 6.1 ("xtest libei integration for Xwayland", the 6.1.0 changelog).
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
const KWIN_EI_SINCE: (u32, u32) = (6, 1);

/// KWin's version, from its library's file name (`libkwin.so.6.7.5`): read
/// without running anything. The highest one found, as (major, minor).
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn kwin_version() -> Option<(u32, u32)> {
    [
        "/usr/lib64",
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    ]
    .iter()
    .filter_map(|d| std::fs::read_dir(d).ok())
    .flat_map(|entries| entries.flatten())
    .filter_map(|e| libkwin_version(&e.file_name().to_string_lossy()))
    .max()
}

/// Has the person let this agent's XTest through KWin's gate without a
/// prompt? KConfig reads the user's `kwinrc` over the system's
/// (`/etc/xdg/kwinrc`), key by key, and so does this.
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn kwin_granted() -> bool {
    let user_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")));
    let read = |p: std::path::PathBuf| std::fs::read_to_string(p).unwrap_or_default();
    let user = user_dir.map(|d| read(d.join("kwinrc"))).unwrap_or_default();
    let system = read(std::path::PathBuf::from("/etc/xdg/kwinrc"));
    // Xwayland names an X11 client's EI connection after the process: the
    // grant measured on the lab was `XwaylandEisNoPromptApps=roomlerd`.
    let me = std::fs::read_to_string("/proc/self/comm").unwrap_or_default();
    kwinrc_grants(&user, &system, me.trim())
}

/// `":0"` / `":0.0"` / `"unix:1"` → the display number. `None` for anything
/// else (a TCP display is never Xwayland's).
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
fn display_number(display: &str) -> Option<&str> {
    let (host, rest) = display.rsplit_once(':')?;
    if !(host.is_empty() || host == "unix") {
        return None;
    }
    let number = rest.split('.').next()?;
    (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())).then_some(number)
}

/// Does a NUL-separated command line serve display `:number`?
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
fn cmdline_serves(cmdline: &[u8], number: &str) -> bool {
    let want = format!(":{number}");
    cmdline.split(|b| *b == 0).any(|a| a == want.as_bytes())
}

/// The pure half of [`xwayland_ei_route`]: from an Xwayland's NUL-separated
/// command line, and whether a compositor handed it an EI socket, how its
/// XTest reaches EI. `granted` is asked only on KWin's route.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
fn ei_route(
    cmdline: &[u8],
    compositor_ei: bool,
    granted: impl FnOnce() -> bool,
) -> Option<EiRoute> {
    if cmdline
        .split(|b| *b == 0)
        .any(|a| a == b"-enable-ei-portal")
    {
        return Some(EiRoute::Portal);
    }
    compositor_ei.then(|| EiRoute::Compositor { granted: granted() })
}

/// A NUL-separated environment carrying a `LIBEI_SOCKET`. An empty one names
/// no socket, so it does not count.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
fn environ_has_libei_socket(environ: &[u8]) -> bool {
    environ
        .split(|b| *b == 0)
        .any(|v| v.len() > b"LIBEI_SOCKET=".len() && v.starts_with(b"LIBEI_SOCKET="))
}

/// `PPid:` from a `/proc/<pid>/status`.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
fn status_ppid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// `libkwin.so.6.7.5` → `(6, 7)`. KWin's own library, with its full version
/// only: `libkwin.so.6` is the symlink, and says less.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
fn libkwin_version(file_name: &str) -> Option<(u32, u32)> {
    let mut parts = file_name.strip_prefix("libkwin.so.")?.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let _patch: u32 = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((major, minor))
}

/// KWin's grant, the user's kwinrc over the system's, key by key: the global
/// `XwaylandEisNoPrompt`, or `me` named in `XwaylandEisNoPromptApps`.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
fn kwinrc_grants(user: &str, system: &str, me: &str) -> bool {
    let (user_all, user_apps) = kwinrc_xwayland(user);
    let (system_all, system_apps) = kwinrc_xwayland(system);
    let all = user_all.or(system_all).unwrap_or(false);
    let apps = user_apps.or(system_apps).unwrap_or_default();
    all || (!me.is_empty() && apps.iter().any(|a| a == me))
}

/// `XwaylandEisNoPrompt` and `XwaylandEisNoPromptApps` from one kwinrc's
/// `[Xwayland]` group, each `None` where the file does not set it. A
/// `[$i]` (immutable) marker on the group or the key is KConfig's and is read
/// through.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
fn kwinrc_xwayland(text: &str) -> (Option<bool>, Option<Vec<String>>) {
    let (mut in_group, mut all, mut apps) = (false, None, None);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') && !line.contains('=') {
            in_group = line == "[Xwayland]" || line.starts_with("[Xwayland][$");
            continue;
        }
        let Some((key, value)) = line.split_once('=').filter(|_| in_group) else {
            continue;
        };
        let key = key.split('[').next().unwrap_or(key).trim();
        let value = value.trim();
        match key {
            "XwaylandEisNoPrompt" => {
                all = Some(matches!(
                    value.to_ascii_lowercase().as_str(),
                    "true" | "1" | "on" | "yes"
                ))
            }
            "XwaylandEisNoPromptApps" => apps = Some(kconfig_list(value)),
            _ => {}
        }
    }
    (all, apps)
}

/// A KConfig string list: comma-separated, a backslash escapes the next
/// character.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
fn kconfig_list(value: &str) -> Vec<String> {
    let (mut out, mut cur) = (Vec::new(), String::new());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => cur.extend(chars.next()),
            ',' => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The `rc:input-reach` control-channel message. Built with serde, because a
/// reason carries the operator's words and must arrive as written.
pub fn payload(r: &InputReach) -> String {
    serde_json::json!({
        "t": "rc:input-reach",
        "reach": r.reach.wire(),
        "reason": r.reason,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux(x: XServer) -> Facts {
        Facts {
            platform: Platform::Linux,
            route: None,
            uinput_on: false,
            uinput_ok: false,
            enigo_built: true,
            x,
        }
    }

    /// #2473 — the automatic `uinput` counts while its capture is live (the
    /// per-session verdict) AND when the plan says one would open (the brief,
    /// which mostly runs with none live); never with `uinput` set either way.
    #[test]
    fn the_automatic_uinput_counts_when_live_or_planned() {
        assert!(super::automatic_uinput(true, true, false), "live");
        assert!(
            super::automatic_uinput(true, false, true),
            "planned, nothing live"
        );
        assert!(!super::automatic_uinput(true, false, false), "neither");
        assert!(
            !super::automatic_uinput(false, true, true),
            "uinput set by the operator: the configured path decides"
        );
        // And what the brief then says: the injector reaches the desktop.
        let mut f = linux(XServer::Absent);
        f.uinput_on = true;
        f.uinput_ok = true;
        assert_eq!(decide(&f).reach, Reach::Full);
    }

    /// The FR-93 lab's per-user GNOME 50 guest, stock: XTest is all there is,
    /// and its Xwayland routes XTest through the EI portal.
    #[test]
    fn gnome_50s_xwayland_reaches_nothing() {
        let r = decide(&linux(XServer::XwaylandEi(EiRoute::Portal)));
        assert_eq!(r.reach, Reach::None);
        assert!(r.reason.contains("EI portal"), "{}", r.reason);
        assert!(r.reason.contains("portal_input"), "{}", r.reason);
    }

    /// The FR-93 lab's per-user Plasma 6.7 guest, stock: KWin's Xwayland
    /// carries no `-enable-ei-portal`, yet XTest reached nothing, not even an
    /// X11 window, because KWin handed it an EI socket.
    #[test]
    fn kwins_xwayland_reaches_nothing() {
        let r = decide(&linux(XServer::XwaylandEi(EiRoute::Compositor {
            granted: false,
        })));
        assert_eq!(r.reach, Reach::None);
        assert!(r.reason.contains("KWin"), "{}", r.reason);
        // P4b — first the remote control the automatic portal asks for: the
        // session lands here when the person refused it.
        assert!(
            r.reason
                .contains("allow remote control when the desktop asks"),
            "{}",
            r.reason
        );
        // Then the narrow grant, for this agent alone.
        assert!(
            r.reason.contains("XwaylandEisNoPromptApps=roomlerd"),
            "{}",
            r.reason
        );
    }

    /// The same guest once the person allowed roomlerd in Legacy X11 App
    /// Support: the viewer's pointer, click, wheel and typing reached a native
    /// window (FR-93 lab, 2026-10-11).
    #[test]
    fn a_kwin_grant_reaches_everything() {
        let r = decide(&linux(XServer::XwaylandEi(EiRoute::Compositor {
            granted: true,
        })));
        assert_eq!(r.reach, Reach::Full);
        assert!(r.reason.contains("KWin"), "{}", r.reason);
    }

    #[test]
    fn an_older_xwayland_reaches_only_its_own_apps() {
        assert_eq!(decide(&linux(XServer::Xwayland)).reach, Reach::XwaylandOnly);
    }

    #[test]
    fn a_real_x_server_or_the_virtual_desktop_reaches_everything() {
        assert_eq!(decide(&linux(XServer::Real)).reach, Reach::Full);
    }

    /// The lab's system guest: a root unit has no display at all.
    #[test]
    fn no_display_and_no_uinput_reaches_nothing() {
        let r = decide(&linux(XServer::Absent));
        assert_eq!(r.reach, Reach::None);
        assert!(r.reason.contains("uinput"), "{}", r.reason);
    }

    /// FR-93 P1a (AC11): P1's kill switch gives back the agent before FR-93,
    /// which told no session its reach. Nothing is gathered, so the X server
    /// is not even asked. With the switch on, the same desktop is told.
    #[test]
    fn the_kill_switch_tells_nothing_and_asks_nobody() {
        assert_eq!(told_with(false, || panic!("facts gathered")), None);
        let gnome = told_with(true, || linux(XServer::XwaylandEi(EiRoute::Portal)));
        assert_eq!(gnome.map(|r| r.reach), Some(Reach::None));
    }

    #[test]
    fn uinput_or_a_portal_route_reaches_everything_whatever_the_x_server() {
        for x in [
            XServer::Absent,
            XServer::XwaylandEi(EiRoute::Portal),
            XServer::XwaylandEi(EiRoute::Compositor { granted: false }),
            XServer::Xwayland,
        ] {
            let uinput = Facts {
                uinput_on: true,
                uinput_ok: true,
                ..linux(x)
            };
            assert_eq!(decide(&uinput).reach, Reach::Full, "{x:?}");
            let portal = Facts {
                route: Some(RouteKind::Portal),
                ..linux(x)
            };
            assert_eq!(decide(&portal).reach, Reach::Full, "{x:?}");
            // FR-93 P4 — mutter's own RemoteDesktop owns injection the same way,
            // and says whose it is.
            let mutter = decide(&Facts {
                route: Some(RouteKind::Mutter),
                ..linux(x)
            });
            assert_eq!(mutter.reach, Reach::Full, "{x:?}");
            assert!(mutter.reason.contains("mutter"), "{}", mutter.reason);
        }
    }

    /// uinput switched on but unusable falls through to XTest, as
    /// `open_default` does, and the reason says why uinput did not count.
    #[test]
    fn uinput_that_did_not_open_says_so() {
        let f = Facts {
            uinput_on: true,
            uinput_ok: false,
            ..linux(XServer::XwaylandEi(EiRoute::Portal))
        };
        let r = decide(&f);
        assert_eq!(r.reach, Reach::None);
        assert!(
            r.reason.contains("/dev/uinput did not open"),
            "{}",
            r.reason
        );
    }

    #[test]
    fn a_build_without_an_injector_reaches_nothing() {
        let f = Facts {
            enigo_built: false,
            ..linux(XServer::Real)
        };
        assert_eq!(decide(&f).reach, Reach::None);
    }

    #[test]
    fn a_mac_without_accessibility_reaches_nothing() {
        let mac = |accessibility| Facts {
            platform: Platform::MacOs { accessibility },
            ..linux(XServer::Absent)
        };
        assert_eq!(decide(&mac(true)).reach, Reach::Full);
        let r = decide(&mac(false));
        assert_eq!(r.reach, Reach::None);
        assert!(r.reason.contains("Accessibility"), "{}", r.reason);
    }

    #[test]
    fn windows_reaches_everything() {
        let f = Facts {
            platform: Platform::Windows,
            ..linux(XServer::Absent)
        };
        assert_eq!(decide(&f).reach, Reach::Full);
    }

    /// GNOME 50's Xwayland command line, as the lab's guest runs it.
    #[test]
    fn gnome_50s_command_line_is_recognised() {
        // NUL-separated, as /proc/<pid>/cmdline holds it.
        let cmdline = |args: &[&str]| args.join("\0").into_bytes();
        let gnome = cmdline(&[
            "Xwayland",
            ":0",
            "-rootless",
            "-noreset",
            "-accessx",
            "-core",
            "-auth",
            "/run/user/1000/.mutter-Xwaylandauth.Q1",
            "-listenfd",
            "4",
            "-displayfd",
            "6",
            "-enable-ei-portal",
            "",
        ]);
        assert!(cmdline_serves(&gnome, "0"));
        assert!(!cmdline_serves(&gnome, "1"), "another display's Xwayland");
        // The portal route never asks for KWin's grant.
        let never = || -> bool { panic!("asked for KWin's grant on GNOME") };
        assert_eq!(ei_route(&gnome, false, never), Some(EiRoute::Portal));
        let older = cmdline(&["Xwayland", ":0", "-rootless", "-noreset", ""]);
        assert!(cmdline_serves(&older, "0"));
        assert_eq!(ei_route(&older, false, || false), None);
    }

    /// Plasma 6.7's Xwayland, as the lab's KDE guest runs it: nothing about EI
    /// on the command line, and the socket in the environment.
    #[test]
    fn plasmas_environment_is_recognised() {
        let nul = |parts: &[&str]| parts.join("\0").into_bytes();
        let kwin = nul(&[
            "/usr/bin/Xwayland",
            ":0",
            "-auth",
            "/run/user/1000/xauth_PPjmwd",
            "-listenfd",
            "8",
            "-listenfd",
            "9",
            "-displayfd",
            "86",
            "-wm",
            "93",
            "-rootless",
            "",
        ]);
        assert!(cmdline_serves(&kwin, "0"));
        let env = nul(&[
            "XDG_SESSION_TYPE=wayland",
            "LIBEI_SOCKET=/proc/self/fd/65",
            "WAYLAND_SOCKET=95",
            "",
        ]);
        assert!(environ_has_libei_socket(&env));
        assert_eq!(
            ei_route(&kwin, true, || false),
            Some(EiRoute::Compositor { granted: false })
        );
        assert_eq!(
            ei_route(&kwin, true, || true),
            Some(EiRoute::Compositor { granted: true })
        );
        assert_eq!(ei_route(&kwin, false, || true), None);
        // No socket, an empty one, or a look-alike name: no EI.
        assert!(!environ_has_libei_socket(&nul(&["WAYLAND_SOCKET=95", ""])));
        assert!(!environ_has_libei_socket(&nul(&["LIBEI_SOCKET=", ""])));
        assert!(!environ_has_libei_socket(&nul(&["XLIBEI_SOCKET=/x", ""])));
    }

    /// What a sandboxed daemon reads instead of Xwayland's environment.
    #[test]
    fn the_sandbox_stand_ins_are_parsed() {
        let status = "Name:\tXwayland\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4269\nNgid:\t0\nPid:\t4269\nPPid:\t1586\nTracerPid:\t0\n";
        assert_eq!(status_ppid(status), Some(1586));
        assert_eq!(status_ppid("Name:\tx\n"), None);
        assert_eq!(libkwin_version("libkwin.so.6.7.5"), Some((6, 7)));
        assert_eq!(libkwin_version("libkwin.so.5.27.11"), Some((5, 27)));
        assert_eq!(libkwin_version("libkwin.so.6"), None, "the symlink");
        assert_eq!(libkwin_version("libkwin.so.6.7.5.debug"), None);
        assert_eq!(libkwin_version("libkwineffects.so.6.7.5"), None);
        // Plasma 6.1 is where KWin started handing Xwayland an EI socket.
        // Kubuntu 24.04's Plasma 5.27 must stay below it: there XTest does
        // reach X11 apps, and `xwayland_only` is the truth.
        assert_eq!(KWIN_EI_SINCE, (6, 1));
    }

    #[test]
    fn kwinrc_grants_are_read() {
        let lab = "[Desktops]\nNumber=1\n\n[Xwayland]\nScale=1\nXwaylandEisNoPromptApps=roomlerd\n";
        assert!(kwinrc_grants(lab, "", "roomlerd"));
        assert!(
            !kwinrc_grants(lab, "", "xdotool"),
            "the grant names one app"
        );
        assert!(kwinrc_grants(
            "[Xwayland]\nXwaylandEisNoPrompt=true\n",
            "",
            "roomlerd"
        ));
        assert!(kwinrc_grants(
            "[Xwayland]\nXwaylandEisNoPromptApps=a,roomlerd ,b\\,c\n",
            "",
            "roomlerd"
        ));
        // Stock: no keys anywhere.
        assert!(!kwinrc_grants("[Xwayland]\nScale=1\n", "", "roomlerd"));
        // The same key in another group is not the grant.
        assert!(!kwinrc_grants(
            "[Wayland]\nXwaylandEisNoPrompt=true\n",
            "",
            "roomlerd"
        ));
        // The system file counts where the user's says nothing…
        let system = "[Xwayland][$i]\nXwaylandEisNoPrompt[$i]=true\n";
        assert!(kwinrc_grants("", system, "roomlerd"));
        // …and the user's own value wins where it does.
        assert!(!kwinrc_grants(
            "[Xwayland]\nXwaylandEisNoPrompt=false\n",
            system,
            "roomlerd"
        ));
        assert!(!kwinrc_grants(lab, "", ""), "no name of our own, no grant");
    }

    #[test]
    fn display_numbers_are_parsed_and_tcp_displays_refused() {
        assert_eq!(display_number(":0"), Some("0"));
        assert_eq!(display_number(":12.0"), Some("12"));
        assert_eq!(display_number("unix:1"), Some("1"));
        assert_eq!(display_number("10.0.0.1:0"), None);
        assert_eq!(display_number(":x"), None);
        assert_eq!(display_number(""), None);
    }

    #[test]
    fn the_wire_names_and_payload_are_locked() {
        assert_eq!(Reach::Full.wire(), "full");
        assert_eq!(Reach::XwaylandOnly.wire(), "xwayland_only");
        assert_eq!(Reach::None.wire(), "none");
        let p = payload(&InputReach {
            reach: Reach::None,
            reason: "a \"quoted\" reason".into(),
        });
        let v: serde_json::Value = serde_json::from_str(&p).expect("JSON");
        assert_eq!(v["t"], "rc:input-reach");
        assert_eq!(v["reach"], "none");
        assert_eq!(v["reason"], "a \"quoted\" reason");
    }
}
