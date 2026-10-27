// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-45 P1 — is the desktop portal actually usable on this host?
//!
//! [FR-36](../../../docs/fr/FR-36-wayland-capture.md) captures *below* the
//! compositor with DRM/KMS, which needs a real CRTC. Where there is none —
//! WSL2, containers, nested compositors — `xdg-desktop-portal`'s ScreenCast
//! interface is the only route to the pixels. This module answers the question
//! that has to come first: **is it there?**
//!
//! ## Why this is a real question and not a formality
//!
//! FR-36 measured a host where `xdg-desktop-portal` was running and reachable —
//! four portal names on the session bus — and yet exposed **neither
//! `ScreenCast` nor `RemoteDesktop`**, because those come from a
//! compositor-matching backend (`-gnome`, `-kde`, `-wlr`) that was not
//! installed for the running session. "The portal is running" therefore proves
//! nothing at all. The interface has to be **looked for by name**.
//!
//! ⚠️ This module deliberately reports *why* it is unavailable rather than a
//! bare bool. "Portal unavailable" sends an operator hunting; "the portal is
//! running but exposes no ScreenCast interface — install the backend matching
//! your compositor" is a next step.
//!
//! ## Dependency note
//!
//! `zbus` is **pure Rust** — it speaks the D-Bus wire protocol itself and does
//! not link `libdbus`. That matters here: FR-45's central risk is that linking
//! `libpipewire` would put a system `.so` in `roomlerd`'s `DT_NEEDED` and stop
//! the daemon *starting* on headless hosts that will never run a portal. zbus
//! carries none of that hazard, which is why detection can land ahead of the
//! decision about how to reach PipeWire.

/// FR-45 P3c-ii — the sixth `ScreenCapture` backend.
pub mod backend;
/// FR-45 P4 — wire input events onto RemoteDesktop `Notify*` calls (helper side).
pub mod input;
/// FR-45 P4 — the arbiter→helper input seam (daemon side).
pub mod input_route;
/// FR-45 P5 — `org.gnome.Mutter.ScreenCast` direct, no portal. ⚠️ UNATTENDED.
pub mod mutter;
/// FR-93 P2d — one attended portal request per host, handed to the newest
/// session.
pub mod pending;
/// FR-45 P3a — reaching `libpipewire` through `dlopen`, never a link.
pub mod pipewire;
/// FR-45 P3b — SPA POD serialisation, so a format can be negotiated.
pub mod pod;
/// FR-45 P2b — the ScreenCast handshake itself, run inside the session.
pub mod screencast;
/// FR-45 P3c-ii — the frame wire format between helper and daemon.
pub mod wire;

use std::fmt;

/// The portal's well-known bus name and object path.
pub(crate) const PORTAL_BUS: &str = "org.freedesktop.portal.Desktop";
pub(crate) const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
pub(crate) const SCREENCAST_IFACE: &str = "org.freedesktop.portal.ScreenCast";
const REMOTE_DESKTOP_IFACE: &str = "org.freedesktop.portal.RemoteDesktop";

/// What we found, in enough detail to act on.
///
/// Serde is here for one reason: the helper child reports across a process
/// boundary (see `helper`), and a status that crosses it must arrive as the
/// same value it left as — including *why* it was unavailable, which is the
/// whole point of the enum.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PortalStatus {
    /// ScreenCast is present. `remote_desktop` says whether input is available
    /// too — FR-45 needs BOTH on a host with no evdev consumer, so a session
    /// that can see but not touch is worth naming separately.
    Available {
        remote_desktop: bool,
        version: Option<u32>,
    },
    /// The portal answered, but does not expose ScreenCast. This is the case
    /// FR-36 hit: the service runs, the compositor-matching backend is missing.
    NoScreenCast,
    /// Nothing is listening on the portal's bus name.
    PortalAbsent,
    /// There is no session bus to ask (headless daemon, no user session).
    NoSessionBus,
    /// We could not determine it. Carries the reason rather than swallowing it.
    Unknown(String),
}

impl PortalStatus {
    pub fn usable_for_capture(&self) -> bool {
        matches!(self, PortalStatus::Available { .. })
    }

    /// One line an operator can act on. The whole point of the enum.
    pub fn advice(&self) -> &'static str {
        match self {
            PortalStatus::Available {
                remote_desktop: true,
                ..
            } => "portal ScreenCast + RemoteDesktop available",
            PortalStatus::Available {
                remote_desktop: false,
                ..
            } => "portal ScreenCast available but NO RemoteDesktop — capture would be read-only",
            PortalStatus::NoScreenCast => {
                // ⚠️ A MISSING backend is only one cause, and on the one host
                // where this was actually diagnosed it was not the cause: the
                // backend was installed, but its (static, D-Bus-activated)
                // unit was dead — and starting it alone still did not help,
                // because the FRONTEND caches its backend selection at
                // startup and has to be restarted after the backend is up.
                // Advice that only said "install it" sent the reader to a
                // package that was already there.
                "xdg-desktop-portal is running but exposes no ScreenCast. Check the backend for \
                 your compositor is INSTALLED AND RUNNING (systemctl --user status \
                 xdg-desktop-portal-gnome / -kde / -wlr), then restart the frontend (systemctl \
                 --user restart xdg-desktop-portal) — it caches its backend selection at startup"
            }
            PortalStatus::PortalAbsent => {
                "no xdg-desktop-portal on the session bus — install xdg-desktop-portal plus a \
                 backend for your compositor"
            }
            PortalStatus::NoSessionBus => {
                "no D-Bus session bus reachable — the portal needs a logged-in user session \
                 (it is an ATTENDED path by design)"
            }
            PortalStatus::Unknown(_) => "portal availability could not be determined",
        }
    }
}

impl fmt::Display for PortalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortalStatus::Available {
                remote_desktop,
                version,
            } => write!(
                f,
                "available (screencast v{}, remote_desktop={remote_desktop})",
                version.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
            ),
            PortalStatus::NoScreenCast => write!(f, "no-screencast"),
            PortalStatus::PortalAbsent => write!(f, "portal-absent"),
            PortalStatus::NoSessionBus => write!(f, "no-session-bus"),
            PortalStatus::Unknown(why) => write!(f, "unknown ({why})"),
        }
    }
}

/// Ask the session bus what the portal actually exposes.
///
/// Introspects rather than trusting the bus name: a portal with no
/// compositor-matching backend owns the name and answers, while offering
/// neither interface we need.
///
/// ⚠️ Runs the D-Bus work on its own thread. `zbus`'s blocking API panics when
/// called from inside a tokio runtime (it would block the reactor it is
/// standing on), and this is reachable from both the async CLI path and the
/// synchronous `open_default` cascade. A thread makes it safe from either
/// without forcing every caller to be async.
pub fn detect() -> PortalStatus {
    std::thread::spawn(detect_blocking)
        .join()
        .unwrap_or_else(|_| PortalStatus::Unknown("detection thread panicked".into()))
}

/// FR-93 P2d-3 — [`detect`], bounded. The automatic portal arm asks this inside
/// a session's capture open, before it raises a dialog, so a wedged session bus
/// (or a portal that hangs while D-Bus starts it) costs a reason rather than
/// the open: [`detect`] alone waits out D-Bus's own 25 s method timeout.
pub fn detect_within(timeout: std::time::Duration) -> PortalStatus {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The receiver may already have timed out; nothing to do about that.
        let _ = tx.send(detect_blocking());
    });
    match rx.recv_timeout(timeout) {
        Ok(status) => status,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => PortalStatus::Unknown(format!(
            "{PORTAL_BUS} did not answer within {}s",
            timeout.as_secs()
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            PortalStatus::Unknown("detection thread panicked".into())
        }
    }
}

/// How long [`reachable`] waits: two calls to the bus daemon itself.
const REACHABLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// FR-93 P2d-3 — is a desktop portal on this process's session bus, running or
/// installed to start on demand? For the desktop brief, which asks every
/// minute. Unlike [`detect`] it never starts the portal: a name's owner and the
/// bus's activatable names are read from the bus daemon, which activates
/// nothing. So it cannot say whether ScreenCast is served. The brief is a plan,
/// not a promise, and the session's own open asks [`detect_within`].
pub fn reachable() -> Result<(), String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let answer = (|| {
            let conn = zbus::blocking::Connection::session()
                .map_err(|e| format!("no session bus: {e}"))?;
            let bus = zbus::blocking::fdo::DBusProxy::new(&conn)
                .map_err(|e| format!("the session bus: {e}"))?;
            let name = zbus::names::BusName::try_from(PORTAL_BUS)
                .map_err(|e| format!("{PORTAL_BUS}: {e}"))?;
            if bus.name_has_owner(name).unwrap_or(false) {
                return Ok(());
            }
            let activatable = bus
                .list_activatable_names()
                .map_err(|e| format!("the session bus's activatable names: {e}"))?;
            if activatable.iter().any(|n| n.as_str() == PORTAL_BUS) {
                Ok(())
            } else {
                Err(format!(
                    "no {PORTAL_BUS} on this session's bus, running or installed"
                ))
            }
        })();
        // The receiver may already have timed out; nothing to do about that.
        let _ = tx.send(answer);
    });
    match rx.recv_timeout(REACHABLE_TIMEOUT) {
        Ok(answer) => answer,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "the session bus did not answer within {}s",
            REACHABLE_TIMEOUT.as_secs()
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("the portal probe thread panicked".to_string())
        }
    }
}

fn detect_blocking() -> PortalStatus {
    let conn = match zbus::blocking::Connection::session() {
        Ok(c) => c,
        // No session bus at all — the ordinary case on a headless daemon, and
        // not an error worth shouting about. It IS the answer.
        Err(e) => {
            return if is_missing_bus(&e) {
                PortalStatus::NoSessionBus
            } else {
                PortalStatus::Unknown(format!("session bus: {e}"))
            };
        }
    };

    let proxy = match zbus::blocking::fdo::IntrospectableProxy::builder(&conn)
        .destination(PORTAL_BUS)
        .and_then(|b| b.path(PORTAL_PATH))
        .and_then(|b| b.build())
    {
        Ok(p) => p,
        Err(e) => return PortalStatus::Unknown(format!("portal proxy: {e}")),
    };

    let xml = match proxy.introspect() {
        Ok(x) => x,
        // Name not owned / no such service: the portal simply is not there.
        Err(_) => return PortalStatus::PortalAbsent,
    };

    if !xml.contains(SCREENCAST_IFACE) {
        return PortalStatus::NoScreenCast;
    }
    PortalStatus::Available {
        remote_desktop: xml.contains(REMOTE_DESKTOP_IFACE),
        version: screencast_version(&conn),
    }
}

/// The ScreenCast interface's `version` property, when it can be read.
/// Advisory only — absence must never turn an available portal into an
/// unavailable one, which is why this returns `Option` and is not in the
/// availability decision.
fn screencast_version(conn: &zbus::blocking::Connection) -> Option<u32> {
    let p = zbus::blocking::Proxy::new(conn, PORTAL_BUS, PORTAL_PATH, SCREENCAST_IFACE).ok()?;
    p.get_property::<u32>("version").ok()
}

/// Distinguish "there is no session bus" from "the bus rejected us". The first
/// is a normal state on a headless host; the second is a fault worth naming.
fn is_missing_bus(e: &zbus::Error) -> bool {
    let s = e.to_string();
    s.contains("DBUS_SESSION_BUS_ADDRESS")
        || s.contains("No such file or directory")
        || s.contains("Failed to connect")
}

/// Ask the portal *from wherever it can actually be reached* — this process if
/// it has a session bus, otherwise a helper child inside the console user's
/// session.
///
/// ## Why a child at all
///
/// FR-45 P1 measured the thing that shapes this whole phase: `roomlerd` runs
/// as **root**, and the portal is **per-user-session**. Detection from the
/// daemon returns `NoSessionBus` on a host with a perfectly good GNOME Wayland
/// session running three feet away. No amount of care in the D-Bus code fixes
/// that — the daemon is simply not in the session. Something has to run
/// *inside* it.
///
/// ## Why a subcommand and not a separate binary
///
/// The near-miss worth recording: a helper **subcommand does not by itself**
/// solve FR-45's dependency problem. `roomlerd portal-helper` is the same ELF
/// as `roomlerd`, so linking `libpipewire` for the helper would put it in the
/// daemon's `DT_NEEDED` and stop the daemon *starting* on every headless host
/// that will never run a portal. The subcommand buys the session context; the
/// `dlopen` that P3 will use buys the linkage. Both are needed, and it is easy
/// to believe the first has bought the second.
///
/// P2a is only the first half: the helper exists, runs in the session, and
/// reports. Nothing is linked or dlopened yet.
pub fn detect_in_session() -> PortalStatus {
    // Cheapest first, and it is not merely an optimisation: an attended daemon
    // running as the logged-in user IS in the session already, and spawning a
    // child to ask a question we can answer here would be pure cost.
    let direct = detect();
    if !matches!(direct, PortalStatus::NoSessionBus) {
        return direct;
    }
    // We ARE the helper and still found no bus. Report it rather than
    // spawning ourselves again — belt-and-braces against a recursion that
    // would fork-bomb a host.
    if std::env::var_os(helper::CHILD_ENV).is_some() {
        return direct;
    }
    helper::probe()
}

/// The session-resident half: spawn ourselves as the console user, ask there,
/// read the answer back.
pub mod helper {
    use super::PortalStatus;

    /// Marks the line carrying the child's JSON. Scanned for by prefix, never
    /// taken as "the last line" — the child's own logging shares this stream
    /// and would be mistaken for the result the first time it said anything.
    const MARKER: &str = "ROOMLER_PORTAL_JSON:";

    /// What we ask the compositor for as an upper bound. It is a *range* max,
    /// not a demand — the source picks its own rate within it, and asking for
    /// a single fixed rate is how a negotiation fails on a display that runs
    /// at something else.
    const DEFAULT_MAX_FPS: u32 = 60;

    /// How many frames the helper pulls before reporting. A handful proves
    /// delivery works; this is a proof, not a capture session.
    const WANT_FRAMES: u32 = 3;

    /// P2b's marker. A **separate** marker rather than a variant inside one
    /// payload, so a parent asking for detection can never be handed a session
    /// report (or the reverse) by a helper built from a different revision.
    const SESSION_MARKER: &str = "ROOMLER_PORTAL_SESSION:";

    /// Set in the child's environment; `detect_in_session` refuses to spawn
    /// when it sees it.
    pub(super) const CHILD_ENV: &str = "ROOMLERD_PORTAL_CHILD";

    /// Generous for a handful of D-Bus round-trips, and deliberately larger
    /// than nothing: a wedged session bus blocks `Introspect` for D-Bus's own
    /// 25 s method timeout, and a capture cascade must not stall behind it.
    /// This is a backstop against a hung bus, not a performance budget.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    /// The `portal-helper` child's entire job: do one thing inside the
    /// session, print one marked line.
    ///
    /// The human-readable line goes to **stderr**, which the parent inherits,
    /// so the daemon's log carries the child's own account of what it saw next
    /// to the parent's verdict. Same reasoning as the caps probe.
    pub fn run(screencast: bool, stream: bool, input: bool, mutter: bool, window: bool) {
        if stream {
            run_stream(input, mutter, window);
            return;
        }
        if screencast {
            run_screencast();
            return;
        }
        let st = super::detect();
        eprintln!("portal-helper: {st} — {}", st.advice());
        match serde_json::to_string(&st) {
            Ok(json) => println!("{MARKER}{json}"),
            // Unreachable in practice; still not silent. A child that cannot
            // report is worse than one that reports a failure.
            Err(e) => println!(
                "{MARKER}{}",
                serde_json::to_string(&PortalStatus::Unknown(format!("encoding status: {e}")))
                    .unwrap_or_else(|_| r#"{"Unknown":"encoding status"}"#.to_string())
            ),
        }
    }

    /// P2b — open a ScreenCast session and report it.
    ///
    /// 🔑 **The restore token never appears here.** It is a standing grant the
    /// person at the screen gave to *their* session, and `screencast::open`
    /// both loads and stores it internally, in their own state directory at
    /// 0600. A caller that cannot hold the credential cannot leak it — which
    /// is a stronger guarantee than a caller that holds it and is careful, and
    /// it is what makes "the daemon never sees the token" structurally true
    /// rather than merely intended.
    /// What the child announces before it starts writing pixels.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct StreamStarted {
        pub width: u32,
        pub height: u32,
        pub video_format: u32,
        /// P4 — whether this helper consumes `InputMsg` JSON lines on stdin.
        /// `serde(default)` so a handshake from an older helper reads as
        /// "no input", never as a parse failure.
        #[serde(default)]
        pub input_ok: bool,
        /// FR-85 P1d — whether the compositor draws the pointer into the
        /// frames (the cursor mode it granted was EMBEDDED). A recording
        /// says so in its sidecar; `false` from an older helper reads as
        /// "no pointer", the honest default.
        #[serde(default)]
        pub cursor_embedded: bool,
    }

    /// Marks the streaming handshake line. A THIRD marker, distinct from the
    /// other two, so a parent expecting a stream can never be handed a
    /// detection result by a helper built from another revision.
    const STREAM_MARKER: &str = "ROOMLER_PORTAL_STREAM:";

    /// FR-93 P2d-4 — marks the line a streaming helper writes when it fails
    /// before its stream starts: why, as a JSON string, in the words the
    /// viewer is shown. Before it, the helper only logged the reason and
    /// exited, and the parent could say no more than "the portal helper exited
    /// before announcing a stream". Measured on the FR-93 lab's KDE guest on
    /// 0.4.135, where the person at the screen had declined both dialogs.
    /// [`STREAM_MARKER`] is not a prefix of it (`:` against `_`), so neither is
    /// ever read as the other. A parent from before it skips the line as noise.
    const STREAM_FAILED_MARKER: &str = "ROOMLER_PORTAL_STREAM_FAILED:";

    /// Child side: say why on stdout for the parent, log it, and exit `1`.
    fn fail_stream(why: impl std::fmt::Display) -> ! {
        let why = why.to_string();
        eprintln!("portal-helper: {why}");
        if let Ok(j) = serde_json::to_string(&why) {
            println!("{STREAM_FAILED_MARKER}{j}");
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
        std::process::exit(1);
    }

    /// FR-93 P5b — the streaming helper's exit status when the compositor
    /// closed its session (GNOME, at a screen lock). Distinct from `1`, a
    /// failure, so the journal tells the two apart; the parent reopens either.
    const EXIT_SESSION_CLOSED: i32 = 3;

    /// FR-93 P5c — the exit status when the compositor ended the stream but
    /// not the session: mutter ends a monitor's recording when that monitor's
    /// configuration changes (a resolution change, a hotplug), and (P5d) a
    /// compositor that restarts (KWin, after a crash) takes every stream with
    /// it. The parent reopens, which records the monitor anew.
    const EXIT_STREAM_ENDED: i32 = 4;

    /// FR-93 P6c — the exit status when the person at the screen stopped the
    /// share with the desktop's own control: Stop on GNOME's screen-sharing
    /// indicator, End on KDE's. The parent does NOT reopen: it ends the
    /// remote-control session as the person's Disconnect does. Reopening is
    /// what made the control a no-op (measured on 0.4.135: GNOME's Stop undone
    /// 0.5 s later by a new unattended screencast).
    pub(crate) const EXIT_STOPPED_AT_SCREEN: i32 = 5;

    /// FR-93 P6c — who closed the session a streaming helper records, as far
    /// as the helper can tell once it is closed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ClosedBy {
        /// The screen locked (GNOME closes every screen cast at its lock). The
        /// parent reopens, and the reopen waits for the unlock (P5b).
        Lock,
        /// The person at the screen, with the desktop's own control.
        Person,
        /// The compositor restarted (KWin after a crash, P5d): the parent
        /// reopens, which restores the session from its token.
        Restart,
        /// Nothing could tell. The parent reopens, the rule before P6c, so a
        /// doubt never ends anyone's session.
        Unknown,
    }

    impl ClosedBy {
        fn exit_code(self) -> i32 {
            match self {
                ClosedBy::Person => EXIT_STOPPED_AT_SCREEN,
                ClosedBy::Restart => EXIT_STREAM_ENDED,
                ClosedBy::Lock | ClosedBy::Unknown => EXIT_SESSION_CLOSED,
            }
        }

        fn reads(self) -> &'static str {
            match self {
                ClosedBy::Lock => "the screen is locked",
                ClosedBy::Person => {
                    "the person at the screen stopped the share with the desktop's own control"
                }
                ClosedBy::Restart => "its compositor restarted",
                ClosedBy::Unknown => "nothing could tell why",
            }
        }
    }

    /// FR-93 P6c — mutter closed its own session. Only its refusal of a new
    /// one tells GNOME's lock from the person's Stop
    /// ([`super::mutter::creation_inhibited`]), and a probe that could not ask
    /// is a doubt.
    fn closed_mutter(inhibited: Option<bool>) -> ClosedBy {
        match inhibited {
            Some(true) => ClosedBy::Lock,
            Some(false) => ClosedBy::Person,
            None => ClosedBy::Unknown,
        }
    }

    /// FR-93 P6c — the desktop portal closed its session. Where mutter answers
    /// (GNOME's portal) its probe decides, as on mutter's own arm. Elsewhere
    /// (KDE): a compositor that restarted, else the lock as the desktop says
    /// it; only a screen positively read as unlocked is the person.
    ///
    /// ⚠️ KDE's portal also closes a session whose last stream the compositor
    /// ended, such as a monitor unplugged while shared, and that reads as the
    /// person here. Nothing on the bus tells the two apart.
    fn closed_portal(
        mutter_inhibited: Option<bool>,
        compositor_restarted: bool,
        locked: Option<bool>,
    ) -> ClosedBy {
        if mutter_inhibited.is_some() {
            return closed_mutter(mutter_inhibited);
        }
        if compositor_restarted {
            return ClosedBy::Restart;
        }
        match locked {
            Some(true) => ClosedBy::Lock,
            Some(false) => ClosedBy::Person,
            None => ClosedBy::Unknown,
        }
    }

    /// Say who closed the session, and end the helper with the status that
    /// tells the parent what to do.
    fn end_closed(arm: &str, by: ClosedBy) -> ! {
        eprintln!(
            "portal-helper: {arm} closed the session: {}; ending the capture",
            by.reads()
        );
        std::process::exit(by.exit_code());
    }

    /// FR-93 P6c — KWin's well-known name, whose owner changes when KWin
    /// restarts: its wrapper restarts it after a crash (P5d).
    const KWIN_BUS: &str = "org.kde.KWin";

    /// How long a closed portal session waits before asking who closed it, so
    /// a compositor that crashed has left the bus by then.
    const CLOSED_SETTLE: std::time::Duration = std::time::Duration::from_millis(500);

    /// The unique name that owns `name` on the session bus, or `None`.
    fn name_owner(conn: &zbus::blocking::Connection, name: &str) -> Option<String> {
        let reply = conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "GetNameOwner",
                &(name,),
            )
            .ok()?;
        reply.body().deserialize::<String>().ok()
    }

    /// FR-93 P6c — whether the screen is locked, as KDE (and every desktop
    /// that follows its API) says over `org.freedesktop.ScreenSaver`. `None`
    /// where nothing answers.
    fn screensaver_active(conn: &zbus::blocking::Connection) -> Option<bool> {
        ["/org/freedesktop/ScreenSaver", "/ScreenSaver"]
            .into_iter()
            .find_map(|path| {
                let reply = conn
                    .call_method(
                        Some("org.freedesktop.ScreenSaver"),
                        path,
                        Some("org.freedesktop.ScreenSaver"),
                        "GetActive",
                        &(),
                    )
                    .ok()?;
                reply.body().deserialize::<bool>().ok()
            })
    }

    /// The helper's frame loop, both arms: frames to `out` (stdout) until the
    /// parent closes the pipe (the normal end, quietly) or, FR-93 P5c/P5d, the
    /// stream's source is gone. Frames alone cannot tell that apart from an
    /// idle desktop, which sends none either but stays STREAMING, so the
    /// stream's state is read between frames; once it has been outside
    /// STREAMING for [`SOURCE_GONE_AFTER`], `gone` is said and the capture ends
    /// with [`EXIT_STREAM_ENDED`].
    ///
    /// FR-93 P5e — the frame that settled the format goes out first: on a
    /// still desktop it is the only picture the compositor sends until
    /// something on screen changes.
    fn write_frames(
        handle: &mut super::pipewire::StreamHandle,
        out: &mut impl std::io::Write,
        gone: &str,
    ) {
        let mut next = handle.first.take();
        let mut not_streaming_since = None;
        loop {
            let frame = match next.take() {
                Some(first) => Ok(first),
                None => handle
                    .frames
                    .recv_timeout(std::time::Duration::from_millis(500)),
            };
            match frame {
                Ok((h, bytes)) => {
                    // A write failure means the parent closed the pipe — the
                    // normal way this process ends. Return quietly rather
                    // than logging a shutdown as an error.
                    if out.write_all(&h.encode()).is_err() || out.write_all(&bytes).is_err() {
                        return;
                    }
                    if out.flush().is_err() {
                        return;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
            let state = handle.state.load(std::sync::atomic::Ordering::Relaxed);
            if source_gone(state, &mut not_streaming_since, std::time::Instant::now()) {
                eprintln!("{gone}");
                std::process::exit(EXIT_STREAM_ENDED);
            }
        }
    }

    /// FR-93 P5c — how long a stream may sit outside `STREAMING` before its
    /// source counts as gone. A renegotiation pauses it for milliseconds; a
    /// source that vanished leaves it paused for good.
    const SOURCE_GONE_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

    /// FR-93 P5c — whether a stream's source is gone: it has been outside
    /// `STREAMING` for [`SOURCE_GONE_AFTER`], counted from `since`, which this
    /// keeps (cleared by any return to `STREAMING`).
    fn source_gone(
        state: i32,
        since: &mut Option<std::time::Instant>,
        now: std::time::Instant,
    ) -> bool {
        if state == super::pipewire::PW_STREAM_STATE_STREAMING {
            *since = None;
            return false;
        }
        let at = *since.get_or_insert(now);
        now.saturating_duration_since(at) >= SOURCE_GONE_AFTER
    }

    #[cfg(test)]
    mod source_gone_tests {
        use super::{SOURCE_GONE_AFTER, source_gone};
        use crate::capture::portal::pipewire::PW_STREAM_STATE_STREAMING;
        use std::time::{Duration, Instant};

        const PAUSED: i32 = 2;

        /// P5c — a pause as short as a renegotiation is not an end; one that
        /// lasts SOURCE_GONE_AFTER is, and streaming again starts the count over.
        #[test]
        fn only_a_lasting_pause_ends_the_stream() {
            let t0 = Instant::now();
            let mut since = None;
            assert!(!source_gone(PW_STREAM_STATE_STREAMING, &mut since, t0));
            assert!(!source_gone(PAUSED, &mut since, t0));
            assert!(!source_gone(
                PAUSED,
                &mut since,
                t0 + Duration::from_millis(1900)
            ));
            assert!(!source_gone(
                PW_STREAM_STATE_STREAMING,
                &mut since,
                t0 + Duration::from_secs(2)
            ));
            assert!(since.is_none(), "streaming again starts the count over");
            let t1 = t0 + Duration::from_secs(3);
            assert!(!source_gone(PAUSED, &mut since, t1));
            assert!(source_gone(PAUSED, &mut since, t1 + SOURCE_GONE_AFTER));
            assert!(
                source_gone(0, &mut since, t1 + SOURCE_GONE_AFTER),
                "unconnected too"
            );
        }

        /// P5e — the frame that settled the format is written before any
        /// other: on a still desktop it is the only picture there is.
        #[test]
        fn the_first_frame_goes_out_first() {
            use crate::capture::portal::pipewire::{NegotiatedFormat, StreamHandle};
            use crate::capture::portal::wire::FrameHeader;
            use std::sync::Arc;
            use std::sync::atomic::AtomicI32;
            let header = |w: u32| FrameHeader {
                width: w,
                height: 1,
                stride: 4,
                video_format: 8,
                len: 4,
            };
            let (tx, frames) = std::sync::mpsc::sync_channel(2);
            tx.send((header(2), vec![2u8; 4])).unwrap();
            // The loop ends where the stream does: the sender goes away.
            drop(tx);
            let mut handle = StreamHandle {
                format: NegotiatedFormat {
                    video_format: 8,
                    width: 1,
                    height: 1,
                    fps_num: 0,
                    fps_denom: 1,
                },
                frames,
                state: Arc::new(AtomicI32::new(PW_STREAM_STATE_STREAMING)),
                first: Some((header(1), vec![1u8; 4])),
            };
            let mut out = Vec::new();
            super::write_frames(&mut handle, &mut out, "gone");
            let mut want = header(1).encode().to_vec();
            want.extend([1u8; 4]);
            want.extend(header(2).encode());
            want.extend([2u8; 4]);
            assert_eq!(out, want, "the first frame, then the stream's");
            assert!(handle.first.is_none(), "written once");
        }
    }

    #[cfg(test)]
    mod closed_tests {
        use super::{
            ClosedBy, EXIT_SESSION_CLOSED, EXIT_STOPPED_AT_SCREEN, EXIT_STREAM_ENDED,
            closed_mutter, closed_portal,
        };

        /// FR-93 P6c — mutter's refusal of a new session is the lock; a new
        /// session allowed is the person's Stop; a probe that could not ask
        /// is a doubt, which reopens as before P6c.
        #[test]
        fn mutter_tells_the_lock_from_the_person_by_its_refusal() {
            assert_eq!(closed_mutter(Some(true)), ClosedBy::Lock);
            assert_eq!(closed_mutter(Some(false)), ClosedBy::Person);
            assert_eq!(closed_mutter(None), ClosedBy::Unknown);
        }

        /// P6c — the portal's close: mutter's probe first wherever it answers
        /// (GNOME's portal), whatever the other readings say; then a
        /// restarted compositor; then only an unlocked screen, positively
        /// read, is the person.
        #[test]
        fn the_portal_ends_the_session_only_on_an_unlocked_screen() {
            assert_eq!(closed_portal(Some(true), true, Some(false)), ClosedBy::Lock);
            assert_eq!(closed_portal(Some(false), false, None), ClosedBy::Person);
            assert_eq!(closed_portal(None, true, Some(false)), ClosedBy::Restart);
            assert_eq!(closed_portal(None, false, Some(true)), ClosedBy::Lock);
            assert_eq!(closed_portal(None, false, Some(false)), ClosedBy::Person);
            assert_eq!(closed_portal(None, false, None), ClosedBy::Unknown);
        }

        /// P6c — only the person's close stops the reopen. The parent reads
        /// these numbers, so each verdict keeps the status it had before.
        #[test]
        fn only_the_person_exits_with_the_status_that_ends_the_session() {
            assert_eq!(ClosedBy::Person.exit_code(), EXIT_STOPPED_AT_SCREEN);
            assert_eq!(ClosedBy::Restart.exit_code(), EXIT_STREAM_ENDED);
            assert_eq!(ClosedBy::Lock.exit_code(), EXIT_SESSION_CLOSED);
            assert_eq!(ClosedBy::Unknown.exit_code(), EXIT_SESSION_CLOSED);
            let all = [
                EXIT_SESSION_CLOSED,
                EXIT_STREAM_ENDED,
                EXIT_STOPPED_AT_SCREEN,
            ];
            assert!(
                !all.contains(&0) && !all.contains(&1),
                "neither the normal end nor a failure"
            );
            assert_eq!(
                all.iter().collect::<std::collections::HashSet<_>>().len(),
                3
            );
        }
    }

    /// P3c-ii, child side — open a session, then write frames on stdout until
    /// the parent goes away.
    ///
    /// ⚠️ **stdout is binary after the handshake line.** Everything
    /// diagnostic goes to stderr, which the parent inherits: a stray
    /// `println!` here does not add a log line, it corrupts a frame.
    fn run_stream(with_input: bool, use_mutter: bool, window: bool) {
        use super::screencast::{SessionKind, SourceKind};
        // FR-56 P4 — one application window instead of the whole screen.
        // ⚠️ The portal picks it, not us: `SelectSources(types=WINDOW)`
        // shows the person at the screen a window picker. There is no
        // API to name a window — GNOME refuses `Introspect.GetWindows`
        // outright (measured, Shell 48.8) — so this is attended by
        // construction and useless on a host with nobody at it.
        let source = if window {
            SourceKind::Window
        } else {
            SourceKind::Monitor
        };
        // FR-45 P5 — mutter's own ScreenCast API, no portal and NO CONSENT
        // DIALOG. Deliberately a separate branch rather than a fallback inside
        // the portal path: the two have different consent properties, and a
        // silent fallback from "asks" to "does not ask" is precisely the kind
        // of thing that must never happen by accident.
        if use_mutter {
            run_stream_mutter(with_input);
            return;
        }
        // The session shape is decided by what the portal OFFERS, not by
        // failing and retrying: a wlr backend has ScreenCast and no
        // RemoteDesktop (measured — the WSL2 field runs), and asking it for
        // input would fail the whole session where capture alone works.
        let kind = if with_input {
            match super::detect() {
                PortalStatus::Available {
                    remote_desktop: true,
                    ..
                } => SessionKind::WithInput,
                st => {
                    eprintln!(
                        "portal-helper: input requested but not available ({st}) — capture only"
                    );
                    SessionKind::CaptureOnly
                }
            }
        } else {
            SessionKind::CaptureOnly
        };
        eprintln!(
            "portal-helper: recording {}",
            match source {
                SourceKind::Window => "ONE WINDOW (the portal will show a picker)",
                SourceKind::Monitor => "a monitor",
            }
        );
        eprintln!(
            "portal-helper: opening a {} session for streaming",
            match kind {
                SessionKind::WithInput => "RemoteDesktop (capture + input)",
                SessionKind::CaptureOnly => "ScreenCast (capture only)",
            }
        );
        // ⚠️ An input session that fails — a declined dialog, a timeout, a
        // compositor that offered RemoteDesktop but would not grant it — must
        // NOT cost CAPTURE. Retry capture-only rather than exiting, so a host
        // where capture-only works is never left with no capture just because
        // the input half was refused. (The kill switch already defaults input
        // OFF; this is the belt to that braces.)
        let mut session = match super::screencast::open(kind, source) {
            Ok(s) => s,
            Err(e) if kind == SessionKind::WithInput => {
                eprintln!("portal-helper: the input session failed ({e}) — retrying capture-only");
                match super::screencast::open(SessionKind::CaptureOnly, source) {
                    Ok(s) => s,
                    Err(e2) => fail_stream(e2),
                }
            }
            Err(e) => fail_stream(e),
        };
        // `take`, not destructure: the session must stay WHOLE — its D-Bus
        // connection keeps the portal session (and so the PipeWire node and
        // the input grant) alive, and the input context still needs it.
        let Some(fd) = session.pipewire_fd.take() else {
            fail_stream("the portal gave no PipeWire fd");
        };
        let Some(first) = session.report.streams.first() else {
            fail_stream("the portal gave no stream to attach to");
        };
        let node_id = first.node_id;
        let advertised = (first.width, first.height);

        let mut handle = match super::pipewire::stream(
            super::pipewire::PwSource::Fd(fd),
            node_id,
            DEFAULT_MAX_FPS,
        ) {
            Ok(h) => h,
            Err(e) => fail_stream(e),
        };
        eprintln!(
            "portal-helper: streaming {}x{} (spa format {})",
            handle.format.width, handle.format.height, handle.format.video_format
        );

        // P4 — the input pump, spawned before the frame loop takes this
        // thread. The portal's advertised stream size is the LOGICAL space
        // absolute motion is addressed in; the negotiated PIXEL size is only
        // a fallback for a portal that advertised none (correct wherever the
        // scale factor is 1, and the best available answer elsewhere).
        let mut input_ok = false;
        if let Some(sess_path) = session.input_session.clone() {
            let logical = match advertised {
                (Some(w), Some(h)) if w > 0 && h > 0 => (f64::from(w), f64::from(h)),
                _ => (
                    f64::from(handle.format.width),
                    f64::from(handle.format.height),
                ),
            };
            // ⚠️⚠️ The `InputContext` (a `zbus::blocking::Proxy`) MUST be built
            // OFF the tokio runtime thread. `run_stream` runs synchronously
            // inside the `#[tokio::main]` daemon, and zbus's blocking API does
            // a fresh `Runtime::block_on` internally — which panics "Cannot
            // start a runtime from within a runtime" on a runtime thread. This
            // is the exact hazard `screencast::open` documents and guards with
            // its own thread; the first cut of P4 rebuilt the proxy here on the
            // tokio thread and would have panicked the instant input was
            // granted (masked in the field run because consent blocked first).
            // Build it on a joined thread so `input_ok` stays honest, then run
            // the pump — also off-runtime — on its own thread.
            let conn = session.connection().clone();
            let built = std::thread::spawn(move || {
                super::input::InputContext::new(&conn, sess_path, node_id, logical)
            })
            .join();
            match built {
                Ok(Ok(ctx)) => {
                    std::thread::spawn(move || super::input::run_pump(ctx, std::io::stdin()));
                    input_ok = true;
                    eprintln!(
                        "portal-helper: input pump ready (logical {}x{})",
                        logical.0, logical.1
                    );
                }
                Ok(Err(e)) => {
                    eprintln!("portal-helper: input context failed: {e} — capture only");
                }
                Err(_) => {
                    eprintln!("portal-helper: input context thread panicked — capture only");
                }
            }
        }

        let started = StreamStarted {
            width: handle.format.width,
            height: handle.format.height,
            video_format: handle.format.video_format,
            input_ok,
            cursor_embedded: session.report.cursor_embedded(),
        };
        match serde_json::to_string(&started) {
            Ok(j) => println!("{STREAM_MARKER}{j}"),
            Err(e) => {
                eprintln!("portal-helper: could not encode the handshake: {e}");
                std::process::exit(1);
            }
        }
        use std::io::Write;
        if std::io::stdout().flush().is_err() {
            std::process::exit(1);
        }

        // FR-93 P6c — the portal closes the session when the person at the
        // screen ends the share with the desktop's own control (KDE's End),
        // and the stream then ends with it: before this the reopen restored
        // the session from its token 3 s later, undoing the End. Whose close
        // it was is asked once it happened; KWin's bus owner, read now, is
        // what tells a crashed compositor apart (P5d's reopen). Read OFF this
        // thread, which is the runtime's: zbus's blocking API panics on it
        // (the input context's rule above).
        let kwin = {
            let conn = session.connection().clone();
            std::thread::spawn(move || name_owner(&conn, KWIN_BUS))
                .join()
                .ok()
                .flatten()
        };
        session.on_closed(move || {
            std::thread::sleep(CLOSED_SETTLE);
            let conn = zbus::blocking::Connection::session().ok();
            let restarted =
                kwin.is_some() && conn.as_ref().and_then(|c| name_owner(c, KWIN_BUS)) != kwin;
            end_closed(
                "the desktop portal",
                closed_portal(
                    super::mutter::creation_inhibited(),
                    restarted,
                    conn.as_ref().and_then(screensaver_active),
                ),
            )
        });

        // From here on stdout carries nothing but frames. FR-93 P5d — a
        // compositor that restarts (KWin, after a crash) takes the portal's
        // stream with it and leaves ours paused, with no error: measured on
        // Plasma 6.7, the viewer kept the last frame for good.
        write_frames(
            &mut handle,
            &mut std::io::stdout().lock(),
            "portal-helper: the portal's stream ended (its compositor restarted, or ended the \
             screen cast); ending the capture",
        );
    }

    /// FR-45 P5, child side — the same streaming loop, but the node id comes
    /// from `org.gnome.Mutter.ScreenCast` instead of the portal; with
    /// `with_input`, driven by mutter's RemoteDesktop, which takes the viewer's
    /// input on stdin (FR-93 P4).
    ///
    /// ⚠️⚠️ **No consent dialog is shown on this path.** See
    /// [`super::mutter`] for why that is acceptable and why it is NOT a portal
    /// variant. It exists for hosts where no portal backend can run at all —
    /// measured on WSL2, where `xdg-desktop-portal-gnome` exits immediately
    /// without a GNOME session while mutter itself works fine.
    fn run_stream_mutter(with_input: bool) {
        eprintln!(
            "portal-helper: opening an org.gnome.Mutter.ScreenCast session (UNATTENDED){}",
            if with_input {
                ", driven by its RemoteDesktop for input"
            } else {
                ""
            }
        );
        // ⚠️ Input must never cost capture, the portal path's rule: a mutter
        // whose RemoteDesktop refuses (a build without it, a session it will not
        // create) still records, view-only. "Not GNOME" is not retried.
        let session = match super::mutter::open(with_input) {
            Ok(s) => s,
            Err(super::mutter::MutterError::Unavailable) => {
                fail_stream(super::mutter::MutterError::Unavailable)
            }
            Err(e) if with_input => {
                eprintln!(
                    "portal-helper: mutter's RemoteDesktop session failed ({e}) — retrying \
                     capture-only"
                );
                match super::mutter::open(false) {
                    Ok(s) => s,
                    Err(e2) => fail_stream(e2),
                }
            }
            Err(e) => fail_stream(e),
        };
        eprintln!(
            "portal-helper: mutter node {} on {} (ScreenCast v{:?}, {} ms, input {})",
            session.report.node_id,
            session.report.connector,
            session.report.version,
            session.report.elapsed_ms,
            if session.report.input {
                "via RemoteDesktop"
            } else {
                "none"
            }
        );

        // 🔑 `PwSource::Session`, not a portal fd: mutter hands out a node id
        // and expects us to reach the session's own PipeWire — which is right,
        // because this helper already runs AS the session user.
        let mut handle = match super::pipewire::stream(
            super::pipewire::PwSource::Session,
            session.report.node_id,
            DEFAULT_MAX_FPS,
        ) {
            Ok(h) => h,
            Err(e) => fail_stream(e),
        };
        eprintln!(
            "portal-helper: streaming {}x{} (spa format {})",
            handle.format.width, handle.format.height, handle.format.video_format
        );

        // FR-93 P4 — the input pump, as the portal path builds it: the context
        // OFF the runtime thread (zbus's blocking API panics on one), on the
        // session's own connection (mutter takes `Notify*` only from it). A
        // mutter stream's coordinates are the stream's own size; mutter divides
        // by the monitor's scale itself.
        let mut input_ok = false;
        if let Some(rd) = session.input.clone() {
            let space = (
                f64::from(handle.format.width),
                f64::from(handle.format.height),
            );
            let conn = session.connection().clone();
            let built = std::thread::spawn(move || {
                super::input::InputContext::new_mutter(&conn, &rd, space)
            })
            .join();
            match built {
                Ok(Ok(ctx)) => {
                    std::thread::spawn(move || super::input::run_pump(ctx, std::io::stdin()));
                    input_ok = true;
                    eprintln!(
                        "portal-helper: mutter input pump ready ({}x{})",
                        space.0, space.1
                    );
                }
                Ok(Err(e)) => {
                    eprintln!("portal-helper: mutter input context failed: {e} — capture only");
                }
                Err(_) => {
                    eprintln!("portal-helper: mutter input context thread panicked — capture only");
                }
            }
        }

        let started = StreamStarted {
            width: handle.format.width,
            height: handle.format.height,
            video_format: handle.format.video_format,
            input_ok,
            // `mutter::open` always asks for `cursor-mode` 1, embedded.
            cursor_embedded: true,
        };
        match serde_json::to_string(&started) {
            Ok(j) => println!("{STREAM_MARKER}{j}"),
            Err(e) => {
                eprintln!("portal-helper: could not encode the handshake: {e}");
                std::process::exit(1);
            }
        }
        use std::io::Write;
        if std::io::stdout().flush().is_err() {
            std::process::exit(1);
        }

        // FR-93 P5b (#2145) — GNOME closes every remote desktop and screen cast
        // when its screen locks, and the stream then goes idle, not to an
        // error: the loop below would wait for frames forever and the viewer
        // keep the last one. End the capture instead. The daemon's pump reopens
        // it, and the reopen waits for the unlock with the controller told why
        // (`capture::open_through_wait`).
        //
        // FR-93 P6c — Stop on GNOME's screen-sharing indicator closes it too,
        // and the reopen undid it 0.5 s later. mutter's refusal of a new
        // session tells the lock from the person, whose Stop ends the
        // remote-control session instead (`EXIT_STOPPED_AT_SCREEN`).
        session.on_closed(|| {
            let inhibited = super::mutter::creation_inhibited();
            end_closed("mutter", closed_mutter(inhibited))
        });

        // ⚠️ `session` must stay alive for the whole loop — mutter tears the
        // session down with the D-Bus connection inside it, taking the node.
        // FR-93 P5c — mutter ends a monitor's recording when that monitor's
        // configuration changes, and leaves both sessions open: no `Closed`,
        // no error, the stream paused for good. The reopen records the
        // monitor at its new size.
        write_frames(
            &mut handle,
            &mut std::io::stdout().lock(),
            "portal-helper: mutter ended the stream (it ends a monitor's recording when the \
             monitor's configuration changes); ending the capture",
        );
        drop(session);
    }

    /// Parent side — spawn the helper for streaming and hand back the child.
    ///
    /// Unlike [`spawn_in_session`], this does NOT wait: the child lives as
    /// long as the capture does.
    pub fn spawn_streaming(
        _target_fps: u32,
        with_input: bool,
        use_mutter: bool,
        window: bool,
    ) -> anyhow::Result<std::process::Child> {
        let mut args: Vec<&str> = vec!["--stream"];
        if use_mutter {
            args.push("--mutter");
        }
        // FR-93 P4 — `--input` with `--mutter` means mutter's RemoteDesktop,
        // which drives the screencast it records.
        if with_input {
            args.push("--input");
        }
        if window {
            args.push("--window");
        }
        // stdin is the input wire, piped exactly when input is wanted — a
        // helper that will never read it should see EOF, not a pipe nothing
        // writes to.
        spawn_child(&args, with_input).map_err(|e| match e {
            SpawnError::NoSession => {
                anyhow::anyhow!("nobody is at this machine's screen — the portal is attended-only")
            }
            SpawnError::Other(why) => anyhow::anyhow!(why),
        })
    }

    /// Read the streaming handshake line, skipping anything the child wrote
    /// before it.
    pub fn read_stream_handshake(r: &mut impl std::io::BufRead) -> anyhow::Result<StreamStarted> {
        let mut line = String::new();
        for _ in 0..64 {
            line.clear();
            if r.read_line(&mut line)? == 0 {
                anyhow::bail!("the portal helper exited before announcing a stream");
            }
            if let Some(json) = line.trim().strip_prefix(STREAM_MARKER) {
                return Ok(serde_json::from_str(json)?);
            }
            // FR-93 P2d-4 — the helper's own reason, e.g. that the person at
            // the screen declined.
            if let Some(json) = line.trim().strip_prefix(STREAM_FAILED_MARKER) {
                let why: String = serde_json::from_str(json).unwrap_or_else(|_| json.to_string());
                anyhow::bail!("{why}");
            }
        }
        anyhow::bail!("the portal helper never announced a stream")
    }

    fn run_screencast() {
        eprintln!("portal-helper: opening a ScreenCast session");
        let outcome = super::screencast::open(
            super::screencast::SessionKind::CaptureOnly,
            super::screencast::SourceKind::Monitor,
        )
        .map(|session| {
            let mut report = session.report;
            // P3b-ii — the fd goes to PipeWire, a stream is connected to the
            // node the portal named, and the compositor's chosen format is
            // reported. ⚠️ Still no frames: buffer delivery is P3c.
            report.pipewire = match (session.pipewire_fd, report.streams.first()) {
                (Some(fd), Some(s)) => super::pipewire::negotiate_status(
                    super::pipewire::PwSource::Fd(fd),
                    s.node_id,
                    DEFAULT_MAX_FPS,
                    WANT_FRAMES,
                ),
                // A session with no stream cannot be negotiated against, and
                // saying "not attempted" is the truth rather than a failure.
                _ => super::pipewire::PipeWireStatus::NotAttempted,
            };
            report
        });
        match &outcome {
            Ok(r) => eprintln!(
                "portal-helper: {} stream(s), node_id={:?}, fd_ok={}, {} ms; pipewire: {}",
                r.streams.len(),
                r.streams.first().map(|s| s.node_id),
                r.pipewire_fd_ok,
                r.elapsed_ms,
                r.pipewire
            ),
            Err(e) => eprintln!("portal-helper: {e}"),
        }
        let wire: Result<super::screencast::SessionReport, super::screencast::OpenError> = outcome;
        match serde_json::to_string(&wire) {
            Ok(json) => println!("{SESSION_MARKER}{json}"),
            Err(e) => eprintln!("portal-helper: could not encode the session report: {e}"),
        }
    }

    /// Parent side. Every failure — no session, no drop, no spawn, timeout,
    /// unparseable output — resolves to a status rather than an error, because
    /// the caller's question is "can the portal serve this host" and every one
    /// of those answers it with *no*.
    pub(super) fn probe() -> PortalStatus {
        match spawn_in_session(&[], TIMEOUT) {
            Ok(text) => parse_marked(&text).unwrap_or_else(|| {
                PortalStatus::Unknown("the portal helper reported nothing usable".into())
            }),
            // Nobody is at this machine's screen. That is not a fault, it IS
            // the answer, and `NoSessionBus`'s advice already says the portal
            // is an attended path by design.
            Err(SpawnError::NoSession) => PortalStatus::NoSessionBus,
            Err(SpawnError::Other(why)) => PortalStatus::Unknown(why),
        }
    }

    /// Why the helper could not be run at all, as distinct from what it said.
    ///
    /// `NoSession` is split out because it is the one arm that is a legitimate
    /// answer rather than a failure, and every caller maps it differently.
    pub(crate) enum SpawnError {
        NoSession,
        Other(String),
    }

    /// Spawn the helper inside the console user's session and return its
    /// stdout. Shared by every helper mode, so the session lookup, the
    /// privilege drop and the deadlock-free drain exist once.
    ///
    /// `timeout` is per-mode on purpose: a detection is a few D-Bus round
    /// trips, while opening a ScreenCast session can legitimately block for as
    /// long as a human takes to read a consent dialog.
    /// Build and start the helper as the console user. Shared by the
    /// collect-and-wait path and the streaming one, so the session lookup, the
    /// session environment and the privilege drop exist exactly once — the
    /// three things that must not drift between two ways of running the same
    /// child. FR-92 P9's keep-busy helper (`--keep-busy`) is the third way,
    /// and reuses it for exactly that reason.
    pub(crate) fn spawn_child(
        extra_args: &[&str],
        piped_stdin: bool,
    ) -> Result<std::process::Child, SpawnError> {
        // SAFETY: `geteuid` reads the caller's own credentials; it cannot fail.
        let euid = unsafe { libc::geteuid() };
        // A per-user daemon may open the portal only in its OWN session, so it
        // looks for that one: on a machine where two people are logged in,
        // "the first active session" could be the other person's.
        let found = if euid == 0 {
            crate::companion::graphical_session()
        } else {
            crate::companion::graphical_session_matching(Some(euid), false)
        };
        let sess = match found {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(%e, "portal: no graphical session to run the helper in");
                return Err(SpawnError::NoSession);
            }
        };
        let exe = std::env::current_exe()
            .map_err(|e| SpawnError::Other(format!("resolving our own path: {e}")))?;

        let mut cmd = std::process::Command::new(exe);
        cmd.arg("portal-helper")
            .args(extra_args)
            .env(CHILD_ENV, "1")
            // The two variables that put a process in a user's session. The
            // uid drop below is what makes them usable: `XDG_RUNTIME_DIR` is
            // 0700 and the bus checks `SO_PEERCRED`, so pointing root at them
            // gets a permission error, not a session.
            .env("XDG_RUNTIME_DIR", format!("/run/user/{}", sess.uid))
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path=/run/user/{}/bus", sess.uid),
            )
            .stdin(if piped_stdin {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            // Inherited on purpose: the child's own account of what it saw
            // belongs in the daemon log, and stdout is reserved for the
            // marked line (or, when streaming, for pixels).
            .stderr(std::process::Stdio::inherit());
        if let Some(d) = &sess.display {
            cmd.env("DISPLAY", d);
        }
        if let Some(w) = &sess.wayland_display {
            cmd.env("WAYLAND_DISPLAY", w);
        }

        match run_as(euid, sess.uid) {
            // The one privilege story. Not `CommandExt::uid()`: that leaves
            // the child in root's supplementary groups, which is a silent
            // retention bug rather than a visible failure.
            RunAs::Drop => {
                if let Err(e) = crate::exec::drop_to_std(&mut cmd, &sess.name) {
                    return Err(SpawnError::Other(format!(
                        "cannot run the portal helper as the session's owner: {e}"
                    )));
                }
            }
            // HOME, USER and LOGNAME are already this account's.
            RunAs::Ourselves => {}
            RunAs::Refuse { euid, owner } => {
                return Err(SpawnError::Other(format!(
                    "this daemon runs as uid {euid}, not as the session's owner (uid {owner}) — \
                     a per-user daemon can open the portal only in its own session"
                )));
            }
        }
        cmd.spawn()
            .map_err(|e| SpawnError::Other(format!("spawning the portal helper: {e}")))
    }

    /// How the helper comes to run as the session's owner.
    #[derive(Debug, PartialEq, Eq)]
    enum RunAs {
        /// A root daemon: the verified drop to the session's owner.
        Drop,
        /// The daemon already IS the session's owner — a per-user install.
        Ourselves,
        /// Neither root nor the owner: another user's session is not ours to
        /// open, and nothing this process can do would make it so.
        Refuse { euid: u32, owner: u32 },
    }

    /// ⚠️ "Dropping" to the account we already run as is NOT a no-op.
    /// `setgroups(2)` needs `CAP_SETGID` even to set the groups a process
    /// already holds, so in a per-user daemon (`meshharbor.service`, the desktop
    /// default) `drop_to_std`'s pre-exec hook failed `EPERM`, the helper never
    /// started, and the cascade fell through to XShm on Xwayland's empty root:
    /// a live black stream on every per-user install that set
    /// `portal_capture`. FR-45 was only ever field-verified under a ROOT
    /// daemon, which is how it stayed hidden until the vmtest per-user cell
    /// ran with the keys set (#1719 run B).
    fn run_as(euid: u32, owner: u32) -> RunAs {
        if euid == 0 {
            RunAs::Drop
        } else if euid == owner {
            RunAs::Ourselves
        } else {
            RunAs::Refuse { euid, owner }
        }
    }

    pub(crate) fn spawn_in_session(
        extra_args: &[&str],
        timeout: std::time::Duration,
    ) -> Result<String, SpawnError> {
        let mut child = spawn_child(extra_args, false)?;

        // Drain stdout on another thread while waiting: a child that filled
        // the pipe would otherwise deadlock against our own wait.
        let out = child.stdout.take();
        let reader = std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = String::new();
            if let Some(mut s) = out {
                let _ = s.read_to_string(&mut buf);
            }
            buf
        });

        let deadline = std::time::Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    tracing::warn!(
                        timeout_s = timeout.as_secs(),
                        "portal: the helper hung — treating the portal as unavailable"
                    );
                    return Err(SpawnError::Other("the portal helper hung".into()));
                }
                Err(e) => {
                    return Err(SpawnError::Other(format!("waiting for the helper: {e}")));
                }
            }
        }

        Ok(reader.join().unwrap_or_default())
    }

    /// Pull the status out of the child's stdout.
    ///
    /// Pure and separately testable on purpose — this is the half that a
    /// chatty child breaks, and the failure looks like an unavailable portal
    /// rather than a parse bug.
    fn parse_marked(out: &str) -> Option<PortalStatus> {
        parse_marked_as(out, MARKER)
    }

    /// The generic form. Finds the marked line — never "the last line", which
    /// breaks the first time anything else writes to stdout — and decodes it.
    fn parse_marked_as<T: serde::de::DeserializeOwned>(out: &str, marker: &str) -> Option<T> {
        out.lines()
            .find_map(|l| l.trim().strip_prefix(marker))
            .and_then(|json| serde_json::from_str(json).ok())
    }

    /// P2b parent side — open a ScreenCast session inside the console user's
    /// session and return what the helper reports.
    ///
    /// ⚠️ The timeout is long because **the first call shows a consent dialog**
    /// and a person has to answer it. That is not a defect to engineer away:
    /// it is the property that makes FR-45 an attended path, and the reason
    /// this can never replace FR-36's greeter and lock-screen capture.
    /// Subsequent calls carry a restore token and return in milliseconds.
    pub fn open_session() -> Result<super::screencast::SessionReport, String> {
        match spawn_in_session(&["--screencast"], SCREENCAST_TIMEOUT) {
            Ok(text) => match parse_marked_as::<
                Result<super::screencast::SessionReport, super::screencast::OpenError>,
            >(&text, SESSION_MARKER)
            {
                Some(Ok(report)) => Ok(report),
                Some(Err(e)) => Err(e.to_string()),
                None => Err("the portal helper reported no session".into()),
            },
            Err(SpawnError::NoSession) => {
                Err("nobody is at this machine's screen — the portal is an attended path".into())
            }
            Err(SpawnError::Other(why)) => Err(why),
        }
    }

    /// Long enough for a person to notice a dialog and decide. Beyond this the
    /// honest reading is that nobody is there, which is a refusal, not a hang.
    const SCREENCAST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A status must survive the process boundary unchanged — including
        /// the reason it was unavailable, which is the entire value of the
        /// enum over a bool.
        #[test]
        fn every_status_round_trips_through_the_wire() {
            let all = [
                PortalStatus::Available {
                    remote_desktop: true,
                    version: Some(5),
                },
                PortalStatus::Available {
                    remote_desktop: false,
                    version: None,
                },
                PortalStatus::NoScreenCast,
                PortalStatus::PortalAbsent,
                PortalStatus::NoSessionBus,
                PortalStatus::Unknown("session bus: connection refused".into()),
            ];
            for st in all {
                let line = format!("{MARKER}{}", serde_json::to_string(&st).unwrap());
                assert_eq!(
                    parse_marked(&line),
                    Some(st.clone()),
                    "{st} did not survive"
                );
            }
        }

        /// The child shares stdout with anything else that writes there. The
        /// marked line has to be *found*, not assumed to be the last one —
        /// taking the last line breaks the first time the child says anything
        /// else, and it breaks as "portal unavailable".
        #[test]
        fn the_marked_line_is_found_among_noise() {
            let st = PortalStatus::Available {
                remote_desktop: true,
                version: Some(5),
            };
            let text = format!(
                "some library banner\n{MARKER}{}\ntrailing chatter after the result\n",
                serde_json::to_string(&st).unwrap()
            );
            assert_eq!(parse_marked(&text), Some(st));
        }

        /// No marker, or a marker carrying garbage, must be `None` so the
        /// caller reports an unusable portal rather than inventing a status.
        #[test]
        fn unmarked_or_corrupt_output_yields_nothing() {
            assert_eq!(parse_marked(""), None);
            assert_eq!(parse_marked("portal is fine, honest\n"), None);
            assert_eq!(parse_marked(&format!("{MARKER}not json")), None);
        }

        /// FR-93 P2d-4 — a streaming helper that failed before its stream says
        /// why, and the parent hands that reason on. Before it the parent saw
        /// only an exit, which is still what a helper that says nothing reads as.
        #[test]
        fn a_helper_that_failed_says_why() {
            let why = "the person at the screen declined the request";
            let failed = format!(
                "{STREAM_FAILED_MARKER}{}\n",
                serde_json::to_string(why).unwrap()
            );
            let mut r = std::io::Cursor::new(format!("portal-helper noise\n{failed}"));
            assert_eq!(read_stream_handshake(&mut r).unwrap_err().to_string(), why);
            // Neither marker is read as the other.
            assert!(!STREAM_FAILED_MARKER.starts_with(STREAM_MARKER));
            let mut silent = std::io::Cursor::new(String::new());
            let e = read_stream_handshake(&mut silent).unwrap_err().to_string();
            assert!(e.contains("exited before announcing a stream"), "{e}");
        }

        /// #1719 run B: only a root daemon drops privilege; a per-user daemon
        /// IS the session's owner and runs the helper as itself; anyone else
        /// is refused with both uids named.
        #[test]
        fn only_root_drops_and_a_per_user_daemon_runs_as_itself() {
            assert_eq!(run_as(0, 1000), RunAs::Drop);
            assert_eq!(
                run_as(0, 0),
                RunAs::Drop,
                "root at the seat keeps the verified path"
            );
            assert_eq!(run_as(1000, 1000), RunAs::Ourselves);
            assert_eq!(
                run_as(1001, 1000),
                RunAs::Refuse {
                    euid: 1001,
                    owner: 1000
                }
            );
        }

        /// The root cause, demonstrated rather than asserted: an unprivileged
        /// process cannot "drop" to its OWN account through `drop_to_std`,
        /// because `setgroups(2)` needs `CAP_SETGID` whatever the groups are.
        /// This is why `RunAs::Ourselves` must skip the drop entirely.
        #[test]
        fn an_unprivileged_drop_to_ourselves_is_refused_by_the_kernel() {
            // SAFETY: plain credential reads.
            let euid = unsafe { libc::geteuid() };
            if euid == 0 {
                // Root holds CAP_SETGID, so the failing case cannot arise here.
                return;
            }
            // SAFETY: `getpwuid` returns a pointer into static storage or
            // null; it is read once, immediately, on this thread.
            let name = unsafe {
                let pw = libc::getpwuid(euid);
                assert!(!pw.is_null(), "no passwd entry for uid {euid}");
                std::ffi::CStr::from_ptr((*pw).pw_name)
                    .to_string_lossy()
                    .into_owned()
            };
            let mut cmd = std::process::Command::new("true");
            crate::exec::drop_to_std(&mut cmd, &name).expect("resolving our own account");
            let err = cmd
                .spawn()
                .expect_err("setgroups must refuse an unprivileged caller");
            assert_eq!(err.raw_os_error(), Some(libc::EPERM), "{err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every status must offer an operator a next step. A bare "unavailable"
    /// is what this enum exists to prevent — FR-36 lost time to exactly that.
    #[test]
    fn every_status_gives_actionable_advice() {
        let all = [
            PortalStatus::Available {
                remote_desktop: true,
                version: Some(5),
            },
            PortalStatus::Available {
                remote_desktop: false,
                version: None,
            },
            PortalStatus::NoScreenCast,
            PortalStatus::PortalAbsent,
            PortalStatus::NoSessionBus,
            PortalStatus::Unknown("x".into()),
        ];
        for s in all {
            assert!(!s.advice().is_empty(), "{s} has no advice");
        }
    }

    /// Only `Available` may be used for capture. In particular a portal that
    /// is RUNNING but exposes no ScreenCast must not count — that is the exact
    /// host FR-36 measured, and treating it as usable would open a session
    /// that then produces nothing.
    #[test]
    fn only_available_is_usable() {
        assert!(
            PortalStatus::Available {
                remote_desktop: true,
                version: Some(4)
            }
            .usable_for_capture()
        );
        // Read-only is still usable for CAPTURE; input is a separate gate.
        assert!(
            PortalStatus::Available {
                remote_desktop: false,
                version: None
            }
            .usable_for_capture()
        );
        assert!(!PortalStatus::NoScreenCast.usable_for_capture());
        assert!(!PortalStatus::PortalAbsent.usable_for_capture());
        assert!(!PortalStatus::NoSessionBus.usable_for_capture());
        assert!(!PortalStatus::Unknown("e".into()).usable_for_capture());
    }

    /// A missing ScreenCast and a missing RemoteDesktop are different
    /// problems: the first means no picture, the second means a session you
    /// can watch but not drive. FR-45 needs both on a host with no evdev
    /// consumer, so the difference has to survive into the report.
    #[test]
    fn read_only_availability_is_distinguishable() {
        let ro = PortalStatus::Available {
            remote_desktop: false,
            version: Some(5),
        };
        assert!(ro.advice().contains("read-only"));
        let rw = PortalStatus::Available {
            remote_desktop: true,
            version: Some(5),
        };
        assert!(!rw.advice().contains("read-only"));
        assert_ne!(ro, rw);
    }

    #[test]
    fn display_is_greppable() {
        assert_eq!(PortalStatus::NoScreenCast.to_string(), "no-screencast");
        assert_eq!(PortalStatus::PortalAbsent.to_string(), "portal-absent");
        assert!(
            PortalStatus::Available {
                remote_desktop: true,
                version: Some(5)
            }
            .to_string()
            .contains("v5")
        );
    }
}
