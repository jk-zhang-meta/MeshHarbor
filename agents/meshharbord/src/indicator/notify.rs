// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-93 P6f — the desktop's own notifications as the last consent surface.
//!
//! Where neither the daemon's panel nor the desktop companion can show a
//! question, it reached nobody. That is a system daemon on a GNOME or KDE
//! Wayland desktop with no companion package: Fedora, openSUSE and Arch, and
//! every aarch64 host. The controller waited, and was told
//! `no_prompt_surface`. Measured on the FR-93 lab (Plasma 6.7, a system install,
//! 0.4.135): *"no desktop companion on this host"*, and nothing on the screen.
//!
//! Every such desktop runs a notification server that takes buttons
//! (`org.freedesktop.Notifications` with the `actions` capability): GNOME
//! Shell's banners, KDE's popups. That is this surface. Its place in the chain
//! is last before the CLI: native panel → companion → notification → none.
//!
//! The notification is posted from INSIDE the person's session, by the session
//! helper (`portal-helper --notify`, spawned by
//! [`crate::capture::portal::helper::spawn_child`], so the session lookup and
//! the privilege drop exist once). The helper prints one marked line when the
//! notification is up and one for what the person did. An answer reaches the
//! broker the way a native panel's does, over the indicator's
//! [`ConsentSender`]: one decision point.
//!
//! - **Approve** and **Deny** are the answer. **Closing** the notification is a
//!   Deny: the person saw the question and did not approve it, and a question
//!   with nothing left on screen would otherwise stand until its window ran
//!   out, with the controller told "nobody answered".
//! - A click on the notification's **body** is not an answer. Servers send it
//!   as the spec's `default` action and then remove the notification (on
//!   GNOME 50 the removal alone arrived as a dismissal, which read as a
//!   refusal), so the helper posts the question again.
//! - **Critical urgency**: GNOME and KDE keep a critical notification on screen
//!   until it is answered, and show it under Do Not Disturb.
//! - **The daemon takes it down** (answered elsewhere, timed out, the session
//!   gone) by closing the helper's stdin. The helper closes the notification
//!   and exits, so no Approve button outlives its question.
//!
//! Kill switch `ROOMLERD_NOTIFY_CONSENT=0`.

use serde::{Deserialize, Serialize};

/// One notification, as the parent asks the helper to post it. The parent
/// writes the words; the helper only knows the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub summary: String,
    pub body: String,
    /// `(key, label)` pairs, in the order shown.
    pub actions: Vec<(String, String)>,
    /// 0 low, 1 normal, 2 critical.
    pub urgency: u8,
    /// How long the helper keeps it up at most. A backstop: the daemon closes
    /// it first.
    pub lifetime_ms: u64,
}

/// Marks the line saying the notification is up (with its id).
const SHOWN: &str = "ROOMLER_NOTIFY_SHOWN:";
/// Marks the line saying it could not be posted, and why.
const FAILED: &str = "ROOMLER_NOTIFY_FAILED:";
/// Marks the key of the button the person pressed.
const ACTION: &str = "ROOMLER_NOTIFY_ACTION:";
/// Marks the server's `NotificationClosed` reason.
const CLOSED: &str = "ROOMLER_NOTIFY_CLOSED:";

/// What the helper said, one marked line at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Said {
    Shown,
    Failed(String),
    Action(String),
    /// `NotificationClosed`'s reason: 1 expired, 2 dismissed by the person,
    /// 3 closed by `CloseNotification`, 4 undefined.
    Closed(u32),
}

/// The helper's stdout carries its own library chatter too, so lines are
/// matched by marker, never by position.
fn parse(line: &str) -> Option<Said> {
    let line = line.trim();
    if line.starts_with(SHOWN) {
        Some(Said::Shown)
    } else if let Some(why) = line.strip_prefix(FAILED) {
        Some(Said::Failed(why.to_string()))
    } else if let Some(key) = line.strip_prefix(ACTION) {
        Some(Said::Action(key.to_string()))
    } else {
        line.strip_prefix(CLOSED)
            .map(|r| Said::Closed(r.parse().unwrap_or(4)))
    }
}

/// The two buttons of a consent question.
const APPROVE: &str = "approve";
const DENY: &str = "deny";
/// The freedesktop spec's click on the body, which no server draws as a
/// button. Without it a click there closed the question as dismissed (GNOME
/// 50), which read as a refusal; with it, the helper posts it again.
const DEFAULT: &str = "default";

/// A consent question's answer, from what the person did: Approve, Deny, or
/// closing it (a Deny). Anything else (the server expired it, it was closed by
/// a call) answers nothing, and the broker's window decides.
fn consent_answer(said: &Said) -> Option<bool> {
    match said {
        Said::Action(k) if k == APPROVE => Some(true),
        Said::Action(k) if k == DENY => Some(false),
        Said::Closed(2) => Some(false),
        _ => None,
    }
}

/// The question in words: who asks and for what, on whose behalf, the
/// permissions, and when an unanswered question is refused.
fn consent_request(view: &super::PromptView, now: std::time::Instant) -> Request {
    let mut lines = vec![view.lead.clone()];
    if !view.org.is_empty() {
        lines.push(format!("On behalf of {}", view.org));
    }
    // The X11 panel's detail box holds two lines; a notification shows them
    // all, the same words.
    if !view.detail.is_empty() {
        lines.push(view.detail.clone());
    }
    if !view.permissions.is_empty() {
        lines.push(format!("Permissions: {}", view.permissions));
    }
    let left = view.expires_at.saturating_duration_since(now);
    lines.push(format!(
        "Unanswered, it is refused in {}.",
        in_words(left.as_secs())
    ));
    Request {
        summary: view.title.clone(),
        body: lines.join("\n"),
        actions: vec![
            (DEFAULT.to_string(), "Show".to_string()),
            (APPROVE.to_string(), "Approve".to_string()),
            (DENY.to_string(), "Deny".to_string()),
        ],
        urgency: 2,
        lifetime_ms: left.as_millis() as u64,
    }
}

/// "5 minutes", "1 minute", "30 seconds". A notification cannot count down, so
/// the window is said once, rounded.
fn in_words(secs: u64) -> String {
    if secs >= 90 {
        format!("{} minutes", (secs + 30) / 60)
    } else if secs >= 60 {
        "1 minute".to_string()
    } else {
        format!("{secs} seconds")
    }
}

/// `body-markup` servers read `&`, `<` and `>` as markup. A controller's name or
/// a command line must arrive as text.
fn escape_markup(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// FR-93 P6f kill switch `ROOMLERD_NOTIFY_CONSENT=0`: no notification, as
/// before P6f.
fn enabled() -> bool {
    tunnel_core::env::flag("NOTIFY_CONSENT", true)
}

pub(super) use parent::Prompts;
pub(crate) use parent::{viewing, viewing_ended};

/// FR-93 P6g's button: end the session, as the companion banner's
/// **Disconnect** does.
const DISCONNECT: &str = "disconnect";

/// FR-93 P6g kill switch `ROOMLERD_VIEWING_NOTICE=0`: a session the compositor
/// says nothing about stays unseen at the screen, as before P6g.
fn viewing_enabled() -> bool {
    tunnel_core::env::flag("VIEWING_NOTICE", true)
}

/// Marks the probe's answer: `yes`, or `no` and why.
const CAN: &str = "ROOMLER_NOTIFY_CAN:";

/// How long the probe may take: a session bus round trip, and the start of a
/// notification server that is activated on demand.
const PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(4);

/// FR-95 P2 (decision D-b) — can the person in the session on screen (`uid`)
/// be told they are being viewed, and end it? FR-93 P6g's notice is that
/// surface: the companion's banner where one runs for them, else a
/// notification with Disconnect. Asked LIVE, at the capture's open: a
/// companion that is installed but not running for them is not counted on
/// its own, and a session whose notification server shows no buttons is no
/// surface. `false` with the notice switched off (`ROOMLERD_VIEWING_NOTICE=0`).
/// Blocking: a helper is started in the session.
pub(crate) fn can_tell(uid: u32) -> bool {
    if !viewing_enabled() {
        return false;
    }
    if crate::companion::companion_running_for_uid(uid) {
        return true;
    }
    use crate::capture::portal::helper::{SpawnError, spawn_in_session};
    match spawn_in_session(&["--notify-probe"], PROBE_BUDGET) {
        Ok(text) => {
            let said = text.lines().find_map(|l| l.trim().strip_prefix(CAN));
            if said.is_some_and(|s| s.starts_with("yes")) {
                return true;
            }
            tracing::info!(
                said = said.unwrap_or("nothing"),
                "no way to tell the person at the screen they are viewed (FR-95 P2)"
            );
            false
        }
        Err(SpawnError::NoSession) => false,
        Err(SpawnError::Other(why)) => {
            tracing::info!(%why, "the notification probe did not run (FR-95 P2)");
            false
        }
    }
}

/// The probe's session half: `roomlerd portal-helper --notify-probe`. Posts
/// nothing. On a plain thread, for the reason [`run_helper`] gives.
pub fn run_probe_helper() {
    let answer = match std::thread::Builder::new()
        .name("notify-probe".into())
        .spawn(helper::probe)
    {
        Ok(worker) => worker
            .join()
            .unwrap_or_else(|_| Err("the probe's thread panicked".into())),
        Err(e) => Err(format!("no thread for the probe: {e}")),
    };
    match answer {
        Ok(()) => println!("{CAN}yes"),
        Err(why) => {
            eprintln!("portal-helper --notify-probe: {why}");
            println!("{CAN}no {why}");
        }
    }
}

/// FR-93 P6g — who is viewing the screen, whether they can type into it, and
/// how to end it. Critical urgency, so it stays on screen for the session:
/// with the DRM arm nothing else at the screen says so.
fn viewing_request(controller: &str, permissions: &str) -> Request {
    // Equality on the pipe-separated names, never a substring: a name that
    // merely contains another is not that permission.
    let input = permissions.split('|').any(|p| p.trim() == "INPUT");
    let lead = if input {
        format!("{controller} is viewing this screen and can use its keyboard and mouse.")
    } else {
        format!("{controller} is viewing this screen.")
    };
    Request {
        summary: "This screen is being viewed".to_string(),
        body: format!("{lead}\nDisconnect ends the session."),
        actions: vec![
            (DEFAULT.to_string(), "Show".to_string()),
            (DISCONNECT.to_string(), "Disconnect".to_string()),
        ],
        urgency: 2,
        // A backstop: the session's end takes it down first.
        lifetime_ms: 24 * 3600 * 1000,
    }
}

mod parent {
    use super::{
        DISCONNECT, Request, Said, consent_answer, consent_request, enabled, parse,
        viewing_enabled, viewing_request,
    };
    use crate::indicator::{ConsentSender, PromptView};
    use bson::oid::ObjectId;
    use std::collections::HashMap;
    use std::io::{BufRead, Write};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    /// How long posting may take: a session bus round trip or three. A wedged
    /// bus must not hold the prompt's window.
    const SHOW_BUDGET: Duration = Duration::from_secs(5);

    /// The consent questions this daemon has on screen as notifications.
    #[derive(Clone)]
    pub(crate) struct Prompts {
        consent_tx: ConsentSender,
        /// The helper's stdin per question: dropping it is what takes the
        /// notification down. The number tells a re-asked question from the
        /// one before it.
        live: Arc<Mutex<HashMap<String, (u64, std::process::ChildStdin)>>>,
    }

    impl Prompts {
        pub(crate) fn new(consent_tx: ConsentSender) -> Self {
            Self {
                consent_tx,
                live: Arc::default(),
            }
        }

        /// Put `view` on the person's screen as a notification with Approve
        /// and Deny. Whether it is up. Blocks for the helper's first line, so
        /// callers run it off the runtime.
        pub(crate) fn show(&self, view: &PromptView) -> bool {
            if !enabled() {
                tracing::info!("no notification prompt (ROOMLERD_NOTIFY_CONSENT=0, FR-93 P6f)");
                return false;
            }
            let now = std::time::Instant::now();
            // A question already over is not posted: nothing would take it
            // down but its own lifetime.
            if view.expires_at <= now {
                return false;
            }
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let generation = NEXT.fetch_add(1, Ordering::Relaxed);
            let session = view.session_hex.clone();
            let tx = self.consent_tx.clone();
            let mut answered = false;
            let said_session = session.clone();
            let on_said = move |said: &Said| {
                let answer = consent_answer(said);
                tracing::info!(
                    session = %said_session, ?said, ?answer,
                    "the person at the screen acted on the notification prompt (FR-93 P6f)"
                );
                if let Some(allow) = answer
                    && !answered
                {
                    answered = true;
                    // The reader's own thread, never the runtime's:
                    // `blocking_send` is safe here.
                    let _ = tx.blocking_send((said_session.clone(), allow));
                }
            };
            let live = self.live.clone();
            let end_session = session.clone();
            let on_end = move || {
                // This question's entry only: a re-asked question under the
                // same id has its own.
                if let Ok(mut l) = live.lock()
                    && l.get(&end_session).is_some_and(|(g, _)| *g == generation)
                {
                    l.remove(&end_session);
                }
            };
            match launch(&consent_request(view, now), "prompt", on_said, on_end) {
                Ok(stdin) => {
                    if let Ok(mut l) = self.live.lock() {
                        l.insert(session, (generation, stdin));
                    }
                    true
                }
                Err(why) => {
                    tracing::info!(%why, "no notification prompt (FR-93 P6f)");
                    false
                }
            }
        }

        /// Take the notification for `session_hex` down, if one is up: its
        /// helper reads the close of its stdin, closes the notification and
        /// exits. Idempotent.
        pub(crate) fn dismiss(&self, session_hex: &str) {
            if let Ok(mut l) = self.live.lock() {
                l.remove(session_hex);
            }
        }
    }

    /// Post `req` from inside the person's session and wait, at most
    /// [`SHOW_BUDGET`], for it to be up. What the person then does goes to
    /// `on_said`, on the reader's own thread, and `on_end` runs once the helper
    /// has gone. The returned stdin is the notification's life: dropping it
    /// takes the notification down. Blocks, so callers run it off the runtime.
    fn launch(
        req: &Request,
        what: &str,
        mut on_said: impl FnMut(&Said) + Send + 'static,
        on_end: impl FnOnce() + Send + 'static,
    ) -> Result<std::process::ChildStdin, String> {
        use crate::capture::portal::helper::{SpawnError, spawn_child};
        let mut child = match spawn_child(&["--notify"], true) {
            Ok(c) => c,
            Err(SpawnError::NoSession) => return Err("no graphical session".into()),
            Err(SpawnError::Other(why)) => return Err(why),
        };
        let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("the session helper has no pipes".into());
        };
        // The request, and then nothing: stdin stays open, and its close is
        // the daemon's "take it down".
        let written = serde_json::to_string(req)
            .map_err(|e| e.to_string())
            .and_then(|l| {
                writeln!(stdin, "{l}")
                    .and_then(|_| stdin.flush())
                    .map_err(|e| e.to_string())
            });
        if let Err(e) = written {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("writing the request: {e}"));
        }
        let (shown_tx, shown_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let pid = child.id();
        let reader = std::thread::Builder::new()
            .name(format!("notify-{what}"))
            .spawn(move || {
                let mut shown = Some(shown_tx);
                for line in std::io::BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    match parse(&line) {
                        Some(Said::Shown) => {
                            if let Some(s) = shown.take() {
                                let _ = s.send(Ok(()));
                            }
                        }
                        Some(Said::Failed(why)) => {
                            if let Some(s) = shown.take() {
                                let _ = s.send(Err(why));
                            }
                        }
                        Some(said) => on_said(&said),
                        None => {}
                    }
                }
                if let Some(s) = shown.take() {
                    let _ = s.send(Err("the helper ended without posting it".into()));
                }
                on_end();
                let _ = child.wait();
            });
        if reader.is_err() {
            // The child was moved into the closure that never ran; its stdin
            // closing ends it.
            return Err("no thread to read the session helper".into());
        }
        match shown_rx.recv_timeout(SHOW_BUDGET) {
            Ok(Ok(())) => Ok(stdin),
            Ok(Err(why)) => Err(why),
            Err(_) => {
                // Not yet reaped (the reader waits on it), so the pid is still
                // this child's.
                // SAFETY: plain `kill(2)` on our own unreaped child.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
                Err(format!(
                    "the session helper did not post it within {} s",
                    SHOW_BUDGET.as_secs()
                ))
            }
        }
    }

    /// FR-93 P6g — what the daemon has put up to say a session is viewed.
    enum Viewing {
        /// Being put up: the companion asked first, then the notification.
        Pending,
        /// The companion runs, and its banner lists every live session.
        Companion,
        /// The notification is up; dropping this takes it down.
        Live(std::process::ChildStdin),
        /// The person closed it: not posted again for this session.
        Closed,
    }

    /// How long a being-viewed notice waits for its session to be registered:
    /// 60 × 500 ms. A session still unregistered after that never connected.
    const REGISTERED_POLLS: u32 = 60;
    const REGISTERED_POLL: Duration = Duration::from_millis(500);

    fn viewings() -> &'static Mutex<HashMap<ObjectId, Viewing>> {
        static V: OnceLock<Mutex<HashMap<ObjectId, Viewing>>> = OnceLock::new();
        V.get_or_init(Default::default)
    }

    fn with_viewings<T>(f: impl FnOnce(&mut HashMap<ObjectId, Viewing>) -> T) -> T {
        f(&mut viewings().lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// FR-93 P6g — `session` is served by an arm the compositor shows nothing
    /// for: DRM reads the scanout below it, so neither GNOME's pill nor KDE's
    /// tray icon appears, and the person at the screen could be watched with
    /// nothing saying so. Say it: the companion's banner where a companion can
    /// run (it lists every live session), else a notification naming the
    /// controller, with **Disconnect**. Once per session; called on the runtime.
    pub(crate) fn viewing(session: ObjectId, registry: crate::rc_sessions::RcSessionRegistry) {
        if !viewing_enabled() {
            return;
        }
        let first = with_viewings(|v| {
            if v.contains_key(&session) {
                return false;
            }
            v.insert(session, Viewing::Pending);
            true
        });
        if !first {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            with_viewings(|v| v.remove(&session));
            return;
        };
        rt.spawn(async move {
            if crate::companion::ensure_running().await {
                tracing::info!(%session, "being viewed: the companion's banner says so (FR-93 P6g)");
                with_viewings(|v| {
                    if matches!(v.get(&session), Some(Viewing::Pending)) {
                        v.insert(session, Viewing::Companion);
                    }
                });
                return;
            }
            // The pump opens its capture as the peer is built, a moment before
            // the session is registered (once its answer is ready): wait for
            // that, and never for a session that does not get there. Measured
            // in the lab: the first build looked once, too early, and showed
            // nothing.
            let hex = session.to_hex();
            let mut found = None;
            for _ in 0..REGISTERED_POLLS {
                found = registry.list().into_iter().find(|i| i.session_id == hex);
                if found.is_some() || !with_viewings(|v| v.contains_key(&session)) {
                    break;
                }
                tokio::time::sleep(REGISTERED_POLL).await;
            }
            let Some(info) = found else {
                tracing::info!(%session, "no being-viewed notification: the session never got to be registered (FR-93 P6g)");
                with_viewings(|v| v.remove(&session));
                return;
            };
            let req = viewing_request(&info.controller_name, &info.permissions);
            let closed = Arc::new(AtomicBool::new(false));
            let (closed_said, closed_end) = (closed.clone(), closed);
            let on_said = move |said: &Said| match said {
                Said::Action(k) if k == DISCONNECT => {
                    let ended = registry.disconnect(&session);
                    tracing::info!(%session, ended, "the person at the screen pressed Disconnect on the being-viewed notification (FR-93 P6g)");
                }
                Said::Closed(2) => closed_said.store(true, Ordering::Relaxed),
                _ => {}
            };
            let on_end = move || {
                // Ended by the person's close: remembered, so a reopen of the
                // capture does not put it back. Any other end leaves the entry
                // to `viewing_ended`.
                if closed_end.load(Ordering::Relaxed) {
                    with_viewings(|v| {
                        if v.contains_key(&session) {
                            v.insert(session, Viewing::Closed);
                        }
                    });
                }
            };
            let posted =
                tokio::task::spawn_blocking(move || launch(&req, "viewing", on_said, on_end)).await;
            match posted {
                Ok(Ok(stdin)) => {
                    tracing::info!(%session, "being viewed: a notification says so, with Disconnect (FR-93 P6g)");
                    // A session that ended while it was being posted drops it
                    // here, which takes the notification down at once.
                    with_viewings(|v| {
                        if matches!(v.get(&session), Some(Viewing::Pending)) {
                            v.insert(session, Viewing::Live(stdin));
                        }
                    });
                }
                Ok(Err(why)) => {
                    tracing::info!(%session, %why, "no being-viewed notification (FR-93 P6g)");
                    with_viewings(|v| v.remove(&session));
                }
                Err(e) => {
                    tracing::warn!(%session, %e, "no being-viewed notification (FR-93 P6g)");
                    with_viewings(|v| v.remove(&session));
                }
            }
        });
    }

    /// FR-93 P6g — `session` ended: its notification, if one is up, comes
    /// down. Idempotent.
    pub(crate) fn viewing_ended(session: &ObjectId) {
        with_viewings(|v| v.remove(session));
    }
}

/// The session helper's half: `roomlerd portal-helper --notify`. Reads one
/// [`Request`] line on stdin, posts it, says what happened on stdout, and
/// closes the notification when stdin closes or its lifetime ends.
///
/// ⚠️ zbus's blocking API panics inside a tokio runtime ("Cannot start a
/// runtime from within a runtime"), and the subcommand is reached from the
/// daemon's runtime, so the D-Bus work runs on a plain thread: the rule keep
/// busy's helper and `capture::portal::mutter` follow. Measured on the FR-93
/// lab: called on the runtime's thread, the helper panicked before it posted
/// anything.
pub fn run_helper() {
    let outcome = match std::thread::Builder::new()
        .name("notify-helper".into())
        .spawn(helper::run)
    {
        Ok(worker) => worker
            .join()
            .unwrap_or_else(|_| Err("the helper's thread panicked".into())),
        Err(e) => Err(format!("no thread for the helper: {e}")),
    };
    if let Err(why) = outcome {
        eprintln!("portal-helper --notify: {why}");
        println!("{FAILED}{why}");
    }
}

mod helper {
    use super::{ACTION, CLOSED, DEFAULT, Request, SHOWN, escape_markup};
    use std::collections::HashMap;
    use std::io::{BufRead, Write};
    use std::time::{Duration, Instant};
    use zbus::zvariant::Value;

    const BUS: &str = "org.freedesktop.Notifications";
    const PATH: &str = "/org/freedesktop/Notifications";
    const IFACE: &str = "org.freedesktop.Notifications";

    enum Event {
        Action(u32, String),
        Closed(u32, u32),
        /// The daemon closed our stdin: take it down.
        Parent,
    }

    fn say(line: String) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }

    /// FR-95 P2 — the session has a notification server that shows buttons:
    /// the one a being-viewed notice's Disconnect needs.
    pub(super) fn probe() -> Result<(), String> {
        let conn =
            zbus::blocking::Connection::session().map_err(|e| format!("no session bus: {e}"))?;
        let proxy = zbus::blocking::Proxy::new(&conn, BUS, PATH, IFACE)
            .map_err(|e| format!("no notification server: {e}"))?;
        let caps: Vec<String> = proxy
            .call_method("GetCapabilities", &())
            .and_then(|r| r.body().deserialize())
            .map_err(|e| format!("no notification server: {e}"))?;
        if caps.iter().any(|c| c == "actions") {
            Ok(())
        } else {
            Err(format!(
                "the notification server shows no buttons (capabilities: {})",
                caps.join(" ")
            ))
        }
    }

    pub(super) fn run() -> Result<(), String> {
        let mut first = String::new();
        let stdin = std::io::stdin();
        stdin
            .lock()
            .read_line(&mut first)
            .map_err(|e| format!("reading the request: {e}"))?;
        let req: Request =
            serde_json::from_str(first.trim()).map_err(|e| format!("the request: {e}"))?;

        let conn =
            zbus::blocking::Connection::session().map_err(|e| format!("no session bus: {e}"))?;
        let proxy = zbus::blocking::Proxy::new(&conn, BUS, PATH, IFACE)
            .map_err(|e| format!("no notification server: {e}"))?;
        let caps: Vec<String> = proxy
            .call_method("GetCapabilities", &())
            .and_then(|r| r.body().deserialize())
            .map_err(|e| format!("no notification server: {e}"))?;
        if !req.actions.is_empty() && !caps.iter().any(|c| c == "actions") {
            return Err(format!(
                "the notification server shows no buttons (capabilities: {})",
                caps.join(" ")
            ));
        }
        let markup = caps.iter().any(|c| c == "body-markup");
        let body = if markup {
            escape_markup(&req.body)
        } else {
            req.body.clone()
        };

        // Subscribed BEFORE Notify, so a press can never come before the
        // subscription that would hear it. ONE stream for both signals, so
        // they arrive in the order the server sent them: a body click is
        // `ActionInvoked(default)` then `NotificationClosed`, and read the
        // other way round it would be a refusal.
        let (tx, rx) = std::sync::mpsc::channel::<Event>();
        let signals = proxy
            .receive_all_signals()
            .map_err(|e| format!("subscribing to the notification signals: {e}"))?;
        let t = tx.clone();
        std::thread::spawn(move || {
            for msg in signals {
                let header = msg.header();
                let event = match header.member().map(|m| m.as_str()) {
                    Some("ActionInvoked") => msg
                        .body()
                        .deserialize::<(u32, String)>()
                        .ok()
                        .map(|(id, key)| Event::Action(id, key)),
                    Some("NotificationClosed") => msg
                        .body()
                        .deserialize::<(u32, u32)>()
                        .ok()
                        .map(|(id, reason)| Event::Closed(id, reason)),
                    _ => None,
                };
                if let Some(e) = event
                    && t.send(e).is_err()
                {
                    return;
                }
            }
        });
        std::thread::spawn(move || {
            // Everything after the request is ignored; the close is the
            // message.
            let mut sink = String::new();
            let mut lock = std::io::stdin().lock();
            while matches!(lock.read_line(&mut sink), Ok(n) if n > 0) {
                sink.clear();
            }
            let _ = tx.send(Event::Parent);
        });

        let mut id = post(&proxy, &req, &body)?;
        say(format!("{SHOWN}{id}"));
        eprintln!("portal-helper --notify: posted notification {id}");

        let close = |id: u32, why: &str| {
            let _ = proxy.call_method("CloseNotification", &(id,));
            eprintln!("portal-helper --notify: closed notification {id} ({why})");
        };
        let deadline = Instant::now() + Duration::from_millis(req.lifetime_ms);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                // A click on the body, not a button: the server invokes
                // `default` and takes the notification away (a dismissal,
                // measured on GNOME 50). The person was looking, not
                // answering, so the question comes back. The old one's
                // `NotificationClosed` then names an id no longer ours.
                Ok(Event::Action(i, key)) if i == id && key == DEFAULT => {
                    close(i, "its body was clicked");
                    id = post(&proxy, &req, &body)?;
                    eprintln!("portal-helper --notify: posted it again as notification {id}");
                }
                Ok(Event::Action(i, key)) if i == id => {
                    say(format!("{ACTION}{key}"));
                    // A question is answered once; the server removes a
                    // non-resident notification on a press, and the close
                    // makes sure.
                    close(id, "answered");
                    return Ok(());
                }
                Ok(Event::Closed(i, reason)) if i == id => {
                    say(format!("{CLOSED}{reason}"));
                    return Ok(());
                }
                Ok(Event::Parent) => {
                    close(id, "the daemon took it down");
                    return Ok(());
                }
                Ok(_) => {}
                Err(_) => {
                    close(id, "its lifetime ended");
                    return Ok(());
                }
            }
        }
    }

    /// One `Notify`: the request's words and buttons, at its urgency, never
    /// expiring by itself (the daemon or the lifetime closes it).
    fn post(proxy: &zbus::blocking::Proxy<'_>, req: &Request, body: &str) -> Result<u32, String> {
        let flat: Vec<&str> = req
            .actions
            .iter()
            .flat_map(|(k, l)| [k.as_str(), l.as_str()])
            .collect();
        let mut hints: HashMap<&str, Value> = HashMap::new();
        hints.insert("urgency", Value::from(req.urgency));
        proxy
            .call_method(
                "Notify",
                &(
                    "Roomler",
                    0u32,
                    "preferences-desktop-remote-desktop",
                    req.summary.as_str(),
                    body,
                    flat,
                    hints,
                    0i32,
                ),
            )
            .and_then(|r| r.body().deserialize())
            .map_err(|e| format!("Notify: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn view(
        now: Instant,
        org: &str,
        detail: &str,
        permissions: &str,
        left: Duration,
    ) -> super::super::PromptView {
        super::super::PromptView {
            session_hex: "abc".into(),
            title: "Remote control request".into(),
            lead: "Alice is requesting to control this device.".into(),
            detail: detail.into(),
            permissions: permissions.into(),
            org: org.into(),
            expires_at: now + left,
        }
    }

    /// FR-93 P6f — the notification says what the native panel says, the
    /// window included, with Approve and Deny, at critical urgency.
    #[test]
    fn the_question_reads_as_the_panel_does() {
        let now = Instant::now();
        let v = view(now, "Acme", "", "VIEW|INPUT", Duration::from_secs(300));
        let r = consent_request(&v, now);
        assert_eq!(r.summary, "Remote control request");
        assert_eq!(
            r.body,
            "Alice is requesting to control this device.\nOn behalf of Acme\n\
             Permissions: VIEW|INPUT\nUnanswered, it is refused in 5 minutes."
        );
        // `default` is the click on the body, which no server draws as a
        // button: the helper posts the question again on it.
        assert_eq!(
            r.actions,
            vec![
                ("default".to_string(), "Show".to_string()),
                ("approve".to_string(), "Approve".to_string()),
                ("deny".to_string(), "Deny".to_string())
            ]
        );
        assert_eq!(r.urgency, 2);
        assert_eq!(r.lifetime_ms, 300_000);
        let exec = view(now, "", "uname -a", "", Duration::from_secs(30));
        assert_eq!(
            consent_request(&exec, now).body,
            "Alice is requesting to control this device.\nuname -a\n\
             Unanswered, it is refused in 30 seconds."
        );
    }

    /// FR-93 P6g — the being-viewed notice names the controller and whether
    /// they can type, by permission name, and has Disconnect.
    #[test]
    fn the_viewing_notice_names_who_and_what() {
        let r = viewing_request("Alice", "VIEW|INPUT|CLIPBOARD");
        assert_eq!(r.summary, "This screen is being viewed");
        assert_eq!(
            r.body,
            "Alice is viewing this screen and can use its keyboard and mouse.\n\
             Disconnect ends the session."
        );
        assert_eq!(
            r.actions,
            vec![
                ("default".to_string(), "Show".to_string()),
                ("disconnect".to_string(), "Disconnect".to_string())
            ]
        );
        assert_eq!(r.urgency, 2);
        assert_eq!(
            viewing_request("Bob", "VIEW").body,
            "Bob is viewing this screen.\nDisconnect ends the session."
        );
        // ⚠️ equality, never a substring: a name that merely contains INPUT
        // grants no input.
        assert_eq!(
            viewing_request("Eve", "VIEW|INPUT_LOG").body,
            "Eve is viewing this screen.\nDisconnect ends the session."
        );
    }

    #[test]
    fn the_window_in_words() {
        assert_eq!(in_words(300), "5 minutes");
        assert_eq!(in_words(287), "5 minutes");
        assert_eq!(in_words(90), "2 minutes");
        assert_eq!(in_words(75), "1 minute");
        assert_eq!(in_words(30), "30 seconds");
        assert_eq!(in_words(0), "0 seconds");
    }

    /// P6f — Approve grants, Deny refuses, closing it refuses; a notification
    /// the server expired, or one the daemon closed, answers nothing.
    #[test]
    fn what_the_person_did_is_the_answer() {
        assert_eq!(consent_answer(&Said::Action("approve".into())), Some(true));
        assert_eq!(consent_answer(&Said::Action("deny".into())), Some(false));
        assert_eq!(consent_answer(&Said::Closed(2)), Some(false));
        assert_eq!(consent_answer(&Said::Closed(1)), None);
        assert_eq!(consent_answer(&Said::Closed(3)), None);
        assert_eq!(consent_answer(&Said::Action("default".into())), None);
        // ⚠️ equality, never a prefix: "approve-all" is not "approve".
        assert_eq!(consent_answer(&Said::Action("approved".into())), None);
    }

    #[test]
    fn marked_lines_are_found_among_chatter() {
        assert_eq!(parse("ROOMLER_NOTIFY_SHOWN:17"), Some(Said::Shown));
        assert_eq!(
            parse("  ROOMLER_NOTIFY_ACTION:deny\n"),
            Some(Said::Action("deny".into()))
        );
        assert_eq!(parse("ROOMLER_NOTIFY_CLOSED:2"), Some(Said::Closed(2)));
        assert_eq!(parse("ROOMLER_NOTIFY_CLOSED:x"), Some(Said::Closed(4)));
        assert_eq!(
            parse("ROOMLER_NOTIFY_FAILED:no buttons"),
            Some(Said::Failed("no buttons".into()))
        );
        assert_eq!(parse("Gtk-WARNING: something"), None);
    }

    /// P6f — a command line or a name with `<`, `>` or `&` arrives as text on
    /// a server that reads markup.
    #[test]
    fn markup_is_escaped() {
        assert_eq!(
            escape_markup("cat </etc/hosts && echo <b>x</b>"),
            "cat &lt;/etc/hosts &amp;&amp; echo &lt;b&gt;x&lt;/b&gt;"
        );
    }

    #[test]
    fn the_request_survives_the_pipe() {
        let now = Instant::now();
        let r = consent_request(&view(now, "", "", "VIEW", Duration::from_secs(60)), now);
        let back: Request = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
}
