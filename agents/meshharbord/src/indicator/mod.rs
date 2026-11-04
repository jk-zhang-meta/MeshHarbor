// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Viewer-indicator overlay.
//!
//! When a remote-control session is active, the controlled host should
//! have a clear local signal that *someone is watching*. Parsec and
//! Moonlight both draw a thin colored border plus a caption listing the
//! active viewers; we copy that idea.
//!
//! The overlay is a topmost, transparent, click-through, always-on-top
//! window drawn on the agent's primary monitor. Two critical Windows
//! properties keep the overlay useful:
//!
//! - `WDA_EXCLUDEFROMCAPTURE` via `SetWindowDisplayAffinity` — DWM
//!   composites the overlay on the local screen but omits it from any
//!   capture API (DXGI desktop duplication, Windows.Graphics.Capture,
//!   BitBlt from the virtual screen). That means the overlay is visible
//!   to the person in front of the controlled PC but is invisible in
//!   the RTP video going back to the controller, so the two parties
//!   don't end up staring at a recursive red picture-frame.
//!
//! - `WS_EX_TRANSPARENT | WS_EX_NOACTIVATE` — mouse input falls through
//!   to whatever window is underneath, and activation focus isn't
//!   stolen from e.g. the game or terminal the user was working in.
//!
//! Non-Windows builds stub the whole module to a no-op so the call
//! sites in signalling don't need `#[cfg]`. A future PR can add an
//! X11 / Wayland / Cocoa implementation.

use anyhow::Result;

/// Channel the overlay's "Disconnect" control uses to ask the signaling
/// loop to tear down a session, identified by its `ObjectId`. Created
/// once in `run()` and handed to [`ViewerIndicator::new`]; the receiver
/// is polled by `connect_once`'s `select!`. `run()` retains its own
/// clone so the channel never fully closes (which would busy-spin the
/// select!) even when the overlay is disabled.
pub type KillSender = tokio::sync::mpsc::Sender<bson::oid::ObjectId>;

/// FR-27 — where an operator's Approve/Deny click on a NATIVE prompt comes
/// back: `(session hex, allowed)`.
///
/// The backend does not resolve consent itself. It hands the answer here, the
/// signalling loop feeds it to `ConsentBroker::record_decision`, and the broker
/// applies the gate it already has — a decision counts only as an answer to a
/// question it is actively asking. One resolution point for the native panel,
/// the companion and the CLI alike; three would be three chances to disagree
/// about whether a session was approved.
pub type ConsentSender = tokio::sync::mpsc::Sender<(String, bool)>;

/// FR-27 — one consent question, as a native surface needs to draw it.
///
/// Deliberately pre-rendered strings rather than the wire types: a window
/// procedure running on a Win32 pump thread (or an X11 event loop, or the
/// AppKit main thread) should be laying out text, not reasoning about
/// `Permissions` bitflags or which subsystem asked.
#[derive(Clone, Debug)]
pub struct PromptView {
    pub session_hex: String,
    /// "Remote control request" / "Command execution request" / …
    pub title: String,
    /// "Alice is requesting to control this device."
    pub lead: String,
    /// The redacted command for `exec`, the activity for `ssh`; empty for rc.
    pub detail: String,
    /// Pipe-separated permission names; empty for exec/ssh.
    pub permissions: String,
    /// Asking organization on a multi-org device; empty otherwise.
    pub org: String,
    /// When the prompt stops mattering — so the panel can count down against
    /// the real deadline rather than one it started itself.
    pub expires_at: std::time::Instant,
}

/// FR-85 P3 — where a recording in progress is shown on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingShown {
    /// The daemon's own badge draws it (Windows, capture-excluded, pinned
    /// open while recording).
    pub native: bool,
    /// The session registry carries it, so the desktop companion's banner
    /// can show it — if the companion is running, which is the caller's to
    /// ensure (`companion::ensure_running`).
    pub listed: bool,
}

/// A handle to the viewer-indicator worker. Cheap to clone; multiple
/// sessions sharing one handle is the common case (one worker, many
/// concurrent sessions → one combined label).
#[derive(Clone)]
pub struct ViewerIndicator {
    inner: Inner,
    /// FR-27 — the LocalAPI-visible mirror of what this overlay shows.
    ///
    /// Maintained HERE rather than at the signalling call sites because
    /// `show_session` / `hide_session` already are the session lifecycle, and
    /// there are four of them: keeping the registry in step by hand would be
    /// four chances to drift, and a banner that outlives its session is worse
    /// than no banner.
    registry: crate::rc_sessions::RcSessionRegistry,
    /// The channel a registry-driven Disconnect fires through — the same one
    /// the native overlay's own button uses, so both take one teardown path.
    kill_tx: Option<KillSender>,
    /// FR-85 P3b-3 — the sessions whose recording is running, and whether
    /// each one's SESSION has already ended (`true`: the banner is kept only
    /// for the recording's re-attach grace). Kept here, not read back from
    /// the registry or the native badge, because either may lack the entry.
    recordings:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<bson::oid::ObjectId, bool>>>,
    /// FR-93 P6f — the consent questions on screen as desktop notifications.
    /// `None` on a handle built by [`Self::disabled`]: it has no
    /// `ConsentSender` for an answer to go to.
    #[cfg(all(target_os = "linux", feature = "portal-capture"))]
    notify: Option<notify::Prompts>,
}

impl ViewerIndicator {
    /// Spin up the worker. On Windows with the `viewer-indicator`
    /// feature this creates a background thread that owns a layered,
    /// click-through overlay window (a thin always-on border) plus a
    /// reveal-on-hover badge carrying the viewer's initials + a
    /// "Disconnect" control that fires through `kill_tx`. Everywhere
    /// else this is a no-op constructor — the returned handle accepts
    /// `show_session` / `hide_session` calls and drops them.
    pub fn new(
        kill_tx: KillSender,
        registry: crate::rc_sessions::RcSessionRegistry,
        consent_tx: ConsentSender,
    ) -> Result<Self> {
        Ok(Self {
            #[cfg(all(target_os = "linux", feature = "portal-capture"))]
            notify: Some(notify::Prompts::new(consent_tx.clone())),
            inner: Inner::new(kill_tx.clone(), consent_tx)?,
            registry,
            kill_tx: Some(kill_tx),
            recordings: Default::default(),
        })
    }

    /// Explicitly-disabled handle. Callers that can't bring the overlay
    /// up (init failed, headless CI, etc.) can use this so the rest of
    /// the code stays oblivious. Equivalent to `new()` on non-Windows.
    pub fn disabled() -> Self {
        Self {
            inner: Inner::disabled(),
            // A disabled OVERLAY is not a disabled session list. Everything
            // outside Windows lands here today, and those are exactly the
            // hosts whose only banner is the companion's — reading an empty
            // registry there would be the bug, not the safe default.
            registry: crate::rc_sessions::RcSessionRegistry::new(),
            kill_tx: None,
            recordings: Default::default(),
            #[cfg(all(target_os = "linux", feature = "portal-capture"))]
            notify: None,
        }
    }

    /// FR-27 — attach the shared registry + kill channel to a handle built by
    /// [`Self::disabled`].
    ///
    /// The two capabilities are independent and were conflated: "no native
    /// overlay on this platform" is the NORMAL state on macOS and Linux, and
    /// it must not also mean "this device cannot report who is viewing it".
    pub fn with_registry(
        mut self,
        kill_tx: KillSender,
        registry: crate::rc_sessions::RcSessionRegistry,
    ) -> Self {
        self.registry = registry;
        self.kill_tx = Some(kill_tx);
        self
    }

    /// FR-93 P6c — the session registry this handle keeps, so a media pump
    /// can end a session the way its Disconnect does: a session's entry
    /// carries its own loop's kill channel.
    pub fn sessions(&self) -> &crate::rc_sessions::RcSessionRegistry {
        &self.registry
    }

    /// Announce that a session has started. The overlay redraws to
    /// include `controller_name` in its caption. Safe to call multiple
    /// times with the same `session_id` (idempotent — the name is
    /// replaced rather than appended).
    pub fn show_session(&self, session_id: String, controller_name: String) {
        self.inner.show(session_id.clone(), controller_name);
    }

    /// FR-27 — the registry-aware form. Same lifecycle point as
    /// [`Self::show_session`], plus the fields a remote banner needs (the
    /// grant, the asking org) and the kill channel its Disconnect fires
    /// through. Callers with that context should prefer it.
    pub fn show_session_full(
        &self,
        session_id: bson::oid::ObjectId,
        controller_name: String,
        permissions: String,
        org: String,
    ) {
        self.inner
            .show(session_id.to_hex(), controller_name.clone());
        if let Some(kill) = &self.kill_tx {
            self.registry
                .insert(session_id, controller_name, permissions, org, kill.clone());
        }
        // FR-99 P3 — the same lifecycle point decides whether this session's
        // end locks the computer (what `auto` needs is read now).
        crate::lock_on_end::session_started(session_id);
    }

    /// FR-27 — put a consent question on this device's screen, natively.
    ///
    /// Returns `false` when this build/platform/session has no native surface
    /// — which is the ordinary answer on a headless host, under a root daemon
    /// with no `DISPLAY` (a Wayland desktop's per-user daemon shows the X11
    /// panel through Xwayland, `x11.rs`), and in a build without the per-OS
    /// feature. The caller then falls back
    /// to the desktop companion, and only reports `no_prompt_surface` when
    /// that fails too.
    ///
    /// Answers arrive on the `ConsentSender` given at construction, never by
    /// resolving consent here: the broker stays the single decision point.
    pub fn show_prompt(&self, view: PromptView) -> bool {
        self.inner.prompt(view)
    }

    /// FR-93 P6f — the last on-screen surface: the question as a desktop
    /// notification with Approve and Deny, for a host where neither the native
    /// panel nor the desktop companion could show it (a system daemon under
    /// GNOME or KDE Wayland with no companion package). `false` where there is
    /// none: no graphical session, a notification server without buttons,
    /// another OS, `ROOMLERD_NOTIFY_CONSENT=0`.
    ///
    /// Answers arrive on the same `ConsentSender` as the native panel's, and
    /// [`Self::hide_prompt`] takes it down.
    pub async fn show_notification_prompt(&self, view: PromptView) -> bool {
        #[cfg(all(target_os = "linux", feature = "portal-capture"))]
        {
            let Some(n) = self.notify.clone() else {
                return false;
            };
            // Posting waits for the session helper's first line; off the
            // runtime's threads.
            tokio::task::spawn_blocking(move || n.show(&view))
                .await
                .unwrap_or(false)
        }
        #[cfg(not(all(target_os = "linux", feature = "portal-capture")))]
        {
            let _ = view;
            false
        }
    }

    /// Take a consent prompt down — it was answered, timed out, or resolved
    /// somewhere else (the CLI, the companion, an emailed link). Idempotent.
    pub fn hide_prompt(&self, session_hex: &str) {
        self.inner.dismiss(session_hex);
        #[cfg(all(target_os = "linux", feature = "portal-capture"))]
        if let Some(n) = &self.notify {
            n.dismiss(session_hex);
        }
    }

    /// FR-85 P3 — mark `session_id` as recording (or not) on every surface
    /// this daemon has, and say which of them can SHOW it. A remote
    /// recording starts only behind one of them: the person at the device
    /// must be told before the first frame is written.
    pub fn set_recording(
        &self,
        session_id: bson::oid::ObjectId,
        recording: bool,
    ) -> RecordingShown {
        if let Ok(mut r) = self.recordings.lock() {
            if recording {
                r.insert(session_id, false);
            } else {
                r.remove(&session_id);
            }
        }
        RecordingShown {
            native: self.inner.set_recording(&session_id.to_hex(), recording),
            listed: self.registry.set_recording(&session_id, recording),
        }
    }

    /// FR-99 — put `session_id`'s privacy curtain up (`on`) or take it down.
    /// `true` only when the curtain is UP and out of every capture path; the
    /// overlay checks the affinity after setting it rather than trusting the
    /// call. Blocks until the overlay has answered (at most about two
    /// seconds), so callers stay off the runtime's threads. A session the
    /// overlay does not carry gets no curtain, and its end
    /// ([`Self::hide_session`]) always takes the curtain down.
    pub fn set_privacy(
        &self,
        session_id: bson::oid::ObjectId,
        on: bool,
        controller_name: &str,
    ) -> bool {
        self.inner
            .set_privacy(&session_id.to_hex(), on, controller_name)
    }

    /// Announce that a session has ended. When the last session drops,
    /// the overlay is hidden.
    ///
    /// ⚠️ FR-85 P3b-3 — NOT while the session is recording. Its recording
    /// outlives it for the re-attach grace, and nothing may stop saying
    /// "recording" while a recording runs: the banner (native and listed)
    /// stays, marked reconnecting, until [`Self::end_recording`].
    pub fn hide_session(&self, session_id: String) {
        // FR-93 P6g — a being-viewed notification comes down with its session,
        // a recording's grace or not: nobody is viewing any more.
        #[cfg(all(target_os = "linux", feature = "portal-capture"))]
        if let Ok(oid) = bson::oid::ObjectId::parse_str(&session_id) {
            notify::viewing_ended(&oid);
        }
        if let Ok(oid) = bson::oid::ObjectId::parse_str(&session_id) {
            // FR-99 P3 — the session is over whether or not a recording keeps
            // its banner: the last end locks, when the decisions say so.
            crate::lock_on_end::session_ended(oid);
            let recording = self
                .recordings
                .lock()
                .ok()
                .and_then(|mut r| r.get_mut(&oid).map(|detached| *detached = true))
                .is_some();
            if recording {
                self.registry.session_ended(&oid);
                return;
            }
            self.registry.remove(&oid);
        }
        self.inner.hide(session_id);
    }

    /// FR-85 P3b-3 — the recording of `session_id` ended, or moved to its
    /// controller's next session. Nothing says "recording" for it any more,
    /// and a banner that was kept only for the recording (its session
    /// already gone) comes down. On a live session this is exactly
    /// `set_recording(session_id, false)`.
    pub fn end_recording(&self, session_id: bson::oid::ObjectId) {
        let detached = self
            .recordings
            .lock()
            .ok()
            .and_then(|mut r| r.remove(&session_id))
            .unwrap_or(false);
        self.inner.set_recording(&session_id.to_hex(), false);
        self.registry.recording_ended(&session_id);
        if detached {
            self.inner.hide(session_id.to_hex());
        }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific inner. The stub is used on non-Windows and when the
// `viewer-indicator` feature is disabled; the real impl is in
// `indicator::win`.

#[cfg(all(target_os = "windows", feature = "viewer-indicator"))]
mod win;

#[cfg(all(target_os = "windows", feature = "viewer-indicator"))]
use win::Inner;

/// FR-27 — the X11 consent panel. PROMPT ONLY: the "being viewed" banner on
/// Linux stays with the desktop companion, which already provides it.
#[cfg(all(target_os = "linux", feature = "viewer-indicator-x11"))]
mod x11;

/// FR-27 — the macOS consent panel. Prompt only, same split as X11.
///
/// `pub` because `main.rs` calls [`mac::run_main_loop`]: the main thread has
/// to be handed to AppKit before the daemon starts, and that decision belongs
/// at the process entry point, not buried in an overlay module.
#[cfg(all(target_os = "macos", feature = "viewer-indicator-macos"))]
pub mod mac;

/// FR-93 P6f — the desktop's notifications as the last consent surface, where
/// neither the native panel nor the companion can show a question. `pub`
/// because `main.rs` runs its session helper (`portal-helper --notify`).
#[cfg(all(target_os = "linux", feature = "portal-capture"))]
pub mod notify;

/// Non-Windows fallback. Delegates the PROMPT to a per-OS backend where one is
/// built in and can start; everything else is a no-op, because the banner on
/// those platforms is the companion's.
///
/// `Option`, not a bool: "this build has an X11 backend" and "that backend
/// actually connected to a display" are different questions, and only the
/// second one decides whether a human can be shown anything. A root systemd
/// daemon has the code compiled in and no display to use it on.
/// The native panel for THIS build. Exactly one of the three aliases below is
/// live, so `Inner`'s own methods carry no `cfg` at all — the platform choice
/// is made once, here, instead of being re-derived at every call site.
#[cfg(all(target_os = "linux", feature = "viewer-indicator-x11"))]
type NativePanel = x11::Inner;
#[cfg(all(target_os = "macos", feature = "viewer-indicator-macos"))]
type NativePanel = mac::Inner;
#[cfg(not(any(
    all(target_os = "windows", feature = "viewer-indicator"),
    all(target_os = "linux", feature = "viewer-indicator-x11"),
    all(target_os = "macos", feature = "viewer-indicator-macos")
)))]
type NativePanel = NoPanel;

/// "This build has no native panel" — a backend that declines to construct.
///
/// Declining rather than existing-and-doing-nothing is the point: `Inner`
/// stores `Option<NativePanel>`, so a refusal here is indistinguishable from
/// an X11 backend that found no display, and both route the caller to the
/// companion by the same path. One code shape, no special case.
#[cfg(not(any(
    all(target_os = "windows", feature = "viewer-indicator"),
    all(target_os = "linux", feature = "viewer-indicator-x11"),
    all(target_os = "macos", feature = "viewer-indicator-macos")
)))]
#[derive(Clone)]
struct NoPanel;

#[cfg(not(any(
    all(target_os = "windows", feature = "viewer-indicator"),
    all(target_os = "linux", feature = "viewer-indicator-x11"),
    all(target_os = "macos", feature = "viewer-indicator-macos")
)))]
impl NoPanel {
    fn new(_consent_tx: ConsentSender) -> Result<Self> {
        Err(anyhow::anyhow!(
            "this build has no native consent panel for the current platform"
        ))
    }
    fn prompt(&self, _view: PromptView) -> bool {
        false
    }
    fn dismiss(&self, _session_hex: &str) {}
}

#[cfg(not(all(target_os = "windows", feature = "viewer-indicator")))]
#[derive(Clone, Default)]
struct Inner {
    /// `None` = no native panel on this host. NOT the same as "this build has
    /// none": an X11 backend that found no display lands here too, and both
    /// mean the same thing to the caller.
    native: Option<NativePanel>,
}

#[cfg(not(all(target_os = "windows", feature = "viewer-indicator")))]
impl Inner {
    fn new(_kill_tx: KillSender, consent_tx: ConsentSender) -> Result<Self> {
        // The kill sender is dropped where there is no native banner: `run()`
        // retains its own clone to keep the channel open, so the signaling
        // `select!` never busy-spins on a fully-closed receiver.
        let native = match NativePanel::new(consent_tx) {
            Ok(v) => Some(v),
            // Never propagated. No display is the NORMAL state for a root
            // daemon and for every headless node, and failing construction
            // here would take the session registry down with it. Log at INFO —
            // an operator debugging "the prompt never appeared" needs this
            // line — and let the caller fall back to the companion.
            Err(e) => {
                tracing::info!(
                    error = %format!("{e:#}"),
                    "no native consent panel on this host — prompts go to the desktop companion"
                );
                None
            }
        };
        Ok(Self { native })
    }
    fn disabled() -> Self {
        Self::default()
    }
    fn show(&self, _session_id: String, _controller_name: String) {}
    fn hide(&self, _session_id: String) {}
    /// No native banner outside Windows: the companion's is the surface.
    fn set_recording(&self, _session_id: &str, _recording: bool) -> bool {
        false
    }
    /// FR-99 — no curtain outside Windows: macOS has no public way to keep
    /// a window out of capture, and X11 / Wayland are out of scope.
    fn set_privacy(&self, _session_id: &str, _on: bool, _controller_name: &str) -> bool {
        false
    }
    /// `false` here is what routes the caller to the companion — never a
    /// swallowed prompt.
    fn prompt(&self, view: PromptView) -> bool {
        self.native.as_ref().is_some_and(|n| n.prompt(view))
    }
    fn dismiss(&self, session_hex: &str) {
        if let Some(n) = self.native.as_ref() {
            n.dismiss(session_hex);
        }
    }
}

/// Compute a 1–2 character initials label from a controller's display
/// name for the overlay badge. "Goran Jovanov" → "GJ", "gjovanov" →
/// "GJ", "alice" → "AL", "" → "?". Splits on whitespace + common
/// separators, takes the first letter of the first two tokens (or the
/// The consent countdown, human-readable. `"30s"` under a minute, `"4:47"`
/// above it — because the plain-`prompt` window is now 5 min (a locked host,
/// FR-34 #917), and "Expires in 287s" reads far worse than "Expires in 4:47".
/// Pure + platform-agnostic, shared by all three native panels (win/x11/mac).
#[cfg_attr(
    not(any(
        all(target_os = "windows", feature = "viewer-indicator"),
        all(target_os = "linux", feature = "viewer-indicator-x11"),
        all(target_os = "macos", feature = "viewer-indicator-macos"),
    )),
    allow(dead_code)
)]
pub(crate) fn format_countdown(secs: u64) -> String {
    if secs >= 60 {
        format!("{}:{:02}", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// first two letters of a single token), uppercased. Pure + platform-
/// agnostic so it's unit-tested in the default CI.
#[cfg_attr(
    not(all(target_os = "windows", feature = "viewer-indicator")),
    allow(dead_code)
)]
pub(crate) fn initials_of(name: &str) -> String {
    let tokens: Vec<&str> = name
        .split(|c: char| c.is_whitespace() || matches!(c, '.' | '_' | '-' | ','))
        .filter(|t| !t.is_empty())
        .collect();
    let mut out = String::new();
    match tokens.as_slice() {
        [] => {}
        [single] => {
            for c in single.chars().take(2) {
                out.extend(c.to_uppercase());
            }
        }
        [first, second, ..] => {
            if let Some(c) = first.chars().next() {
                out.extend(c.to_uppercase());
            }
            if let Some(c) = second.chars().next() {
                out.extend(c.to_uppercase());
            }
        }
    }
    if out.is_empty() {
        out.push('?');
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn format_countdown_reads_as_mmss_above_a_minute() {
        use super::format_countdown;
        assert_eq!(format_countdown(30), "30s");
        assert_eq!(format_countdown(59), "59s");
        assert_eq!(format_countdown(60), "1:00");
        assert_eq!(format_countdown(287), "4:47");
        assert_eq!(format_countdown(300), "5:00");
        assert_eq!(format_countdown(0), "0s");
    }

    use super::initials_of;

    #[test]
    fn initials_two_tokens() {
        assert_eq!(initials_of("Goran Jovanov"), "GJ");
        assert_eq!(initials_of("goran jovanov"), "GJ");
    }

    #[test]
    fn initials_separators() {
        assert_eq!(initials_of("goran.jovanov"), "GJ");
        assert_eq!(initials_of("goran_jovanov"), "GJ");
        assert_eq!(initials_of("goran-jovanov"), "GJ");
    }

    #[test]
    fn initials_single_token() {
        assert_eq!(initials_of("gjovanov"), "GJ");
        assert_eq!(initials_of("alice"), "AL");
        assert_eq!(initials_of("x"), "X");
    }

    #[test]
    fn initials_three_tokens_uses_first_two() {
        assert_eq!(initials_of("Jean Luc Picard"), "JL");
    }

    #[test]
    fn initials_empty_is_placeholder() {
        assert_eq!(initials_of(""), "?");
        assert_eq!(initials_of("   "), "?");
    }

    fn with_banner() -> (
        super::ViewerIndicator,
        crate::rc_sessions::RcSessionRegistry,
    ) {
        let registry = crate::rc_sessions::RcSessionRegistry::new();
        let (kill, _rx) = tokio::sync::mpsc::channel(4);
        let ind = super::ViewerIndicator::disabled().with_registry(kill, registry.clone());
        (ind, registry)
    }

    /// FR-85 P3b-3 — the signalling loop hides a session the moment it ends,
    /// but a session that is RECORDING keeps its banner (reconnecting) for as
    /// long as its recording lasts: a recording is never unseen. The banner
    /// comes down with the recording.
    #[test]
    fn a_recording_sessions_banner_outlives_the_session_until_the_recording_ends() {
        let (ind, reg) = with_banner();
        let (a, b) = (bson::oid::ObjectId::new(), bson::oid::ObjectId::new());
        ind.show_session_full(a, "Rec".into(), "VIEW | RECORD".into(), String::new());
        ind.show_session_full(b, "Watch".into(), "VIEW".into(), String::new());
        assert!(ind.set_recording(a, true).listed);

        ind.hide_session(b.to_hex());
        ind.hide_session(a.to_hex());
        let listed = reg.list();
        assert_eq!(
            listed.len(),
            1,
            "the watcher went, the recording stayed: {listed:?}"
        );
        assert_eq!(listed[0].session_id, a.to_hex());
        assert!(listed[0].recording && listed[0].reconnecting);

        ind.end_recording(a);
        assert!(
            reg.list().is_empty(),
            "the kept banner outlived its recording"
        );
    }

    /// The same end on a LIVE session only clears "recording"; the session's
    /// banner stays for as long as the session does, and then goes as usual.
    #[test]
    fn a_recording_that_ends_on_a_live_session_keeps_the_session_on_screen() {
        let (ind, reg) = with_banner();
        let a = bson::oid::ObjectId::new();
        ind.show_session_full(a, "Rec".into(), "VIEW | RECORD".into(), String::new());
        ind.set_recording(a, true);
        ind.end_recording(a);
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].recording && !listed[0].reconnecting);
        ind.hide_session(a.to_hex());
        assert!(reg.list().is_empty());
    }
}
