// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P6 (multi-org program) — the InputArbiter: ONE injection worker for all
//! concurrent remote-control sessions.
//!
//! Pre-P6 every session ran its own `InputInjector` on its own tokio task:
//! two typing users interleaved raw `SendInput` streams on the host's ONE
//! modifier plane (A holding Shift turned B's clicks into Shift-clicks),
//! and nothing released a session's held keys when it died mid-chord. The
//! server compensated with the P3 single-INPUT-holder rule.
//!
//! The arbiter replaces that with TeamViewer-style **free-for-all +
//! fencing** (the program's decided default):
//!
//!   * every event flows through one worker thread that owns the single
//!     OS injector — per-session streams are serialized, never interleaved;
//!   * per-session held state (keys + mouse buttons) is tracked from the
//!     event stream; **switching injecting sessions fences modifiers**: the
//!     previous sessions' held modifier keys (HID `0xe0..=0xe7`) are
//!     released before the new session's event injects, so one user's held
//!     Ctrl can never contaminate another's click (the cross-session
//!     generalisation of the #306 text-vs-modifier transition planner);
//!   * **release-all on teardown**: a session's every held key/button is
//!     released when it closes (browser crash, tab kill, watchdog) — the
//!     precise superset of the 2026-08-04 blanket modifier release;
//!   * an **exclusive** mode (single INPUT holder with explicit floor
//!     control) selectable per device via `AccessPolicy.input_mode` and
//!     in-session via the control DC. Floor requests auto-transfer when
//!     the current holder has been input-idle ≥ [`IDLE_TAKEOVER`].
//!
//! The worker also owns the multi-user UX fan-out:
//!   * `rc:control.state` on every session's control DC whenever
//!     membership / mode / holder changes (the viewer's participants rail
//!     + request-control UX), and
//!   * **ghost cursors**: each session's pointer position is rebroadcast
//!     (throttled to ~[`GHOST_MIN_INTERVAL`]) to every OTHER session's
//!     cursor DC as `cursor:peer`, name-tagged.
//!
//! Split for testability: [`ArbiterState`] is a pure state machine
//! (returns *plans* — what to inject / whether to broadcast) with zero
//! DC / OS / tokio types, unit-tested on the default build; the worker
//! layer executes plans against the real injector and the DC stashes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use webrtc::data_channel::RTCDataChannel;

use super::{Button, InputMsg};

/// HID usage codes for the 8 modifier keys (L/R Ctrl, Shift, Alt, Meta) —
/// the set the cross-session fence releases.
pub const MODIFIER_CODES: std::ops::RangeInclusive<u32> = 0xe0..=0xe7;

/// A floor request against a holder who has produced no input for this
/// long is auto-granted (walk-away takeover); an ACTIVE holder keeps the
/// floor and the requester is told who has it.
pub const IDLE_TAKEOVER: Duration = Duration::from_secs(2);

/// Per-source ghost-cursor rebroadcast floor (~30 Hz).
pub const GHOST_MIN_INTERVAL: Duration = Duration::from_millis(33);

/// Field diagnostic — ghost-cursor payloads handed to the DC layer since
/// process start (see the log in `ghost_broadcast`).
static GHOSTS_SENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Input arbitration mode. `Free` (the program's decided default) lets
/// every INPUT-granted session inject, serialized + modifier-fenced;
/// `Exclusive` funnels injection through one floor holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Free,
    Exclusive,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "free" => Some(Mode::Free),
            "exclusive" => Some(Mode::Exclusive),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Free => "free",
            Mode::Exclusive => "exclusive",
        }
    }
}

/// One held thing — a key (HID code) or a mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Held {
    Key(u32),
    Btn(Button),
}

impl Held {
    fn release_msg(&self) -> InputMsg {
        match *self {
            Held::Key(code) => InputMsg::Key {
                code,
                down: false,
                mods: 0,
            },
            // #1945 — never a `MouseButton` up: that carries a position, and
            // every backend moves there first. The (0,0) this used to send
            // was GNOME's Activities hot corner, and the end of the drag.
            Held::Btn(btn) => InputMsg::MouseRelease { btn },
        }
    }
    fn is_modifier(&self) -> bool {
        matches!(*self, Held::Key(code) if MODIFIER_CODES.contains(&code))
    }
}

struct SessCore {
    name: String,
    /// The session's INPUT grant (rail display + a defense-in-depth inject
    /// gate behind the per-DC enforcement).
    can_input: bool,
    held: HashSet<Held>,
    last_input: Instant,
}

/// FR-92 — why a session may not switch keep-busy on or off. (An org's
/// deny is not here: it is device-wide — the strictest of every enrolled
/// org — and the engine itself refuses, with `org_denied`, whoever asks.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepBusyRefusal {
    /// Not a registered session (already closed).
    Unknown,
    /// The session holds no INPUT grant — keep-busy is input.
    NoInput,
    /// Exclusive mode, and another session holds the floor.
    NotFloorHolder,
}

impl KeepBusyRefusal {
    pub fn wire(self) -> &'static str {
        match self {
            KeepBusyRefusal::Unknown => "unknown_session",
            KeepBusyRefusal::NoInput => "no_input_permission",
            KeepBusyRefusal::NotFloorHolder => "not_floor_holder",
        }
    }
}

/// What the worker should do with one event.
#[derive(Debug, PartialEq)]
pub enum EventPlan {
    /// Floor-denied (exclusive mode, not the holder) or no INPUT grant.
    Deny,
    /// Inject `pre` (fence releases) then the event itself.
    Inject { pre: Vec<InputMsg> },
}

/// Pure decision core. All methods take `now` so tests inject time.
pub struct ArbiterState {
    mode: Mode,
    /// Exclusive-mode floor holder.
    holder: Option<ObjectId>,
    /// Which session injected last — the fence trigger edge.
    last_injector: Option<ObjectId>,
    /// Whether the device-policy mode hint was already applied (first
    /// session only; later joins must not stomp an in-session toggle).
    ///
    /// FR-27 — CLEARED when the last session leaves. Before that it was set
    /// once for the life of the daemon, so an in-session toggle outlived every
    /// session that could have justified it: set a device to `exclusive`, let
    /// one viewer flip it to `free`, let everyone disconnect, and the next
    /// session still came up `free` — the device policy silently stopped
    /// applying until the daemon restarted. "Later joins must not stomp a
    /// toggle" is about a LIVE conversation between concurrent viewers; with
    /// nobody left there is no conversation to preserve.
    mode_seeded: bool,
    /// FR-27 — an outstanding exclusive-mode floor request, when the holder
    /// was active and the request could not be auto-granted.
    ///
    /// `request_floor` used to just return `false` and drop it: the holder
    /// never learned anyone had asked, and the requester saw nothing at all,
    /// so "Request control" looked broken unless you happened to click it
    /// during the holder's idle window. Carried in the snapshot so both ends
    /// can render it.
    pending_request: Option<ObjectId>,
    sessions: HashMap<ObjectId, SessCore>,
}

/// Broadcast-ready snapshot of the arbiter state.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub mode: Mode,
    pub holder: Option<ObjectId>,
    pub participants: Vec<Participant>,
    /// FR-27 — who is waiting for the floor, if anyone. `None` in free mode
    /// and whenever nothing is outstanding.
    pub pending_request: Option<Participant>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Participant {
    pub session: ObjectId,
    pub name: String,
    pub input: bool,
}

impl Default for ArbiterState {
    fn default() -> Self {
        Self {
            mode: Mode::Free,
            holder: None,
            last_injector: None,
            mode_seeded: false,
            pending_request: None,
            sessions: HashMap::new(),
        }
    }
}

impl ArbiterState {
    /// Register a session. `mode_hint` = the device's `AccessPolicy.input_mode`
    /// (server-resolved) — applied only while no session has toggled the mode.
    /// In exclusive mode the first INPUT-capable session becomes the holder.
    pub fn open(
        &mut self,
        session: ObjectId,
        name: String,
        can_input: bool,
        mode_hint: Option<Mode>,
        now: Instant,
    ) {
        if !self.mode_seeded {
            if let Some(m) = mode_hint {
                self.mode = m;
            }
            self.mode_seeded = true;
        }
        self.sessions.insert(
            session,
            SessCore {
                name,
                can_input,
                held: HashSet::new(),
                last_input: now,
            },
        );
        if self.mode == Mode::Exclusive && self.holder.is_none() && can_input {
            self.holder = Some(session);
        }
    }

    /// FR-93 P4c — whether `session` is registered with an input grant.
    pub fn can_input(&self, session: ObjectId) -> bool {
        self.sessions.get(&session).is_some_and(|s| s.can_input)
    }

    /// Deregister a session. Returns the key/button releases to inject
    /// (its whole held set). Reassigns the exclusive holder if it left.
    pub fn close(&mut self, session: ObjectId) -> Vec<InputMsg> {
        let Some(core) = self.sessions.remove(&session) else {
            return Vec::new();
        };
        if self.last_injector == Some(session) {
            self.last_injector = None;
        }
        if self.pending_request == Some(session) {
            self.pending_request = None;
        }
        if self.holder == Some(session) {
            // Hand the floor to a remaining INPUT-capable session — the
            // LOWEST session id, not whatever `HashMap` iteration happened to
            // yield first. Two viewers watching the same handover should see
            // the same outcome, and a nondeterministic one is untestable.
            self.holder = self
                .sessions
                .iter()
                .filter(|(_, c)| c.can_input)
                .map(|(id, _)| *id)
                .min();
        }
        // FR-27 — with the last session gone there is no in-session decision
        // left to preserve, so let the device policy seed the next one. See
        // the field on `mode_seeded`.
        if self.sessions.is_empty() {
            self.mode_seeded = false;
            self.pending_request = None;
        }
        core.held.iter().map(Held::release_msg).collect()
    }

    /// Release everything one session holds WITHOUT deregistering it — the
    /// input DC died (browser hiccup) but the session may live on.
    pub fn release_held(&mut self, session: ObjectId) -> Vec<InputMsg> {
        self.sessions
            .get_mut(&session)
            .map(|c| {
                let r: Vec<InputMsg> = c.held.iter().map(Held::release_msg).collect();
                c.held.clear();
                r
            })
            .unwrap_or_default()
    }

    /// Decide one event. Tracks held state, applies the exclusive floor,
    /// and plans cross-session modifier fencing on injector switch.
    pub fn plan(&mut self, session: ObjectId, msg: &InputMsg, now: Instant) -> EventPlan {
        // Heartbeats carry no input; pass them through un-fenced so their
        // timing diagnostics stay honest.
        if matches!(msg, InputMsg::Heartbeat { .. }) {
            return EventPlan::Inject { pre: Vec::new() };
        }
        let can_input = self
            .sessions
            .get(&session)
            .map(|c| c.can_input)
            .unwrap_or(false);
        if !can_input {
            return EventPlan::Deny;
        }
        if self.mode == Mode::Exclusive {
            if self.holder.is_none() {
                // No holder yet (e.g. mode toggled with none) — first event wins.
                self.holder = Some(session);
            }
            if self.holder != Some(session) {
                return EventPlan::Deny;
            }
        }

        // Fence: the injecting session changed — release every OTHER
        // session's held MODIFIERS so their chords can't contaminate this
        // event (their own eventual key-ups become OS-level no-ops).
        let mut pre = Vec::new();
        if self.last_injector != Some(session) {
            for (id, core) in self.sessions.iter_mut() {
                if *id == session {
                    continue;
                }
                let mods: Vec<Held> = core
                    .held
                    .iter()
                    .filter(|h| h.is_modifier())
                    .copied()
                    .collect();
                for m in mods {
                    core.held.remove(&m);
                    pre.push(m.release_msg());
                }
            }
            self.last_injector = Some(session);
        }

        // Held-state tracking for THIS session.
        if let Some(core) = self.sessions.get_mut(&session) {
            core.last_input = now;
            match msg {
                InputMsg::Key { code, down, .. } => {
                    if *down {
                        core.held.insert(Held::Key(*code));
                    } else {
                        core.held.remove(&Held::Key(*code));
                    }
                }
                InputMsg::MouseButton { btn, down, .. } => {
                    if *down {
                        core.held.insert(Held::Btn(*btn));
                    } else {
                        core.held.remove(&Held::Btn(*btn));
                    }
                }
                InputMsg::MouseRelease { btn } => {
                    core.held.remove(&Held::Btn(*btn));
                }
                // FR-109 — relative mode presses where the pointer is. It is
                // held like any press, so a session that ends mid-drag still
                // has its button released.
                InputMsg::MousePress { btn } => {
                    core.held.insert(Held::Btn(*btn));
                }
                _ => {}
            }
        }
        EventPlan::Inject { pre }
    }

    /// Floor request. Returns `(granted, releases)` — on a takeover the
    /// previous holder's held set is released (their chord is over).
    pub fn request_floor(&mut self, session: ObjectId, now: Instant) -> (bool, Vec<InputMsg>) {
        if self.mode == Mode::Free {
            // Nothing to hold in free mode — trivially granted.
            return (true, Vec::new());
        }
        if !self
            .sessions
            .get(&session)
            .map(|c| c.can_input)
            .unwrap_or(false)
        {
            return (false, Vec::new());
        }
        match self.holder {
            None => {
                self.holder = Some(session);
                self.pending_request = None;
                (true, Vec::new())
            }
            Some(h) if h == session => {
                self.pending_request = None;
                (true, Vec::new())
            }
            Some(h) => {
                let idle = self
                    .sessions
                    .get(&h)
                    .map(|c| now.duration_since(c.last_input) >= IDLE_TAKEOVER)
                    .unwrap_or(true);
                if idle {
                    let releases = self
                        .sessions
                        .get_mut(&h)
                        .map(|c| {
                            let r: Vec<InputMsg> = c.held.iter().map(Held::release_msg).collect();
                            c.held.clear();
                            r
                        })
                        .unwrap_or_default();
                    self.holder = Some(session);
                    self.pending_request = None;
                    (true, releases)
                } else {
                    // FR-27 — REMEMBER the refusal. Dropping it on the floor
                    // made "Request control" indistinguishable from a dead
                    // button: the holder was never told anyone wanted the
                    // floor, and the requester got no acknowledgement, so the
                    // only way to succeed was to happen to click during the
                    // holder's idle window. The snapshot broadcast that
                    // follows tells both ends.
                    self.pending_request = Some(session);
                    (false, Vec::new())
                }
            }
        }
    }

    /// FR-27 — the holder hands the floor over on request, without waiting for
    /// the idle timer. The courteous half of [`Self::request_floor`]: once you
    /// can SEE that someone is waiting, you need a way to say yes.
    ///
    /// Only the current holder may grant, and only to the session that
    /// actually asked — a stale click after the requester left, or after the
    /// floor moved, must not hand control to whoever asked last.
    pub fn grant_floor(&mut self, holder: ObjectId, to: ObjectId) -> (bool, Vec<InputMsg>) {
        if self.mode != Mode::Exclusive
            || self.holder != Some(holder)
            || self.pending_request != Some(to)
        {
            return (false, Vec::new());
        }
        if !self.sessions.get(&to).map(|c| c.can_input).unwrap_or(false) {
            self.pending_request = None;
            return (false, Vec::new());
        }
        let releases = self
            .sessions
            .get_mut(&holder)
            .map(|c| {
                let r: Vec<InputMsg> = c.held.iter().map(Held::release_msg).collect();
                c.held.clear();
                r
            })
            .unwrap_or_default();
        self.holder = Some(to);
        self.pending_request = None;
        (true, releases)
    }

    /// FR-27 — the holder declines, or the requester withdraws. Clearing the
    /// request is what stops a refused chip from sitting on the toolbar
    /// forever; the requester may always ask again.
    pub fn clear_floor_request(&mut self, by: ObjectId) -> bool {
        let mine = self.pending_request == Some(by);
        let im_the_holder = self.holder == Some(by);
        if self.pending_request.is_some() && (mine || im_the_holder) {
            self.pending_request = None;
            return true;
        }
        false
    }

    /// In-session mode toggle (INPUT-granted sessions only). Returns whether
    /// the mode actually changed. Flipping to exclusive makes the toggling
    /// session the holder; flipping to free clears the floor.
    pub fn set_mode(&mut self, session: ObjectId, mode: Mode) -> bool {
        if !self
            .sessions
            .get(&session)
            .map(|c| c.can_input)
            .unwrap_or(false)
        {
            return false;
        }
        self.mode_seeded = true;
        if self.mode == mode {
            return false;
        }
        self.mode = mode;
        self.holder = match mode {
            Mode::Exclusive => Some(session),
            Mode::Free => None,
        };
        // Either direction settles the floor, so nothing can still be waiting
        // for it: exclusive just handed it to the toggler, free abolished it.
        self.pending_request = None;
        true
    }

    /// FR-92 — is any session holding a mouse button? A keep-busy move
    /// spliced into a controller's drag would drag whatever they hold.
    pub fn any_button_held(&self) -> bool {
        self.sessions
            .values()
            .any(|c| c.held.iter().any(|h| matches!(h, Held::Btn(_))))
    }

    /// FR-92 — may `session` switch keep-busy on or off? The same bar as
    /// injecting: an INPUT grant, and the floor in exclusive mode. Returns
    /// the controller's display name for the `set_by` the host and the
    /// other viewers see.
    pub fn keep_busy_may_set(&self, session: ObjectId) -> Result<String, KeepBusyRefusal> {
        let core = self
            .sessions
            .get(&session)
            .ok_or(KeepBusyRefusal::Unknown)?;
        if !core.can_input {
            return Err(KeepBusyRefusal::NoInput);
        }
        if self.mode == Mode::Exclusive && self.holder.is_some_and(|h| h != session) {
            return Err(KeepBusyRefusal::NotFloorHolder);
        }
        Ok(core.name.clone())
    }

    pub fn snapshot(&self) -> Snapshot {
        let participant = |id: &ObjectId| -> Option<Participant> {
            self.sessions.get(id).map(|c| Participant {
                session: *id,
                name: c.name.clone(),
                input: c.can_input,
            })
        };
        let mut participants: Vec<Participant> =
            self.sessions.keys().filter_map(participant).collect();
        participants.sort_by_key(|p| p.session);
        Snapshot {
            mode: self.mode,
            holder: self.holder,
            participants,
            // Free mode has no floor, so a leftover request there would render
            // a "waiting for control" chip nobody can act on.
            pending_request: (self.mode == Mode::Exclusive)
                .then(|| self.pending_request.as_ref().and_then(participant))
                .flatten(),
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

// ─── Worker layer ───────────────────────────────────────────────────────

type DcStash = Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>;

enum Cmd {
    Open {
        session: ObjectId,
        name: String,
        can_input: bool,
        mode_hint: Option<Mode>,
        control: DcStash,
        cursor: DcStash,
    },
    Close {
        session: ObjectId,
    },
    ReleaseHeld {
        session: ObjectId,
    },
    /// P6 field fix — a session's control DC just OPENED. Registration
    /// happens at `AgentPeer::new`, before any DC exists, so the join-time
    /// `rc:control.state` broadcast found an empty stash and was dropped:
    /// followers never saw the participants rail (and in exclusive mode
    /// could not render the Request-control button). Re-broadcast now.
    ControlReady {
        session: ObjectId,
    },
    Event {
        session: ObjectId,
        msg: InputMsg,
    },
    RequestFloor {
        session: ObjectId,
    },
    /// FR-27 — the holder hands the floor to whoever is waiting.
    GrantFloor {
        holder: ObjectId,
        to: ObjectId,
    },
    /// FR-27 — the holder declines, or the requester withdraws.
    ClearFloorRequest {
        session: ObjectId,
    },
    SetMode {
        session: ObjectId,
        mode: Mode,
    },
    /// FR-92 — keep-busy's engine asks the ONE injector to read or move.
    KeepBusy(KbReq),
    /// FR-92 — a controller asked to switch keep-busy on or off; the
    /// arbiter holds the grant and the floor, so it decides.
    KeepBusySet {
        session: ObjectId,
        request: crate::keep_busy::SetRequest,
    },
    /// FR-97 P3e — a controller's `rc:layout.set`. Switching the host's
    /// layout changes what the person at it types, so it takes keep busy's
    /// rule: a session that may type, and in exclusive mode the floor holder.
    /// Before P3e the control arm switched for any session, a view-only one's
    /// included.
    #[cfg(all(
        any(target_os = "windows", target_os = "linux"),
        feature = "enigo-input"
    ))]
    LayoutSet {
        session: ObjectId,
        token: String,
    },
}

/// FR-92 — a keep-busy request, answered on `reply` from the arbiter thread
/// (where the one OS injector lives).
pub struct KbReq {
    pub op: KbOp,
    pub reply: std::sync::mpsc::SyncSender<KbReply>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbOp {
    /// The cursor, in desktop pixels.
    Locate,
    /// A real-input absolute move to desktop pixel `(x, y)`.
    Move { x: i32, y: i32 },
    /// FR-92 P9 — a real-input absolute move to `(x, y) / NORM_ONE` of the
    /// whole desktop, for a backend with no pixel space of its own (uinput).
    MoveNorm { x: u32, y: u32 },
    /// Is a physical mouse button held?
    Buttons,
}

/// [`KbOp::MoveNorm`]'s unit: `NORM_ONE` is the far edge of the desktop.
/// 2¹⁶ steps is finer than a pixel on any screen uinput's own 0..=32767
/// axis can address.
pub const NORM_ONE: u32 = 1 << 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KbReply {
    Located(i32, i32),
    Moved,
    Buttons(bool),
    /// Refused: a controller is holding a mouse button.
    RemoteButtonHeld,
    /// This backend has no pixel-space read/move.
    Unsupported,
    /// The injector exists but the OS has not granted it (macOS
    /// Accessibility).
    NoPermission,
    Failed(String),
}

/// How long the keep-busy engine waits for the arbiter: the injector
/// thread's own bound plus room for a queue of controller events ahead.
pub const KB_REPLY_TIMEOUT: Duration = Duration::from_millis(500);

struct Sinks {
    control: DcStash,
    cursor: DcStash,
    last_ghost: Instant,
}

/// Process-global handle. Cheap to clone; all methods are non-blocking
/// sends into the worker (a full queue drops the event — input is a
/// realtime stream, stale events are worse than lost ones).
#[derive(Clone)]
pub struct Arbiter {
    tx: std::sync::mpsc::SyncSender<Cmd>,
}

/// The global arbiter. First call must happen inside a tokio runtime (the
/// worker captures the handle for DC sends) — peer.rs session setup is.
pub fn global() -> &'static Arbiter {
    static ARBITER: OnceLock<Arbiter> = OnceLock::new();
    ARBITER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Cmd>(512);
        let handle = tokio::runtime::Handle::current();
        std::thread::Builder::new()
            .name("input-arbiter".into())
            .spawn(move || worker(rx, handle))
            .expect("spawn input-arbiter worker");
        Arbiter { tx }
    })
}

impl Arbiter {
    pub fn session_open(
        &self,
        session: ObjectId,
        name: String,
        can_input: bool,
        mode_hint: Option<Mode>,
        control: DcStash,
        cursor: DcStash,
    ) {
        let _ = self.tx.try_send(Cmd::Open {
            session,
            name,
            can_input,
            mode_hint,
            control,
            cursor,
        });
    }
    pub fn session_closed(&self, session: ObjectId) {
        let _ = self.tx.try_send(Cmd::Close { session });
    }
    /// Input DC died mid-session — release this session's held keys/buttons
    /// without removing it from the participants rail.
    pub fn release_held(&self, session: ObjectId) {
        let _ = self.tx.try_send(Cmd::ReleaseHeld { session });
    }
    /// A session's control DC opened — (re)deliver `rc:control.state`.
    pub fn control_ready(&self, session: ObjectId) {
        let _ = self.tx.try_send(Cmd::ControlReady { session });
    }
    pub fn event(&self, session: ObjectId, msg: InputMsg) {
        if self.tx.try_send(Cmd::Event { session, msg }).is_err() {
            tracing::debug!(%session, "input arbiter queue full — event dropped");
        }
    }
    pub fn request_floor(&self, session: ObjectId) {
        let _ = self.tx.try_send(Cmd::RequestFloor { session });
    }
    /// FR-27 — the holder grants the floor to the waiting session.
    pub fn grant_floor(&self, holder: ObjectId, to: ObjectId) {
        let _ = self.tx.try_send(Cmd::GrantFloor { holder, to });
    }
    /// FR-27 — the holder declines, or the requester withdraws.
    pub fn clear_floor_request(&self, session: ObjectId) {
        let _ = self.tx.try_send(Cmd::ClearFloorRequest { session });
    }
    pub fn set_mode(&self, session: ObjectId, mode: Mode) {
        let _ = self.tx.try_send(Cmd::SetMode { session, mode });
    }

    /// FR-92 — run one keep-busy request on the injector and wait (bounded)
    /// for the answer. Called from the keep-busy engine thread, never from
    /// a tokio task.
    pub fn keep_busy(&self, op: KbOp) -> KbReply {
        let (reply, rx) = std::sync::mpsc::sync_channel(1);
        if self
            .tx
            .try_send(Cmd::KeepBusy(KbReq { op, reply }))
            .is_err()
        {
            return KbReply::Failed("input arbiter queue full".into());
        }
        rx.recv_timeout(KB_REPLY_TIMEOUT)
            .unwrap_or_else(|_| KbReply::Failed("input arbiter did not answer".into()))
    }

    /// FR-92 — a controller's `rc:keep-busy.set`.
    pub fn keep_busy_set(&self, session: ObjectId, request: crate::keep_busy::SetRequest) {
        let _ = self.tx.try_send(Cmd::KeepBusySet { session, request });
    }

    /// FR-97 P3e — a controller's `rc:layout.set` ([`Cmd::LayoutSet`]).
    #[cfg(all(
        any(target_os = "windows", target_os = "linux"),
        feature = "enigo-input"
    ))]
    pub fn layout_set(&self, session: ObjectId, token: String) {
        let _ = self.tx.try_send(Cmd::LayoutSet { session, token });
    }
}

/// FR-97 P3e — [`Cmd::LayoutSet`]'s decision, apart from the worker so a test
/// holds it: `switch` runs only for a session keep busy's rule lets act. A
/// refusal sends nothing: the picker is bound to the reported layout, which did
/// not change, so it snaps back.
#[cfg(any(
    test,
    all(
        any(target_os = "windows", target_os = "linux"),
        feature = "enigo-input"
    )
))]
fn layout_set_if_allowed(
    state: &ArbiterState,
    session: ObjectId,
    token: String,
    switch: impl FnOnce(String),
) {
    match state.keep_busy_may_set(session) {
        Ok(_) => switch(token),
        Err(refusal) => tracing::info!(
            %session,
            refusal = refusal.wire(),
            "layout: a session's switch refused"
        ),
    }
}

fn worker(rx: std::sync::mpsc::Receiver<Cmd>, handle: tokio::runtime::Handle) {
    let mut state = ArbiterState::default();
    let mut sinks: HashMap<ObjectId, Sinks> = HashMap::new();
    // ONE OS injector for the whole process — created lazily so the
    // SystemContext worker-role probe runs at first real use, matching the
    // pre-P6 per-session open timing.
    let mut injector: Option<Box<dyn super::InputInjector + Send>> = None;

    while let Ok(cmd) = rx.recv() {
        match cmd {
            Cmd::Open {
                session,
                name,
                can_input,
                mode_hint,
                control,
                cursor,
            } => {
                state.open(session, name, can_input, mode_hint, Instant::now());
                sinks.insert(
                    session,
                    Sinks {
                        control,
                        cursor,
                        last_ghost: crate::clock::instant_before(GHOST_MIN_INTERVAL),
                    },
                );
                tracing::info!(
                    %session, can_input, mode = state.snapshot().mode.as_str(),
                    sessions = state.session_count(),
                    "input arbiter: session registered"
                );
                broadcast_state(&state, &sinks, &handle);
            }
            Cmd::Close { session } => {
                let releases = state.close(session);
                if !releases.is_empty() {
                    tracing::info!(
                        %session,
                        released = releases.len(),
                        "input arbiter: release-all on session close"
                    );
                    inject_all(&mut injector, &releases);
                    // FR-92 — a released button moves the pointer first
                    // (#1945): keep-busy must re-anchor, not fight it.
                    crate::keep_busy::note_remote_input();
                }
                sinks.remove(&session);
                if state.session_count() > 0 {
                    broadcast_state(&state, &sinks, &handle);
                }
            }
            Cmd::ControlReady { session } => {
                tracing::debug!(%session, "input arbiter: control DC ready — re-broadcasting state");
                broadcast_state(&state, &sinks, &handle);
                if state.can_input(session) {
                    warm(&mut injector);
                }
            }
            Cmd::ReleaseHeld { session } => {
                let releases = state.release_held(session);
                if !releases.is_empty() {
                    tracing::info!(
                        %session,
                        released = releases.len(),
                        "input arbiter: input DC closed — released held keys"
                    );
                    inject_all(&mut injector, &releases);
                    crate::keep_busy::note_remote_input();
                }
            }
            Cmd::Event { session, msg } => {
                // Ghost cursors ride on intent, not on the floor: even a
                // denied (non-holder) session's pointer shows to others.
                if let InputMsg::MouseMove { x, y, mon } = msg
                    && sinks.len() > 1
                {
                    ghost_broadcast(&state, &mut sinks, &handle, session, x, y, mon);
                }
                match state.plan(session, &msg, Instant::now()) {
                    EventPlan::Deny => {}
                    EventPlan::Inject { pre } => {
                        if !pre.is_empty() {
                            tracing::debug!(
                                %session,
                                fenced = pre.len(),
                                "input arbiter: cross-session modifier fence"
                            );
                            inject_all(&mut injector, &pre);
                        }
                        inject_all(&mut injector, std::slice::from_ref(&msg));
                        // FR-92 — a controller's input reached the OS: a
                        // remote person is active. A heartbeat is not input.
                        if !matches!(msg, InputMsg::Heartbeat { .. }) {
                            crate::keep_busy::note_remote_input();
                        }
                    }
                }
            }
            Cmd::KeepBusy(req) => {
                let reply = keep_busy_op(&state, &mut injector, req.op);
                let _ = req.reply.try_send(reply);
            }
            Cmd::KeepBusySet { session, request } => {
                // Accepted requests are answered by the engine's broadcast;
                // a refusal goes to the asking viewer alone, with its reason.
                let refused = match state.keep_busy_may_set(session) {
                    Ok(name) => (!crate::keep_busy::submit_from_session(session, name, request))
                        .then_some("unsupported"),
                    Err(refusal) => {
                        tracing::info!(
                            %session,
                            refusal = refusal.wire(),
                            "keep-busy: a session's request refused"
                        );
                        Some(refusal.wire())
                    }
                };
                if let Some(why) = refused
                    && let Some(s) = sinks.get(&session)
                {
                    let stash = s.control.clone();
                    let payload = crate::keep_busy::state_json(Some(why));
                    handle.spawn(async move {
                        if let Some(dc) = stash.lock().await.clone() {
                            let _ = dc.send_text(payload).await;
                        }
                    });
                }
            }
            #[cfg(all(
                any(target_os = "windows", target_os = "linux"),
                feature = "enigo-input"
            ))]
            Cmd::LayoutSet { session, token } => layout_set_if_allowed(
                &state,
                session,
                token,
                crate::input::layout::request_set_layout,
            ),
            Cmd::RequestFloor { session } => {
                let (granted, releases) = state.request_floor(session, Instant::now());
                tracing::info!(%session, granted, "input arbiter: floor request");
                if !releases.is_empty() {
                    inject_all(&mut injector, &releases);
                    crate::keep_busy::note_remote_input();
                }
                broadcast_state(&state, &sinks, &handle);
            }
            Cmd::GrantFloor { holder, to } => {
                let (granted, releases) = state.grant_floor(holder, to);
                tracing::info!(%holder, %to, granted, "input arbiter: floor grant");
                if !releases.is_empty() {
                    inject_all(&mut injector, &releases);
                    crate::keep_busy::note_remote_input();
                }
                // Broadcast even on a refusal: the requester may have left, or
                // the floor may have moved, and both ends need the truth.
                broadcast_state(&state, &sinks, &handle);
            }
            Cmd::ClearFloorRequest { session } => {
                if state.clear_floor_request(session) {
                    tracing::info!(%session, "input arbiter: floor request cleared");
                    broadcast_state(&state, &sinks, &handle);
                }
            }
            Cmd::SetMode { session, mode } => {
                if state.set_mode(session, mode) {
                    tracing::info!(%session, mode = mode.as_str(), "input arbiter: mode changed");
                }
                broadcast_state(&state, &sinks, &handle);
            }
        }
    }
    tracing::debug!("input arbiter worker exiting (channel closed)");
}

/// FR-93 P4c — open the ONE injector (or replace a stale one) as soon as a
/// session that may input is ready, instead of at its first event.
///
/// ⚠️ A uinput device is not usable the moment it exists: libinput adds it
/// asynchronously, and under load the first move written after the backend's
/// settle still reached nobody (measured on KDE, real hardware: 2 of 8 fresh
/// devices). Opened here, the device has the second or more a viewer takes to
/// send anything. Linux only — the race is libinput's — and an injector
/// without the OS's permission is not cached, by `keep_busy_op`'s rule: one
/// cached before a display exists would break every later controller's input.
/// `MESHHARBORD_INPUT_WARM=0` keeps the first event as the opener.
fn warm(injector: &mut Option<Box<dyn super::InputInjector + Send>>) {
    if !cfg!(target_os = "linux") || !tunnel_core::env::flag("INPUT_WARM", true) {
        return;
    }
    if injector.as_deref().is_some_and(|i| super::stale(i)) {
        *injector = None;
    }
    if injector.is_some() {
        return;
    }
    let fresh = super::open_default();
    if fresh.has_permission() {
        tracing::info!("input arbiter: injector opened ahead of the first event (FR-93 P4c)");
        *injector = Some(fresh);
    }
}

fn inject_all(injector: &mut Option<Box<dyn super::InputInjector + Send>>, msgs: &[InputMsg]) {
    inject_all_with(
        injector,
        msgs,
        cfg!(target_os = "macos"),
        super::open_default,
    );
}

fn inject_all_with(
    injector: &mut Option<Box<dyn super::InputInjector + Send>>,
    msgs: &[InputMsg],
    retry_unpermitted: bool,
    mut open: impl FnMut() -> Box<dyn super::InputInjector + Send>,
) {
    for m in msgs {
        // FR-45 P4 — while a portal capture with granted input is live, the
        // portal session owns injection: on the hosts that backend serves,
        // the OS injector's events have no reader at all (which is why the
        // portal is in use). Checked PER EVENT, not at injector creation —
        // the injector is created lazily at the first event while the portal
        // capture opens concurrently from another task, so a one-time choice
        // would race startup and freeze the loser in for the process life.
        #[cfg(all(target_os = "linux", feature = "portal-capture"))]
        if crate::capture::portal::input_route::try_route(m) {
            continue;
        }
        // FR-95 P2 — the injector follows the automatic system capture: its
        // uinput while one reads a person's session, the configured cascade
        // otherwise (`input::stale`).
        if injector.as_deref().is_some_and(|i| super::stale(i)) {
            *injector = None;
        }
        // Match keep_busy_op: a denied backend must not pin Noop for the
        // daemon's lifetime. Retry on the next event after the owner grants it.
        if retry_unpermitted && injector.as_deref().is_some_and(|i| !i.has_permission()) {
            *injector = None;
        }
        let inj = injector.get_or_insert_with(&mut open);
        if retry_unpermitted && !inj.has_permission() {
            *injector = None;
            continue;
        }
        if let Err(e) = inj.inject(m.clone()) {
            tracing::debug!(%e, "input arbiter: inject failed");
        }
    }
}

/// FR-92 — run one keep-busy request against the ONE injector.
///
/// ⚠️ The injector is created lazily and then cached for the life of the
/// process — a `NoopInjector` included. Remote control's first event used to
/// be the only creator, and a session implies a display. Keep-busy may be
/// first (a boot-time restore), so an injector without the OS's permission
/// is answered for and NOT cached: a Noop cached before a display exists
/// would silently break every later controller's input. (The engine also
/// sends nothing before its host confirms an interactive session.)
fn keep_busy_op(
    state: &ArbiterState,
    injector: &mut Option<Box<dyn super::InputInjector + Send>>,
    op: KbOp,
) -> KbReply {
    if matches!(op, KbOp::Move { .. } | KbOp::MoveNorm { .. }) && state.any_button_held() {
        return KbReply::RemoteButtonHeld;
    }
    // FR-95 P2 — the same swap the controller's path makes (`input::stale`).
    if injector.as_deref().is_some_and(|i| super::stale(i)) {
        *injector = None;
    }
    if injector.is_none() {
        let fresh = super::open_default();
        if !fresh.has_permission() {
            return classify_unpermitted(fresh);
        }
        *injector = Some(fresh);
    }
    let Some(inj) = injector.as_mut() else {
        return KbReply::Unsupported;
    };
    if !inj.has_permission() {
        return KbReply::NoPermission;
    }
    let result = match op {
        KbOp::Locate => inj.cursor_px().map(|(x, y)| KbReply::Located(x, y)),
        KbOp::Move { x, y } => inj.move_px(x, y).map(|()| KbReply::Moved),
        KbOp::MoveNorm { x, y } => {
            let f = |v: u32| f64::from(v.min(NORM_ONE)) / f64::from(NORM_ONE);
            inj.move_norm(f(x), f(y)).map(|()| KbReply::Moved)
        }
        KbOp::Buttons => inj.buttons_held().map(KbReply::Buttons),
    };
    result.unwrap_or_else(|e| {
        if e.is::<super::PxUnsupported>() {
            KbReply::Unsupported
        } else {
            KbReply::Failed(e.to_string())
        }
    })
}

/// An injector the OS has not granted: a Noop (no backend at all) has no
/// pixel read either; a real backend without permission (macOS
/// Accessibility) does.
///
/// ⚠️ macOS asks the OS first. enigo now REFUSES to construct without
/// Accessibility ("the application does not have the permission to simulate
/// input"), so `open_default` hands back a Noop there too, and a Noop alone
/// reads as `unsupported`: "Unavailable on this computer." Field, macOS 27,
/// 0.4.126, with the grant switched off: exactly that, where the truth was
/// one switch the owner can flip. `no_permission` is the reason that says so.
fn classify_unpermitted(mut inj: Box<dyn super::InputInjector + Send>) -> KbReply {
    #[cfg(target_os = "macos")]
    if !crate::tcc::accessibility_trusted() {
        return KbReply::NoPermission;
    }
    match inj.cursor_px() {
        Err(e) if e.is::<super::PxUnsupported>() => KbReply::Unsupported,
        _ => KbReply::NoPermission,
    }
}

/// `rc:control.state` fan-out to every session's control DC.
fn broadcast_state(
    state: &ArbiterState,
    sinks: &HashMap<ObjectId, Sinks>,
    handle: &tokio::runtime::Handle,
) {
    let snap = state.snapshot();
    let payload = serde_json::json!({
        "t": "rc:control.state",
        "mode": snap.mode.as_str(),
        "holder": snap.holder.map(|h| h.to_hex()),
        "participants": snap
            .participants
            .iter()
            .map(|p| serde_json::json!({
                "session": p.session.to_hex(),
                "name": p.name,
                "input": p.input,
            }))
            .collect::<Vec<_>>(),
        // FR-27 — who is waiting for the floor. Omitted when nothing is, so a
        // viewer that ignores the key behaves exactly as before.
        "pending_request": snap.pending_request.as_ref().map(|p| serde_json::json!({
            "session": p.session.to_hex(),
            "name": p.name,
        })),
    })
    .to_string();
    for s in sinks.values() {
        let stash = s.control.clone();
        let payload = payload.clone();
        handle.spawn(async move {
            if let Some(dc) = stash.lock().await.clone() {
                let _ = dc.send_text(payload).await;
            }
        });
    }
}

/// Throttled `cursor:peer` rebroadcast of one session's pointer to every
/// OTHER session's cursor DC.
fn ghost_broadcast(
    state: &ArbiterState,
    sinks: &mut HashMap<ObjectId, Sinks>,
    handle: &tokio::runtime::Handle,
    from: ObjectId,
    x: f32,
    y: f32,
    mon: u8,
) {
    let now = Instant::now();
    let Some(own) = sinks.get_mut(&from) else {
        return;
    };
    if now.duration_since(own.last_ghost) < GHOST_MIN_INTERVAL {
        return;
    }
    own.last_ghost = now;
    // Field diagnostic (2026-08-05): ghost cursors were not observed in the
    // first two-viewer field test. The viewer coalesces `mouse_move` through
    // `requestAnimationFrame`, which Chrome SUSPENDS in a background tab — so
    // a test driving two tabs (only one foreground at a time) may simply
    // never send the moves. Log the first send and then every 300th so the
    // field can tell "agent never sent" from "viewer never rendered" without
    // a debug build.
    let n = GHOSTS_SENT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if n == 1 || n.is_multiple_of(300) {
        tracing::info!(
            source = %from,
            targets = sinks.len().saturating_sub(1),
            total = n,
            "input arbiter: ghost cursor broadcast"
        );
    }
    let name = state
        .snapshot()
        .participants
        .iter()
        .find(|p| p.session == from)
        .map(|p| p.name.clone())
        .unwrap_or_default();
    let payload = serde_json::json!({
        "t": "cursor:peer",
        "sid": from.to_hex(),
        "name": name,
        "x": x,
        "y": y,
        "mon": mon,
    })
    .to_string();
    for (id, s) in sinks.iter() {
        if *id == from {
            continue;
        }
        let stash = s.cursor.clone();
        let payload = payload.clone();
        handle.spawn(async move {
            if let Some(dc) = stash.lock().await.clone() {
                let _ = dc.send_text(payload).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_recovers_after_permission_is_granted_without_caching_a_denial() {
        struct Granted(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl crate::input::InputInjector for Granted {
            fn inject(&mut self, _: InputMsg) -> anyhow::Result<()> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            fn has_permission(&self) -> bool {
                true
            }
        }
        let events = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Include the Noop cached by an earlier event on the baseline.
        let mut injector: Option<Box<dyn crate::input::InputInjector + Send>> =
            Some(Box::new(crate::input::NoopInjector));
        inject_all_with(&mut injector, &[key(0x04, true)], true, || {
            Box::new(crate::input::NoopInjector)
        });
        assert!(injector.is_none(), "a denied backend must not be cached");
        assert_eq!(events.load(std::sync::atomic::Ordering::Relaxed), 0);
        inject_all_with(&mut injector, &[key(0x04, true)], true, || {
            Box::new(Granted(events.clone()))
        });
        inject_all_with(&mut injector, &[key(0x04, false)], true, || {
            panic!("the permitted backend should be reused")
        });
        assert_eq!(events.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn input_without_permission_recovery_keeps_the_existing_fallback() {
        let mut injector: Option<Box<dyn crate::input::InputInjector + Send>> = None;
        inject_all_with(&mut injector, &[key(0x04, true)], false, || {
            Box::new(crate::input::NoopInjector)
        });
        assert!(injector.is_some());
        inject_all_with(&mut injector, &[key(0x04, false)], false, || {
            panic!("non-macOS fallback behavior must stay unchanged")
        });
    }

    fn sid() -> ObjectId {
        ObjectId::new()
    }
    fn key(code: u32, down: bool) -> InputMsg {
        InputMsg::Key {
            code,
            down,
            mods: 0,
        }
    }
    fn click(down: bool) -> InputMsg {
        InputMsg::MouseButton {
            btn: Button::Left,
            down,
            x: 0.5,
            y: 0.5,
            mon: 0,
        }
    }

    #[test]
    fn free_mode_switch_fences_other_sessions_held_modifiers() {
        let mut st = ArbiterState::default();
        let (a, b) = (sid(), sid());
        let now = Instant::now();
        st.open(a, "A".into(), true, None, now);
        st.open(b, "B".into(), true, None, now);

        // A holds Left-Ctrl (0xe0).
        assert_eq!(
            st.plan(a, &key(0xe0, true), now),
            EventPlan::Inject { pre: vec![] }
        );
        // B clicks — A's held Ctrl must be released FIRST.
        match st.plan(b, &click(true), now) {
            EventPlan::Inject { pre } => {
                assert_eq!(pre.len(), 1);
                assert!(matches!(
                    pre[0],
                    InputMsg::Key {
                        code: 0xe0,
                        down: false,
                        ..
                    }
                ));
            }
            p => panic!("expected inject, got {p:?}"),
        }
        // A's Ctrl was force-released — its own later key-up releases nothing
        // new, and switching back to A fences B's held button? No: the fence
        // covers MODIFIERS only; B's held left button is untouched.
        match st.plan(a, &key(0xe0, false), now) {
            EventPlan::Inject { pre } => assert!(pre.is_empty(), "no modifiers left to fence"),
            p => panic!("expected inject, got {p:?}"),
        }
    }

    #[test]
    fn non_modifier_keys_are_not_fenced_on_switch() {
        let mut st = ArbiterState::default();
        let (a, b) = (sid(), sid());
        let now = Instant::now();
        st.open(a, "A".into(), true, None, now);
        st.open(b, "B".into(), true, None, now);
        // A holds the letter W (0x1a) — a game-style hold, not a modifier.
        st.plan(a, &key(0x1a, true), now);
        match st.plan(b, &click(true), now) {
            EventPlan::Inject { pre } => assert!(pre.is_empty(), "letters are not fenced"),
            p => panic!("expected inject, got {p:?}"),
        }
    }

    #[test]
    fn close_releases_everything_the_session_held() {
        let mut st = ArbiterState::default();
        let a = sid();
        let now = Instant::now();
        st.open(a, "A".into(), true, None, now);
        st.plan(a, &key(0xe1, true), now); // L-Shift
        st.plan(a, &key(0x04, true), now); // letter A
        st.plan(a, &click(true), now); // left button
        let releases = st.close(a);
        assert_eq!(releases.len(), 3, "shift + letter + button all released");
        assert!(releases.iter().all(|m| matches!(
            m,
            InputMsg::Key { down: false, .. } | InputMsg::MouseRelease { .. }
        )));
        // Idempotent.
        assert!(st.close(a).is_empty());
    }

    /// FR-109 — relative mode presses with `MousePress`, and that press is
    /// held like any other: a session that ends mid-drag still has its button
    /// released, and released where the pointer is. A watcher without input
    /// moves nothing, relatively or not.
    #[test]
    fn a_relative_press_is_held_and_released_at_the_end() {
        let now = Instant::now();
        let mut st = ArbiterState::default();
        let (a, w) = (sid(), sid());
        st.open(a, "A".into(), true, None, now);
        st.open(w, "W".into(), false, None, now);
        assert_eq!(
            st.plan(a, &InputMsg::MousePress { btn: Button::Left }, now),
            EventPlan::Inject { pre: vec![] }
        );
        assert_eq!(
            st.plan(a, &InputMsg::MouseRel { dx: 30, dy: 0 }, now),
            EventPlan::Inject { pre: vec![] }
        );
        assert_eq!(
            st.plan(w, &InputMsg::MouseRel { dx: 30, dy: 0 }, now),
            EventPlan::Deny
        );
        assert_eq!(
            st.close(a),
            vec![InputMsg::MouseRelease { btn: Button::Left }]
        );

        // The control: a release lets go of the relative press, so nothing is
        // left to release when the session ends.
        let mut st = ArbiterState::default();
        st.open(a, "A".into(), true, None, now);
        st.plan(a, &InputMsg::MousePress { btn: Button::Left }, now);
        st.plan(a, &InputMsg::MouseRelease { btn: Button::Left }, now);
        assert!(st.close(a).is_empty());
    }

    /// #1945 — every path that lets go of a session's held button lets go
    /// WHERE THE POINTER IS. A `MouseButton` up carries a position every
    /// backend moves to first; the (0,0) the release-all used to send was
    /// GNOME's Activities hot corner (a macOS hot corner may lock the screen),
    /// and the end of the drag.
    #[test]
    fn a_held_button_is_released_without_moving_the_pointer() {
        let moves = |ms: &[InputMsg]| {
            ms.iter()
                .filter(|m| matches!(m, InputMsg::MouseButton { .. } | InputMsg::MouseMove { .. }))
                .count()
        };
        let released = |ms: &[InputMsg]| ms.contains(&InputMsg::MouseRelease { btn: Button::Left });
        let now = Instant::now();

        // The session closes mid-drag (tab closed, browser crashed, watchdog).
        let mut st = ArbiterState::default();
        let a = sid();
        st.open(a, "A".into(), true, None, now);
        st.plan(a, &click(true), now);
        let r = st.close(a);
        assert!(released(&r) && moves(&r) == 0, "close: {r:?}");

        // Its input channel dies but the session lives on.
        let mut st = ArbiterState::default();
        st.open(a, "A".into(), true, None, now);
        st.plan(a, &click(true), now);
        let r = st.release_held(a);
        assert!(released(&r) && moves(&r) == 0, "release_held: {r:?}");

        // Exclusive mode: an idle holder's floor is taken over, and the holder
        // hands it over on request.
        let b = sid();
        let mut st = ArbiterState::default();
        st.open(a, "A".into(), true, Some(Mode::Exclusive), now);
        st.open(b, "B".into(), true, None, now);
        st.plan(a, &click(true), now);
        let (granted, r) = st.request_floor(b, now + IDLE_TAKEOVER);
        assert!(granted);
        assert!(released(&r) && moves(&r) == 0, "takeover: {r:?}");

        let mut st = ArbiterState::default();
        st.open(a, "A".into(), true, Some(Mode::Exclusive), now);
        st.open(b, "B".into(), true, None, now);
        st.plan(a, &click(true), now);
        assert!(
            !st.request_floor(b, now).0,
            "an active holder keeps the floor"
        );
        let (granted, r) = st.grant_floor(a, b);
        assert!(granted);
        assert!(released(&r) && moves(&r) == 0, "grant: {r:?}");
    }

    /// A viewer may send the no-move release itself; it ends the hold, so
    /// nothing is released twice when the session closes.
    #[test]
    fn a_viewers_own_release_ends_the_hold() {
        let mut st = ArbiterState::default();
        let a = sid();
        let now = Instant::now();
        st.open(a, "A".into(), true, None, now);
        st.plan(a, &click(true), now);
        st.plan(a, &InputMsg::MouseRelease { btn: Button::Left }, now);
        assert!(st.close(a).is_empty());
    }

    /// FR-27 P10 — the host's Disconnect closes the session HERE at the click
    /// (`AgentPeer::stop_serving`) while its transport lives on for the grace,
    /// so whatever the input channel still delivers must go nowhere.
    #[test]
    fn a_closed_sessions_later_events_are_denied() {
        let mut st = ArbiterState::default();
        let a = sid();
        let now = Instant::now();
        st.open(a, "A".into(), true, None, now);
        assert!(matches!(
            st.plan(a, &click(true), now),
            EventPlan::Inject { .. }
        ));
        st.close(a);
        assert_eq!(st.plan(a, &click(false), now), EventPlan::Deny);
        assert_eq!(st.plan(a, &key(0x04, true), now), EventPlan::Deny);
        // A denied event is not tracked as held: nothing is left to release.
        assert!(st.close(a).is_empty());
    }

    #[test]
    fn exclusive_mode_drops_non_holder_events() {
        let mut st = ArbiterState::default();
        let (a, b) = (sid(), sid());
        let now = Instant::now();
        st.open(a, "A".into(), true, Some(Mode::Exclusive), now);
        st.open(b, "B".into(), true, None, now);
        assert_eq!(st.snapshot().holder, Some(a), "first INPUT session holds");
        assert!(matches!(
            st.plan(a, &click(true), now),
            EventPlan::Inject { .. }
        ));
        assert_eq!(st.plan(b, &click(true), now), EventPlan::Deny);
        // Heartbeats always pass.
        assert!(matches!(
            st.plan(b, &InputMsg::Heartbeat { seq: 1, ts_ms: 0 }, now),
            EventPlan::Inject { .. }
        ));
    }

    #[test]
    fn floor_request_denied_while_holder_active_granted_when_idle() {
        let mut st = ArbiterState::default();
        let (a, b) = (sid(), sid());
        let now = Instant::now();
        st.open(a, "A".into(), true, Some(Mode::Exclusive), now);
        st.open(b, "B".into(), true, None, now);
        // Holder is actively typing (and holding Shift).
        st.plan(a, &key(0xe1, true), now);
        let (granted, _) = st.request_floor(b, now + Duration::from_millis(500));
        assert!(!granted, "active holder keeps the floor");
        // Holder goes idle past the takeover window → transfer + release-all.
        let later = now + IDLE_TAKEOVER + Duration::from_millis(1);
        let (granted, releases) = st.request_floor(b, later);
        assert!(granted);
        assert_eq!(releases.len(), 1, "previous holder's Shift released");
        assert_eq!(st.snapshot().holder, Some(b));
        // B now injects; A is denied.
        assert!(matches!(
            st.plan(b, &click(true), later),
            EventPlan::Inject { .. }
        ));
        assert_eq!(st.plan(a, &click(true), later), EventPlan::Deny);
    }

    #[test]
    fn mode_toggle_and_holder_lifecycle() {
        let mut st = ArbiterState::default();
        let (a, b) = (sid(), sid());
        let now = Instant::now();
        st.open(a, "A".into(), true, None, now);
        st.open(b, "B".into(), true, None, now);
        assert_eq!(st.snapshot().mode, Mode::Free);
        // B flips to exclusive → B holds.
        assert!(st.set_mode(b, Mode::Exclusive));
        assert_eq!(st.snapshot().holder, Some(b));
        assert_eq!(st.plan(a, &click(true), now), EventPlan::Deny);
        // Holder leaves → floor passes to a remaining INPUT session.
        st.close(b);
        assert_eq!(st.snapshot().holder, Some(a));
        assert!(matches!(
            st.plan(a, &click(true), now),
            EventPlan::Inject { .. }
        ));
        // Back to free clears the floor.
        assert!(st.set_mode(a, Mode::Free));
        assert_eq!(st.snapshot().holder, None);
    }

    #[test]
    fn policy_mode_hint_applies_once_and_never_stomps_a_toggle() {
        let mut st = ArbiterState::default();
        let (a, b) = (sid(), sid());
        let now = Instant::now();
        st.open(a, "A".into(), true, Some(Mode::Exclusive), now);
        assert_eq!(st.snapshot().mode, Mode::Exclusive);
        st.set_mode(a, Mode::Free);
        // A later join re-sending the policy hint must not re-apply it.
        st.open(b, "B".into(), true, Some(Mode::Exclusive), now);
        assert_eq!(st.snapshot().mode, Mode::Free, "in-session toggle wins");
    }

    #[test]
    fn view_only_sessions_appear_in_snapshot_but_never_inject_or_hold() {
        let mut st = ArbiterState::default();
        let (a, w) = (sid(), sid());
        let now = Instant::now();
        st.open(w, "Watcher".into(), false, Some(Mode::Exclusive), now);
        assert_eq!(st.snapshot().holder, None, "view-only never holds");
        st.open(a, "A".into(), true, None, now);
        assert_eq!(st.plan(w, &click(true), now), EventPlan::Deny);
        let (granted, _) = st.request_floor(w, now);
        assert!(!granted);
        assert!(!st.set_mode(w, Mode::Free), "view-only cannot toggle mode");
        let snap = st.snapshot();
        assert_eq!(snap.participants.len(), 2);
        assert!(
            snap.participants
                .iter()
                .any(|p| p.name == "Watcher" && !p.input)
        );
    }

    /// Field regression (2026-08-05): arbiter entries LEAKED because
    /// deregistration hung off the control DC's `on_close`, which does not
    /// fire on PeerConnection teardown — a fresh session then registered as
    /// `sessions=3` while the server reported zero open sessions. The state
    /// machine itself is correct (close removes the entry); the fix is the
    /// CALLER (`Drop for AgentPeer`). This locks the invariant the leak
    /// violated: registering N sessions and closing them all leaves zero,
    /// and a later session sees a count of exactly 1.
    #[test]
    fn close_leaves_no_residue_for_the_next_session() {
        let mut st = ArbiterState::default();
        let now = Instant::now();
        let (a, b) = (sid(), sid());
        st.open(a, "A".into(), true, None, now);
        st.open(b, "B".into(), true, None, now);
        assert_eq!(st.session_count(), 2);
        st.close(a);
        st.close(b);
        assert_eq!(st.session_count(), 0, "both entries released");
        let c = sid();
        st.open(c, "C".into(), true, None, now);
        assert_eq!(
            st.session_count(),
            1,
            "a later session must see a clean arbiter, not stale peers"
        );
        // And the reused-close path stays idempotent.
        assert!(st.close(a).is_empty());
        assert_eq!(st.session_count(), 1);
    }

    #[test]
    fn mode_parse_round_trips() {
        assert_eq!(Mode::parse("free"), Some(Mode::Free));
        assert_eq!(Mode::parse(" Exclusive "), Some(Mode::Exclusive));
        assert_eq!(Mode::parse("nope"), None);
        assert_eq!(Mode::Free.as_str(), "free");
        assert_eq!(Mode::Exclusive.as_str(), "exclusive");
    }

    // ─── FR-27 ──────────────────────────────────────────────────────────

    /// The device policy must apply to EVERY fresh occupancy, not just the
    /// first one since the daemon booted. `mode_seeded` used to latch for the
    /// process lifetime, so one viewer's in-session toggle silently disabled
    /// the policy forever.
    #[test]
    fn the_device_policy_re_seeds_once_everyone_has_left() {
        let (a, b) = (sid(), sid());
        let mut st = ArbiterState::default();
        let now = Instant::now();

        st.open(a, "A".into(), true, Some(Mode::Exclusive), now);
        assert_eq!(st.snapshot().mode, Mode::Exclusive);

        // A viewer overrides it mid-session — legitimate, and it must stick
        // while anyone is still connected.
        assert!(st.set_mode(a, Mode::Free));
        st.open(b, "B".into(), true, Some(Mode::Exclusive), now);
        assert_eq!(
            st.snapshot().mode,
            Mode::Free,
            "a later JOIN must not stomp a live in-session toggle"
        );

        // Everyone leaves. There is no conversation left to preserve.
        st.close(a);
        st.close(b);
        st.open(sid(), "C".into(), true, Some(Mode::Exclusive), now);
        assert_eq!(
            st.snapshot().mode,
            Mode::Exclusive,
            "the device policy must apply again once the device is idle"
        );
    }

    /// A refused floor request has to be VISIBLE. Dropping it made "Request
    /// control" indistinguishable from a dead button.
    #[test]
    fn a_refused_floor_request_is_remembered_and_broadcast() {
        let (holder, asker) = (sid(), sid());
        let mut st = ArbiterState::default();
        let t0 = Instant::now();
        st.open(holder, "Holder".into(), true, Some(Mode::Exclusive), t0);
        st.open(asker, "Asker".into(), true, None, t0);
        assert_eq!(st.snapshot().holder, Some(holder));

        // The holder is ACTIVE, so no auto-takeover…
        st.plan(holder, &key(0x04, true), t0);
        let (granted, _) = st.request_floor(asker, t0);
        assert!(!granted);

        // …but both ends can now see who is waiting.
        let snap = st.snapshot();
        assert_eq!(
            snap.pending_request.as_ref().map(|p| p.session),
            Some(asker)
        );
        assert_eq!(snap.pending_request.unwrap().name, "Asker");
    }

    /// The holder can hand over without waiting out the idle timer — and
    /// handing over releases whatever they were holding down, exactly as an
    /// idle takeover does.
    #[test]
    fn the_holder_can_grant_the_floor_and_their_keys_are_released() {
        let (holder, asker) = (sid(), sid());
        let mut st = ArbiterState::default();
        let t0 = Instant::now();
        st.open(holder, "Holder".into(), true, Some(Mode::Exclusive), t0);
        st.open(asker, "Asker".into(), true, None, t0);

        st.plan(holder, &key(0xe0, true), t0); // holding Ctrl
        st.plan(holder, &click(true), t0); // and the left button
        assert!(!st.request_floor(asker, t0).0);

        let (granted, releases) = st.grant_floor(holder, asker);
        assert!(granted);
        assert_eq!(st.snapshot().holder, Some(asker));
        assert_eq!(
            releases.len(),
            2,
            "the outgoing holder's chord must not be left down"
        );
        assert!(st.snapshot().pending_request.is_none());
        // The new holder can actually inject now.
        assert!(matches!(
            st.plan(asker, &key(0x04, true), t0),
            EventPlan::Inject { .. }
        ));
    }

    /// Only the CURRENT holder may grant, and only to the session that asked.
    /// A stale click must not hand control to whoever asked last.
    #[test]
    fn granting_is_refused_from_a_non_holder_or_to_a_non_requester() {
        let (holder, asker, third) = (sid(), sid(), sid());
        let mut st = ArbiterState::default();
        let t0 = Instant::now();
        st.open(holder, "Holder".into(), true, Some(Mode::Exclusive), t0);
        st.open(asker, "Asker".into(), true, None, t0);
        st.open(third, "Third".into(), true, None, t0);
        st.plan(holder, &key(0x04, true), t0);
        assert!(!st.request_floor(asker, t0).0);

        assert!(!st.grant_floor(third, asker).0, "a non-holder cannot grant");
        assert!(
            !st.grant_floor(holder, third).0,
            "the holder cannot grant to someone who never asked"
        );
        assert_eq!(st.snapshot().holder, Some(holder));
        assert_eq!(
            st.snapshot().pending_request.map(|p| p.session),
            Some(asker),
            "a refused grant must leave the real request standing"
        );
    }

    /// A request must not outlive the thing it was about: the requester
    /// leaving, the mode being abolished, or a decline.
    #[test]
    fn a_pending_request_is_cleared_by_departure_mode_change_or_decline() {
        let (holder, asker) = (sid(), sid());
        let t0 = Instant::now();

        // …the requester disconnects.
        let mut st = ArbiterState::default();
        st.open(holder, "H".into(), true, Some(Mode::Exclusive), t0);
        st.open(asker, "A".into(), true, None, t0);
        st.plan(holder, &key(0x04, true), t0);
        st.request_floor(asker, t0);
        st.close(asker);
        assert!(st.snapshot().pending_request.is_none());

        // …the holder declines.
        let mut st = ArbiterState::default();
        st.open(holder, "H".into(), true, Some(Mode::Exclusive), t0);
        st.open(asker, "A".into(), true, None, t0);
        st.plan(holder, &key(0x04, true), t0);
        st.request_floor(asker, t0);
        assert!(st.clear_floor_request(holder));
        assert!(st.snapshot().pending_request.is_none());

        // …the mode goes free, so there is no floor left to want.
        let mut st = ArbiterState::default();
        st.open(holder, "H".into(), true, Some(Mode::Exclusive), t0);
        st.open(asker, "A".into(), true, None, t0);
        st.plan(holder, &key(0x04, true), t0);
        st.request_floor(asker, t0);
        assert!(st.set_mode(holder, Mode::Free));
        assert!(st.snapshot().pending_request.is_none());
    }

    /// Handover on close must be deterministic — two viewers watching the same
    /// disconnect have to agree on who got the floor.
    #[test]
    fn floor_handover_on_close_is_deterministic() {
        let mut ids = [sid(), sid(), sid()];
        ids.sort();
        let (low, high, holder) = (ids[0], ids[1], ids[2]);
        let t0 = Instant::now();

        // Run it repeatedly: HashMap iteration order varies per process AND
        // per insertion history, so a single pass could pass by luck.
        for _ in 0..8 {
            let mut st = ArbiterState::default();
            st.open(holder, "H".into(), true, Some(Mode::Exclusive), t0);
            st.open(high, "High".into(), true, None, t0);
            st.open(low, "Low".into(), true, None, t0);
            assert_eq!(st.snapshot().holder, Some(holder));
            st.close(holder);
            assert_eq!(
                st.snapshot().holder,
                Some(low),
                "the lowest surviving INPUT session must take the floor"
            );
        }
    }

    /// FR-92 — keep-busy is input: it needs the INPUT grant, the floor in
    /// exclusive mode, and an org that allows it.
    #[test]
    fn keep_busy_needs_the_input_grant_the_floor_and_the_org() {
        let mut st = ArbiterState::default();
        let (a, b, viewer) = (sid(), sid(), sid());
        let now = Instant::now();
        st.open(a, "A".into(), true, Some(Mode::Exclusive), now);
        st.open(b, "B".into(), true, None, now);
        st.open(viewer, "V".into(), false, None, now);
        assert_eq!(st.keep_busy_may_set(a), Ok("A".to_string()));
        assert_eq!(
            st.keep_busy_may_set(b),
            Err(KeepBusyRefusal::NotFloorHolder)
        );
        assert_eq!(st.keep_busy_may_set(viewer), Err(KeepBusyRefusal::NoInput));
        assert_eq!(st.keep_busy_may_set(sid()), Err(KeepBusyRefusal::Unknown));
        assert!(st.set_mode(a, Mode::Free));
        assert_eq!(st.keep_busy_may_set(b), Ok("B".to_string()));
    }

    /// FR-97 P3e — switching the host's keyboard layout changes what the person
    /// at it types, so it takes keep busy's rule. Before P3e every session's
    /// `rc:layout.set` reached the switch, a view-only one's included.
    #[test]
    fn a_layout_switch_needs_the_input_grant_and_the_floor() {
        let mut st = ArbiterState::default();
        let (a, b, viewer) = (sid(), sid(), sid());
        let now = Instant::now();
        st.open(a, "A".into(), true, Some(Mode::Exclusive), now);
        st.open(b, "B".into(), true, None, now);
        st.open(viewer, "V".into(), false, None, now);
        let switched = |st: &ArbiterState, s| {
            let mut got = None;
            layout_set_if_allowed(st, s, "the-token".into(), |t| got = Some(t));
            got
        };
        assert_eq!(switched(&st, a).as_deref(), Some("the-token"));
        assert_eq!(switched(&st, b), None, "not the floor holder");
        assert_eq!(switched(&st, viewer), None, "view-only");
        assert_eq!(switched(&st, sid()), None, "an unknown session");
        assert!(st.set_mode(a, Mode::Free));
        assert_eq!(switched(&st, b).as_deref(), Some("the-token"));
        assert_eq!(switched(&st, viewer), None, "view-only, in free mode too");
    }

    /// FR-92 — a keep-busy move spliced into a controller's drag would drag
    /// whatever they hold, so a held BUTTON blocks it. A held key does not.
    #[test]
    fn only_a_held_mouse_button_blocks_keep_busy_moves() {
        let mut st = ArbiterState::default();
        let a = sid();
        let now = Instant::now();
        st.open(a, "A".into(), true, None, now);
        assert!(!st.any_button_held());
        st.plan(a, &key(0x04, true), now);
        assert!(!st.any_button_held(), "a held key is not a drag");
        st.plan(a, &click(true), now);
        assert!(st.any_button_held());
        st.plan(a, &click(false), now);
        assert!(!st.any_button_held());
        st.plan(a, &click(true), now);
        let _ = st.close(a);
        assert!(!st.any_button_held(), "a closed session holds nothing");
    }

    /// FR-92 — why keep busy cannot run, from an injector the OS has not
    /// granted: no backend at all (a Noop) is `unsupported`; a backend that
    /// can read the pointer but may not move it is `no_permission`. (A Mac
    /// asks the OS first, because its enigo refuses to construct at all
    /// without Accessibility; that branch is field-verified, not reachable
    /// from here.)
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn an_unpermitted_injector_is_unsupported_only_when_there_is_no_backend() {
        struct Unpermitted;
        impl crate::input::InputInjector for Unpermitted {
            fn inject(&mut self, _event: crate::input::InputMsg) -> anyhow::Result<()> {
                Ok(())
            }
            fn has_permission(&self) -> bool {
                false
            }
            fn cursor_px(&mut self) -> anyhow::Result<(i32, i32)> {
                Ok((10, 10))
            }
        }
        assert!(matches!(
            classify_unpermitted(Box::new(crate::input::NoopInjector)),
            KbReply::Unsupported
        ));
        assert!(matches!(
            classify_unpermitted(Box::new(Unpermitted)),
            KbReply::NoPermission
        ));
    }

    /// An injector that records keep busy's normalised moves — uinput's
    /// shape: no pixel read, no pixel move.
    struct NormOnly(std::sync::Arc<std::sync::Mutex<Vec<(f64, f64)>>>);

    impl crate::input::InputInjector for NormOnly {
        fn inject(&mut self, _event: crate::input::InputMsg) -> anyhow::Result<()> {
            Ok(())
        }
        fn has_permission(&self) -> bool {
            true
        }
        fn move_norm(&mut self, x: f64, y: f64) -> anyhow::Result<()> {
            self.0.lock().unwrap().push((x, y));
            Ok(())
        }
    }

    /// FR-92 P9 — the normalised move takes the same held-button rule as a
    /// pixel move (a GNOME/Wayland drag is still a drag), reaches the
    /// injector as a fraction of the desktop, clamps a value past the far
    /// edge, and a backend without it says so instead of failing.
    #[test]
    fn a_normalised_move_is_blocked_by_a_held_button_and_reaches_the_injector() {
        let moves = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut injector: Option<Box<dyn crate::input::InputInjector + Send>> =
            Some(Box::new(NormOnly(moves.clone())));
        let mut st = ArbiterState::default();
        let a = sid();
        let now = Instant::now();
        st.open(a, "A".into(), true, None, now);
        let half = KbOp::MoveNorm {
            x: NORM_ONE / 2,
            y: NORM_ONE / 4,
        };
        st.plan(a, &click(true), now);
        assert_eq!(
            keep_busy_op(&st, &mut injector, half),
            KbReply::RemoteButtonHeld
        );
        assert!(moves.lock().unwrap().is_empty(), "nothing reached the OS");
        st.plan(a, &click(false), now);
        assert_eq!(keep_busy_op(&st, &mut injector, half), KbReply::Moved);
        let past = KbOp::MoveNorm {
            x: NORM_ONE * 3,
            y: 0,
        };
        assert_eq!(keep_busy_op(&st, &mut injector, past), KbReply::Moved);
        assert_eq!(*moves.lock().unwrap(), vec![(0.5, 0.25), (1.0, 0.0)]);
        // The pixel ops are not this backend's: unsupported, never "failed".
        assert_eq!(
            keep_busy_op(&st, &mut injector, KbOp::Locate),
            KbReply::Unsupported
        );
        assert_eq!(
            keep_busy_op(&st, &mut injector, KbOp::Move { x: 1, y: 1 }),
            KbReply::Unsupported
        );
    }
}
