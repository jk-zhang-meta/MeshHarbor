// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! OS input injection abstraction.
//!
//! The browser controller emits `InputMsg` values (mouse move / click /
//! wheel / key / touch — see docs/remote-control.md §6); the agent maps
//! them to OS-native input events via this trait.
//!
//! Backends:
//! - [`enigo_backend::EnigoInjector`] (feature `enigo-input`) — uses
//!   enigo which dispatches to XTest/uinput on Linux, SendInput on
//!   Windows, CGEventPost on macOS.
//! - [`NoopInjector`] — fallback when no backend feature is enabled.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicU32;

/// Process-global counter for `to_pixels` diagnostic logging. The first
/// 50 increments are logged at INFO level; subsequent events drop to
/// DEBUG. [`reset_input_diag_counter`] is called from
/// `peer::attach_input_handler` so EVERY session gets the first-50
/// INFO sample, not just the first session after process start.
///
/// rc.57 — promoted from a function-local static in `enigo_backend.rs`
/// to a module-level static so peer.rs can reset it from outside the
/// `enigo-input` feature gate. The field log from rc.55 ran out of
/// INFO samples after session 1 — the subsequent Crystal-Clear-OFF
/// session (where the misposition reproduces) had only DEBUG dispatch
/// lines, hiding the per-event norm/px math.
pub(crate) static INPUT_DIAG_COUNT: AtomicU32 = AtomicU32::new(0);

/// Reset the per-process `to_pixels` diagnostic counter so the next 50
/// input events are logged at INFO. Called from
/// `peer::attach_input_handler` each time the `input` DC opens (once
/// per session).
pub fn reset_input_diag_counter() {
    INPUT_DIAG_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// Parse the `MESHHARBORD_VIRTUAL_SCREEN` env-var value into a
/// `bool`. Accepts `1`, `true`, `yes`, `on` (case-insensitive, trimmed)
/// as truthy; anything else (including `None`) is false.
///
/// Lives here (in `input/mod.rs`) rather than `enigo_backend.rs` so
/// it's reachable from `main.rs` regardless of whether the
/// `enigo-input` feature is on for this build — the startup log line
/// surfaces the gate value even on signalling-only builds.
///
/// rc.54 — gate for the virtual-screen-aware `to_pixels` path.
pub fn parse_virtual_screen_flag(value: Option<&str>) -> bool {
    match value {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        None => false,
    }
}

// P6 — the multi-user InputArbiter: one injection worker for all sessions,
// per-session held-state tracking, cross-session modifier fencing,
// release-all on teardown, free|exclusive floor control, ghost cursors.
// Compiles on every build (injection degrades to NoopInjector).
pub mod arbiter;

// FR-93 P1 — what a session's input can reach, told to the controller
// (`rc:input-reach`) instead of injecting into nothing in silence.
pub mod reach;

// FR-97 P4a — the real Ctrl+Alt+Del (`SendSAS`) where Windows lets this
// process send it. The decision compiles everywhere; the call is Windows-only.
pub mod sas;

#[cfg(feature = "enigo-input")]
pub mod enigo_backend;

// rc.122 — Windows real-virtual-key text injection so typed letters land in the
// legacy console (Windows PowerShell 5.1 / cmd), which drops enigo.text()'s
// KEYEVENTF_UNICODE. Used by the shared `dispatch` KeyText arm.
#[cfg(all(target_os = "windows", feature = "enigo-input"))]
pub mod win_text;

// rc.227 — keyboard-layout awareness: per-char auto-switch (the programmatic
// ALT+SHIFT that fixes "typing is dead until I flip the remote layout"),
// rc:layout status snapshots for the viewer chip/picker, and the
// rc:layout.set manual-switch handler.
#[cfg(all(target_os = "windows", feature = "enigo-input"))]
pub mod layout;

/// FR-97 P3e — the X11 keyboard layout: the same snapshot, watch and switch
/// as the Windows module, so the peer's `rc:layout` emitter and its
/// `rc:layout.set` arm serve both under one name.
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
pub mod layout_x11;
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
pub use layout_x11 as layout;

#[cfg(all(
    feature = "system-context",
    target_os = "windows",
    feature = "enigo-input"
))]
pub mod system_context_backend;

/// FR-36 P4 — input via `/dev/uinput`, below the compositor. The companion to
/// `capture::drm_backend`: XTest reaches Xwayland clients only, so without
/// this a captured Wayland session is READ-ONLY. Linux-only by construction.
#[cfg(all(target_os = "linux", feature = "uinput-input"))]
pub mod uinput_backend;

/// FR-36 P4b — character → physical key, per keyboard layout. Split out from
/// the uinput backend because "which key produces this character" is a layout
/// question, not a uinput one, and it is the part most likely to grow.
#[cfg(all(target_os = "linux", feature = "uinput-input"))]
pub mod keylayout;

/// FR-36 P4 / FR-45 P4 — the HID usage → evdev keycode table. Shared: the
/// uinput injector writes these codes to `/dev/uinput`, the portal input path
/// sends them through `RemoteDesktop.NotifyKeyboardKeycode` — and the two
/// consumers sit behind different features.
#[cfg(all(
    target_os = "linux",
    any(feature = "uinput-input", feature = "portal-capture")
))]
pub(crate) mod hid_evdev;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Button {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

/// Linux `BTN_*` code for a mouse button. Shared by the uinput backend (evdev,
/// FR-36) and the portal input path (RemoteDesktop `NotifyPointerButton`,
/// FR-45) — the same 0x110–0x114 codes, previously duplicated in both.
#[cfg(all(
    target_os = "linux",
    any(feature = "uinput-input", feature = "portal-capture")
))]
pub(crate) fn button_code(btn: Button) -> u16 {
    match btn {
        Button::Left => 0x110,
        Button::Right => 0x111,
        Button::Middle => 0x112,
        Button::Back => 0x113,
        Button::Forward => 0x114,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WheelMode {
    Pixel,
    Line,
    Page,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TouchPhase {
    Start,
    Move,
    End,
    Cancel,
}

/// FR-109 — the kill switch for relative mode. `MESHHARBORD_INPUT_MOUSE_REL=0`
/// (or `false`, `no`, `off`) stops this agent advertising `mouse-rel`, so no
/// viewer sends it `mouse_rel`. Read where the caps are built.
pub const MOUSE_REL_ENV: &str = "MESHHARBORD_INPUT_MOUSE_REL";

/// FR-109 — does this agent advertise `mouse-rel` in `AgentCaps.input`?
/// Only where the injector a session opens now carries relative motion, and
/// not when the kill switch is set. On Windows the user worker and
/// SystemContext both inject through the same enigo `dispatch` (`SendInput`
/// relative). On Linux it is uinput's relative pointer (P2b), a RemoteDesktop
/// session on Wayland (P2c) or enigo on a real X11 display (P2a),
/// [`linux_injector_carries_rel`]. On macOS it is enigo's CGEvent motion in a
/// GUI session with the Accessibility grant (P2d),
/// [`macos_injector_carries_rel`].
pub fn advertises_mouse_rel() -> bool {
    !mouse_rel_switched_off(std::env::var(MOUSE_REL_ENV).ok().as_deref()) && injector_carries_rel()
}

#[cfg(all(target_os = "windows", feature = "enigo-input"))]
fn injector_carries_rel() -> bool {
    true
}

/// The cached desktop brief is at most a minute old, and the heartbeat
/// re-announces the caps when it changes, so the word follows the session:
/// a desktop whose input reaches only Xwayland takes it back.
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn injector_carries_rel() -> bool {
    let brief = crate::desktop_brief::current();
    linux_injector_carries_rel(uinput_would_inject(brief.as_ref()), brief.as_ref())
}

/// FR-109 P2b — whether a session opened now would inject through uinput,
/// answered when the caps are announced, which is before any session (a
/// capture that is alive only during one would come too late). Never when the
/// device cannot be opened: `open_default` then falls through to enigo.
/// - opted in (`MESHHARBORD_UINPUT=1`);
/// - an automatic system capture (FR-95) already alive;
/// - the brief planning the DRM arm with `uinput` unset: a system install's
///   automatic capture pairs that arm with uinput (`planned_input_route` leaves
///   it to the OS injector, and `open_default` picks uinput for it).
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn uinput_would_inject(brief: Option<&meshharbor_remote_control::models::DesktopBrief>) -> bool {
    #[cfg(feature = "uinput-input")]
    {
        if !uinput_backend::available() {
            return false;
        }
        if uinput_backend::env_enabled() {
            return true;
        }
        #[cfg(feature = "drm-capture")]
        {
            if crate::capture::seat_guard::live() {
                return true;
            }
            if uinput_unset() && brief.is_some_and(|b| b.capture_arm == "drm") {
                return true;
            }
        }
        #[cfg(not(feature = "drm-capture"))]
        let _ = brief;
        false
    }
    #[cfg(not(feature = "uinput-input"))]
    {
        let _ = brief;
        false
    }
}

/// Read at every announcement, like the Linux brief: a grant given while the
/// daemon runs is announced by the next heartbeat.
#[cfg(all(target_os = "macos", feature = "enigo-input"))]
fn injector_carries_rel() -> bool {
    macos_injector_carries_rel(
        crate::tcc::has_gui_session(),
        crate::tcc::accessibility_trusted(),
    )
}

#[cfg(not(all(
    any(target_os = "windows", target_os = "linux", target_os = "macos"),
    feature = "enigo-input"
)))]
fn injector_carries_rel() -> bool {
    false
}

/// FR-109 P2d — on macOS, whether the input a session opens now carries
/// relative motion. enigo's `Coordinate::Rel` posts a `MouseMoved` (or, with a
/// button held, a `…Dragged`) CGEvent at the cursor plus the delta, and sets
/// the event's `MOUSE_EVENT_DELTA_X/Y` to the delta itself, which is what a
/// game reading raw deltas takes. Both of these must hold:
/// - **a GUI session.** The root LaunchDaemon is in session 0 with no
///   WindowServer, and its TCC preflight can still answer "granted" (FR-80),
///   so the grant alone would advertise a word no event could honour.
/// - **the Accessibility grant.** Without it macOS drops every `CGEventPost`
///   and reports success, and the enigo we ship refuses to construct, so the
///   session falls back to no input at all.
#[cfg_attr(
    not(all(target_os = "macos", feature = "enigo-input")),
    allow(dead_code)
)]
pub(crate) fn macos_injector_carries_rel(gui_session: bool, accessibility: bool) -> bool {
    gui_session && accessibility
}

/// FR-109 P2 — on Linux, whether the input a session opens now carries
/// relative motion. Each yes below carries it, whichever takes an event:
/// - **uinput** (`uinput_injects`: opted in with `MESHHARBORD_UINPUT=1` and the
///   device opens, or the input of the automatic system capture, FR-95), the
///   first injector [`open_default`] tries. Its relative pointer (P2b) sits
///   below the compositor, so it carries relative motion whatever the session:
///   libinput hands its unaccelerated deltas on 1:1 (spec §8, P0 (3)).
/// - A **RemoteDesktop session** (P2c), which the arbiter hands each event
///   before any injector: on a Wayland desktop whose input reaches everything
///   through it (the brief's `portal` or `mutter` arm with `full` reach), its
///   own relative call (`NotifyPointerMotion`, `NotifyPointerMotionRelative`).
/// - Otherwise **enigo**, whose `Coordinate::Rel` is XTest relative motion
///   (P2a): an XI2 raw reader sees it 1:1 (§8 rows 4, 13). On a Wayland
///   desktop XTest reaches only Xwayland clients, so the brief's
///   `input_reach` must be `full` on an `x11` session.
/// - No brief yet (the refresher's first pass has not landed) is no.
#[cfg_attr(
    not(all(target_os = "linux", feature = "enigo-input")),
    allow(dead_code)
)]
pub(crate) fn linux_injector_carries_rel(
    uinput_injects: bool,
    brief: Option<&meshharbor_remote_control::models::DesktopBrief>,
) -> bool {
    uinput_injects
        || brief.is_some_and(|b| {
            b.input_reach == "full"
                && (b.kind == "x11"
                    || (b.kind == "wayland"
                        && matches!(b.capture_arm.as_str(), "portal" | "mutter")))
        })
}

/// FR-109 — the kill switch's reading of [`MOUSE_REL_ENV`]: only an explicit
/// false word switches relative mode off. Unset, or anything else, leaves it
/// on.
pub fn mouse_rel_switched_off(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("0" | "false" | "no" | "off")
    )
}

/// Input event from the controller. Coordinates are normalised 0..1 per
/// monitor so the agent's resolution can change mid-session without
/// needing a resync.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum InputMsg {
    MouseMove {
        x: f32,
        y: f32,
        mon: u8,
    },
    MouseButton {
        btn: Button,
        down: bool,
        x: f32,
        y: f32,
        mon: u8,
    },
    /// #1945 — let go of a button WITHOUT moving the pointer: how the arbiter
    /// releases what a closing session still holds.
    ///
    /// A `MouseButton` carries a position, and every backend moves there
    /// before the button so a click lands on its target. The release-all used
    /// to send a `MouseButton` up at (0,0), so a viewer that vanished mid-drag
    /// threw the host's cursor into the top-left corner: GNOME's Activities
    /// hot corner, or whatever a Mac has bound to that corner (Lock Screen,
    /// the screen saver). The drag ended there, too.
    ///
    /// It is a real variant, not a flag: the portal path serialises every
    /// event to its helper, and each backend's match is exhaustive, so a new
    /// backend cannot forget it. A viewer may send it as well; it can only let
    /// go of a button.
    MouseRelease {
        btn: Button,
    },
    /// FR-109 — relative motion in whole counts: the pointer moves by
    /// `(dx, dy)` from wherever it is, as a mouse moves it. Pointer Lock's
    /// deltas, for an app that hides the cursor and recentres it (a 3D
    /// viewport, a game camera), which an absolute move cannot drive past
    /// the edge of the viewer's stage.
    ///
    /// ⚠️ Sent only to an agent that advertises `mouse-rel`
    /// ([`advertises_mouse_rel`]): an older agent cannot parse it.
    MouseRel {
        dx: i32,
        dy: i32,
    },
    /// FR-109 — press a button WHERE THE POINTER IS. In relative mode the
    /// viewer has no position to send, because the host app owns the cursor,
    /// and a `MouseButton` moves to its position first. This is the press
    /// twin of [`InputMsg::MouseRelease`], which lets go without moving.
    MousePress {
        btn: Button,
    },
    MouseWheel {
        dx: f32,
        dy: f32,
        mode: WheelMode,
    },
    Key {
        code: u32,
        down: bool,
        mods: u8,
    },
    KeyText {
        text: String,
    },
    Touch {
        id: u32,
        phase: TouchPhase,
        x: f32,
        y: f32,
        mon: u8,
    },
    Heartbeat {
        seq: u64,
        ts_ms: u64,
    },
    /// FR-97 P4a — the secure attention sequence: what the physical
    /// Ctrl+Alt+Del raises, and what the Windows lock and sign-in screens
    /// answer where three ordinary keys reach nothing. `SendSAS` on a host
    /// that can send it ([`sas::availability`]); nothing anywhere else.
    ///
    /// ⚠️ Sent only to an agent that advertises `sas`: an older agent cannot
    /// parse it.
    Sas,
}

pub trait InputInjector: Send {
    fn inject(&mut self, event: InputMsg) -> Result<()>;
    /// Whether the backend currently has the OS permission to inject.
    /// On macOS this maps to the Accessibility privilege; on Wayland to
    /// membership in the `input` group / uinput permission.
    fn has_permission(&self) -> bool;

    /// FR-92 — the cursor, in DESKTOP pixels (the virtual screen on Windows,
    /// global display space on macOS, the root window on X11). Read on the
    /// injector thread, so a SystemContext worker's desktop rebind covers the
    /// read as well as the write. Default: [`PxUnsupported`].
    fn cursor_px(&mut self) -> Result<(i32, i32)> {
        Err(anyhow::Error::new(PxUnsupported))
    }

    /// FR-92 — move the cursor to desktop pixel `(x, y)` with REAL input,
    /// which resets the OS idle clock (a warp — `SetCursorPos`,
    /// `CGWarpMouseCursorPosition`, `XWarpPointer` — would move the pixel
    /// and reset nothing). Never goes through [`InputMsg`]'s normalised,
    /// primary-display mapping. Default: [`PxUnsupported`].
    fn move_px(&mut self, _x: i32, _y: i32) -> Result<()> {
        Err(anyhow::Error::new(PxUnsupported))
    }

    /// FR-92 — is a physical mouse button held right now? Read once per
    /// keep-busy resume, never polled. Default: [`PxUnsupported`].
    fn buttons_held(&mut self) -> Result<bool> {
        Err(anyhow::Error::new(PxUnsupported))
    }

    /// FR-92 P9 — move the pointer with REAL input to `(x, y)`, each in
    /// `0..=1` of the whole desktop the compositor maps an absolute pointing
    /// device onto (every monitor's bounding box). For a backend below the
    /// compositor — uinput, which has no pixel space and cannot read the
    /// pointer back — this is the only move keep busy has. Default:
    /// [`PxUnsupported`].
    fn move_norm(&mut self, _x: f64, _y: f64) -> Result<()> {
        Err(anyhow::Error::new(PxUnsupported))
    }

    /// FR-95 P2 — this injector was switched on by a system install by itself
    /// (uinput for the automatic DRM capture), and injects only while that
    /// capture reads the person's unlocked session. Default: `false`.
    fn automatic(&self) -> bool {
        false
    }
}

/// FR-95 P2 — `uinput` set to anything takes the automatic choice back:
/// `true` is the configured path, `false` keeps an automatic capture
/// view-only.
#[cfg(all(target_os = "linux", feature = "uinput-input", feature = "drm-capture"))]
fn uinput_unset() -> bool {
    tunnel_core::env::node_env("UINPUT").is_none()
}

/// FR-95 P2 — whether the arbiter's cached injector no longer matches what
/// [`open_default`] would pick now: an automatic system capture started (with
/// `uinput` unset) while another backend was cached, or an automatic uinput
/// outlived both its captures and the desktop they were for: a Wayland one,
/// or (FR-113) an X11 one while `x11_auto_system` is on. Never
/// while an automatic capture is alive, locked or not: an injector swapped in
/// there would be enigo, whose XTest reaches Xwayland windows behind the lock
/// screen.
pub(crate) fn stale(inj: &dyn InputInjector) -> bool {
    #[cfg(all(target_os = "linux", feature = "uinput-input", feature = "drm-capture"))]
    {
        let live = crate::capture::seat_guard::live();
        if inj.automatic() {
            !live && crate::capture::automatic_seat_kind().is_none()
        } else {
            live && uinput_unset()
        }
    }
    #[cfg(not(all(target_os = "linux", feature = "uinput-input", feature = "drm-capture")))]
    {
        let _ = inj;
        false
    }
}

/// FR-92 — the backend has no pixel-space read/move (Noop, uinput, a
/// portal-owned route). Distinct from a transient failure: keep-busy reports
/// it as unavailable rather than retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PxUnsupported;

impl std::fmt::Display for PxUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("this input backend has no pixel-space cursor read/move")
    }
}

impl std::error::Error for PxUnsupported {}

/// FR-92 — a pixel-space job for an injector THREAD, answered on `reply`.
/// The enigo and SystemContext backends carry these on the same channel as
/// their [`InputMsg`]s, so a read is ordered after every event queued
/// before it.
#[cfg(feature = "enigo-input")]
pub(crate) enum PxJob {
    Locate(std::sync::mpsc::SyncSender<Result<(i32, i32)>>),
    Move {
        x: i32,
        y: i32,
        reply: std::sync::mpsc::SyncSender<Result<()>>,
    },
    Buttons(std::sync::mpsc::SyncSender<Result<bool>>),
}

/// How long a caller waits for an injector thread to answer a [`PxJob`]. A
/// stuck injector thread must not hang the arbiter (and with it every
/// controller's input) behind a keep-busy read.
pub const PX_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

/// Send `make(reply)` to an injector thread and wait (bounded) for the answer.
#[cfg(feature = "enigo-input")]
pub(crate) fn px_round_trip<T, J>(
    tx: &std::sync::mpsc::Sender<J>,
    make: impl FnOnce(std::sync::mpsc::SyncSender<Result<T>>) -> J,
) -> Result<T> {
    let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel::<Result<T>>(1);
    tx.send(make(reply_tx))
        .map_err(|_| anyhow::anyhow!("input worker exited"))?;
    reply_rx
        .recv_timeout(PX_REPLY_TIMEOUT)
        .map_err(|_| anyhow::anyhow!("input worker did not answer within {PX_REPLY_TIMEOUT:?}"))?
}

pub struct NoopInjector;

impl InputInjector for NoopInjector {
    fn inject(&mut self, _event: InputMsg) -> Result<()> {
        Ok(())
    }
    fn has_permission(&self) -> bool {
        false
    }
}

/// Open the best-available input backend for the current host. Falls
/// back to [`NoopInjector`] when enigo-input is off or init fails.
///
/// M3 A1: when the agent is built with the `system-context` feature
/// AND the worker probes as `WorkerRole::SystemContext` at startup
/// (i.e. it was spawned by the SCM service via
/// `winlogon_token::spawn_system_in_session`), route to
/// [`system_context_backend::SystemContextInjector`] which adds a
/// per-event `SetThreadDesktop` rebind preamble. User-context workers
/// fall through to [`enigo_backend::EnigoInjector`] with no behaviour
/// change.
pub fn open_default() -> Box<dyn InputInjector + Send> {
    // Plain preflight: while the owner grants Accessibility, do not construct
    // an enigo worker (and prompt) for every incoming event.
    #[cfg(target_os = "macos")]
    if !crate::tcc::accessibility_trusted() {
        crate::tcc_recovery::watch_permissions();
        return Box::new(NoopInjector);
    }
    #[cfg(all(
        feature = "system-context",
        target_os = "windows",
        feature = "enigo-input"
    ))]
    {
        use crate::system_context::worker_role::{WorkerRole, probe_self};
        match probe_self() {
            Ok(WorkerRole::SystemContext) => {
                match system_context_backend::SystemContextInjector::new() {
                    Ok(e) => {
                        tracing::info!(
                            "input: backend=system-context (enigo with SetThreadDesktop rebind)"
                        );
                        return Box::new(e);
                    }
                    Err(e) => {
                        tracing::warn!(
                            %e,
                            "system-context input init failed — falling through to standard enigo backend"
                        );
                    }
                }
            }
            Ok(WorkerRole::User) => {
                // Normal path. Fall through to the user-context
                // EnigoInjector below.
            }
            Err(e) => {
                tracing::warn!(
                    %e,
                    "worker_role::probe_self in input::open_default failed — assuming user-context"
                );
            }
        }
    }
    // FR-36 P4 — uinput, below the compositor. Opt-in for the same reason the
    // DRM capture backend is: a virtual input device is host-global and shows
    // up in every application's device list, so one must never appear merely
    // because a host upgraded. `MESHHARBORD_UINPUT=1`, normally paired with
    // `MESHHARBORD_DRM_CAPTURE=1` on a Wayland host.
    //
    // ⚠️ Placed AHEAD of enigo deliberately: on a native Wayland desktop XTest
    // reaches only Xwayland clients, so enigo does not fail — it succeeds and
    // does nothing, which is far harder to diagnose than an error.
    #[cfg(all(target_os = "linux", feature = "uinput-input"))]
    {
        if uinput_backend::env_enabled() {
            match uinput_backend::UinputInjector::new() {
                Ok(u) => return Box::new(u),
                Err(e) => {
                    tracing::warn!(
                        error = %format!("{e:#}"),
                        "MESHHARBORD_UINPUT=1 but uinput init failed — falling through to the standard backend"
                    );
                }
            }
        }
    }
    // FR-95 P2 — the input of a capture a system install switched on by
    // itself: uinput, below the compositor, injecting only while that capture
    // reads the person's session on screen, unlocked. Chosen whenever one is
    // alive, locked or not (the arbiter swaps it in when one starts, `stale`),
    // so a first event during a lock never opens enigo; never with `uinput`
    // set either way.
    #[cfg(all(target_os = "linux", feature = "uinput-input", feature = "drm-capture"))]
    {
        if uinput_unset() && crate::capture::seat_guard::live() {
            match uinput_backend::UinputInjector::new() {
                Ok(u) => {
                    tracing::info!(
                        "input: uinput for the automatic system capture, injecting only while it \
                         reads the person's session (FR-95 P2)"
                    );
                    return Box::new(u.for_auto_system());
                }
                Err(e) => {
                    tracing::warn!(
                        error = %format!("{e:#}"),
                        "input: the automatic system capture's uinput did not open (FR-95 P2)"
                    );
                }
            }
        }
    }
    #[cfg(feature = "enigo-input")]
    {
        match enigo_backend::EnigoInjector::new() {
            Ok(e) => return Box::new(e),
            Err(e) => {
                tracing::warn!(%e, "enigo init failed — input injection disabled");
            }
        }
    }
    #[cfg(not(feature = "enigo-input"))]
    {
        tracing::info!(
            "built without enigo-input feature — input events will be dropped. \
             Rebuild with `--features enigo-input` (or `--features full`)."
        );
    }
    Box::new(NoopInjector)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rc.54 — verify the env-var parse rules. Covers truthy variants
    /// (case + whitespace), explicit false values, missing var, and
    /// unrecognised values (which must default to false to keep the
    /// gate fail-closed).
    #[test]
    fn parse_virtual_screen_flag_accepts_truthy_values() {
        assert!(parse_virtual_screen_flag(Some("1")));
        assert!(parse_virtual_screen_flag(Some("true")));
        assert!(parse_virtual_screen_flag(Some("True")));
        assert!(parse_virtual_screen_flag(Some("TRUE")));
        assert!(parse_virtual_screen_flag(Some("yes")));
        assert!(parse_virtual_screen_flag(Some("on")));
        assert!(parse_virtual_screen_flag(Some("  1  ")));
        assert!(parse_virtual_screen_flag(Some("\tTrue\n")));
    }

    /// rc.57 — verify the diagnostic counter actually resets. Cargo
    /// runs tests in parallel within a binary by default, but only one
    /// test below mutates `INPUT_DIAG_COUNT` so there's no inter-test
    /// race. If another test ever touches the counter, gate this with
    /// `#[serial_test::serial]` or move both to a single test.
    #[test]
    fn reset_input_diag_counter_zeroes_the_counter() {
        use std::sync::atomic::Ordering;
        // Set to non-zero to prove the reset has work to do.
        INPUT_DIAG_COUNT.store(42, Ordering::Relaxed);
        assert_eq!(INPUT_DIAG_COUNT.load(Ordering::Relaxed), 42);
        reset_input_diag_counter();
        assert_eq!(INPUT_DIAG_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn parse_virtual_screen_flag_rejects_falsy_values() {
        assert!(!parse_virtual_screen_flag(None));
        assert!(!parse_virtual_screen_flag(Some("")));
        assert!(!parse_virtual_screen_flag(Some("0")));
        assert!(!parse_virtual_screen_flag(Some("false")));
        assert!(!parse_virtual_screen_flag(Some("no")));
        assert!(!parse_virtual_screen_flag(Some("off")));
        // Unrecognised values must be false — fail-closed gate.
        assert!(!parse_virtual_screen_flag(Some("maybe")));
        assert!(!parse_virtual_screen_flag(Some("2")));
        assert!(!parse_virtual_screen_flag(Some("enabled")));
    }

    /// FR-109 — the two new frames as the viewer spells them. A wire name is
    /// a compatibility surface: renaming one makes every viewer's frames
    /// unparseable without failing anything loudly.
    #[test]
    fn fr109_the_wire_spells_mouse_rel_and_mouse_press() {
        let rel: InputMsg = serde_json::from_str(r#"{"t":"mouse_rel","dx":3,"dy":-4}"#).unwrap();
        assert_eq!(rel, InputMsg::MouseRel { dx: 3, dy: -4 });
        let press: InputMsg = serde_json::from_str(r#"{"t":"mouse_press","btn":"left"}"#).unwrap();
        assert_eq!(press, InputMsg::MousePress { btn: Button::Left });
        assert_eq!(
            serde_json::to_string(&InputMsg::MouseRel { dx: -1, dy: 0 }).unwrap(),
            r#"{"t":"mouse_rel","dx":-1,"dy":0}"#
        );
        // Whole counts only: the viewer carries the fraction, so a float is a
        // viewer bug, refused rather than truncated here.
        assert!(serde_json::from_str::<InputMsg>(r#"{"t":"mouse_rel","dx":0.5,"dy":0}"#).is_err());
    }

    /// FR-97 P4a — the viewer's word for the real Ctrl+Alt+Del, both ways.
    #[test]
    fn fr97_p4a_the_wire_spells_sas() {
        let sas: InputMsg = serde_json::from_str(r#"{"t":"sas"}"#).unwrap();
        assert_eq!(sas, InputMsg::Sas);
        assert_eq!(
            serde_json::to_string(&InputMsg::Sas).unwrap(),
            r#"{"t":"sas"}"#
        );
    }

    /// FR-109 — the kill switch reads only an explicit false word; unset or
    /// anything else leaves relative mode on.
    #[test]
    fn fr109_the_kill_switch_reads_only_false_words() {
        for off in ["0", "false", "FALSE", " no ", "off"] {
            assert!(mouse_rel_switched_off(Some(off)), "{off:?}");
        }
        for on in ["1", "true", "yes", "", "maybe"] {
            assert!(!mouse_rel_switched_off(Some(on)), "{on:?}");
        }
        assert!(!mouse_rel_switched_off(None));
    }

    /// FR-109 — on Linux, nothing is advertised while no X11 desktop brief
    /// says enigo reaches the session: a test process has none. (Not on
    /// macOS, where the answer is the grant of whatever launched the test,
    /// [`fr109_macos_needs_a_gui_session_and_the_grant`].)
    #[cfg(target_os = "linux")]
    #[test]
    fn fr109_no_brief_advertises_no_mouse_rel() {
        assert!(!advertises_mouse_rel());
    }

    /// FR-109 P2 — on Linux, uinput's relative pointer carries relative motion
    /// whatever the session (P2b), a RemoteDesktop session on Wayland (P2c),
    /// and enigo only on a real X11 display (P2a).
    /// Without uinput, a Wayland desktop, Xwayland-only reach, a tty and no
    /// brief do not.
    #[test]
    fn fr109_linux_mouse_rel_for_uinput_and_for_xtest_on_a_real_x11_display() {
        use meshharbor_remote_control::models::DesktopBrief;
        let briefed = |kind: &str, arm: &str, reach: &str| DesktopBrief {
            session: "user".into(),
            kind: kind.into(),
            desktop: None,
            capture_arm: arm.into(),
            input_reach: reach.into(),
        };
        let brief = |kind: &str, reach: &str| briefed(kind, "x11", reach);
        // P2c — a Wayland session whose input reaches everything through the
        // portal's or mutter's RemoteDesktop session carries it; the same arm
        // with only Xwayland's reach, or a DRM arm without uinput, does not.
        assert!(linux_injector_carries_rel(
            false,
            Some(&briefed("wayland", "portal", "full"))
        ));
        assert!(linux_injector_carries_rel(
            false,
            Some(&briefed("wayland", "mutter", "full"))
        ));
        assert!(!linux_injector_carries_rel(
            false,
            Some(&briefed("wayland", "portal", "xwayland_only"))
        ));
        assert!(!linux_injector_carries_rel(
            false,
            Some(&briefed("wayland", "drm", "full"))
        ));
        let wayland = brief("wayland", "full");
        // uinput, below the compositor: any session, even before a brief.
        assert!(linux_injector_carries_rel(true, Some(&wayland)));
        assert!(linux_injector_carries_rel(
            true,
            Some(&brief("x11", "full"))
        ));
        assert!(linux_injector_carries_rel(true, None));
        // enigo: a real X11 display its input reaches, and nothing else.
        assert!(linux_injector_carries_rel(
            false,
            Some(&brief("x11", "full"))
        ));
        assert!(!linux_injector_carries_rel(false, Some(&wayland)));
        assert!(!linux_injector_carries_rel(
            false,
            Some(&brief("wayland", "xwayland_only"))
        ));
        assert!(!linux_injector_carries_rel(
            false,
            Some(&brief("x11", "none"))
        ));
        assert!(!linux_injector_carries_rel(
            false,
            Some(&brief("tty", "none"))
        ));
        assert!(!linux_injector_carries_rel(false, None));
    }

    /// FR-109 P2d — on macOS, the word needs a GUI session AND the
    /// Accessibility grant. The root LaunchDaemon's preflight can answer
    /// "granted" with no WindowServer to post into, so a grant alone is no.
    #[test]
    fn fr109_macos_needs_a_gui_session_and_the_grant() {
        assert!(macos_injector_carries_rel(true, true));
        assert!(
            !macos_injector_carries_rel(false, true),
            "the root LaunchDaemon"
        );
        assert!(!macos_injector_carries_rel(true, false), "no grant");
        assert!(!macos_injector_carries_rel(false, false));
    }

    /// FR-109 AC6 — relative mode only INJECTS: no hook, raw-input sink or key
    /// poll anywhere in its agent code, FR-92's rule. Each is what a keylogger
    /// looks like to EDR, and a GPO-locked desktop running EDR is in the
    /// acceptance bar. The one sanctioned read is FR-92's own: keep busy asks
    /// whether a MOUSE button is down (`buttons_held_now`, never a key), and
    /// only that function may. The banned names are assembled at run time, so
    /// this file cannot trip its own scan.
    #[test]
    fn fr109_relative_mouse_reads_no_input() {
        let sources = [
            ("input/mod.rs", include_str!("mod.rs")),
            ("input/enigo_backend.rs", include_str!("enigo_backend.rs")),
            (
                "input/system_context_backend.rs",
                include_str!("system_context_backend.rs"),
            ),
            ("input/arbiter.rs", include_str!("arbiter.rs")),
            ("input/uinput_backend.rs", include_str!("uinput_backend.rs")),
            (
                "capture/portal/input.rs",
                include_str!("../capture/portal/input.rs"),
            ),
        ];
        let banned: Vec<String> = [
            ["SetWindows", "HookEx"],
            ["RegisterRaw", "InputDevices"],
            ["GetRaw", "InputData"],
            ["GetKeyboard", "State"],
            ["EVIOC", "GRAB"],
            ["XRecord", "EnableContext"],
            ["XISelect", "Events"],
            ["CGEvent", "TapCreate"],
        ]
        .iter()
        .map(|p| p.concat())
        .collect();
        let key_poll = ["GetAsync", "KeyState"].concat();
        for (name, src) in sources {
            let lines: Vec<&str> = src.lines().collect();
            // FR-92's mouse-button read: the first `buttons_held_now` (the
            // Windows one) down to its closing brace.
            let sanctioned = if name == "input/enigo_backend.rs" {
                lines
                    .iter()
                    .position(|l| l.starts_with("fn buttons_held_now"))
                    .and_then(|start| {
                        let len = lines[start..].iter().position(|l| *l == "}")?;
                        Some(start..=start + len)
                    })
            } else {
                None
            };
            for (i, line) in lines.iter().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for b in &banned {
                    assert!(!code.contains(b.as_str()), "{name}:{}: uses {b}", i + 1);
                }
                if code.contains(key_poll.as_str()) {
                    assert!(
                        sanctioned.as_ref().is_some_and(|r| r.contains(&i)),
                        "{name}:{}: polls key state outside FR-92's mouse-button read",
                        i + 1
                    );
                }
            }
        }
    }
}
