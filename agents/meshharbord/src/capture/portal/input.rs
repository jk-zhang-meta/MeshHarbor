// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-45 P4 — input through the portal's **RemoteDesktop** interface.
//!
//! The pair to [`super::backend`]'s capture half: on a host whose desktop only
//! the portal can see, the portal is also the only thing that can *touch* it.
//! Measured on WSL2 (FR-45 field log, 2026-08-31): uinput happily creates a
//! device and libinput enumerates it, but a nested compositor reads its
//! PARENT, not evdev — the writer works and the reader is missing. So capture
//! without this is a read-only session on exactly the hosts FR-45 exists for.
//!
//! ## Where this runs
//!
//! In the **helper**, which holds the portal session. The daemon's input
//! arbiter forwards [`InputMsg`] values as JSON lines on the helper's stdin
//! (see [`super::helper`]); this module maps each to `Notify*` calls on the
//! session. Same binary on both ends, so the line format cannot skew.
//!
//! ## The mapping is a pure function
//!
//! [`plan`] turns an `InputMsg` into [`PortalCall`]s with no D-Bus in sight,
//! and [`InputContext`] executes them. The split is what makes the mapping
//! testable — the tests pin the coordinate scaling, the button codes, the
//! wheel-detent accumulation and the keysym rules without a portal anywhere.
//!
//! ## Conventions worth pinning
//!
//! - `NotifyKeyboardKeycode` takes **evdev** keycodes (KEY_A = 30) — not
//!   X keycodes (evdev+8), not keysyms. gnome-remote-desktop sends exactly
//!   these; the shared [`hid_to_evdev`] table already speaks them.
//! - `KeyText` goes through **keysyms**: keysym = codepoint for the printable
//!   Latin-1 ranges, codepoint + 0x0100_0000 above. The compositor resolves
//!   each against its OWN keymap, so this needs no char→key table of ours and
//!   gets shifted levels for free — which is what the uinput backend has to
//!   hand-maintain per layout.
//!
//!   ⚠️⚠️ **It is NOT layout-proof, and the failure is SILENT.** Measured on
//!   GNOME with a US keymap (2026-09-01, FR-45 field log): `@ # ~` typed
//!   correctly — shifted levels the keymap can reach — while `é € £` produced
//!   **nothing at all**, with `NotifyKeyboardKeysym` returning success for
//!   every one of them. A character the host's active keymap cannot produce is
//!   dropped by the compositor, and nothing on this side can see that happen.
//!   [`run_pump`] therefore warns once when it forwards a non-ASCII keysym, so
//!   "my accented characters vanish" is diagnosable from the daemon log rather
//!   than being an unattributable mystery.
//!
//!   The real fix is what gnome-remote-desktop does — temporarily remap a
//!   spare keycode to the wanted keysym — which is a feature, not a tweak, and
//!   is deliberately not attempted here.
//! - Axis sign follows libinput: **positive is down/right**, matching the
//!   browser's wheel delta directly. ⚠️ evdev `REL_WHEEL` is the opposite —
//!   copying the uinput backend's inversion here would scroll backwards.
//!   ⚠️ KDE's backend negates the vertical smooth axis on its way to KWin, so
//!   [`for_backend`] negates it first there (FR-93 P4b).
//! - ⚠️ **The portal's calls wait for their replies** (FR-93 P4b). The portal
//!   handles each call on a worker thread, so unawaited calls can reach the
//!   compositor out of order. [`Target::delivery`] has the measurement.

use crate::input::hid_evdev::hid_to_evdev;
use crate::input::{InputMsg, WheelMode, button_code};

/// The keysym for one typed character, or `None` for one we cannot honestly
/// express as a printable keysym.
///
/// The rules are X11's: the PRINTABLE Latin-1 ranges (U+0020..=U+007E and
/// U+00A0..=U+00FF) ARE the keysym values; everything above U+00FF rides the
/// Unicode escape 0x0100_0000 + cp. Return and Tab are the two C0 controls a
/// text field actually receives.
///
/// ⚠️ DEL (0x7F) and the C1 controls (0x80..=0x9F) are deliberately excluded:
/// they fall INSIDE the raw Latin-1 numeric span but are control characters,
/// not printable keysyms, so mapping them to a bare keysym would send an
/// undefined value. They return `None` like the C0 controls below 0x20.
fn keysym_of(ch: char) -> Option<u32> {
    match ch {
        '\n' | '\r' => Some(0xFF0D), // XK_Return
        '\t' => Some(0xFF09),        // XK_Tab
        c => {
            let cp = c as u32;
            match cp {
                0x20..=0x7E | 0xA0..=0xFF => Some(cp), // printable Latin-1
                0x100.. => Some(0x0100_0000 + cp),     // Unicode escape plane
                _ => None,                             // C0, DEL (0x7F), C1 (0x80..=0x9F)
            }
        }
    }
}

/// One portal call, as data. `plan` produces these; `InputContext` executes
/// them; the tests read them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PortalCall {
    /// `NotifyPointerMotionAbsolute` — coordinates in the STREAM's logical
    /// space, which is why planning needs the logical size.
    MotionAbs { x: f64, y: f64 },
    /// `NotifyPointerMotion` — FR-109 P2c, relative motion. It names no
    /// stream: it moves the pointer from wherever it is.
    MotionRel { dx: f64, dy: f64 },
    /// `NotifyPointerButton` — `code` is a Linux `BTN_*`.
    Button { code: i32, down: bool },
    /// `NotifyPointerAxis` — smooth scroll, positive down/right.
    Axis { dx: f64, dy: f64 },
    /// `NotifyPointerAxisDiscrete` — `axis` 0 = vertical, 1 = horizontal.
    AxisDiscrete { axis: u32, steps: i32 },
    /// `NotifyKeyboardKeycode` — evdev code.
    Keycode { code: i32, down: bool },
    /// `NotifyKeyboardKeysym`.
    Keysym { sym: i32, down: bool },
}

/// Carries the fractional wheel remainder between events, exactly as the
/// uinput backend does — without it, slow trackpad scrolling in `Line` mode
/// never accumulates to a detent and simply does nothing.
#[derive(Debug, Default)]
pub struct WheelAccum {
    rx: f64,
    ry: f64,
}

/// Map one wire event onto portal calls.
///
/// `logical` is the stream's logical size — the portal's own coordinate space
/// for `NotifyPointerMotionAbsolute`, NOT the pixel size (they differ under a
/// HiDPI scale factor). The wire's normalised 0..1 makes the conversion a
/// single multiply.
pub fn plan(msg: &InputMsg, logical: (f64, f64), wheel: &mut WheelAccum) -> Vec<PortalCall> {
    let to_abs = |x: f32, y: f32| PortalCall::MotionAbs {
        x: f64::from(x.clamp(0.0, 1.0)) * logical.0,
        y: f64::from(y.clamp(0.0, 1.0)) * logical.1,
    };
    match msg {
        InputMsg::MouseMove { x, y, .. } => vec![to_abs(*x, *y)],
        InputMsg::MouseButton {
            btn, down, x, y, ..
        } => {
            // Position first, then the button — same rule as the uinput
            // backend: a click whose move arrives separately can land at the
            // old position if the compositor samples between the two.
            vec![
                to_abs(*x, *y),
                PortalCall::Button {
                    code: i32::from(button_code(*btn)),
                    down: *down,
                },
            ]
        }
        // #1945 — the arbiter's release-all: no motion, so the button lets go
        // where the pointer is. A move first threw it to (0,0), GNOME's
        // Activities hot corner, whenever a viewer vanished mid-drag.
        InputMsg::MouseRelease { btn } => vec![PortalCall::Button {
            code: i32::from(button_code(*btn)),
            down: false,
        }],
        // FR-109 — relative mode's press, the release's twin: no motion.
        InputMsg::MousePress { btn } => vec![PortalCall::Button {
            code: i32::from(button_code(*btn)),
            down: true,
        }],
        // FR-109 P2c — relative motion rides the RemoteDesktop session's own
        // call (the portal's `NotifyPointerMotion`, mutter's
        // `NotifyPointerMotionRelative`), which names no stream. An all-zero
        // frame sends nothing.
        InputMsg::MouseRel { dx, dy } => {
            if *dx == 0 && *dy == 0 {
                vec![]
            } else {
                vec![PortalCall::MotionRel {
                    dx: f64::from(*dx),
                    dy: f64::from(*dy),
                }]
            }
        }
        InputMsg::MouseWheel { dx, dy, mode } => match mode {
            // Smooth deltas pass through: the browser's pixels are already
            // libinput's "scroll distance", positive down/right on both ends.
            WheelMode::Pixel => vec![PortalCall::Axis {
                dx: f64::from(*dx),
                dy: f64::from(*dy),
            }],
            // Lines and pages become discrete detents, with the remainder
            // carried. A page is a burst of detents rather than its own axis
            // — the uinput backend's convention, kept so the two paths scroll
            // the same distance for the same wire event.
            WheelMode::Line | WheelMode::Page => {
                let per = if *mode == WheelMode::Page { 3.0 } else { 1.0 };
                wheel.rx += f64::from(*dx) * per;
                wheel.ry += f64::from(*dy) * per;
                let (cx, cy) = (wheel.rx.trunc() as i32, wheel.ry.trunc() as i32);
                wheel.rx -= f64::from(cx);
                wheel.ry -= f64::from(cy);
                let mut out = Vec::new();
                if cy != 0 {
                    out.push(PortalCall::AxisDiscrete { axis: 0, steps: cy });
                }
                if cx != 0 {
                    out.push(PortalCall::AxisDiscrete { axis: 1, steps: cx });
                }
                out
            }
        },
        InputMsg::Key { code, down, .. } => match hid_to_evdev(*code) {
            Some(k) => vec![PortalCall::Keycode {
                code: i32::from(k),
                down: *down,
            }],
            // FR-13's contract, shared with every other backend: an unmapped
            // HID usage is DROPPED, never guessed at.
            None => vec![],
        },
        InputMsg::KeyText { text } => {
            let mut out = Vec::new();
            for ch in text.chars() {
                if let Some(sym) = keysym_of(ch) {
                    let sym = sym as i32;
                    out.push(PortalCall::Keysym { sym, down: true });
                    out.push(PortalCall::Keysym { sym, down: false });
                }
            }
            out
        }
        // Same as enigo and uinput: no touch injection yet. The portal has
        // NotifyTouch*, so this is a follow-up, not a wall.
        InputMsg::Touch { .. } => vec![],
        InputMsg::Heartbeat { .. } => vec![],
        // FR-97 P4a — Windows only; a Linux agent never advertises `sas`.
        InputMsg::Sas => vec![],
    }
}

/// FR-93 P4b — the bus name xdg-desktop-portal-kde owns while it runs. On a KDE
/// session the portal's RemoteDesktop calls reach KWin through it.
const KDE_PORTAL_IMPL: &str = "org.freedesktop.impl.portal.desktop.kde";

/// FR-93 P4b — where a RemoteDesktop backend departs from the portal's own
/// conventions on its way to the compositor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackendQuirks {
    /// xdg-desktop-portal-kde negates the VERTICAL SMOOTH scroll delta
    /// (`requestPointerAxis`: `wl_fixed_from_double(-y)`), while the portal's
    /// convention, GNOME's backend, KDE's own horizontal axis and its discrete
    /// path all keep positive = down/right. Measured on Plasma 6.7: a wheel
    /// notch down (`dy = +120`) reached the probe as `-120`, up.
    pub negated_smooth_y: bool,
}

/// FR-93 P4b — undo a backend's departure, so the call reaches the compositor
/// meaning what the portal's convention says it means.
pub fn for_backend(call: PortalCall, quirks: BackendQuirks) -> PortalCall {
    match call {
        PortalCall::Axis { dx, dy } if quirks.negated_smooth_y => PortalCall::Axis { dx, dy: -dy },
        other => other,
    }
}

/// FR-93 P4b — is KDE's portal backend the one on this session's bus? Read
/// from the bus daemon, which starts nothing. Any error reads as "no": the
/// calls then go out as the portal's convention has them.
fn kde_backend(conn: &zbus::blocking::Connection) -> bool {
    let Ok(bus) = zbus::blocking::fdo::DBusProxy::new(conn) else {
        return false;
    };
    let Ok(name) = zbus::names::BusName::try_from(KDE_PORTAL_IMPL) else {
        return false;
    };
    bus.name_has_owner(name).unwrap_or(false)
}

/// FR-93 P4 — `NotifyPointerAxis` flags on mutter's RemoteDesktop session:
/// `1` finish, `2` wheel, `4` finger, `8` continuous. With no source flag
/// mutter assumes a FINGER (a touchpad gesture, which a `FINISH` ends and
/// kinetic scrolling follows); a viewer's wheel delta is a wheel.
const MUTTER_AXIS_SOURCE_WHEEL: u32 = 1 << 1;

/// FR-93 P4 — one call on mutter's own RemoteDesktop session, as data: the same
/// events as [`PortalCall`] in mutter's shapes. The call is made ON the session
/// object, so there is no session handle and no options; absolute motion names
/// the screencast stream (by object path), and states are booleans.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MutterCall {
    /// `NotifyPointerMotionAbsolute(stream, x, y)`: the stream's own
    /// coordinates, which mutter maps onto the monitor it records.
    MotionAbs { x: f64, y: f64 },
    /// `NotifyPointerMotionRelative(d, d)`: FR-109 P2c, from wherever the
    /// pointer is.
    MotionRel { dx: f64, dy: f64 },
    /// `NotifyPointerButton(i, b)`: a Linux `BTN_*`.
    Button { code: i32, down: bool },
    /// `NotifyPointerAxis(d, d, u)`.
    Axis { dx: f64, dy: f64, flags: u32 },
    /// `NotifyPointerAxisDiscrete(u, i)`: `axis` 0 = vertical, 1 = horizontal;
    /// positive steps are down/right, as on the portal.
    AxisDiscrete { axis: u32, steps: i32 },
    /// `NotifyKeyboardKeycode(u, b)`: an evdev code, as on the portal.
    Keycode { code: u32, down: bool },
    /// `NotifyKeyboardKeysym(u, b)`.
    Keysym { sym: u32, down: bool },
}

/// [`PortalCall`] → [`MutterCall`]. `None` only for a keycode that cannot be
/// one (negative), which no HID usage maps to.
pub fn mutter_call(call: PortalCall) -> Option<MutterCall> {
    Some(match call {
        PortalCall::MotionAbs { x, y } => MutterCall::MotionAbs { x, y },
        PortalCall::MotionRel { dx, dy } => MutterCall::MotionRel { dx, dy },
        PortalCall::Button { code, down } => MutterCall::Button { code, down },
        PortalCall::Axis { dx, dy } => MutterCall::Axis {
            dx,
            dy,
            flags: MUTTER_AXIS_SOURCE_WHEEL,
        },
        PortalCall::AxisDiscrete { axis, steps } => MutterCall::AxisDiscrete { axis, steps },
        PortalCall::Keycode { code, down } => MutterCall::Keycode {
            code: u32::try_from(code).ok()?,
            down,
        },
        // `keysym_of` built it from a u32; the cast is the way back.
        PortalCall::Keysym { sym, down } => MutterCall::Keysym {
            sym: sym as u32,
            down,
        },
    })
}

// ── the D-Bus half ──────────────────────────────────────────────────────

/// Which RemoteDesktop session the calls go to.
enum Target {
    /// xdg-desktop-portal's (FR-45 P4): every call names the session handle
    /// and the PipeWire node.
    Portal {
        session: zbus::zvariant::OwnedObjectPath,
        /// The PipeWire node whose logical space `MotionAbs` coordinates are in.
        node_id: u32,
    },
    /// mutter's own (FR-93 P4): the proxy IS the session.
    Mutter {
        /// The screencast stream's object path, which absolute motion names.
        stream: String,
    },
}

/// FR-93 P4b — how a `Notify*` call goes on the bus. This decides whether the
/// calls reach the compositor in the order they were sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// Wait for each call's reply before sending the next. The reply is empty;
    /// the wait is what keeps the order.
    Awaited,
    /// Write the call and go on (`NO_REPLY_EXPECTED`). Only for a receiver
    /// that handles calls in the order they arrive.
    Unawaited,
}

impl Target {
    /// ⚠️ **The portal's calls are [`Delivery::Awaited`]: never "optimise"
    /// them back to `call_noreply`.** xdg-desktop-portal runs every
    /// RemoteDesktop method call on its own worker thread
    /// (`HANDLE_METHOD_INVOCATIONS_IN_THREAD`), so two calls sent back to back
    /// reach the backend in either order.
    ///
    /// Measured on KDE (Plasma 6.7) with unawaited calls: 41 of 452 typed
    /// characters came out wrong over four runs, and none once the calls
    /// waited. A key's release arrived before its press. KWin dropped the
    /// release, because the key was not down, then took the press. The key
    /// stayed held until that letter's next keystroke, and KWin dropped that
    /// press as a repeat. A button's release overtaking its press would hold a
    /// mouse button down on the host the same way.
    ///
    /// The frontend forwards each call to the backend BEFORE it replies, so
    /// waiting for the reply keeps the order, for one bus round trip per call.
    /// Measured on that host: 0.5 ms at the median, under 4 ms at p99. The
    /// viewer sends a pointer move every 8 ms at most, so this keeps up.
    ///
    /// Mutter answers its own RemoteDesktop session on its main loop, in the
    /// order the calls arrive, so there a reply would only add a round trip.
    fn delivery(&self) -> Delivery {
        match self {
            Target::Portal { .. } => Delivery::Awaited,
            Target::Mutter { .. } => Delivery::Unawaited,
        }
    }
}

/// Everything needed to execute [`PortalCall`]s against a live RemoteDesktop
/// session. Built in `run_stream` once the stream is negotiated, handed to
/// the stdin pump thread.
pub struct InputContext {
    proxy: zbus::blocking::Proxy<'static>,
    target: Target,
    /// The space `MotionAbs` coordinates are in: the portal stream's logical
    /// size, or a mutter stream's own size.
    pub logical: (f64, f64),
    /// FR-93 P4b — what the portal's backend does to the calls (none for
    /// mutter, which is no portal).
    pub quirks: BackendQuirks,
}

impl InputContext {
    pub fn new(
        conn: &zbus::blocking::Connection,
        session: zbus::zvariant::OwnedObjectPath,
        node_id: u32,
        logical: (f64, f64),
    ) -> Result<Self, zbus::Error> {
        let proxy = zbus::blocking::Proxy::new(
            conn,
            super::PORTAL_BUS,
            super::PORTAL_PATH,
            super::REMOTE_DESKTOP_IFACE,
        )?;
        // FR-93 P4b — kill switch `ROOMLERD_PORTAL_KDE_SCROLL_FIX=0`, should
        // KDE's backend ever stop negating.
        let quirks = BackendQuirks {
            negated_smooth_y: tunnel_core::env::flag("PORTAL_KDE_SCROLL_FIX", true)
                && kde_backend(conn),
        };
        Ok(Self {
            proxy,
            target: Target::Portal { session, node_id },
            logical,
            quirks,
        })
    }

    /// FR-93 P4 — input on mutter's RemoteDesktop session.
    ///
    /// ⚠️ `conn` must be the connection that CREATED the session
    /// ([`super::mutter::MutterSession::connection`]): mutter takes `Notify*`
    /// calls only from that peer. `space` is the stream's own size, the
    /// coordinates `NotifyPointerMotionAbsolute` takes (mutter divides by the
    /// monitor's scale itself).
    pub fn new_mutter(
        conn: &zbus::blocking::Connection,
        input: &super::mutter::MutterInput,
        space: (f64, f64),
    ) -> Result<Self, zbus::Error> {
        let proxy = zbus::blocking::Proxy::new(
            conn,
            super::mutter::RD_BUS,
            input.session.clone(),
            super::mutter::RD_SESSION_IFACE,
        )?;
        Ok(Self {
            proxy,
            target: Target::Mutter {
                stream: input.stream.as_str().to_string(),
            },
            logical: space,
            quirks: BackendQuirks::default(),
        })
    }

    /// Execute one call. Errors are returned, not logged — the pump decides
    /// how loud to be, and it deliberately keeps going: one refused event
    /// must not end input for the session.
    ///
    /// Every call goes out as [`Target::delivery`] says: the portal's wait for
    /// their replies, which is what keeps them in order.
    fn execute(&self, call: PortalCall) -> Result<(), zbus::Error> {
        use std::collections::HashMap;
        let (sess, node_id) = match &self.target {
            Target::Portal { session, node_id } => (session, *node_id),
            Target::Mutter { stream } => return self.execute_mutter(call, stream),
        };
        let opts: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();
        match for_backend(call, self.quirks) {
            PortalCall::MotionAbs { x, y } => {
                self.send("NotifyPointerMotionAbsolute", &(sess, opts, node_id, x, y))
            }
            PortalCall::MotionRel { dx, dy } => {
                self.send("NotifyPointerMotion", &(sess, opts, dx, dy))
            }
            PortalCall::Button { code, down } => {
                self.send("NotifyPointerButton", &(sess, opts, code, u32::from(down)))
            }
            PortalCall::Axis { dx, dy } => self.send("NotifyPointerAxis", &(sess, opts, dx, dy)),
            PortalCall::AxisDiscrete { axis, steps } => {
                self.send("NotifyPointerAxisDiscrete", &(sess, opts, axis, steps))
            }
            PortalCall::Keycode { code, down } => self.send(
                "NotifyKeyboardKeycode",
                &(sess, opts, code, u32::from(down)),
            ),
            PortalCall::Keysym { sym, down } => {
                self.send("NotifyKeyboardKeysym", &(sess, opts, sym, u32::from(down)))
            }
        }
    }

    /// FR-93 P4 — [`Self::execute`] on mutter's own session.
    fn execute_mutter(&self, call: PortalCall, stream: &str) -> Result<(), zbus::Error> {
        let Some(call) = mutter_call(call) else {
            return Ok(());
        };
        match call {
            MutterCall::MotionAbs { x, y } => {
                self.send("NotifyPointerMotionAbsolute", &(stream, x, y))
            }
            MutterCall::MotionRel { dx, dy } => self.send("NotifyPointerMotionRelative", &(dx, dy)),
            MutterCall::Button { code, down } => self.send("NotifyPointerButton", &(code, down)),
            MutterCall::Axis { dx, dy, flags } => self.send("NotifyPointerAxis", &(dx, dy, flags)),
            MutterCall::AxisDiscrete { axis, steps } => {
                self.send("NotifyPointerAxisDiscrete", &(axis, steps))
            }
            MutterCall::Keycode { code, down } => self.send("NotifyKeyboardKeycode", &(code, down)),
            MutterCall::Keysym { sym, down } => self.send("NotifyKeyboardKeysym", &(sym, down)),
        }
    }

    /// One `Notify*` call, delivered as [`Target::delivery`] says. A send error
    /// (a dead session) comes back either way; an awaited call also returns a
    /// refusal the receiver answers with.
    fn send<B>(&self, method: &'static str, body: &B) -> Result<(), zbus::Error>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        match self.target.delivery() {
            Delivery::Awaited => self.proxy.call_method(method, body).map(drop),
            Delivery::Unawaited => self.proxy.call_noreply(method, body),
        }
    }
}

/// The helper's stdin pump: one `InputMsg` JSON line per event, EOF when the
/// daemon is done with us. Runs on its own thread for the life of the stream.
///
/// A line that does not parse is SKIPPED, not fatal: normally both ends are
/// the same binary, but an update can leave a stale helper on disk for one
/// session, and a wire variant it does not know must cost that event only.
pub fn run_pump(ctx: InputContext, stdin: std::io::Stdin) {
    use std::io::BufRead;
    let mut wheel = WheelAccum::default();
    let mut dropped_parse = 0u64;
    let mut failed_calls = 0u64;
    let mut executed = 0u64;
    let mut nonascii_keysyms = 0u64;
    let mut warned_nonascii = false;
    if ctx.quirks.negated_smooth_y {
        eprintln!(
            "portal-helper: KDE's portal backend negates the vertical smooth scroll; negating it \
             first (ROOMLERD_PORTAL_KDE_SCROLL_FIX=0 stops this)"
        );
    }
    // FR-93 P4b — `ROOMLERD_PORTAL_INPUT_TRACE=1`: every event and every call
    // made for it, on the wall clock, so a lab can line what was SENT up against
    // what a probe RECEIVED. Off by default: a keystroke log does not belong in
    // a journal.
    let trace = tunnel_core::env::flag("PORTAL_INPUT_TRACE", false);
    let wall = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    };
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: InputMsg = match serde_json::from_str(trimmed) {
            Ok(m) => m,
            Err(e) => {
                dropped_parse += 1;
                if dropped_parse <= 3 {
                    eprintln!("portal-helper: unparseable input line dropped: {e}");
                }
                continue;
            }
        };
        // ⚠️ The compositor silently drops a keysym its active keymap cannot
        // produce (measured: é € £ on a US keymap typed NOTHING while the call
        // returned success). We cannot observe that, so say it ONCE here —
        // otherwise the only symptom is "some characters never arrive", with
        // nothing in any log to explain it.
        if let InputMsg::KeyText { text } = &msg {
            let n = text.chars().filter(|c| !c.is_ascii()).count() as u64;
            if n > 0 {
                nonascii_keysyms += n;
                if !warned_nonascii {
                    warned_nonascii = true;
                    eprintln!(
                        "portal-helper: forwarding non-ASCII text as keysyms — characters the \
                         host's active keymap cannot produce are dropped BY THE COMPOSITOR, \
                         silently and with a successful return. If accented or symbol characters \
                         never appear, that is why."
                    );
                }
            }
        }
        if trace {
            eprintln!("portal-helper: input-trace {:.4} event {msg:?}", wall());
        }
        for call in plan(&msg, ctx.logical, &mut wheel) {
            let done = ctx.execute(call);
            if trace {
                eprintln!(
                    "portal-helper: input-trace {:.4} call {call:?} {}",
                    wall(),
                    if done.is_ok() { "sent" } else { "FAILED" }
                );
            }
            match done {
                Ok(()) => executed += 1,
                Err(e) => {
                    failed_calls += 1;
                    // The first few loudly — a systematically refused call
                    // (revoked session, missing device grant) should be
                    // diagnosable from the daemon log, not invisible.
                    if failed_calls <= 3 {
                        eprintln!("portal-helper: input call failed: {e}");
                    }
                }
            }
        }
    }
    eprintln!(
        "portal-helper: input pump ended (executed={executed} failed={failed_calls} \
         unparseable={dropped_parse} non_ascii_keysyms={nonascii_keysyms})"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::Button;

    const LOGICAL: (f64, f64) = (1920.0, 1080.0);

    fn plan1(msg: InputMsg) -> Vec<PortalCall> {
        plan(&msg, LOGICAL, &mut WheelAccum::default())
    }

    /// Normalised wire coordinates land in the stream's LOGICAL space — the
    /// single multiply this backend's coordinate story rests on.
    #[test]
    fn moves_scale_into_logical_space() {
        let calls = plan1(InputMsg::MouseMove {
            x: 0.5,
            y: 0.25,
            mon: 0,
        });
        assert_eq!(calls, vec![PortalCall::MotionAbs { x: 960.0, y: 270.0 }]);
    }

    /// Out-of-range coordinates clamp rather than leaving the stream — a
    /// negative or >1 value would ask the compositor to move outside the
    /// surface it granted.
    #[test]
    fn moves_clamp_to_the_stream() {
        let calls = plan1(InputMsg::MouseMove {
            x: -0.5,
            y: 1.5,
            mon: 0,
        });
        assert_eq!(calls, vec![PortalCall::MotionAbs { x: 0.0, y: 1080.0 }]);
    }

    /// #1945 — the arbiter's release-all lets go where the pointer is: no
    /// motion at all. (`clicks_position_then_press` is the control: the same
    /// plan does produce a motion when an event carries one.)
    #[test]
    fn a_release_never_moves_the_pointer() {
        assert_eq!(
            plan1(InputMsg::MouseRelease { btn: Button::Left }),
            vec![PortalCall::Button {
                code: 0x110,
                down: false
            }]
        );
    }

    /// FR-109 — relative mode's press, the release's twin: a button and no
    /// motion.
    #[test]
    fn a_relative_press_never_moves_the_pointer() {
        assert_eq!(
            plan1(InputMsg::MousePress { btn: Button::Left }),
            vec![PortalCall::Button {
                code: 0x110,
                down: true
            }]
        );
    }

    /// FR-109 P2c — relative motion is one relative call with the counts as
    /// they came, naming no stream; an all-zero frame plans nothing. On
    /// mutter's own session it is `NotifyPointerMotionRelative`'s shape.
    #[test]
    fn relative_motion_is_one_relative_call() {
        assert_eq!(
            plan1(InputMsg::MouseRel { dx: 5, dy: -3 }),
            vec![PortalCall::MotionRel { dx: 5.0, dy: -3.0 }]
        );
        assert_eq!(plan1(InputMsg::MouseRel { dx: 0, dy: 0 }), vec![]);
        assert_eq!(
            mutter_call(PortalCall::MotionRel { dx: 5.0, dy: -3.0 }),
            Some(MutterCall::MotionRel { dx: 5.0, dy: -3.0 })
        );
        // No backend quirk touches it: KDE's negated smooth scroll is the
        // wheel's alone.
        assert_eq!(
            for_backend(
                PortalCall::MotionRel { dx: 5.0, dy: -3.0 },
                BackendQuirks {
                    negated_smooth_y: true
                }
            ),
            PortalCall::MotionRel { dx: 5.0, dy: -3.0 }
        );
    }

    /// Clicks position first, then press — same rule as uinput, same reason.
    #[test]
    fn clicks_position_then_press() {
        let calls = plan1(InputMsg::MouseButton {
            btn: Button::Right,
            down: true,
            x: 1.0,
            y: 0.0,
            mon: 0,
        });
        assert_eq!(
            calls,
            vec![
                PortalCall::MotionAbs { x: 1920.0, y: 0.0 },
                PortalCall::Button {
                    code: 0x111,
                    down: true
                },
            ]
        );
    }

    /// Pixel wheel passes through as smooth axis — positive stays positive.
    /// ⚠️ The sign is the libinput convention (positive = down), NOT evdev's
    /// REL_WHEEL (positive = up). Copying the uinput inversion here scrolls
    /// backwards; this test is what keeps that from "looking obviously right"
    /// to a future editor.
    #[test]
    fn pixel_wheel_is_smooth_and_uninverted() {
        let calls = plan1(InputMsg::MouseWheel {
            dx: 0.0,
            dy: 106.0,
            mode: WheelMode::Pixel,
        });
        assert_eq!(calls, vec![PortalCall::Axis { dx: 0.0, dy: 106.0 }]);
    }

    /// Line mode accumulates fractional detents across events — three thirds
    /// make a step, not zero steps three times.
    #[test]
    fn line_wheel_accumulates_detents() {
        let mut wheel = WheelAccum::default();
        let m = InputMsg::MouseWheel {
            dx: 0.0,
            dy: 0.4,
            mode: WheelMode::Line,
        };
        assert!(plan(&m, LOGICAL, &mut wheel).is_empty());
        assert!(plan(&m, LOGICAL, &mut wheel).is_empty());
        assert_eq!(
            plan(&m, LOGICAL, &mut wheel),
            vec![PortalCall::AxisDiscrete { axis: 0, steps: 1 }]
        );
    }

    /// A page is a burst of detents on the SAME axis, mirroring uinput.
    #[test]
    fn page_wheel_is_three_detents() {
        let calls = plan1(InputMsg::MouseWheel {
            dx: 0.0,
            dy: 1.0,
            mode: WheelMode::Page,
        });
        assert_eq!(calls, vec![PortalCall::AxisDiscrete { axis: 0, steps: 3 }]);
    }

    /// Keys ride the shared HID→evdev table; an unmapped usage is dropped,
    /// never guessed (FR-13's contract, kept across a third backend).
    #[test]
    fn keys_are_evdev_codes_and_unmapped_drops() {
        let calls = plan1(InputMsg::Key {
            code: 0x04,
            down: true,
            mods: 0,
        });
        assert_eq!(
            calls,
            vec![PortalCall::Keycode {
                code: 30,
                down: true
            }]
        );
        assert!(
            plan1(InputMsg::Key {
                code: 0xffff,
                down: true,
                mods: 0
            })
            .is_empty()
        );
    }

    /// The keysym rules: Latin-1 is identity, Unicode rides the escape plane,
    /// Return and Tab are the two honest control characters. This is what
    /// makes KeyText layout-proof — the exact property the uinput backend
    /// cannot offer (its table is physical keys).
    #[test]
    fn keysyms_follow_the_x11_unicode_rules() {
        assert_eq!(keysym_of('a'), Some(0x61));
        assert_eq!(
            keysym_of('é'),
            Some(0xE9),
            "printable Latin-1 is the identity zone"
        );
        assert_eq!(keysym_of('€'), Some(0x0100_20AC), "Unicode escape plane");
        assert_eq!(keysym_of('\n'), Some(0xFF0D));
        assert_eq!(keysym_of('\t'), Some(0xFF09));
        assert_eq!(keysym_of('\u{7}'), None, "other C0 controls are dropped");
        // ⚠️ DEL and the C1 controls sit INSIDE the raw Latin-1 numeric span
        // but are not printable keysyms — they must be dropped, not sent as a
        // bare undefined keysym.
        assert_eq!(keysym_of('\u{7F}'), None, "DEL is not a printable keysym");
        assert_eq!(keysym_of('\u{80}'), None, "C1 controls are dropped");
        assert_eq!(keysym_of('\u{9F}'), None, "C1 controls are dropped");
        assert_eq!(
            keysym_of('\u{A0}'),
            Some(0xA0),
            "NBSP resumes printable Latin-1"
        );
    }

    /// FR-93 P4 — mutter's shapes for the same events: no session handle or
    /// node id (the call is on the session, motion names the stream), boolean
    /// states, evdev keycodes as `u`, and the keysym's bits unchanged.
    #[test]
    fn mutter_calls_carry_mutters_shapes() {
        assert_eq!(
            mutter_call(PortalCall::MotionAbs { x: 960.0, y: 270.0 }),
            Some(MutterCall::MotionAbs { x: 960.0, y: 270.0 })
        );
        assert_eq!(
            mutter_call(PortalCall::Button {
                code: 0x110,
                down: true
            }),
            Some(MutterCall::Button {
                code: 0x110,
                down: true
            })
        );
        assert_eq!(
            mutter_call(PortalCall::Keycode {
                code: 30,
                down: false
            }),
            Some(MutterCall::Keycode {
                code: 30,
                down: false
            })
        );
        assert_eq!(
            mutter_call(PortalCall::Keycode {
                code: -1,
                down: true
            }),
            None,
            "no keycode is negative; one that would be is dropped, never wrapped"
        );
        let euro = keysym_of('€').unwrap() as i32;
        assert_eq!(
            mutter_call(PortalCall::Keysym {
                sym: euro,
                down: true
            }),
            Some(MutterCall::Keysym {
                sym: 0x0100_20AC,
                down: true
            })
        );
        assert_eq!(
            mutter_call(PortalCall::AxisDiscrete { axis: 0, steps: -2 }),
            Some(MutterCall::AxisDiscrete { axis: 0, steps: -2 }),
            "negative steps are up, as on the portal"
        );
    }

    /// FR-93 P4b — KDE's backend negates the vertical smooth scroll, so the
    /// call is negated first for it, and only for it: the horizontal axis and
    /// the discrete detents pass through, as they do in KDE's backend.
    #[test]
    fn only_kdes_vertical_smooth_scroll_is_negated() {
        let kde = BackendQuirks {
            negated_smooth_y: true,
        };
        assert_eq!(
            for_backend(PortalCall::Axis { dx: 4.0, dy: 120.0 }, kde),
            PortalCall::Axis {
                dx: 4.0,
                dy: -120.0
            }
        );
        let discrete = PortalCall::AxisDiscrete { axis: 0, steps: 1 };
        assert_eq!(
            for_backend(discrete, kde),
            discrete,
            "KDE does not negate detents"
        );
        let button = PortalCall::Button {
            code: 0x110,
            down: true,
        };
        assert_eq!(for_backend(button, kde), button);
        assert_eq!(
            for_backend(
                PortalCall::Axis { dx: 4.0, dy: 120.0 },
                BackendQuirks::default()
            ),
            PortalCall::Axis { dx: 4.0, dy: 120.0 },
            "every other backend keeps the portal's convention"
        );
    }

    /// FR-93 P4b — the portal's calls wait for their replies, because only the
    /// wait keeps them in order. xdg-desktop-portal handles each call on a
    /// worker thread; unawaited, 41 of 452 typed characters came out wrong on KDE.
    #[test]
    fn portal_calls_wait_for_their_replies() {
        let portal = Target::Portal {
            session: zbus::zvariant::OwnedObjectPath::try_from(
                "/org/freedesktop/portal/desktop/session/1_42/roomler",
            )
            .unwrap(),
            node_id: 42,
        };
        assert_eq!(
            portal.delivery(),
            Delivery::Awaited,
            "unawaited portal calls reach the compositor out of order: a key's release \
             before its press drops typed characters (see Target::delivery)"
        );
    }

    /// FR-93 P4 — a viewer's smooth wheel reaches mutter as a WHEEL, unscaled
    /// and with its sign. With no source flag mutter takes it for a touchpad
    /// finger, which waits for a finish and scrolls on kinetically after it.
    #[test]
    fn mutter_smooth_scroll_is_a_wheel() {
        let calls = plan1(InputMsg::MouseWheel {
            dx: 0.0,
            dy: -53.0,
            mode: WheelMode::Pixel,
        });
        let mutter: Vec<_> = calls.into_iter().filter_map(mutter_call).collect();
        assert_eq!(
            mutter,
            vec![MutterCall::Axis {
                dx: 0.0,
                dy: -53.0,
                flags: 2
            }]
        );
    }

    /// Typed text becomes press+release pairs, in order.
    #[test]
    fn key_text_is_press_release_pairs() {
        let calls = plan1(InputMsg::KeyText { text: "hé".into() });
        assert_eq!(
            calls,
            vec![
                PortalCall::Keysym {
                    sym: 0x68,
                    down: true
                },
                PortalCall::Keysym {
                    sym: 0x68,
                    down: false
                },
                PortalCall::Keysym {
                    sym: 0xE9,
                    down: true
                },
                PortalCall::Keysym {
                    sym: 0xE9,
                    down: false
                },
            ]
        );
    }
}
