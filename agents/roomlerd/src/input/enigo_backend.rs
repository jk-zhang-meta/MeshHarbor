// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Cross-platform input injection via [enigo].
//!
//! enigo picks the right OS primitive per platform: XTest / uinput on
//! Linux, SendInput on Windows, CGEventPost on macOS. We run it inside a
//! dedicated thread (same reason as the other hardware-talking backends
//! in this crate: the underlying handles have thread affinity on some
//! platforms) and fan command in via std::mpsc.
//!
//! Coordinate mapping: the controller sends normalised `x,y` in `[0,1]`
//! per monitor. We resolve those against the screen dimensions at the
//! moment of the event — resolution changes mid-session are OK.
//!
//! [enigo]: https://docs.rs/enigo

use anyhow::{Context, Result, anyhow};
use enigo::{
    Axis, Button as EnigoButton, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings,
};
use std::sync::mpsc as std_mpsc;
use std::thread;

use super::{Button, InputInjector, InputMsg, PxJob, WheelMode};
use tunnel_core::env::node_env;

pub struct EnigoInjector {
    tx: std_mpsc::Sender<Job>,
    has_perm: bool,
}

impl EnigoInjector {
    pub fn new() -> Result<Self> {
        let (tx, rx) = std_mpsc::channel::<Job>();
        // Construct Enigo on the worker thread — we never want to move it
        // between threads. Use a ready-ack channel to surface init errors.
        let (ready_tx, ready_rx) = std_mpsc::channel::<Result<()>>();

        thread::Builder::new()
            .name("roomlerd-input".into())
            .spawn(move || {
                let settings = enigo_settings();
                let enigo = match Enigo::new(&settings) {
                    Ok(e) => {
                        let _ = ready_tx.send(Ok(()));
                        e
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow!("enigo init: {e}")));
                        return;
                    }
                };
                run_worker(enigo, rx);
            })
            .context("spawn input thread")?;

        ready_rx.recv().context("input thread never responded")??;

        // macOS: Enigo::new used to succeed even when Accessibility was
        // denied — the OS then swallows every CGEventPost with no error
        // anywhere ("the mouse doesn't move and nothing logs"). Probe
        // honestly. ⚠️ The enigo we ship now refuses to construct instead
        // ("the application does not have the permission to simulate
        // input", field, macOS 27), so a denied Mac never gets here: it
        // gets `open_default`'s Noop, and keep busy reads the grant from
        // the OS itself (`arbiter::classify_unpermitted`).
        #[cfg(target_os = "macos")]
        let has_perm = {
            let trusted = crate::tcc::accessibility_trusted();
            if !trusted {
                tracing::warn!(
                    "macOS Accessibility permission MISSING — injected input will be silently dropped. \
                     Grant it under System Settings → Privacy & Security → Accessibility; \
                     the agent retries input after the grant"
                );
            }
            trusted
        };
        #[cfg(not(target_os = "macos"))]
        let has_perm = true;

        Ok(Self { tx, has_perm })
    }
}

fn run_worker(mut enigo: Enigo, rx: std_mpsc::Receiver<Job>) {
    while let Ok(job) = rx.recv() {
        match job {
            Job::Input(msg) => {
                if let Err(e) = dispatch(&mut enigo, msg) {
                    tracing::debug!(%e, "input event dropped");
                }
            }
            Job::Px(job) => run_px_job(&mut enigo, job),
        }
    }
}

/// FR-109 — the settings every `Enigo` this agent builds starts from, the
/// user worker's and the SystemContext worker's alike.
///
/// ⚠️ enigo 0.6 sends `Coordinate::Rel` on Windows as an ABSOLUTE move unless
/// `windows_subject_to_mouse_speed_and_acceleration_level` is set: it reads the
/// cursor and moves it to cursor + delta, so that pointer speed and acceleration
/// do not apply. Raw input, which is what a game or a 3D viewport reads, then
/// sees one absolute event and no motion at all. Field, agent 0.4.140: ten
/// `mouse_rel {dx: 100}` frames reached the host as 0 relative counts and 10
/// absolute events. With the flag set, `Rel` is `SendInput` with
/// `MOUSEEVENTF_MOVE`, the relative event FR-109's P0 measured arriving 1:1.
/// The visible cursor then follows pointer speed and acceleration, as a real
/// mouse does. Absolute moves ignore the flag, and no other caller sends `Rel`.
pub(super) fn enigo_settings() -> Settings {
    Settings {
        windows_subject_to_mouse_speed_and_acceleration_level: true,
        ..Settings::default()
    }
}

/// Dispatch one [`InputMsg`] through enigo. Public to sibling backends
/// in the `input/` module (specifically [`super::system_context_backend`])
/// so the M3 A1 SYSTEM-context worker can reuse the exact same HID-to-
/// VK mapping + wheel/mouse semantics behind a different per-event
/// preamble (`SetThreadDesktop` rebind). Not exposed outside `input/`.
///
/// Compiled only when both `system-context` and `enigo-input` features
/// are on AND the target is Windows — i.e. the only configuration
/// where `system_context_backend` itself compiles.
#[cfg(all(
    feature = "system-context",
    target_os = "windows",
    feature = "enigo-input"
))]
pub(super) fn dispatch_for_external(enigo: &mut Enigo, msg: InputMsg) -> Result<()> {
    dispatch(enigo, msg)
}

/// Generic over enigo's two traits only so a test can record which calls an
/// event makes (`tests::a_release_never_moves_the_pointer`); production
/// passes the one concrete `Enigo`.
fn dispatch<E: Mouse + Keyboard>(enigo: &mut E, msg: InputMsg) -> Result<()> {
    match msg {
        InputMsg::MouseMove { x, y, mon } => {
            // rc.227 — coarse layout sampling (every 32nd event) so a
            // layout change surfaces on the viewer chip within ~a
            // second of mouse activity. Runs on this injector thread —
            // the only thread guaranteed desktop-bound under the
            // SYSTEM-context worker.
            #[cfg(target_os = "windows")]
            super::layout::maybe_sample_coarse();
            let (px, py) = to_pixels(enigo, x, y, mon);
            enigo
                .move_mouse(px, py, Coordinate::Abs)
                .map_err(|e| anyhow!("move_mouse: {e}"))?;
            verify_cursor_position(px, py, "move");
        }
        InputMsg::MouseButton {
            btn,
            down,
            x,
            y,
            mon,
        } => {
            #[cfg(target_os = "windows")]
            super::layout::maybe_sample_coarse();
            // Move first so the click hits the intended target even if
            // earlier MouseMove events were coalesced away.
            let (px, py) = to_pixels(enigo, x, y, mon);
            enigo
                .move_mouse(px, py, Coordinate::Abs)
                .map_err(|e| anyhow!("move_mouse: {e}"))?;
            verify_cursor_position(px, py, "button");
            let direction = if down {
                Direction::Press
            } else {
                Direction::Release
            };
            enigo
                .button(map_button(btn), direction)
                .map_err(|e| anyhow!("button: {e}"))?;
        }
        // #1945 — the arbiter's release-all: let go where the pointer IS.
        // Moving first, as a click does, threw the cursor to (0,0) — GNOME's
        // Activities hot corner — whenever a viewer vanished mid-drag.
        InputMsg::MouseRelease { btn } => {
            enigo
                .button(map_button(btn), Direction::Release)
                .map_err(|e| anyhow!("button: {e}"))?;
        }
        // FR-109 — relative motion, as a mouse moves: `SendInput` with
        // `MOUSEEVENTF_MOVE` and no `ABSOLUTE` on Windows, XTest relative
        // motion on X11. Nothing to verify against: the host app owns where
        // the cursor is, and usually recentres it.
        InputMsg::MouseRel { dx, dy } => {
            enigo
                .move_mouse(dx, dy, Coordinate::Rel)
                .map_err(|e| anyhow!("move_mouse rel: {e}"))?;
        }
        // FR-109 — relative mode's press, where the pointer is: the twin of
        // the release above, and for the same reason it never moves first.
        InputMsg::MousePress { btn } => {
            enigo
                .button(map_button(btn), Direction::Press)
                .map_err(|e| anyhow!("button: {e}"))?;
        }
        InputMsg::MouseWheel { dx, dy, mode } => {
            let (x_steps, y_steps) = wheel_to_steps(dx, dy, mode);
            if y_steps != 0 {
                enigo
                    .scroll(y_steps, Axis::Vertical)
                    .map_err(|e| anyhow!("scroll y: {e}"))?;
            }
            if x_steps != 0 {
                enigo
                    .scroll(x_steps, Axis::Horizontal)
                    .map_err(|e| anyhow!("scroll x: {e}"))?;
            }
        }
        InputMsg::Key {
            code,
            down,
            mods: _,
        } => {
            // rc.227 — exact layout sampling on key events (cheap: 2
            // syscalls + 1 atomic when unchanged). Catches the remote
            // user's own ALT+SHIFT within one event.
            #[cfg(target_os = "windows")]
            super::layout::sample_active_layout();
            let direction = if down {
                Direction::Press
            } else {
                Direction::Release
            };
            if let Some(k) = hid_to_key(code) {
                enigo.key(k, direction).map_err(|e| anyhow!("key: {e}"))?;
            } else {
                // FR-13: an unmapped HID usage is DROPPED, never forwarded.
                // `Key::Other` is a platform-native virtual keycode (VK /
                // CGKeyCode / keysym), NOT a scancode escape hatch — handing
                // it the raw HID byte reinterprets it in a foreign namespace.
                // Field: HID 0x39 (CapsLock) == VK_9 typed the digit 9;
                // HID 0x5f (Numpad7) == VK_SLEEP would sleep the host.
                tracing::debug!(code, "dropping key event with unmapped HID usage");
            }
        }
        InputMsg::KeyText { text } => {
            #[cfg(target_os = "windows")]
            super::layout::sample_active_layout();
            // rc.122 — on Windows, inject printable text as real virtual keys
            // (scancode) instead of enigo.text()'s KEYEVENTF_UNICODE, which the
            // legacy console (Windows PowerShell 5.1 / cmd in conhost) silently
            // drops (field: REGAL-112500982 — letters vanished in elevated
            // Windows PowerShell but worked in pwsh 7 / Windows Terminal). The
            // `ROOMLERD_UNICODE_TEXT=1` kill switch reverts to enigo.text().
            #[cfg(target_os = "windows")]
            {
                if super::win_text::unicode_only() {
                    enigo.text(&text).map_err(|e| anyhow!("text: {e}"))?;
                } else {
                    super::win_text::type_text(&text);
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                enigo.text(&text).map_err(|e| anyhow!("text: {e}"))?;
            }
        }
        InputMsg::Touch { .. } => {
            // No cross-platform touch injection in enigo yet. Map to
            // mouse in a follow-up; for now, drop silently.
        }
        InputMsg::Heartbeat { .. } => {}
        // FR-97 P4a — the real Ctrl+Alt+Del, re-checked here: a viewer is
        // sent `sas` only by an agent that advertised it, but the policy can
        // change between the hello and the click. The worker only asks: the
        // service process sends it (`win_service::sas_relay`). Nothing off
        // Windows.
        InputMsg::Sas =>
        {
            #[cfg(target_os = "windows")]
            match super::sas::availability() {
                Ok(()) => {
                    super::sas::send()?;
                    tracing::info!(
                        "Ctrl+Alt+Del: asked the service to send the secure attention sequence"
                    );
                }
                Err(refusal) => tracing::warn!(
                    ?refusal,
                    "Ctrl+Alt+Del: this host cannot send the real one; nothing sent"
                ),
            }
        }
    }
    Ok(())
}

fn map_button(b: Button) -> EnigoButton {
    match b {
        Button::Left => EnigoButton::Left,
        Button::Right => EnigoButton::Right,
        Button::Middle => EnigoButton::Middle,
        Button::Back => EnigoButton::Back,
        Button::Forward => EnigoButton::Forward,
    }
}

/// Whether the virtual-screen-aware `to_pixels` path is enabled.
///
/// Opt-in via `ROOMLERD_VIRTUAL_SCREEN=1` (also accepts `true`,
/// `yes`, `on` — case-insensitive). Default off — the legacy
/// `enigo.main_display()` path is preserved verbatim.
///
/// rc.54 — addresses the "orthogonal mouse-offset" field bug surfaced
/// in `79d6dee` and instrumented by the rc.48 `monitor_diag` log. When
/// the primary monitor's virtual-screen origin is non-zero (multi-
/// monitor host where the user has dragged the primary off `(0,0)`),
/// `SetCursorPos` interprets coordinates in the virtual-desktop space,
/// not the primary-local space; without the origin offset, clicks
/// land on the wrong monitor or shifted by the offset magnitude.
///
/// Read once at process startup via [`std::sync::LazyLock`]; the
/// resulting `bool` is then cheap to read from the hot input path.
fn virtual_screen_enabled() -> bool {
    use std::sync::LazyLock;
    static FLAG: LazyLock<bool> =
        LazyLock::new(|| super::parse_virtual_screen_flag(node_env("VIRTUAL_SCREEN").as_deref()));
    *FLAG
}

/// Map a normalised `(x, y)` in `[0,1]` plus a target monitor rect
/// `(origin_x, origin_y, w, h)` (all in physical pixels on the virtual
/// desktop) to absolute virtual-screen pixel coordinates suitable for
/// `SetCursorPos` (Windows) / `XTest` (X11) / `CGEventPost` (macOS).
///
/// Out-of-range normalised values are clamped to `[0,1]`; degenerate
/// `w` / `h` ≤ 1 still produce a well-defined origin-anchored point.
pub(crate) fn map_normalised_to_virtual(
    x: f32,
    y: f32,
    origin_x: i32,
    origin_y: i32,
    w: i32,
    h: i32,
) -> (i32, i32) {
    let x_clamped = x.clamp(0.0, 1.0);
    let y_clamped = y.clamp(0.0, 1.0);
    // Clamp `(w-1)` / `(h-1)` to non-negative so a degenerate enumeration
    // (0×0 monitor on a headless host) maps to (origin_x, origin_y)
    // instead of an underflow-induced negative pixel value.
    let span_w = (w - 1).max(0) as f32;
    let span_h = (h - 1).max(0) as f32;
    let local_px = (x_clamped * span_w).round() as i32;
    let local_py = (y_clamped * span_h).round() as i32;
    (origin_x + local_px, origin_y + local_py)
}

/// Resolve the monitor we map normalised `(x, y)` against. Returns
/// `(origin_x, origin_y, width_px, height_px)`.
///
/// Path resolution (when `ROOMLERD_VIRTUAL_SCREEN=1`):
///   1. `win32_monitors::target_monitor(mon)` — looks up the cached
///      enumerate() result by browser-supplied index, falls back to
///      the primary monitor when out of range. Today's browser sends
///      `mon=0` (only primary monitor streams), so this matches the
///      `MonitorInfo` for the primary on every event. rc.55 wires
///      the per-index lookup so the agent is ready when multi-stream
///      lands.
///
/// Legacy path (default, gate off): returns `enigo.main_display()`
/// (i.e. origin (0,0) + primary dims). Math is identical to pre-rc.54.
fn resolve_target_monitor<E: Mouse>(enigo: &E, mon: u8) -> (i32, i32, i32, i32) {
    if virtual_screen_enabled() {
        #[cfg(target_os = "windows")]
        {
            if let Some(m) = crate::win32_monitors::target_monitor(mon) {
                return (m.origin_x, m.origin_y, m.width_px, m.height_px);
            }
        }
    }
    // Legacy path / non-Windows / Win32 enumeration miss → enigo's view.
    // `mon` is silently dropped here — single-monitor + non-Windows
    // hosts only have one display to map against.
    let _ = mon;
    let (w, h) = enigo.main_display().unwrap_or((1920, 1080));
    (0, 0, w, h)
}

/// Normalised `(x, y)` in `[0,1]` → absolute pixel coordinates on the
/// agent's primary display. Multi-monitor mapping (`mon` > 0) picks the
/// monitor from enigo's enumeration; on single-monitor hosts it falls
/// back to primary. Out-of-range values are clamped.
///
/// rc.39 — rate-limited diagnostic logging at INFO level for the first
/// 50 dispatches per process. the field-test host / a second field-test host field test 2026-05-17
/// shows mouse positioned wrong even after rc.38's aspect-preserving
/// downscale + skip-first-frame fixes. Suspect a coord-system mismatch
/// between enigo.main_display() (returns OS-reported logical pixels,
/// possibly DPI-virtualised) and the capture surface (device pixels).
/// The first 50 events surface the actual numbers in agent logs;
/// remaining events drop to debug level to avoid spam.
///
/// rc.54 — when `ROOMLERD_VIRTUAL_SCREEN=1` is set, the new path
/// queries `win32_monitors::primary()` for the OS-designated primary
/// monitor's virtual-screen origin and applies the offset to the
/// computed pixel coords. Closes the orthogonal mouse-offset bug on
/// multi-monitor hosts where the primary monitor isn't at (0,0).
/// Default off; flip the default in a later rc once the field-test
/// host smoke confirms the path on rc.54.
fn to_pixels<E: Mouse>(enigo: &E, x: f32, y: f32, mon: u8) -> (i32, i32) {
    use std::sync::atomic::Ordering;
    const DIAG_INFO_LIMIT: u32 = 50;

    let (origin_x, origin_y, w, h) = resolve_target_monitor(enigo, mon);
    let (px, py) = map_normalised_to_virtual(x, y, origin_x, origin_y, w, h);
    let count = super::INPUT_DIAG_COUNT.fetch_add(1, Ordering::Relaxed);
    let vscreen = virtual_screen_enabled();
    if count < DIAG_INFO_LIMIT {
        tracing::info!(
            norm_x = x.clamp(0.0, 1.0),
            norm_y = y.clamp(0.0, 1.0),
            display_w = w,
            display_h = h,
            origin_x,
            origin_y,
            px,
            py,
            mon,
            virtual_screen = vscreen,
            seq = count,
            "input dispatch — diagnostic (first 50 events)"
        );
    } else {
        tracing::debug!(
            norm_x = x.clamp(0.0, 1.0),
            norm_y = y.clamp(0.0, 1.0),
            display_w = w,
            display_h = h,
            origin_x,
            origin_y,
            px,
            py,
            mon,
            virtual_screen = vscreen,
            "input dispatch"
        );
    }
    (px, py)
}

/// rc.60 — after enigo dispatches a mouse-move, read the OS's actual
/// cursor position via `GetCursorPos` and log expected vs actual. If
/// the two diverge on a per-monitor-v2 DPI-aware process, the
/// hypothesis is enigo applying internal DPI conversion incorrectly
/// for absolute coords (e.g., dividing by DPI scale when it shouldn't,
/// producing a cursor at (px/1.5, py/1.5) on a 150% scale host).
///
/// User-reported symptom matches: top-left corner click (0, 0) lands
/// correctly (0/1.5 = 0), but bottom-right click (1851, 1175) lands
/// at ~(1234, 783) — "more to left and top" relative to where the
/// user clicked in the browser.
///
/// Rate-limited via the same `INPUT_DIAG_COUNT` as `to_pixels` so it
/// only fires for the first 50 events per session.
#[cfg(target_os = "windows")]
fn verify_cursor_position(expected_x: i32, expected_y: i32, op: &str) {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::WindowsAndMessaging::GetCursorPos;

    let count = super::INPUT_DIAG_COUNT.load(Ordering::Relaxed);
    if count > 50 {
        return;
    }
    let mut pt = POINT { x: 0, y: 0 };
    // SAFETY: GetCursorPos takes a stack-allocated POINT pointer.
    // Returns 0 on failure (e.g. session not interactive); we treat
    // failure as a logged sentinel rather than a panic.
    let ok = unsafe { GetCursorPos(&mut pt) };
    if ok == 0 {
        tracing::warn!(
            op,
            expected_x,
            expected_y,
            "cursor verify — GetCursorPos failed (session not interactive?)"
        );
        return;
    }
    let dx = pt.x - expected_x;
    let dy = pt.y - expected_y;
    let drift = dx != 0 || dy != 0;
    tracing::info!(
        op,
        expected_x,
        expected_y,
        actual_x = pt.x,
        actual_y = pt.y,
        dx,
        dy,
        drift,
        "cursor verify — enigo.move_mouse vs GetCursorPos"
    );
}

#[cfg(not(target_os = "windows"))]
fn verify_cursor_position(_expected_x: i32, _expected_y: i32, _op: &str) {}

/// Convert a browser `WheelEvent` delta into enigo scroll "notches".
/// Browsers emit pixels at 100+ per notch; enigo wants integer notches,
/// so we accumulate fractional pixels and round.
fn wheel_to_steps(dx: f32, dy: f32, mode: WheelMode) -> (i32, i32) {
    let px_per_step = match mode {
        WheelMode::Pixel => 100.0,
        WheelMode::Line => 1.0,
        WheelMode::Page => 1.0,
    };
    // Browsers use "positive Y == down". enigo's convention matches on
    // every platform we target.
    (
        (dx / px_per_step).round() as i32,
        (dy / px_per_step).round() as i32,
    )
}

/// Map a USB HID usage code (what the browser emits via the `Key*`
/// KeyboardEvent.code normalisation) to enigo's `Key` enum.
///
/// On Windows, letters and digits route through `Key::Other(VK_*)`
/// rather than `Key::Unicode(c)`. Reason: enigo's Unicode path sets
/// `KEYEVENTF_SCANCODE` on Windows, which makes the OS rely on the
/// current keyboard layout to map scan → character. On non-US layouts
/// (German, International) this can drop or reassign control-sequence
/// characters — user reported `Ctrl+C → ©` and `Backspace → ^H` in
/// pwsh / Windows Terminal on 0.1.33. The VK path injects the virtual
/// key directly so modifiers (VK_CONTROL, VK_SHIFT, VK_MENU) combine
/// with the letter exactly as if typed on a physical keyboard,
/// regardless of layout.
///
/// Unknown codes are DROPPED by the caller (FR-13) — `Key::Other` takes a
/// platform-native virtual keycode, so feeding it a HID usage types garbage
/// (0x39 CapsLock == VK_9 → `9`). Every usage the browser's `kbdCodeToHid`
/// can emit must therefore have an arm here or be a documented per-platform
/// drop — locked by `browser_emitted_hid_usages_map_or_are_documented_drops`.
fn hid_to_key(code: u32) -> Option<Key> {
    // HID usage codes from "Keyboard/Keypad" Page (0x07).
    match code {
        // Letters: HID 0x04..=0x1d → 'a'..='z'.
        // Windows: VK_A..VK_Z = 0x41..0x5A — inject as virtual-key so
        // Ctrl/Alt/Shift combine correctly regardless of keyboard
        // layout. Other platforms: Key::Unicode is honoured by
        // XTest / CGEventPost and combines with modifiers there.
        #[cfg(target_os = "windows")]
        0x04..=0x1d => Some(Key::Other(0x41 + (code - 0x04))),
        #[cfg(not(target_os = "windows"))]
        0x04..=0x1d => char::from_u32(u32::from(b'a') + (code - 0x04)).map(Key::Unicode),
        // Digits: HID 0x1e..=0x26 → '1'..='9', 0x27 → '0'.
        // Windows VK_0 = 0x30, VK_1..VK_9 = 0x31..0x39.
        #[cfg(target_os = "windows")]
        0x1e..=0x26 => Some(Key::Other(0x31 + (code - 0x1e))),
        #[cfg(target_os = "windows")]
        0x27 => Some(Key::Other(0x30)),
        #[cfg(not(target_os = "windows"))]
        0x1e..=0x26 => char::from_u32(u32::from(b'1') + (code - 0x1e)).map(Key::Unicode),
        #[cfg(not(target_os = "windows"))]
        0x27 => Some(Key::Unicode('0')),
        // Common punctuation (US layout HID usages). Keeping Unicode
        // here even on Windows — the scancode route is layout-dependent
        // but punctuation is less frequently combined with modifiers
        // than letters, and the VK codes for these vary dramatically
        // by layout (VK_OEM_1 etc.). Layouts other than US will be
        // addressed in a follow-up when we wire a layout-aware mapper.
        0x2d => Some(Key::Unicode('-')),
        0x2e => Some(Key::Unicode('=')),
        0x2f => Some(Key::Unicode('[')),
        0x30 => Some(Key::Unicode(']')),
        0x31 => Some(Key::Unicode('\\')),
        0x33 => Some(Key::Unicode(';')),
        0x34 => Some(Key::Unicode('\'')),
        0x35 => Some(Key::Unicode('`')),
        0x36 => Some(Key::Unicode(',')),
        0x37 => Some(Key::Unicode('.')),
        0x38 => Some(Key::Unicode('/')),
        0x28 => Some(Key::Return),
        0x29 => Some(Key::Escape),
        0x2a => Some(Key::Backspace),
        0x2b => Some(Key::Tab),
        0x2c => Some(Key::Space),
        0x4f => Some(Key::RightArrow),
        0x50 => Some(Key::LeftArrow),
        0x51 => Some(Key::DownArrow),
        0x52 => Some(Key::UpArrow),
        0x4a => Some(Key::Home),
        0x4d => Some(Key::End),
        0x4b => Some(Key::PageUp),
        0x4e => Some(Key::PageDown),
        // `Key::Insert` only exists on Linux + Windows builds of enigo;
        // macOS keyboards have no Insert key, so enigo omits the variant.
        // Fall through to None on macOS — the browser-side composable can
        // retry via InputMsg::KeyText for the rare caller that needs it.
        #[cfg(not(target_os = "macos"))]
        0x49 => Some(Key::Insert),
        0x4c => Some(Key::Delete),
        0x3a => Some(Key::F1),
        0x3b => Some(Key::F2),
        0x3c => Some(Key::F3),
        0x3d => Some(Key::F4),
        0x3e => Some(Key::F5),
        0x3f => Some(Key::F6),
        0x40 => Some(Key::F7),
        0x41 => Some(Key::F8),
        0x42 => Some(Key::F9),
        0x43 => Some(Key::F10),
        0x44 => Some(Key::F11),
        0x45 => Some(Key::F12),
        // FR-13: CapsLock. HID 0x39 previously fell through to the
        // `Key::Other` fallback, where the same byte is VK_9 on Windows —
        // pressing CapsLock TYPED the digit 9 (field report 2026-08-26).
        // `Key::CapsLock` is un-cfg'd in enigo 0.6.1 and resolves to
        // VK_CAPITAL / Caps_Lock / kVK_CapsLock (with the AlphaShift toggle).
        0x39 => Some(Key::CapsLock),
        // FR-13: numeric keypad (HID 0x54..=0x63). All of these previously
        // hit the fallback and typed garbage — worst cases: Numpad3/5 ==
        // VK_LWIN/VK_RWIN opened the Start menu, Numpad7 == VK_SLEEP slept
        // a Windows host, Numpad4 == kVK_ANSI_KEYPAD_9 typed 9 on a Mac.
        // Every variant here is un-cfg'd in enigo 0.6.1.
        0x54 => Some(Key::Divide),
        0x55 => Some(Key::Multiply),
        0x56 => Some(Key::Subtract),
        0x57 => Some(Key::Add),
        0x58 => Some(Key::Return), // NumpadEnter
        0x59 => Some(Key::Numpad1),
        0x5a => Some(Key::Numpad2),
        0x5b => Some(Key::Numpad3),
        0x5c => Some(Key::Numpad4),
        0x5d => Some(Key::Numpad5),
        0x5e => Some(Key::Numpad6),
        0x5f => Some(Key::Numpad7),
        0x60 => Some(Key::Numpad8),
        0x61 => Some(Key::Numpad9),
        0x62 => Some(Key::Numpad0),
        0x63 => Some(Key::Decimal),
        // FR-13: lock/system keys enigo models only on some platforms (the
        // same shape as the 0x49 Insert arm above). Where a variant doesn't
        // exist — Apple keyboards have none of these — the usage DROPS,
        // which since FR-13 is the contract for anything unmappable.
        #[cfg(not(target_os = "macos"))]
        0x46 => Some(Key::PrintScr),
        #[cfg(target_os = "windows")]
        0x47 => Some(Key::Scroll),
        #[cfg(all(unix, not(target_os = "macos")))]
        0x47 => Some(Key::ScrollLock),
        #[cfg(not(target_os = "macos"))]
        0x48 => Some(Key::Pause),
        #[cfg(not(target_os = "macos"))]
        0x53 => Some(Key::Numlock),
        // ContextMenu: only Windows models it (VK_APPS).
        #[cfg(target_os = "windows")]
        0x65 => Some(Key::Apps),
        0xe0 => Some(Key::Control),
        0xe1 => Some(Key::Shift),
        0xe2 => Some(Key::Alt),
        0xe3 => Some(Key::Meta),
        0xe4 => Some(Key::Control), // right control
        0xe5 => Some(Key::Shift),   // right shift
        0xe6 => Some(Key::Alt),     // right alt
        0xe7 => Some(Key::Meta),    // right meta
        // Deliberately unmapped (documented drops): 0x64 IntlBackslash — no
        // enigo variant and the glyph is layout-dependent; the printable
        // path reaches it via KeyText.
        _ => None,
    }
}

impl InputInjector for EnigoInjector {
    fn inject(&mut self, event: InputMsg) -> Result<()> {
        self.tx
            .send(Job::Input(event))
            .map_err(|_| anyhow!("input worker exited"))
    }

    fn has_permission(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.has_perm && crate::tcc::accessibility_trusted()
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.has_perm
        }
    }

    fn cursor_px(&mut self) -> Result<(i32, i32)> {
        super::px_round_trip(&self.tx, |reply| Job::Px(PxJob::Locate(reply)))
    }

    fn move_px(&mut self, x: i32, y: i32) -> Result<()> {
        super::px_round_trip(&self.tx, |reply| Job::Px(PxJob::Move { x, y, reply }))
    }

    fn buttons_held(&mut self) -> Result<bool> {
        super::px_round_trip(&self.tx, |reply| Job::Px(PxJob::Buttons(reply)))
    }
}

/// What the input thread runs: a controller's event, or (FR-92) a
/// pixel-space job for keep-busy. One channel, so a read is ordered after
/// every event queued before it.
pub(super) enum Job {
    Input(InputMsg),
    Px(PxJob),
}

/// FR-92 — run one pixel-space job on the input thread. Shared with the
/// SystemContext backend, which calls it after its desktop rebind.
pub(super) fn run_px_job(enigo: &mut Enigo, job: PxJob) {
    match job {
        PxJob::Locate(reply) => {
            let _ = reply.try_send(locate_px(enigo));
        }
        PxJob::Move { x, y, reply } => {
            let _ = reply.try_send(move_px_now(enigo, x, y));
        }
        PxJob::Buttons(reply) => {
            let _ = reply.try_send(buttons_held_now());
        }
    }
}

/// The cursor in desktop pixels. Windows: `GetCursorPos` — the process is
/// per-monitor-v2 DPI aware (`dpi.rs`), so these are physical virtual-screen
/// pixels, the same space [`move_px_now`] writes.
#[cfg(target_os = "windows")]
fn locate_px(_enigo: &mut Enigo) -> Result<(i32, i32)> {
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::WindowsAndMessaging::GetCursorPos;
    let mut pt = POINT { x: 0, y: 0 };
    // SAFETY: a stack POINT the call writes; 0 = failure (e.g. a desktop
    // this thread cannot read), surfaced as an error.
    if unsafe { GetCursorPos(&mut pt) } == 0 {
        return Err(anyhow!(
            "GetCursorPos failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((pt.x, pt.y))
}

/// The cursor in desktop pixels, through enigo — the same coordinate space
/// its `move_mouse(Abs)` writes (global display space on macOS, the root
/// window on X11).
#[cfg(not(target_os = "windows"))]
fn locate_px(enigo: &mut Enigo) -> Result<(i32, i32)> {
    enigo.location().map_err(|e| anyhow!("enigo location: {e}"))
}

/// An absolute move to desktop pixel `(x, y)` as a REAL input event, so the
/// OS idle clock resets. Windows: `SendInput(MOVE | ABSOLUTE | VIRTUALDESK)`
/// normalised over the virtual screen — enigo 0.6.1's own absolute move has
/// no `VIRTUALDESK` and reaches the primary display only.
#[cfg(target_os = "windows")]
fn move_px_now(_enigo: &mut Enigo, x: i32, y: i32) -> Result<()> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_MOVE,
        MOUSEEVENTF_VIRTUALDESK, MOUSEINPUT, SendInput,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };
    // SAFETY: GetSystemMetrics has no preconditions.
    let (vx, vy, vw, vh) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };
    let (dx, dy) = crate::keep_busy::normalise_virtual(x, y, vx, vy, vw, vh)
        .ok_or_else(|| anyhow!("no virtual screen ({vw}x{vh})"))?;
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: 0,
                dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    // SAFETY: one valid INPUT record; cbSize is its size.
    let sent = unsafe { SendInput(1, &input, std::mem::size_of::<INPUT>() as i32) };
    if sent != 1 {
        // 0 = blocked by another thread (UIPI) or a desktop we cannot reach.
        return Err(anyhow!(
            "SendInput sent {sent} of 1: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn move_px_now(enigo: &mut Enigo, x: i32, y: i32) -> Result<()> {
    enigo
        .move_mouse(x, y, Coordinate::Abs)
        .map_err(|e| anyhow!("move_mouse: {e}"))
}

/// Is a physical mouse button held? Windows: `GetAsyncKeyState` for the
/// five MOUSE buttons only — never a keyboard key: polling key state is what
/// a keylogger looks like to EDR. Read once per keep-busy resume.
#[cfg(target_os = "windows")]
fn buttons_held_now() -> Result<bool> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_LBUTTON, VK_MBUTTON, VK_RBUTTON, VK_XBUTTON1, VK_XBUTTON2,
    };
    let held = [VK_LBUTTON, VK_RBUTTON, VK_MBUTTON, VK_XBUTTON1, VK_XBUTTON2]
        .into_iter()
        // SAFETY: GetAsyncKeyState has no preconditions; the high bit is
        // "down now".
        .any(|vk| unsafe { GetAsyncKeyState(vk as i32) } as u16 & 0x8000 != 0);
    Ok(held)
}

/// Not wired off Windows yet (FR-92 P3: `CGEventSourceButtonState`, the X11
/// pointer mask). The engine treats "cannot tell" as "not held".
#[cfg(not(target_os = "windows"))]
fn buttons_held_now() -> Result<bool> {
    Err(anyhow::Error::new(super::PxUnsupported))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construction may fail on headless hosts (no DISPLAY / no Accessibility
    /// privilege on macOS). Skip gracefully — we only want failures when
    /// construction succeeds but the behaviour is wrong.
    #[test]
    fn constructs_or_skips() {
        match EnigoInjector::new() {
            Ok(_) => {}
            Err(e) => eprintln!("skipping — enigo unavailable: {e}"),
        }
    }

    /// rc.54 — virtual-screen-aware mapping math. Verifies the
    /// `map_normalised_to_virtual` helper that produces the absolute
    /// pixel coordinates passed to `SetCursorPos` / equivalents.
    #[test]
    fn map_zero_zero_lands_at_origin() {
        // Origin (0, 0), single-monitor 1920×1200.
        assert_eq!(
            map_normalised_to_virtual(0.0, 0.0, 0, 0, 1920, 1200),
            (0, 0)
        );
        // Non-zero origin (multi-monitor layout): (0,0) should land at
        // the monitor origin, NOT at the virtual desktop origin.
        assert_eq!(
            map_normalised_to_virtual(0.0, 0.0, 1920, 0, 1920, 1200),
            (1920, 0)
        );
        // Negative origin (primary to right of secondary).
        assert_eq!(
            map_normalised_to_virtual(0.0, 0.0, -1920, 0, 1920, 1200),
            (-1920, 0)
        );
    }

    #[test]
    fn map_one_one_lands_at_far_corner() {
        // Single-monitor 1920×1200: (1,1) → (1919, 1199) (w-1, h-1).
        assert_eq!(
            map_normalised_to_virtual(1.0, 1.0, 0, 0, 1920, 1200),
            (1919, 1199)
        );
        // Non-zero origin: far corner is shifted by origin.
        assert_eq!(
            map_normalised_to_virtual(1.0, 1.0, 1920, 0, 1920, 1200),
            (1920 + 1919, 1199)
        );
    }

    #[test]
    fn map_centre_lands_at_centre() {
        // 1920×1200 centre at origin: (960, 600).
        assert_eq!(
            map_normalised_to_virtual(0.5, 0.5, 0, 0, 1920, 1200),
            (960, 600)
        );
        // With origin offset (1920, 0): centre shifts by origin.
        assert_eq!(
            map_normalised_to_virtual(0.5, 0.5, 1920, 0, 1920, 1200),
            (1920 + 960, 600)
        );
    }

    #[test]
    fn map_clamps_out_of_range_normalised_values() {
        // Negative norm → clamped to 0 → at origin.
        assert_eq!(
            map_normalised_to_virtual(-0.5, -0.5, 0, 0, 1920, 1200),
            (0, 0)
        );
        // > 1 → clamped to 1 → at far corner.
        assert_eq!(
            map_normalised_to_virtual(1.5, 1.5, 0, 0, 1920, 1200),
            (1919, 1199)
        );
    }

    #[test]
    fn map_handles_degenerate_dims() {
        // 0×0 monitor (e.g. enumeration anomaly on a headless host):
        // result anchors at origin without underflow.
        assert_eq!(
            map_normalised_to_virtual(0.5, 0.5, 100, 200, 0, 0),
            (100, 200)
        );
        // 1×1 (singular dim): span_w / span_h are 0 → result at origin.
        assert_eq!(
            map_normalised_to_virtual(0.5, 0.5, 100, 200, 1, 1),
            (100, 200)
        );
    }

    /// WINHOST-A layout regression check — primary monitor at virtual
    /// origin (1920, 0): a click at centre-screen (0.5, 0.5) must land
    /// inside the primary monitor's virtual rect, not on the secondary
    /// monitor sitting at (0, 0).
    #[test]
    fn winhost_a_primary_offset_layout_lands_correct_monitor() {
        // Secondary 1920×1080 at (0, 0); primary 1920×1200 at (1920, 0).
        // We map against primary's MonitorInfo.
        let (px, py) = map_normalised_to_virtual(0.5, 0.5, 1920, 0, 1920, 1200);
        // Must be inside primary's [1920, 3840) × [0, 1200) rect.
        assert!(
            (1920..3840).contains(&px),
            "centre x should be inside primary's x-range, got {px}"
        );
        assert!(
            (0..1200).contains(&py),
            "centre y should be inside primary's y-range, got {py}"
        );
        // Pre-rc.54 would have produced (960, 600) — that's on the
        // SECONDARY monitor, hence the field-bug.
        assert_ne!((px, py), (960, 600));
    }

    #[test]
    fn wheel_pixel_deltas_round_to_notches() {
        assert_eq!(wheel_to_steps(0.0, 50.0, WheelMode::Pixel), (0, 1));
        assert_eq!(wheel_to_steps(0.0, -150.0, WheelMode::Pixel), (0, -2));
        assert_eq!(wheel_to_steps(100.0, 0.0, WheelMode::Pixel), (1, 0));
        assert_eq!(wheel_to_steps(0.0, 30.0, WheelMode::Pixel), (0, 0)); // below threshold
    }

    #[test]
    fn hid_table_covers_navigation_keys() {
        assert!(matches!(hid_to_key(0x4f), Some(Key::RightArrow)));
        assert!(matches!(hid_to_key(0x50), Some(Key::LeftArrow)));
        assert!(matches!(hid_to_key(0x29), Some(Key::Escape)));
        assert!(matches!(hid_to_key(0x3a), Some(Key::F1)));
        assert!(matches!(hid_to_key(0x45), Some(Key::F12)));
        assert_eq!(hid_to_key(0xffff), None);
    }

    /// On Windows, letters route through Key::Other(VK_*) so Ctrl/Alt
    /// modifiers combine with them. On other platforms the same input
    /// routes through Key::Unicode which the XTest / CGEventPost
    /// backends honour natively.
    #[test]
    #[cfg(target_os = "windows")]
    fn hid_letters_map_to_virtual_keycodes_on_windows() {
        // HID 0x04 = 'a' → VK_A (0x41)
        assert!(matches!(hid_to_key(0x04), Some(Key::Other(0x41))));
        // HID 0x06 = 'c' → VK_C (0x43) — Ctrl+C path
        assert!(matches!(hid_to_key(0x06), Some(Key::Other(0x43))));
        // HID 0x1d = 'z' → VK_Z (0x5a)
        assert!(matches!(hid_to_key(0x1d), Some(Key::Other(0x5a))));
        // HID 0x1e = '1' → VK_1 (0x31)
        assert!(matches!(hid_to_key(0x1e), Some(Key::Other(0x31))));
        // HID 0x27 = '0' → VK_0 (0x30)
        assert!(matches!(hid_to_key(0x27), Some(Key::Other(0x30))));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn hid_letters_map_to_unicode_on_non_windows() {
        assert!(matches!(hid_to_key(0x04), Some(Key::Unicode('a'))));
        assert!(matches!(hid_to_key(0x06), Some(Key::Unicode('c'))));
    }

    /// FR-13 (#789): CapsLock is a real mapping on every platform — HID
    /// 0x39 used to fall through to `Key::Other(0x39)` == VK_9 on Windows,
    /// so pressing CapsLock TYPED the digit 9.
    #[test]
    fn hid_caps_lock_and_keypad_map_everywhere() {
        assert!(matches!(hid_to_key(0x39), Some(Key::CapsLock)));
        assert!(matches!(hid_to_key(0x58), Some(Key::Return))); // NumpadEnter
        assert!(matches!(hid_to_key(0x59), Some(Key::Numpad1)));
        assert!(matches!(hid_to_key(0x61), Some(Key::Numpad9)));
        assert!(matches!(hid_to_key(0x62), Some(Key::Numpad0)));
        assert!(matches!(hid_to_key(0x63), Some(Key::Decimal)));
        assert!(matches!(hid_to_key(0x54), Some(Key::Divide)));
        assert!(matches!(hid_to_key(0x57), Some(Key::Add)));
    }

    /// FR-13 (#789): the contract the CapsLock bug broke silently — every
    /// HID usage the browser's `kbdCodeToHid`
    /// (ui/src/composables/useRemoteControl.ts) can emit either maps to a
    /// real `Key` or is a DOCUMENTED per-platform drop. The caller drops
    /// unmapped usages now; it must never again hand them to `Key::Other`,
    /// which reinterprets the byte as a platform virtual keycode (VK_9 /
    /// kVK_ANSI_KEYPAD_9 / a keysym).
    #[test]
    fn browser_emitted_hid_usages_map_or_are_documented_drops() {
        // Mirror of kbdCodeToHid's full emission set. Update BOTH sides
        // together when the viewer learns a new key.
        let browser_emitted: Vec<u32> = (0x04..=0x31)
            .chain(0x33..=0x52) // (0x32 Europe-1 is never emitted)
            .chain(0x53..=0x65)
            .chain(0xe0..=0xe7)
            .collect();

        // Keys this platform's enigo genuinely cannot model (same rationale
        // as the pre-existing 0x49 Insert exclusion on macOS). Moving one
        // OUT of this list requires a real mapping arm — never `Key::Other`.
        #[cfg(target_os = "windows")]
        let documented_drops: &[u32] = &[0x64]; // IntlBackslash (layout-dependent)
        #[cfg(all(unix, not(target_os = "macos")))]
        let documented_drops: &[u32] = &[0x64, 0x65]; // + ContextMenu (Apps is Windows-only)
        #[cfg(target_os = "macos")]
        let documented_drops: &[u32] = &[
            0x46, // PrintScreen — no such key/variant on Apple keyboards
            0x47, // ScrollLock
            0x48, // Pause
            0x49, // Insert (pre-existing exclusion)
            0x53, // NumLock
            0x64, // IntlBackslash
            0x65, // ContextMenu
        ];

        for code in browser_emitted {
            if documented_drops.contains(&code) {
                assert!(
                    hid_to_key(code).is_none(),
                    "0x{code:02x} is listed as a documented drop but now maps — \
                     remove it from documented_drops"
                );
            } else {
                assert!(
                    hid_to_key(code).is_some(),
                    "browser-emitted HID usage 0x{code:02x} has no hid_to_key arm — \
                     it would previously have hit the Key::Other fallback and typed \
                     garbage (FR-13); add a real mapping or document the drop"
                );
            }
        }
    }

    /// Stands in for `Enigo`: records every call `dispatch` makes.
    #[derive(Default)]
    struct Recorder {
        calls: Vec<String>,
    }

    impl Mouse for Recorder {
        fn button(&mut self, button: EnigoButton, direction: Direction) -> enigo::InputResult<()> {
            self.calls.push(format!("button {button:?} {direction:?}"));
            Ok(())
        }
        fn move_mouse(&mut self, x: i32, y: i32, c: Coordinate) -> enigo::InputResult<()> {
            self.calls.push(format!("move {x},{y} {c:?}"));
            Ok(())
        }
        fn scroll(&mut self, length: i32, axis: Axis) -> enigo::InputResult<()> {
            self.calls.push(format!("scroll {length} {axis:?}"));
            Ok(())
        }
        fn main_display(&self) -> enigo::InputResult<(i32, i32)> {
            Ok((1920, 1080))
        }
        fn location(&self) -> enigo::InputResult<(i32, i32)> {
            Ok((0, 0))
        }
    }

    impl Keyboard for Recorder {
        fn fast_text(&mut self, _text: &str) -> enigo::InputResult<Option<()>> {
            Ok(None)
        }
        fn key(&mut self, key: Key, direction: Direction) -> enigo::InputResult<()> {
            self.calls.push(format!("key {key:?} {direction:?}"));
            Ok(())
        }
        fn raw(&mut self, keycode: u16, direction: Direction) -> enigo::InputResult<()> {
            self.calls.push(format!("raw {keycode} {direction:?}"));
            Ok(())
        }
    }

    /// #1945 — the arbiter's release-all lets go where the pointer IS. A
    /// click moves first so it lands on its target; a release that did the
    /// same threw the cursor to (0,0), GNOME's Activities hot corner, every
    /// time a viewer vanished mid-drag.
    #[test]
    fn a_release_never_moves_the_pointer() {
        let mut r = Recorder::default();
        dispatch(&mut r, InputMsg::MouseRelease { btn: Button::Left }).unwrap();
        assert_eq!(r.calls, ["button Left Release"]);
    }

    /// The control: a viewer's own button-up still moves first. The recorder
    /// is shown to see a move, so the test above cannot pass by seeing none.
    #[test]
    fn a_button_up_from_a_viewer_still_lands_where_it_points() {
        let mut r = Recorder::default();
        dispatch(
            &mut r,
            InputMsg::MouseButton {
                btn: Button::Left,
                down: false,
                x: 0.5,
                y: 0.5,
                mon: 0,
            },
        )
        .unwrap();
        assert_eq!(r.calls, ["move 960,540 Abs", "button Left Release"]);
    }

    /// FR-109 — every enigo this agent builds sends `Coordinate::Rel` as a real
    /// relative move. With enigo 0.6's default the flag is off, and `Rel` on
    /// Windows went out as an absolute move to cursor + delta. Raw input saw
    /// one absolute event and no motion (field, 0.4.140: 10 frames reached the
    /// host as 0 relative counts and 10 absolute events). The dispatch test
    /// below checks that `Rel` is asked for; this checks what enigo does with it.
    #[test]
    fn enigo_settings_send_relative_moves_as_relative() {
        let s = enigo_settings();
        assert!(
            s.windows_subject_to_mouse_speed_and_acceleration_level,
            "enigo must send Coordinate::Rel as MOUSEEVENTF_MOVE, not as an absolute move"
        );
        // Everything else stays enigo's default.
        let d = Settings::default();
        assert_eq!(s.release_keys_when_dropped, d.release_keys_when_dropped);
        assert_eq!(
            s.independent_of_keyboard_state,
            d.independent_of_keyboard_state
        );
    }

    /// FR-109 — relative motion is one relative move, by exactly the counts
    /// sent, and never an absolute one: the host app owns the cursor.
    #[test]
    fn relative_motion_moves_by_its_counts() {
        let mut r = Recorder::default();
        dispatch(&mut r, InputMsg::MouseRel { dx: 37, dy: -12 }).unwrap();
        assert_eq!(r.calls, ["move 37,-12 Rel"]);
    }

    /// FR-109 — relative mode's press lands where the pointer is. A press
    /// that moved first, as a click does, would throw the pointer to a
    /// position the viewer never had.
    #[test]
    fn a_relative_press_never_moves_the_pointer() {
        let mut r = Recorder::default();
        dispatch(&mut r, InputMsg::MousePress { btn: Button::Right }).unwrap();
        assert_eq!(r.calls, ["button Right Press"]);
    }
}
