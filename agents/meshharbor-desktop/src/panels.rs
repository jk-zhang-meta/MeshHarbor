// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-27 — the two small always-on-top panels: the consent prompt, and the
//! "Being viewed by …" session banner.
//!
//! Why separate windows and not the main one: the main window is a 1100×740
//! SPA, and throwing that over whatever someone is doing to ask a single
//! yes/no is the wrong shape for a prompt. It is also the wrong shape for a
//! banner, which has to be visible *while* they keep working.
//!
//! Platform reality, stated plainly because it decides what these are for:
//!
//! - **Windows** has a native, capture-excluded overlay in the daemon
//!   (`indicator/win.rs`) and keeps it — `SetWindowDisplayAffinity` keeps it
//!   out of the video going back to the viewer, which a webview window only
//!   gets if we ask for it too (we do, below). The banner here is therefore
//!   opt-in on Windows and the default everywhere else.
//! - **macOS** honours `NSWindowSharingNone` for ScreenCaptureKit and
//!   `CGWindowListCreateImage`, but NOT for `CGDisplayStream` — which is what
//!   `capture/scrap_backend.rs` uses. ⚠️ The macOS banner is therefore expected
//!   to appear in the captured stream until capture moves to ScreenCaptureKit.
//!   Applied anyway: it costs nothing and becomes correct the day capture moves.
//! - **Linux/X11** has no equivalent at all. The banner appears in the stream.
//!
//! Both windows are created on demand and hidden rather than destroyed —
//! rebuilding a webview per prompt would put a visible delay in front of a
//! 30-second decision.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager, Runtime, WebviewUrl, WebviewWindowBuilder};

pub const CONSENT: &str = "consent";
pub const VIEWING: &str = "viewing";

/// The banner window's title. #2286's KWin script finds the banner by it.
pub const BANNER_TITLE: &str = "MeshHarbor — session active";

// ── FR-27 P9: the banner's Windows manners, here ──────────────────────────
//
// The native Windows badge (`meshharbord/src/indicator/win.rs`) hides until the
// pointer rests at the top edge, can be dragged, and leaves a thin red frame
// round the screen for the whole session. This banner showed and STAYED, and
// on macOS every show took keyboard focus from whatever the person was using.
// The numbers below are the Windows badge's, so the two behave alike.

/// The pointer within this many logical pixels of the top edge is "at the top".
const TOP_ZONE: f64 = 4.0;
/// How long the pointer rests at the top before the banner comes back.
const REVEAL_DWELL: Duration = Duration::from_millis(1200);
/// How long the banner stays once the pointer has left it.
const HIDE_DELAY: Duration = Duration::from_millis(2500);
/// How long a session's banner stays the first time, pointer or not: the
/// person must SEE that a session started before it tucks itself away.
const FIRST_SHOW: Duration = Duration::from_millis(4000);
/// The watch's tick: the Windows badge's timer.
const TICK: Duration = Duration::from_millis(120);

/// A session wants the banner (the session watch in `main.rs` says so).
static BANNER_WANTED: AtomicBool = AtomicBool::new(false);
/// The banner was just brought up for a new session: the reveal watch starts
/// from "visible, shown now".
static BANNER_FRESH: AtomicBool = AtomicBool::new(false);
static REVEAL_WATCH: Mutex<bool> = Mutex::new(false);

/// `=0` (or `false`/`off`) turns a P9 behaviour off — each is its own kill
/// switch: `MESHHARBOR_DESKTOP_BANNER_AUTOHIDE` (the banner then stays, as
/// before P9) and `MESHHARBOR_DESKTOP_FRAME` (no red frame).
fn switched_off(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

/// Escape hatch, both ways. `MESHHARBOR_DESKTOP_BANNER=0` turns the banner off
/// where the native overlay already covers it; `=1` forces it on for an A/B
/// against that overlay.
///
/// Default: ON everywhere except Windows, which has the better one already.
pub fn banner_enabled() -> bool {
    match std::env::var("MESHHARBOR_DESKTOP_BANNER").ok().as_deref() {
        Some("0") | Some("false") | Some("off") => false,
        Some(_) => true,
        None => !cfg!(windows),
    }
}

/// Bring the consent prompt up. Idempotent — a second pending request while
/// one is already shown just re-focuses; the page renders whatever the daemon
/// currently lists.
pub fn show_consent<R: Runtime>(app: &AppHandle<R>) {
    show(
        app,
        CONSENT,
        "panel-consent.html",
        "MeshHarbor — permission needed",
        460.0,
        260.0,
        // Focused: this one is a question, and a prompt nobody's keyboard can
        // reach is the failure mode we are here to fix.
        true,
    );
}

/// Bring the session banner up. Never focused and never in the taskbar — it is
/// a status indicator beside whatever the person is actually doing.
///
/// FR-27 P9: from here the reveal watch owns it — it tucks itself away after
/// [`FIRST_SHOW`], comes back when the pointer rests at the top edge, and
/// stays while anything records. The red frame comes up with it (macOS) and
/// stays for the whole session.
pub fn show_banner<R: Runtime>(app: &AppHandle<R>) {
    show(
        app,
        VIEWING,
        "panel-viewing.html",
        BANNER_TITLE,
        360.0,
        76.0,
        false,
    );
    // #2286 — on KDE, KWin places it: at the top, above everything. Off this
    // thread, because it is a blocking D-Bus round trip.
    #[cfg(target_os = "linux")]
    std::thread::spawn(|| crate::pin::ensure_kwin_pin(BANNER_TITLE));
    BANNER_FRESH.store(true, Ordering::SeqCst);
    BANNER_WANTED.store(true, Ordering::SeqCst);
    if !switched_off("MESHHARBOR_DESKTOP_FRAME") {
        frame::show(app);
    }
    if !switched_off("MESHHARBOR_DESKTOP_BANNER_AUTOHIDE") {
        spawn_reveal_watch(app);
    }
}

pub fn hide<R: Runtime>(app: &AppHandle<R>, label: &str) {
    if label == VIEWING {
        // The session is over: the watch must not bring the banner back, and
        // the frame goes with it.
        BANNER_WANTED.store(false, Ordering::SeqCst);
        frame::hide(app);
    }
    if let Some(w) = app.get_webview_window(label) {
        let _ = w.hide();
    }
}

/// Start the reveal watch once; it idles while no session wants the banner.
fn spawn_reveal_watch<R: Runtime>(app: &AppHandle<R>) {
    let mut started = match REVEAL_WATCH.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if *started {
        return;
    }
    let app = app.clone();
    if std::thread::Builder::new()
        .name("banner-reveal".into())
        .spawn(move || reveal_watch(app))
        .is_ok()
    {
        *started = true;
    }
}

fn reveal_watch<R: Runtime>(app: AppHandle<R>) {
    let mut state = Reveal::default();
    loop {
        std::thread::sleep(TICK);
        if !BANNER_WANTED.load(Ordering::SeqCst) {
            state = Reveal::default();
            continue;
        }
        let Some(win) = app.get_webview_window(VIEWING) else {
            continue;
        };
        let now = Instant::now();
        if BANNER_FRESH.swap(false, Ordering::SeqCst) {
            state = Reveal::shown(now);
        }
        match state.step(now, Sample::read(&win), crate::tray::recording_now()) {
            Some(true) => present(&win, false),
            Some(false) => {
                let _ = win.hide();
            }
            None => {}
        }
    }
}

/// One look at the pointer. `None` when it cannot be read (a Wayland session
/// keeps the global pointer to itself) — and then the banner simply stays,
/// because an indicator that hid with no way back would be worse than one that
/// never hides.
#[derive(Clone, Copy, Debug)]
struct Sample {
    /// Within [`TOP_ZONE`] of the primary screen's top edge.
    at_top: bool,
    /// Over the banner, or within a small margin of it (a drag in progress).
    over_banner: bool,
}

impl Sample {
    fn read<R: Runtime>(win: &tauri::WebviewWindow<R>) -> Option<Self> {
        // #2286 — under Xwayland the pointer is known only over X11 windows:
        // at GNOME's top bar it reads where it last was, so the top-edge
        // gesture would never bring a tucked-away banner back. Unreadable,
        // then, and the banner stays where it is pinned.
        #[cfg(target_os = "linux")]
        if crate::pin::under_xwayland() {
            return None;
        }
        let p = win.cursor_position().ok()?;
        let mon = win.primary_monitor().ok().flatten()?;
        let scale = mon.scale_factor();
        let (mx, my) = (f64::from(mon.position().x), f64::from(mon.position().y));
        let mw = f64::from(mon.size().width);
        let at_top = p.x >= mx && p.x < mx + mw && p.y <= my + TOP_ZONE * scale;
        let over_banner = match (win.outer_position(), win.outer_size()) {
            (Ok(o), Ok(sz)) => {
                let margin = 8.0 * scale;
                let (ox, oy) = (f64::from(o.x), f64::from(o.y));
                p.x >= ox - margin
                    && p.x <= ox + f64::from(sz.width) + margin
                    && p.y >= oy - margin
                    && p.y <= oy + f64::from(sz.height) + margin
            }
            _ => false,
        };
        Some(Self {
            at_top,
            over_banner,
        })
    }
}

/// The reveal watch's state machine: when to show and when to hide.
#[derive(Debug, Default)]
struct Reveal {
    visible: bool,
    shown_at: Option<Instant>,
    /// Since when the pointer has rested at the top (banner hidden).
    dwell_since: Option<Instant>,
    /// Since when the pointer has been away from the banner (banner shown).
    away_since: Option<Instant>,
}

impl Reveal {
    fn shown(now: Instant) -> Self {
        Self {
            visible: true,
            shown_at: Some(now),
            ..Self::default()
        }
    }

    /// One tick. `Some(true)` shows the banner, `Some(false)` hides it.
    fn step(&mut self, now: Instant, sample: Option<Sample>, recording: bool) -> Option<bool> {
        if !self.visible {
            // A recording brings it back at once and holds it: that is not
            // something to be told about only on request.
            let reveal = match sample {
                None => true,
                Some(_) if recording => true,
                Some(s) if s.at_top => {
                    let since = *self.dwell_since.get_or_insert(now);
                    now.duration_since(since) >= REVEAL_DWELL
                }
                Some(_) => {
                    self.dwell_since = None;
                    false
                }
            };
            if reveal {
                *self = Self::shown(now);
                return Some(true);
            }
            return None;
        }
        let first_show = self
            .shown_at
            .is_some_and(|t| now.duration_since(t) < FIRST_SHOW);
        let keep = recording || first_show || sample.is_none_or(|s| s.over_banner || s.at_top);
        if keep {
            self.away_since = None;
            return None;
        }
        let since = *self.away_since.get_or_insert(now);
        if now.duration_since(since) >= HIDE_DELAY {
            *self = Self::default();
            return Some(false);
        }
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn show<R: Runtime>(
    app: &AppHandle<R>,
    label: &str,
    page: &str,
    title: &str,
    w: f64,
    h: f64,
    focus: bool,
) {
    if let Some(win) = app.get_webview_window(label) {
        present(&win, focus);
        return;
    }
    let built = WebviewWindowBuilder::new(app, label, WebviewUrl::App(page.into()))
        .title(title)
        .inner_size(w, h)
        // #2286 — and no bigger. On Linux a NON-resizable GTK window takes
        // its child's natural size, and a webview's is ~200 px: the banner
        // asked for 76 px and came out 198 px tall, the rest of it empty.
        // Resizable with min = max is the same fixed size without that.
        .min_inner_size(w, h)
        .max_inner_size(w, h)
        .resizable(cfg!(target_os = "linux"))
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .focused(focus)
        // #1852 — a panel shown WITHOUT focus must take its first click, or
        // that click is spent making the window key and the button under it
        // does nothing: on macOS the banner's Disconnect and Stop recording
        // needed two clicks (FR-27 P9 field check, 2026-10-08). The consent
        // prompt is shown focused and keeps the default — a click-through on
        // an approval surface is not wanted. macOS only; a no-op elsewhere.
        .accept_first_mouse(takes_first_click(focus))
        .visible(false)
        .build();
    let win = match built {
        Ok(win) => win,
        Err(e) => {
            // Loud: the fallback for a failed panel is the in-window modal the
            // SPA still carries, and a silent failure here would look exactly
            // like "consent does not work" — the bug this FR exists to close.
            tracing::error!(%label, %e, "could not create the panel window — falling back to the main window's modal");
            if let Some(main) = app.get_webview_window("main") {
                let _ = main.show();
                let _ = main.set_focus();
            }
            return;
        }
    };
    exclude_from_capture(&win);
    // #2286 — on Linux only the banner sits at the top. The daemon's own X11
    // consent panel already holds the top centre there, and with the
    // companion on Xwayland (GNOME) a consent window placed there too landed
    // right under it when two questions were pending; a question goes in the
    // middle, where a Wayland compositor puts it anyway.
    if label == VIEWING || !cfg!(target_os = "linux") {
        position_top_centre(&win, w);
    } else {
        position_centre(&win, w, h);
    }
    present(&win, focus);
}

/// #2286 — the middle of the primary monitor, computed as the top centre is.
/// (`WebviewWindow::center` put the window's CORNER at the middle under
/// Xwayland at 2×, half a window off.)
fn position_centre<R: Runtime>(win: &tauri::WebviewWindow<R>, logical_w: f64, logical_h: f64) {
    let Ok(Some(monitor)) = win.primary_monitor() else {
        return;
    };
    let scale = monitor.scale_factor();
    let size = monitor.size().to_logical::<f64>(scale);
    let pos = monitor.position().to_logical::<f64>(scale);
    let x = pos.x + (size.width - logical_w) / 2.0;
    let y = pos.y + (size.height - logical_h) / 2.0;
    let _ = win.set_position(tauri::LogicalPosition::new(x, y));
}

/// Whether a panel's webview takes the FIRST click while its window is
/// inactive (`accept_first_mouse`). Derived from how the panel is shown, so
/// the two cannot drift apart: a panel brought up without focus — the session
/// banner, `show_without_focus` — is one the person clicks INTO from another
/// app, so its first click must act; a panel brought up focused — the consent
/// prompt — already has the keyboard and must not be click-through (#1852).
fn takes_first_click(focus: bool) -> bool {
    !focus
}

/// Show a panel. A focused one takes the keyboard (a question needs it); an
/// unfocused one must not.
fn present<R: Runtime>(win: &tauri::WebviewWindow<R>, focus: bool) {
    if focus {
        let _ = win.show();
        let _ = win.set_focus();
    } else {
        show_without_focus(win);
    }
}

/// ⚠️ macOS: `show()` makes the window KEY whatever `focused(false)` said at
/// build time, so every session's banner took key status from the window the
/// person was using, and their next click into it only made it key again — it
/// did nothing else (measured 2026-10-06: the first click into meshharbor-desktop
/// after each new session was lost). `orderFrontRegardless` shows it without
/// that, the way the native consent panel (`indicator/mac.rs`) shows itself.
#[cfg(target_os = "macos")]
fn show_without_focus<R: Runtime>(win: &tauri::WebviewWindow<R>) {
    let w = win.clone();
    let shown = win.run_on_main_thread(move || {
        if let Ok(ptr) = w.ns_window() {
            // SAFETY: `ns_window` is this live window's own `NSWindow`, and
            // this runs on the main thread, where AppKit must be called.
            let ns = unsafe { &*ptr.cast::<objc2_app_kit::NSWindow>() };
            ns.orderFrontRegardless();
        }
    });
    if shown.is_err() {
        let _ = win.show();
    }
}

#[cfg(not(target_os = "macos"))]
fn show_without_focus<R: Runtime>(win: &tauri::WebviewWindow<R>) {
    let _ = win.show();
}

/// Top-centre of the primary monitor: out of the way of most content, and the
/// place a notification is expected on all three platforms. Best-effort — a
/// failure just leaves the window wherever the OS put it.
fn position_top_centre<R: Runtime>(win: &tauri::WebviewWindow<R>, logical_w: f64) {
    let Ok(Some(monitor)) = win.primary_monitor() else {
        return;
    };
    let scale = monitor.scale_factor();
    let size = monitor.size().to_logical::<f64>(scale);
    let pos = monitor.position().to_logical::<f64>(scale);
    let x = pos.x + (size.width - logical_w) / 2.0;
    let y = pos.y + 48.0;
    let _ = win.set_position(tauri::LogicalPosition::new(x, y));
}

/// Ask the OS to keep this window out of screen capture.
///
/// Windows honours it outright. macOS honours it for ScreenCaptureKit and
/// window-list captures but NOT for `CGDisplayStream`, which is what our
/// capture backend uses today — so the call is correct and currently
/// ineffective there; see the module docs. X11 has nothing to ask.
#[cfg(windows)]
fn exclude_from_capture<R: Runtime>(win: &tauri::WebviewWindow<R>) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE,
    };
    if let Ok(handle) = win.hwnd() {
        // SAFETY: `handle` is a live HWND owned by this window for the
        // duration of the call; the flag is a documented constant.
        unsafe {
            SetWindowDisplayAffinity(handle.0 as _, WDA_EXCLUDEFROMCAPTURE);
        }
    }
}

/// macOS: `NSWindowSharingNone`. Correct and, for our `CGDisplayStream`
/// capture, currently ineffective (see the module docs) — set because it
/// costs nothing and becomes true the day capture moves to ScreenCaptureKit.
/// Until FR-27 P9 this was an empty function despite the docs above.
#[cfg(target_os = "macos")]
fn exclude_from_capture<R: Runtime>(win: &tauri::WebviewWindow<R>) {
    let w = win.clone();
    let _ = win.run_on_main_thread(move || {
        if let Ok(ptr) = w.ns_window() {
            // SAFETY: as in `show_without_focus`.
            let ns = unsafe { &*ptr.cast::<objc2_app_kit::NSWindow>() };
            ns.setSharingType(objc2_app_kit::NSWindowSharingType::None);
        }
    });
}

#[cfg(not(any(windows, target_os = "macos")))]
fn exclude_from_capture<R: Runtime>(_win: &tauri::WebviewWindow<R>) {}

/// FR-27 P9 — the red frame round the screen while a session is up: the
/// native Windows border's 2 px, as four click-through strips (no layer, no
/// transparency: an opaque strip needs nothing beyond what `indicator/mac.rs`
/// already uses). ⚠️ It WILL appear in the captured stream, like the banner:
/// our macOS capture is `CGDisplayStream`, which ignores
/// `NSWindowSharingNone` (the operator's call, 2026-10-06: ship it anyway).
#[cfg(target_os = "macos")]
mod frame {
    use std::cell::RefCell;

    use objc2::rc::Retained;
    // `MainThreadOnly` provides `NSWindow::alloc` — load-bearing import.
    use objc2::{MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{
        NSBackingStoreType, NSColor, NSScreen, NSScreenSaverWindowLevel, NSWindow,
        NSWindowCollectionBehavior, NSWindowSharingType, NSWindowStyleMask,
    };
    use objc2_foundation::{NSPoint, NSRect, NSSize};
    use tauri::{AppHandle, Runtime};

    /// Frame thickness in points.
    const BORDER: f64 = 2.0;

    thread_local! {
        /// The four strips, created once and kept: only the main thread
        /// touches them, so they live in its thread-local.
        static STRIPS: RefCell<Vec<Retained<NSWindow>>> = const { RefCell::new(Vec::new()) };
    }

    pub fn show<R: Runtime>(app: &AppHandle<R>) {
        let _ = app.run_on_main_thread(|| {
            let Some(mtm) = MainThreadMarker::new() else {
                return;
            };
            STRIPS.with(|strips| {
                let mut strips = strips.borrow_mut();
                if strips.is_empty() {
                    *strips = build(mtm);
                }
                for s in strips.iter() {
                    s.orderFrontRegardless();
                }
            });
        });
    }

    pub fn hide<R: Runtime>(app: &AppHandle<R>) {
        let _ = app.run_on_main_thread(|| {
            STRIPS.with(|strips| {
                for s in strips.borrow().iter() {
                    s.orderOut(None);
                }
            });
        });
    }

    fn build(mtm: MainThreadMarker) -> Vec<Retained<NSWindow>> {
        let Some(screen) = NSScreen::mainScreen(mtm) else {
            return Vec::new();
        };
        let f = screen.frame();
        let (x, y, w, h) = (f.origin.x, f.origin.y, f.size.width, f.size.height);
        // AppKit's origin is bottom-left.
        [
            (x, y + h - BORDER, w, BORDER),
            (x, y, w, BORDER),
            (x, y, BORDER, h),
            (x + w - BORDER, y, BORDER, h),
        ]
        .into_iter()
        .map(|(x, y, w, h)| strip(mtm, NSRect::new(NSPoint::new(x, y), NSSize::new(w, h))))
        .collect()
    }

    fn strip(mtm: MainThreadMarker, rect: NSRect) -> Retained<NSWindow> {
        // SAFETY: a plain borderless window on the main thread (`mtm`).
        let w = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                rect,
                NSWindowStyleMask::Borderless,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        // SAFETY: we hold the window (`Retained`) and never `close()` it;
        // AppKit must not ALSO release it if something ever does.
        unsafe { w.setReleasedWhenClosed(false) };
        // Above full-screen apps and every Space, like the consent panel.
        w.setLevel(NSScreenSaverWindowLevel);
        w.setCollectionBehavior(
            NSWindowCollectionBehavior::CanJoinAllSpaces
                | NSWindowCollectionBehavior::Stationary
                | NSWindowCollectionBehavior::FullScreenAuxiliary
                | NSWindowCollectionBehavior::IgnoresCycle,
        );
        w.setSharingType(NSWindowSharingType::None);
        w.setOpaque(true);
        w.setHasShadow(false);
        w.setBackgroundColor(Some(&NSColor::colorWithSRGBRed_green_blue_alpha(
            1.0, 0.2, 0.2, 1.0,
        )));
        // Click-through: a frame that ate clicks along the screen edges would
        // break the Dock, the menu bar and every edge-snapped window.
        w.setIgnoresMouseEvents(true);
        w.setHidesOnDeactivate(false);
        w
    }
}

#[cfg(not(target_os = "macos"))]
mod frame {
    use tauri::{AppHandle, Runtime};

    pub fn show<R: Runtime>(_app: &AppHandle<R>) {}
    pub fn hide<R: Runtime>(_app: &AppHandle<R>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn away() -> Option<Sample> {
        Some(Sample {
            at_top: false,
            over_banner: false,
        })
    }

    fn top() -> Option<Sample> {
        Some(Sample {
            at_top: true,
            over_banner: false,
        })
    }

    fn over() -> Option<Sample> {
        Some(Sample {
            at_top: false,
            over_banner: true,
        })
    }

    #[test]
    fn a_new_sessions_banner_stays_its_first_show_then_tucks_away() {
        let t0 = Instant::now();
        let mut r = Reveal::shown(t0);
        // Pointer nowhere near it: still shown for the whole first show.
        assert_eq!(
            r.step(t0 + Duration::from_millis(3900), away(), false),
            None
        );
        // Then the hide delay runs from the first tick it is allowed to hide.
        assert_eq!(r.step(t0 + FIRST_SHOW, away(), false), None);
        assert_eq!(
            r.step(t0 + FIRST_SHOW + HIDE_DELAY, away(), false),
            Some(false)
        );
        assert!(!r.visible);
    }

    #[test]
    fn resting_at_the_top_brings_it_back_only_after_the_dwell() {
        let t0 = Instant::now();
        let mut r = Reveal::default();
        assert_eq!(r.step(t0, top(), false), None);
        assert_eq!(r.step(t0 + Duration::from_millis(1100), top(), false), None);
        assert_eq!(r.step(t0 + REVEAL_DWELL, top(), false), Some(true));
        assert!(r.visible);
    }

    #[test]
    fn leaving_the_top_resets_the_dwell() {
        let t0 = Instant::now();
        let mut r = Reveal::default();
        r.step(t0, top(), false);
        r.step(t0 + Duration::from_millis(1000), away(), false);
        // The rest starts again: 1.0 s more at the top is not enough.
        assert_eq!(r.step(t0 + Duration::from_millis(1100), top(), false), None);
        assert_eq!(r.step(t0 + Duration::from_millis(2100), top(), false), None);
        assert_eq!(
            r.step(
                t0 + Duration::from_millis(1100) + REVEAL_DWELL,
                top(),
                false
            ),
            Some(true)
        );
    }

    #[test]
    fn the_pointer_on_the_banner_keeps_it_however_long() {
        let t0 = Instant::now();
        let mut r = Reveal::shown(t0);
        for s in 0..60 {
            assert_eq!(r.step(t0 + Duration::from_secs(s), over(), false), None);
        }
        assert!(r.visible);
    }

    #[test]
    fn a_recording_shows_it_at_once_and_holds_it() {
        let t0 = Instant::now();
        let mut r = Reveal::default();
        assert_eq!(r.step(t0, away(), true), Some(true));
        for s in 1..60 {
            assert_eq!(r.step(t0 + Duration::from_secs(s), away(), true), None);
        }
        assert!(r.visible);
    }

    #[test]
    fn an_unreadable_pointer_never_hides_it() {
        // A Wayland session keeps the global pointer to itself: hiding with no
        // way to bring the banner back would leave the person with nothing.
        let t0 = Instant::now();
        let mut r = Reveal::shown(t0);
        for s in 0..60 {
            assert_eq!(r.step(t0 + Duration::from_secs(s), None, false), None);
        }
        let mut hidden = Reveal::default();
        assert_eq!(hidden.step(t0, None, false), Some(true));
    }

    #[test]
    fn the_unfocused_banner_takes_its_first_click_the_consent_prompt_does_not() {
        // #1852: an inactive macOS window spends its first click on activation
        // unless its view accepts first mouse. The banner is shown without
        // focus (P9), so Disconnect / Stop recording must fire on ONE click;
        // the consent prompt is shown focused and must not be click-through.
        // The builder itself needs a live Tauri runtime, so the decision is
        // what this pins.
        assert!(takes_first_click(false), "the banner (shown without focus)");
        assert!(
            !takes_first_click(true),
            "the consent prompt (shown focused)"
        );
    }
}
