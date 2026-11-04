// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows implementation of the viewer-indicator overlay.
//!
//! Two topmost, capture-excluded windows on the primary monitor:
//!
//! - A **thin, click-through border** (`WS_EX_TRANSPARENT`) that is
//!   always visible while a session is active — the passive "someone is
//!   watching" cue (Parsec / Moonlight style).
//! - A small **interactive badge** carrying the viewer's initials, name
//!   and a **Disconnect** control. It stays hidden until the user parks
//!   the pointer at the top edge for ~1.2 s (RDP / RustDesk reveal), is
//!   **draggable** so the viewee can move it off something they need to
//!   read, and auto-hides shortly after the pointer leaves. Clicking
//!   Disconnect fires the session's `ObjectId` through the `KillSender`
//!   back to the signaling loop, which tears the session down.
//!
//! `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` is the
//! load-bearing piece on BOTH windows: DWM composites them on the local
//! screen but omits them from every capture path (our WGC backend, DXGI
//! duplication, BitBlt), so the overlay — including the Disconnect
//! button — never leaks into the RTP stream going back to the viewer.
//!
//! The border uses a single COLORKEY (magenta) for transparency; the
//! badge is an ordinary opaque popup.

#![cfg(all(target_os = "windows", feature = "viewer-indicator"))]

use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread;
use std::time::Instant;

use bson::oid::ObjectId;

use windows::Win32::Foundation::{
    BOOL, COLORREF, HMODULE, HWND, LPARAM, LRESULT, POINT, RECT, TRUE, WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DT_CENTER, DT_END_ELLIPSIS, DT_LEFT, DT_SINGLELINE,
    DT_VCENTER, DeleteObject, DrawTextW, Ellipse, EndPaint, EnumDisplayMonitors, FW_BOLD,
    FW_NORMAL, FillRect, FrameRect, GetStockObject, HBRUSH, HDC, HGDIOBJ, HMONITOR, InvalidateRect,
    NULL_PEN, OUT_DEFAULT_PRECIS, PAINTSTRUCT, SelectObject, SetBkMode, SetTextColor, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::ReleaseCapture;
use windows::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GWLP_USERDATA, GetClientRect, GetCursorPos, GetMessageW, GetSystemMetrics,
    GetWindowDisplayAffinity, GetWindowLongPtrW, GetWindowRect, HMENU, HTCAPTION, HWND_TOPMOST,
    IDC_ARROW, KillTimer, LWA_ALPHA, LWA_COLORKEY, LoadCursorW, MSG, PostMessageW, PostQuitMessage,
    RegisterClassExW, SM_CXSCREEN, SM_CXVIRTUALSCREEN, SM_CYSCREEN, SM_CYVIRTUALSCREEN,
    SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SW_HIDE, SW_SHOWNOACTIVATE, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOSIZE, SWP_SHOWWINDOW, SendMessageW, SetLayeredWindowAttributes, SetTimer,
    SetWindowDisplayAffinity, SetWindowLongPtrW, SetWindowPos, ShowWindow, TranslateMessage,
    WDA_EXCLUDEFROMCAPTURE, WM_APP, WM_DESTROY, WM_DISPLAYCHANGE, WM_ERASEBKGND, WM_EXITSIZEMOVE,
    WM_LBUTTONDOWN, WM_LBUTTONUP, WM_NCLBUTTONDOWN, WM_PAINT, WM_TIMER, WNDCLASSEXW, WS_EX_LAYERED,
    WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
};
use windows::core::w;

use super::{KillSender, initials_of};

// Custom window messages. WM_APP + N is reserved for application use;
// Windows promises not to send anything in this range to our WndProc.
const WM_APP_REDRAW: u32 = WM_APP + 1;
const WM_APP_SHUTDOWN: u32 = WM_APP + 2;

/// Border thickness in pixels. Kept thin (2 px) — a visible-but-subtle
/// frame that doesn't occlude window chrome; the reveal-on-hover badge
/// carries the who/Disconnect detail.
const BORDER_PX: i32 = 2;
/// Magenta — the COLORKEY for the border window. Any pixel painted
/// exactly this color renders transparent.
const COLORKEY_RGB: u32 = 0x00FF00FF;
/// Red (0xFF3333) for the visible border, initials chip, Disconnect
/// button and badge frame. COLORREF is 0x00BBGGRR.
const BORDER_RGB: u32 = 0x003333FF;
/// White caption / button text.
const TEXT_RGB: u32 = 0x00FFFFFF;
/// Muted grey for the small "Being viewed by" label.
const LABEL_RGB: u32 = 0x00B0B0B0;
/// Dark badge background.
const BADGE_BG_RGB: u32 = 0x001E1E1E;

// Badge geometry (device pixels; DPI-naive, matching the border).
const BADGE_W: i32 = 300;
const BADGE_H: i32 = 48;
const BTN_W: i32 = 96;
const BTN_H: i32 = 30;
const BTN_MARGIN: i32 = 8;
const CHIP_MARGIN: i32 = 8;
const CHIP_DIA: i32 = 32;

// Reveal-on-hover tuning.
const TIMER_ID: usize = 1;
const TIMER_MS: u32 = 120;
/// Pointer within this many pixels of the top edge counts as "at top".
const TOP_ZONE_PX: i32 = 4;
/// Dwell at the top edge before the badge appears.
const REVEAL_DWELL_MS: u128 = 1200;
/// Grace period after the pointer leaves before the badge hides.
const HIDE_DELAY_MS: u128 = 2500;

/// Disconnect button rectangle in badge client coordinates. Fixed, so
/// both the painter and the hit-test agree without stashing state.
fn button_rect() -> RECT {
    let top = (BADGE_H - BTN_H) / 2;
    RECT {
        left: BADGE_W - BTN_W - BTN_MARGIN,
        top,
        right: BADGE_W - BTN_MARGIN,
        bottom: top + BTN_H,
    }
}

/// Half-open point-in-rect test (client coordinates).
fn pt_in(r: &RECT, x: i32, y: i32) -> bool {
    x >= r.left && x < r.right && y >= r.top && y < r.bottom
}

// ── FR-27: the native consent panel ────────────────────────────────────────
//
// Drawn by the daemon itself, so it needs no second process running, no
// login-session plumbing and no IPC — and it inherits the property that makes
// this module worth having: `WDA_EXCLUDEFROMCAPTURE`, so the Approve button is
// invisible in the video going back to the person asking for access. A prompt
// the requester can SEE (and, with input granted on another session, click) is
// not a consent prompt.

/// Panel geometry. Wider and much taller than the badge: this one has to carry
/// a title, who is asking, which org, what they want to run, and two buttons.
const CONSENT_W: i32 = 460;
const CONSENT_H: i32 = 232;
const CONSENT_PAD: i32 = 14;
const CONSENT_BTN_W: i32 = 104;
const CONSENT_BTN_H: i32 = 32;
/// Green (0x2E9E4F) for Approve. COLORREF is 0x00BBGGRR.
const APPROVE_RGB: u32 = 0x004F9E2E;

/// Approve / Deny rectangles in panel client coordinates. Fixed, so the
/// painter and the hit-test agree without stashing state — same reason as
/// [`button_rect`].
fn consent_approve_rect() -> RECT {
    let top = CONSENT_H - CONSENT_PAD - CONSENT_BTN_H;
    RECT {
        left: CONSENT_W - CONSENT_PAD - CONSENT_BTN_W,
        top,
        right: CONSENT_W - CONSENT_PAD,
        bottom: top + CONSENT_BTN_H,
    }
}

fn consent_deny_rect() -> RECT {
    let a = consent_approve_rect();
    RECT {
        left: a.left - 8 - CONSENT_BTN_W,
        top: a.top,
        right: a.left - 8,
        bottom: a.bottom,
    }
}

#[derive(Default)]
struct State {
    /// Active sessions: `session_id_hex → controller display name`.
    sessions: HashMap<String, String>,
    /// FR-85 P3 — the sessions RECORDING the screen. While any is, the badge
    /// is pinned open and says so: a recording is not something to be told
    /// about only when the cursor happens to wander to the top edge.
    recording: std::collections::HashSet<String>,
    /// FR-27 — the consent question currently on screen, if any.
    ///
    /// At most ONE: two overlapping Approve/Deny panels is how someone
    /// approves the wrong thing. A second request while one is up waits for
    /// the first to resolve, and its own 30 s window is what bounds the wait.
    prompt: Option<super::PromptView>,
    /// FR-99 — the sessions with privacy mode ON: `session hex → controller
    /// display name`. While any is, the curtain covers every monitor.
    privacy: HashMap<String, String>,
    /// FR-99 — the pump's last word on the curtain: `Some(true)` up and
    /// verified out of capture, `Some(false)` it could not be (creation or
    /// the capture exclusion failed), `None` down or not decided yet.
    curtain: Option<bool>,
}

// ── FR-99: the privacy curtain ─────────────────────────────────────────────
//
// One window over the whole virtual desktop, so every monitor is covered,
// with the notice painted centred on each monitor. Layered and click-through
// (`WS_EX_TRANSPARENT`): the controller's injected clicks must reach the
// application beneath it, which also means it HIDES the screen and does not
// stop a person at the keyboard (P2 is the input block). Kept out of every
// capture path by `WDA_EXCLUDEFROMCAPTURE`, set before the window is shown and
// read back afterwards: a curtain the capture could see would hide the desktop
// from the controller too, so an affinity that does not read back is a refusal.

/// How long `set_privacy` waits for the pump to put the curtain up and answer.
const CURTAIN_ANSWER_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
/// Every this many pump ticks (120 ms each) the curtain re-takes the top of
/// the z-order, refits the virtual desktop, and puts the person's own controls
/// back above it.
const CURTAIN_RAISE_EVERY: u32 = 4;
/// Slate (0x1E293B). COLORREF is 0x00BBGGRR.
const CURTAIN_RGB: u32 = 0x003B291E;

#[derive(Clone)]
pub(super) struct Inner {
    state: Arc<Mutex<State>>,
    hwnd: Arc<Mutex<Option<isize>>>, // border HWND as isize for Send+Sync
    tx: std_mpsc::Sender<Cmd>,
}

enum Cmd {
    Redraw,
    Shutdown,
}

/// Everything the pump thread's two window procs need. Owned solely by
/// the pump thread (never sent across threads); a raw pointer to it is
/// stashed in BOTH windows' `GWLP_USERDATA`. Reclaimed once on teardown.
///
/// SOUNDNESS: window procs must not hold a `&mut PumpState` across a
/// Win32 call that can synchronously re-enter the pump (the drag's
/// `SendMessage(WM_NCLBUTTONDOWN)`, `ShowWindow`, `SetWindowPos`). The
/// code computes decisions inside a short borrow, drops it, then runs
/// the window ops through helpers that touch fields only momentarily.
struct PumpState {
    shared: Arc<Mutex<State>>,
    kill_tx: KillSender,
    badge_hwnd: HWND,
    badge_pos: (i32, i32),
    badge_visible: bool,
    dragging: bool,
    dwell_since: Option<Instant>,
    hide_since: Option<Instant>,
    // FR-27 — the consent panel.
    consent_hwnd: HWND,
    consent_tx: super::ConsentSender,
    consent_visible: bool,
    /// Whole seconds left as last PAINTED. The pump ticks at 120 ms; repainting
    /// the panel eight times a second to redraw the same number is flicker for
    /// nothing, so the countdown only invalidates when the digit changes.
    consent_secs_shown: u64,
    // FR-99 — the privacy curtain. Created when the first session turns
    // privacy on and destroyed when the last turns it off; null otherwise.
    hinstance: HMODULE,
    curtain_hwnd: HWND,
    /// The virtual desktop the curtain was last fitted to.
    curtain_rect: RECT,
    curtain_ticks: u32,
}

impl Inner {
    pub(super) fn new(kill_tx: KillSender, consent_tx: super::ConsentSender) -> Result<Self> {
        let state = Arc::new(Mutex::new(State::default()));
        let hwnd_cell: Arc<Mutex<Option<isize>>> = Arc::new(Mutex::new(None));
        let (tx, rx) = std_mpsc::channel::<Cmd>();

        let state_for_thread = state.clone();
        let hwnd_for_thread = hwnd_cell.clone();
        let (ready_tx, ready_rx) = std_mpsc::channel::<Result<()>>();

        thread::Builder::new()
            .name("roomlerd-indicator".into())
            .spawn(move || {
                match run_pump(state_for_thread, hwnd_for_thread, rx, kill_tx, consent_tx) {
                    Ok(()) => {
                        let _ = ready_tx.send(Ok(()));
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
            })
            .context("spawning viewer-indicator thread")?;

        // The pump writes the border HWND into `hwnd_for_thread` before
        // it enters its GetMessage loop; spin briefly (up to 500 ms) for
        // it rather than blocking on ready_rx (which only fires on exit).
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            if hwnd_cell.lock().unwrap().is_some() {
                break;
            }
            if let Ok(res) = ready_rx.try_recv() {
                return res.map(|_| Inner {
                    state,
                    hwnd: hwnd_cell,
                    tx,
                });
            }
            if std::time::Instant::now() >= deadline {
                return Err(anyhow!("viewer-indicator thread did not create window"));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        Ok(Inner {
            state,
            hwnd: hwnd_cell,
            tx,
        })
    }

    /// Construct a no-op inner — same public surface, drops show/hide.
    pub(super) fn disabled() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            hwnd: Arc::new(Mutex::new(None)),
            tx: std_mpsc::channel::<Cmd>().0,
        }
    }

    pub(super) fn show(&self, session_id: String, controller_name: String) {
        {
            let mut s = self.state.lock().unwrap();
            s.sessions.insert(session_id, controller_name);
        }
        self.post_redraw();
    }

    pub(super) fn hide(&self, session_id: String) {
        {
            let mut s = self.state.lock().unwrap();
            s.sessions.remove(&session_id);
            s.recording.remove(&session_id);
            // FR-99 — a session's end always takes its curtain down, whatever
            // its privacy channel managed to say first.
            s.privacy.remove(&session_id);
        }
        self.post_redraw();
    }

    /// FR-99 — turn `session_id`'s privacy curtain on or off. `true` only when
    /// the curtain is UP and verified out of capture. Off answers `false`.
    ///
    /// Blocks until the pump has answered (at most [`CURTAIN_ANSWER_WAIT`]):
    /// the window, its layering and its capture exclusion are the pump
    /// thread's to create, and the caller must not be told "up" before they
    /// exist. No answer in time counts as no curtain.
    pub(super) fn set_privacy(&self, session_id: &str, on: bool, controller_name: &str) -> bool {
        if !on {
            self.state.lock().unwrap().privacy.remove(session_id);
            self.post_redraw();
            return false;
        }
        {
            let mut s = self.state.lock().unwrap();
            // No curtain for a session the overlay does not carry: its end
            // would never reach `hide`, and nothing would take it down.
            if !s.sessions.contains_key(session_id) {
                return false;
            }
            // A fresh decision when no curtain is up or pending; one already
            // up covers this session too.
            if s.privacy.is_empty() {
                s.curtain = None;
            }
            s.privacy
                .insert(session_id.to_string(), controller_name.to_string());
        }
        if self.hwnd.lock().unwrap().is_none() {
            self.state.lock().unwrap().privacy.remove(session_id);
            return false;
        }
        self.post_redraw();
        let deadline = Instant::now() + CURTAIN_ANSWER_WAIT;
        loop {
            let answer = self.state.lock().unwrap().curtain;
            match answer {
                Some(true) => return true,
                Some(false) => break,
                None if Instant::now() >= deadline => break,
                None => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        // Refused, or no answer in time: take this session back out, so
        // nothing claims or keeps a curtain that may not be there.
        self.state.lock().unwrap().privacy.remove(session_id);
        self.post_redraw();
        false
    }

    /// FR-85 P3 — mark a session as recording (or not). `true` when the badge
    /// will SHOW it: the pump is up and the session is on it. A session the
    /// badge does not carry is never marked, so nothing claims a notice that
    /// is not on screen.
    pub(super) fn set_recording(&self, session_id: &str, recording: bool) -> bool {
        let shown = {
            let mut s = self.state.lock().unwrap();
            if !recording {
                s.recording.remove(session_id);
                false
            } else if s.sessions.contains_key(session_id) {
                s.recording.insert(session_id.to_string());
                true
            } else {
                false
            }
        };
        self.post_redraw();
        shown && self.hwnd.lock().unwrap().is_some()
    }

    /// FR-27 — raise the native consent panel. `false` when one is already up
    /// (see [`State::prompt`]) or the pump never came up.
    pub(super) fn prompt(&self, view: super::PromptView) -> bool {
        {
            let mut s = self.state.lock().unwrap();
            if s.prompt.is_some() {
                return false;
            }
            s.prompt = Some(view);
        }
        if self.hwnd.lock().unwrap().is_none() {
            // No pump → nothing will ever draw it. Undo, and let the caller
            // fall through to the companion instead of waiting on a panel
            // that does not exist.
            self.state.lock().unwrap().prompt = None;
            return false;
        }
        self.post_redraw();
        true
    }

    pub(super) fn dismiss(&self, session_hex: &str) {
        {
            let mut s = self.state.lock().unwrap();
            if s.prompt.as_ref().map(|p| p.session_hex.as_str()) != Some(session_hex) {
                return;
            }
            s.prompt = None;
        }
        self.post_redraw();
    }

    fn post_redraw(&self) {
        let hwnd_isize = match *self.hwnd.lock().unwrap() {
            Some(h) => h,
            None => return,
        };
        let hwnd = HWND(hwnd_isize as *mut c_void);
        unsafe {
            let _ = PostMessageW(hwnd, WM_APP_REDRAW, WPARAM(0), LPARAM(0));
        }
        let _ = self.tx.send(Cmd::Redraw);
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if Arc::strong_count(&self.state) == 1 {
            let _ = self.tx.send(Cmd::Shutdown);
            let hwnd_isize = *self.hwnd.lock().unwrap();
            if let Some(h) = hwnd_isize {
                let hwnd = HWND(h as *mut c_void);
                unsafe {
                    let _ = PostMessageW(hwnd, WM_APP_SHUTDOWN, WPARAM(0), LPARAM(0));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Win32 pump (runs on a dedicated thread)

fn run_pump(
    state: Arc<Mutex<State>>,
    hwnd_out: Arc<Mutex<Option<isize>>>,
    _rx: std_mpsc::Receiver<Cmd>,
    kill_tx: KillSender,
    consent_tx: super::ConsentSender,
) -> Result<()> {
    unsafe {
        let hinstance = GetModuleHandleW(None).context("GetModuleHandleW")?;

        // Border class (colorkey, click-through).
        let border_class = w!("RoomlerIndicatorWClass");
        let magenta_brush = CreateSolidBrush(COLORREF(COLORKEY_RGB));
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(border_wnd_proc),
            hInstance: hinstance.into(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: magenta_brush,
            lpszClassName: border_class,
            ..Default::default()
        };
        if RegisterClassExW(&wc) == 0 {
            let err = windows::Win32::Foundation::GetLastError();
            if err.0 != 1410 {
                let _ = DeleteObject(HGDIOBJ(magenta_brush.0));
                return Err(anyhow!("RegisterClassExW(border) failed: {:?}", err));
            }
        }

        // Badge class (opaque, interactive).
        let badge_class = w!("RoomlerIndicatorBadgeWClass");
        let badge_wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(badge_wnd_proc),
            hInstance: hinstance.into(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: HBRUSH::default(),
            lpszClassName: badge_class,
            ..Default::default()
        };
        if RegisterClassExW(&badge_wc) == 0 {
            let err = windows::Win32::Foundation::GetLastError();
            if err.0 != 1410 {
                let _ = DeleteObject(HGDIOBJ(magenta_brush.0));
                return Err(anyhow!("RegisterClassExW(badge) failed: {:?}", err));
            }
        }

        // FR-27 — consent-panel class. Opaque and INTERACTIVE (no
        // `WS_EX_TRANSPARENT`): unlike the border, this one exists to be
        // clicked.
        let consent_class = w!("RoomlerConsentWClass");
        let consent_wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(consent_wnd_proc),
            hInstance: hinstance.into(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: HBRUSH::default(),
            lpszClassName: consent_class,
            ..Default::default()
        };
        if RegisterClassExW(&consent_wc) == 0 {
            let err = windows::Win32::Foundation::GetLastError();
            if err.0 != 1410 {
                let _ = DeleteObject(HGDIOBJ(magenta_brush.0));
                return Err(anyhow!("RegisterClassExW(consent) failed: {:?}", err));
            }
        }

        // FR-99 — the privacy curtain's class. No background brush: WM_PAINT
        // fills every pixel, so erasing first would only flicker. A failure
        // here costs privacy mode alone (every "on" then answers `no_curtain`),
        // never the overlay that tells the person they are being watched.
        let curtain_wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(curtain_wnd_proc),
            hInstance: hinstance.into(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: HBRUSH::default(),
            lpszClassName: CURTAIN_CLASS,
            ..Default::default()
        };
        if RegisterClassExW(&curtain_wc) == 0 {
            let err = windows::Win32::Foundation::GetLastError();
            if err.0 != 1410 {
                tracing::warn!(
                    ?err,
                    "privacy: RegisterClassExW(curtain) failed; no curtain"
                );
            }
        }

        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);

        // Full-screen click-through border.
        let border_hwnd = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            border_class,
            w!("Roomler viewer indicator"),
            WS_POPUP,
            0,
            0,
            screen_w,
            screen_h,
            HWND::default(),
            HMENU::default(),
            hinstance,
            None,
        )
        .context("CreateWindowExW(border)")?;

        // Interactive badge, initially hidden, default top-centre.
        let badge_x = (screen_w - BADGE_W) / 2;
        let badge_y = BORDER_PX + 2;
        let badge_hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            badge_class,
            w!("Roomler viewer badge"),
            WS_POPUP,
            badge_x,
            badge_y,
            BADGE_W,
            BADGE_H,
            HWND::default(),
            HMENU::default(),
            hinstance,
            None,
        )
        .context("CreateWindowExW(badge)")?;

        // FR-27 — consent panel, hidden until a prompt arrives. Top-centre,
        // the place a notification is expected. `WS_EX_NOACTIVATE` so raising
        // it does not yank focus out of whatever the person is typing in —
        // clicks still land (the badge's Disconnect already works this way).
        let consent_hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            consent_class,
            w!("Roomler consent"),
            WS_POPUP,
            (screen_w - CONSENT_W) / 2,
            48,
            CONSENT_W,
            CONSENT_H,
            HWND::default(),
            HMENU::default(),
            hinstance,
            None,
        )
        .context("CreateWindowExW(consent)")?;

        // Colorkey transparency + capture exclusion on the border.
        let _ = SetLayeredWindowAttributes(border_hwnd, COLORREF(COLORKEY_RGB), 0, LWA_COLORKEY);
        let _ = SetWindowDisplayAffinity(border_hwnd, WDA_EXCLUDEFROMCAPTURE);
        // Capture exclusion on the badge too — its Disconnect button must
        // never appear in the RTP stream, and the viewer's injected input
        // can't intentionally target what it can't see.
        let _ = SetWindowDisplayAffinity(badge_hwnd, WDA_EXCLUDEFROMCAPTURE);
        // FR-27 — and on the consent panel, which matters MORE than the badge:
        // the person asking for access must not be able to see the Approve
        // button, let alone (with input already granted on another session)
        // aim at it.
        let _ = SetWindowDisplayAffinity(consent_hwnd, WDA_EXCLUDEFROMCAPTURE);

        // Build the shared pump state and hand a raw pointer to ALL THREE procs.
        let pump = Box::new(PumpState {
            shared: state,
            kill_tx,
            badge_hwnd,
            badge_pos: (badge_x, badge_y),
            badge_visible: false,
            dragging: false,
            dwell_since: None,
            hide_since: None,
            consent_hwnd,
            consent_tx,
            consent_visible: false,
            consent_secs_shown: u64::MAX,
            hinstance,
            curtain_hwnd: HWND::default(),
            curtain_rect: RECT::default(),
            curtain_ticks: 0,
        });
        let pump_ptr_val = Box::into_raw(pump) as isize;
        SetWindowLongPtrW(border_hwnd, GWLP_USERDATA, pump_ptr_val);
        SetWindowLongPtrW(badge_hwnd, GWLP_USERDATA, pump_ptr_val);
        SetWindowLongPtrW(consent_hwnd, GWLP_USERDATA, pump_ptr_val);

        *hwnd_out.lock().unwrap() = Some(border_hwnd.0 as isize);

        let _ = ShowWindow(border_hwnd, SW_HIDE);

        // Classic message pump — dispatches to both window procs.
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Clean up.
        let _ = KillTimer(border_hwnd, TIMER_ID);
        // FR-99 — a curtain still up goes with the pump.
        if pump_ptr_val != 0 {
            destroy_curtain(pump_ptr_val as *mut PumpState);
        }
        let _ = DestroyWindow(consent_hwnd);
        let _ = DestroyWindow(badge_hwnd);
        let _ = DestroyWindow(border_hwnd);
        let _ = DeleteObject(HGDIOBJ(magenta_brush.0));
        if pump_ptr_val != 0 {
            drop(Box::from_raw(pump_ptr_val as *mut PumpState));
        }
        *hwnd_out.lock().unwrap() = None;
        Ok(())
    }
}

/// Read the pump-state pointer from a window's `GWLP_USERDATA`.
unsafe fn pump_ptr(hwnd: HWND) -> *mut PumpState {
    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut PumpState }
}

/// True while ≥1 session is active.
unsafe fn has_session(p: *mut PumpState) -> bool {
    unsafe { !(*p).shared.lock().unwrap().sessions.is_empty() }
}

/// FR-85 P3 — true while ≥1 session is recording the screen.
unsafe fn is_recording(p: *mut PumpState) -> bool {
    unsafe { !(*p).shared.lock().unwrap().recording.is_empty() }
}

unsafe fn show_badge(p: *mut PumpState) {
    unsafe {
        let hwnd = (*p).badge_hwnd;
        let (x, y) = (*p).badge_pos;
        let _ = SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            x,
            y,
            BADGE_W,
            BADGE_H,
            SWP_NOACTIVATE | SWP_SHOWWINDOW,
        );
        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        let _ = InvalidateRect(hwnd, None, true);
        (*p).badge_visible = true;
        (*p).hide_since = None;
    }
}

unsafe fn hide_badge(p: *mut PumpState) {
    unsafe {
        let hwnd = (*p).badge_hwnd;
        let _ = ShowWindow(hwnd, SW_HIDE);
        (*p).badge_visible = false;
        (*p).hide_since = None;
        (*p).dwell_since = None;
    }
}

/// Fire the current session's teardown through the kill channel.
unsafe fn kill_current_session(p: *mut PumpState) {
    unsafe {
        let hex = {
            let guard = (*p).shared.lock().unwrap();
            guard.sessions.keys().next().cloned()
        };
        if let Some(hex) = hex
            && let Ok(oid) = ObjectId::parse_str(&hex)
        {
            let _ = (*p).kill_tx.try_send(oid);
        }
        hide_badge(p);
    }
}

// ---------------------------------------------------------------------------
// FR-27 — consent panel.

/// Bring the panel in line with `State.prompt`: shown while a question is
/// outstanding, hidden otherwise. Idempotent, so both the redraw message and
/// the timer can call it.
unsafe fn sync_consent(p: *mut PumpState) {
    unsafe {
        let want = (*p).shared.lock().unwrap().prompt.is_some();
        let hwnd = (*p).consent_hwnd;
        if want && !(*p).consent_visible {
            let _ = SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
            );
            let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            let _ = InvalidateRect(hwnd, None, true);
            (*p).consent_visible = true;
            (*p).consent_secs_shown = u64::MAX;
        } else if !want && (*p).consent_visible {
            let _ = ShowWindow(hwnd, SW_HIDE);
            (*p).consent_visible = false;
        }
    }
}

/// Repaint only when the displayed second actually changes. The pump ticks
/// every 120 ms; redrawing the same digit eight times a second is flicker in
/// exchange for nothing.
unsafe fn tick_consent_countdown(p: *mut PumpState) {
    unsafe {
        if !(*p).consent_visible {
            return;
        }
        let secs = {
            let s = (*p).shared.lock().unwrap();
            match &s.prompt {
                Some(v) => v
                    .expires_at
                    .saturating_duration_since(Instant::now())
                    .as_secs(),
                None => return,
            }
        };
        if secs != (*p).consent_secs_shown {
            (*p).consent_secs_shown = secs;
            let _ = InvalidateRect((*p).consent_hwnd, None, true);
        }
    }
}

unsafe extern "system" fn consent_wnd_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        match msg {
            WM_PAINT => {
                paint_consent(hwnd);
                LRESULT(0)
            }
            // Decide on button-UP, so a press-then-drag-away cancels — the
            // same rule the badge's Disconnect uses, and it matters more here.
            WM_LBUTTONUP => {
                let p = pump_ptr(hwnd);
                if p.is_null() {
                    return LRESULT(0);
                }
                let x = (lparam.0 & 0xFFFF) as i16 as i32;
                let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                let allow = if pt_in(&consent_approve_rect(), x, y) {
                    true
                } else if pt_in(&consent_deny_rect(), x, y) {
                    false
                } else {
                    return LRESULT(0);
                };
                // Take the session id and CLEAR the prompt in one borrow, so a
                // double-click cannot answer twice.
                let session = {
                    let mut s = (*p).shared.lock().unwrap();
                    match s.prompt.take() {
                        Some(v) => v.session_hex,
                        None => return LRESULT(0),
                    }
                };
                // The panel does not resolve consent — it reports. The
                // signalling loop feeds this to the broker, which applies the
                // live-prompt gate every other answer path goes through.
                let _ = (*p).consent_tx.try_send((session, allow));
                sync_consent(p);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, _wparam, lparam),
        }
    }
}

unsafe fn paint_consent(hwnd: HWND) {
    unsafe {
        let mut ps = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut ps);
        if hdc.is_invalid() {
            return;
        }
        let view = {
            let p = pump_ptr(hwnd);
            if p.is_null() {
                None
            } else {
                (*p).shared.lock().unwrap().prompt.clone()
            }
        };
        let Some(view) = view else {
            let _ = EndPaint(hwnd, &ps);
            return;
        };

        let full = RECT {
            left: 0,
            top: 0,
            right: CONSENT_W,
            bottom: CONSENT_H,
        };
        let bg = CreateSolidBrush(COLORREF(BADGE_BG_RGB));
        FillRect(hdc, &full, bg);
        let _ = DeleteObject(HGDIOBJ(bg.0));
        let red = CreateSolidBrush(COLORREF(BORDER_RGB));
        FrameRect(hdc, &full, red);

        let line = |top: i32, h: i32| RECT {
            left: CONSENT_PAD,
            top,
            right: CONSENT_W - CONSENT_PAD,
            bottom: top + h,
        };
        let mut y = CONSENT_PAD;
        draw_text(
            hdc,
            &view.title,
            line(y, 22),
            -17,
            FW_BOLD.0 as i32,
            TEXT_RGB,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        y += 26;
        draw_text(
            hdc,
            &view.lead,
            line(y, 20),
            -14,
            FW_NORMAL.0 as i32,
            TEXT_RGB,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        y += 22;
        // Multi-org: WHO is asking is only half the question when the same
        // person can be a colleague in one org and a contractor in another.
        if !view.org.is_empty() {
            draw_text(
                hdc,
                &format!("On behalf of {}", view.org),
                line(y, 18),
                -12,
                FW_NORMAL.0 as i32,
                LABEL_RGB,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            y += 20;
        }
        // The command an `exec` prompt would run — the line the decision
        // actually rests on. Already redacted by the caller.
        if !view.detail.is_empty() {
            draw_text(
                hdc,
                &view.detail,
                line(y, 34),
                -12,
                FW_NORMAL.0 as i32,
                TEXT_RGB,
                DT_LEFT | DT_END_ELLIPSIS,
            );
            y += 36;
        }
        if !view.permissions.is_empty() {
            draw_text(
                hdc,
                &format!("Permissions: {}", view.permissions),
                line(y, 18),
                -12,
                FW_NORMAL.0 as i32,
                LABEL_RGB,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
        }

        // Countdown, bottom-left, level with the buttons. This prompt expires;
        // one that silently stops mattering is how "consent seems not to work"
        // looks from the other end.
        let secs = view
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_secs();
        let btns = consent_approve_rect();
        draw_text(
            hdc,
            &format!("Expires in {}", super::format_countdown(secs)),
            RECT {
                left: CONSENT_PAD,
                top: btns.top,
                right: consent_deny_rect().left - 8,
                bottom: btns.bottom,
            },
            -12,
            FW_NORMAL.0 as i32,
            LABEL_RGB,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );

        let deny = consent_deny_rect();
        let deny_brush = CreateSolidBrush(COLORREF(BORDER_RGB));
        FillRect(hdc, &deny, deny_brush);
        let _ = DeleteObject(HGDIOBJ(deny_brush.0));
        draw_text(
            hdc,
            "Deny",
            deny,
            -14,
            FW_BOLD.0 as i32,
            TEXT_RGB,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );

        let approve_brush = CreateSolidBrush(COLORREF(APPROVE_RGB));
        FillRect(hdc, &btns, approve_brush);
        let _ = DeleteObject(HGDIOBJ(approve_brush.0));
        draw_text(
            hdc,
            "Approve",
            btns,
            -14,
            FW_BOLD.0 as i32,
            TEXT_RGB,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );

        let _ = DeleteObject(HGDIOBJ(red.0));
        let _ = EndPaint(hwnd, &ps);
    }
}

// ---------------------------------------------------------------------------
// FR-99 — the privacy curtain.

const CURTAIN_CLASS: windows::core::PCWSTR = w!("RoomlerPrivacyCurtainWClass");

/// The whole virtual desktop: every monitor, in physical pixels.
unsafe fn virtual_screen() -> RECT {
    unsafe {
        let x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        RECT {
            left: x,
            top: y,
            right: x + GetSystemMetrics(SM_CXVIRTUALSCREEN),
            bottom: y + GetSystemMetrics(SM_CYVIRTUALSCREEN),
        }
    }
}

/// Create the curtain over the virtual desktop. Its capture exclusion is set
/// BEFORE it is shown, so no captured frame ever holds it, and read back
/// after: on a build that does not know `WDA_EXCLUDEFROMCAPTURE`, or when the
/// call fails, the capture would see the curtain and the controller would
/// lose the desktop. `Err` destroys whatever was made.
unsafe fn create_curtain(p: *mut PumpState) -> Result<HWND> {
    unsafe {
        let r = virtual_screen();
        let hwnd = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            CURTAIN_CLASS,
            w!("Roomler privacy curtain"),
            WS_POPUP,
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            HWND::default(),
            HMENU::default(),
            (*p).hinstance,
            None,
        )
        .context("CreateWindowExW(curtain)")?;
        // A layered window stays invisible until it is given attributes.
        if let Err(e) = SetLayeredWindowAttributes(hwnd, COLORREF(0), 255, LWA_ALPHA) {
            let _ = DestroyWindow(hwnd);
            return Err(anyhow!("SetLayeredWindowAttributes(curtain): {e}"));
        }
        let set = SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
        let mut got = 0u32;
        let read = GetWindowDisplayAffinity(hwnd, &mut got);
        if set.is_err() || read.is_err() || got != WDA_EXCLUDEFROMCAPTURE.0 {
            let _ = DestroyWindow(hwnd);
            return Err(anyhow!(
                "the curtain's capture exclusion did not hold (set: {set:?}, read: {read:?}, \
                 affinity: {got:#x})"
            ));
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, p as isize);
        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        Ok(hwnd)
    }
}

/// Take the curtain down, if it is up, and clear the pump's answer.
unsafe fn destroy_curtain(p: *mut PumpState) {
    unsafe {
        if !(*p).curtain_hwnd.is_invalid() {
            let _ = DestroyWindow((*p).curtain_hwnd);
            (*p).curtain_hwnd = HWND::default();
            tracing::info!("privacy: curtain down");
        }
        (*p).shared.lock().unwrap().curtain = None;
    }
}

/// Refit the curtain when the virtual desktop changed (a monitor plugged in,
/// a resolution change).
unsafe fn fit_curtain(p: *mut PumpState) {
    unsafe {
        let r = virtual_screen();
        let c = (*p).curtain_rect;
        if (r.left, r.top, r.right, r.bottom) != (c.left, c.top, c.right, c.bottom) {
            let _ = SetWindowPos(
                (*p).curtain_hwnd,
                HWND_TOPMOST,
                r.left,
                r.top,
                r.right - r.left,
                r.bottom - r.top,
                SWP_NOACTIVATE,
            );
            (*p).curtain_rect = r;
            let _ = InvalidateRect((*p).curtain_hwnd, None, true);
        }
    }
}

/// The curtain on top of every other topmost window, then the person's own
/// controls back above it: the badge's Disconnect is their way out while the
/// curtain is up, and a consent question must never sit behind it.
unsafe fn raise_curtain_chain(p: *mut PumpState, border: HWND) {
    unsafe {
        let flags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;
        let _ = SetWindowPos((*p).curtain_hwnd, HWND_TOPMOST, 0, 0, 0, 0, flags);
        let _ = SetWindowPos(border, HWND_TOPMOST, 0, 0, 0, 0, flags);
        if (*p).badge_visible {
            let _ = SetWindowPos((*p).badge_hwnd, HWND_TOPMOST, 0, 0, 0, 0, flags);
        }
        if (*p).consent_visible {
            let _ = SetWindowPos((*p).consent_hwnd, HWND_TOPMOST, 0, 0, 0, 0, flags);
        }
    }
}

/// Bring the curtain in line with `State.privacy`: up while any session has
/// privacy on, down otherwise, and the answer recorded for `set_privacy`.
/// Idempotent; the redraw message and the timer both call it. `repaint` when
/// the names on it may have changed.
unsafe fn sync_curtain(p: *mut PumpState, border: HWND, repaint: bool) {
    unsafe {
        let (want, answer) = {
            let s = (*p).shared.lock().unwrap();
            (!s.privacy.is_empty(), s.curtain)
        };
        let up = !(*p).curtain_hwnd.is_invalid();
        if want && !up {
            // Refused already: the requester takes its session back out.
            if answer == Some(false) {
                return;
            }
            let ok = match create_curtain(p) {
                Ok(h) => {
                    (*p).curtain_hwnd = h;
                    (*p).curtain_rect = virtual_screen();
                    (*p).curtain_ticks = 0;
                    raise_curtain_chain(p, border);
                    tracing::info!("privacy: curtain up, out of capture");
                    true
                }
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "privacy: no curtain");
                    false
                }
            };
            (*p).shared.lock().unwrap().curtain = Some(ok);
        } else if !want && up {
            destroy_curtain(p);
        } else if want && up {
            (*p).curtain_ticks = (*p).curtain_ticks.wrapping_add(1);
            if (*p).curtain_ticks.is_multiple_of(CURTAIN_RAISE_EVERY) {
                fit_curtain(p);
                raise_curtain_chain(p, border);
            }
            if repaint {
                let _ = InvalidateRect((*p).curtain_hwnd, None, true);
            }
        }
    }
}

unsafe extern "system" fn curtain_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        match msg {
            WM_PAINT => {
                paint_curtain(hwnd);
                LRESULT(0)
            }
            // WM_PAINT fills every pixel; erasing first would only flicker.
            WM_ERASEBKGND => LRESULT(1),
            WM_DISPLAYCHANGE => {
                let p = pump_ptr(hwnd);
                if !p.is_null() {
                    fit_curtain(p);
                }
                LRESULT(0)
            }
            // ⚠️ No WM_DESTROY arm: the border's posts the pump's quit, and
            // the curtain is destroyed every time privacy mode goes off.
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Collects each monitor's rectangle, in virtual-desktop coordinates.
unsafe extern "system" fn collect_monitor(
    _monitor: HMONITOR,
    _hdc: HDC,
    rect: *mut RECT,
    data: LPARAM,
) -> BOOL {
    unsafe {
        let monitors = &mut *(data.0 as *mut Vec<RECT>);
        monitors.push(*rect);
        TRUE
    }
}

/// The curtain: slate everywhere, and the notice centred on every monitor.
/// Monitors are enumerated WITHOUT the paint DC, whose clip would shrink each
/// rectangle to the update region and move the text on a partial repaint.
unsafe fn paint_curtain(hwnd: HWND) {
    unsafe {
        let mut ps = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut ps);
        if hdc.is_invalid() {
            return;
        }
        let mut client = RECT::default();
        let _ = GetClientRect(hwnd, &mut client);
        let bg = CreateSolidBrush(COLORREF(CURTAIN_RGB));
        FillRect(hdc, &client, bg);
        let _ = DeleteObject(HGDIOBJ(bg.0));

        let p = pump_ptr(hwnd);
        let by = if p.is_null() {
            String::new()
        } else {
            let s = (*p).shared.lock().unwrap();
            let mut names: Vec<&str> = s.privacy.values().map(String::as_str).collect();
            names.sort_unstable();
            names.dedup();
            names.join(", ")
        };

        let mut monitors: Vec<RECT> = Vec::new();
        let _ = EnumDisplayMonitors(
            HDC::default(),
            None,
            Some(collect_monitor),
            LPARAM(&mut monitors as *mut Vec<RECT> as isize),
        );
        let mut origin = RECT::default();
        let _ = GetWindowRect(hwnd, &mut origin);
        for m in monitors {
            let r = RECT {
                left: m.left - origin.left,
                top: m.top - origin.top,
                right: m.right - origin.left,
                bottom: m.bottom - origin.top,
            };
            paint_notice(hdc, r, &by);
        }
        let _ = EndPaint(hwnd, &ps);
    }
}

/// One monitor's notice, centred in `r` (window coordinates).
unsafe fn paint_notice(hdc: HDC, r: RECT, by: &str) {
    unsafe {
        let mid = (r.top + r.bottom) / 2;
        let row = |top: i32, height: i32| RECT {
            left: r.left + 40,
            top,
            right: r.right - 40,
            bottom: top + height,
        };
        let centred = DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS;
        draw_text(
            hdc,
            "This computer is being used remotely",
            row(mid - 96, 48),
            -36,
            FW_BOLD.0 as i32,
            TEXT_RGB,
            centred,
        );
        if !by.is_empty() {
            draw_text(
                hdc,
                &format!("by {by}"),
                row(mid - 42, 34),
                -24,
                FW_NORMAL.0 as i32,
                TEXT_RGB,
                centred,
            );
        }
        draw_text(
            hdc,
            "Privacy mode is on: the screen is hidden while they work.",
            row(mid + 10, 28),
            -18,
            FW_NORMAL.0 as i32,
            LABEL_RGB,
            centred,
        );
        draw_text(
            hdc,
            "To end the session, move the pointer to the top edge of the screen and choose \
             Disconnect.",
            row(mid + 42, 28),
            -18,
            FW_NORMAL.0 as i32,
            LABEL_RGB,
            centred,
        );
    }
}

// ---------------------------------------------------------------------------
// Border window proc: paints the thin frame + drives the reveal timer.

unsafe extern "system" fn border_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        match msg {
            WM_APP_REDRAW => {
                let p = pump_ptr(hwnd);
                if p.is_null() {
                    return LRESULT(0);
                }
                // FR-27 — the consent panel is driven by `State.prompt`, NOT
                // by session presence: it is what stands between a request and
                // a session, so gating it on the latter would hide it exactly
                // when it is needed.
                sync_consent(p);
                // FR-99 — the curtain follows `State.privacy`, and the names on
                // it may have changed.
                sync_curtain(p, hwnd, true);
                if has_session(p) {
                    let _ = SetWindowPos(
                        hwnd,
                        HWND_TOPMOST,
                        0,
                        0,
                        0,
                        0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
                    );
                    let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                    let _ = InvalidateRect(hwnd, None, true);
                    let _ = SetTimer(hwnd, TIMER_ID, TIMER_MS, None);
                    if (*p).badge_visible {
                        // Name may have changed; refresh the revealed badge.
                        let _ = InvalidateRect((*p).badge_hwnd, None, true);
                    }
                } else {
                    let _ = ShowWindow(hwnd, SW_HIDE);
                    let _ = KillTimer(hwnd, TIMER_ID);
                    hide_badge(p);
                }
                LRESULT(0)
            }
            WM_TIMER if wparam.0 == TIMER_ID => {
                let p = pump_ptr(hwnd);
                if p.is_null() {
                    return LRESULT(0);
                }
                // FR-27 — keep the panel's countdown honest. Cheap: it
                // repaints only when the whole second changes.
                tick_consent_countdown(p);
                // FR-99 — before the early returns below: a curtain is kept on
                // top and fitted to the desktop while anything records too.
                sync_curtain(p, hwnd, false);
                if !has_session(p) {
                    if (*p).badge_visible {
                        hide_badge(p);
                    }
                    return LRESULT(0);
                }
                // FR-85 P3 — while anything records, the badge stays OPEN:
                // no hover-to-reveal, no auto-hide.
                if is_recording(p) {
                    if !(*p).badge_visible {
                        show_badge(p);
                    }
                    return LRESULT(0);
                }
                // Decide inside a short borrow, then run window ops after
                // it is dropped (they can re-enter the pump).
                let (do_show, do_hide) = {
                    let mut pt = POINT::default();
                    let _ = GetCursorPos(&mut pt);
                    let in_top = pt.y <= TOP_ZONE_PX;
                    let visible = (*p).badge_visible;
                    let (bx, by) = (*p).badge_pos;
                    let over_badge = visible
                        && pt.x >= bx
                        && pt.x < bx + BADGE_W
                        && pt.y >= by
                        && pt.y < by + BADGE_H;
                    let dragging = (*p).dragging;
                    let now = Instant::now();

                    let mut do_show = false;
                    if in_top {
                        match (*p).dwell_since {
                            None => (*p).dwell_since = Some(now),
                            Some(t) => {
                                if !visible && now.duration_since(t).as_millis() >= REVEAL_DWELL_MS
                                {
                                    do_show = true;
                                }
                            }
                        }
                    } else {
                        (*p).dwell_since = None;
                    }

                    let mut do_hide = false;
                    if visible && !in_top && !over_badge && !dragging {
                        match (*p).hide_since {
                            None => (*p).hide_since = Some(now),
                            Some(t) => {
                                if now.duration_since(t).as_millis() >= HIDE_DELAY_MS {
                                    do_hide = true;
                                }
                            }
                        }
                    } else {
                        (*p).hide_since = None;
                    }
                    (do_show, do_hide)
                };
                if do_show {
                    show_badge(p);
                }
                if do_hide {
                    hide_badge(p);
                }
                LRESULT(0)
            }
            WM_APP_SHUTDOWN => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            WM_PAINT => {
                paint_border(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

unsafe fn paint_border(hwnd: HWND) {
    unsafe {
        let mut ps = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut ps);
        if hdc.is_invalid() {
            return;
        }
        let magenta = CreateSolidBrush(COLORREF(COLORKEY_RGB));
        FillRect(hdc, &ps.rcPaint, magenta);
        let _ = DeleteObject(HGDIOBJ(magenta.0));

        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);
        let red = CreateSolidBrush(COLORREF(BORDER_RGB));
        let bars = [
            RECT {
                left: 0,
                top: 0,
                right: screen_w,
                bottom: BORDER_PX,
            },
            RECT {
                left: 0,
                top: screen_h - BORDER_PX,
                right: screen_w,
                bottom: screen_h,
            },
            RECT {
                left: 0,
                top: 0,
                right: BORDER_PX,
                bottom: screen_h,
            },
            RECT {
                left: screen_w - BORDER_PX,
                top: 0,
                right: screen_w,
                bottom: screen_h,
            },
        ];
        for b in &bars {
            FillRect(hdc, b, red);
        }
        let _ = DeleteObject(HGDIOBJ(red.0));
        let _ = EndPaint(hwnd, &ps);
    }
}

// ---------------------------------------------------------------------------
// Badge window proc: paints the initials + name + Disconnect, handles
// dragging and the Disconnect click.

unsafe extern "system" fn badge_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        match msg {
            WM_PAINT => {
                paint_badge(hwnd);
                LRESULT(0)
            }
            WM_LBUTTONDOWN => {
                let p = pump_ptr(hwnd);
                if p.is_null() {
                    return LRESULT(0);
                }
                let x = (lparam.0 & 0xFFFF) as i16 as i32;
                let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                let on_button = pt_in(&button_rect(), x, y);
                if on_button {
                    // Act on button-up so a press-then-drag-away cancels.
                    return LRESULT(0);
                }
                // Start a drag. Mark it, THEN SendMessage (which runs a
                // modal move loop that re-enters the pump) — no borrow held.
                (*p).dragging = true;
                let _ = ReleaseCapture();
                SendMessageW(
                    hwnd,
                    WM_NCLBUTTONDOWN,
                    WPARAM(HTCAPTION as usize),
                    LPARAM(0),
                );
                LRESULT(0)
            }
            WM_LBUTTONUP => {
                let p = pump_ptr(hwnd);
                if p.is_null() {
                    return LRESULT(0);
                }
                let x = (lparam.0 & 0xFFFF) as i16 as i32;
                let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                if pt_in(&button_rect(), x, y) {
                    kill_current_session(p);
                }
                LRESULT(0)
            }
            WM_EXITSIZEMOVE => {
                // Drag finished — remember the new position.
                let p = pump_ptr(hwnd);
                if !p.is_null() {
                    (*p).dragging = false;
                    let mut r = RECT::default();
                    if GetWindowRect(hwnd, &mut r).is_ok() {
                        (*p).badge_pos = (r.left, r.top);
                    }
                }
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

unsafe fn paint_badge(hwnd: HWND) {
    unsafe {
        let mut ps = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut ps);
        if hdc.is_invalid() {
            return;
        }

        let full = RECT {
            left: 0,
            top: 0,
            right: BADGE_W,
            bottom: BADGE_H,
        };

        // Background + 1px red frame.
        let bg = CreateSolidBrush(COLORREF(BADGE_BG_RGB));
        FillRect(hdc, &full, bg);
        let _ = DeleteObject(HGDIOBJ(bg.0));
        let red = CreateSolidBrush(COLORREF(BORDER_RGB));
        FrameRect(hdc, &full, red);

        // Initials chip: filled red circle (no outline).
        let old_brush = SelectObject(hdc, HGDIOBJ(red.0));
        let old_pen = SelectObject(hdc, GetStockObject(NULL_PEN));
        let chip_top = (BADGE_H - CHIP_DIA) / 2;
        let _ = Ellipse(
            hdc,
            CHIP_MARGIN,
            chip_top,
            CHIP_MARGIN + CHIP_DIA,
            chip_top + CHIP_DIA,
        );
        let _ = SelectObject(hdc, old_pen);
        let _ = SelectObject(hdc, old_brush);

        // Read the current controller name (first/only session), and whether
        // anything is recording (FR-85 P3).
        let (name, recording) = {
            let p = pump_ptr(hwnd);
            if p.is_null() {
                (String::new(), false)
            } else {
                let s = (*p).shared.lock().unwrap();
                (
                    s.sessions.values().next().cloned().unwrap_or_default(),
                    !s.recording.is_empty(),
                )
            }
        };
        let inits = initials_of(&name);

        let chip_rect = RECT {
            left: CHIP_MARGIN,
            top: chip_top,
            right: CHIP_MARGIN + CHIP_DIA,
            bottom: chip_top + CHIP_DIA,
        };
        draw_text(
            hdc,
            &inits,
            chip_rect,
            -14,
            FW_BOLD.0 as i32,
            TEXT_RGB,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );

        // Text column between the chip and the button.
        let text_left = CHIP_MARGIN + CHIP_DIA + 8;
        let text_right = button_rect().left - 8;
        draw_text(
            hdc,
            if recording {
                "\u{25CF} Recording, viewed by"
            } else {
                "Being viewed by"
            },
            RECT {
                left: text_left,
                top: 6,
                right: text_right,
                bottom: 24,
            },
            -11,
            FW_NORMAL.0 as i32,
            LABEL_RGB,
            DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
        );
        draw_text(
            hdc,
            &name,
            RECT {
                left: text_left,
                top: 23,
                right: text_right,
                bottom: 43,
            },
            -15,
            FW_BOLD.0 as i32,
            TEXT_RGB,
            DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
        );

        // Disconnect button.
        let btn = button_rect();
        FillRect(hdc, &btn, red);
        draw_text(
            hdc,
            "Disconnect",
            btn,
            -13,
            FW_BOLD.0 as i32,
            TEXT_RGB,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );

        let _ = DeleteObject(HGDIOBJ(red.0));
        let _ = EndPaint(hwnd, &ps);
    }
}

/// Draw a single run of text with a freshly-created Segoe UI font.
unsafe fn draw_text(
    hdc: HDC,
    text: &str,
    rect: RECT,
    height: i32,
    weight: i32,
    color: u32,
    format: windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT,
) {
    unsafe {
        let font = CreateFontW(
            height,
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            0,
            OUT_DEFAULT_PRECIS.0 as u32,
            0,
            0,
            0,
            w!("Segoe UI"),
        );
        let prev = SelectObject(hdc, HGDIOBJ(font.0));
        let _ = SetBkMode(hdc, TRANSPARENT);
        let _ = SetTextColor(hdc, COLORREF(color));
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        let mut r = rect;
        if !wide.is_empty() {
            DrawTextW(hdc, &mut wide, &mut r, format);
        }
        let _ = SelectObject(hdc, prev);
        let _ = DeleteObject(HGDIOBJ(font.0));
    }
}
