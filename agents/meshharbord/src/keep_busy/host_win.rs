// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 — the Windows host for the keep-busy engine.
//!
//! Cursor reads and moves go through the input arbiter (the one OS
//! injector, on its own thread, desktop-rebound under SystemContext). The
//! idle clock, the lock state and the monitor geometry are read here, on the
//! engine's own thread, so none of it touches the input path.
//!
//! The idle clock is `GetLastInputInfo` — the session's last-input tick,
//! the same signal Teams, the screensaver and the idle lock read. No hook,
//! no raw input, no key polling: EDR reads each as a keylogger.

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::POINT;
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromPoint,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SPI_GETACTIVEWINDOWTRACKING, SystemParametersInfoW,
};

use super::arbiter_io;
use super::engine::{Host, HostError, IdleMarker, SessionState};
use super::patterns::{self, Rect};
use crate::lock_state::LockState;

/// How long `settle` polls for our own move to land in `GetLastInputInfo`.
/// `SendInput` updates it asynchronously; in practice within a millisecond
/// or two. A move that never shows up is not landing (UIPI, another desktop).
const SETTLE_CAP: Duration = Duration::from_millis(50);
const SETTLE_POLL: Duration = Duration::from_millis(2);

pub struct WinHost;

impl WinHost {
    pub fn new() -> WinHost {
        WinHost
    }
}

/// The session's last-input tick (ms since boot, wrapping u32).
fn last_input_tick() -> Option<u32> {
    let mut lii = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: a stack LASTINPUTINFO with cbSize set, as the API requires.
    (unsafe { GetLastInputInfo(&mut lii) } != 0).then_some(lii.dwTime)
}

impl Host for WinHost {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_ms(&self) -> u64 {
        super::wall_ms()
    }

    fn session(&mut self) -> SessionState {
        // The worker exists only while a console session does, so the only
        // question is the lock screen / secure desktop. Under SystemContext
        // the injector COULD drive Winlogon — keep-busy never does.
        match crate::lock_state::probe_lock_state() {
            LockState::Locked => SessionState::Locked,
            _ => SessionState::Present,
        }
    }

    fn idle_marker(&mut self) -> Option<IdleMarker> {
        last_input_tick().map(|t| IdleMarker::exact(t as u64))
    }

    fn cursor(&mut self) -> Result<(i32, i32), HostError> {
        arbiter_io::cursor()
    }

    fn move_to(&mut self, p: (i32, i32)) -> Result<(), HostError> {
        arbiter_io::move_to(p)
    }

    fn settle(&mut self, before: IdleMarker) -> Option<IdleMarker> {
        let deadline = Instant::now() + SETTLE_CAP;
        loop {
            if let Some(t) = last_input_tick()
                && t as u64 != before.value
            {
                return Some(IdleMarker::exact(t as u64));
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(SETTLE_POLL);
        }
    }

    fn buttons_held(&mut self) -> Result<bool, HostError> {
        arbiter_io::buttons()
    }

    fn safe_box_at(&mut self, p: (i32, i32)) -> Option<Rect> {
        // SAFETY: MonitorFromPoint takes a POINT by value and returns a
        // non-owning handle; NEAREST never returns null while any monitor
        // is attached.
        let hmon = unsafe { MonitorFromPoint(POINT { x: p.0, y: p.1 }, MONITOR_DEFAULTTONEAREST) };
        if hmon.is_null() {
            return None;
        }
        let mut mi: MONITORINFO = unsafe { std::mem::zeroed() };
        mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        // SAFETY: a valid HMONITOR and a MONITORINFO with cbSize set.
        if unsafe { GetMonitorInfoW(hmon, &mut mi) } == 0 {
            return None;
        }
        let r = |rc: windows_sys::Win32::Foundation::RECT| {
            Rect::new(
                rc.left as f64,
                rc.top as f64,
                rc.right as f64,
                rc.bottom as f64,
            )
        };
        patterns::safe_box(r(mi.rcMonitor), r(mi.rcWork))
    }

    fn remote_epoch(&self) -> u64 {
        super::remote_input_epoch()
    }

    fn wait(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Host settings that change what keep-busy should say, not what it does.
/// `focus_follows_mouse`: "activate a window by hovering over it" is on, so
/// a moving pointer moves the keyboard focus too — the viewer suggests
/// `subtle`.
pub fn warnings() -> Vec<&'static str> {
    let mut on: i32 = 0;
    // SAFETY: SPI_GETACTIVEWINDOWTRACKING writes a BOOL into pvParam.
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETACTIVEWINDOWTRACKING,
            0,
            (&mut on as *mut i32).cast(),
            0,
        )
    };
    if ok != 0 && on != 0 {
        vec!["focus_follows_mouse"]
    } else {
        Vec::new()
    }
}
