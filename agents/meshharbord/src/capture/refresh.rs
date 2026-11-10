// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-119 P2b-3 — the captured display's refresh rate.
//!
//! A screen cannot produce frames faster than it refreshes. So the rate grant
//! refuses an ask above it (`refresh`), a rate class is keyed on it, and the
//! viewer's picker greys the rates above it. Each backend reads it once, at its
//! open, for the display it captures. A backend that cannot read it answers
//! `None`, which decides nothing: a trial then finds out.
//!
//! | OS | Read from |
//! |---|---|
//! | Windows | `EnumDisplaySettingsW(ENUM_CURRENT_SETTINGS)` → `dmDisplayFrequency`, for the captured monitor's device |
//! | macOS | `CGDisplayModeGetRefreshRate` of the main display's current mode |
//! | Linux, X11 | the primary output's RandR mode: the dot clock over `htotal × vtotal` |
//! | Linux, DRM | the CRTC mode's `vrefresh` |

/// A reading as a rate. Windows reports 0 or 1 for "the hardware's default",
/// and macOS reports 0 for a panel it cannot name a rate for (some built-in
/// ones): neither is a rate, and both decide nothing.
pub fn hz(raw: f64) -> Option<u16> {
    let r = raw.round();
    (r >= 2.0 && r <= f64::from(u16::MAX)).then_some(r as u16)
}

/// The rate of a display device (`\\.\DISPLAY1`), or of the primary display
/// when `device` is null.
#[cfg(target_os = "windows")]
fn of_device(device: *const u16) -> Option<u16> {
    use windows_sys::Win32::Graphics::Gdi::{
        DEVMODEW, ENUM_CURRENT_SETTINGS, EnumDisplaySettingsW,
    };
    let mut dm: DEVMODEW = unsafe { std::mem::zeroed() };
    dm.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
    // SAFETY: `device` is null or a NUL-terminated device name, and `dm` says
    // its own size.
    if unsafe { EnumDisplaySettingsW(device, ENUM_CURRENT_SETTINGS, &mut dm) } == 0 {
        return None;
    }
    hz(f64::from(dm.dmDisplayFrequency))
}

/// The rate of the primary display (the output scrap's DXGI arm captures).
#[cfg(target_os = "windows")]
pub fn of_primary() -> Option<u16> {
    of_device(std::ptr::null())
}

/// The rate of the monitor WGC captures, by its device name. The `HMONITOR`
/// comes as its value: a handle the system resolves, never a pointer this
/// side reads through.
#[cfg(all(target_os = "windows", feature = "wgc-capture"))]
pub fn of_monitor(hmon: usize) -> Option<u16> {
    use windows_sys::Win32::Graphics::Gdi::{
        GetMonitorInfoW, HMONITOR, MONITORINFO, MONITORINFOEXW,
    };
    let mut info: MONITORINFOEXW = unsafe { std::mem::zeroed() };
    info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
    // SAFETY: `cbSize` says this is the EX form, which carries `szDevice`;
    // the API writes no further than that size, and an invalid handle is an
    // error return, not a fault.
    let ok = unsafe {
        GetMonitorInfoW(
            hmon as HMONITOR,
            (&mut info as *mut MONITORINFOEXW).cast::<MONITORINFO>(),
        )
    };
    if ok == 0 {
        return None;
    }
    of_device(info.szDevice.as_ptr())
}

/// The rate of the main display (the one scrap's quartz stream captures).
#[cfg(target_os = "macos")]
pub fn of_main_display() -> Option<u16> {
    type CGDisplayModeRef = *mut core::ffi::c_void;
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGMainDisplayID() -> u32;
        fn CGDisplayCopyDisplayMode(display: u32) -> CGDisplayModeRef;
        fn CGDisplayModeGetRefreshRate(mode: CGDisplayModeRef) -> f64;
        fn CGDisplayModeRelease(mode: CGDisplayModeRef);
    }
    // SAFETY: plain CoreGraphics queries, safe from any thread; the copied
    // mode is released exactly once.
    unsafe {
        let mode = CGDisplayCopyDisplayMode(CGMainDisplayID());
        if mode.is_null() {
            return None;
        }
        let rate = CGDisplayModeGetRefreshRate(mode);
        CGDisplayModeRelease(mode);
        hz(rate)
    }
}

/// A RandR mode's rate: the dot clock over the pixels a frame takes, halved
/// for an interlaced mode and doubled for a double-scanned one, as `xrandr`
/// computes it.
pub fn of_mode_timings(
    dot_clock: u32,
    htotal: u16,
    vtotal: u16,
    interlace: bool,
    double_scan: bool,
) -> Option<u16> {
    let mut lines = f64::from(vtotal);
    if double_scan {
        lines *= 2.0;
    }
    if interlace {
        lines /= 2.0;
    }
    let pixels = f64::from(htotal) * lines;
    if pixels <= 0.0 {
        return None;
    }
    hz(f64::from(dot_clock) / pixels)
}

/// The X11 primary output's rate, read over a connection of its own (once, at
/// the open). Any failure, or no primary output, is `None`.
#[cfg(all(target_os = "linux", feature = "scrap-capture"))]
pub fn of_x11_primary() -> Option<u16> {
    use x11rb::connection::Connection;
    use x11rb::protocol::randr::{ConnectionExt as _, ModeFlag};
    let (conn, screen) = x11rb::connect(None).ok()?;
    let root = conn.setup().roots.get(screen)?.root;
    let output = conn
        .randr_get_output_primary(root)
        .ok()?
        .reply()
        .ok()?
        .output;
    if output == x11rb::NONE {
        return None;
    }
    let info = conn
        .randr_get_output_info(output, x11rb::CURRENT_TIME)
        .ok()?
        .reply()
        .ok()?;
    if info.crtc == x11rb::NONE {
        return None;
    }
    let crtc = conn
        .randr_get_crtc_info(info.crtc, x11rb::CURRENT_TIME)
        .ok()?
        .reply()
        .ok()?;
    let resources = conn
        .randr_get_screen_resources_current(root)
        .ok()?
        .reply()
        .ok()?;
    let mode = resources.modes.iter().find(|m| m.id == crtc.mode)?;
    let flags = u32::from(mode.mode_flags);
    of_mode_timings(
        mode.dot_clock,
        mode.htotal,
        mode.vtotal,
        flags & u32::from(ModeFlag::INTERLACE) != 0,
        flags & u32::from(ModeFlag::DOUBLE_SCAN) != 0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "The hardware's default" (0, 1) and nonsense are no rate; a real
    /// reading rounds to the nearest hertz (a 59.94 Hz mode is 60).
    #[test]
    fn only_a_real_reading_is_a_rate() {
        assert_eq!(hz(0.0), None);
        assert_eq!(hz(1.0), None);
        assert_eq!(hz(-60.0), None);
        assert_eq!(hz(f64::NAN), None);
        assert_eq!(hz(1e9), None);
        assert_eq!(hz(59.94), Some(60));
        assert_eq!(hz(120.0), Some(120));
        assert_eq!(hz(143.856), Some(144));
    }

    /// The CVT timings of real modes, as `xrandr` reports their rates.
    #[test]
    fn a_randr_mode_rate_is_its_dot_clock_over_its_frame() {
        // 1920x1080 at 60 Hz (CVT-RB): 138.5 MHz, 2080 x 1111.
        assert_eq!(
            of_mode_timings(138_500_000, 2080, 1111, false, false),
            Some(60)
        );
        // 2560x1440 at 144 Hz: 586.59 MHz, 2720 x 1497.
        assert_eq!(
            of_mode_timings(586_590_000, 2720, 1497, false, false),
            Some(144)
        );
        // Interlaced 1080i at 60 fields: 74.25 MHz, 2200 x 1125.
        assert_eq!(
            of_mode_timings(74_250_000, 2200, 1125, true, false),
            Some(60)
        );
        // A double-scanned 320x240 at 60 Hz.
        assert_eq!(of_mode_timings(12_587_000, 400, 262, false, true), Some(60));
        assert_eq!(of_mode_timings(138_500_000, 0, 1111, false, false), None);
    }
}
