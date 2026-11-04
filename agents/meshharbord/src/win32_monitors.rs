// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows multi-monitor enumeration — diagnostic-only as of rc.48.
//!
//! Surfaces the per-monitor virtual-screen layout (origin, size, DPI,
//! and the primary flag) so an operator can triage the "orthogonal
//! mouse-offset" field bug the rc.43-ui commit (79d6dee) flagged as
//! still open even after rc.41/44's DPI-awareness work landed.
//!
//! Hypothesis chain:
//!   1. Capture pipeline surfaces physical pixels for monitor 0.
//!   2. `enigo.main_display()` reports the same physical dims (per
//!      rc.41 DPI fix) so `to_pixels` math gets the right *extent*.
//!   3. BUT `SetCursorPos` interprets `(px, py)` against the **virtual
//!      desktop origin** (`SM_X/YVIRTUALSCREEN`). On a single-monitor
//!      host that origin is `(0, 0)` and the math is symmetric. On a
//!      multi-monitor or docked-laptop host where the primary monitor
//!      has been repositioned (e.g. user dragged it to "right of the
//!      external"), the primary's origin is no longer `(0, 0)` and
//!      our normalised-to-primary mapping lands clicks at the WRONG
//!      monitor.
//!
//! This module logs the actual layout at startup so we can confirm or
//! reject (3) against the field-test host field data BEFORE writing a fix. No
//! behaviour change — `to_pixels` still uses the legacy path.
//!
//! When the data confirms the hypothesis: a follow-up rc adds a
//! virtual-screen-aware `to_pixels` behind `ROOMLERD_VIRTUAL_SCREEN=1`.

#![cfg(target_os = "windows")]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows_sys::Win32::Foundation::{BOOL, LPARAM, POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    DEVMODEW, ENUM_CURRENT_SETTINGS, EnumDisplayMonitors, EnumDisplaySettingsW, GetMonitorInfoW,
    HDC, HMONITOR, MONITOR_DEFAULTTOPRIMARY, MONITORINFOEXW, MonitorFromPoint,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, MONITORINFOF_PRIMARY, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
    SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

/// One monitor as reported by `EnumDisplayMonitors` + `GetMonitorInfoW`.
/// All coordinates are in **physical pixels** because the agent calls
/// `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` at startup
/// (see `dpi.rs`). On a host where DPI awareness fails to set, these
/// values fall back to logical pixels — the rc.41 startup line tells
/// the operator which world we're in.
#[derive(Debug, Clone)]
pub struct MonitorInfo {
    /// Enumeration index (0 == first reported by Windows; not the same
    /// as "primary" — see `primary` flag).
    pub index: u8,
    /// `\\.\DISPLAY1` style device name (UTF-16 → UTF-8).
    pub device_name: String,
    /// Virtual-screen origin X (can be negative — primary is not
    /// always at `(0,0)` on multi-monitor setups).
    pub origin_x: i32,
    /// Virtual-screen origin Y (can be negative).
    pub origin_y: i32,
    /// Width in physical pixels.
    pub width_px: i32,
    /// Height in physical pixels.
    pub height_px: i32,
    /// Effective DPI X (96 == 100% scale, 120 == 125%, 144 == 150%).
    pub dpi_x: u32,
    /// Effective DPI Y.
    pub dpi_y: u32,
    /// Mode reported by `EnumDisplaySettingsW(ENUM_CURRENT_SETTINGS)` —
    /// the native panel resolution. Useful contrast vs `width_px` when
    /// DXGI / WGC reports a different surface size than the panel has.
    pub native_width_px: u32,
    /// Native panel height per `EnumDisplaySettingsW`.
    pub native_height_px: u32,
    /// True if this monitor carries the `MONITORINFOF_PRIMARY` flag.
    pub primary: bool,
}

/// Bounds of the **virtual desktop** — the rectangle that contains every
/// attached monitor in shared coordinates. Returned as
/// `(origin_x, origin_y, width, height)`. Origin can be negative when
/// the primary isn't at `(0, 0)`.
pub fn virtual_screen_rect() -> (i32, i32, i32, i32) {
    // SAFETY: GetSystemMetrics is thread-safe per MSDN, takes no
    // memory, returns 0 on unsupported indices (all four we use are
    // valid on every supported Windows).
    let x = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    let y = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    let w = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) };
    let h = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) };
    (x, y, w, h)
}

/// `MonitorInfo` for the OS-designated **primary** monitor — the one
/// `enigo.main_display()` *should* report. Returns `None` if
/// `MonitorFromPoint` fails (no monitors attached → headless / RDP
/// without a session console).
pub fn primary() -> Option<MonitorInfo> {
    // SAFETY: MonitorFromPoint takes a stack-allocated POINT; returns
    // a non-owning HMONITOR handle. Thread-safe per MSDN.
    let hmon = unsafe { MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY) };
    if hmon.is_null() {
        return None;
    }
    monitor_info_from_handle(hmon, 0)
}

/// Resolve the `MonitorInfo` matching the browser's `mon` index in the
/// `InputMsg::MouseMove { mon, .. }` field. Lookup order:
///
///   1. Cached `enumerate()` result `cached_monitors()[mon as usize]`
///      when the index is in range — matches the order
///      `rc:agent.hello`'s `displays` field reports, so the browser
///      and agent agree on monitor identity.
///   2. Fall back to [`primary`] when `mon` is out of range (or `0`
///      and the cache is empty) so a misconfigured browser still gets
///      sensible input dispatch.
///
/// rc.55 — wired into `enigo_backend::resolve_target_monitor` when the
/// `ROOMLERD_VIRTUAL_SCREEN` gate is on. Today's browser only
/// streams the primary monitor and sends `mon=0`, so this collapses to
/// the primary lookup; the per-index path is future-proofing for when
/// the agent's video pipeline gains multi-monitor streams.
pub fn target_monitor(mon: u8) -> Option<MonitorInfo> {
    let monitors = cached_monitors();
    if let Some(m) = monitors.get(mon as usize) {
        return Some(m.clone());
    }
    primary()
}

/// Cached enumeration result, populated once on first call via
/// [`std::sync::LazyLock`]. Layout changes mid-session (hot-plug,
/// dock/undock) WILL be stale until the agent process restarts;
/// acceptable trade-off vs. paying ~1 ms FFI cost per mouse event.
/// Operators can reconnect (kicks the agent supervisor → fresh worker
/// → fresh cache) to pick up a new layout.
pub fn cached_monitors() -> &'static Vec<MonitorInfo> {
    use std::sync::LazyLock;
    static MONITORS: LazyLock<Vec<MonitorInfo>> = LazyLock::new(enumerate);
    &MONITORS
}

/// Walk every attached monitor via `EnumDisplayMonitors` and return one
/// `MonitorInfo` per monitor. Indexed in enumeration order (which
/// matches the order the agent's `displays.rs` already reports via
/// `scrap::Display::all()` on Windows because both ultimately read DXGI
/// adapter enumeration).
///
/// Empty `Vec` only if `EnumDisplayMonitors` itself returned 0 (zero
/// monitors attached, or the calling station/desktop has no display
/// access — happens on a service agent running in `Service-0x0` without
/// the SystemContext desktop hop).
pub fn enumerate() -> Vec<MonitorInfo> {
    // Build state on the stack; the callback dereferences `lparam` to
    // push into this Vec. Keeps the FFI surface minimal — no globals.
    let mut state = EnumState {
        monitors: Vec::new(),
        next_index: 0,
    };
    let state_ptr: *mut EnumState = &mut state;
    // SAFETY: EnumDisplayMonitors blocks until the callback has been
    // invoked for every monitor. We pass a Rust pointer in LPARAM and
    // dereference it from inside the callback; the pointer is live for
    // the duration of the call. No threading concerns — the callback
    // runs on the same thread per MSDN.
    let _ = unsafe {
        EnumDisplayMonitors(
            std::ptr::null_mut() as HDC,
            std::ptr::null(),
            Some(enum_callback),
            state_ptr as LPARAM,
        )
    };
    state.monitors
}

struct EnumState {
    monitors: Vec<MonitorInfo>,
    next_index: u8,
}

unsafe extern "system" fn enum_callback(
    hmon: HMONITOR,
    _hdc: HDC,
    _rect: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    // SAFETY: `lparam` is the `EnumState*` we passed in. Live for the
    // duration of EnumDisplayMonitors. Callback runs on the calling
    // thread so the `&mut` is exclusive.
    let state = unsafe { &mut *(lparam as *mut EnumState) };
    let idx = state.next_index;
    if let Some(info) = monitor_info_from_handle(hmon, idx) {
        state.monitors.push(info);
    }
    state.next_index = state.next_index.wrapping_add(1);
    1 // TRUE — keep enumerating
}

/// Pull `MONITORINFOEXW` + DPI + native panel size for one monitor.
fn monitor_info_from_handle(hmon: HMONITOR, index: u8) -> Option<MonitorInfo> {
    // MONITORINFOEXW = MONITORINFO + szDevice[32]. szSize MUST be set
    // to sizeof::<MONITORINFOEXW>() or GetMonitorInfoW silently returns
    // FALSE with no extended info.
    let mut info: MONITORINFOEXW = unsafe { std::mem::zeroed() };
    info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
    // SAFETY: `info` is a valid MONITORINFOEXW with cbSize set; pointer
    // cast is the documented pattern for the extended form.
    let ok = unsafe {
        GetMonitorInfoW(
            hmon,
            &mut info as *mut MONITORINFOEXW as *mut windows_sys::Win32::Graphics::Gdi::MONITORINFO,
        )
    };
    if ok == 0 {
        return None;
    }
    let RECT {
        left,
        top,
        right,
        bottom,
    } = info.monitorInfo.rcMonitor;
    let primary = (info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY) != 0;
    let device_name = wide_to_string(&info.szDevice);

    // GetDpiForMonitor — MDT_EFFECTIVE_DPI matches what the OS feeds to
    // DPI-aware apps. On legacy / unaware hosts this would return 96
    // but we set per-monitor-v2 at startup, so values reflect reality.
    let mut dpi_x: u32 = 0;
    let mut dpi_y: u32 = 0;
    // SAFETY: GetDpiForMonitor requires the calling process to be at
    // least per-monitor-v1 DPI-aware (we set v2 in main()). Returns
    // E_INVALIDARG if pointers are null; we provide stack-allocated
    // u32s. Thread-safe per MSDN.
    let dpi_hr = unsafe { GetDpiForMonitor(hmon, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y) };
    if dpi_hr != 0 {
        // Non-zero == failure HRESULT. Leave dpi_x/y at 0 to surface
        // the failure in the log without aborting the diagnostic dump.
        dpi_x = 0;
        dpi_y = 0;
    }

    // EnumDisplaySettingsW with ENUM_CURRENT_SETTINGS — what the
    // device thinks its current mode is. Compared against
    // (right-left, bottom-top) helps spot scaling vs panel-mismatch.
    let (native_w, native_h) = native_panel_size(&info.szDevice);

    Some(MonitorInfo {
        index,
        device_name,
        origin_x: left,
        origin_y: top,
        width_px: right - left,
        height_px: bottom - top,
        dpi_x,
        dpi_y,
        native_width_px: native_w,
        native_height_px: native_h,
        primary,
    })
}

fn native_panel_size(device_name: &[u16; 32]) -> (u32, u32) {
    let mut mode: DEVMODEW = unsafe { std::mem::zeroed() };
    mode.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
    // SAFETY: EnumDisplaySettingsW reads from device_name (null-terminated
    // wide string). MONITORINFOEXW::szDevice always carries a
    // null-terminated `\\.\DISPLAYn` string per MSDN.
    let ok =
        unsafe { EnumDisplaySettingsW(device_name.as_ptr(), ENUM_CURRENT_SETTINGS, &mut mode) };
    if ok == 0 {
        return (0, 0);
    }
    (mode.dmPelsWidth, mode.dmPelsHeight)
}

fn wide_to_string(buf: &[u16; 32]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end])
        .to_string_lossy()
        .into_owned()
}

/// Log every monitor + the virtual-screen rect at INFO. Called once at
/// startup. Lines are structured (each field is a separate key) so an
/// operator can grep for `monitor_diag` and pipe to `jq`.
///
/// Format choice: one line per monitor (so a 6-monitor host doesn't
/// explode the log) plus one summary line for the virtual rect.
pub fn log_monitor_diagnostic() {
    let (vsx, vsy, vsw, vsh) = virtual_screen_rect();
    tracing::info!(
        virt_origin_x = vsx,
        virt_origin_y = vsy,
        virt_width_px = vsw,
        virt_height_px = vsh,
        "monitor_diag — virtual screen rect (rc.48 diagnostic; SM_X/YVIRTUALSCREEN + SM_C{{X,Y}}VIRTUALSCREEN)"
    );
    let monitors = enumerate();
    if monitors.is_empty() {
        tracing::warn!(
            "monitor_diag — EnumDisplayMonitors returned 0 entries (headless / no console session)"
        );
        return;
    }
    for m in &monitors {
        tracing::info!(
            index = m.index,
            device = %m.device_name,
            origin_x = m.origin_x,
            origin_y = m.origin_y,
            width_px = m.width_px,
            height_px = m.height_px,
            dpi_x = m.dpi_x,
            dpi_y = m.dpi_y,
            native_width_px = m.native_width_px,
            native_height_px = m.native_height_px,
            primary = m.primary,
            "monitor_diag — monitor entry"
        );
    }
    // The whole point of this diagnostic: surface the contrast
    // between primary's virtual-screen origin and (0,0). If they
    // differ, the mouse-offset hypothesis (3) is confirmed.
    if let Some(p) = monitors.iter().find(|m| m.primary)
        && (p.origin_x != 0 || p.origin_y != 0)
    {
        tracing::warn!(
            origin_x = p.origin_x,
            origin_y = p.origin_y,
            "monitor_diag — primary monitor origin is NOT (0,0); to_pixels currently maps against primary dims without applying this offset. Likely root cause of the field-test host mouse-offset bug."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: virtual_screen_rect never panics + always returns
    /// finite values. Width/height should be ≥ 0 on a real desktop;
    /// 0 is acceptable on a headless CI box where no display attaches.
    #[test]
    fn virtual_screen_rect_returns_sane_values() {
        let (x, y, w, h) = virtual_screen_rect();
        // Origin can be negative on multi-monitor; width/height must
        // be non-negative (Windows returns 0 if no monitors).
        assert!(w >= 0, "virtual width should be ≥ 0, got {w}");
        assert!(h >= 0, "virtual height should be ≥ 0, got {h}");
        // x/y are i32; just confirm the call returned.
        let _ = (x, y);
    }

    /// Smoke test: enumerate doesn't panic. On a CI runner with no
    /// session-attached display this can return 0 monitors; on a
    /// developer box it should return ≥ 1.
    #[test]
    fn enumerate_does_not_panic() {
        let list = enumerate();
        // Don't assert on length — CI windows runners run as a service
        // and may have no console display. Just confirm each entry has
        // a non-empty device name when present.
        for m in &list {
            assert!(!m.device_name.is_empty(), "device_name should not be empty");
            // dpi can be 0 if GetDpiForMonitor failed (which would be
            // logged by log_monitor_diagnostic). Don't assert on it.
        }
    }

    /// Smoke test: log_monitor_diagnostic just logs; should never
    /// crash on any host configuration.
    #[test]
    fn log_diagnostic_does_not_panic() {
        log_monitor_diagnostic();
    }

    /// rc.55 — `cached_monitors` returns the same Vec on repeat calls
    /// (memoised via LazyLock). Test only checks the call doesn't
    /// panic + returns the same length each time; the actual content
    /// is host-dependent (CI runners may report 0).
    #[test]
    fn cached_monitors_is_stable() {
        let a = cached_monitors().len();
        let b = cached_monitors().len();
        assert_eq!(a, b, "cached_monitors should be memoised");
    }

    /// rc.55 — `target_monitor(0)` always resolves to *some* monitor on
    /// a real desktop (either cached_monitors[0] or the primary
    /// fallback). On headless CI it may return None — both are OK.
    #[test]
    fn target_monitor_in_range_or_falls_back_to_primary() {
        let cached_count = cached_monitors().len();
        let t0 = target_monitor(0);
        if cached_count >= 1 {
            assert!(t0.is_some(), "mon=0 must resolve on a host with ≥1 monitor");
        }
        // Out-of-range index: must NOT panic; falls back to primary or
        // returns None on headless.
        let _ = target_monitor(99);
    }
}
