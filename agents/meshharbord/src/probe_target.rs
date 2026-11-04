// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-16 L4 — `roomlerd probe-target`: input to photon on a release build.
//!
//! The bench probe (`synthetic_backend::probe`) exists only where the
//! synthetic source does, and no release profile builds that. This window
//! brings L4 to a real host. It sits flush in the primary monitor's
//! bottom-right corner, and its marker changes when **real OS input**
//! reaches it. A bench viewer (`roomler-rc-bench=target`) moves the remote
//! pointer onto one of the 16 cells across the window's pad. The agent
//! injects that move like any other, and the window reads the cell from its
//! own `WM_MOUSEMOVE` and paints the cell's number into the marker. The
//! viewer then times send → the first painted frame carrying that number,
//! the same way it times a bench probe. So a round trip here also counts
//! injection, the host's compositor and the capture, which the in-process
//! probe cannot.
//!
//! Layout, in physical pixels (the window is per-monitor DPI aware, as the
//! capture is):
//!
//! ```text
//!   ┌──────────────────── 144 px ────────────────────┐
//!   │ 1 │ 2 │ 3 │ …                          │ 16 │   │ pad: 16 cells × 9 px, 32 px high
//!   ├────────────────────────────────────────────────┤
//!   │  8 px margin · marker grid 128 × 32 · margin   │ 48 px
//!   └────────────────────────────────────────────────┘ ← the monitor's bottom-right corner
//! ```
//!
//! The marker area is exactly the region the viewer's bottom-right decoder
//! reads (`capture::bench_marker`), at native size or a 2× or 4× downscale.
//! The viewer aims at a cell's centre, `x = mon_w − 144 + (cell − 1)·9 + 4`
//! and `y = mon_h − 64`, normalised by `(w − 1)` and `(h − 1)`: the agent's
//! own mapping (`input::enigo_backend::map_normalised_to_virtual`), so the
//! move lands on that pixel exactly. `ui/src/composables/rcBench.ts` mirrors
//! [`cell_centre`] and pins the same vectors.
//!
//! ⚠️ **A bench tool, run on purpose.** It covers the corner of the screen
//! (on Windows, the clock in the taskbar), it holds the remote pointer in its
//! pad while probing, and it closes on its own after `--seconds` (default
//! 600), or on a right-click. It has no input of its own beyond reading the
//! pointer over its pad: no hook, no key reading (FR-92).

use crate::capture::bench_marker;

/// The window's width: the marker's margin, grid and margin.
pub const WIDTH: u32 = bench_marker::MARGIN * 2 + bench_marker::W;
/// The marker area's height, at the bottom of the window.
pub const MARKER_H: u32 = bench_marker::MARGIN * 2 + bench_marker::H;
/// The pad's height, above the marker.
pub const PAD_H: u32 = 32;
pub const HEIGHT: u32 = PAD_H + MARKER_H;
/// Cells across the pad, numbered 1..=CELLS.
pub const CELLS: u16 = 16;
pub const CELL_W: u32 = WIDTH / CELLS as u32;

/// The window's rectangle `(x, y, w, h)`: flush with the bottom-right corner
/// of a monitor at `(left, top)` sized `mon_w × mon_h`.
pub fn window_rect(left: i32, top: i32, mon_w: u32, mon_h: u32) -> (i32, i32, u32, u32) {
    (
        left + mon_w as i32 - WIDTH as i32,
        top + mon_h as i32 - HEIGHT as i32,
        WIDTH,
        HEIGHT,
    )
}

/// The cell under a window-relative point: 1..=CELLS inside the pad, else
/// `None` (the marker area, or outside the window).
pub fn cell_at(x: i32, y: i32) -> Option<u16> {
    if x < 0 || y < 0 || y >= PAD_H as i32 || x >= (CELL_W * CELLS as u32) as i32 {
        return None;
    }
    Some((x as u32 / CELL_W) as u16 + 1)
}

/// A cell's centre in a `mon_w × mon_h` monitor's own pixels, the point a
/// viewer aims at. `None` for a cell outside 1..=CELLS or a monitor too
/// small to hold the window.
pub fn cell_centre(mon_w: u32, mon_h: u32, cell: u16) -> Option<(u32, u32)> {
    if !(1..=CELLS).contains(&cell) || mon_w < WIDTH || mon_h < HEIGHT {
        return None;
    }
    let x = mon_w - WIDTH + (u32::from(cell) - 1) * CELL_W + CELL_W / 2;
    let y = mon_h - HEIGHT + PAD_H / 2;
    Some((x, y))
}

/// The window's pixels, BGRA, top-down, `WIDTH × HEIGHT`. The pad's cells
/// alternate two dark greys so a person can see them; the marker area
/// carries `value`, or stays plain mid-grey before the first move, which the
/// decoder reads as nothing (every block sits in its dead band).
pub fn render(value: Option<u16>) -> Vec<u8> {
    let stride = WIDTH * 4;
    let mut px = vec![0u8; (stride * HEIGHT) as usize];
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let v: u8 = if y < PAD_H {
                if (x / CELL_W).is_multiple_of(2) {
                    0x30
                } else {
                    0x50
                }
            } else {
                0x80
            };
            let i = (y * stride + x * 4) as usize;
            px[i..i + 4].copy_from_slice(&[v, v, v, 0xFF]);
        }
    }
    if let Some(value) = value {
        // A canvas exactly the window's size: the bottom-left grid of a
        // 144-wide canvas sits MARGIN in from both edges, which is where a
        // frame's bottom-right decoder looks once the window is flush in the
        // monitor's corner.
        bench_marker::paint_bgra(&mut px, WIDTH, HEIGHT, stride, value);
    }
    px
}

/// Run the window until it closes: after `seconds`, or on a right-click.
#[cfg(windows)]
pub fn run(seconds: u64) -> anyhow::Result<()> {
    win::run(seconds)
}

#[cfg(not(windows))]
pub fn run(_seconds: u64) -> anyhow::Result<()> {
    anyhow::bail!(
        "probe-target is Windows-only for now: it paints from WM_MOUSEMOVE. \
         Bench a Linux or macOS host with an agent built with the synthetic source"
    )
}

#[cfg(windows)]
mod win {
    use super::{CELLS, HEIGHT, WIDTH, cell_at, render, window_rect};
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicU32, Ordering};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows_sys::Win32::Graphics::Gdi::{
        BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BeginPaint, DIB_RGB_COLORS, EndPaint,
        GetMonitorInfoW, InvalidateRect, MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromPoint,
        PAINTSTRUCT, SetDIBitsToDevice,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        HWND_TOPMOST, IDC_ARROW, LoadCursorW, MA_NOACTIVATE, MSG, PostQuitMessage,
        RegisterClassExW, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SetTimer, SetWindowPos,
        TranslateMessage, WM_DESTROY, WM_MOUSEACTIVATE, WM_MOUSEMOVE, WM_PAINT, WM_RBUTTONUP,
        WM_TIMER, WNDCLASSEXW, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
        WS_VISIBLE,
    };

    /// Re-assert topmost this often: the taskbar is topmost too, and wins
    /// the corner back whenever it is activated.
    const TOPMOST_TIMER: usize = 1;
    const TOPMOST_MS: u32 = 500;
    const CLOSE_TIMER: usize = 2;

    /// The number the marker carries; 0 = none yet. The window procedure is
    /// a plain `extern "system"` function, so its one piece of state lives
    /// here (one window per process).
    static VALUE: AtomicU32 = AtomicU32::new(0);

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    pub(super) fn run(seconds: u64) -> anyhow::Result<()> {
        unsafe {
            // Physical pixels, the capture's own: the pad and the marker must
            // land where the viewer aims and reads.
            SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            let monitor = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
            let mut info: MONITORINFO = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
            if GetMonitorInfoW(monitor, &mut info) == 0 {
                anyhow::bail!("GetMonitorInfoW failed for the primary monitor");
            }
            let r: RECT = info.rcMonitor;
            let (mon_w, mon_h) = ((r.right - r.left) as u32, (r.bottom - r.top) as u32);
            let (x, y, w, h) = window_rect(r.left, r.top, mon_w, mon_h);

            let instance = GetModuleHandleW(std::ptr::null());
            let class = wide("RoomlerProbeTarget");
            let title = wide("Roomler L4 probe target");
            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0,
                lpfnWndProc: Some(wnd_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: instance,
                hIcon: std::ptr::null_mut(),
                hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: class.as_ptr(),
                hIconSm: std::ptr::null_mut(),
            };
            if RegisterClassExW(&wc) == 0 {
                anyhow::bail!("RegisterClassExW failed");
            }
            let hwnd = CreateWindowExW(
                WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                class.as_ptr(),
                title.as_ptr(),
                WS_POPUP | WS_VISIBLE,
                x,
                y,
                w as i32,
                h as i32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null::<c_void>(),
            );
            if hwnd.is_null() {
                anyhow::bail!("CreateWindowExW failed");
            }
            SetTimer(hwnd, TOPMOST_TIMER, TOPMOST_MS, None);
            let close_ms = seconds.clamp(1, 24 * 3600).saturating_mul(1000);
            SetTimer(
                hwnd,
                CLOSE_TIMER,
                close_ms.min(u64::from(u32::MAX)) as u32,
                None,
            );
            println!(
                "probe-target: {w}x{h} at ({x},{y}) on a {mon_w}x{mon_h} primary monitor; \
                 {CELLS} cells; closes after {seconds} s or on a right-click"
            );

            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        Ok(())
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_MOUSEMOVE => {
                // Window-relative, signed 16-bit each (GET_X_LPARAM / GET_Y_LPARAM).
                let x = (lparam & 0xFFFF) as u16 as i16 as i32;
                let y = ((lparam >> 16) & 0xFFFF) as u16 as i16 as i32;
                if let Some(cell) = cell_at(x, y)
                    && VALUE.swap(u32::from(cell), Ordering::AcqRel) != u32::from(cell)
                {
                    unsafe { InvalidateRect(hwnd, std::ptr::null(), 0) };
                }
                0
            }
            WM_PAINT => {
                let value = match VALUE.load(Ordering::Acquire) {
                    0 => None,
                    v => Some(v as u16),
                };
                let px = render(value);
                unsafe {
                    let mut ps: PAINTSTRUCT = std::mem::zeroed();
                    let hdc = BeginPaint(hwnd, &mut ps);
                    let mut bmi: BITMAPINFO = std::mem::zeroed();
                    bmi.bmiHeader = BITMAPINFOHEADER {
                        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: WIDTH as i32,
                        // Negative: a top-down bitmap, as `render` lays it out.
                        biHeight: -(HEIGHT as i32),
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: BI_RGB,
                        biSizeImage: 0,
                        biXPelsPerMeter: 0,
                        biYPelsPerMeter: 0,
                        biClrUsed: 0,
                        biClrImportant: 0,
                    };
                    SetDIBitsToDevice(
                        hdc,
                        0,
                        0,
                        WIDTH,
                        HEIGHT,
                        0,
                        0,
                        0,
                        HEIGHT,
                        px.as_ptr().cast(),
                        &bmi,
                        DIB_RGB_COLORS,
                    );
                    EndPaint(hwnd, &ps);
                }
                0
            }
            WM_TIMER => {
                unsafe {
                    if wparam == TOPMOST_TIMER {
                        SetWindowPos(
                            hwnd,
                            HWND_TOPMOST,
                            0,
                            0,
                            0,
                            0,
                            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                        );
                    } else if wparam == CLOSE_TIMER {
                        DestroyWindow(hwnd);
                    }
                }
                0
            }
            // A click must not take focus from whatever the person was using.
            WM_MOUSEACTIVATE => MA_NOACTIVATE as LRESULT,
            WM_RBUTTONUP => {
                unsafe { DestroyWindow(hwnd) };
                0
            }
            WM_DESTROY => {
                unsafe { PostQuitMessage(0) };
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_is_the_marker_plus_a_pad_flush_in_the_corner() {
        assert_eq!((WIDTH, MARKER_H, PAD_H, HEIGHT), (144, 48, 32, 80));
        assert_eq!((CELLS, CELL_W), (16, 9));
        assert_eq!(window_rect(0, 0, 1920, 1080), (1776, 1000, 144, 80));
        // A secondary monitor left of the primary: the corner moves with it.
        assert_eq!(window_rect(-2560, 0, 2560, 1440), (-144, 1360, 144, 80));
    }

    #[test]
    fn a_point_maps_to_its_cell_and_the_marker_area_to_none() {
        assert_eq!(cell_at(0, 0), Some(1));
        assert_eq!(cell_at(8, 31), Some(1));
        assert_eq!(cell_at(9, 0), Some(2));
        assert_eq!(cell_at(143, 10), Some(16));
        // The marker area and anything outside the window are not cells.
        assert_eq!(cell_at(10, 32), None);
        assert_eq!(cell_at(144, 10), None);
        assert_eq!(cell_at(-1, 10), None);
        assert_eq!(cell_at(10, -1), None);
    }

    #[test]
    fn every_cell_centre_lands_in_its_own_cell() {
        let (mon_w, mon_h) = (1920u32, 1080u32);
        let (wx, wy, _, _) = window_rect(0, 0, mon_w, mon_h);
        for cell in 1..=CELLS {
            let (x, y) = cell_centre(mon_w, mon_h, cell).expect("centre");
            assert_eq!(
                cell_at(x as i32 - wx, y as i32 - wy),
                Some(cell),
                "cell {cell}"
            );
        }
        // The vectors `rcBench.spec.ts` pins too.
        assert_eq!(cell_centre(1920, 1080, 1), Some((1780, 1016)));
        assert_eq!(cell_centre(1920, 1080, 16), Some((1915, 1016)));
        assert_eq!(cell_centre(2560, 1600, 7), Some((2474, 1536)));
        assert_eq!(cell_centre(1920, 1080, 0), None);
        assert_eq!(cell_centre(1920, 1080, 17), None);
        assert_eq!(cell_centre(100, 1080, 1), None);
    }

    /// Paste the window into a `w × h` frame's bottom-right corner and read
    /// the frame the way the viewer does (BT.601 luma of the BGRA).
    fn read_back(window: &[u8], w: u32, h: u32) -> Option<u16> {
        let mut frame = vec![0x22u8; (w * h * 4) as usize];
        let (wx, wy, _, _) = window_rect(0, 0, w, h);
        for row in 0..HEIGHT {
            let src = (row * WIDTH * 4) as usize;
            let dst = (((wy as u32 + row) * w + wx as u32) * 4) as usize;
            frame[dst..dst + (WIDTH * 4) as usize]
                .copy_from_slice(&window[src..src + (WIDTH * 4) as usize]);
        }
        let luma: Vec<u8> = frame
            .chunks_exact(4)
            .map(|p| {
                let (b, g, r) = (u32::from(p[0]), u32::from(p[1]), u32::from(p[2]));
                (16 + (66 * r + 129 * g + 25 * b + 128) / 256) as u8
            })
            .collect();
        bench_marker::decode_luma_at(bench_marker::Corner::BottomRight, &luma, w, h, w as usize)
    }

    #[test]
    fn the_painted_cell_reads_back_from_the_frames_bottom_right() {
        for cell in [1, 7, 16] {
            assert_eq!(
                read_back(&render(Some(cell)), 1920, 1080),
                Some(cell),
                "cell {cell}"
            );
        }
    }

    #[test]
    fn before_the_first_move_the_marker_reads_as_nothing() {
        assert_eq!(read_back(&render(None), 1920, 1080), None);
    }
}
