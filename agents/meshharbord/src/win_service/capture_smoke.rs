// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! WGC session-0 / Winlogon capture smoke binary (M3 derisking spike).
//!
//! Why this exists. M3's load-bearing assumption is that
//! `Windows.Graphics.Capture` (WGC) on Win11 22H2+ supports session-0
//! capture for SYSTEM processes attached to `winsta0\Winlogon`. The
//! M5 verification on the field-test host (2026-05-02) confirmed the gap from the
//! user-context side; before we commit to writing `system_worker.rs`,
//! we need empirical evidence that WGC actually initialises against
//! the secure desktop. The 2026-05-02 critic review (item D) flagged
//! that `psexec -s -i 0` lands on session 0's *visible* desktop, not
//! Winlogon — so this binary *explicitly* opens `winsta0\Winlogon`
//! and `SetThreadDesktop`-attaches before init.
//!
//! Three modes (`--desktop`):
//!   - `default` (default): no desktop swap; attach stays on whatever
//!     the parent shell's thread is on (typically `Default`). Sanity
//!     baseline — must succeed on a normal user session.
//!   - `input`: `OpenInputDesktop` → swap. Reproduces what the M3
//!     supervisor's poll loop will do every 250 ms.
//!   - `winlogon`: explicitly opens `winsta0\Winlogon`. Requires
//!     SYSTEM context (run via `psexec -s -i 1 roomlerd system-
//!     capture-smoke --desktop winlogon` from an elevated shell).
//!
//! Reports first frame size, frame-arrived count over a 5-second
//! window, and structured error codes on every init step so the field
//! can pinpoint exactly where session-0 capture diverges from the
//! happy path on each Win11 build.

#![cfg(all(target_os = "windows", feature = "wgc-capture"))]

use anyhow::{Context, Result, bail};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};
use std::time::{Duration, Instant};

use windows::Foundation::TypedEventHandler;
use windows::Graphics::Capture::{Direct3D11CaptureFramePool, GraphicsCaptureItem};
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Graphics::SizeInt32;
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_11_0,
    D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION, D3D11CreateDevice, ID3D11Device,
    ID3D11DeviceContext,
};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::Graphics::Gdi::{HMONITOR, MONITOR_DEFAULTTOPRIMARY, MonitorFromPoint};
use windows::Win32::System::WinRT::Direct3D11::CreateDirect3D11DeviceFromDXGIDevice;
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::Interface;

use super::desktop;

/// Where to attach the calling thread before WGC init. Mirrors the
/// CLI `--desktop` enum so the subcommand can hand the parsed value
/// in cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopTarget {
    /// Don't change desktop. Sanity baseline — should always succeed
    /// in a user session.
    Default,
    /// `OpenInputDesktop` + `SetThreadDesktop`. Mirrors the M3
    /// supervisor's poll-loop behaviour.
    Input,
    /// `OpenDesktop("Winlogon")` + `SetThreadDesktop`. Requires
    /// SYSTEM context. The whole point of M3.
    Winlogon,
}

impl std::str::FromStr for DesktopTarget {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "default" => Ok(Self::Default),
            "input" => Ok(Self::Input),
            "winlogon" => Ok(Self::Winlogon),
            _ => Err(format!(
                "unknown --desktop {s:?}; expected one of default|input|winlogon"
            )),
        }
    }
}

/// CLI entry. Init COM, swap desktop if requested, run the WGC probe,
/// print a structured result line, exit non-zero on failure so CI /
/// the operator can `echo $?` straight to a release-block decision.
pub fn run(target: DesktopTarget, frames: u32, timeout_ms: u32) -> Result<()> {
    println!("system-capture-smoke: target={target:?} frames={frames} timeout_ms={timeout_ms}");

    // Step 1: optionally attach to a specific desktop FIRST, before
    // initialising COM. Win32 documents that SetThreadDesktop must
    // succeed before any GUI / COM work begins on the thread; an
    // initialised COM apartment is bound to the desktop it was
    // initialised on, and a desktop swap after init invalidates the
    // capture-related interface vtables (empirical 2026-05-02:
    // initialising RoInitialize first then swapping caused a silent
    // crash deeper in IGraphicsCaptureItemInterop::CreateForMonitor).
    // Logs the before/after name so the field can confirm the swap
    // took.
    let before = desktop::current_thread_desktop_name().unwrap_or_else(|_| "<unknown>".into());
    println!("  before-attach desktop = {before:?}");

    let _desk_owner = match target {
        DesktopTarget::Default => None,
        DesktopTarget::Input => {
            let d = desktop::open_input_desktop()
                .context("OpenInputDesktop")?
                .ok_or_else(|| {
                    anyhow::anyhow!("OpenInputDesktop returned ACCESS_DENIED — need SYSTEM context")
                })?;
            desktop::set_thread_desktop(&d).context("SetThreadDesktop(input)")?;
            Some(d)
        }
        DesktopTarget::Winlogon => {
            let d = desktop::open_desktop_by_name("Winlogon")
                .context("OpenDesktopW(Winlogon)")?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "OpenDesktopW(Winlogon) returned ACCESS_DENIED — \
                     this mode requires SYSTEM context. Run via \
                     `psexec -s -i 1 roomlerd.exe system-capture-smoke --desktop winlogon` \
                     from elevated PowerShell."
                    )
                })?;
            desktop::set_thread_desktop(&d).context("SetThreadDesktop(Winlogon)")?;
            Some(d)
        }
    };

    let after = desktop::current_thread_desktop_name().unwrap_or_else(|_| "<unknown>".into());
    println!("  after-attach  desktop = {after:?}");

    // Step 2: now init COM. SAFETY: RoInitialize is the documented
    // WinRT entry point. MTA is the right apartment for WGC's free-
    // threaded frame pool. Call once per thread; the spike binary is
    // single-threaded so this is the only call. Pair with
    // RoUninitialize at scope end.
    let hr = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    let hr_dbg = format!("{hr:?}");
    hr.ok()
        .with_context(|| format!("RoInitialize(MTA) failed: {hr_dbg}"))?;
    let _ro_guard = scopeguard_ro_uninit();

    // Step 3: D3D11 device. WGC needs BGRA support and a DXGI-derived
    // IDirect3DDevice. Hardware driver type per WGC convention.
    let (d3d_device, _ctx) = create_d3d_device().context("create D3D11 device")?;
    println!("  D3D11 device created");
    let dxgi_device: IDXGIDevice = d3d_device
        .cast()
        .context("ID3D11Device::cast::<IDXGIDevice>")?;
    let direct3d_device = unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi_device) }
        .context("CreateDirect3D11DeviceFromDXGIDevice")?;
    let direct3d_device: windows::Graphics::DirectX::Direct3D11::IDirect3DDevice =
        direct3d_device.cast()?;
    println!("  IDirect3DDevice wrapped");

    // Step 4: pick a monitor. WGC needs an HMONITOR; primary is the
    // safe default for the spike. M3's system worker will use the
    // monitor associated with the input-desktop's window station.
    let hmon: HMONITOR = unsafe {
        MonitorFromPoint(
            windows::Win32::Foundation::POINT { x: 0, y: 0 },
            MONITOR_DEFAULTTOPRIMARY,
        )
    };
    if hmon.0.is_null() {
        bail!("MonitorFromPoint returned null HMONITOR");
    }
    println!("  HMONITOR resolved");

    // Step 5: GraphicsCaptureItem via interop. This is the most likely
    // failure point in session 0 / Winlogon — the secure desktop's
    // capture permission story is murky on older Win11 builds.
    let interop: IGraphicsCaptureItemInterop =
        windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()
            .context("GraphicsCaptureItem factory")?;
    let item: GraphicsCaptureItem = unsafe { interop.CreateForMonitor(hmon) }
        .context("IGraphicsCaptureItemInterop::CreateForMonitor")?;
    let size: SizeInt32 = item.Size().context("GraphicsCaptureItem::Size")?;
    println!("  CaptureItem created size={}x{}", size.Width, size.Height);

    // Step 6: free-threaded frame pool. CreateFreeThreaded means
    // FrameArrived fires on a WinRT thread pool, not on the calling
    // thread's apartment.
    let frame_pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &direct3d_device,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        2,
        size,
    )
    .context("Direct3D11CaptureFramePool::CreateFreeThreaded")?;
    println!("  FramePool::CreateFreeThreaded ok");

    // Step 7: capture session + frame counter.
    let session = frame_pool
        .CreateCaptureSession(&item)
        .context("CreateCaptureSession")?;

    let arrived = Arc::new(AtomicU32::new(0));
    let first_size: Arc<Mutex<Option<(i32, i32)>>> = Arc::new(Mutex::new(None));

    {
        let arrived = arrived.clone();
        let first_size = first_size.clone();
        let handler =
            TypedEventHandler::<Direct3D11CaptureFramePool, windows::core::IInspectable>::new(
                move |sender, _| {
                    if let Some(s) = sender.as_ref()
                        && let Ok(frame) = s.TryGetNextFrame()
                    {
                        arrived.fetch_add(1, Ordering::Relaxed);
                        if let Ok(content_size) = frame.ContentSize() {
                            let mut g = first_size.lock().unwrap();
                            if g.is_none() {
                                *g = Some((content_size.Width, content_size.Height));
                            }
                        }
                    }
                    Ok(())
                },
            );
        frame_pool
            .FrameArrived(&handler)
            .context("FramePool::FrameArrived register")?;
    }

    session.StartCapture().context("StartCapture")?;
    println!("  StartCapture ok — waiting for frames...");

    // Step 8: wait until we hit the requested frame count or the
    // timeout, whichever comes first.
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    while Instant::now() < deadline {
        if arrived.load(Ordering::Relaxed) >= frames {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let got = arrived.load(Ordering::Relaxed);
    let first = *first_size.lock().unwrap();
    println!("  frames_arrived={got} (target {frames})");
    if let Some((w, h)) = first {
        println!("  first_frame_content_size = {w}x{h}");
    } else {
        println!("  first_frame_content_size = <none>");
    }

    // Stop the capture before tearing down (the WGC docs are
    // emphatic about this).
    let _ = session.Close();
    let _ = frame_pool.Close();

    if got == 0 {
        bail!(
            "system-capture-smoke FAILED on desktop={after:?}: no frames arrived within {timeout_ms} ms"
        );
    }

    println!("system-capture-smoke PASSED on desktop={after:?}: {got} frames in <={timeout_ms} ms");
    Ok(())
}

/// Create an `ID3D11Device` with the BGRA-support flag WGC requires.
/// Returns the device + immediate context; we discard the context but
/// keep its drop slot in the signature for clarity.
fn create_d3d_device() -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let levels = [
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0,
    ];
    let mut device: Option<ID3D11Device> = None;
    let mut ctx: Option<ID3D11DeviceContext> = None;
    let mut feat = Default::default();
    // SAFETY: All buffers are alive for the call; out-pointers are
    // owned Options the OS fills in. Driver type Hardware is the
    // canonical WGC choice.
    let hr = unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            Some(&mut feat),
            Some(&mut ctx),
        )
    };
    hr.ok().context("D3D11CreateDevice")?;
    let device = device.context("D3D11CreateDevice returned no device")?;
    let ctx = ctx.context("D3D11CreateDevice returned no context")?;
    Ok((device, ctx))
}

/// RAII for `RoUninitialize`. Mirrors the wgc_backend.rs pattern but
/// duplicated here so the spike binary doesn't drag in the full
/// capture pipeline.
fn scopeguard_ro_uninit() -> RoUninitGuard {
    RoUninitGuard
}

struct RoUninitGuard;
impl Drop for RoUninitGuard {
    fn drop(&mut self) {
        // SAFETY: paired with the matching RoInitialize at the top
        // of `run`. WinRT requires every successful Initialize to be
        // matched by Uninitialize.
        unsafe {
            RoUninitialize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_target_parses() {
        use std::str::FromStr;
        assert_eq!(
            DesktopTarget::from_str("default").unwrap(),
            DesktopTarget::Default
        );
        assert_eq!(
            DesktopTarget::from_str("Input").unwrap(),
            DesktopTarget::Input
        );
        assert_eq!(
            DesktopTarget::from_str("WINLOGON").unwrap(),
            DesktopTarget::Winlogon
        );
        assert!(DesktopTarget::from_str("nonsense").is_err());
    }
}
