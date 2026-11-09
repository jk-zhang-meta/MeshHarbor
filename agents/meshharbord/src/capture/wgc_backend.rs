// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows.Graphics.Capture (WGC) screen-capture backend.
//!
//! Preferred on Windows 10 1803+. Advantages over the `scrap` /
//! DXGI Desktop Duplication backend:
//!
//! - **Hardware cursor inclusion**: DXGI excludes HW cursor overlays
//!   (Windows composites them post-DXGI), which is why the mouse
//!   disappears over apps like VS Code when the agent uses `scrap`.
//!   WGC produces frames *after* DWM composition, so the cursor is
//!   always there. Our separate cursor data channel (1E.*) is still
//!   useful for sub-frame accuracy + shape identity, but the baseline
//!   frame now carries the cursor.
//!
//! - **Per-frame dirty regions** (Win 11 22000+): `DirtyRegions()` on
//!   the capture frame returns a `IVectorView<RectInt32>` covering
//!   the changed areas. Populated into `Frame::dirty_rects` when
//!   available; the encoder layer uses those for ROI hints (1D.1)
//!   and eventual encode-only-when-dirty VFR (1F.1 step 2).
//!
//! - **Multi-monitor, HDR, per-display capture**: works cleanly per
//!   monitor via `GraphicsCaptureItemInterop::CreateForMonitor(hmon)`,
//!   where `scrap` is primary-monitor-only today.
//!
//! Architecture mirrors [`super::scrap_backend::ScrapCapture`]:
//!
//! - Pinned worker OS thread runs `RoInitialize(MTA)` + WGC session.
//! - `Direct3D11CaptureFramePool::CreateFreeThreaded` means the
//!   frame-pool's `FrameArrived` event fires on a WinRT thread pool;
//!   the handler converts the frame to BGRA and stashes it in a
//!   shared slot.
//! - `next_frame()` on the async side awaits a `Notify` signal that
//!   the slot is populated, then `take()`s the frame. Missed frames
//!   are silently dropped (the slot holds only the newest).
//!
//! Fallback: if any init step fails (Windows too old, WinRT broken,
//! D3D11 device creation, frame pool) the caller (`capture::open_default`)
//! demotes to `scrap` then `NoopCapture` — the agent keeps running.

#![cfg(all(target_os = "windows", feature = "wgc-capture"))]

use anyhow::{Context, Result, anyhow};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use windows::Foundation::TypedEventHandler;
use windows::Graphics::Capture::{Direct3D11CaptureFramePool, GraphicsCaptureItem};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Graphics::SizeInt32;
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_11_0,
    D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_FLAG, D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
    D3D11_CREATE_DEVICE_FLAG, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::Graphics::Gdi::{HMONITOR, MONITOR_DEFAULTTOPRIMARY, MonitorFromPoint};
use windows::Win32::System::WinRT::Direct3D11::{
    CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
};
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::{IInspectable, Interface};

use super::d3d11_scale::BgraScaler;
use super::pointer::{PointerRequest, RecordedPointer};
use super::{Damage, DirtyRect, DownscalePolicy, Frame, PixelFormat, ScreenCapture};

/// Number of buffers in the frame pool. `2` is the canonical WGC
/// default — one frame is being decoded by the OS while the other is
/// being read by our handler. Higher values smooth over jitter but add
/// end-to-end latency; one is the minimum the API accepts.
const FRAME_POOL_BUFFERS: i32 = 2;

/// How long `next_frame()` waits for the worker to produce a frame
/// before returning `Ok(None)`. Matches scrap's 100 ms budget so the
/// caller's pacing logic behaves identically across backends.
const NEXT_FRAME_TIMEOUT: Duration = Duration::from_millis(100);

/// Shared state between the async `next_frame` caller and the WinRT
/// `FrameArrived` event handler. The handler publishes the latest
/// frame and signals `notify`; `next_frame` waits on the notify,
/// then `take()`s the slot. Semantics are "latest frame wins" — if a
/// new frame arrives before the async side reads, the old one is
/// dropped, matching scrap's DXGI behaviour.
struct SharedSlot {
    latest: Mutex<Option<FramePayload>>,
    output_cap: Mutex<Option<(u32, u32)>>,
    notify: Notify,
    /// Total `FrameArrived` events the handler processed. Includes
    /// frames that were later dropped because the slot was occupied.
    /// Diagnostic: at steady-state this should equal the monitor's
    /// refresh rate × elapsed seconds; if it's much lower the WGC
    /// pipeline itself is producing fewer frames (Intel iGPU under
    /// contention, GPU schedule starvation).
    arrived_total: std::sync::atomic::AtomicU64,
    /// Times the handler replaced a still-un-consumed payload in the
    /// slot. High values mean the encode path can't keep up with
    /// the capture rate. Ratio against `arrived_total` is the
    /// interesting number.
    dropped_stale: std::sync::atomic::AtomicU64,
    /// FR-118 P0 — successful CPU readbacks (`copy_to_cpu`), and the time they
    /// took, in the handler. Off the pump's clock, so `avg_capture_ms` cannot
    /// see it; [`ScreenCapture::readback_totals`] reports it.
    readback_total: std::sync::atomic::AtomicU64,
    readback_us_total: std::sync::atomic::AtomicU64,
}

/// Internal frame representation carried from the event handler to
/// the async reader. Kept separate from `capture::Frame` so the
/// handler's hot path doesn't allocate the outer struct when nobody
/// is reading.
struct FramePayload {
    bgra: Vec<u8>,
    width: u32,
    height: u32,
    stride: u32,
    captured_at: Instant,
    damage: Damage,
    /// Phase B — native dims when the handler GPU-scaled before the
    /// readback; `None` = the payload is native-sized.
    source: Option<(u32, u32)>,
}

/// Cap on accumulated damage rects (slot unions can grow the list). Past
/// this the localisation is worthless — collapse to a full-frame rect,
/// which stays motion-TRUE (over-reports area, never under).
const MAX_DAMAGE_RECTS: usize = 256;

const GPU_RETRY_AFTER: Duration = Duration::from_secs(60);

/// One instance per capture device. The callback holds its mutex through
/// readback and publication, serializing the immediate context and caches.
#[derive(Default)]
struct ReadbackState {
    staging: Arc<Mutex<Option<ID3D11Texture2D>>>,
    scaler: Option<BgraScaler>,
    failed_at: Option<Instant>,
}

impl ReadbackState {
    fn try_scaled(
        &mut self,
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        texture: &ID3D11Texture2D,
        native: (u32, u32),
        cap: Option<(u32, u32)>,
    ) -> Option<(Vec<u8>, (u32, u32))> {
        if matches!(
            tunnel_core::env::node_env("GPU_SCALE").as_deref(),
            Some("0") | Some("false")
        ) {
            return None;
        }
        let (width, height) = cap?;
        let output = crate::encode::resample::target_dims(
            native,
            crate::peer::TargetResolution::Fixed { width, height },
        );
        if output == native {
            return None;
        }
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { texture.GetDesc(&mut desc) };
        if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM
            || (desc.Width, desc.Height) != native
            || desc.SampleDesc.Count != 1
        {
            return None;
        }
        if self
            .failed_at
            .is_some_and(|when| when.elapsed() < GPU_RETRY_AFTER)
        {
            return None;
        }
        self.failed_at = None;
        let result = (|| -> std::result::Result<Vec<u8>, String> {
            if self
                .scaler
                .as_ref()
                .is_none_or(|s| !s.matches(native, output))
            {
                self.scaler = Some(BgraScaler::new(device, context, native, output)?);
            }
            self.scaler
                .as_mut()
                .ok_or("WGC scaler cache missing")?
                .read(texture)
        })();
        match result {
            Ok(bytes) => Some((bytes, output)),
            Err(error) => {
                self.scaler = None;
                self.failed_at = Some(Instant::now());
                tracing::warn!(%error, retry_s = GPU_RETRY_AFTER.as_secs(),
                    "wgc: GPU scale unavailable — using native readback and CPU resample fallback");
                None
            }
        }
    }
}

pub struct WgcCapture {
    shared: Arc<SharedSlot>,
    width: u32,
    height: u32,
    monitor: u8,
    target_frame_period: Duration,
    last_frame_at: Option<Instant>,
    /// A relaxed cap needs a new initial WGC image even on a static desktop.
    /// Consumed before either gate can deliver an old scaled slot.
    reopen_for_cap_lift: bool,
    /// FR-98 C1 — `Some` when this open runs the slot-first gate
    /// (`MESHHARBORD_CAPTURE_GATE=slot_first`); `None` keeps the legacy gate
    /// above, whose code path is unchanged.
    slot_first: Option<super::gate::SlotFirst>,
    /// FR-119 P2b — the gate the open chose, which a rate moved back to 60 or
    /// below returns to (`set_target_fps`).
    gate_mode: super::gate::GateMode,
    /// FR-119 P2b-3 — the captured monitor's refresh rate, read at the open.
    refresh_hz: Option<u16>,
    // Retained for constructor compatibility. The pump's effective output
    // cap controls GPU scaling; its CPU resampler remains the fallback.
    _downscale: DownscalePolicy,
    // Kept alive so the worker thread doesn't outlive the handle.
    _worker: thread::JoinHandle<()>,
    _shutdown: Arc<std::sync::atomic::AtomicBool>,
    start: Instant,
    /// FR-85 P1d — the session was opened with cursor capture ON, so the
    /// pointer is in every frame (a recording's session; or the live one
    /// under `MESHHARBORD_WGC_CURSOR=1`).
    pointer_in_frame: bool,
}

/// FR-85 P1d — whether a WGC session draws the pointer into its frames.
///
/// ⚠️ The live path stays OFF unless `MESHHARBORD_WGC_CURSOR=1`: it streams the
/// pointer on its own channel, and a baked one would show twice, the baked
/// copy lagging by the video's latency. A recording has no other channel, so
/// it is always ON there.
fn bake_cursor(request: PointerRequest, env_escape_hatch: bool) -> bool {
    request == PointerRequest::InFrame || env_escape_hatch
}

impl WgcCapture {
    /// Build a capture bound to the system's primary monitor. Fails
    /// early if D3D11 / WinRT / WGC is unavailable; the caller treats
    /// `Err` as "fall back to scrap".
    pub fn primary(target_fps: u32, downscale: DownscalePolicy) -> Result<Self> {
        Self::primary_with(target_fps, downscale, PointerRequest::Separate)
    }

    /// [`Self::primary`], saying whether the pointer belongs in the frames
    /// (FR-85 P1d: a recording asks for it; the live path does not).
    pub fn primary_with(
        target_fps: u32,
        downscale: DownscalePolicy,
        pointer: PointerRequest,
    ) -> Result<Self> {
        let hmon = unsafe {
            // (0, 0) + DEFAULTTOPRIMARY yields the primary monitor's
            // HMONITOR regardless of whether the origin is inside it
            // (Windows returns the primary if no monitor matches).
            MonitorFromPoint(
                windows::Win32::Foundation::POINT { x: 0, y: 0 },
                MONITOR_DEFAULTTOPRIMARY,
            )
        };
        if hmon.is_invalid() {
            return Err(anyhow!(
                "MonitorFromPoint returned NULL — no primary display?"
            ));
        }
        Self::for_monitor(hmon, 0, target_fps, downscale, pointer)
    }

    /// Build a capture bound to an explicit HMONITOR. `monitor_index`
    /// is the logical index used by `DisplayInfo` and the `Frame::monitor`
    /// field so higher layers can distinguish multi-monitor streams.
    pub fn for_monitor(
        hmon: HMONITOR,
        monitor_index: u8,
        target_fps: u32,
        downscale: DownscalePolicy,
        pointer: PointerRequest,
    ) -> Result<Self> {
        let pointer_in_frame = bake_cursor(pointer, tunnel_core::env::flag("WGC_CURSOR", false));
        let shared = Arc::new(SharedSlot {
            latest: Mutex::new(None),
            output_cap: Mutex::new(None),
            notify: Notify::new(),
            arrived_total: std::sync::atomic::AtomicU64::new(0),
            dropped_stale: std::sync::atomic::AtomicU64::new(0),
            readback_total: std::sync::atomic::AtomicU64::new(0),
            readback_us_total: std::sync::atomic::AtomicU64::new(0),
        });
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Passed into the worker thread — the `HMONITOR` is a raw
        // pointer (usize) and is not Send by default, so cast to u64
        // for transport.
        let hmon_value = hmon.0 as u64;
        let shared_for_worker = shared.clone();
        let shutdown_for_worker = shutdown.clone();

        // Ready-ack channel so init failures surface synchronously to
        // the caller instead of silently starving next_frame().
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<SizeInt32>>();

        let worker = thread::Builder::new()
            .name("meshharbord-wgc-capture".into())
            .spawn(move || {
                let hmon = HMONITOR(hmon_value as *mut _);
                if let Err(e) = worker_main(
                    hmon,
                    shared_for_worker,
                    shutdown_for_worker,
                    pointer_in_frame,
                    ready_tx.clone(),
                ) {
                    tracing::error!(%e, "wgc worker init failed");
                    let _ = ready_tx.send(Err(e));
                }
            })
            .context("spawning wgc worker thread")?;

        // Wait up to 2 s for init (D3D11 device + WGC session setup is
        // usually <200 ms but we allow slack for slow GPUs). If the wait
        // fails or times out, signal `shutdown` before returning so a
        // late-finishing worker exits immediately without starting capture
        // or leaking its D3D11/WinRT objects.
        let size = match ready_rx.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(size)) => size,
            Ok(Err(e)) => {
                shutdown.store(true, std::sync::atomic::Ordering::Release);
                return Err(e);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                shutdown.store(true, std::sync::atomic::Ordering::Release);
                return Err(anyhow!("wgc worker didn't ack within 2s"));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                shutdown.store(true, std::sync::atomic::Ordering::Release);
                return Err(anyhow!("wgc worker channel disconnected before ack"));
            }
        };

        // FR-98 C1 — read once per open (FR-70: never per frame).
        let gate_mode = super::gate::GateMode::from_env();
        // FR-119 P2b-3 — so is the monitor's refresh rate.
        let refresh_hz = super::refresh::of_monitor(hmon.0 as usize);
        tracing::info!(
            gate = gate_mode.as_str(),
            target_fps,
            ?refresh_hz,
            "wgc capture gate"
        );
        Ok(Self {
            shared,
            width: size.Width.max(0) as u32,
            height: size.Height.max(0) as u32,
            monitor: monitor_index,
            target_frame_period: super::gate::legacy_period(target_fps),
            last_frame_at: None,
            reopen_for_cap_lift: false,
            slot_first: (gate_mode == super::gate::GateMode::SlotFirst)
                .then(|| super::gate::SlotFirst::new(target_fps)),
            gate_mode,
            refresh_hz,
            _downscale: downscale,
            _worker: worker,
            _shutdown: shutdown,
            start: Instant::now(),
            pointer_in_frame,
        })
    }

    /// FR-98 C1 — the slot first: a frame that is already waiting goes out
    /// now, unless the source is outrunning the target, and only then does
    /// the gate pace it (`capture::gate`). The legacy gate in `next_frame`
    /// sleeps first and looks second.
    async fn next_frame_slot_first(&mut self) -> Result<Option<Frame>> {
        let mut payload = self.shared.latest.lock().unwrap().take();
        if payload.is_none() {
            // Same wait as the legacy path: bail with None on timeout so the
            // pump can loop and decide idle behaviour (keepalive).
            let notified = self.shared.notify.notified();
            tokio::pin!(notified);
            if tokio::time::timeout(NEXT_FRAME_TIMEOUT, &mut notified)
                .await
                .is_err()
            {
                return Ok(None);
            }
            payload = self.shared.latest.lock().unwrap().take();
        }
        let Some(mut payload) = payload else {
            return Ok(None);
        };
        let Some(gate) = self.slot_first.as_mut() else {
            return Ok(Some(self.frame_from_payload(payload)));
        };
        let wait = gate.wait(Instant::now());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
            // A fresher frame may have landed while the source was paced.
            if let Some(newer) = self.shared.latest.lock().unwrap().take() {
                payload = merge_stale_damage(payload, newer);
            }
        }
        gate.took(Instant::now());
        Ok(Some(self.frame_from_payload(payload)))
    }

    fn frame_from_payload(&mut self, payload: FramePayload) -> Frame {
        // Keep the last delivered native geometry even after the slot is empty.
        // A cap relaxation after a resize must compare against this geometry.
        (self.width, self.height) = payload.source.unwrap_or((payload.width, payload.height));
        payload_to_frame(payload, self.monitor, self.start)
    }

    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
}

impl Drop for WgcCapture {
    fn drop(&mut self) {
        self._shutdown
            .store(true, std::sync::atomic::Ordering::Release);
        // The worker's event loop checks `shutdown` on each tick; the
        // `TypedEventHandler`'s closures hold the shared state via Arc
        // so they drop cleanly once the session closes. We don't
        // join() because worker may be in a PumpMessages() blocking
        // call; the thread exits when the session closes and Arc
        // refcounts reach zero.
    }
}

#[async_trait::async_trait]
impl ScreenCapture for WgcCapture {
    async fn next_frame(&mut self) -> Result<Option<Frame>> {
        // WGC does not emit FrameArrived on an unchanged desktop. Reopening
        // delivers its initial image, so idle refine can regain lost detail.
        if std::mem::take(&mut self.reopen_for_cap_lift) {
            return Err(anyhow!(
                "wgc: output cap relaxed — reopen capture for a fresh frame"
            ));
        }
        if self.slot_first.is_some() {
            return self.next_frame_slot_first().await;
        }
        // FPS gate — same shape as scrap.
        if let Some(last) = self.last_frame_at {
            let elapsed = last.elapsed();
            if elapsed < self.target_frame_period {
                tokio::time::sleep(self.target_frame_period - elapsed).await;
            }
        }
        self.last_frame_at = Some(Instant::now());

        // Fast path: a frame is already waiting in the slot.
        let payload = self.shared.latest.lock().unwrap().take();
        if let Some(payload) = payload {
            return Ok(Some(self.frame_from_payload(payload)));
        }

        // Wait for the handler to notify; bail with None on timeout
        // so the pump can loop + decide idle behaviour (keepalive).
        let wait = {
            let notified = self.shared.notify.notified();
            tokio::pin!(notified);
            tokio::time::timeout(NEXT_FRAME_TIMEOUT, &mut notified).await
        };
        if wait.is_err() {
            return Ok(None);
        }

        let Some(payload) = self.shared.latest.lock().unwrap().take() else {
            // Handler fired but another reader beat us to the slot
            // (shouldn't happen with a single reader, but be robust).
            return Ok(None);
        };
        Ok(Some(self.frame_from_payload(payload)))
    }

    fn readback_totals(&self) -> Option<(u64, u64)> {
        let frames = self
            .shared
            .readback_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let us = self
            .shared
            .readback_us_total
            .load(std::sync::atomic::Ordering::Relaxed);
        Some((frames, us))
    }

    fn set_output_cap(&mut self, target: Option<(u32, u32)>) {
        let mut cap = self.shared.output_cap.lock().unwrap();
        if *cap == target {
            return;
        }
        // Prefer the newest payload's native geometry after a resize. The
        // callback releases its cap snapshot lock before publishing a payload.
        let native = self
            .shared
            .latest
            .lock()
            .unwrap()
            .as_ref()
            .map_or((self.width, self.height), |payload| {
                payload.source.unwrap_or((payload.width, payload.height))
            });
        let effective = |cap: Option<(u32, u32)>| {
            cap.map_or(native, |(width, height)| {
                crate::encode::resample::target_dims(
                    native,
                    crate::peer::TargetResolution::Fixed { width, height },
                )
            })
        };
        let old = effective(*cap);
        let new = effective(target);
        // None→Some at startup and tightening need no recovery. Compare the
        // effective dimensions so zero/native/oversized boxes agree with scaling.
        // Like DXGI, a full lift always requests a fresh initial image.
        self.reopen_for_cap_lift |=
            cap.is_some() && (target.is_none() || new.0 > old.0 || new.1 > old.1);
        *cap = target;
    }

    /// FR-119 P2b — both gates move in place. Above 60 the slot-first gate
    /// runs whatever the open chose (`GateMode::at_fps`), with a fresh bucket
    /// at the new period; at 60 or below the open's own gate comes back.
    fn set_target_fps(&mut self, fps: u32) {
        let gate = super::gate::GateMode::at_fps(self.gate_mode, fps);
        self.target_frame_period = super::gate::legacy_period(fps);
        self.slot_first =
            (gate == super::gate::GateMode::SlotFirst).then(|| super::gate::SlotFirst::new(fps));
        tracing::info!(gate = gate.as_str(), fps, "wgc capture gate moved");
    }

    fn backend(&self) -> &'static str {
        "wgc"
    }

    fn refresh_hz(&self) -> Option<u16> {
        self.refresh_hz
    }

    fn monitor_count(&self) -> u8 {
        // scrap is authoritative for "how many displays are there?" —
        // we piggy-back on its enumeration rather than re-wrapping
        // `EnumDisplayMonitors`. Falls back to 1 on any error.
        #[cfg(feature = "scrap-capture")]
        {
            scrap::Display::all()
                .map(|v| v.len().min(u8::MAX as usize) as u8)
                .unwrap_or(1)
        }
        #[cfg(not(feature = "scrap-capture"))]
        {
            1
        }
    }

    fn recorded_pointer(&mut self) -> RecordedPointer {
        // A session opened with cursor capture on draws the pointer itself —
        // shape, position and hardware cursor included. On a Windows build
        // before 2004, where the switch does not exist, WGC always draws it.
        if self.pointer_in_frame {
            RecordedPointer::InFrame
        } else {
            RecordedPointer::Absent
        }
    }
}

/// Translate an internal `FramePayload` into the public `Frame` type.
/// Preserve the handler's output dimensions and native-source metadata;
/// the encoder's existing CPU resampler remains the fallback.
fn payload_to_frame(payload: FramePayload, monitor: u8, start: Instant) -> Frame {
    let monotonic_us = payload
        .captured_at
        .saturating_duration_since(start)
        .as_micros() as u64;
    Frame {
        width: payload.width,
        height: payload.height,
        stride: payload.stride,
        pixel_format: PixelFormat::Bgra,
        data: payload.bgra,
        monotonic_us,
        monitor,
        damage: payload.damage,
        source: payload.source,
    }
}

/// Pinned-worker main. Initialises WinRT MTA, builds the D3D11
/// device + IDirect3DDevice, creates the frame pool + session, wires
/// the `FrameArrived` handler, then parks until shutdown.
fn worker_main(
    hmon: HMONITOR,
    shared: Arc<SharedSlot>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    bake_cursor: bool,
    ready_tx: std::sync::mpsc::Sender<Result<SizeInt32>>,
) -> Result<()> {
    // Pin the process-wide COM MTA apartment open once so `windows-core` v0.58.0's
    // process-global `FactoryCache` (`windows-core-0.58.0/src/imp/factory_cache.rs`:
    // `FactoryCache::call` at lines 31-65 and `pub fn factory<C, I>()` at lines 73-99)
    // never holds a dangling activation-factory pointer across sessions after a WGC
    // worker thread's `RoUninitializeGuard` drops:
    // - `FactoryCache::call` (lines 35-40) loads `self.shared` (`AtomicPtr<c_void>`) and,
    //   when non-null, immediately invokes the callback on the cached pointer (`assume_vtable`
    //   + vtable slot call); on first use (lines 43-57) it calls `factory::<C, I>()?`,
    //   checks `IAgileObject`, CAS-stores `factory.as_raw()` into `self.shared`, and calls
    //   `forget(factory)`.
    // - `factory::<C, I>()` (lines 79-91) calls `RoGetActivationFactory` and ONLY calls
    //   `CoIncrementMTAUsage(&mut cookie)` when `code == CO_E_NOTINITIALIZED` (line 89).
    //   Because `worker_main` calls `RoInitialize(RO_INIT_MULTITHREADED)` on the worker
    //   thread, `RoGetActivationFactory` returns `S_OK` on Session 1 without `factory()`
    //   ever calling `CoIncrementMTAUsage`.
    // - Verified by A/B reproduction (`f91109a56af15d9e` on `696daf379 + 82220862b`
    //   without `MTA_PIN`): Session 1 succeeds and closes (`RoUninitializeGuard::drop` ->
    //   `RoUninitialize()`), and Session 2 crashes with `0xc0000005` (`Fault offset:
    //   0x0109b764`, symbolized via `addr2line` / `objdump` at `0x14109b764: call *0x30(%rax)`
    //   in `Direct3D11CaptureFramePool::CreateFreeThreaded::{{closure}}` at
    //   `windows-0.58.0/src/Windows/Graphics/Capture/mod.rs:332` inlined into
    //   `FactoryCache<Direct3D11CaptureFramePool, IDirect3D11CaptureFramePoolStatics2>::call`
    //   at `windows-core-0.58.0/src/imp/factory_cache.rs:39` on the cached `self.shared`
    //   fast path). With `MTA_PIN` present, 5/5 consecutive sessions in `f91109ab6af14fd2`
    //   and 14/14 sessions in the full suite completed in the same process with 0 crashes.
    static MTA_PIN: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    MTA_PIN.get_or_init(|| {
        let _ = unsafe { windows::Win32::System::Com::CoIncrementMTAUsage() };
    });

    let init_t0 = Instant::now();
    tracing::debug!(hmon = hmon.0 as usize, "wgc worker_main: step 0 entry");

    // RoInitialize must be called on every thread that touches WinRT
    // objects; MTA because we run free-threaded (no UI loop needed).
    // SAFETY: the corresponding `RoUninitialize` runs at function exit.
    unsafe {
        RoInitialize(RO_INIT_MULTITHREADED)
            .ok()
            .context("RoInitialize(MTA)")?;
    }
    let _ro_guard = RoUninitializeGuard;
    tracing::debug!(
        elapsed_us = init_t0.elapsed().as_micros() as u64,
        "wgc worker_main: step 1 RoInitialize(RO_INIT_MULTITHREADED) ok"
    );

    // 1. Create an ID3D11Device (+ context) we'll use for: (a) wrapping
    //    as IDirect3DDevice for the frame pool, (b) CopyResource
    //    from the capture frame to a staging texture for CPU readback.
    let (d3d_device, d3d_context) = create_d3d11_device()?;
    tracing::debug!(
        elapsed_us = init_t0.elapsed().as_micros() as u64,
        "wgc worker_main: step 2 create_d3d11_device ok"
    );

    // 2. Wrap the D3D11 device as the WinRT `IDirect3DDevice` that
    //    Direct3D11CaptureFramePool::CreateFreeThreaded expects.
    //    The wrapper holds a strong reference to the D3D11 device;
    //    dropping the wrapper later is the correct cleanup.
    let dxgi_device: IDXGIDevice = d3d_device
        .cast()
        .map_err(|e| anyhow!("ID3D11Device -> IDXGIDevice cast: {e:?}"))?;
    let winrt_inspectable: IInspectable =
        unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi_device)? };
    let winrt_device: IDirect3DDevice = winrt_inspectable
        .cast()
        .map_err(|e| anyhow!("IInspectable -> IDirect3DDevice cast: {e:?}"))?;
    tracing::debug!(
        elapsed_us = init_t0.elapsed().as_micros() as u64,
        "wgc worker_main: step 3 CreateDirect3D11DeviceFromDXGIDevice ok"
    );

    // 3. Build the GraphicsCaptureItem for the target monitor via the
    //    Win32 interop interface (there's no pure-WinRT entry point
    //    for HMONITOR on Windows).
    let item: GraphicsCaptureItem = unsafe {
        let interop: IGraphicsCaptureItemInterop =
            windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
        tracing::debug!(
            elapsed_us = init_t0.elapsed().as_micros() as u64,
            "wgc worker_main: step 4a GraphicsCaptureItem factory ok"
        );
        interop.CreateForMonitor(hmon)?
    };
    let size = item.Size()?;
    tracing::debug!(
        elapsed_us = init_t0.elapsed().as_micros() as u64,
        width = size.Width,
        height = size.Height,
        "wgc worker_main: step 4b CreateForMonitor + Size ok"
    );
    if size.Width <= 0 || size.Height <= 0 {
        return Err(anyhow!(
            "GraphicsCaptureItem reports zero-sized monitor ({} x {})",
            size.Width,
            size.Height
        ));
    }

    // 4. Create the frame pool + session. CreateFreeThreaded means
    //    FrameArrived can fire on any thread, which is fine because
    //    our handler locks a Mutex + notifies a tokio Notify (both
    //    Send + Sync). The alternative (`Create`, non-free-threaded)
    //    would require a UI thread with a message pump.
    let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &winrt_device,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        FRAME_POOL_BUFFERS,
        size,
    )?;
    tracing::debug!(
        elapsed_us = init_t0.elapsed().as_micros() as u64,
        "wgc worker_main: step 5a CreateFreeThreaded ok"
    );
    let session = pool.CreateCaptureSession(&item)?;
    tracing::debug!(
        elapsed_us = init_t0.elapsed().as_micros() as u64,
        "wgc worker_main: step 5b CreateCaptureSession ok"
    );

    // Hide the yellow border WGC draws around the captured surface on
    // Windows 11 by default (operators don't want a "screen is being
    // captured" indicator on the AGENT; we'll add our own later per
    // the viewer-indicator plan). Property is available on
    // GraphicsCaptureSession since Windows 11 22000+; silently ignore
    // if the setter doesn't exist on older builds.
    let _ = session.SetIsBorderRequired(false);
    // Keep the OS cursor OUT of the encoded frame by default: the agent
    // streams the cursor over a separate low-latency channel and the
    // browser renders either the native OS cursor (via the CSS keyword
    // hint) or the shape bitmap. Baking it in too would double the
    // cursor (baked one lags at video latency behind the low-latency
    // overlay). Escape hatch: MESHHARBORD_WGC_CURSOR=1 re-bakes it
    // without a rebuild if a field regression appears. FR-85 P1d: a
    // RECORDING's session always bakes it — the file has no other channel
    // (`bake_cursor`, decided by the constructor).
    let _ = session.SetIsCursorCaptureEnabled(bake_cursor);
    tracing::debug!(
        elapsed_us = init_t0.elapsed().as_micros() as u64,
        "wgc worker_main: step 5c session properties configured, sending ready_tx ack"
    );

    // Size is known now — ack to the constructor so it can return. If the
    // constructor already timed out (`shutdown` set or `ready_rx` dropped),
    // close the pool/session and exit immediately so we never leak the
    // worker thread or D3D11/WinRT objects.
    if shutdown.load(std::sync::atomic::Ordering::Acquire) || ready_tx.send(Ok(size)).is_err() {
        tracing::warn!(
            elapsed_us = init_t0.elapsed().as_micros() as u64,
            width = size.Width,
            height = size.Height,
            "wgc: caller timed out before init ack — closing session/pool and exiting worker without StartCapture"
        );
        session.Close().ok();
        pool.Close().ok();
        return Ok(());
    }

    // 5. Register the FrameArrived handler. State captured into the
    //    closure: the frame pool (for TryGetNextFrame), a reusable
    //    readback/cache state, the d3d context (for CopyResource +
    //    Map), and the shared slot + notify.
    let readback = Arc::new(Mutex::new(ReadbackState::default()));
    let handler_d3d_device = d3d_device.clone();
    let handler_d3d_context = d3d_context.clone();
    let handler_shared = shared.clone();
    let handler_readback = readback.clone();

    let handler =
        TypedEventHandler::<Direct3D11CaptureFramePool, IInspectable>::new(move |sender, _args| {
            let Some(pool) = sender.as_ref() else {
                return Ok(());
            };
            // Free-threaded callbacks can overlap. Keep context operations,
            // reusable textures and publication in the same frame order.
            let mut readback = handler_readback.lock().unwrap();
            let output_cap = *handler_shared.output_cap.lock().unwrap();
            let frame = match pool.TryGetNextFrame() {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(%e, "wgc: TryGetNextFrame failed");
                    return Ok(());
                }
            };
            let content_size = frame.ContentSize().unwrap_or(SizeInt32 {
                Width: 0,
                Height: 0,
            });
            let w = content_size.Width.max(0) as u32;
            let h = content_size.Height.max(0) as u32;
            if w == 0 || h == 0 {
                return Ok(());
            }

            // Extract the underlying ID3D11Texture2D from the WinRT
            // IDirect3DSurface via IDirect3DDxgiInterfaceAccess.
            let Some(gpu_tex) = surface_to_d3d11_texture(&frame) else {
                return Ok(());
            };

            // Scale while GPU-resident when possible. A contained failure
            // immediately takes the unchanged native-copy path.
            let readback_started = Instant::now();
            let scaled = readback.try_scaled(
                &handler_d3d_device,
                &handler_d3d_context,
                &gpu_tex,
                (w, h),
                output_cap,
            );
            let (bgra, (out_w, out_h), source) = match scaled {
                Some((bytes, output)) => (bytes, output, Some((w, h))),
                None => match copy_to_cpu(
                    &handler_d3d_device,
                    &handler_d3d_context,
                    &readback.staging,
                    &gpu_tex,
                    w,
                    h,
                ) {
                    Ok(bytes) => (bytes, (w, h), None),
                    Err(e) => {
                        tracing::debug!(%e, "wgc: CPU readback failed");
                        return Ok(());
                    }
                },
            };
            // FR-118 P0 — counted only when it succeeded, like a frame.
            handler_shared.readback_us_total.fetch_add(
                readback_started.elapsed().as_micros() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            handler_shared
                .readback_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let stride = out_w * 4;

            // DirtyRegions() lands on the IDirect3D11CaptureFrame2
            // interface (newer Windows 11 SDK generations). Any failure
            // to read a COMPLETE, non-empty region list degrades to
            // Damage::Unknown — never a shorter "authoritative" list
            // (P8a: under-reported damage reads as a false settle).
            let native_damage = collect_damage(&frame, w, h);
            let damage = if source.is_some() {
                super::scale_damage(&native_damage, w, h, out_w, out_h)
            } else {
                native_damage
            };

            let mut payload = FramePayload {
                bgra,
                width: out_w,
                height: out_h,
                stride,
                captured_at: Instant::now(),
                damage,
                source,
            };
            let arrived = handler_shared
                .arrived_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            let had_stale = {
                let mut slot = handler_shared.latest.lock().unwrap();
                // P8a — "latest wins" must not LOSE the stale payload's
                // damage: the consumer's last-seen frame predates it, so
                // the replacement's damage is a delta against a frame
                // nobody read. A dimensions or native-source mismatch
                // changes coordinate spaces and degrades to Unknown.
                let prev = slot.take();
                let had_stale = prev.is_some();
                if let Some(prev) = prev {
                    payload = merge_stale_damage(prev, payload);
                }
                *slot = Some(payload);
                had_stale
            };
            if had_stale {
                handler_shared
                    .dropped_stale
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            // Every 120 arrivals (~2 s at 60 Hz) log the drop ratio so
            // we can see in the field whether the encode consumer is
            // keeping up with the capture producer. Silent after the
            // first log if nothing is dropping.
            if arrived.is_multiple_of(120) {
                let drops = handler_shared
                    .dropped_stale
                    .load(std::sync::atomic::Ordering::Relaxed);
                tracing::info!(
                    arrived,
                    drops,
                    drop_ratio_pct = (drops * 100) / arrived.max(1),
                    "wgc: capture cadence"
                );
            }
            handler_shared.notify.notify_waiters();
            Ok(())
        });
    let _token = pool.FrameArrived(&handler)?;

    session.StartCapture()?;
    tracing::info!(
        width = size.Width,
        height = size.Height,
        "wgc: capture session started"
    );

    // 6. Park until shutdown; worker thread stays alive so the COM
    //    objects (session, frame pool) don't drop and their event
    //    handlers keep firing. Poll the shutdown flag every 100 ms —
    //    cheap and eliminates the need for a real message pump since
    //    CreateFreeThreaded dispatches events via the system thread
    //    pool, not this thread.
    while !shutdown.load(std::sync::atomic::Ordering::Acquire) {
        thread::sleep(Duration::from_millis(100));
    }

    session.Close().ok();
    pool.Close().ok();
    tracing::info!("wgc: capture session closed");
    Ok(())
}

/// Builds a new `ID3D11Device` + `ID3D11DeviceContext` tuned for WGC:
/// BGRA support (needed to read the capture surface's format), driver
/// type `HARDWARE`, feature-level cascade starting at 11_1. The device
/// is created bound to the default adapter — multi-GPU hosts where
/// the capture target lives on a non-default adapter would need
/// `EnumAdapters1` + adapter-bound `D3D11CreateDevice`; defer until
/// that's a real field issue.
fn create_d3d11_device() -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let feature_levels = [
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0,
    ];
    let attempt = |flags: D3D11_CREATE_DEVICE_FLAG| {
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        let mut actual_level = D3D_FEATURE_LEVEL_11_0;
        unsafe {
            D3D11CreateDevice(
                None, // default adapter
                D3D_DRIVER_TYPE_HARDWARE,
                windows::Win32::Foundation::HMODULE::default(),
                flags,
                Some(&feature_levels),
                D3D11_SDK_VERSION,
                Some(&mut device),
                Some(&mut actual_level),
                Some(&mut context),
            )
        }
        .map(|_| (device, context))
    };
    let (device, context) = match attempt(
        D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
    ) {
        Ok(pair) => pair,
        Err(error) => {
            tracing::info!(%error, "wgc: VIDEO_SUPPORT device unavailable — retrying original BGRA device");
            attempt(D3D11_CREATE_DEVICE_BGRA_SUPPORT)
                .map_err(|e| anyhow!("D3D11CreateDevice for WGC: {e:?}"))?
        }
    };
    let device = device.ok_or_else(|| anyhow!("D3D11CreateDevice returned null device"))?;
    let context = context.ok_or_else(|| anyhow!("D3D11CreateDevice returned null context"))?;
    Ok((device, context))
}

/// Create only the production device/context, without a monitor, capture item,
/// frame pool or session. Used by the offscreen readback benchmark.
#[cfg(test)]
pub(crate) fn test_d3d_device() -> std::result::Result<(ID3D11Device, ID3D11DeviceContext), String>
{
    create_d3d11_device().map_err(|error| error.to_string())
}

/// Cast the frame's `IDirect3DSurface` down to `ID3D11Texture2D` via
/// the WinRT DXGI interop access interface.
fn surface_to_d3d11_texture(
    frame: &windows::Graphics::Capture::Direct3D11CaptureFrame,
) -> Option<ID3D11Texture2D> {
    let surface = frame.Surface().ok()?;
    let access: IDirect3DDxgiInterfaceAccess = surface.cast().ok()?;
    unsafe { access.GetInterface::<ID3D11Texture2D>() }.ok()
}

/// Copy the GPU capture texture to a CPU-readable staging texture and
/// return a packed top-down BGRA Vec. Reuses (and re-creates on size
/// change) a staging texture held in `staging_slot` so we don't churn
/// the allocator on every frame.
fn copy_to_cpu(
    device: &ID3D11Device,
    context: &ID3D11DeviceContext,
    staging_slot: &Arc<Mutex<Option<ID3D11Texture2D>>>,
    gpu_tex: &ID3D11Texture2D,
    w: u32,
    h: u32,
) -> Result<Vec<u8>> {
    unsafe {
        // Reuse or rebuild the staging texture.
        let mut slot = staging_slot.lock().unwrap();
        let staging = match slot.as_ref() {
            Some(tex) => {
                // Check cached size matches current.
                let mut desc = D3D11_TEXTURE2D_DESC::default();
                tex.GetDesc(&mut desc);
                if desc.Width == w && desc.Height == h {
                    tex.clone()
                } else {
                    let fresh = create_staging_texture(device, w, h)?;
                    *slot = Some(fresh.clone());
                    fresh
                }
            }
            None => {
                let fresh = create_staging_texture(device, w, h)?;
                *slot = Some(fresh.clone());
                fresh
            }
        };
        drop(slot);

        // GPU → staging copy (fast; DMA over PCIe).
        context.CopyResource(&staging, gpu_tex);

        // Map + read.
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        context
            .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
            .map_err(|e| anyhow!("Map staging: {e:?}"))?;
        let row_pitch = mapped.RowPitch as usize;
        let packed_row = (w as usize) * 4;
        let mut bgra = vec![0u8; packed_row * h as usize];
        let src_ptr = mapped.pData as *const u8;
        for row in 0..h as usize {
            let src = src_ptr.add(row * row_pitch);
            let dst = bgra.as_mut_ptr().add(row * packed_row);
            std::ptr::copy_nonoverlapping(src, dst, packed_row);
        }
        context.Unmap(&staging, 0);

        Ok(bgra)
    }
}

/// Offscreen benchmark baseline: reuse precisely the legacy staging cache and
/// native copy. The caller serializes use of its immediate context.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct NativeReadbackForTest {
    staging: Arc<Mutex<Option<ID3D11Texture2D>>>,
}

#[cfg(test)]
impl NativeReadbackForTest {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn read(
        &self,
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        texture: &ID3D11Texture2D,
        width: u32,
        height: u32,
    ) -> std::result::Result<Vec<u8>, String> {
        copy_to_cpu(device, context, &self.staging, texture, width, height)
            .map_err(|error| error.to_string())
    }
}

fn create_staging_texture(device: &ID3D11Device, w: u32, h: u32) -> Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: w,
        Height: h,
        MipLevels: 1,
        ArraySize: 1,
        Format: windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_STAGING,
        BindFlags: D3D11_BIND_FLAG(0).0 as u32,
        CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
        MiscFlags: 0,
    };
    let mut out: Option<ID3D11Texture2D> = None;
    unsafe {
        device
            .CreateTexture2D(&desc, None, Some(&mut out))
            .map_err(|e| anyhow!("CreateTexture2D staging {w}x{h}: {e:?}"))?;
    }
    out.ok_or_else(|| anyhow!("CreateTexture2D returned null"))
}

/// Pull the per-frame damage from the capture frame. `Tracked` only
/// when a COMPLETE, non-empty region list was read; every degraded
/// case is `Unknown` (P8a):
/// - the `IDirect3D11CaptureFrame2` cast fails (OS without the API),
/// - `Size()`/`GetAt` errors (a partial list would under-report damage
///   — the false-settle direction),
/// - the list is empty or fully clipped away: WGC frames arrive
///   BECAUSE something changed, so "changed but zero damage" is
///   self-contradictory — an OS build that systematically reports
///   empty regions must fall back to the bytes leg, not silently
///   disable motion detection.
fn collect_damage(
    frame: &windows::Graphics::Capture::Direct3D11CaptureFrame,
    w: u32,
    h: u32,
) -> Damage {
    let Ok(view) = frame.DirtyRegions() else {
        return Damage::Unknown;
    };
    let Ok(size) = view.Size() else {
        return Damage::Unknown;
    };
    if size == 0 {
        return Damage::Unknown;
    }
    let mut out = Vec::with_capacity((size as usize).min(MAX_DAMAGE_RECTS));
    for i in 0..size {
        let Ok(r) = view.GetAt(i) else {
            return Damage::Unknown;
        };
        let x = (r.X.max(0) as u32).min(w);
        let y = (r.Y.max(0) as u32).min(h);
        let rw = (r.Width.max(0) as u32).min(w.saturating_sub(x));
        let rh = (r.Height.max(0) as u32).min(h.saturating_sub(y));
        if rw > 0 && rh > 0 {
            out.push(DirtyRect { x, y, w: rw, h: rh });
        }
    }
    if out.is_empty() {
        return Damage::Unknown;
    }
    if out.len() > MAX_DAMAGE_RECTS {
        return Damage::Tracked(vec![DirtyRect { x: 0, y: 0, w, h }]);
    }
    Damage::Tracked(out)
}

fn merge_stale_damage(prev: FramePayload, mut next: FramePayload) -> FramePayload {
    let same_space =
        (prev.width, prev.height, prev.source) == (next.width, next.height, next.source);
    next.damage = union_damage(prev.damage, next.damage, same_space);
    next
}

/// Merge a dropped-stale payload's damage into its replacement (P8a).
/// `same_dims` false (mid-session resize) ⇒ the rect coordinate spaces
/// differ ⇒ `Unknown`; `Unknown` on either side is contagious.
fn union_damage(prev: Damage, next: Damage, same_dims: bool) -> Damage {
    if !same_dims {
        return Damage::Unknown;
    }
    match (prev, next) {
        (Damage::Tracked(mut a), Damage::Tracked(mut b)) => {
            a.append(&mut b);
            if a.len() > MAX_DAMAGE_RECTS {
                // Collapse to the bounding box — motion-true, coarse.
                let x0 = a.iter().map(|r| r.x).min().unwrap_or(0);
                let y0 = a.iter().map(|r| r.y).min().unwrap_or(0);
                let x1 = a.iter().map(|r| r.x + r.w).max().unwrap_or(0);
                let y1 = a.iter().map(|r| r.y + r.h).max().unwrap_or(0);
                return Damage::Tracked(vec![DirtyRect {
                    x: x0,
                    y: y0,
                    w: x1.saturating_sub(x0),
                    h: y1.saturating_sub(y0),
                }]);
            }
            Damage::Tracked(a)
        }
        _ => Damage::Unknown,
    }
}

/// RAII guard that calls RoUninitialize on drop. Paired with the
/// `RoInitialize(MTA)` call at worker start.
struct RoUninitializeGuard;
impl Drop for RoUninitializeGuard {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No monitor, WinRT session, callback, or GPU resource is created.
    fn static_scaled_capture(gate_mode: super::super::gate::GateMode) -> WgcCapture {
        WgcCapture {
            shared: Arc::new(SharedSlot {
                latest: Mutex::new(Some(FramePayload {
                    bgra: vec![7; 4 * 2 * 4],
                    width: 4,
                    height: 2,
                    stride: 4 * 4,
                    captured_at: Instant::now(),
                    damage: Damage::Unknown,
                    source: Some((8, 4)),
                })),
                output_cap: Mutex::new(Some((4, 2))),
                notify: Notify::new(),
                arrived_total: std::sync::atomic::AtomicU64::new(0),
                dropped_stale: std::sync::atomic::AtomicU64::new(0),
                readback_total: std::sync::atomic::AtomicU64::new(0),
                readback_us_total: std::sync::atomic::AtomicU64::new(0),
            }),
            width: 8,
            height: 4,
            monitor: 0,
            target_frame_period: Duration::ZERO,
            last_frame_at: None,
            reopen_for_cap_lift: false,
            slot_first: (gate_mode == super::super::gate::GateMode::SlotFirst)
                .then(|| super::super::gate::SlotFirst::new(30)),
            gate_mode,
            refresh_hz: None,
            _downscale: DownscalePolicy::Auto,
            _worker: thread::spawn(|| {}),
            _shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            start: Instant::now(),
            pointer_in_frame: false,
        }
    }

    #[tokio::test]
    async fn static_cap_relaxation_reopens_before_scaled_slot_for_both_gates() {
        use super::super::gate::GateMode;
        for gate in [GateMode::Legacy, GateMode::SlotFirst] {
            for target in [None, Some((6, 3)), Some((0, 2)), Some((16, 8))] {
                let mut capture = static_scaled_capture(gate);
                capture.set_output_cap(target);
                // A repeated setter must not cancel the pending recovery.
                capture.set_output_cap(target);
                assert_eq!(*capture.shared.output_cap.lock().unwrap(), target);
                let error = capture.next_frame().await.err().expect("must reopen");
                assert!(error.to_string().contains("output cap relaxed"));
                assert!(!capture.reopen_for_cap_lift, "recovery is consumed once");
                let slot = capture.shared.latest.lock().unwrap();
                assert_eq!(slot.as_ref().unwrap().bgra, vec![7; 32]);
                assert_eq!(slot.as_ref().unwrap().source, Some((8, 4)));
            }
        }
    }

    #[tokio::test]
    async fn consumed_resized_payload_keeps_native_geometry_for_cap_relaxation() {
        use super::super::gate::GateMode;
        for gate in [GateMode::Legacy, GateMode::SlotFirst] {
            for target in [None, Some((6, 3))] {
                let mut capture = static_scaled_capture(gate);
                // The display grew after this capture opened. Its queued 4x2
                // payload was scaled from 8x4; both caps exceed the old size.
                capture.width = 2;
                capture.height = 1;
                let frame = capture.next_frame().await.unwrap().unwrap();
                assert_eq!(frame.native_dims(), (8, 4));
                assert_eq!((capture.width(), capture.height()), (8, 4));
                assert!(capture.shared.latest.lock().unwrap().is_none());
                capture.set_output_cap(target);
                let error = capture.next_frame().await.err().expect("must reopen");
                assert!(error.to_string().contains("output cap relaxed"));
            }
        }
    }

    #[tokio::test]
    async fn initial_cap_and_tightening_do_not_reopen() {
        use super::super::gate::GateMode;
        for gate in [GateMode::Legacy, GateMode::SlotFirst] {
            let mut capture = static_scaled_capture(gate);
            for initial in [Some((4, 2)), Some((16, 2))] {
                *capture.shared.output_cap.lock().unwrap() = None;
                capture.set_output_cap(initial);
                assert!(!capture.reopen_for_cap_lift);
            }
            *capture.shared.output_cap.lock().unwrap() = Some((4, 2));
            capture.set_output_cap(Some((2, 2)));
            let frame = capture.next_frame().await.unwrap().unwrap();
            assert_eq!(frame.data, vec![7; 32]);
            assert!(!capture.reopen_for_cap_lift);
        }
    }

    #[test]
    fn stale_damage_cannot_cross_native_or_scaled_coordinate_spaces() {
        let payload = |source| FramePayload {
            bgra: Vec::new(),
            width: 640,
            height: 360,
            stride: 640 * 4,
            captured_at: Instant::now(),
            source,
            damage: Damage::Tracked(vec![DirtyRect {
                x: 2,
                y: 2,
                w: 4,
                h: 4,
            }]),
        };
        for (old, new) in [
            (None, Some((1920, 1080))),
            (Some((1920, 1080)), None),
            (Some((1920, 1080)), Some((2560, 1440))),
        ] {
            assert!(matches!(
                merge_stale_damage(payload(old), payload(new)).damage,
                Damage::Unknown
            ));
        }
        let merged = merge_stale_damage(payload(Some((1920, 1080))), payload(Some((1920, 1080))));
        assert!(matches!(merged.damage, Damage::Tracked(ref rects) if rects.len() == 2));
    }

    /// FR-85 P1d. The live session keeps the pointer out of its frames
    /// unless the escape hatch says otherwise (it streams the pointer on its
    /// own channel); a recording's session always draws it in.
    #[test]
    fn only_a_recording_or_the_escape_hatch_bakes_the_pointer() {
        assert!(!bake_cursor(PointerRequest::Separate, false));
        assert!(bake_cursor(PointerRequest::Separate, true));
        assert!(bake_cursor(PointerRequest::InFrame, false));
        assert!(bake_cursor(PointerRequest::InFrame, true));
    }

    /// On a headless host (CI) WGC init usually fails because there's
    /// no primary monitor; we only exercise a clean failure path.
    /// Otherwise we open the backend, grab a frame, and assert basic
    /// shape.
    #[tokio::test]
    async fn primary_monitor_capture_or_clean_failure() {
        let mut cap = match WgcCapture::primary(30, DownscalePolicy::Auto) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("no WGC-capable display ({e}) — skipping");
                return;
            }
        };
        assert!(cap.width() > 0, "width should be > 0 on a real display");
        assert!(cap.height() > 0, "height should be > 0 on a real display");
        assert!(cap.monitor_count() >= 1);

        // A real frame may take several ticks to land (the capture
        // session emits frames only on screen change). Budget ~1s.
        let mut got = None;
        for _ in 0..20 {
            if let Some(f) = cap.next_frame().await.unwrap() {
                got = Some(f);
                break;
            }
        }
        let Some(frame) = got else {
            eprintln!("no frame within 2s on a static desktop — skipping assertions");
            return;
        };
        assert!(frame.width > 0);
        assert!(frame.height > 0);
        assert_eq!(frame.pixel_format, PixelFormat::Bgra);
        assert_eq!(frame.data.len(), (frame.width * frame.height * 4) as usize);
        assert_eq!(frame.stride, frame.width * 4);
    }
}
