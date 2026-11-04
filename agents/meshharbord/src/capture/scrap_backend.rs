// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Cross-platform screen capture backed by the `scrap` crate.
//!
//! `scrap` is a thin wrapper that picks the right kernel primitive per OS:
//!   - Linux  → XShm (X11 shared-memory pixmap)
//!   - Windows → DXGI Desktop Duplication
//!   - macOS  → CoreGraphics `CGDisplayStream` fallback
//!
//! `scrap::Capturer` is `!Send` (XShm handles have thread affinity), so we
//! pin it to a dedicated OS thread and drive it via oneshot commands: the
//! async `next_frame` sends a oneshot sender, the worker captures, fills
//! the oneshot. That keeps the async runtime free while respecting the
//! underlying thread-affinity requirement.
//!
//! BGRA is always emitted (scrap's native format); the encoder layer is
//! responsible for any colour conversion.

use anyhow::{Context, Result, anyhow};
use scrap::{Capturer, Display};
use std::io::ErrorKind::WouldBlock;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

use super::{
    DOWNSCALE_TRIGGER_PIXELS, Damage, DownscalePolicy, Frame, PixelFormat, ScreenCapture,
    downscale_bgra_2x,
};

pub const DEFAULT_TARGET_FPS: u32 = 30;

/// Bounded retry for a transient `Capturer::new` failure at init. On Windows a
/// `permission denied` (E_ACCESSDENIED) here means the input desktop is
/// mid-transition — UAC secure desktop up, a just-completed logon, or a
/// fast-user-switch — and clears within a few hundred ms once the user's
/// desktop is back. Without a retry the worker dropped straight to
/// `NoopCapture` (a black screen) with no recovery. 8 × 120 ms ≈ 1 s worst
/// case. Only `PermissionDenied` is retried — a missing display / unsupported
/// adapter won't fix itself with a backoff. No-op on Linux/macOS (succeeds
/// first attempt).
const INIT_MAX_ATTEMPTS: u32 = 8;
const INIT_RETRY_BACKOFF: Duration = Duration::from_millis(120);

type CaptureReply = Result<Option<Frame>>;
type CaptureCmd = oneshot::Sender<CaptureReply>;

/// Packed `(width << 32) | height` for [`ScrapCapture::set_output_cap`].
/// `0` means "no cap — deliver native".
fn pack_dims(w: u32, h: u32) -> u64 {
    ((w as u64) << 32) | (h as u64)
}

pub struct ScrapCapture {
    cmd_tx: std_mpsc::Sender<CaptureCmd>,
    width: u32,
    height: u32,
    monitor: u8,
    target_frame_period: Duration,
    last_frame_at: Option<Instant>,
    /// Phase B — the encode box the pump wants, published to the capture
    /// worker. An atomic rather than a new command variant deliberately: the
    /// command channel is the per-frame hot path and a cap change is rare, so
    /// this keeps the frame path byte-for-byte as it was.
    desired: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// FR-29 — frames the damage tracker proved were unnecessary. Shared with
    /// the worker; surfaced through `ScreenCapture::frames_unchanged`.
    unchanged: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// FR-85 P1d — the captured display's top-left in screen coordinates
    /// (the virtual desktop on Windows, the root window on X11), where a
    /// recording places the pointer. Unused on macOS, which draws its own,
    /// and in a Windows build without the cursor tracker (`mf-encoder`).
    #[cfg_attr(
        any(
            target_os = "macos",
            all(target_os = "windows", not(feature = "mf-encoder"))
        ),
        allow(dead_code)
    )]
    origin: (i32, i32),
    /// FR-119 P2b-3 — the captured display's refresh rate, read at the open.
    refresh_hz: Option<u16>,
}

/// FR-85 P1d — where a display sits in screen coordinates. DXGI's first
/// output need not be the primary monitor, and an X11 monitor is a rectangle
/// of the root window, so neither is assumed to be at (0, 0).
#[cfg(not(target_os = "macos"))]
fn display_origin(d: &Display) -> (i32, i32) {
    d.origin()
}

/// macOS: CoreGraphics draws the pointer into the frame itself, so the
/// origin is never used.
#[cfg(target_os = "macos")]
fn display_origin(_d: &Display) -> (i32, i32) {
    (0, 0)
}

impl ScrapCapture {
    pub fn primary(target_fps: u32, downscale: DownscalePolicy) -> Result<Self> {
        // macOS: a missing Screen Recording grant does NOT fail
        // Capturer::new — CGDisplayStream opens fine and delivers
        // wallpaper-only frames, which reads as "black screen" with an
        // empty log. Preflight and say so; the request call also lands
        // the app in the Screen Recording pane so granting is one toggle.
        #[cfg(target_os = "macos")]
        if !crate::tcc::screen_recording_granted() && !crate::tcc::request_screen_recording() {
            tracing::warn!(
                "macOS Screen Recording permission MISSING — capture will deliver blank/wallpaper-only frames. \
                 Grant it under System Settings → Privacy & Security → Screen Recording, then restart the agent \
                 (launchctl kickstart -k gui/$UID/fans.itachi.meshharbor.agent)"
            );
        }

        // Build the Capturer on the worker thread so it never crosses
        // thread boundaries; use a ready-ack channel to surface any
        // init failure back to the caller synchronously.
        let (ready_tx, ready_rx) = std_mpsc::channel::<Result<(u32, u32, (i32, i32))>>();
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<CaptureCmd>();
        // FR-29 — counted on the worker, read by the pump's heartbeat. Kept
        // separate from `frames_empty` so "idle screen, working as intended"
        // never masquerades as "pump starved".
        let unchanged = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let unchanged_worker = unchanged.clone();
        let desired = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        #[cfg(target_os = "macos")]
        let desired_worker = desired.clone();

        thread::Builder::new()
            .name("roomlerd-capture".into())
            .spawn(move || {
                // macOS — a sleeping display composites nothing, so a stream
                // opened on it never delivers a frame and the viewer hangs up
                // (`power::DisplayAwake`). Taken here, on the thread that owns
                // the capturer, so it lives exactly as long as the capture.
                #[cfg(target_os = "macos")]
                let display_awake = crate::power::DisplayAwake::acquire();
                // Set only when the display was asleep: the field check that
                // waking it is what brought the picture back.
                #[cfg(target_os = "macos")]
                let mut woke_at = display_awake.was_asleep().then(Instant::now);
                let mut attempt: u32 = 0;
                let init_outcome = loop {
                    attempt += 1;
                    let display = match Display::primary() {
                        Ok(d) => d,
                        Err(e) => break Err(anyhow!("no primary display: {e}")),
                    };
                    // FR-85 P1d — read before the capturer consumes the
                    // display: where the pointer's screen coordinates land.
                    let origin = display_origin(&display);
                    match Capturer::new(display) {
                        // Dims come from the CAPTURER, never the Display.
                        //
                        // On macOS the stream is sized in PIXELS while
                        // `Display::width/height` report POINTS, so on a Retina
                        // panel they differ by 2x per axis. Reading them from the
                        // Display would describe every frame with half its true
                        // size — and describing a frame with the wrong height is
                        // precisely the mismatch that sheared macOS capture
                        // before (see `frame_stride`). Elsewhere (DXGI, X11) the
                        // capturer reports the display's own size, so this is a
                        // no-op there.
                        Ok(cap) => {
                            let w = cap.width() as u32;
                            let h = cap.height() as u32;
                            break Ok((cap, w, h, origin));
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::PermissionDenied
                                && attempt < INIT_MAX_ATTEMPTS =>
                        {
                            tracing::warn!(
                                attempt,
                                max = INIT_MAX_ATTEMPTS,
                                %e,
                                "scrap::Capturer::new permission denied (input desktop mid-transition) — backing off + retrying"
                            );
                            thread::sleep(INIT_RETRY_BACKOFF);
                            continue;
                        }
                        Err(e) => break Err(anyhow!("creating scrap::Capturer: {e}")),
                    }
                };
                #[allow(unused_mut)]
                let (mut cap, mut w, mut h, origin) = match init_outcome {
                    Ok(v) => {
                        let _ = ready_tx.send(Ok((v.1, v.2, v.3)));
                        v
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let start = Instant::now();
                #[cfg(target_os = "macos")]
                let mut applied: u64 = 0;
                // The display's TRUE pixel size, tracked independently of the
                // stream's output size. This is what frames report as their
                // `source` when the stream is opened at the encode box — the
                // pump's cap decision keys on native dims, and feeding it the
                // CAPPED dims closed a feedback loop that re-opened the stream
                // every frame (capped frame ⇒ "no cap needed" ⇒ reopen native
                // ⇒ native frame ⇒ "cap!" ⇒ reopen capped ⇒ …), ~30 rebuilds/s,
                // no codec able to stream — field 2026-08-26 on the MacBook.
                // Reassigned only by the macOS stream-rebuild block below, so
                // every other target sees an unused `mut`. Scoped allow rather
                // than dropping `mut`, which would break the macOS build.
                #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
                let mut native_w = w;
                #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
                let mut native_h = h;
                #[cfg(target_os = "macos")]
                let mut last_reopen = Instant::now();

                // FR-29 P1 — built HERE, on the capture worker, because an
                // X11 connection has the same thread affinity the XShm
                // capturer does. `None` = tracking unavailable or switched
                // off, in which case every tick captures exactly as before.
                #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                let mut damage = super::x11_damage::DamageTracker::open();
                // FR-97 P3a — XShm frames carry no pointer, so the worker reads
                // it from XFixes for the cursor channel, on a connection of its
                // own, built here for the same thread affinity. `None` = no
                // XFixes or switched off: the viewer draws its stand-in.
                #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                let mut x11_cursor = super::x11_cursor::X11Cursor::open(origin);
                #[cfg(not(all(target_os = "linux", feature = "scrap-capture")))]
                let _ = origin;
                // FR-108 P2 — the X11 capturer takes its size when it opens, so
                // a display-match switch on the virtual desktop opens it again.
                #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                let mut seen_mode = crate::display_match::mode_generation();
                #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                let mut reopen_tried: Option<Instant> = None;

                // Wait for capture requests.
                while let Ok(res_tx) = cmd_rx.recv() {
                    #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                    {
                        let now_mode = crate::display_match::mode_generation();
                        if now_mode != seen_mode
                            && reopen_tried.is_none_or(|t| t.elapsed() >= Duration::from_millis(500))
                        {
                            reopen_tried = Some(Instant::now());
                            match Display::primary().and_then(Capturer::new) {
                                Ok(c) => {
                                    let (was_w, was_h) = (w, h);
                                    w = c.width() as u32;
                                    h = c.height() as u32;
                                    native_w = w;
                                    native_h = h;
                                    cap = c;
                                    damage = super::x11_damage::DamageTracker::open();
                                    seen_mode = now_mode;
                                    reopen_tried = None;
                                    tracing::info!(
                                        was_w,
                                        was_h,
                                        w,
                                        h,
                                        "capture: the display mode changed — opened again at the new size (FR-108 P2)"
                                    );
                                }
                                Err(e) => tracing::warn!(
                                    %e,
                                    "capture: the display mode changed but the capturer did not open again — retrying"
                                ),
                            }
                        }
                    }
                    // Phase B (macOS) — re-open the CGDisplayStream at the
                    // encode box so CoreGraphics does the reduction on the GPU.
                    // Capturing native and CPU-resampling to the same size cost
                    // a measured 38 ms/frame against a 16.7 ms budget, which is
                    // why a SMALLER requested picture used to be slower than
                    // native. Rare event: only when the pump's cap changes.
                    #[cfg(target_os = "macos")]
                    {
                        let want = desired_worker.load(std::sync::atomic::Ordering::Relaxed);
                        // Rate-floor the rebuilds. With `source` reported
                        // correctly the pump's target is stable and this never
                        // engages; it exists so that any FUTURE feedback bug
                        // degrades to one rebuild per second (a survivable
                        // stream + a visible log cadence) instead of a rebuild
                        // per frame (a dead session on every codec).
                        if want != applied && last_reopen.elapsed() >= Duration::from_secs(1) {
                            let (nw, nh) = ((want >> 32) as u32, (want & 0xFFFF_FFFF) as u32);
                            // Query the panel's true pixel size BEFORE the
                            // display is consumed by the capturer build; a
                            // SIZED stream reports the box, not the panel.
                            let rebuilt = if want == 0 {
                                Display::primary().ok().map(|d| {
                                    let pw = d.pixel_width() as u32;
                                    let ph = d.pixel_height() as u32;
                                    (Capturer::new(d).ok(), pw, ph)
                                })
                            } else {
                                Display::primary().ok().map(|d| {
                                    let pw = d.pixel_width() as u32;
                                    let ph = d.pixel_height() as u32;
                                    (
                                        Capturer::new_sized(d, nw as usize, nh as usize).ok(),
                                        pw,
                                        ph,
                                    )
                                })
                            };
                            last_reopen = Instant::now();
                            match rebuilt {
                                Some((Some(c), pw, ph)) => {
                                    w = c.width() as u32;
                                    h = c.height() as u32;
                                    // Plain open delivers the panel itself —
                                    // trust the capturer (it also tracks a
                                    // display-mode change); sized open must
                                    // take the queried panel size.
                                    if want == 0 {
                                        native_w = w;
                                        native_h = h;
                                    } else {
                                        native_w = pw.max(1);
                                        native_h = ph.max(1);
                                    }
                                    cap = c;
                                    applied = want;
                                    tracing::info!(
                                        width = w,
                                        height = h,
                                        native_w,
                                        native_h,
                                        "capture: re-opened the stream at the encode box (CoreGraphics scales; no CPU resample)"
                                    );
                                }
                                Some((None, _, _)) | None => {
                                    // Keep the WORKING capturer rather than
                                    // dropping the session: a refused resize
                                    // costs the optimisation, not the stream.
                                    // Mark it applied so we retry only on the
                                    // next distinct request, not every frame.
                                    applied = want;
                                    tracing::warn!(
                                        width = nw,
                                        height = nh,
                                        "capture: could not re-open at the requested size — keeping the current stream (CPU resample stays the fallback)"
                                    );
                                }
                            }
                        }
                    }
                    // FR-97 P3a — the pointer, on every request and before the
                    // damage check below can skip the frame: a pointer moving
                    // over an unchanged screen damages nothing, and must still
                    // move on the viewer's side.
                    #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                    if let Some(c) = x11_cursor.as_mut() {
                        c.publish();
                    }
                    // FR-29 P1 — skip the full-screen XShm readback when the
                    // server says nothing changed. `Ok(None)` is the pump's
                    // existing idle-screen path (it already logs "capture
                    // produced no frame (idle screen)"), so this makes a path
                    // that always existed reachable on Linux rather than
                    // inventing a new one. The tracker's own safety valve
                    // forces a capture periodically, so a missed damage event
                    // costs a stale tile, never a frozen stream.
                    #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                    // P2 — what the tracker says changed, stamped on the frame
                    // below. `Unknown` is the honest default for every path
                    // that is not damage-driven (tracker absent or switched
                    // off), and matches the pre-FR-29 contract exactly.
                    #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                    let mut frame_damage = Damage::Unknown;
                    #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                    if let Some(d) = damage.as_mut() {
                        match d.tick() {
                            super::x11_damage::Tick::Skip => {
                                unchanged_worker
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let _ = res_tx.send(Ok(None));
                                continue;
                            }
                            super::x11_damage::Tick::Capture(dmg) => frame_damage = dmg,
                        }
                    }
                    #[allow(unused_mut)]
                    let mut reply =
                        capture_one_blocking(&mut cap, w, h, (native_w, native_h), start, downscale);
                    #[cfg(target_os = "macos")]
                    if let (Some(since), Ok(Some(_))) = (woke_at, reply.as_ref()) {
                        tracing::info!(
                            ms = since.elapsed().as_millis() as u64,
                            "capture: the first frame after waking the display"
                        );
                        woke_at = None;
                    }
                    // The tracker reports in ROOT coordinates; a delivered
                    // frame may have been downscaled on the way out, so the
                    // rects have to follow it or every consumer would point at
                    // the wrong pixels.
                    #[cfg(all(target_os = "linux", feature = "scrap-capture"))]
                    if let Ok(Some(f)) = reply.as_mut() {
                        f.damage = if f.width == w && f.height == h {
                            frame_damage
                        } else {
                            super::scale_damage(&frame_damage, w, h, f.width, f.height)
                        };
                    }
                    let _ = res_tx.send(reply);
                }
            })
            .context("spawning capture thread")?;

        let (width, height, origin) = ready_rx
            .recv()
            .context("capture thread never responded")??;

        // FR-119 P2b-3 — the captured display's refresh rate, read once: the
        // primary output on Windows (DXGI) and X11, the main display on macOS.
        #[cfg(target_os = "windows")]
        let refresh_hz = super::refresh::of_primary();
        #[cfg(target_os = "macos")]
        let refresh_hz = super::refresh::of_main_display();
        #[cfg(target_os = "linux")]
        let refresh_hz = super::refresh::of_x11_primary();
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        let refresh_hz = None;
        tracing::info!(?refresh_hz, "scrap capture: the display's refresh rate");

        Ok(Self {
            cmd_tx,
            width,
            height,
            monitor: 0,
            target_frame_period: super::gate::legacy_period(target_fps),
            last_frame_at: None,
            desired,
            unchanged,
            origin,
            refresh_hz,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
}

/// Bytes between the starts of two consecutive rows in a captured frame.
///
/// Deliberately NOT `buf.len() / height` everywhere. That division is exact on
/// two of the three backends and silently wrong on the third, and the failure
/// mode is a progressive shear rather than an error:
///
/// * **X11** allocates exactly `width * height * 4` and **DXGI** reports
///   `height * Pitch`, so on both the quotient IS the pitch.
/// * **macOS** hands back an IOSurface whose slice length is
///   `IOSurfaceGetAllocSize` — the PAGE-ROUNDED TOTAL ALLOCATION. Dividing it
///   by the height overshoots the real pitch, and the result is usually not a
///   multiple of 4, so the BGRA channel phase rotates row to row on top of the
///   shear. It is wrong even when the surface has no row padding at all: the
///   16 KiB page rounding alone is enough. The true value is
///   `IOSurfaceGetBytesPerRow`, which upstream scrap does not bind — hence the
///   vendored patch (`crates/vendored/scrap.patch`).
fn frame_stride(buf: &scrap::Frame<'_>, width: u32, height: u32) -> u32 {
    #[cfg(target_os = "macos")]
    let stride = {
        let bpr = buf.bytes_per_row() as u32;
        debug_assert!(
            u64::from(bpr) * u64::from(height) <= buf.len() as u64,
            "bytes_per_row * height exceeds the surface allocation"
        );
        bpr
    };
    #[cfg(not(target_os = "macos"))]
    let stride = (buf.len() as u32) / height.max(1);

    // A stride under one packed row would read past the end of every row.
    // Clamp instead of trusting the backend blindly.
    stride.max(width.saturating_mul(4))
}

/// The `Frame::source` a scaled delivery must carry: the TRUE panel size when
/// the delivered dims differ from it, `None` for a 1:1 delivery. Feeding the
/// pump capped dims as "native" is the feedback loop documented at the worker's
/// rebuild site — this is the one place the truth gets stamped.
fn native_source(native: (u32, u32), out: (u32, u32)) -> Option<(u32, u32)> {
    (native != out && native.0 > 0 && native.1 > 0).then_some(native)
}

/// The instant the NEXT frame's FPS gate is measured from.
///
/// A backend whose `next_frame` blocks for the readback (DXGI on Windows, XShm
/// on Linux) paces from when the frame was ASKED for (`asked_at`), so the
/// readback overlaps the period instead of being serialised after a full-period
/// sleep. macOS keeps arrival timing (`arrived_at`): its CGDisplayStream
/// self-paces and the reply does not carry a blocking grab. Pure so both
/// branches are unit-tested on every target (the `macos` flag is the real
/// `cfg!(target_os = "macos")` at the one call site).
fn gate_mark(asked_at: Instant, arrived_at: Instant, macos: bool) -> Instant {
    if macos { arrived_at } else { asked_at }
}

fn capture_one_blocking(
    cap: &mut Capturer,
    width: u32,
    height: u32,
    native: (u32, u32),
    start: Instant,
    downscale: DownscalePolicy,
) -> CaptureReply {
    // Give the compositor a budget — if nothing is ready within ~100 ms we
    // return None and let the async side decide whether to retry.
    let deadline = Instant::now() + Duration::from_millis(100);
    loop {
        match cap.frame() {
            Ok(buf) => {
                let stride = frame_stride(&buf, width, height);
                let monotonic_us = start.elapsed().as_micros() as u64;
                let pixel_count = u64::from(width) * u64::from(height);
                let should_downscale = match downscale {
                    DownscalePolicy::Never => false,
                    DownscalePolicy::Always => width >= 2 && height >= 2,
                    DownscalePolicy::Auto => {
                        pixel_count >= DOWNSCALE_TRIGGER_PIXELS && width >= 2 && height >= 2
                    }
                };
                let (data, out_w, out_h, out_stride) = if should_downscale {
                    let (dst, dw, dh) = downscale_bgra_2x(&buf, width, height, stride);
                    (dst, dw, dh, dw * 4)
                } else {
                    (buf.to_vec(), width, height, stride)
                };
                return Ok(Some(Frame {
                    width: out_w,
                    height: out_h,
                    stride: out_stride,
                    pixel_format: PixelFormat::Bgra,
                    data,
                    monotonic_us,
                    monitor: 0,
                    // scrap doesn't expose a dirty-rect API on any
                    // platform; encoder treats empty as "full-frame
                    // dirty" / no ROI hints. WGC backend (1C.1) will
                    // populate this from Direct3D11CaptureFrame::
                    // DirtyRegion() once it lands.
                    damage: Damage::Unknown,
                    // The panel's true size whenever this delivery is scaled
                    // (CG encode-box stream and/or the 2x CPU downscale) —
                    // `Frame::native_dims()` is the pump's cap input and the
                    // cursor pump's coordinate space, and both are wrong the
                    // moment a scaled frame claims to BE native.
                    source: native_source(native, (out_w, out_h)),
                }));
            }
            Err(e) if e.kind() == WouldBlock => {
                if Instant::now() > deadline {
                    return Ok(None);
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(anyhow!("scrap frame error: {e}")),
        }
    }
}

#[async_trait::async_trait]
impl ScreenCapture for ScrapCapture {
    fn frames_unchanged(&self) -> u64 {
        self.unchanged.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// FR-119 P2b — the pace is this side's sleep, so it moves in place. The
    /// legacy gate is kept above 60: this backend has no slot to look at first
    /// (the worker asks the capturer when the pump asks), and its
    /// whole-millisecond period runs a little fast at 120 and 144, so it does
    /// not lock to a phase (`gate::legacy_period`). The macOS stream itself is
    /// unthrottled, so a 120 Hz panel already delivers what this asks for.
    fn set_target_fps(&mut self, fps: u32) {
        self.target_frame_period = super::gate::legacy_period(fps);
    }

    fn backend(&self) -> &'static str {
        "scrap"
    }

    fn refresh_hz(&self) -> Option<u16> {
        self.refresh_hz
    }

    /// Phase B — honour the pump's encode box by re-opening the capture
    /// stream at that size, so CoreGraphics scales on the GPU instead of the
    /// pump resampling on the CPU.
    ///
    /// macOS ONLY. `CGDisplayStreamCreateWithDispatchQueue` takes an
    /// arbitrary output size; DXGI Desktop Duplication and XShm both hand
    /// back the framebuffer as-is, so on those platforms this stays the
    /// documented no-op and the pump's resample remains the truth.
    ///
    /// ⚠️ This is the fix for "a SMALLER picture is slower than native":
    /// Lanczos-3 costs ≈24× the SOURCE area regardless of ratio, measured at
    /// **38 ms/frame** from a 3024×1964 Retina panel against a 16.7 ms budget
    /// at 60 fps. Native was fast only because 1:1 never resamples.
    fn set_output_cap(&mut self, target: Option<(u32, u32)>) {
        let packed = match target {
            // Ignore a degenerate box rather than opening a zero-sized
            // stream — that would be a black session, worse than the resample.
            Some((w, h)) if w >= 2 && h >= 2 => pack_dims(w, h),
            Some(_) => return,
            None => 0,
        };
        self.desired
            .store(packed, std::sync::atomic::Ordering::Relaxed);
    }

    async fn next_frame(&mut self) -> Result<Option<Frame>> {
        // FPS gate.
        if let Some(last) = self.last_frame_at {
            let elapsed = last.elapsed();
            if elapsed < self.target_frame_period {
                tokio::time::sleep(self.target_frame_period - elapsed).await;
            }
        }

        let asked_at = Instant::now();
        let (res_tx, res_rx) = oneshot::channel();
        self.cmd_tx
            .send(res_tx)
            .map_err(|_| anyhow!("capture worker exited"))?;
        let reply = res_rx
            .await
            .map_err(|_| anyhow!("capture worker dropped reply"))?;
        // FR-107's P2b, for X11, extended to Windows (rcfix 2026-11-04): the
        // frame period runs from when this frame was ASKED for, not from when
        // it arrived. `next_frame` BLOCKS here for the whole DXGI/XShm readback
        // (the worker grabs and copies the surface before it replies), so timing
        // the next gate from arrival serialises that readback AFTER a full-period
        // sleep: a 30 fps target then ran at 1000 / (period + readback). Measured
        // on the Surface (Iris Xe, DXGI, software build, static/changing screen):
        // a 30 fps target delivered **19 fps** (52 ms/frame = 33 ms sleep + 19 ms
        // readback) and a 60 fps target 29 fps. Pacing from `asked_at` overlaps
        // the readback with the period and restores ~30 and ~45-55 fps. macOS is
        // the exception: its CGDisplayStream self-paces and does not block in the
        // reply, so arrival timing stays correct there.
        self.last_frame_at = Some(gate_mark(
            asked_at,
            Instant::now(),
            cfg!(target_os = "macos"),
        ));
        let _ = self.monitor; // (exercised below by `monitor_count`)
        reply
    }

    fn monitor_count(&self) -> u8 {
        Display::all()
            .map(|v| v.len().min(u8::MAX as usize) as u8)
            .unwrap_or(1)
    }

    /// FR-85 P1d. CoreGraphics draws the pointer (the vendored scrap patch
    /// asks for `kCGDisplayStreamShowCursor`); DXGI and XShm hand back the
    /// framebuffer without it, so there the recorder draws it.
    fn recorded_pointer(&mut self) -> super::pointer::RecordedPointer {
        use super::pointer::RecordedPointer;
        #[cfg(target_os = "macos")]
        {
            RecordedPointer::InFrame
        }
        #[cfg(target_os = "linux")]
        {
            match super::pointer::X11Pointer::open(self.origin) {
                Some(p) => RecordedPointer::Drawn(Box::new(p)),
                None => RecordedPointer::Absent,
            }
        }
        #[cfg(all(target_os = "windows", feature = "mf-encoder"))]
        {
            RecordedPointer::Drawn(Box::new(super::pointer::WindowsPointer::new(self.origin)))
        }
        #[cfg(any(
            all(target_os = "windows", not(feature = "mf-encoder")),
            not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
        ))]
        {
            RecordedPointer::Absent
        }
    }

    /// FR-93 P2 — on Linux this is the X11 arm. The other platforms have no
    /// arm worth naming to the controller.
    fn arm(&self) -> Option<super::CaptureArm> {
        cfg!(target_os = "linux").then_some(super::CaptureArm::X11)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rcfix 2026-11-04 — the FPS-gate pacing choice. On a readback-blocking
    /// backend (Windows DXGI, Linux XShm) the next gate is timed from the ASK,
    /// so the readback overlaps the frame period; timing it from arrival
    /// serialised the readback after a full-period sleep and ran a 30 fps target
    /// at a measured 19 fps on the Surface. macOS keeps arrival timing (its
    /// stream self-paces). A regression either way silently caps the capture
    /// rate below the target, so both branches are pinned here.
    #[test]
    fn gate_paces_from_the_ask_except_on_macos() {
        let asked = Instant::now();
        let arrived = asked + Duration::from_millis(19); // the readback cost
        // Windows / Linux: pace from the ask — the 19 ms readback overlaps the
        // next period instead of being added on top of it.
        assert_eq!(gate_mark(asked, arrived, false), asked);
        // macOS: pace from arrival — the reply carried no blocking grab.
        assert_eq!(gate_mark(asked, arrived, true), arrived);
    }

    /// The encode box crosses to the capture worker as a packed u64, so the
    /// pack and the worker's unpack have to agree exactly — a mismatch would
    /// re-open the stream at a garbage size, which is a black session rather
    /// than a slow one. Mirrors the worker's `(want >> 32, want & 0xFFFF_FFFF)`.
    #[test]
    fn packed_dims_round_trip() {
        for (w, h) in [
            (1920u32, 1246u32),
            (3024, 1964),
            (2, 2),
            (u32::MAX, u32::MAX),
        ] {
            let packed = pack_dims(w, h);
            assert_eq!(
                ((packed >> 32) as u32, (packed & 0xFFFF_FFFF) as u32),
                (w, h)
            );
        }
        // 0 is reserved for "no cap — deliver native" and must be
        // unreachable from any dimension the guard lets through (w,h >= 2).
        assert_ne!(pack_dims(2, 2), 0);
    }

    /// The feedback-loop lock (field 2026-08-26): a frame delivered at the
    /// encode box MUST report the panel as its `source`, and a 1:1 delivery
    /// must NOT carry one. The pump's cap decision keys on
    /// `Frame::native_dims()`; a capped frame claiming to be native makes the
    /// pump lift the cap, which re-opens the stream at native, which re-engages
    /// the cap — ~30 stream rebuilds per second and a dead session on every
    /// codec.
    #[test]
    fn scaled_delivery_reports_the_panel_as_source() {
        let native = (3024u32, 1964u32);
        // CG stream opened at the encode box → source = panel.
        assert_eq!(native_source(native, (1926, 1252)), Some(native));
        // 1:1 delivery → no source (own dims ARE native).
        assert_eq!(native_source(native, native), None);
        // Degenerate native must never be reported (a poisoned query would
        // otherwise become the pump's cap input).
        assert_eq!(native_source((0, 0), (1926, 1252)), None);
    }

    /// On a headless host there may be no $DISPLAY / X server, so we accept
    /// either a successful capture or a clean construction failure. We only
    /// fail the test if construction *succeeds* but the captured frame
    /// looks wrong.
    #[tokio::test]
    async fn captures_one_frame_if_display_is_available() {
        let Ok(mut cap) = ScrapCapture::primary(30, DownscalePolicy::Auto) else {
            eprintln!("no display available — skipping");
            return;
        };
        assert!(cap.width() > 0);
        assert!(cap.height() > 0);
        assert!(cap.monitor_count() >= 1);

        // Budget a few attempts because the compositor needs to paint once.
        let mut got_frame = None;
        for _ in 0..20 {
            if let Some(f) = cap.next_frame().await.unwrap() {
                got_frame = Some(f);
                break;
            }
        }
        let Some(frame) = got_frame else {
            eprintln!("no frame within budget — compositor may be idle, skipping assertions");
            return;
        };
        // `cap.width()` is the source dim; Frame.width is the output
        // dim, which is floor(source/2) when DownscalePolicy::Auto
        // kicks in on displays ≥ 3.5 Mpx (QHD / 4K). Accept either.
        let src_w = cap.width();
        let src_h = cap.height();
        let down = (u64::from(src_w) * u64::from(src_h)) >= 3_500_000;
        let expected_w = if down { src_w / 2 } else { src_w };
        let expected_h = if down { src_h / 2 } else { src_h };
        assert_eq!(frame.width, expected_w);
        assert_eq!(frame.height, expected_h);
        assert_eq!(frame.pixel_format, PixelFormat::Bgra);
        assert!(
            frame.data.len() >= (frame.width * frame.height * 3) as usize,
            "unexpectedly small capture buffer"
        );

        // `stride >= width * 4` alone was the ONLY stride assertion here, and
        // it is far too weak: the invented macOS stride (allocSize / height)
        // satisfied it while shearing every frame. These three do not.
        assert!(
            frame.stride >= frame.width * 4,
            "stride {} is under one packed row of {} px",
            frame.stride,
            frame.width
        );
        // A BGRA row pitch is a whole number of pixels. `allocSize / height`
        // generally is not — that mismatch is what rotates the channel phase
        // row to row on top of the shear.
        assert_eq!(
            frame.stride % 4,
            0,
            "stride {} is not a whole number of BGRA pixels — it was derived, not read",
            frame.stride
        );
        // Every row the encoder will read has to be inside the buffer.
        assert!(
            (frame.stride as u64) * u64::from(frame.height) <= frame.data.len() as u64,
            "stride {} x height {} overruns the {}-byte buffer",
            frame.stride,
            frame.height,
            frame.data.len()
        );
    }
}
