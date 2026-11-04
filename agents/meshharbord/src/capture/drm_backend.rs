// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-36 P1 — DRM/KMS capture: read the scanout framebuffer from the kernel,
//! **below the compositor**.
//!
//! This exists because a Wayland desktop is uncapturable by every other
//! backend we have: XShm needs an X root window, and `xdg-desktop-portal`'s
//! ScreenCast is structurally an *attended* API — it needs an interactive
//! picker, it only lives inside an active user session, and while the session
//! is LOCKED mutter refuses to create *or restore* a screencast (consuming the
//! saved restore token in the process). A locked host is the normal state of
//! an unattended machine, so the portal refuses in exactly the case remote
//! access exists for. Reading the scanout plane sidesteps the compositor and
//! its permission prompt entirely: one code path for GNOME, KDE, XFCE, X11 —
//! and for no session at all. See `docs/fr/FR-36-wayland-capture.md`.
//!
//! ## What this backend deliberately does NOT do
//!
//! - **No damage tracking.** DRM tells us nothing about which pixels changed,
//!   so every frame it delivers is [`Damage::Unknown`]. What it can tell is
//!   whether anything changed, on a Wayland seat only (FR-93 P3d,
//!   `drm_idle.rs`): a Wayland compositor draws the next frame into another
//!   buffer and flips, so the same buffer with the same sampled rows is the
//!   same picture, and the worker skips that frame (`frames_unchanged` counts
//!   the skips). X11 renders in place into a stable framebuffer (same buffer,
//!   new content), which no buffer check can see, so there every frame is
//!   read, as before. The backend stays **opt-in**; see [`env_enabled`].
//! - **Primary CRTC only.** Multi-monitor is per-CRTC capture with origin and
//!   scale mapping, deferred by the spec.
//! - **No detiling.** Measured on Apple Silicon, the `apple-drm` plane
//!   advertises `DRM_FORMAT_MOD_LINEAR` and nothing else, so a tiled scanout
//!   buffer is not representable there. Tiled-scanout GPUs (Intel `*_RC_CCS`,
//!   Nvidia block-linear) need an EGL import step that is FR-36 P2; until it
//!   lands this backend REFUSES a non-linear modifier rather than emitting
//!   garbage, because garbage pixels read as a codec bug and cost days.

use anyhow::{Result, anyhow, bail};
use drm::Device as BasicDevice;
use drm::control::Device as ControlDevice;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{info, warn};

use drm::buffer::DrmFourcc;
use drm::control::{crtc, framebuffer, plane, property};

use super::drm_cursor::{self, CursorSnapshot, PlaneKind};
use super::drm_idle::{self, IdleGate};
use super::{CursorInfo, Damage, DownscalePolicy, Frame, PixelFormat, ScreenCapture, WaitFor};

/// `/dev/dri/cardN` nodes to probe. The kernel numbers these from 0, but the
/// numbering is NOT stable across kernel upgrades — on the Asahi field host the
/// display controller moved from `card0` to `card2` when the kernel was
/// updated, with the render-only `asahi` node landing on `card1`. Hence the
/// scan-and-discriminate in [`open_display_node`] rather than a fixed path.
const MAX_CARD_INDEX: u32 = 16;

/// A DRM device node. `drm`'s traits are blanket-implemented for anything that
/// can hand over a borrowed fd, so this newtype is the whole adapter.
struct Card(File);

impl AsFd for Card {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl BasicDevice for Card {}
impl ControlDevice for Card {}

/// An `mmap`ed dma-buf, unmapped on drop.
///
/// Held across frames and keyed by the buffer ([`BufferId`]): re-exporting and
/// re-mapping every frame measured 2.07 ms against 1.58 ms for a cached
/// mapping at 1080p, and a compositor cycles through a small set of buffers,
/// so the cache hits nearly always after the first few frames. The export is
/// cheap and runs every frame, to name the buffer; the mapping is what costs.
struct Mapping {
    ptr: *mut libc::c_void,
    len: usize,
}

// SAFETY: the pointer is a private `mmap` of a dma-buf owned by this struct.
// Nothing else aliases it, and `Drop` is the only unmap.
unsafe impl Send for Mapping {}

impl Mapping {
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr`/`len` come from a successful `mmap` and stay valid for
        // the lifetime of `self`; the region is mapped PROT_READ.
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: unmapping exactly what we mapped, once.
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

/// FR-93 P3f — the buffer on the primary plane: its framebuffer id and its
/// dma-buf's inode.
///
/// The kernel reuses a framebuffer id for a new buffer once the old one is
/// gone, so a cache keyed on the id alone could go on reading the old buffer's
/// mapping: a frozen picture (FR-93 §2.3 #6). Every dma-buf has its own inode
/// from Linux 5.3; before that they share one, which leaves the id to tell
/// buffers apart, as before. `0` is a failed `fstat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BufferId {
    fb: framebuffer::Handle,
    inode: u64,
}

/// The cached mapping, and the buffer it maps.
struct Cached {
    id: BufferId,
    mapping: Mapping,
}

/// What a worker keeps between grabs: the CPU mapping of the last buffer
/// (the idle check reads it, and the CPU path repacks from it), and the GPU
/// path's state (FR-107 P3).
struct ReadCache {
    mapping: Option<Cached>,
    gpu: GpuState,
}

/// FR-107 P3 — whether this worker reads the scanout through the GPU.
enum GpuState {
    /// Not opened yet: the first grab tries, on this worker thread, which is
    /// where its EGL context must live.
    Untried,
    Ready(Box<super::drm_gpu::Converter>),
    /// `ROOMLERD_DRM_GPU=0`, no usable GPU, or a GPU pass that failed: the CPU
    /// reads every frame of this capture.
    Off,
}

/// FR-107 P3 — this frame through the GPU, where it is up; `None` hands it to
/// the CPU path. A failure turns the GPU off for the rest of this capture,
/// said once: a GPU that failed once is not trusted with the next frame.
fn via_gpu(
    gpu: &mut GpuState,
    id: BufferId,
    src: &super::drm_gpu::Source,
    sizing: Sizing,
) -> Option<Scaled> {
    if matches!(gpu, GpuState::Untried) {
        *gpu = match super::drm_gpu::Converter::open() {
            Ok(c) => {
                info!(
                    renderer = c.renderer.as_str(),
                    "drm capture: the GPU reads the scanout (FR-107 P3; ROOMLERD_DRM_GPU=0 hands it back to the CPU)"
                );
                GpuState::Ready(Box::new(c))
            }
            Err(e) => {
                info!(
                    error = %format!("{e:#}"),
                    "drm capture: no GPU path here, the CPU reads the scanout (FR-107 P3)"
                );
                GpuState::Off
            }
        };
    }
    let GpuState::Ready(conv) = gpu else {
        return None;
    };
    let out = gpu_out(src.width, src.height, sizing);
    match conv.convert((u32::from(id.fb), id.inode), src, out) {
        Ok(data) => Some(Scaled {
            data,
            width: out.0,
            height: out.1,
            stride: out.0 * 4,
            source: (out != (src.width, src.height)).then_some((src.width, src.height)),
        }),
        Err(e) => {
            warn!(
                error = %format!("{e:#}"),
                "drm capture: a GPU pass failed, the CPU reads the scanout for the rest of this capture (FR-107 P3)"
            );
            *gpu = GpuState::Off;
            None
        }
    }
}

/// FR-107 P3 — the size the GPU renders: exactly the pump's encode box where
/// it is smaller than the source, so the pump's resample passes the frame
/// through untouched; otherwise what the CPU path would deliver.
fn gpu_out(width: u32, height: u32, sizing: Sizing) -> (u32, u32) {
    if let Some((cw, ch)) = sizing.cap
        && cw >= 2
        && ch >= 2
        && cw <= width
        && ch <= height
    {
        return (cw, ch);
    }
    if wants_half(width, height, sizing.policy, None) {
        (width / 2, height / 2)
    } else {
        (width, height)
    }
}

/// Whether a mapping of `mapped` (its buffer and length) still maps buffer
/// `id` at `len` bytes: the same framebuffer over the same buffer, the same
/// size. The framebuffer id alone is not enough (P3f).
fn maps(mapped: Option<(BufferId, usize)>, id: BufferId, len: usize) -> bool {
    mapped == Some((id, len))
}

/// `DRM_CLOEXEC` for the PRIME export: the exported fd must not leak into a
/// child the daemon spawns meanwhile (a helper, a `meshharbor exec` command),
/// where it would hold the screen's buffer.
const DRM_CLOEXEC: u32 = libc::O_CLOEXEC as u32;

/// Something that can close a GEM handle — the [`Card`], or a test's recorder.
trait CloseHandle {
    fn close_handle(&self, handle: drm::buffer::Handle);
}

impl CloseHandle for Card {
    fn close_handle(&self, handle: drm::buffer::Handle) {
        // A failed close leaves one handle open until the fd closes — the old
        // behaviour for every frame — and nothing else can be done about it.
        let _ = ControlDevice::close_buffer(self, handle);
    }
}

/// The GEM handles one `drmModeGetFB2` handed back, closed on drop.
///
/// ⚠️ GETFB2 mints a NEW handle on every call: the kernel runs
/// `drm_gem_handle_create` per buffer object, and closing it is the caller's
/// job (libdrm's `drmCloseBufferHandle`; FFmpeg's kmsgrab does it). drm-rs
/// hands them back as plain ids with no `Drop` — its own docs say to close
/// them — and [`grab`] asks every frame, so before this guard every frame
/// leaked one. Measured on the FR-93 Wayland lab (0.4.125, one DRM viewer
/// session): `drm_gem_handle_create` 115, `drm_gem_handle_delete` 0. They
/// lived until the device fd closed and pinned every scanout buffer the
/// compositor had freed in the meantime.
///
/// Closing right after use is safe for the cached [`Mapping`]: the mmap holds
/// the exported dma-buf, which holds the buffer — neither needs the handle.
struct FbHandles<'a> {
    closer: &'a dyn CloseHandle,
    handles: Vec<drm::buffer::Handle>,
}

impl<'a> FbHandles<'a> {
    fn new(closer: &'a dyn CloseHandle, buffers: [Option<drm::buffer::Handle>; 4]) -> Self {
        Self {
            closer,
            handles: distinct_handles(buffers),
        }
    }
}

impl Drop for FbHandles<'_> {
    fn drop(&mut self) {
        for handle in self.handles.drain(..) {
            self.closer.close_handle(handle);
        }
    }
}

/// GETFB2 repeats a handle across planes that share one buffer object, and a
/// second close of the same handle is an error — so each distinct one, once.
fn distinct_handles(buffers: [Option<drm::buffer::Handle>; 4]) -> Vec<drm::buffer::Handle> {
    let mut out = Vec::with_capacity(4);
    for handle in buffers.into_iter().flatten() {
        if !out.contains(&handle) {
            out.push(handle);
        }
    }
    out
}

/// Runtime gate. **Default OFF** — deliberately the inverse of the usual
/// "kill switch" shape, because switching every Linux host to this backend
/// would silently undo FR-29: the X11 path tracks damage and idles at ~2.8 %
/// of a core, whereas DRM has no damage information at all and, on X11, would
/// grab every frame forever (FR-93 P3d's idle skip is Wayland-only). So a host
/// opts IN (`ROOMLERD_DRM_CAPTURE=1`) — which is what a Wayland or headless
/// host wants — and everything else keeps the existing cascade byte-for-byte.
pub fn env_enabled() -> bool {
    tunnel_core::env::flag("DRM_CAPTURE", false)
}

/// Open the first `/dev/dri/cardN` that is a **display** node.
///
/// The discriminator is `resource_handles()` reporting at least one CRTC and
/// one connector: a render-only node (Asahi's `asahi`, Nvidia's `renderD*`
/// sibling) has neither. Never trust the index — see [`MAX_CARD_INDEX`].
fn open_display_node() -> Result<(Card, String)> {
    let mut tried = 0usize;
    for i in 0..MAX_CARD_INDEX {
        let path = format!("/dev/dri/card{i}");
        let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) else {
            continue;
        };
        tried += 1;
        let card = Card(file);
        let Ok(res) = card.resource_handles() else {
            continue;
        };
        if res.crtcs().is_empty() || res.connectors().is_empty() {
            continue;
        }
        return Ok((card, path));
    }
    bail!(
        "no DRM display node found ({tried} /dev/dri/card* opened, none had CRTCs+connectors). \
         A render-only node is not enough; this needs the display controller."
    )
}

/// One plane's `type`, and the cursor properties this backend reads. Looked up
/// once at open: neither a plane's type nor its property ids change.
struct PlaneEntry {
    handle: plane::Handle,
    kind: Option<PlaneKind>,
    crtc_x: Option<property::Handle>,
    crtc_y: Option<property::Handle>,
    hotspot_x: Option<property::Handle>,
    hotspot_y: Option<property::Handle>,
}

/// Every plane the device shows this fd, with its type and property ids.
///
/// ⚠️ Read AFTER the client caps are set: `UNIVERSAL_PLANES` decides whether
/// the primary plane is listed at all, `ATOMIC` whether `CRTC_X/Y` exist, and
/// on a paravirtual GPU `CURSOR_PLANE_HOTSPOT` whether an atomic client sees
/// the cursor plane.
fn read_planes(card: &Card) -> Vec<PlaneEntry> {
    let Ok(handles) = card.plane_handles() else {
        return Vec::new();
    };
    handles
        .into_iter()
        .map(|handle| {
            let mut entry = PlaneEntry {
                handle,
                kind: None,
                crtc_x: None,
                crtc_y: None,
                hotspot_x: None,
                hotspot_y: None,
            };
            if let Ok(props) = card.get_properties(handle) {
                for (prop, raw) in props.iter() {
                    let Ok(info) = card.get_property(*prop) else {
                        continue;
                    };
                    match info.name().to_bytes() {
                        b"type" => entry.kind = PlaneKind::from_raw(*raw),
                        b"CRTC_X" => entry.crtc_x = Some(*prop),
                        b"CRTC_Y" => entry.crtc_y = Some(*prop),
                        b"HOTSPOT_X" => entry.hotspot_x = Some(*prop),
                        b"HOTSPOT_Y" => entry.hotspot_y = Some(*prop),
                        _ => {}
                    }
                }
            }
            entry
        })
        .collect()
}

/// The live scanout framebuffer on the primary plane, and the CRTC it is on.
///
/// ⚠️ `plane_handles()` returns ONLY overlay planes until
/// `DRM_CLIENT_CAP_UNIVERSAL_PLANES` is set — without it the primary plane is
/// invisible and this returns `None` on a perfectly healthy display. That is a
/// silent empty result, not an error, which is why the cap is set once at open
/// and asserted here by comment rather than discovered again later.
///
/// FR-93 P3 — chosen by the plane's `type` ([`drm_cursor::pick_primary`]).
/// The first bound plane used to stand in for it, on the assumption that
/// cursor and overlay planes are unbound; the cursor plane is bound wherever
/// the pointer shows, and an overlay whenever a compositor scans a video out
/// directly.
fn primary_plane(
    card: &Card,
    planes: &[PlaneEntry],
) -> Option<(framebuffer::Handle, crtc::Handle)> {
    let bound: Vec<_> = planes
        .iter()
        .map(|entry| {
            let live = card
                .get_plane(entry.handle)
                .ok()
                .and_then(|info| Some((info.framebuffer()?, info.crtc()?)));
            (entry.kind, live)
        })
        .collect();
    drm_cursor::pick_primary(&bound)
}

/// FR-93 P3c — kill switch `ROOMLERD_DRM_CURSOR=0`: no cursor-plane read, and
/// none of the client caps it needs. The viewer then shows its own badge for
/// the pointer, as before.
fn cursor_enabled() -> bool {
    tunnel_core::env::flag("DRM_CURSOR", true)
}

/// FR-93 P3d — kill switch `ROOMLERD_DRM_IDLE_SKIP=0`: every frame is read,
/// converted and encoded again, unchanged or not, as before P3d. The caller
/// also needs the seat to show a Wayland session (see `drm_idle.rs`).
pub fn idle_skip_enabled() -> bool {
    tunnel_core::env::flag("DRM_IDLE_SKIP", true)
}

/// FR-93 P3e — kill switch `ROOMLERD_DRM_WAKE_WAIT=0`: a display the
/// compositor switched off reads as it did before P3e. A running session
/// keeps its last frame alive with no reason given, and an open during the
/// blank falls through the cascade.
pub fn wake_wait_enabled() -> bool {
    tunnel_core::env::flag("DRM_WAKE_WAIT", true)
}

/// FR-107 P1 — kill switch `ROOMLERD_DRM_FOLLOW_CAP=0`: the pump's encode box
/// no longer picks the half-size read, and a 4K scanout is read at full size
/// whenever the policy says `Never`, as before.
fn follow_cap_enabled() -> bool {
    tunnel_core::env::flag("DRM_FOLLOW_CAP", true)
}

/// FR-107 P1 — the pump's encode box, packed `(w << 32) | h` (`0`: none), as
/// [`ScreenCapture::set_output_cap`] hands it over and the worker reads it.
fn pack_cap(cap: Option<(u32, u32)>) -> u64 {
    match cap {
        Some((w, h)) if w >= 2 && h >= 2 => (u64::from(w) << 32) | u64::from(h),
        _ => 0,
    }
}

fn unpack_cap(packed: u64) -> Option<(u32, u32)> {
    (packed != 0).then_some(((packed >> 32) as u32, packed as u32))
}

/// What decides one grab's size: the policy the capture opened with, and the
/// pump's encode box at that moment (FR-107 P1, [`wants_half`]).
#[derive(Clone, Copy, Debug)]
struct Sizing {
    policy: DownscalePolicy,
    cap: Option<(u32, u32)>,
}

/// How often a capture whose display is off looks again: no frame period's
/// worth of ioctls while nothing can change, and a wake seen within a quarter
/// of a second.
const DARK_POLL: Duration = Duration::from_millis(250);

/// FR-93 P3e — whether the display is off: a monitor is connected, and no
/// CRTC drives a mode. Measured on GNOME 50 (2026-10-14): its idle blank
/// switches the CRTC off (`enable=0 active=0`, every plane `fb=0`), and the
/// connector stays `connected` with `dpms=Off`. A host with no monitor
/// connected has no display to wake, so it reads `false` and the cascade goes
/// on as before. `None` when the device cannot be read.
fn display_off(card: &Card) -> Option<bool> {
    let res = card.resource_handles().ok()?;
    let connected = res.connectors().iter().any(|&c| {
        card.get_connector(c, false)
            .is_ok_and(|info| info.state() == drm::control::connector::State::Connected)
    });
    if !connected {
        return Some(false);
    }
    let driven = res
        .crtcs()
        .iter()
        .any(|&c| card.get_crtc(c).is_ok_and(|info| info.mode().is_some()));
    Some(!driven)
}

/// FR-93 P3e — [`display_off`] on the display node, for an open that waits
/// for the display to wake. A fresh fd each time: it is asked once a second.
pub fn display_is_off() -> Option<bool> {
    let (card, _) = open_display_node().ok()?;
    display_off(&card)
}

/// FR-93 P3c — the client caps the cursor plane needs, set after
/// `UNIVERSAL_PLANES`. `ATOMIC` exposes `CRTC_X/Y`, which are atomic-only
/// properties. On a paravirtual GPU an atomic client then sees the cursor plane
/// only with `CURSOR_PLANE_HOTSPOT` as well: the kernel hides it otherwise.
/// Neither refusal is fatal. Capture works without them, and the pointer stays
/// the viewer's own badge, as it was before P3c.
fn enable_cursor_caps(card: &Card) -> (bool, bool) {
    let atomic = card
        .set_client_capability(drm::ClientCapability::Atomic, true)
        .is_ok();
    let hotspot = atomic
        && card
            .set_client_capability(drm::ClientCapability::CursorPlaneHotspot, true)
            .is_ok();
    (atomic, hotspot)
}

/// FR-93 P3c — reads the cursor plane on the captured CRTC, once per frame.
#[derive(Default)]
struct CursorReader {
    /// The framebuffer last read, and when.
    fb: Option<framebuffer::Handle>,
    read_at: Option<Instant>,
    pixels: Option<drm_cursor::CursorPixels>,
    /// The shape last built for the wire, by its id.
    shape: Option<(u64, std::sync::Arc<CursorInfo>)>,
    /// One warning per worker for a buffer this cannot read, not one a frame.
    warned: bool,
}

impl CursorReader {
    /// The cursor on `crtc` now, or `None` when no cursor plane is bound there
    /// with a framebuffer (a hidden pointer, a pointer on another CRTC, or a
    /// compositor drawing it into the primary plane, where it is already in
    /// the frame).
    fn read(
        &mut self,
        card: &Card,
        planes: &[PlaneEntry],
        crtc: crtc::Handle,
    ) -> Option<CursorSnapshot> {
        let (entry, fb) = planes
            .iter()
            .filter(|e| e.kind == Some(PlaneKind::Cursor))
            .find_map(|e| {
                let info = card.get_plane(e.handle).ok()?;
                (info.crtc() == Some(crtc)).then_some(())?;
                Some((e, info.framebuffer()?))
            })?;
        let props = card.get_properties(entry.handle).ok()?;
        let value = |want: Option<property::Handle>| -> Option<i32> {
            let want = want?;
            props
                .iter()
                .find(|(prop, _)| **prop == want)
                .map(|(_, raw)| drm_cursor::signed(*raw))
        };
        let at = (value(entry.crtc_x)?, value(entry.crtc_y)?);
        let hotspot = value(entry.hotspot_x).zip(value(entry.hotspot_y));

        let now = Instant::now();
        let stale = self
            .read_at
            .is_none_or(|t| now.duration_since(t) >= drm_cursor::SHAPE_REREAD);
        if self.fb != Some(fb) || stale {
            self.pixels = match read_cursor_pixels(card, fb) {
                Ok(pixels) => pixels,
                Err(e) => {
                    if !self.warned {
                        self.warned = true;
                        tracing::warn!(error = %format!("{e:#}"), "drm cursor: the cursor plane's buffer cannot be read; the viewer keeps its own pointer");
                    }
                    None
                }
            };
            self.fb = Some(fb);
            self.read_at = Some(now);
        }
        let pixels = self.pixels.as_ref()?;
        let ((x, y), in_crop) = drm_cursor::place(at, hotspot, pixels);
        let id = drm_cursor::shape_id(pixels, in_crop);
        let shape = match &self.shape {
            Some((sid, shape)) if *sid == id => shape.clone(),
            _ => {
                let shape = std::sync::Arc::new(drm_cursor::shape_info(pixels, in_crop));
                self.shape = Some((id, shape.clone()));
                shape
            }
        };
        Some(CursorSnapshot {
            x,
            y,
            shape_id: id,
            shape,
            at: now,
        })
    }
}

/// The cursor plane's buffer, straightened and cropped. `Ok(None)` for one
/// with nothing visible in it.
fn read_cursor_pixels(
    card: &Card,
    fb: framebuffer::Handle,
) -> Result<Option<drm_cursor::CursorPixels>> {
    let info = card
        .get_planar_framebuffer(fb)
        .map_err(|e| anyhow!("drmModeGetFB2 on the cursor plane: {e}"))?;
    let _handles = FbHandles::new(card, info.buffers());
    if info.pixel_format() != DrmFourcc::Argb8888 {
        bail!(
            "cursor plane format {:?}, not ARGB8888",
            info.pixel_format()
        );
    }
    if !modifier_is_linear(&info) {
        bail!("cursor plane modifier {:?} is not linear", info.modifier());
    }
    let (width, height) = info.size();
    // Hardware cursors are 64×64 to 512×512; anything else is not a cursor
    // this should be copying every 250 ms.
    if width == 0 || height == 0 || width > 512 || height > 512 {
        bail!("cursor plane is {width}×{height}");
    }
    let pitch = info.pitches()[0];
    let len = pitch as usize * height as usize;
    let handle =
        info.buffers()[0].ok_or_else(|| anyhow!("the cursor framebuffer has no GEM handle"))?;
    let prime = card
        .buffer_to_prime_fd(handle, 0)
        .map_err(|e| anyhow!("PRIME export of the cursor buffer: {e}"))?;
    // SAFETY: a fresh private read-only mapping of the exported dma-buf, sized
    // from the framebuffer's own pitch × height, unmapped when `mapping` drops
    // at the end of this function.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            prime.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        bail!(
            "mmap of the cursor dma-buf failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let mapping = Mapping { ptr, len };
    Ok(drm_cursor::straighten_and_crop(
        mapping.as_slice(),
        width,
        height,
        pitch,
    ))
}

/// How a scanout pixel is laid out — the two facts about its fourcc the
/// repack needs. Every format here is 32 bits per pixel, little-endian.
///
/// ⚠️ **Which order a compositor scans out is the compositor's choice, not
/// the display's.** mutter picked `XR30` on the Apple-silicon (Asahi) Mac
/// mini's display and KWin picked `AB24` on the very same one: same driver,
/// same panel, red and blue in opposite places. A `Layout` is resolved from
/// each framebuffer, never from what the last one was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    /// 2:10:10:10 packed words (`XR30` and friends) rather than 8-bit bytes.
    ten_bit: bool,
    /// Red in the LOW channel — the `XB`/`AB` fourccs (`XBGR8888`: R,G,B,X in
    /// memory) — where the `XR`/`AR` ones keep blue there.
    red_low: bool,
}

impl Layout {
    /// `None` for anything outside the eight 32-bit RGB fourccs.
    fn of(format: DrmFourcc) -> Option<Self> {
        let (ten_bit, red_low) = match format {
            DrmFourcc::Xrgb8888 | DrmFourcc::Argb8888 => (false, false),
            DrmFourcc::Xbgr8888 | DrmFourcc::Abgr8888 => (false, true),
            DrmFourcc::Xrgb2101010 | DrmFourcc::Argb2101010 => (true, false),
            DrmFourcc::Xbgr2101010 | DrmFourcc::Abgr2101010 => (true, true),
            _ => return None,
        };
        Some(Self { ten_bit, red_low })
    }
}

/// Repack one scanout framebuffer into tightly-packed BGRA.
///
/// ⚠️ **The fourcc must be honoured, not assumed.** X11 handed us 8-bit
/// `XR24`, GNOME/mutter handed us 10-bit `XR30` on the same display — and
/// decoding `XR30` with the 8-bit layout yields a *structurally perfect,
/// psychedelic* frame: correct geometry, correct layout, colours pure noise.
/// That reads as a colour-space bug rather than a format bug, so it is exactly
/// the mistake that survives review. The `XB`/`AB` orders fail the same way,
/// more quietly still: decoded as `XR24`, `AB24` is the right picture with red
/// and blue exchanged — a blue sky turns orange and nothing else looks wrong.
fn repack_to_bgra(src: &[u8], width: u32, height: u32, pitch: u32, layout: Layout) -> Vec<u8> {
    let w = width as usize;
    let h = height as usize;
    let mut out = vec![0u8; w * h * 4];
    in_bands(&mut out, w * 4, h, |y0, band| {
        repack_rows(src, w, pitch as usize, layout, y0, band);
    });
    out
}

/// FR-107 P2 — split `out` (`rows` rows of `row_bytes`) into one band of rows
/// per thread and fill every band at once: `fill(first_row, band)`.
///
/// One core reads this mapping slowly (it is uncached device memory: each core
/// keeps only a few reads in flight), and the frame is independent row by row,
/// so the bands need no coordination. Each thread still reads its own rows in
/// order, the one access pattern FR-36 measured the mapping to tolerate.
fn in_bands<F>(out: &mut [u8], row_bytes: usize, rows: usize, fill: F)
where
    F: Fn(usize, &mut [u8]) + Sync,
{
    in_bands_n(band_threads(rows), out, row_bytes, rows, fill);
}

/// [`in_bands`] with the thread count given, so a test can drive every split.
fn in_bands_n<F>(threads: usize, out: &mut [u8], row_bytes: usize, rows: usize, fill: F)
where
    F: Fn(usize, &mut [u8]) + Sync,
{
    if threads <= 1 || row_bytes == 0 {
        fill(0, out);
        return;
    }
    let per = rows.div_ceil(threads);
    std::thread::scope(|s| {
        for (i, band) in out.chunks_mut(per * row_bytes).enumerate() {
            let fill = &fill;
            s.spawn(move || fill(i * per, band));
        }
    });
}

/// FR-107 P2 — how many threads repack one frame: `ROOMLERD_DRM_THREADS`
/// (`1` is the single pass every release before it made), else 4. Never more
/// than the cores there are, nor more than one per 64 rows.
fn band_threads(rows: usize) -> usize {
    static THREADS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let want = *THREADS.get_or_init(|| {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        std::env::var("ROOMLERD_DRM_THREADS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(4)
            .clamp(1, cores.max(1))
    });
    want.min((rows / 64).max(1))
}

/// The rows of `band` (output rows from `y0`), repacked from the same rows of
/// `src`.
fn repack_rows(src: &[u8], w: usize, pitch: usize, layout: Layout, y0: usize, band: &mut [u8]) {
    for (j, dst) in band.chunks_exact_mut(w * 4).enumerate() {
        let y = y0 + j;
        let row = &src[y * pitch..y * pitch + w * 4];
        match (layout.ten_bit, layout.red_low) {
            (true, false) => unpack_ten_bit_row::<false>(dst, row),
            (true, true) => unpack_ten_bit_row::<true>(dst, row),
            (false, false) => {
                // XR24/AR24 is already B,G,R,X in memory — the Frame contract's
                // byte order. Copy the row wholesale, then force alpha opaque so
                // an X-variant (where the 4th byte is undefined) cannot render
                // transparent downstream.
                dst.copy_from_slice(row);
                for px in dst.chunks_exact_mut(4) {
                    px[3] = 0xFF;
                }
            }
            (false, true) => {
                // XB24/AB24 is R,G,B,X in memory: swap the outer two bytes,
                // and force alpha opaque for the same reason as above.
                for (d, s) in dst.chunks_exact_mut(4).zip(row.chunks_exact(4)) {
                    d[0] = s[2];
                    d[1] = s[1];
                    d[2] = s[0];
                    d[3] = 0xFF;
                }
            }
        }
    }
}

/// One row of 2:10:10:10 words to 8-bit BGRA. `RED_LOW` picks XB30/AB30
/// (x:B:G:R) over XR30/AR30 (x:R:G:B) at compile time, so neither order pays
/// for the other in the loop.
///
/// Written as paired `chunks_exact` rather than indexed arithmetic so the
/// bounds checks fold away and LLVM can vectorise: this loop runs 8.8 M times
/// per frame at 4K and was measured as the single dominant cost of the whole
/// backend there. The low 2 bits of each channel are dropped to reach 8 bits;
/// alpha is opaque because the 2-bit `x` field is padding on the X-variants.
fn unpack_ten_bit_row<const RED_LOW: bool>(dst: &mut [u8], row: &[u8]) {
    for (d, s) in dst.chunks_exact_mut(4).zip(row.chunks_exact(4)) {
        let v = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
        let low = ((v & 0x3FF) >> 2) as u8;
        let high = (((v >> 20) & 0x3FF) >> 2) as u8;
        let (b, r) = if RED_LOW { (high, low) } else { (low, high) };
        d[0] = b;
        d[1] = (((v >> 10) & 0x3FF) >> 2) as u8; // G is the middle field in both
        d[2] = r;
        d[3] = 0xFF;
    }
}

enum WorkerReply {
    Grabbed(Grabbed),
    Failed(String),
}

/// What one grab came to.
enum Grabbed {
    /// A frame to deliver.
    Frame(Box<Frame>),
    /// FR-93 P3d — the same picture as the last frame delivered.
    Unchanged,
    /// Nothing is scanned out (a mode change, a blanked panel).
    Nothing,
    /// FR-93 P3e — nothing is scanned out because the display is off: a
    /// monitor is connected, and no CRTC drives a mode ([`display_off`]).
    Dark,
}

type FrameRequest = oneshot::Sender<WorkerReply>;

/// DRM/KMS screen capture over the primary CRTC's scanout plane.
pub struct DrmCapture {
    cmd_tx: std_mpsc::Sender<FrameRequest>,
    width: u32,
    height: u32,
    target_frame_period: Duration,
    last_frame_at: Option<Instant>,
    /// FR-119 P2b-3 — the scanned-out mode's refresh rate, read at the open.
    refresh_hz: Option<u16>,
    /// FR-93 P3d — frames the worker skipped because nothing changed.
    unchanged: Arc<AtomicU64>,
    /// FR-93 P3e — the last grab found the display off.
    dark: bool,
    /// FR-95 P2 — set when a system install switched this capture on by
    /// itself: the person's session it may read, and nothing else.
    guard: Option<Guarded>,
    /// FR-107 P1 — the pump's encode box ([`pack_cap`]), read by the worker on
    /// every grab.
    output_cap: Arc<AtomicU64>,
}

/// FR-95 P2 — an automatic capture's binding to the person who was told.
struct Guarded {
    /// logind's id for the person's session that was on screen at the open.
    session: String,
    /// What the guard said last, when it was closed: the wait the controller
    /// is told.
    closed: Option<super::seat_guard::Guard>,
    /// Counted in `seat_guard::viewing` while open, so the automatic input
    /// injects only then.
    mark: super::seat_guard::ViewingMark,
}

impl DrmCapture {
    /// FR-95 P2 — bind this capture to `session`: it reads the scanout only
    /// while that session is on screen, unlocked (`seat_guard`).
    pub fn guarded(mut self, session: String) -> Self {
        // Counted from the open, not the first frame: the session's input
        // reach is read as the capture opens, and must already see it.
        let mut mark = super::seat_guard::ViewingMark::default();
        mark.set(super::seat_guard::now(&session) == super::seat_guard::Guard::Open);
        self.guard = Some(Guarded {
            session,
            closed: None,
            mark,
        });
        self
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    /// Open the primary CRTC's scanout plane.
    ///
    /// Fails (rather than degrading) when there is no display node, no live
    /// framebuffer, or the scanout modifier is not linear — each of those
    /// produces a wrong picture rather than a slow one, and the caller's
    /// cascade has a working fallback.
    ///
    /// `idle_skip` (FR-93 P3d, FR-113 P1): how a frame nothing changed in is
    /// skipped, by the seat's kind, which the caller decides (`drm_idle.rs`).
    pub fn primary(
        target_fps: u32,
        downscale: DownscalePolicy,
        idle_skip: drm_idle::IdleSkip,
    ) -> Result<Self> {
        // Build the device on the worker thread so the fd and every mapping
        // stay on one thread for their whole life, and ack readiness back
        // synchronously so an init failure surfaces to the cascade here rather
        // than as a silently dead capturer.
        let (ready_tx, ready_rx) = std_mpsc::channel::<WorkerReady>();
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<FrameRequest>();
        let unchanged = Arc::new(AtomicU64::new(0));
        let worker_unchanged = Arc::clone(&unchanged);
        let output_cap = Arc::new(AtomicU64::new(0));
        let worker_cap = Arc::clone(&output_cap);

        std::thread::Builder::new()
            .name("drm-capture".into())
            .spawn(move || {
                // FR-112 P1 — the grab is on every frame's path too; the same
                // periodic-thread clocking applies to it as to the encoder.
                crate::encode::clock::ask_for_this_thread("capture");
                worker(
                    ready_tx,
                    cmd_rx,
                    downscale,
                    idle_skip,
                    worker_unchanged,
                    worker_cap,
                )
            })
            .map_err(|e| anyhow!("spawn drm-capture worker: {e}"))?;

        let (width, height, path, refresh_hz) = ready_rx
            .recv()
            .map_err(|_| anyhow!("drm-capture worker exited before reporting readiness"))??;

        info!(
            node = path.as_str(),
            width,
            height,
            ?refresh_hz,
            "capture: backend=drm (scanout plane, below the compositor)"
        );

        Ok(Self {
            cmd_tx,
            width,
            height,
            target_frame_period: Duration::from_micros(1_000_000 / target_fps.max(1) as u64),
            last_frame_at: None,
            unchanged,
            dark: false,
            guard: None,
            output_cap,
            refresh_hz,
        })
    }
}

/// What the capture thread reports once, when it is ready or has failed: the
/// scanout's width and height, the device node it opened, and (FR-119 P2b-3)
/// the scanned-out mode's refresh rate.
type WorkerReady = Result<(u32, u32, String, Option<u16>)>;

/// The capture thread: owns the device, the cached mapping, and every unsafe
/// region in this module.
fn worker(
    ready_tx: std_mpsc::Sender<WorkerReady>,
    cmd_rx: std_mpsc::Receiver<FrameRequest>,
    downscale: DownscalePolicy,
    idle_skip: drm_idle::IdleSkip,
    unchanged: Arc<AtomicU64>,
    output_cap: Arc<AtomicU64>,
) {
    let follow_cap = follow_cap_enabled();
    let (card, path) = match open_display_node() {
        Ok(v) => v,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };

    // ⚠️ Without this the primary plane is INVISIBLE to `plane_handles()` and
    // every grab would come back empty on a working display.
    if let Err(e) = card.set_client_capability(drm::ClientCapability::UniversalPlanes, true) {
        let _ = ready_tx.send(Err(anyhow!(
            "DRM_CLIENT_CAP_UNIVERSAL_PLANES refused ({e}) — the primary plane would be invisible"
        )));
        return;
    }

    // FR-93 P3c — the cursor plane's caps, before the plane table: they decide
    // what it lists.
    let (atomic, hotspot) = if cursor_enabled() {
        enable_cursor_caps(&card)
    } else {
        (false, false)
    };
    let planes = read_planes(&card);
    let mut cursor = atomic.then(CursorReader::default);
    info!(
        planes = planes.len(),
        cursor_planes = planes
            .iter()
            .filter(|p| p.kind == Some(PlaneKind::Cursor))
            .count(),
        atomic,
        hotspot,
        "drm capture: the cursor plane is {}",
        if cursor.is_some() {
            "read for the viewer"
        } else {
            "not read (ROOMLERD_DRM_CURSOR=0, or the driver refused DRM_CLIENT_CAP_ATOMIC)"
        }
    );

    // Resolve the geometry once so the caller gets a real size, and so an
    // unusable modifier is refused at open rather than per frame.
    let Some((fb, crtc_handle)) = primary_plane(&card, &planes) else {
        let _ = ready_tx.send(Err(anyhow!(
            "no plane is bound to a CRTC with a live framebuffer — is anything being scanned out? \
             (a blanked screen stops scanout, which is why screen blanking must be disabled)"
        )));
        return;
    };
    let info = match card.get_planar_framebuffer(fb) {
        Ok(i) => i,
        Err(e) => {
            let _ = ready_tx.send(Err(anyhow!(
                "drmModeGetFB2 failed ({e}) — this needs CAP_SYS_ADMIN to receive the GEM handle"
            )));
            return;
        }
    };
    // This look only reads the geometry; its handles close before the loop
    // (and on every early return below, with the guard).
    let open_handles = FbHandles::new(&card, info.buffers());
    if let Some(why) = unreadable(info.buffers()) {
        let _ = ready_tx.send(Err(anyhow!(why)));
        return;
    }
    if !modifier_is_linear(&info) {
        let _ = ready_tx.send(Err(anyhow!(
            "scanout modifier {:?} is not linear — detiling is FR-36 P2 and is not implemented; \
             refusing rather than emitting garbage pixels",
            info.modifier()
        )));
        return;
    }
    let (w, h) = info.size();
    drop(open_handles);
    // FR-119 P2b-3 — the scanned-out mode's refresh rate.
    let refresh_hz = card
        .get_crtc(crtc_handle)
        .ok()
        .and_then(|c| c.mode())
        .and_then(|m| super::refresh::hz(f64::from(m.vrefresh())));
    if ready_tx.send(Ok((w, h, path, refresh_hz))).is_err() {
        return;
    }

    let mut cache = ReadCache {
        mapping: None,
        gpu: if super::drm_gpu::enabled() {
            GpuState::Untried
        } else {
            GpuState::Off
        },
    };
    // FR-93 P3d — the frame skip for an unchanged screen: a Wayland seat's,
    // or (FR-113 P1) an X11 seat's, which samples dense rows.
    let mut gate: Option<IdleGate> = idle_skip.gate();
    // FR-93 P3e — an empty scanout is told apart: a display switched off.
    let dark_check = wake_wait_enabled();
    info!(
        "drm capture: {}",
        match idle_skip {
            drm_idle::IdleSkip::Flips => {
                "a frame nothing changed in is skipped (FR-93 P3d; ROOMLERD_DRM_IDLE_SKIP=0 reads every frame)"
            }
            drm_idle::IdleSkip::InPlace => {
                "a frame nothing changed in is skipped by dense rows, an X server draws in place \
                 (FR-113 P1; ROOMLERD_DRM_IDLE_SKIP=0 or x11_auto_system = false reads every frame)"
            }
            drm_idle::IdleSkip::Off => {
                "every frame is read (no Wayland seat and no X11 one with x11_auto_system on, or \
                 ROOMLERD_DRM_IDLE_SKIP=0)"
            }
        }
    );

    while let Ok(reply_tx) = cmd_rx.recv() {
        let sizing = Sizing {
            policy: downscale,
            cap: if follow_cap {
                unpack_cap(output_cap.load(Ordering::Relaxed))
            } else {
                None
            },
        };
        let reply = match grab(
            &card,
            &planes,
            &mut cache,
            sizing,
            cursor.as_mut(),
            gate.as_mut(),
            &unchanged,
        ) {
            // FR-93 P3e — nothing scanned out because the display is off, not
            // a passing modeset: the controller is told, and nothing
            // re-encodes the last frame.
            Ok(Grabbed::Nothing) if dark_check && display_off(&card) == Some(true) => {
                WorkerReply::Grabbed(Grabbed::Dark)
            }
            Ok(grabbed) => WorkerReply::Grabbed(grabbed),
            Err(e) => WorkerReply::Failed(format!("{e:#}")),
        };
        if reply_tx.send(reply).is_err() {
            // Caller went away mid-frame; keep serving the next one.
            continue;
        }
    }
    // The capturer is gone: no pointer to show until another one opens.
    if cursor.is_some() {
        drm_cursor::publish(None);
    }
}

/// `None` means "the driver did not report a modifier", which the kernel uses
/// for pre-modifier framebuffers — those are linear by definition.
fn modifier_is_linear(info: &drm::control::framebuffer::PlanarInfo) -> bool {
    match info.modifier() {
        None => true,
        Some(m) => u64::from(m) == 0,
    }
}

/// FR-93 P3h — why this process cannot read the scanout, when it cannot.
///
/// GETFB2 answers a caller without `CAP_SYS_ADMIN` with the geometry and NO
/// buffer handle: the kernel zeroes it rather than failing. So a daemon that is
/// not root opened DRM capture without complaint and then failed every frame
/// in [`grab`]. The session died and re-created itself, and the viewer was
/// never told why (the FR-93 lab's GNOME per-user guest with `drm_capture` set,
/// on 0.4.135 and every release before). Refused at open, the reason reaches
/// the viewer as the arm's own error, inside FR-80's 200-character cap (a
/// longer first draft lost its fix, at the end, to that cap).
fn unreadable(buffers: [Option<drm::buffer::Handle>; 4]) -> Option<&'static str> {
    buffers[0].is_none().then_some(
        "reading the scanout needs CAP_SYS_ADMIN (root), which this daemon lacks: on a per-user \
         install run meshharbor config clear drm_capture",
    )
}

fn grab(
    card: &Card,
    planes: &[PlaneEntry],
    cache: &mut ReadCache,
    sizing: Sizing,
    cursor: Option<&mut CursorReader>,
    gate: Option<&mut IdleGate>,
    unchanged: &AtomicU64,
) -> Result<Grabbed> {
    let Some((fb, crtc)) = primary_plane(card, planes) else {
        // Nothing being scanned out right now (mode change, blanked panel).
        // Not an error: report "no frame" and let the pump retry. FR-93 P3e:
        // the worker tells a display switched off apart.
        if cursor.is_some() {
            drm_cursor::publish(None);
        }
        // FR-93 P3d — whatever is scanned out next is delivered.
        if let Some(gate) = gate {
            gate.forget();
        }
        return Ok(Grabbed::Nothing);
    };
    // FR-93 P3c — the pointer at this frame, for the cursor data channel. Read
    // before the primary's pixels, so a failure there cannot leave it stale;
    // its own failures only ever hide the pointer.
    if let Some(reader) = cursor {
        drm_cursor::publish(reader.read(card, planes, crtc));
    }
    let info = card
        .get_planar_framebuffer(fb)
        .map_err(|e| anyhow!("drmModeGetFB2: {e}"))?;
    // ⚠️ A NAMED binding: `let _ = …` would drop the guard — and close the
    // handle — before the export below could use it. It closes at the end of
    // this frame, on every return path including the bails.
    let _handles = FbHandles::new(card, info.buffers());

    if !modifier_is_linear(&info) {
        bail!(
            "scanout modifier changed to {:?} (non-linear) — detiling is FR-36 P2",
            info.modifier()
        );
    }

    let (width, height) = info.size();
    let pitch = info.pitches()[0];
    let Some(layout) = Layout::of(info.pixel_format()) else {
        bail!("unhandled scanout pixel format {:?}", info.pixel_format());
    };
    let len = pitch as usize * height as usize;

    // FR-93 P3f — the buffer itself, named by its dma-buf: exported on every
    // frame (an ioctl and an fd), because the framebuffer id alone is reused
    // for a new buffer once the old one is gone.
    let handle = info.buffers()[0]
        .ok_or_else(|| anyhow!("framebuffer has no GEM handle — CAP_SYS_ADMIN missing?"))?;
    let prime = File::from(
        card.buffer_to_prime_fd(handle, DRM_CLOEXEC)
            .map_err(|e| anyhow!("PRIME export: {e}"))?,
    );
    let id = BufferId {
        fb,
        inode: prime.metadata().map_or(0, |m| m.ino()),
    };

    // Re-map only when the compositor handed us a different buffer.
    let cached = &mut cache.mapping;
    if !maps(cached.as_ref().map(|c| (c.id, c.mapping.len)), id, len) {
        // SAFETY: a fresh private read-only mapping of the exported dma-buf,
        // sized from the framebuffer's own pitch × height.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                prime.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(anyhow!(
                "mmap of the scanout dma-buf failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        *cached = Some(Cached {
            id,
            mapping: Mapping { ptr, len },
        });
    }
    // The mapping holds the dma-buf, which holds the buffer. `prime` stays
    // open until the GPU path (FR-107 P3) has imported it, below.

    let Some(Cached { mapping, .. }) = cache.mapping.as_ref() else {
        return Ok(Grabbed::Nothing);
    };

    // FR-93 P3d — the same buffer, with the same sampled rows, within
    // `MAX_SKIP` of the last frame delivered: nothing to send. Checked before
    // any pixel is converted, which is the cost this skips.
    let now = Instant::now();
    let shown = gate.as_ref().map(|g| drm_idle::Shown {
        fb: u32::from(fb),
        buffer: id.inode,
        rows: drm_idle::sample_rows_n(
            mapping.as_slice(),
            width as usize * 4,
            height,
            pitch,
            g.rows(height),
        ),
    });
    if let (Some(gate), Some(shown)) = (gate.as_deref(), shown)
        && gate.unchanged(shown, now)
    {
        unchanged.fetch_add(1, Ordering::Relaxed);
        return Ok(Grabbed::Unchanged);
    }
    // Decide the output size BEFORE touching pixels, so a downscaled frame is
    // produced in ONE pass instead of building a full-size intermediate and
    // filtering it afterwards. At 4K that is the difference between
    // read 35 MB → write 35 MB → read 35 MB → write 8.8 MB and
    // read 35 MB → write 8.8 MB; the backend there is memory-bandwidth bound,
    // so the pass count is the cost.
    //
    // FR-107 P3 — the GPU first, where it is up: it reads the buffer itself,
    // so the mapping above serves only the idle check.
    let src = super::drm_gpu::Source {
        fd: prime.as_raw_fd(),
        width,
        height,
        fourcc: info.pixel_format() as u32,
        offset: info.offsets()[0],
        pitch,
        modifier: info.modifier().map(u64::from),
    };
    let via_gpu = via_gpu(&mut cache.gpu, id, &src, sizing);
    drop(prime);
    let scaled = if let Some(scaled) = via_gpu {
        scaled
    } else if wants_half(width, height, sizing.policy, sizing.cap) {
        Scaled {
            data: repack_bgra_half(mapping.as_slice(), width, height, pitch, layout),
            width: width / 2,
            height: height / 2,
            stride: (width / 2) * 4,
            source: Some((width, height)),
        }
    } else {
        Scaled {
            data: repack_to_bgra(mapping.as_slice(), width, height, pitch, layout),
            width,
            height,
            stride: width * 4,
            source: None,
        }
    };
    if let (Some(gate), Some(shown)) = (gate, shown) {
        gate.delivered(shown, now);
    }

    Ok(Grabbed::Frame(Box::new(Frame {
        width: scaled.width,
        height: scaled.height,
        stride: scaled.stride,
        pixel_format: PixelFormat::Bgra,
        data: scaled.data,
        monotonic_us: now_us(),
        monitor: 0,
        // DRM reports nothing about WHICH pixels changed: a buffer check says
        // only whether any did (P3d, above). See the module docs.
        damage: Damage::Unknown,
        // Pre-downscale dims, so the pump can still reason about the real
        // screen size; `None` when we delivered native.
        source: scaled.source,
    })))
}

/// A frame's pixels plus the geometry that describes them.
struct Scaled {
    data: Vec<u8>,
    width: u32,
    height: u32,
    stride: u32,
    /// Native capture dims when a downscale happened, else `None` — the
    /// `Frame::source` contract.
    source: Option<(u32, u32)>,
}

/// Mirror the scrap backend's policy — sharing `DOWNSCALE_TRIGGER_PIXELS`
/// rather than restating the threshold — so a host does not get a different
/// picture size purely because it switched capture backend.
///
/// FR-107 P1 — and whatever the policy, a half-size frame whenever it still
/// covers the pump's encode box `cap`. The pump resamples every frame down to
/// that box anyway, and its Lanczos costs in proportion to the SOURCE area, so
/// a 4K scanout encoded at 1920×1012 was read in full and resampled from 8.8 M
/// pixels (measured 43 ms a frame on the Asahi box) for detail the encode then
/// threw away. A box bigger than half the source keeps the full read: halving
/// there would lose pixels the encode keeps.
fn wants_half(width: u32, height: u32, policy: DownscalePolicy, cap: Option<(u32, u32)>) -> bool {
    if width < 2 || height < 2 {
        return false;
    }
    if let Some((cw, ch)) = cap
        && cw <= width / 2
        && ch <= height / 2
    {
        return true;
    }
    match policy {
        DownscalePolicy::Always => true,
        DownscalePolicy::Never => false,
        DownscalePolicy::Auto => (width as u64 * height as u64) >= super::DOWNSCALE_TRIGGER_PIXELS,
    }
}

/// Repack **and** 2×2 box-downsample in a single pass over the scanout buffer.
///
/// Same filter as `capture::downscale_bgra_2x` (average four samples per
/// channel, `+2/4` round) and therefore the same picture — but it never
/// materialises the full-size frame, which is the whole point: this backend is
/// memory-bandwidth bound, so the win is one fewer read and one 4×-smaller
/// write, not a cheaper inner loop.
fn repack_bgra_half(src: &[u8], width: u32, height: u32, pitch: u32, layout: Layout) -> Vec<u8> {
    let (dw, dh) = ((width / 2) as usize, (height / 2) as usize);
    let mut out = vec![0u8; dw * dh * 4];
    in_bands(&mut out, dw * 4, dh, |y0, band| {
        half_rows(src, width as usize, pitch as usize, layout, y0, band);
    });
    out
}

/// The output rows of `band` (from `y0`) of [`repack_bgra_half`], each from
/// its two source rows.
fn half_rows(src: &[u8], width: usize, pitch: usize, layout: Layout, y0: usize, band: &mut [u8]) {
    let Layout { ten_bit, red_low } = layout;
    let dw = width / 2;
    // ⚠️ Copy each source row pair into cached scratch FIRST, then filter from
    // there. Reading the two rows directly would alternate between addresses a
    // whole pitch apart on every output pixel, and the scanout mapping punishes
    // strided access brutally: the naive version measured 329 ms/frame at 4K
    // against 53 ms for read-everything-then-filter. Sequential reads out of
    // this mapping are the constraint — not the number of passes over it.
    let row_bytes = width * 4;
    let mut scratch = vec![0u8; row_bytes * 2];
    for (j, dst) in band.chunks_exact_mut(dw * 4).enumerate() {
        let y = y0 + j;
        scratch[..row_bytes].copy_from_slice(&src[2 * y * pitch..2 * y * pitch + row_bytes]);
        scratch[row_bytes..]
            .copy_from_slice(&src[(2 * y + 1) * pitch..(2 * y + 1) * pitch + row_bytes]);
        let (r0, r1) = (0usize, row_bytes);
        let src = &scratch[..];
        for x in 0..dw {
            let o = 2 * x * 4;
            // Average in the SOURCE's own precision, then narrow — narrowing
            // first would throw away the two bits that make averaging 10-bit
            // samples worth doing at all. Summed in the source's channel
            // order (low, middle, high); which of low/high is blue is decided
            // once, at the store.
            let (mut low, mut g, mut high) = (0u32, 0u32, 0u32);
            for base in [r0 + o, r0 + o + 4, r1 + o, r1 + o + 4] {
                if ten_bit {
                    let v = u32::from_le_bytes([
                        src[base],
                        src[base + 1],
                        src[base + 2],
                        src[base + 3],
                    ]);
                    low += v & 0x3FF;
                    g += (v >> 10) & 0x3FF;
                    high += (v >> 20) & 0x3FF;
                } else {
                    low += u32::from(src[base]);
                    g += u32::from(src[base + 1]);
                    high += u32::from(src[base + 2]);
                }
            }
            let narrow = |sum: u32| -> u8 {
                if ten_bit {
                    // 4 samples of 10 bits → /4 back to 10, then >>2 to 8.
                    (((sum + 2) / 4) >> 2) as u8
                } else {
                    ((sum + 2) / 4) as u8
                }
            };
            let (b, r) = if red_low { (high, low) } else { (low, high) };
            dst[x * 4] = narrow(b);
            dst[x * 4 + 1] = narrow(g);
            dst[x * 4 + 2] = narrow(r);
            dst[x * 4 + 3] = 0xFF;
        }
    }
}

fn now_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[async_trait::async_trait]
impl ScreenCapture for DrmCapture {
    async fn next_frame(&mut self) -> Result<Option<Frame>> {
        let started = Instant::now();
        loop {
            // FR-95 P2 — an automatic capture reads nothing while the person
            // it was bound to is not on screen, unlocked: no grab is even
            // asked of the worker, so the greeter's and the lock screen's
            // pixels never leave the card. Looked at again a quarter of a
            // second on, like a dark display.
            if let Some(g) = self.guard.as_mut() {
                let now = super::seat_guard::now(&g.session);
                g.mark.set(now == super::seat_guard::Guard::Open);
                if now != super::seat_guard::Guard::Open {
                    if g.closed != Some(now) {
                        info!(session = %g.session, guard = ?now, "drm capture: the person's session is not on screen, unlocked; reading nothing until it is (FR-95 P2)");
                        g.closed = Some(now);
                    }
                    tokio::time::sleep(DARK_POLL).await;
                    return Ok(None);
                }
                if g.closed.take().is_some() {
                    info!(session = %g.session, "drm capture: the person's session is on screen again (FR-95 P2)");
                }
            }
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
                .map_err(|_| anyhow!("drm capture worker exited"))?;
            let reply = res_rx
                .await
                .map_err(|_| anyhow!("drm capture worker dropped reply"))?;
            // FR-107 — the frame period runs from when this frame was ASKED
            // for. Timed from its arrival, every period also paid for the
            // grab, and a 30 fps target ran at 1000 / (33.3 + grab): 16 fps
            // with the CPU's ~34 ms read of a 4K scanout, 27 with the GPU's
            // ~3 ms (measured on the Asahi box, both matching to within 1 fps).
            self.last_frame_at = Some(asked_at);
            if !matches!(reply, WorkerReply::Grabbed(Grabbed::Dark)) && self.dark {
                self.dark = false;
                info!("drm capture: the display is on again (FR-93 P3e)");
            }
            match reply {
                WorkerReply::Grabbed(Grabbed::Frame(frame)) => {
                    self.width = frame.width;
                    self.height = frame.height;
                    return Ok(Some(*frame));
                }
                WorkerReply::Grabbed(Grabbed::Nothing) => return Ok(None),
                // FR-93 P3d — a still screen is waited out at the frame rate,
                // up to IDLE_WAIT, as the portal arm waits on its stream. The
                // pump answers each "nothing this tick" with a keepalive
                // re-encode of its last frame, so a "nothing" every frame
                // period would cost more encodes than the frames it saved.
                WorkerReply::Grabbed(Grabbed::Unchanged) => {
                    if started.elapsed() >= drm_idle::IDLE_WAIT {
                        return Ok(None);
                    }
                }
                // FR-93 P3e — the display is off. Nothing changes until it
                // wakes, so look again a quarter of a second on rather than
                // every frame period, and say "no frame": the pump reads
                // `waits_for`, tells the controller, and keeps no keepalive.
                WorkerReply::Grabbed(Grabbed::Dark) => {
                    if !self.dark {
                        self.dark = true;
                        info!(
                            "drm capture: the display is off; waiting for it to wake (FR-93 P3e)"
                        );
                    }
                    tokio::time::sleep(DARK_POLL).await;
                    return Ok(None);
                }
                WorkerReply::Failed(e) => return Err(anyhow!(e)),
            }
        }
    }

    fn monitor_count(&self) -> u8 {
        // P1 captures the primary CRTC only; per-CRTC capture with origin and
        // scale mapping is deferred by the spec. Reporting the true count here
        // would advertise monitors this backend cannot deliver.
        1
    }

    fn arm(&self) -> Option<super::CaptureArm> {
        Some(super::CaptureArm::Drm)
    }

    /// FR-119 P2b — the pace is this side's sleep, in microseconds as at the
    /// open, so it moves in place.
    fn set_target_fps(&mut self, fps: u32) {
        self.target_frame_period = Duration::from_micros(1_000_000 / u64::from(fps.max(1)));
    }

    fn backend(&self) -> &'static str {
        "drm"
    }

    fn refresh_hz(&self) -> Option<u16> {
        self.refresh_hz
    }

    /// FR-93 P3d — the frames skipped because nothing changed, which the
    /// pump's idle log carries beside its own count of empty polls.
    /// FR-93 P3e — a display switched off waits for its wake.
    fn waits_for(&self) -> Option<WaitFor> {
        // FR-95 P2 — the guard first: a locked screen may also be dark.
        self.guard
            .as_ref()
            .and_then(|g| g.closed)
            .and_then(super::seat_guard::Guard::wait)
            .or(self.dark.then_some(WaitFor::DisplayWake))
    }

    /// FR-107 P1 — the pump's encode box: a half-size read wherever it still
    /// covers it ([`wants_half`]), from the next grab.
    fn set_output_cap(&mut self, target: Option<(u32, u32)>) {
        self.output_cap.store(pack_cap(target), Ordering::Relaxed);
    }

    fn frames_unchanged(&self) -> u64 {
        self.unchanged.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(format: DrmFourcc) -> Layout {
        Layout::of(format).expect("a handled scanout fourcc")
    }

    /// Both channel orders at both depths, and NOTHING else: a fourcc outside
    /// the table must stay a refusal, because the alternative is decoding it
    /// with somebody else's layout.
    #[test]
    fn layout_covers_both_channel_orders_at_both_depths() {
        for (format, ten_bit, red_low) in [
            (DrmFourcc::Xrgb8888, false, false),
            (DrmFourcc::Argb8888, false, false),
            (DrmFourcc::Xbgr8888, false, true),
            (DrmFourcc::Abgr8888, false, true),    // KWin on Asahi
            (DrmFourcc::Xrgb2101010, true, false), // mutter on Asahi
            (DrmFourcc::Argb2101010, true, false),
            (DrmFourcc::Xbgr2101010, true, true),
            (DrmFourcc::Abgr2101010, true, true),
        ] {
            assert_eq!(layout(format), Layout { ten_bit, red_low }, "{format:?}");
        }
        for other in [DrmFourcc::Rgb565, DrmFourcc::Nv12, DrmFourcc::Rgbx8888] {
            assert_eq!(Layout::of(other), None, "{other:?}");
        }
    }

    /// The 10-bit path is the one that fails SILENTLY — an 8-bit decode of
    /// XR30 keeps every shape and ruins every colour, which reads as a
    /// colour-space bug. Pin the channel extraction against hand-computed
    /// values so a future edit to the shifts fails loudly instead.
    #[test]
    fn repack_unpacks_xr30_channels() {
        // x=0b11, R=0x3FF (255), G=0x200 (128), B=0x100 (64)
        let word: u32 = (0b11 << 30) | (0x3FF << 20) | (0x200 << 10) | 0x100;
        let src = word.to_le_bytes().to_vec();
        let out = repack_to_bgra(&src, 1, 1, 4, layout(DrmFourcc::Xrgb2101010));
        assert_eq!(out[0], 64, "B");
        assert_eq!(out[1], 128, "G");
        assert_eq!(out[2], 255, "R");
        assert_eq!(out[3], 255, "alpha must be forced opaque");
    }

    /// The same word read as XB30 is the same picture with red and blue
    /// exchanged — the field at bits 20..30 is BLUE there.
    #[test]
    fn repack_unpacks_xb30_channels() {
        // x=0b11, B=0x3FF (255), G=0x200 (128), R=0x100 (64)
        let word: u32 = (0b11 << 30) | (0x3FF << 20) | (0x200 << 10) | 0x100;
        let src = word.to_le_bytes().to_vec();
        let out = repack_to_bgra(&src, 1, 1, 4, layout(DrmFourcc::Abgr2101010));
        assert_eq!(&out[..], &[255, 128, 64, 0xFF], "B, G, R, opaque");
    }

    /// XR24 is already BGRA in memory, so the repack is a copy — except for
    /// alpha, which is UNDEFINED in the X-variant and must be forced opaque or
    /// the frame can render transparent downstream.
    #[test]
    fn repack_passes_xr24_through_and_forces_alpha() {
        let src = vec![10u8, 20, 30, 0x00];
        let out = repack_to_bgra(&src, 1, 1, 4, layout(DrmFourcc::Xrgb8888));
        assert_eq!(&out[..3], &[10, 20, 30]);
        assert_eq!(out[3], 0xFF);
    }

    /// AB24 is R,G,B,A in memory (KWin's scanout on Asahi). Copied through as
    /// if it were AR24, the picture keeps every shape and swaps red for blue —
    /// the bug that reads as "the colours are a bit off".
    #[test]
    fn repack_swaps_ab24_into_bgra_and_forces_alpha() {
        let src = vec![30u8, 20, 10, 0x00]; // R=30, G=20, B=10, A=0
        let out = repack_to_bgra(&src, 1, 1, 4, layout(DrmFourcc::Abgr8888));
        assert_eq!(&out[..], &[10, 20, 30, 0xFF], "B, G, R, opaque");
    }

    /// FR-107 P2 — splitting a frame into bands of rows, one per thread,
    /// changes nothing in the picture: every split of every layout is
    /// byte-identical to the single pass, with an odd height, an odd width
    /// and a padded pitch.
    #[test]
    fn banded_repacks_match_the_single_pass() {
        let (w, h, pitch) = (37usize, 131usize, 37 * 4 + 12);
        let src: Vec<u8> = (0..pitch * h).map(|i| (i * 7 + i / 13) as u8).collect();
        for fourcc in [
            DrmFourcc::Xrgb8888,
            DrmFourcc::Abgr8888,
            DrmFourcc::Xrgb2101010,
            DrmFourcc::Abgr2101010,
        ] {
            let l = layout(fourcc);
            let full = |threads: usize| {
                let mut out = vec![0u8; w * h * 4];
                in_bands_n(threads, &mut out, w * 4, h, |y0, band| {
                    repack_rows(&src, w, pitch, l, y0, band)
                });
                out
            };
            let half = |threads: usize| {
                let (dw, dh) = (w / 2, h / 2);
                let mut out = vec![0u8; dw * dh * 4];
                in_bands_n(threads, &mut out, dw * 4, dh, |y0, band| {
                    half_rows(&src, w, pitch, l, y0, band)
                });
                out
            };
            let (one_full, one_half) = (full(1), half(1));
            for threads in [2, 3, 4, 7, 64] {
                assert_eq!(
                    full(threads),
                    one_full,
                    "{fourcc:?} full, {threads} threads"
                );
                assert_eq!(
                    half(threads),
                    one_half,
                    "{fourcc:?} half, {threads} threads"
                );
            }
        }
    }

    /// Scanout pitch is nearly always wider than width×4 (4096-wide 10-bit
    /// scanout measured a 16384-byte pitch against a 4096×4 = 16384 exact fit,
    /// but 1920×1080 measured 7680 = exact). Padding must be skipped, or every
    /// row after the first is offset and the image shears.
    #[test]
    fn repack_honours_a_padded_pitch() {
        // 2×2 image, pitch 12 bytes (2 px × 4 + 4 bytes of padding).
        let mut src = vec![0u8; 12 * 2];
        src[0] = 1; // row 0, px 0, B
        src[12] = 2; // row 1, px 0, B  — only correct if pitch is honoured
        let out = repack_to_bgra(&src, 2, 2, 12, layout(DrmFourcc::Xrgb8888));
        assert_eq!(out[0], 1);
        assert_eq!(
            out[2 * 4],
            2,
            "row 1 must start at src[pitch], not src[w*4]"
        );
    }

    /// The fused path exists to save memory passes, NOT to change the picture.
    /// Pin it against the two-step route it replaced: repack to full-size BGRA,
    /// then run the shared 2×2 box filter, and require identical bytes.
    ///
    /// ⚠️ This is the test that would catch a fusion that quietly shifted the
    /// sample grid by a pixel — which looks fine in a screenshot and is wrong.
    #[cfg(feature = "scrap-capture")]
    #[test]
    fn fused_half_matches_repack_then_downscale_for_xr24_and_ab24() {
        // 4×4 8-bit with a padded pitch, values chosen so every 2×2 block
        // averages to something non-uniform.
        let (w, h, pitch) = (4u32, 4u32, 20u32);
        let mut src = vec![0u8; (pitch * h) as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let o = y * pitch as usize + x * 4;
                src[o] = (x * 17 + y * 3) as u8;
                src[o + 1] = (x * 5 + y * 29) as u8;
                src[o + 2] = (x * 11 + y * 7) as u8;
                src[o + 3] = 0x00;
            }
        }
        for format in [DrmFourcc::Xrgb8888, DrmFourcc::Abgr8888] {
            let full = repack_to_bgra(&src, w, h, pitch, layout(format));
            let (two_step, tw, th) = super::super::downscale_bgra_2x(&full, w, h, w * 4);
            let fused = repack_bgra_half(&src, w, h, pitch, layout(format));
            assert_eq!((tw, th), (w / 2, h / 2));
            assert_eq!(
                fused, two_step,
                "{format:?}: fusing must not change the picture"
            );
        }
    }

    /// The fused path must swap AB24 exactly as the full-size one does —
    /// pinned without the shared filter, so it runs in every build.
    #[test]
    fn fused_half_swaps_ab24_into_bgra() {
        // Four identical R=200, G=100, B=50 pixels: the mean is the pixel.
        let (w, h, pitch) = (2u32, 2u32, 8u32);
        let src = [200u8, 100, 50, 0x00].repeat(4);
        let out = repack_bgra_half(&src, w, h, pitch, layout(DrmFourcc::Abgr8888));
        assert_eq!(&out[..], &[50, 100, 200, 0xFF], "B, G, R, opaque");
    }

    /// 10-bit has no two-step equivalent to compare against (the shared filter
    /// only knows BGRA), so pin the arithmetic itself: averaging must happen in
    /// the SOURCE's precision and narrow afterwards. Narrowing first would
    /// discard exactly the bits that make averaging 10-bit samples useful.
    #[test]
    fn fused_half_averages_xr30_in_source_precision() {
        // Four pixels with 10-bit R = 4, 8, 12, 16 → mean 10 → 8-bit 10>>2 = 2.
        let (w, h, pitch) = (2u32, 2u32, 8u32);
        let mut src = vec![0u8; (pitch * h) as usize];
        for (i, r) in [4u32, 8, 12, 16].iter().enumerate() {
            let (x, y) = (i % 2, i / 2);
            let word = r << 20;
            let o = y * pitch as usize + x * 4;
            src[o..o + 4].copy_from_slice(&word.to_le_bytes());
        }
        let out = repack_bgra_half(&src, w, h, pitch, layout(DrmFourcc::Xrgb2101010));
        assert_eq!(out.len(), 4, "2x2 → 1 pixel");
        assert_eq!(out[2], 2, "R: mean of 4,8,12,16 in 10-bit is 10 → 8-bit 2");
        assert_eq!(out[3], 0xFF);
        // The same words as XB30 put that field in BLUE, and red reads zero.
        let out = repack_bgra_half(&src, w, h, pitch, layout(DrmFourcc::Xbgr2101010));
        assert_eq!(&out[..], &[2, 0, 0, 0xFF], "XB30: bits 20..30 are blue");
    }

    /// The policy has to match scrap's, or a host gets a different picture size
    /// purely from switching backend.
    #[test]
    fn wants_half_follows_the_shared_threshold() {
        assert!(!wants_half(1920, 1080, DownscalePolicy::Never, None));
        assert!(wants_half(1920, 1080, DownscalePolicy::Always, None));
        // 1080p is under the trigger; 4K is over it.
        assert!(!wants_half(1920, 1080, DownscalePolicy::Auto, None));
        assert!(wants_half(4096, 2160, DownscalePolicy::Auto, None));
        // Degenerate sizes must never halve into nothing.
        assert!(!wants_half(1, 1, DownscalePolicy::Always, None));
    }

    /// FR-107 P3 — the GPU renders exactly the pump's encode box where it is
    /// smaller than the source, so the pump's resample has nothing left to
    /// do; with no box, or a box it cannot honour, it delivers what the CPU
    /// path would.
    #[test]
    fn the_gpu_renders_the_encode_box() {
        let s = |policy, cap| Sizing { policy, cap };
        let never = DownscalePolicy::Never;
        assert_eq!(
            gpu_out(4096, 2160, s(never, Some((1920, 1012)))),
            (1920, 1012)
        );
        assert_eq!(gpu_out(4096, 2160, s(never, None)), (4096, 2160));
        assert_eq!(
            gpu_out(4096, 2160, s(DownscalePolicy::Auto, None)),
            (2048, 1080)
        );
        // A box bigger than the source, or a degenerate one, is no box.
        assert_eq!(
            gpu_out(1920, 1080, s(never, Some((2560, 1440)))),
            (1920, 1080)
        );
        assert_eq!(gpu_out(1920, 1080, s(never, Some((1, 1)))), (1920, 1080));
    }

    /// FR-107 P1 — the pump's encode box halves the read only where the half
    /// still covers it: a 4K scanout for a 1920×1012 encode (the software cap
    /// on the Asahi box), never a 1440p one for the same box, whose half is
    /// smaller than what the encode keeps.
    #[test]
    fn the_encode_box_halves_only_what_it_cannot_tell() {
        let never = DownscalePolicy::Never;
        assert!(wants_half(4096, 2160, never, Some((1920, 1012))));
        assert!(wants_half(4096, 2160, never, Some((2048, 1080))));
        assert!(!wants_half(4096, 2160, never, Some((2050, 1080))));
        assert!(!wants_half(2560, 1440, never, Some((1920, 1080))));
        assert!(!wants_half(1920, 1080, never, Some((1920, 1080))));
        assert!(wants_half(1920, 1080, never, Some((960, 540))));
        // No box: the policy alone, as before.
        assert!(!wants_half(4096, 2160, never, None));
        // The packing round-trips, and a degenerate box is no box.
        assert_eq!(unpack_cap(pack_cap(Some((1920, 1012)))), Some((1920, 1012)));
        assert_eq!(unpack_cap(pack_cap(Some((1, 1012)))), None);
        assert_eq!(unpack_cap(pack_cap(None)), None);
    }

    /// A framebuffer with no reported modifier is a pre-modifier one, which is
    /// linear by definition — treating `None` as non-linear would refuse to
    /// capture on older drivers that work perfectly.
    #[test]
    fn env_gate_defaults_off() {
        // Default OFF is load-bearing: defaulting ON would silently undo
        // FR-29's idle-CPU win on every X11 host, because this backend has no
        // damage information and would grab every frame forever.
        assert!(!tunnel_core::env::flag(
            "DRM_CAPTURE_DEFINITELY_UNSET_XYZ",
            false
        ));
    }

    /// Stands in for the device so the guard's closes are observable without
    /// a DRM node.
    struct Recorder(std::cell::RefCell<Vec<u32>>);

    impl CloseHandle for Recorder {
        fn close_handle(&self, handle: drm::buffer::Handle) {
            self.0.borrow_mut().push(u32::from(handle));
        }
    }

    fn handle(n: u32) -> drm::buffer::Handle {
        drm::control::from_u32(n).expect("a non-zero handle")
    }

    /// FR-93 P3f — the kernel reuses a framebuffer id for a new buffer once
    /// the old one is gone, and a mapping keyed on the id alone went on
    /// showing the old buffer.
    #[test]
    fn a_mapping_is_reused_only_for_the_same_buffer_at_the_same_size() {
        let fb =
            |n: u32| -> framebuffer::Handle { drm::control::from_u32(n).expect("a non-zero id") };
        let a = BufferId {
            fb: fb(31),
            inode: 1001,
        };
        assert!(maps(Some((a, 4096)), a, 4096));
        assert!(!maps(None, a, 4096), "nothing mapped yet");
        assert!(
            !maps(
                Some((a, 4096)),
                BufferId {
                    fb: fb(31),
                    inode: 1002
                },
                4096
            ),
            "the framebuffer id reused for a new buffer"
        );
        assert!(
            !maps(
                Some((a, 4096)),
                BufferId {
                    fb: fb(32),
                    inode: 1001
                },
                4096
            ),
            "another framebuffer"
        );
        assert!(!maps(Some((a, 4096)), a, 8192), "a new size");
    }

    /// FR-93 AC9: every handle a GETFB2 hands back is closed, each buffer
    /// object exactly once (GETFB2 repeats a handle across planes that share
    /// one, and a second close is an error), and none before the frame is done.
    #[test]
    fn every_getfb2_handle_is_closed_once_on_drop() {
        let rec = Recorder(Default::default());
        {
            let _guard = FbHandles::new(
                &rec,
                [Some(handle(7)), Some(handle(7)), Some(handle(9)), None],
            );
            assert!(
                rec.0.borrow().is_empty(),
                "nothing may close while the frame still needs the handle"
            );
        }
        assert_eq!(*rec.0.borrow(), vec![7, 9]);
    }

    /// The bails in `grab` — a modifier that turned non-linear, a pixel
    /// format we cannot repack — return early, and they are exactly the frames
    /// that leaked a handle every time. They close too.
    #[test]
    fn an_early_return_still_closes() {
        fn bails(rec: &Recorder) -> Result<()> {
            let _guard = FbHandles::new(rec, [Some(handle(3)), None, None, None]);
            bail!("scanout modifier changed to a tiled one")
        }
        let rec = Recorder(Default::default());
        assert!(bails(&rec).is_err());
        assert_eq!(*rec.0.borrow(), vec![3]);
    }

    #[test]
    fn a_framebuffer_with_no_handles_closes_nothing() {
        let rec = Recorder(Default::default());
        drop(FbHandles::new(&rec, [None; 4]));
        assert!(rec.0.borrow().is_empty());
    }

    /// FR-93 P3h — what GETFB2 gives a daemon without CAP_SYS_ADMIN: the
    /// geometry and no handle. Refused at open with the fix in words, never a
    /// failure on every frame. A buffer with its handle is read as before.
    #[test]
    fn a_scanout_without_its_handle_is_refused_at_open() {
        let why = unreadable([None; 4]).expect("refused");
        assert!(why.contains("CAP_SYS_ADMIN"), "{why}");
        assert!(why.contains("meshharbor config clear drm_capture"), "{why}");
        assert_eq!(unreadable([Some(handle(7)), None, None, None]), None);
        // What the viewer is shown, the cascade's prefix included, fits FR-80's
        // cap whole: the fix is at the end, where a cap cuts first.
        let shown = format!("drm_capture is on, but DRM capture could not open: {why}");
        let max = crate::capture::CaptureUnavailable::DETAIL_MAX;
        assert!(shown.chars().count() <= max, "{shown}");
    }
}
