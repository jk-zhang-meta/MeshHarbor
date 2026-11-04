// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! DXGI Desktop Duplication backend for the M3 A1 SYSTEM-context
//! worker.
//!
//! Wraps `scrap-0.5.0`'s DXGI-backed `Capturer` and translates the
//! `io::ErrorKind` surface into a 5-variant [`BackendBail`] enum the
//! capture pump can route on. The translation table is:
//!
//! | Inner DXGI HRESULT | After scrap wrapper translation | [`BackendBail`] | Action |
//! |---|---|---|---|
//! | `DXGI_ERROR_WAIT_TIMEOUT` | `WouldBlock` | [`Transient`] | Retry next tick |
//! | `DXGI_ERROR_NOT_CURRENTLY_AVAILABLE` | `Interrupted` | [`Transient`] | Short backoff |
//! | `E_ACCESSDENIED` | `PermissionDenied` | [`DesktopMismatch`] | `try_change_desktop` |
//! | `DXGI_ERROR_ACCESS_LOST` | `ConnectionReset` | [`AccessLost`] | Recreate `Capturer` + `try_change_desktop` |
//! | `DXGI_ERROR_SESSION_DISCONNECTED` | `ConnectionAborted` | [`SessionGone`] | Tear down worker |
//! | `DXGI_ERROR_UNSUPPORTED` | `ConnectionRefused` | [`HardError`] | Fall to GDI |
//! | `DXGI_ERROR_INVALID_CALL` | `InvalidData` | [`HardError`] | Programming error — log + tear down |
//! | (other) | `Other` | [`HardError`] | Log + tear down |
//!
//! [`Transient`]: BackendBail::Transient
//! [`DesktopMismatch`]: BackendBail::DesktopMismatch
//! [`AccessLost`]: BackendBail::AccessLost
//! [`SessionGone`]: BackendBail::SessionGone
//! [`HardError`]: BackendBail::HardError
//!
//! ## Why DXGI not WGC
//!
//! M3 A1 ran into a `0x80070424 (ERROR_SERVICE_DOES_NOT_EXIST)` from
//! `IGraphicsCaptureItemInterop::CreateForMonitor` when called from
//! the SYSTEM session 0 (`psexec -s -i 1` on the field-test host 2026-05-02).
//! WGC's WinRT activation chain has an undocumented service
//! dependency that doesn't exist in session 0. DXGI Desktop
//! Duplication has no WinRT activation and no service dependency —
//! works cleanly under SYSTEM. RustDesk's pattern is the same.
//!
//! ## `!Send` constraint
//!
//! `scrap::Capturer` is not `Send` (DXGI / D3D11 device handles
//! have thread affinity on Windows; the existing `scrap_backend.rs`
//! pins to a dedicated thread for the same reason). The M3 A1
//! capture pump is a single dedicated thread that owns one
//! [`DxgiDupBackend`] and drives it synchronously; nobody else
//! touches it.
//!
//! ## Stride
//!
//! `scrap::Frame` exposes `Deref<Target=[u8]>` only — no width /
//! height / stride. The buffer is BGRA8 (4 bytes per pixel) with
//! row-stride exactly `width * 4` on the DXGI Win32 path (DXGI
//! Desktop Duplication's `IDXGIOutputDuplication::AcquireNextFrame`
//! always returns tightly-packed buffers per Microsoft docs).
//! [`DxgiFrame::stride`] is therefore deterministic; we compute it
//! from `width * 4` rather than `bytes.len() / height` so the
//! backend exposes a stable contract even on partial frames.
//!
//! ## What this module does NOT do
//!
//! * No encoder pipeline integration — that's the job of the
//!   capture pump in `peer.rs` (or the SYSTEM-context-mode variant
//!   of it that the supervisor wires up).
//! * No GDI fallback — that's [`super::gdi_backend`] (TODO).
//! * No frame timing / cadence — same; the capture pump owns it.

#![cfg(target_os = "windows")]

use std::io;

/// What kind of failure the backend just reported. The capture pump
/// branches on this to decide between retry / rebind / recreate /
/// fall-through-to-GDI / tear-down.
#[derive(Debug)]
pub enum BackendBail {
    /// `WouldBlock` or `Interrupted`. No frame was available; either
    /// the desktop is static (most common — DXGI Desktop Duplication
    /// only emits frames on screen change) or the OS briefly
    /// throttled us. Retry next tick. **Not** an error worth logging
    /// at info — fires hundreds of times per second on a static
    /// desktop.
    Transient,
    /// `PermissionDenied`. The thread's desktop binding doesn't
    /// match the input desktop — usually because focus moved to
    /// Winlogon / UAC under our nose. Caller runs
    /// [`super::desktop_rebind::try_change_desktop`] then retries.
    /// No `Capturer` recreate needed; the existing one is still
    /// healthy, it just can't see the new desktop.
    DesktopMismatch,
    /// `ConnectionReset` (`DXGI_ERROR_ACCESS_LOST`). Most often a
    /// desktop transition (lock → unlock) where the OS revoked our
    /// duplication; can also be GPU device-lost on hybrid Optimus
    /// laptops (1-3/min observed on RustDesk hybrid GPU reports).
    /// Caller calls [`DxgiDupBackend::reset`] to drop+recreate the
    /// capturer, then retries.
    AccessLost,
    /// `ConnectionAborted` (`DXGI_ERROR_SESSION_DISCONNECTED`). The
    /// console / RDP session has gone away entirely. Capture cannot
    /// recover from inside the worker; supervisor needs to tear it
    /// down and respawn (or fall through to Idle).
    SessionGone,
    /// Any other `io::ErrorKind` — `InvalidData` (programming
    /// error), `ConnectionRefused` (driver doesn't support DXGI
    /// dup), `Other` (unknown). The capture pump logs the inner
    /// error and falls through to the GDI BitBlt backend; if that
    /// also fails, the supervisor tears down.
    HardError(io::Error),
}

impl BackendBail {
    /// Translate an `io::Error` (as emitted by `scrap::Capturer`) to
    /// a typed bail variant.
    pub fn from_io(e: io::Error) -> Self {
        match e.kind() {
            // `TimedOut` would also map to Transient but the scrap
            // wrapper at common/dxgi.rs:28-37 translates it to
            // `WouldBlock` for cross-platform consistency. Match
            // both anyway — costs nothing, defends against a future
            // wrapper change.
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
                Self::Transient
            }
            io::ErrorKind::PermissionDenied => Self::DesktopMismatch,
            io::ErrorKind::ConnectionReset => Self::AccessLost,
            io::ErrorKind::ConnectionAborted => Self::SessionGone,
            _ => Self::HardError(e),
        }
    }

    /// Whether the capture pump should retry without recreating the
    /// backend. True for `Transient` and `DesktopMismatch` (the
    /// latter assuming the input thread has handled the desktop
    /// rebind).
    pub fn is_retryable_without_reset(&self) -> bool {
        matches!(self, Self::Transient | Self::DesktopMismatch)
    }

    /// Whether the capture pump should recreate the backend (drop +
    /// new). True for `AccessLost` only.
    pub fn requires_reset(&self) -> bool {
        matches!(self, Self::AccessLost)
    }

    /// Whether the supervisor should tear the worker down. True for
    /// `SessionGone` and `HardError`.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::SessionGone | Self::HardError(_))
    }
}

/// One captured frame. BGRA8 always (the scrap DXGI backend's native
/// format). `stride = width * 4` — the DXGI Desktop Duplication API
/// returns tightly-packed buffers per Microsoft docs, but we expose
/// `stride` explicitly so downstream colour converters don't have
/// to recompute.
#[cfg(feature = "scrap-capture")]
pub struct DxgiFrame {
    /// BGRA8 pixel data, length `width * height * 4`.
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// Bytes per row. Always `width * 4` on the DXGI path; carried
    /// explicitly so callers don't have to remember.
    pub stride: u32,
    /// P8a — per-frame damage truth. The adapter-bound direct backend
    /// reads the duplication metadata (`GetFrameMoveRects` /
    /// `GetFrameDirtyRects`) and reports `Tracked`; the scrap-wrapped
    /// backend cannot (scrap's public API drops the frame info) and
    /// always reports `Unknown`.
    pub damage: crate::capture::Damage,
    /// Phase B — native dims when the backend GPU-scaled before the
    /// readback; `None` = the frame is native-sized.
    pub source: Option<(u32, u32)>,
}

/// Uniform interface over the two DXGI Desktop Duplication backends —
/// the `scrap`-wrapping [`DxgiDupBackend`] (auto-adapter) and the
/// adapter-bound [`super::dxgi_direct::DxgiDirectBackend`] (rc.108, the
/// hybrid-GPU fix). The capture pump holds a `Box<dyn DxgiCapture>` so its
/// per-frame match arm is identical regardless of which backend won at
/// startup. Gated on `scrap-capture` because the surface returns
/// [`DxgiFrame`]; the direct backend additionally needs `mf-encoder`.
#[cfg(feature = "scrap-capture")]
pub trait DxgiCapture {
    /// Acquire one frame (non-blocking). `BackendBail::Transient` on a
    /// static desktop (no new frame this tick). Phase B — `output_cap`
    /// is the pump's effective encode box: a GPU-capable backend MAY
    /// scale to it before the CPU readback (delivering `source` = native
    /// dims + damage in scaled coords); backends without a GPU path
    /// ignore it and deliver native.
    fn frame(&mut self, output_cap: Option<(u32, u32)>) -> Result<DxgiFrame, BackendBail>;
    /// Drop + recreate the duplication after `AccessLost`.
    fn reset(&mut self) -> Result<(), BackendBail>;
    /// Capture dimensions in pixels.
    fn dimensions(&self) -> (u32, u32);
    /// Short backend label for the worker heartbeat (`"dxgi-scrap"` /
    /// `"dxgi-direct"`) so a single `rc:logs-fetch` shows which DXGI path
    /// is live on a hybrid host.
    fn kind(&self) -> &'static str;
}

/// DXGI Desktop Duplication backend. Owns one `scrap::Capturer`
/// pinned to the calling thread. Not `Send`.
#[cfg(feature = "scrap-capture")]
pub struct DxgiDupBackend {
    capturer: scrap::Capturer,
    width: u32,
    height: u32,
}

#[cfg(feature = "scrap-capture")]
impl DxgiDupBackend {
    /// Open the primary display and construct a backend.
    ///
    /// Failure modes:
    /// * `Display::primary()` returns `Err(NotFound)` if no DXGI
    ///   adapter is enumerable — surfaces as
    ///   `BackendBail::HardError`. SYSTEM-context worker on a
    ///   headless box (no GPU) hits this.
    /// * `Capturer::new()` failures (driver init, etc.) also surface
    ///   as `HardError`.
    pub fn primary() -> Result<Self, BackendBail> {
        let display = scrap::Display::primary().map_err(|e| {
            BackendBail::HardError(io::Error::new(
                io::ErrorKind::NotFound,
                format!("scrap::Display::primary: {e}"),
            ))
        })?;
        let width = display.width() as u32;
        let height = display.height() as u32;
        let capturer = scrap::Capturer::new(display).map_err(|e| {
            // PRESERVE the io::ErrorKind. scrap returns E_ACCESSDENIED (the
            // thread isn't on a desktop it can duplicate yet — secure desktop
            // up, mid session-transition, etc.) as `PermissionDenied`, which
            // `from_io` classifies as the RECOVERABLE `DesktopMismatch` — same
            // as the per-frame path and the adapter-bound direct backend.
            // Flattening to `io::Error::other` here (the pre-fix behaviour)
            // dropped the kind to `Other`, so a transient desktop race surfaced
            // as a `HardError` and burned the 3-strike GDI fallback, pinning the
            // host on ~12 fps GDI. Re-wrap with the SAME kind + a `Capturer::new`
            // prefix so the HardError message stays self-describing in the field log.
            let kind = e.kind();
            BackendBail::from_io(io::Error::new(kind, format!("scrap::Capturer::new: {e}")))
        })?;
        Ok(Self {
            capturer,
            width,
            height,
        })
    }

    /// Width, height in pixels.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Try to acquire one frame. Synchronous; the scrap wrapper
    /// passes `MILLISECONDS_PER_FRAME=0` so this is non-blocking
    /// (returns `WouldBlock` immediately if no new frame is
    /// available). The capture pump owns timing.
    pub fn frame(&mut self) -> Result<DxgiFrame, BackendBail> {
        match self.capturer.frame() {
            Ok(buf) => {
                let stride = self.width * 4;
                let expected = (stride as usize) * (self.height as usize);
                if buf.len() < expected {
                    // Partial / undersized buffer — treat as a
                    // transient hiccup. DXGI shouldn't actually do
                    // this on a tightly-packed surface but defend
                    // against driver oddities.
                    return Err(BackendBail::Transient);
                }
                let bytes = buf[..expected].to_vec();
                Ok(DxgiFrame {
                    bytes,
                    width: self.width,
                    height: self.height,
                    stride,
                    damage: crate::capture::Damage::Unknown,
                    source: None,
                })
            }
            Err(e) => Err(BackendBail::from_io(e)),
        }
    }

    /// Drop the inner `Capturer` and reopen against the primary
    /// display. Called by the capture pump after `BackendBail::
    /// AccessLost`. Width / height may have changed across a
    /// resolution swap during the lock screen, so we re-read them.
    ///
    /// Failure: same shape as `primary()`.
    pub fn reset(&mut self) -> Result<(), BackendBail> {
        let new = Self::primary()?;
        // Replace inner state. Drop runs on the old `Capturer`,
        // which releases the duplication.
        *self = new;
        Ok(())
    }
}

#[cfg(feature = "scrap-capture")]
impl DxgiCapture for DxgiDupBackend {
    // Inherent methods win method resolution, so these delegate without
    // recursing. Kept as a thin shim so the capture pump can box this
    // backend behind `dyn DxgiCapture` alongside the adapter-bound one.
    fn frame(&mut self, _output_cap: Option<(u32, u32)>) -> Result<DxgiFrame, BackendBail> {
        // scrap owns the readback — no GPU-scale hook here.
        DxgiDupBackend::frame(self)
    }
    fn reset(&mut self) -> Result<(), BackendBail> {
        DxgiDupBackend::reset(self)
    }
    fn dimensions(&self) -> (u32, u32) {
        DxgiDupBackend::dimensions(self)
    }
    fn kind(&self) -> &'static str {
        "dxgi-scrap"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_io_would_block_is_transient() {
        let e = io::Error::from(io::ErrorKind::WouldBlock);
        assert!(matches!(BackendBail::from_io(e), BackendBail::Transient));
    }

    #[test]
    fn from_io_timed_out_is_transient() {
        // Defends against a future scrap wrapper change that stops
        // translating TimedOut → WouldBlock.
        let e = io::Error::from(io::ErrorKind::TimedOut);
        assert!(matches!(BackendBail::from_io(e), BackendBail::Transient));
    }

    #[test]
    fn from_io_interrupted_is_transient() {
        // DXGI_ERROR_NOT_CURRENTLY_AVAILABLE → Interrupted. Maps to
        // Transient (short backoff).
        let e = io::Error::from(io::ErrorKind::Interrupted);
        assert!(matches!(BackendBail::from_io(e), BackendBail::Transient));
    }

    #[test]
    fn from_io_permission_denied_is_desktop_mismatch() {
        // E_ACCESSDENIED → PermissionDenied → DesktopMismatch.
        let e = io::Error::from(io::ErrorKind::PermissionDenied);
        assert!(matches!(
            BackendBail::from_io(e),
            BackendBail::DesktopMismatch
        ));
    }

    #[test]
    fn init_permission_denied_wraps_to_desktop_mismatch() {
        // Fix lock: DxgiDupBackend::primary() re-wraps a scrap
        // Capturer::new failure with `io::Error::new(kind, msg)` (NOT
        // `io::Error::other`), so an E_ACCESSDENIED at init keeps its
        // PermissionDenied kind and classifies as the recoverable
        // DesktopMismatch. Reproduce that exact wrapping here.
        let scrap_err = io::Error::new(io::ErrorKind::PermissionDenied, "permission denied");
        let kind = scrap_err.kind();
        let wrapped = io::Error::new(kind, format!("scrap::Capturer::new: {scrap_err}"));
        assert!(matches!(
            BackendBail::from_io(wrapped),
            BackendBail::DesktopMismatch
        ));
    }

    #[test]
    fn from_io_connection_reset_is_access_lost() {
        // DXGI_ERROR_ACCESS_LOST → ConnectionReset → AccessLost.
        let e = io::Error::from(io::ErrorKind::ConnectionReset);
        assert!(matches!(BackendBail::from_io(e), BackendBail::AccessLost));
    }

    #[test]
    fn from_io_connection_aborted_is_session_gone() {
        // DXGI_ERROR_SESSION_DISCONNECTED → ConnectionAborted →
        // SessionGone.
        let e = io::Error::from(io::ErrorKind::ConnectionAborted);
        assert!(matches!(BackendBail::from_io(e), BackendBail::SessionGone));
    }

    #[test]
    fn from_io_connection_refused_is_hard_error() {
        // DXGI_ERROR_UNSUPPORTED → ConnectionRefused → HardError
        // (caller falls to GDI).
        let e = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert!(matches!(BackendBail::from_io(e), BackendBail::HardError(_)));
    }

    #[test]
    fn from_io_invalid_data_is_hard_error() {
        let e = io::Error::from(io::ErrorKind::InvalidData);
        assert!(matches!(BackendBail::from_io(e), BackendBail::HardError(_)));
    }

    #[test]
    fn from_io_other_is_hard_error() {
        let e = io::Error::other("unknown driver error");
        assert!(matches!(BackendBail::from_io(e), BackendBail::HardError(_)));
    }

    #[test]
    fn is_retryable_without_reset_covers_transient_and_desktop_mismatch() {
        assert!(BackendBail::Transient.is_retryable_without_reset());
        assert!(BackendBail::DesktopMismatch.is_retryable_without_reset());
        assert!(!BackendBail::AccessLost.is_retryable_without_reset());
        assert!(!BackendBail::SessionGone.is_retryable_without_reset());
        assert!(!BackendBail::HardError(io::Error::other("x")).is_retryable_without_reset());
    }

    #[test]
    fn requires_reset_only_for_access_lost() {
        assert!(!BackendBail::Transient.requires_reset());
        assert!(!BackendBail::DesktopMismatch.requires_reset());
        assert!(BackendBail::AccessLost.requires_reset());
        assert!(!BackendBail::SessionGone.requires_reset());
        assert!(!BackendBail::HardError(io::Error::other("x")).requires_reset());
    }

    #[test]
    fn is_terminal_covers_session_gone_and_hard_error() {
        assert!(!BackendBail::Transient.is_terminal());
        assert!(!BackendBail::DesktopMismatch.is_terminal());
        assert!(!BackendBail::AccessLost.is_terminal());
        assert!(BackendBail::SessionGone.is_terminal());
        assert!(BackendBail::HardError(io::Error::other("x")).is_terminal());
    }

    #[cfg(feature = "scrap-capture")]
    #[test]
    fn primary_does_not_panic_under_test_runner() {
        // The test runner has access to a primary display in the
        // user-context interactive case. Don't assert on the
        // outcome — CI without a GPU will fail the Capturer::new
        // step and surface HardError, which is the correct
        // behaviour. Lock against panic.
        let _ = DxgiDupBackend::primary();
    }
}
