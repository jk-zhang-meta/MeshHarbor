// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FFmpeg-based encoder backend (rc.72 onwards).
//!
//! Wraps `ffmpeg-next` to dispatch HEVC + H.264 + VP9 to vendor HW
//! encoders (NVENC, Intel QSV / oneVPL, AMD AMF) without going through
//! Windows Media Foundation. Bypasses two confirmed MF bugs:
//!
//! 1. `ActivateObject` returns 0x8000FFFF on RTX 5090 Blackwell for all
//!    HEVC / H.264 / AV1 MFTs (Known Issues, CLAUDE.md).
//! 2. Intel Iris Xe HEVC MFT is async-only on Tiger Lake; our MF cascade
//!    does not handle the async-MFT path correctly.
//!
//! As a bonus, FFmpeg's `vp9_qsv` encoder unlocks HW VP9 on Intel iGPUs
//! (unavailable via MF at all).
//!
//! ## Phased rollout (Option B plan, +7 shifted after vcpkg hotfixes)
//!
//! - rc.64–rc.71: scaffolding + CI plumbing (vcpkg ffmpeg install,
//!   ffmpeg-next link verification, DLL staging — 7 RCs of CI iteration
//!   to land a working FFmpeg 8.1.1 bundle in the agent MSI).
//! - **rc.72 (this RC)**: `FfmpegEncoder` lands in `encoder.rs`. Hooks
//!   into `open_for_codec_hevc` behind `ROOMLERD_USE_FFMPEG=1` env
//!   var. CPU BGRA→NV12 conversion via dcv_color_primitives. MF cascade
//!   still default.
//! - rc.73: D3D11VA zero-copy (capture's D3D11 texture fed directly to
//!   NVENC/QSV/AMF without CPU readback).
//! - rc.74: caps probe + HEVC DC framer + anti-IDR-storm coalescer.
//! - rc.75: browser HEVC worker.
//! - rc.76+: vp9_qsv, codec dropdown, AIMD, Linux/macOS.
//!
//! Pre-flight WebCodecs spike (2026-05-26) locked the wire design:
//! Annex-B + 4-byte start codes + no decoder description. See
//! `~/.claude/projects/.../memory/project_hevc_webcodecs_go.md`.

#[cfg(feature = "ffmpeg-encoder")]
pub mod encoder;
/// FR-77 P4 — the VAAPI device + frame pools (`*_vaapi` encoders only).
pub(crate) mod hwframes;

#[cfg(feature = "ffmpeg-encoder")]
pub use encoder::{FfmpegEncoder, RebuiltEncoder};
/// FR-70 M1 — the pump's handle: the encoder inline or on its own thread.
pub mod handle;
pub use handle::EncoderHandle;

/// rc.66 link probe. Returns libavcodec's compile-time version (e.g.
/// `0x3F0000` for libavcodec 63.x = FFmpeg 9.0). Forces the linker to
/// keep the FFmpeg static libs in the final binary so a missing or
/// version-mismatched FFmpeg fails at link time, not at encoder
/// construction time.
///
/// Encoded as `(major << 16) | (minor << 8) | micro`. FFmpeg 7.x uses
/// libavcodec 61.x; FFmpeg 8.x 62.x; FFmpeg 9.x 63.x. We assert >= 61
/// in the test so a binding regression to FFmpeg 6.x fails CI.
#[cfg(feature = "ffmpeg-encoder")]
pub fn linked_libavcodec_version() -> u32 {
    // Safety: avcodec_version is a pure C function returning a u32
    // constant set at libavcodec build time; no state, no allocation.
    unsafe { ffmpeg_next::ffi::avcodec_version() }
}

/// Whether the FFmpeg encoder backend is enabled for this process.
///
/// **rc.107: DEFAULT ON.** HEVC-over-DataChannel is the primary remote-video
/// path now, so the FFmpeg backend is enabled UNLESS explicitly disabled with
/// `ROOMLERD_USE_FFMPEG=0` (or `false`/`no`/`off`/empty). The rc.72 opt-IN
/// gate flipped this default because an MSI MajorUpgrade WIPES the operator's
/// service env block, and since 6bc9d58 every `agent-v*` bump is a MajorUpgrade
/// → the dropped `USE_FFMPEG=1` silently disabled HEVC FLEET-WIDE (caps stopped
/// advertising `data-channel-hevc` → black canvas; field rc.105→rc.106). The
/// caps probe still gates ADVERTISEMENT on a real `FfmpegEncoder` probe, so a
/// host without working HW HEVC/QSV falls back cleanly regardless of this flag.
#[cfg(feature = "ffmpeg-encoder")]
pub fn ffmpeg_backend_enabled() -> bool {
    use tunnel_core::env::node_env;
    match node_env("USE_FFMPEG") {
        // Explicit opt-OUT only. Any other value (the old truthy set, or
        // unrecognised text) leaves the backend ON.
        Some(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off" | ""
        ),
        None => true,
    }
}

/// rc.72 entrypoint: returns true when the FFmpeg backend is opted in
/// AND a real `FfmpegEncoder` is reachable. `available()` is consulted
/// by `encode::open_for_codec_hevc` to decide whether to try the FFmpeg
/// path before falling through to MF.
///
/// In the `#[cfg(not(feature = "ffmpeg-encoder"))]` build, this always
/// returns false — callers compile against the same signature so the
/// dispatch site doesn't need extra cfg gates.
#[cfg(feature = "ffmpeg-encoder")]
pub fn available() -> bool {
    ffmpeg_backend_enabled()
}

#[cfg(not(feature = "ffmpeg-encoder"))]
pub fn available() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_core::env::test_env::Saved;

    /// Both tests below write `USE_FFMPEG` and then assert on it, and libtest
    /// runs them on parallel threads of ONE process: unserialised, the first
    /// one's "unset → ON" can read the second one's `"0"`, and the second's
    /// "`0` → OFF" can read the first one's clear. Nothing outside this module
    /// writes the var; its other readers (`caps`, `peer`, `encode::mod`) are
    /// pump or probe paths whose tests assert nothing that depends on it.
    static USE_FFMPEG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn available_default_on_when_env_unset() {
        let _guard = USE_FFMPEG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Snapshots, clears, and restores on drop, including on a failed assert.
        let _saved = Saved::cleared("USE_FFMPEG");
        // rc.107 — DEFAULT ON in the ffmpeg-encoder build (HEVC-over-DC is
        // the primary path); the feature-off build hardwires available()=false.
        #[cfg(feature = "ffmpeg-encoder")]
        assert!(
            available(),
            "rc.107: FFmpeg backend defaults ON unless explicitly disabled (=0)"
        );
        #[cfg(not(feature = "ffmpeg-encoder"))]
        assert!(
            !available(),
            "feature-off build: available() is hardwired false"
        );
    }

    #[cfg(feature = "ffmpeg-encoder")]
    #[test]
    fn ffmpeg_backend_enabled_default_on_with_explicit_opt_out() {
        let _guard = USE_FFMPEG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _saved = Saved::cleared("USE_FFMPEG");
        assert!(ffmpeg_backend_enabled(), "rc.107: unset → ON (default)");
        for on in ["1", "true", "TRUE", "yes", "On", "whatever"] {
            unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "USE_FFMPEG", on) };
            assert!(
                ffmpeg_backend_enabled(),
                "value {on:?} (not an explicit off-value) should keep the FFmpeg backend ON"
            );
        }
        for off in ["0", "false", "no", "off", ""] {
            unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "USE_FFMPEG", off) };
            assert!(
                !ffmpeg_backend_enabled(),
                "value {off:?} should explicitly disable the FFmpeg backend"
            );
        }
    }

    /// rc.66 link verification. Exercises the FFmpeg dep so a missing
    /// or symbol-broken link fails locally + in CI before any encoder
    /// code runs. Asserts libavcodec major >= 61 (FFmpeg 7.0+), which
    /// is the version pair we depend on for `hevc_qsv` + `vp9_qsv`
    /// being reachable.
    #[cfg(feature = "ffmpeg-encoder")]
    #[test]
    fn libavcodec_version_is_ffmpeg_7_or_newer() {
        let v = linked_libavcodec_version();
        let major = (v >> 16) & 0xFF;
        assert!(
            major >= 61,
            "libavcodec {} is too old; need FFmpeg 7+ (libavcodec 61+) for hevc_qsv + vp9_qsv. \
             Raw version constant: 0x{:06X}",
            major,
            v
        );
    }
}
