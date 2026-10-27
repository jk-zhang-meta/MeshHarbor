// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-77 — the cell matrix's shared vocabulary: which FFmpeg encoders are
//! ever ASKED for 4:4:4, and the denylist that is the matrix's kill switch.
//!
//! Shared by the caps probe (what the hello advertises) and the session pump
//! (what a session may open), so the two can never disagree: a cell the probe
//! would not advertise is a cell no session opens, and vice versa.

// Every item here is read by the FFmpeg probe and pump; a build without
// that backend has nothing to ask the matrix.
#![cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]

use roomler_ai_remote_control::models::ChromaFormat;

/// FFmpeg encoder names whose 4:4:4 open the probe ATTEMPTS. Taken from the
/// FFmpeg n9.0 sources, not from vendor marketing: `h264_nvenc` and
/// `hevc_nvenc` list yuv444p (runtime-gated by
/// `NV_ENC_CAPS_SUPPORT_YUV444_ENCODE`), `hevc_qsv` and `vp9_qsv` list a
/// packed 4:4:4 form (VUYX — P3 teaches the pump that layout),
/// `hevc_vaapi`/`vp9_vaapi` carry the Main444 / profile-1 rows (P4). Every
/// AV1 encoder, every AMF encoder, VideoToolbox and Media Foundation cannot,
/// so they are never asked and never cost a failed open. Locked by a test
/// against the vocabulary.
pub(crate) const FFMPEG_444_CAPABLE: &[&str] = &[
    "h264_nvenc",
    "hevc_nvenc",
    "hevc_qsv",
    "vp9_qsv",
    "hevc_vaapi",
    "vp9_vaapi",
    // FR-78 — Vulkan HEVC lists 4:4:4 as runtime-decided (planar yuv444p
    // against the driver's format list); AV1 stays 4:2:0 by the AV1 rule
    // and D3D12 video encode is NV12/P010 only.
    "hevc_vulkan",
];

/// Cells this build will not open or advertise until a field test takes
/// them off the list. `name:chroma`. HEVC 4:4:4 on QSV and VAAPI start here
/// (the code called QSV Rext encode unreliable before it was ever opened);
/// the operator's `ROOMLERD_ENCODER_CELLS_DENY` / the `encoder_cells_deny`
/// config key REPLACES this default.
// `vp9_qsv:yuv444` joined on 2026-09-08: CORPLAP-3's Intel media runtime died
// with 0xc0000005 on the first VUYX open (FR-77 P3b field read) — the cell
// opens only once a driver proves it, through `encoder_cells_deny`.
pub(crate) const DEFAULT_DENIED_CELLS: &[&str] = &[
    "hevc_qsv:yuv444",
    "hevc_vaapi:yuv444",
    "vp9_qsv:yuv444",
    // P4: the packed 4:4:4 open on VAAPI is as unproven as it was on QSV.
    "vp9_vaapi:yuv444",
    // FR-78 — as unproven as every other non-NVENC 4:4:4 form: denied
    // until a driver survives the open on a fleet host.
    "hevc_vulkan:yuv444",
    // FR-78 P3 (the dev box, RTX 5090, 2026-09-08) — the one 4:2:0 entry.
    // The cell opens, encodes and reports nothing wrong, and its frames
    // cannot be decoded: dav1d fails every frame header ("Error parsing
    // frame header"), libaom aborts, Chrome paints garbage where the picture
    // changed. Reproduced with the FFmpeg CLI's own `av1_vulkan` on the same
    // GPU, with no roomler code in the loop — an FFmpeg 9.0.1 / NVIDIA
    // driver defect, not our packaging (the missing temporal delimiter WAS
    // ours to fix, and is). Leaves the list when a driver or FFmpeg release
    // decodes; the read is on the FR-78 spec.
    "av1_vulkan:yuv420",
];

/// The value that means "deny nothing". An EMPTY override means the same
/// (the P1 env contract); the word exists because a config key cannot carry
/// an empty string — `meshharbor config set encoder_cells_deny ""` CLEARS the
/// key back to the built-in default, so "nothing" needs a spelling.
pub(crate) const DENY_NOTHING: &str = "none";

pub(crate) fn ffmpeg_444_capable(name: &str) -> bool {
    FFMPEG_444_CAPABLE.contains(&name)
}

/// Parse an override value into denylist entries. `""` and `none` (any
/// case) are the empty list; entries are trimmed, blanks dropped.
pub(crate) fn parse_denylist(value: &str) -> Vec<String> {
    if value.trim().eq_ignore_ascii_case(DENY_NOTHING) {
        return Vec::new();
    }
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The effective denylist: the env/config override when set (it REPLACES
/// the built-in, it does not add to it), else the built-in.
pub(crate) fn denied_cells() -> Vec<String> {
    match tunnel_core::env::node_env("ENCODER_CELLS_DENY") {
        Some(v) => parse_denylist(&v),
        None => DEFAULT_DENIED_CELLS.iter().map(|s| s.to_string()).collect(),
    }
}

pub(crate) fn cell_denied(deny: &[String], name: &str, chroma: ChromaFormat) -> bool {
    let key = format!("{name}:{}", chroma.wire());
    deny.iter().any(|d| d == &key)
}

/// The encoder names a 4:4:4 session may try for `codec`, in cascade order:
/// every backend the source matrix can open in 4:4:4, minus the denylist.
/// Empty when no backend of this codec does 4:4:4 (AV1) or every one is
/// denied — the caller then runs the 4:2:0 cascade and reports the truth.
#[cfg(feature = "ffmpeg-encoder")]
pub(crate) fn names_444(codec: roomler_ai_remote_control::models::VideoCodec) -> Vec<&'static str> {
    let deny = denied_cells();
    crate::encode::ffmpeg::FfmpegEncoder::cascade_names(codec)
        .iter()
        .copied()
        .filter(|name| ffmpeg_444_capable(name) && !cell_denied(&deny, name, ChromaFormat::Yuv444))
        .collect()
}

/// The encoder names a 4:2:0 session may try for `codec`, in cascade order:
/// the whole table minus the denylist. Empty when every cell of the codec is
/// denied — the open then fails with the dispatcher's "no candidates" error,
/// which is the truth (the hello advertised nothing either), never a quiet
/// fallback to the raw table.
///
/// FR-78 P3 field read (jupiter, 2026-09-08): with `hevc_vaapi:yuv420` denied
/// the probe advertised only the Vulkan cells, and a HEVC session then opened
/// `hevc_vaapi` anyway — the 4:2:0 constructors handed the static table to the
/// dispatcher, and only the probe and the 4:4:4 list read the denylist. A kill
/// switch the probe honours and a session ignores is not a kill switch: the
/// probe opens in a child process, a session opens in the daemon — the crash
/// the list exists to keep out of the daemon was the one thing it did not
/// keep out.
#[cfg(feature = "ffmpeg-encoder")]
pub(crate) fn names_420(codec: roomler_ai_remote_control::models::VideoCodec) -> Vec<&'static str> {
    let deny = denied_cells();
    let names: Vec<&'static str> = crate::encode::ffmpeg::FfmpegEncoder::cascade_names(codec)
        .iter()
        .copied()
        .filter(|name| !cell_denied(&deny, name, ChromaFormat::Yuv420))
        .collect();
    if names.is_empty() {
        tracing::warn!(
            ?codec,
            ?deny,
            "every 4:2:0 cell of this codec is on the device denylist — nothing to open"
        );
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use roomler_ai_remote_control::models::{VideoBackend, VideoCodec};

    /// The 4:4:4 attempt list names only encoders the FFmpeg n9.0 sources can
    /// actually open in 4:4:4: nothing AV1 (`av1_nvenc` hard-errors "AV1 High
    /// Profile not supported"; every other AV1 backend lists 4:2:0 only),
    /// nothing AMF, nothing VideoToolbox — and every entry must be a name the
    /// vocabulary can split, or the probe would open it for nothing.
    #[test]
    fn ffmpeg_444_attempt_list_matches_the_source_matrix() {
        for name in FFMPEG_444_CAPABLE {
            let (codec, backend) = VideoBackend::from_ffmpeg_name(name)
                .unwrap_or_else(|| panic!("{name} is outside the cell vocabulary"));
            assert_ne!(
                codec,
                VideoCodec::Av1,
                "{name}: no AV1 encoder can do 4:4:4"
            );
            assert!(
                !matches!(backend, VideoBackend::Amf | VideoBackend::VideoToolbox),
                "{name}: AMF and VideoToolbox have no 4:4:4 surface"
            );
        }
        assert!(ffmpeg_444_capable("hevc_nvenc"));
        assert!(ffmpeg_444_capable("h264_nvenc"));
        assert!(ffmpeg_444_capable("vp9_qsv"));
        assert!(!ffmpeg_444_capable("av1_nvenc"));
        assert!(!ffmpeg_444_capable("hevc_amf"));
        assert!(!ffmpeg_444_capable("hevc_videotoolbox"));
    }

    /// The denylist is the kill switch: the built-in default keeps the
    /// unproven cells closed, the override replaces it wholesale, and an
    /// explicitly EMPTY override — or the word `none` — denies nothing.
    #[test]
    fn denylist_default_env_override_empty_and_none() {
        use tunnel_core::env::test_env::Saved;
        let _guard = crate::encode::DENY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _saved = Saved::cleared("ENCODER_CELLS_DENY");

        let deny = denied_cells();
        assert!(cell_denied(&deny, "hevc_qsv", ChromaFormat::Yuv444));
        assert!(cell_denied(&deny, "hevc_vaapi", ChromaFormat::Yuv444));
        assert!(
            cell_denied(&deny, "vp9_qsv", ChromaFormat::Yuv444),
            "CORPLAP-3, 2026-09-08"
        );
        assert!(!cell_denied(&deny, "hevc_qsv", ChromaFormat::Yuv420));
        assert!(!cell_denied(&deny, "hevc_nvenc", ChromaFormat::Yuv444));

        unsafe {
            tunnel_core::env::test_env::set(
                "ENCODER_CELLS_DENY",
                " h264_nvenc:yuv444 ,vp9_qsv:yuv444,",
            )
        };
        let deny = denied_cells();
        assert!(cell_denied(&deny, "h264_nvenc", ChromaFormat::Yuv444));
        assert!(cell_denied(&deny, "vp9_qsv", ChromaFormat::Yuv444));
        assert!(
            !cell_denied(&deny, "hevc_qsv", ChromaFormat::Yuv444),
            "the override REPLACES the default, it does not add to it"
        );

        unsafe { tunnel_core::env::test_env::set("ENCODER_CELLS_DENY", "") };
        assert!(
            denied_cells().is_empty(),
            "an empty override denies nothing"
        );
        unsafe { tunnel_core::env::test_env::set("ENCODER_CELLS_DENY", " None ") };
        assert!(denied_cells().is_empty(), "`none` denies nothing, any case");
    }

    #[test]
    fn parse_denylist_trims_and_drops_blanks() {
        assert_eq!(
            parse_denylist("a:yuv444, b:yuv420 ,,"),
            vec!["a:yuv444", "b:yuv420"]
        );
        assert!(parse_denylist("").is_empty());
        assert!(parse_denylist("NONE").is_empty());
    }

    /// The pump's 4:4:4 cascade is the probe's attempt list minus the
    /// denylist, in cascade order — so a session can never open a cell the
    /// hello did not advertise.
    #[cfg(feature = "ffmpeg-encoder")]
    #[test]
    fn names_444_follow_the_cascade_minus_the_denylist() {
        use tunnel_core::env::test_env::Saved;
        let _guard = crate::encode::DENY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _saved = Saved::cleared("ENCODER_CELLS_DENY");
        assert_eq!(
            names_444(VideoCodec::Hevc),
            vec!["hevc_nvenc"],
            "hevc_qsv is denied by default"
        );
        assert!(
            names_444(VideoCodec::Vp9).is_empty(),
            "vp9_qsv 4:4:4 is denied by default"
        );
        assert_eq!(names_444(VideoCodec::H264), vec!["h264_nvenc"]);
        assert!(names_444(VideoCodec::Av1).is_empty());
        unsafe { tunnel_core::env::test_env::set("ENCODER_CELLS_DENY", "none") };
        assert_eq!(
            names_444(VideoCodec::Hevc),
            vec!["hevc_nvenc", "hevc_qsv", "hevc_vaapi", "hevc_vulkan"]
        );
        assert_eq!(names_444(VideoCodec::Vp9), vec!["vp9_qsv", "vp9_vaapi"]);
    }

    /// FR-78 P3 (jupiter, 2026-09-08): with `hevc_vaapi:yuv420` denied the
    /// probe advertised only the Vulkan cells and a session opened
    /// `hevc_vaapi` anyway — the 4:2:0 cascades never read the list. The
    /// session's 4:2:0 list is the cascade minus the denylist, like the 4:4:4
    /// one, so what the hello advertises is all a session can reach.
    #[cfg(feature = "ffmpeg-encoder")]
    #[test]
    fn names_420_follow_the_cascade_minus_the_denylist() {
        use crate::encode::ffmpeg::FfmpegEncoder;
        use tunnel_core::env::test_env::Saved;
        let _guard = crate::encode::DENY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _saved = Saved::cleared("ENCODER_CELLS_DENY");
        for codec in [VideoCodec::Hevc, VideoCodec::H264, VideoCodec::Vp9] {
            assert_eq!(
                names_420(codec),
                FfmpegEncoder::cascade_names(codec).to_vec(),
                "the built-in denylist names no 4:2:0 cell of this codec"
            );
        }
        let av1 = names_420(VideoCodec::Av1);
        assert!(
            !av1.contains(&"av1_vulkan"),
            "av1_vulkan:yuv420 is denied by default (its frames do not decode): {av1:?}"
        );
        assert_eq!(
            av1.len(),
            FfmpegEncoder::cascade_names(VideoCodec::Av1).len() - 1,
            "and it is the only AV1 cell the built-in list removes"
        );
        unsafe {
            tunnel_core::env::test_env::set(
                "ENCODER_CELLS_DENY",
                "hevc_vaapi:yuv420,h264_vaapi:yuv420",
            )
        };
        let hevc = names_420(VideoCodec::Hevc);
        assert!(!hevc.contains(&"hevc_vaapi"), "{hevc:?}");
        assert!(
            hevc.contains(&"hevc_nvenc") && hevc.contains(&"hevc_vulkan"),
            "{hevc:?}"
        );
        assert_eq!(
            hevc.last(),
            Some(&"hevc_vulkan"),
            "the order is the cascade's"
        );
        assert!(!names_420(VideoCodec::H264).contains(&"h264_vaapi"));
        assert_eq!(
            names_420(VideoCodec::Av1),
            FfmpegEncoder::cascade_names(VideoCodec::Av1).to_vec(),
            "a deny names ONE cell, not a backend"
        );
        unsafe {
            tunnel_core::env::test_env::set(
                "ENCODER_CELLS_DENY",
                "hevc_nvenc:yuv420,hevc_qsv:yuv420,hevc_amf:yuv420,hevc_videotoolbox:yuv420,hevc_vaapi:yuv420,hevc_d3d12va:yuv420,hevc_vulkan:yuv420",
            )
        };
        assert!(
            names_420(VideoCodec::Hevc).is_empty(),
            "every cell denied ⇒ nothing to try, never a fallback to the raw table"
        );
    }
}
