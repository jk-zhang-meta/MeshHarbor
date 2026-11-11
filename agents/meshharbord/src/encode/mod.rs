// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Video encoder abstraction.
//!
//! Encoders consume `capture::Frame` values and produce NAL-unit-delimited
//! byte runs ready to feed into a WebRTC `TrackLocalStaticSample`.
//!
//! Backends are feature-gated so the agent builds on any host without
//! dragging in their system deps:
//!
//! - `openh264-encoder` → [`openh264_backend::Openh264Encoder`] (software)
//!
//! Future backends: `nvenc` / `qsv` / `vaapi` / `videotoolbox` / `mf`.

use std::sync::Arc;

use anyhow::Result;
use tunnel_core::env::node_env;

use crate::capture::{DirtyRect, Frame};

pub mod caps;
pub mod caps_cache;
pub mod cells;
pub mod color;
pub mod hwid;

#[cfg(feature = "openh264-encoder")]
pub mod openh264_backend;

#[cfg(feature = "vp9-444")]
pub mod libvpx;

#[cfg(all(target_os = "windows", feature = "mf-encoder"))]
pub mod mf;

// rc.64 — Option B HEVC plan. `ffmpeg-encoder` ships header-only here:
// the module declares zero callers and `available()` returns false, so
// every release build with the feature flipped on or off behaves
// identically. The CI plumbing that links stripped FFmpeg + libmfx is
// rc.65; the actual encoder backend is rc.66. See
// `docs/encoders.md` (rc.64) for the phased rollout.
#[cfg(feature = "ffmpeg-encoder")]
pub mod ffmpeg;

// Shared AIMD bitrate controller for the DataChannel pumps (VP9-444 +
// FFmpeg). Always compiled — it's pure (no ffmpeg/webrtc types), so its
// unit tests run on the default `cargo test --lib`. The pump features are
// what USE it, so allow dead_code on the signalling-only build to keep
// `clippy -D warnings` clean (mirrors `transport_is_constrained` below).
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub mod aimd;
/// FR-35 — the constrained ceiling learns the pair (pure controller).
pub mod ceiling_learn;
/// FR-112 P1 — an encoding thread asks the scheduler for its clock (a Linux
/// utilisation clamp): a periodic encoder is otherwise parked on a slow core.
pub mod clock;
/// FR-79 — the validity gate every estimator consumes: was this window
/// evidence about the PIPE? (pure; no clock, no I/O, and no kill switch —
/// it replaced three).
pub mod evidence;
/// FR-79 V3b / FR-74 — ONE belief about what the path carries, split into a
/// DEMONSTRATED floor (what arrived; available every window on every carrier)
/// and a pushed-back CAPACITY estimate (only when the path resisted). Pure.
pub mod pipe;
/// FR-71 T1a — which plane is the limiter this window: sender, path or
/// browser (pure). FR-79 made it load-bearing: the gate reads its verdict,
/// so it runs on every constrained window.
pub mod pipe_state;
/// FR-70 M3a — the media plan and its shadow: the pure producer of what the
/// media loop is allowed to know, and the per-field comparison against the
/// pump's inline values. Pure and tested on the default build; only the
/// FFmpeg DC pump runs it.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub(crate) mod plan;
/// FR-70 P1 — the remembered rate as a PRIOR that decays while nothing
/// measures (pure; no clock, no I/O).
pub mod prior;
/// FR-35 P2 — per-peer rate memory (one JSON file in the data dir).
pub mod rate_memory;
/// FR-63 B0 — the deterministic rate-law simulator. TEST-ONLY: it ships zero
/// bytes, and it exists so the cells the field cannot summon (a genuinely thin
/// pipe, a link that stalls on cue) can still be run against the SHIPPED laws.
/// ⚠️ A simulator result is evidence about a law, never about the fleet.
#[cfg(test)]
pub mod sim;
/// FR-63 — slow-start for the session opener (pure; no clock, no I/O).
pub mod slow_start;
/// FR-65 P0 — the pump stall watch's verdict and phase attribution (pure).
/// Extracted from the pump so it compiles and is tested on the DEFAULT feature
/// set: the rule deciding whether an operator ever sees a stall used to live
/// behind `ffmpeg-encoder`, i.e. unreachable in the lane everyone runs.
pub mod stall;
/// FR-70 M1 — the encoder thread (generic; the FFmpeg encoder implements its
/// trait behind the feature).
pub mod thread;

// Viewer-rate controller (rc.188) — folds the browser's measured `rc:decodestat`
// (decoded fps + struggling) into a send-fps cap for the DC pumps, so the agent
// settles at the viewer's real sustainable rate instead of firehosing 60 fps and
// relying on the (harmful) keyframe-storm the rc.184 `decode_pressure` heuristic
// tried and failed to break. Pure (unit-tested on the default build); only the
// pump features USE it.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub mod viewer_rate;

// FR-119 P1 — the frame rate a viewer asks for (`rc:fps`) and the answer the
// pump gives it in `rc:video-info`. Pure (unit-tested on the default build).
pub mod frame_rate;

// FR-119 P2b — what trials concluded about this host's rate classes, next to
// the probe cache and under its key. Its one caller is the FFmpeg pump, so a
// build without that pump has none.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub mod fps_class_cache;

// Encode-pressure controller — auto-reduces the maxrate ceiling when the
// SENDER's encoder saturates (avg encode time high), the dynamic version of
// the field-proven `FFMPEG_FPS=30`. Pure (unit-tested on the default build);
// only `media_pump_ffmpeg_dc` (the ffmpeg-encoder feature) USES it, so the
// dead_code allow is keyed on that feature alone.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub mod encode_pressure;

// Measured-rate stage 0 — the per-session delivered-rate estimate. Pure
// and unit-tested on the default build; the DC pumps feed it and the
// heartbeat reports it. Stage 0 DERIVES NOTHING from it: the number is
// observed and logged so it can be checked against known truth in the
// field before any ceiling depends on it.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub mod goodput;

// P3 (Parsec-class plan) — transport/codec-aware rate-profile helpers:
// persisted-flip rebuild decision (FlipTracker), per-codec maxrate factor
// (H.264 ×1.5 — text-sharpness field fix), H.264 CQ adjustment. Pure
// (unit-tested on the default build); only the ffmpeg DC pump USES it.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub mod rate_profile;

/// P8b — the encode-policy module: the resolution/ceiling decision table
/// the pumps execute. See `policy.rs` module docs. Only the (feature-
/// gated) DC pumps call it, hence the dead_code allow on the
/// signalling-only build — the decision-table tests still run there.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) mod policy;

/// P8c — the rate governor: one owner for the four rate controllers
/// (AIMD, viewer-rate, encode-pressure, downscale tier) the DC pumps
/// previously threaded by hand. Structural only — see `governor.rs`
/// module docs. Same dead_code rationale as `policy`.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) mod governor;

/// P8b stage 2 — the keyframe-force policy machine (pending-force
/// lifecycle: backstop retry, force-ignored rebuild fallback + churn
/// cooldown, resync scheduling, lock edge). See `kf_policy.rs` module
/// docs. Same dead_code rationale as `policy`/`governor`.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) mod kf_policy;

/// HW-downscale Phase A — the CPU resampler (moved out of peer.rs) with
/// cached taps + pooled buffers + alpha skip. No feature gate: the RTP
/// pump uses it too, and its tests run on the default build.
pub(crate) mod resample;

/// Serialises tests that read/write the shared rate env vars
/// (RELAY_MAX_KBPS, RATE_FACTOR_*, FFMPEG_MAXRATE_KBPS, SCALE_CQ_BOOST):
/// cargo's parallel runner interleaved them once the test count grew
/// (rc.191 field flake). Module-scoped (not tests-mod-private) since P8b
/// so `policy::tests` can take the same lock.
// RETIRED-NAME-ANCHOR-BEGIN
// Every retired name below is a test deliberately feeding the RETIRED
// `MESHHARBOR_AGENT_*` spelling in, to prove it does NOTHING. Until FR-46 P2b it
// proved the opposite — that field hosts kept working — and the names are the
// same either way, so rewriting them deletes the coverage while leaving the
// tests green.
// INVARIANT: a retired name here must be one a real host can still have set.
// docs/fr/FR-46
#[cfg(test)]
pub(crate) static RELAY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// FR-77 — `MESHHARBORD_ENCODER_CELLS_DENY` has the same shape: three tests set
/// it (`cells.rs` x2, `caps.rs`), `test_env` serialises nothing, and the
/// harness runs them in parallel — it flaked once in four native runs. A test
/// that only READS it twice and compares (`caps::tests::
/// not_probed_never_triggers_a_probe`) needs the lock as much as a writer.
#[cfg(test)]
pub(crate) static DENY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ---------------------------------------------------------------------
// Shared helpers usable by every backend.
// ---------------------------------------------------------------------

/// Resolution-scaled initial bitrate target.
///
/// A fixed bitrate across all sizes (which 0.1.10 used at 8 Mbps) is
/// either overkill or underkill at any resolution other than the one it
/// was tuned for; we derive from dims × fps × bpp/s. Desktop-content
/// bpp/s bumped to 0.15 in the RustDesk-parity sprint: we measured
/// RustDesk at ~0.14 bpp/s and decided perceptual parity on fine text
/// trumps a 30% bandwidth save. At 60 fps 1080p that's ≈18.7 Mbps
/// uncapped, which the 25 Mbps MAX now accommodates.
///
/// MAX bumped 15→25 Mbps so 4K60 HEVC isn't permanently clipped on
/// LAN/gigabit links. Adaptive bitrate driven by REMB still pulls the
/// effective bitrate down under congestion; this value is a ceiling,
/// not a target.
#[cfg_attr(
    not(any(
        feature = "openh264-encoder",
        all(target_os = "windows", feature = "mf-encoder")
    )),
    allow(dead_code)
)]
pub fn initial_bitrate_for(width: u32, height: u32) -> u32 {
    initial_bitrate_for_fps(width, height, 30)
}

/// Like `initial_bitrate_for` but parameterised on fps. Backends that
/// know their target rate (peer.rs sets it per-session via
/// target_fps_for) pass their real value; the default-30 form above is
/// kept for call sites that don't have fps in scope.
#[cfg_attr(
    not(any(
        feature = "openh264-encoder",
        all(target_os = "windows", feature = "mf-encoder")
    )),
    allow(dead_code)
)]
/// Legibility floor — below this bitrate, heavy codecs (HEVC / AV1) at
/// 1080p produce green chroma artefacts and unreadable terminal text
/// (2026-04-24 field report). Consulted by peer.rs as the REMB-safety
/// minimum so a collapsing REMB signal can't drop encode quality into
/// unusability while the link is still technically up.
pub const MIN_BITRATE_BPS: u32 = 1_500_000;

/// Area-scaled AIMD floor (field 2026-08-26, neo16 viewing Rozalina):
/// [`MIN_BITRATE_BPS`] was tuned as a 1080p legibility floor, but the
/// AIMD collapse rides it at ANY resolution — at 2880×1800 (5.2 MPix)
/// 1.5 Mbps is 0.006 bpp, unreadable mush for the whole post-collapse
/// phase of every drag burst. Scale the floor with the ENCODED area
/// (~0.6 bit/pixel-second at the nominal 30–60 fps band), capped at
/// 4 Mbps so huge panels don't demand more than a modest uplink:
/// ≤2.5 MPix → 1.5 M (unchanged), 2560×1600 → ~2.5 M, 2880×1800 →
/// ~3.1 M, 4K+ → 4 M.
///
/// UNCONSTRAINED sessions only — on a relay the 3 Mbps clamp is the
/// physics and a floor above it would pin the target AT the clamp,
/// disabling the multiplicative decrease entirely (the rc.171
/// starvation class). The AIMD additionally caps the floor at its live
/// ceiling, so a mid-session flip to relay can never invert the two.
/// Hatch: `MESHHARBORD_AREA_MIN_BITRATE=0` / config
/// `area_min_bitrate` restores the flat 1.5 M floor.
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn area_min_bitrate_bps(width: u32, height: u32, constrained: bool) -> u32 {
    if constrained || !area_min_bitrate_enabled() {
        return MIN_BITRATE_BPS;
    }
    let px = width as u64 * height as u64;
    (((px * 3) / 5) as u32).clamp(MIN_BITRATE_BPS, 4_000_000)
}

#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
fn area_min_bitrate_enabled() -> bool {
    tunnel_core::env::node_env("AREA_MIN_BITRATE").as_deref() != Some("0")
}

/// Measured-rate stage 1 kill switch (2026-08-27): when on (default),
/// the governor clamps the nominal bitrate ceiling to 85 % of the
/// session's MEASURED drain rate while an estimate holds — the session
/// tops out just under the pipe instead of rediscovering it by
/// congesting the send queue on every drag burst. See
/// `encode::goodput` for the sampling rules. Hatch:
/// `MESHHARBORD_MEASURED_CEILING=0` / config `measured_ceiling`.
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn measured_ceiling_enabled() -> bool {
    tunnel_core::env::node_env("MEASURED_CEILING").as_deref() != Some("0")
}

/// FR-59 P1 kill switch (2026-09-01): when on (default), the AIMD's
/// legibility floor descends toward a MEASURED pipe on a constrained
/// transport, so a link slower than the 1.5 Mbps `MIN_BITRATE_BPS` band
/// can actually be converged onto instead of pinning the encoder at a
/// multiple of what it carries. Evidence-gated — with no held goodput
/// estimate the nominal floor stands. `0` restores the flat floor.
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn slow_link_floor_enabled() -> bool {
    tunnel_core::env::node_env("SLOW_LINK_FLOOR").as_deref() != Some("0")
}

/// FR-62 A1 — apply a rate move IN PLACE on QSV (and keep NVENC's corrected
/// HRD sizing) instead of rebuilding the encoder. Default **OFF**: the PR
/// ships inert and this flips on only after A0 clears the QSV `MFXVideoENCODE_Reset`
/// on real Iris-Xe silicon. Env `MESHHARBORD_ENCODER_INPLACE_RATE` / config
/// `encoder_inplace_rate`. OFF = the pre-A1 behaviour byte-for-byte.
pub fn encoder_inplace_rate_enabled() -> bool {
    tunnel_core::env::node_env("ENCODER_INPLACE_RATE").as_deref() == Some("1")
}

/// FR-62 A2 — escape hatch: force NVENC rate moves back onto the pre-A2
/// IDR-rationing path (the pump defers a constrained increase instead of
/// applying it live) if some driver ever emits a keyframe on an in-place
/// reconfigure DESPITE the vendored-FFmpeg patch. Default **OFF** — the patch
/// dropped `resetEncoder=forceIDR=1` from `nvenc.c` and A0 measured 0/20
/// rate-caused IDRs on the RTX (default AND constrained). Env-only, like
/// `MESHHARBORD_HW_AUTO`; the tell that would justify flipping it is a rising
/// `idr_count` on a constrained NVENC heartbeat.
pub fn nvenc_assume_reconfig_idr() -> bool {
    tunnel_core::env::node_env("ENCODER_NVENC_ASSUME_IDR").as_deref() == Some("1")
}

/// FR-59 P1 — the absolute stop for the floor relief above (bps). Below
/// roughly this a full-resolution frame is illegible at any QP and the
/// honest lever is fewer PIXELS, not fewer bits; the relief exists to let
/// the AIMD converge, not to chase a pipe to zero. Env
/// `MESHHARBORD_SLOW_LINK_MIN_BITRATE` / config `slow_link_min_bitrate`
/// (default 200 000, clamped to [50 000, `MIN_BITRATE_BPS`] — a value
/// above the nominal floor is inert by construction, see
/// `goodput::measured_floor_bps`).
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn slow_link_min_bitrate_bps() -> u32 {
    tunnel_core::env::node_env("SLOW_LINK_MIN_BITRATE")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(200_000)
        .clamp(50_000, MIN_BITRATE_BPS)
}

/// FR-59 P2 kill switch (2026-09-01): when on (default), the CONSTRAINED
/// send-queue byte budget is denominated in the MEASURED drain rate
/// rather than the nominal relay ceiling. A budget expressed in
/// milliseconds is a lie unless the bits-per-second it divides by is the
/// pipe's: field 2026-09-01, `constrained_queue_ms` 450 against a 3 Mbps
/// nominal produced 168 750 bytes, which on the measured 395 kbps link
/// was **3.4 seconds** of standing queue — and the gate never fired.
///
/// ⚠ This consumes the same lumpy TURN-TCP estimate that `governor`
/// deliberately refuses for the CEILING, and the asymmetry is the whole
/// justification: an under-estimate shrinks the budget ⇒ more shedding ⇒
/// LOWER latency, whereas an under-estimated ceiling collapses quality.
/// A measurement may only ever LOWER the reference, never raise it.
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn constrained_queue_measured_enabled() -> bool {
    tunnel_core::env::node_env("CONSTRAINED_QUEUE_MEASURED").as_deref() != Some("0")
}

/// FR-59 P6 kill switch (2026-09-01): when on (default), a held goodput
/// measurement far below the FR-35 learned/seeded ceiling ABANDONS it
/// back to the nominal band. The rate memory keys on the nominated pair's
/// remote address, which on a relay is the RELAY's — so one fast office
/// day writes a number every later session through that relay inherits
/// for the memory's 7-day TTL, regardless of the client's own network
/// (field 2026-09-01: a 5 069 353 bps seed opened a session on a measured
/// 395 kbps hotspot). `0` keeps the seed until the AIMD walks it down.
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn seed_contradiction_enabled() -> bool {
    tunnel_core::env::node_env("SEED_CONTRADICTION").as_deref() != Some("0")
}

/// FR-59 P3 kill switch (2026-09-01): when on (default), the VIEWER's own
/// report of what is arriving — bytes/s received, and how much its transit
/// queue grew — drives the constrained rate loop.
///
/// This is the signal the agent structurally cannot produce for itself: on
/// a relayed path its send channel is empty while seconds of video sit in
/// the relay and the carrier (field 2026-09-01: `bytes_inflight` 1–4 KB
/// and `send_wait_max_ms` 0.1 ms in the windows the viewer reported
/// 2 284 ms of paint age). Unlike FR-15's age it needs no clock probe —
/// a byte count is local, and the queue drift is a DIFFERENCE of two
/// intervals, so the unknown offset cancels — which matters because on
/// exactly this kind of link the age report is absent or rejected in most
/// windows. `0` = observe-and-report only.
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn viewer_rate_clamp_enabled() -> bool {
    tunnel_core::env::node_env("VIEWER_RATE_CLAMP").as_deref() != Some("0")
}

/// FR-59 P4 kill switch (2026-09-01): when on (default), a transit queue
/// the viewer reports as too deep to cut our way out of is DRAINED — the
/// pump stops producing for a bounded, sub-second pause.
///
/// A rate cut alone drains a queue at `capacity − inflow`, the slowest
/// possible way: converging to 90 % of a 400 kbps pipe clears a 2 s
/// backlog at 40 kbps, i.e. over ~20 s, which is why the field session
/// stayed seconds behind even once it had stopped growing. Pausing sets
/// inflow to zero, so the backlog clears in the ~2 s it represents.
/// `0` = rate control only.
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn queue_drain_enabled() -> bool {
    tunnel_core::env::node_env("QUEUE_DRAIN").as_deref() != Some("0")
}

/// FR-59 P5 kill switch (2026-09-01): when on (default), a constrained
/// session whose pair the rate memory remembers as SLOW opens with fewer
/// pixels and fewer frames (see `rate_profile::slow_link_profile`).
///
/// The bitrate levers can make the encoder track a 400 kbps pipe; they
/// cannot make 1920×1200 at 30 fps legible through it — that is ~1.7 KB
/// per frame. `0` = open at the session's normal size regardless.
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn slow_link_profile_enabled() -> bool {
    tunnel_core::env::node_env("SLOW_LINK_PROFILE").as_deref() != Some("0")
}

/// Drag-latency P3 kill switch (2026-08-27): when on (default), a
/// rebuild-bound bitrate apply (QSV/AMF — no in-place reconfigure)
/// opens the replacement encoder on a BLOCKING THREAD while the current
/// one keeps producing frames, and swaps between frames — no mid-drag
/// stall, no dead air, and rate DROPS finally land DURING motion as
/// smaller frames instead of production skips. `0` restores the rc.445
/// motion-defer (applies held until 1.2 s of quiet, then a blocking
/// re-open). Hatch: `MESHHARBORD_BG_REBUILD=0` / config `bg_rebuild`.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub fn bg_rebuild_enabled() -> bool {
    tunnel_core::env::node_env("BG_REBUILD").as_deref() != Some("0")
}

/// FR-62 — run a rebuild-bound rate apply OFF-THREAD on CONSTRAINED sessions
/// too. Default **on**; `MESHHARBORD_BG_REBUILD_CONSTRAINED=0` restores the inline
/// rebuild.
///
/// Measured on Iris Xe (CORPLAP-1, 2026-09-02): a QSV encoder open costs
/// ~340-390 ms at maxrate >= 1.5 Mbps but **1.3-2.0 s at <= 1 Mbps**, in BOTH
/// `low_power` modes — and a constrained session is exactly where those targets
/// live. The inline apply therefore froze the whole pump for ~2 s. The old
/// rationale ("the rebuild stalls a frozen image nobody can see") holds only
/// while the scene stays static for the entire open; resume motion inside that
/// window and the session is dead air until it finishes.
///
/// ⚠️ This changes only WHERE the open runs, never WHEN the change lands: the
/// adoption stays gated on the same quiet window the defer policy already uses,
/// so the swap's IDR still arrives on a static scene. That distinction is the
/// whole point — adopting mid-motion on a thin pipe is the 2026-08-27 relay
/// regression that put the `!constrained` guard there in the first place.
pub fn bg_rebuild_constrained_enabled() -> bool {
    tunnel_core::env::node_env("BG_REBUILD_CONSTRAINED").as_deref() != Some("0")
}

/// FR-65 P0 — the pump stall watch. Default **on**: it costs two `Instant::now()`
/// per loop iteration (~20-40 ns each against a 16.7 ms frame budget at 60 fps)
/// and logs nothing until an iteration actually overruns.
///
/// 🔑 Its absence is why a 2 s encoder open hid for months. The pump already
/// measured `capture`/`scale`/`encode`/`send`, and the stall appeared in NONE of
/// them: the apply/rebuild phase was untimed, and a per-heartbeat AVERAGE cannot
/// represent a single outlier even where it is counted. `MESHHARBORD_PUMP_STALL_WATCH=0`
/// disables.
pub fn pump_stall_watch_enabled() -> bool {
    tunnel_core::env::node_env("PUMP_STALL_WATCH").as_deref() != Some("0")
}

/// FR-63 — open a session with [`slow_start`] instead of committing to a
/// constant. **Default OFF**: this is a controller change, and the FR's own
/// rule is that none ships live without a release of field evidence first.
/// `MESHHARBORD_RATE_SLOW_START=1` enables it per host for that measurement.
///
/// The evidence it exists to answer (CORPLAP-1 over a corp VPN): a session
/// opened at the nominal `2_550_000` into a path measured at `213_180` and
/// paid a 1550 ms paint, while another opened at a remembered `6_134_627` and
/// paid 6287 ms. Both directions of the same mistake — committing before
/// measuring.
pub fn rate_slow_start_enabled() -> bool {
    tunnel_core::env::node_env("RATE_SLOW_START").as_deref() == Some("1")
}

/// FR-70 M1 — the FFmpeg encoder lives on its own OS thread per session
/// (`rc-enc-<session>`) behind a command channel, instead of encoding under
/// `block_in_place` on whichever runtime worker polls the pump. Every
/// decision the pump makes is unchanged; a method call becomes a message.
/// Default **on** since 0.4.70: M1c met its gate on all three CORPLAP hosts on
/// 0.4.69 (encode and capture averages unchanged, the worst pass per window down
/// on every host); `media_thread = false` per device restores the inline path.
/// Env `MESHHARBORD_MEDIA_THREAD` / config `media_thread`.
pub fn media_thread_enabled() -> bool {
    tunnel_core::env::flag("MEDIA_THREAD", true)
}

/// FR-65 P0 — an iteration slower than this (ms) is logged once, with its phase
/// breakdown. `MESHHARBORD_PUMP_STALL_WARN_MS`.
///
/// **100 ms, lowered from the 250 ms this shipped with**, because the first field
/// data said 250 was blind to the class that actually hurts: CORPLAP-1 on the
/// corp VPN reported `iter_ms_max = 107.6` — real 100 ms+ passes, matching the
/// operator's own ">100 ms" and ">148 ms" age spikes — while `pump_stalls` stayed
/// **0**. Only the separately-logged max saw them, which is exactly why the max
/// is logged separately from the mean.
///
/// ⚠️ Deliberately a FLAT threshold, not a multiple of the frame budget. Scaling
/// it by `target_fps` is self-defeating: the pump lowers `target_fps` BECAUSE it
/// is already struggling, so a budget-relative bar RISES as the session degrades
/// and stops reporting precisely when the trouble starts. A pass is either fast
/// in wall-clock terms or it is worth a line.
pub fn pump_stall_warn_ms() -> u64 {
    tunnel_core::env::node_env("PUMP_STALL_WARN_MS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(100)
}

/// Drag-latency P5 kill switch (FR-1, 2026-08-27): when on (default), big
/// frames run the BGRA→NV12/I444 conversion in row bands across scoped
/// threads (byte-identical output; ~25→~15 ms of "encode" time at
/// 2880×1800). `0` restores the single-threaded dcv call. Hatch:
/// `MESHHARBORD_PAR_CONVERT=0` / config `par_convert`.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub fn par_convert_enabled() -> bool {
    tunnel_core::env::node_env("PAR_CONVERT").as_deref() != Some("0")
}

/// FR-10 kill switch (2026-08-27): when on (default), CONSTRAINED sessions
/// run IDR-thrifty — the idle-settle keyframe is suppressed (on a reliable
/// ordered DC it is a quality refresh, not a correctness need; the
/// request-driven resync stays) and deferred bitrate applies are spaced
/// (see [`relay_deferred_apply_allowed`]). Field (CORPLAP-3, 2026-08-27): each
/// such IDR was a single ~300 KB frame ≈ 1.2–1.5 s of a ~2 Mbps relay —
/// the "bulky" lumps. `0` restores the previous relay behaviour. Hatch:
/// `MESHHARBORD_RELAY_IDR_THRIFT=0` / config `relay_idr_thrift`.
#[cfg_attr(
    not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
    allow(dead_code)
)]
pub fn relay_idr_thrift_enabled() -> bool {
    tunnel_core::env::node_env("RELAY_IDR_THRIFT").as_deref() != Some("0")
}

/// FR-15 — whether the constrained-transport age loop (viewer paint-age →
/// fps cap + multiplicative decrease) is active. Default ON; kill switch
/// `relay_age_feedback=false` / `MESHHARBORD_RELAY_AGE_FEEDBACK=0`
/// reverts relay rate control to the open-loop 0.4.7 posture.
pub fn relay_age_feedback_enabled() -> bool {
    tunnel_core::env::node_env("RELAY_AGE_FEEDBACK").as_deref() != Some("0")
}

/// FR-10 — whether a deferred (quiet-flushed) bitrate apply may land on a
/// thrifty CONSTRAINED session. Each apply is a QSV/AMF re-open whose first
/// frame is an IDR — a lump on a thin pipe — so small moves wait out a
/// 15 s interval while a LARGE move (≥40 % relative — a genuine collapse
/// or recovery) applies promptly.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub fn relay_deferred_apply_allowed(
    since_last_apply: Option<std::time::Duration>,
    current_bps: u32,
    target_bps: u32,
) -> bool {
    const MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
    let (lo, hi) = if current_bps < target_bps {
        (current_bps, target_bps)
    } else {
        (target_bps, current_bps)
    };
    let big_move = lo == 0 || (hi as u64) * 10 >= (lo as u64) * 14;
    big_move || since_last_apply.is_none_or(|d| d >= MIN_INTERVAL)
}

/// How long ONE frame may sit inside the DataChannel send call before the
/// pump treats it as congestion, ms. `0` disables the signal.
///
/// Default 250: a healthy relay's send wait sits at ~0.2 ms p50 and, since
/// FR-18 bounded the carrier queue, ~200 ms p99 — so this fires on the tail
/// that FR-18 could not reach (SCTP's own window), not on ordinary jitter.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub fn send_stall_threshold() -> Option<std::time::Duration> {
    let ms = tunnel_core::env::node_env("SEND_STALL_MS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(250);
    (ms > 0).then(|| std::time::Duration::from_millis(ms))
}

/// FR-10 follow-up — MAY a rebuild-bound bitrate apply land right now?
///
/// One named rule for both apply paths. It exists because the spacing was
/// originally written into the DEFERRED flush only, and the sibling arm —
/// "the scene is quiet, apply now" — silently skipped it. At session start
/// nothing has moved yet, so that arm is always taken, and the AIMD's
/// startup ramp turned into two or three blocking QSV re-opens inside the
/// first 15 s, each shipping a fresh IDR onto a ~3 Mbps pipe (field
/// 2026-08-28: the operator's "always slow right after connecting").
///
/// Keeping the rule in one function is the point: a third apply path added
/// later gets the spacing by calling this, rather than by remembering.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub fn rebuild_apply_allowed(
    constrained: bool,
    thrift: bool,
    since_last_apply: Option<std::time::Duration>,
    current_bps: u32,
    target_bps: u32,
) -> bool {
    !(constrained && thrift)
        || relay_deferred_apply_allowed(since_last_apply, current_bps, target_bps)
}

/// MAX bumped 25→40 Mbps in rc.36. Field-confirmed (the field-test host) that
/// rc.35 at 1920×1200 Quality=High was content-bound around 13 Mbps,
/// well under the 25 Mbps cap — but `Quality=High × 1.5` math could
/// land above 25 Mbps at 4K@60 and was getting clipped. Lifting the
/// MAX gives Quality=High more room before the post-multiply clamp
/// in `quality::target_bitrate` kicks in, and gives the AIMD's
/// additive-increase headroom on the DC backpressure controller.
pub const MAX_BITRATE_BPS: u32 = 40_000_000;

/// rc.443 — consecutive-encode-error escalation for the FFmpeg DC pump.
/// The historical arm was `warn + continue` forever, which turned a
/// persistently-failing HW encoder into a silent frozen stream (field
/// 2026-08-21, corplap: av1_qsv returned `Invalid data` on a forced IDR — the
/// error alone would have looped; the driver then hung, which the
/// pipeline-staleness eviction covers). The ladder retries transient
/// errors, REBUILDS the encoder at 3 and 6 consecutive failures (a fresh
/// open clears most driver states and its first frame is an IDR), and at
/// 9 exits the pump CLEANLY — dropping the shared pipeline so followers
/// detach and the viewer renegotiates, possibly onto a different codec.
/// Any successful encode resets the ladder. Only the ffmpeg-encoder pump
/// consumes it, hence the feature-scoped dead_code allow (the `mod tests`
/// use does not count for a non-test build — the aimd/viewer_rate
/// pattern).
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
#[derive(Default)]
pub(crate) struct EncodeErrorLadder {
    consecutive: u32,
}

#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncodeErrorAction {
    /// Transient — skip this frame, keep the encoder.
    Retry,
    /// Drop + rebuild the encoder before the next frame.
    Rebuild,
    /// Unrecoverable — exit the pump so the session/pipeline tears down.
    ExitPump,
}

#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
impl EncodeErrorLadder {
    const REBUILD_EVERY: u32 = 3;
    const EXIT_AT: u32 = 9;

    pub fn on_error(&mut self) -> EncodeErrorAction {
        self.consecutive += 1;
        if self.consecutive >= Self::EXIT_AT {
            EncodeErrorAction::ExitPump
        } else if self.consecutive.is_multiple_of(Self::REBUILD_EVERY) {
            EncodeErrorAction::Rebuild
        } else {
            EncodeErrorAction::Retry
        }
    }

    pub fn on_success(&mut self) {
        self.consecutive = 0;
    }

    pub fn consecutive(&self) -> u32 {
        self.consecutive
    }
}

pub(crate) fn initial_bitrate_for_fps(width: u32, height: u32, fps: u32) -> u32 {
    // bpp/s bumped 0.15 → 0.20 in rc.36. RustDesk's published default is
    // ≈ 0.14–0.18; field reports (the field-test host, a second field-test host, 2026-05-17)
    // showed that 0.15 left desktop content visibly under-bitted at
    // 1920×1200 — fine text on Outlook / Start menu / Notepad++ took
    // multiple frames to sharpen after a window-uncover event. 0.20
    // gives the encoder ~33 % more bits, which combined with the
    // restored 240-frame keyframe interval lets a refresh land sharp.
    const DESKTOP_BPP_PER_SECOND: f64 = 0.20;
    let pixels = width as f64 * height as f64;
    let raw = (pixels * fps as f64 * DESKTOP_BPP_PER_SECOND) as u32;
    raw.clamp(MIN_BITRATE_BPS, MAX_BITRATE_BPS)
}

/// FR-112 P2 — the bitrate base for a software pump running at `fps`: today's
/// 30 fps figure, scaled by √(fps/30) rather than linearly. At 60 a moving
/// window travels half as far between frames, so a frame needs fewer bits than
/// at 30; and a base computed for 60 while the encoder is paced to 30 would
/// double every frame's bits (FR-112 §2: the 60 target took the VP9 ceiling from
/// 17.5 to 30.4 Mbps and bought nothing). At 30 it is exactly today's. Both
/// software pumps use it (the RTP pump's since P2b).
pub(crate) fn bitrate_base_for_fps(width: u32, height: u32, fps: u32) -> u32 {
    let at_30 = initial_bitrate_for_fps(width, height, 30) as f64;
    let scaled = at_30 * (fps.max(1) as f64 / 30.0).sqrt();
    (scaled.round() as u32).clamp(MIN_BITRATE_BPS, MAX_BITRATE_BPS)
}

/// FR-112 P2 — software encoders target 60 fps, paced down to what the encoder
/// sustains (`SoftwarePace`, fed by the pump's `avg_encode_ms`), with the
/// bitrate base following the rate they actually run at: the VP9-444 pump
/// (P2a) and the RTP pump's OpenH264 (P2b). Default **on for Linux**, where the
/// encoder asks for its clock (P1) and the tier was measured; Windows and
/// macOS opt in with `MESHHARBORD_SW_FPS_60=1` until P3 measures them on their own
/// hardware (60 frames cost twice the CPU of 30 on a host whose clock was
/// never the limit, and an attended desktop pays for it).
/// `MESHHARBORD_SW_FPS_60=0` restores 0.4.141's 30 fps and its base.
pub fn sw_fps_60_enabled() -> bool {
    tunnel_core::env::flag("SW_FPS_60", cfg!(target_os = "linux"))
}

/// FR-119 P1 — advertise `fps-high` in `AgentCaps.video`, so a viewer offers
/// frame rates above 60 and asks for one with `rc:fps`, and (P2b) let the pump
/// grant one. `MESHHARBORD_FPS_HIGH`, or the `fps_high` config key through the
/// bridge. Default **off** until the field has proven the grant. The probe child
/// inherits the environment, so it reads the same answer the daemon would.
pub fn fps_high_enabled() -> bool {
    tunnel_core::env::flag("FPS_HIGH", false)
}

/// FR-112 P2 — 0.4.141's software target, and the floor of the software tier's
/// pace: a software pump is never paced below it, so a host that cannot
/// sustain 30 runs exactly as it did (`encode_pressure::SoftwarePace`).
pub const SW_PACE_FLOOR_FPS: u32 = 30;

/// True when the ICE transport is forced to a TURN relay — on TCP (WSL,
/// corp-UDP-blocked nets) that path is bandwidth- + head-of-line-constrained.
/// Set by virtual-desktop mode and the corp path via MESHHARBORD_ICE_RELAY_TCP.
///
/// Only the VP9-444 DC pump (`vp9-444`) and the FFmpeg DC pump
/// (`ffmpeg-encoder`) consume this; the default-feature build has neither, so
/// the `dead_code` allow keeps the signalling-only CI build warning-clean
/// (mirrors `initial_bitrate_for`'s feature guard above).
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn transport_is_constrained() -> bool {
    node_env("ICE_RELAY_TCP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Bitrate ceiling (bps) for a constrained relay-TCP transport. Default 3 Mbps;
/// override with MESHHARBORD_RELAY_MAX_KBPS. A single TURN-TCP relay carries
/// ~1-4 Mbps; the VP9-444 0.20-bpp ~12 Mbps target collapses it (27s freeze).
///
/// See `transport_is_constrained` for why the `dead_code` allow is keyed on the
/// pump features (the `mod tests` use below does not count for a non-test build).
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn relay_max_bps() -> u32 {
    node_env("RELAY_MAX_KBPS")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|k| *k > 0)
        .map(|k| k.saturating_mul(1000))
        .unwrap_or(3_000_000)
}

/// Shared-pipeline egress split (default ON; `MESHHARBORD_SHARED_RATE_SPLIT=0` /
/// `false` reverts). On a CONSTRAINED (relay) transport every viewer of a
/// shared encoder gets its OWN ciphertext copy over the SAME host uplink to
/// the relay, so N viewers = N× egress; the DC pumps divide the ceiling by the
/// live viewer count so all copies together fit the pipe the AIMD is clamping
/// to. Without it a 2nd viewer's motion oversubscribes the relay and the
/// leader's ICE disconnects (field CORPLAP-3, two neo16 viewers, 2026-08-30).
/// Direct paths don't share a bottleneck this way and are never split.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn shared_rate_split_enabled() -> bool {
    !matches!(
        node_env("SHARED_RATE_SPLIT").as_deref(),
        Some("0") | Some("false")
    )
}

/// The per-viewer ceiling on a shared CONSTRAINED pipeline: the full ceiling
/// divided by the viewer count, floored at the per-stream minimum so no copy
/// drops below usable quality (the reactive backpressure/AIMD path trims any
/// residual oversubscription). A no-op for a single viewer or when disabled.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn shared_split_ceiling_bps(
    ceiling_bps: u32,
    viewers: u32,
    floor_bps: u32,
    constrained: bool,
    enabled: bool,
) -> u32 {
    if !enabled || !constrained || viewers <= 1 {
        return ceiling_bps;
    }
    (ceiling_bps / viewers).max(floor_bps)
}

/// FR-35 — the upper bound the LEARNED constrained ceiling may reach (bps).
/// `0` = learning off (today's fixed ceiling, no rate memory). Env
/// `MESHHARBORD_RELAY_MAX_HI_KBPS` / config `relay_max_hi_kbps`, gated by the
/// tribool `relay_ceiling_learn` (`MESHHARBORD_RELAY_CEILING_LEARN`, default on).
/// Default 8 000 kbps — from ONE pair's measurement (`neo16 → CORPLAP-2`
/// sustained ~6–9 Mbps and choked at 12.8); revisit with a second pair.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn relay_max_hi_bps() -> u32 {
    if !tunnel_core::env::flag("RELAY_CEILING_LEARN", true) {
        return 0;
    }
    node_env("RELAY_MAX_HI_KBPS")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|k| k.saturating_mul(1000))
        .unwrap_or(8_000_000)
}

/// rc.190 (B1) — long-edge RESOLUTION cap for a constrained relay-TCP
/// transport. `relay_max_bps` caps the bitrate at ~3 Mbps, but a 2560×1600
/// stream at 3 Mbps starves into the blur↔crystallize AIMD sawtooth (field
/// DEVBOX→WINHOST-A 2026-07-16) — fewer pixels per bit is the actual fix, so the
/// DC pumps also cap the encode resolution. Default 1280 long edge (≈1280×800
/// at 3 Mbps is smooth); env `MESHHARBORD_RELAY_MAX_EDGE`, `0` disables.
/// Hard cap: clamps even an explicit controller pick (it's link physics).
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn relay_res_cap_long_edge() -> Option<u32> {
    let v = tunnel_core::env::node_env("RELAY_MAX_EDGE")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(1280);
    (v > 0).then_some(v)
}

/// Loopback-TURN corp-relay (Phase 3): is a relay candidate's ADDRESS the local
/// agent's own fast TURN rather than the far capped coturn? The loopback-TURN
/// hands out its relay candidates on loopback (127.0.0.0/8, ::1) or the overlay
/// CGNAT/ULA range (100.64.0.0/10, fc00::/7); a real coturn relay lives at a
/// public IP. When `true` the relay classifier ([`crate::peer`]) must NOT flag
/// the pair as constrained — the whole point of routing a corp-Chrome viewer
/// through the local overlay TURN is full-quality video, not the coturn caps.
/// A public relay address (real coturn) still returns `false` ⇒ still capped.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn relay_addr_is_fast_local(addr: &str) -> bool {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            v4.is_loopback() || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
}

/// rc.190 (B2) — long-edge RESOLUTION cap for the SOFTWARE-encoded DC pump
/// (libvpx). Mirrors the RTP pump's SW auto-downscale: a 4K panel through
/// libvpx crawls (~25 fps at cpu-used 6, host CPU pinned — field WINHOST-H
/// 2026-07-16). Default 1920 long edge; env `MESHHARBORD_SW_MAX_EDGE`,
/// `0` disables. Soft cap: fills in only when the controller left resolution
/// at Native — an explicit rc:resolution pick wins ("operator can override",
/// same contract as the RTP pump's auto-downscale).
#[cfg_attr(not(feature = "vp9-444"), allow(dead_code))]
pub(crate) fn sw_res_cap_long_edge() -> Option<u32> {
    let v = tunnel_core::env::node_env("SW_MAX_EDGE")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(1920);
    (v > 0).then_some(v)
}

/// rc.199 — the "Smoother" priority resolution cap (long-edge px). Chosen
/// BELOW the relay hard cap (1280) so that even a direct-but-weak path sheds
/// pixels in exchange for frame-rate + latency when the operator explicitly
/// picks Smoother. Default 1024 long edge; env `MESHHARBORD_SMOOTH_MAX_EDGE`,
/// `0` disables (falls back to native, subject to any independent SW soft cap).
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn smooth_res_cap_long_edge() -> Option<u32> {
    let v = tunnel_core::env::node_env("SMOOTH_MAX_EDGE")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(1024);
    (v > 0).then_some(v)
}

/// rc.199 — the viewer "Priority" lever (`rc:priority` control message). A
/// per-session dial the controller flips to trade resolution sharpness against
/// motion smoothness. The control handler decodes the wire string to one of
/// these u8 codes into a per-session atomic; both DC video pumps read it to
/// resolve the relay resolution cap fed to `effective_target_resolution`.
pub mod priority {
    /// Default: honour the relay hard cap on a constrained (relay) path,
    /// native on a direct path. The pre-rc.199 behaviour.
    pub const BALANCED: u8 = 0;
    /// The user-facing "Sharpness override": lift the relay cap entirely so
    /// the encode stays at native long-edge even on a relay. Accepts possible
    /// stutter on a slow link in exchange for 1:1 pixels (crisp text).
    pub const SHARPER: u8 = 1;
    /// Cap harder (see `smooth_res_cap_long_edge`) on EVERY path so the
    /// encoder/decoder/link carry fewer pixels — favours frame-rate + latency.
    pub const SMOOTHER: u8 = 2;

    /// Decode the `rc:priority` `mode` wire string. Unknown values → `None`
    /// (caller keeps the session's current dial).
    pub fn from_wire(s: &str) -> Option<u8> {
        match s {
            "balanced" => Some(BALANCED),
            "sharp" | "sharper" => Some(SHARPER),
            "smooth" | "smoother" => Some(SMOOTHER),
            _ => None,
        }
    }

    /// Human label for logs.
    pub fn label(v: u8) -> &'static str {
        match v {
            SHARPER => "sharper",
            SMOOTHER => "smoother",
            _ => "balanced",
        }
    }
}

/// rc.199 — resolve the relay resolution cap (long-edge px) a DC video pump
/// feeds to `effective_target_resolution`, given the session's Priority dial
/// (`priority::*`) and whether the pump detected a constrained (relay)
/// transport. `None` = no relay cap (native, still subject to any independent
/// SW soft cap on the libvpx pump). Replaces the inline
/// `if constrained { relay_res_cap_long_edge() } else { None }` at both pumps.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn priority_relay_cap(priority: u8, constrained: bool) -> Option<u32> {
    // rc.445 — the dial dims-caps are OFF BY DEFAULT. Field 2026-08-21 (all
    // three test hosts, Smoother AND Balanced): every mid-motion rung flip
    // pays a BLOCKING QSV encoder open on the pump thread — measured
    // 865 ms for the Down and 654 ms for the Up on Iris-Xe-class (corplap,
    // `resolution cap engaged` → `encoder (re)built` deltas) — plus a
    // fresh IDR behind the queued frames. The user-felt result was "drag
    // takes off ~1 s, freezes ~1 s, then continues", and "Sharper is best"
    // on every host — i.e. never flipping beats the rung's steady-state
    // benefit. The rung's bit-shedding job moved to the continuous,
    // rebuild-free dial CEILING factor (`dial_rate_factor_pct` — the HRD
    // raises QP during motion by itself). `MESHHARBORD_PRIORITY_RES_CAP=1`
    // / config `priority_res_cap` restores the rc.443 caps for A/B.
    if !priority_res_cap_enabled() {
        return None;
    }
    // FR-70 M3a — the decision is `priority_relay_cap_for` over the caps read
    // here, per call, exactly as before; the plan producer reads them once.
    priority_relay_cap_for(
        priority,
        constrained,
        &PriorityCaps {
            dims_caps: true,
            smooth_long_edge: smooth_res_cap_long_edge(),
            relay_long_edge: relay_res_cap_long_edge(),
        },
    )
}

/// rc.445 — are the Priority dial's dims-caps restored (`MESHHARBORD_PRIORITY_RES_CAP`
/// / config `priority_res_cap`)? Off by default; see [`priority_relay_cap`].
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn priority_res_cap_enabled() -> bool {
    matches!(
        node_env("PRIORITY_RES_CAP").as_deref().map(str::trim),
        Some("1") | Some("true")
    )
}

/// FR-70 M3a — the Priority dial's dims-caps, resolved ONCE per pump for the
/// plan producer (`encode::plan`): the three knobs [`priority_relay_cap`]
/// reads per call. `Default` = the caps off, which is the shipped default.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PriorityCaps {
    /// The rc.443 dims-caps restored for A/B (off by default since rc.445).
    pub dims_caps: bool,
    /// `smooth_res_cap_long_edge` — Smoother's cap on every path.
    pub smooth_long_edge: Option<u32>,
    /// `relay_res_cap_long_edge` — Balanced's link-physics cap on a relay.
    pub relay_long_edge: Option<u32>,
}

impl PriorityCaps {
    #[cfg_attr(
        not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
        allow(dead_code)
    )]
    pub(crate) fn from_env() -> Self {
        Self {
            dims_caps: priority_res_cap_enabled(),
            smooth_long_edge: smooth_res_cap_long_edge(),
            relay_long_edge: relay_res_cap_long_edge(),
        }
    }
}

/// [`priority_relay_cap`] over explicit caps — the plan producer's form
/// (FR-70 M3a). The reader above is this applied to the caps it reads per
/// call; `priority_relay_cap_for_is_priority_relay_cap_over_explicit_caps`
/// locks the two together.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn priority_relay_cap_for(
    priority: u8,
    constrained: bool,
    caps: &PriorityCaps,
) -> Option<u32> {
    if !caps.dims_caps {
        return None;
    }
    match priority {
        // Sharpness override — native even on a relay.
        self::priority::SHARPER => None,
        // Fewer pixels on every path.
        self::priority::SMOOTHER => caps.smooth_long_edge,
        // Balanced (default + any unknown code): the link-physics hard cap
        // only on a constrained path.
        _ => {
            if constrained {
                caps.relay_long_edge
            } else {
                None
            }
        }
    }
}

/// rc.445 — the rebuild-free replacement for the dial dims-caps: a
/// per-dial bitrate-ceiling factor (percent). A lower ceiling makes the
/// HRD raise QP during motion continuously — smaller frames, steadier
/// arrival, more fps through a clamped pipe — with ZERO encoder rebuilds
/// and an untouched at-rest polish (a settled desktop never reaches the
/// ceiling, so CQ-quality stills are unaffected). Smoother trades the
/// most bits for fluidity; Sharper none. Env overrides
/// `MESHHARBORD_SMOOTHER_RATE_PCT` / `MESHHARBORD_BALANCED_RATE_PCT`
/// (clamped [30, 100]).
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn dial_rate_factor_pct(priority: u8) -> usize {
    let env_pct = |suffix: &str, default: usize| -> usize {
        node_env(suffix)
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map(|v| v.clamp(30, 100))
            .unwrap_or(default)
    };
    match priority {
        self::priority::SHARPER => 100,
        self::priority::SMOOTHER => env_pct("SMOOTHER_RATE_PCT", 70),
        _ => env_pct("BALANCED_RATE_PCT", 85),
    }
}

/// P7 (2026-08-20) — does idle native-rung refinement apply for this
/// Priority dial / transport combination? (See
/// `rate_profile::IdleRefine` for the state machine.)
///
/// Scope: **Smoother on every path** — that dial explicitly trades
/// pixels for motion smoothness, and a settled still costs neither, so
/// crisp-at-rest is pure win. **Balanced+relay** lifts the B1 *physics*
/// cap at idle (a native IDR is ~150-400 KB through a 3 Mbps pipe) —
/// opt-in at v1, default ON since P7c: a full field day on the winhost-b
/// relay (2026-08-20) showed clean refine cycles at exactly this IDR
/// cost, and the un-refined Balanced rung was the user-visible "still
/// blurred" report. `MESHHARBORD_IDLE_REFINE_BALANCED=0` restores the
/// old behaviour. Sharper has no cap to lift. The vp9-444 SW pump is
/// excluded entirely (refined-native keepalives would cost ~16 fps of
/// native libvpx SW encode while "idle" — a real CPU tax with none of
/// the HW pump's free-ness).
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub(crate) fn idle_refine_applies(priority: u8, constrained: bool) -> bool {
    match priority {
        self::priority::SMOOTHER => true,
        self::priority::SHARPER => false,
        _ => {
            constrained
                && !matches!(
                    node_env("IDLE_REFINE_BALANCED").as_deref().map(str::trim),
                    Some("0") | Some("false")
                )
        }
    }
}

/// P7 — long-edge cap for the REFINED rung. Default 0 = full native (rc.191
/// field data: even a 0.85× resample mushes ClearType, so a half-rung pays
/// the same rebuild + IDR without delivering 1:1 crispness). Safety valve
/// `MESHHARBORD_IDLE_REFINE_MAX_EDGE` (e.g. 1600) bounds the refined IDR
/// size if the field disagrees.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub(crate) fn idle_refine_cap_long_edge() -> Option<u32> {
    // node_env (not raw std::env) so the `idle_refine_max_edge` config-
    // surface key reaches this read through the fallback map.
    let v = node_env("IDLE_REFINE_MAX_EDGE")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(0);
    (v > 0).then_some(v)
}

#[derive(Debug, Clone)]
pub struct EncodedPacket {
    pub data: Vec<u8>,
    pub is_keyframe: bool,
    pub duration_us: u64,
    /// P8 Phase 5 (QP telemetry, record-only) — the encoder's reported
    /// quantizer for the frame this packet belongs to, in the CODEC'S
    /// NATIVE scale (H.264/HEVC avg-QP 0-51 recovered from FFmpeg
    /// quality stats; VP9 the libvpx last-quantizer index). `None` =
    /// the backend doesn't report one (openh264, MF, or an FFmpeg
    /// encoder that attaches no quality-stats side data). Feeds the
    /// pump heartbeats' avg/max-QP fields — the dataset that decides
    /// whether a closed quality loop replaces the area ladder. No
    /// control loop reads it.
    pub qp: Option<i32>,
}

/// Recover the encoder-reported average QP from an
/// `AV_PKT_DATA_QUALITY_STATS` side-data payload. Layout (libavcodec
/// packet.h): `u32le quality` (frame quality factor = QP ×
/// FF_QP2LAMBDA), `u8` pict type, `u8` error count, `u16` reserved, ….
/// NVENC and QSV fill it via `ff_side_data_set_encoder_stats(
/// frameAvgQP × FF_QP2LAMBDA)`; x264-class SW encoders likewise.
/// Zero/absent/short ⇒ `None` — an honest gap, not a zero QP.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub(crate) fn qp_from_quality_stats(data: &[u8]) -> Option<i32> {
    // FF_QP2LAMBDA = 118 (libavutil). Encoders pass exact multiples.
    const FF_QP2LAMBDA: u32 = 118;
    let quality = u32::from_le_bytes(data.get(..4)?.try_into().ok()?);
    (quality > 0).then_some((quality / FF_QP2LAMBDA) as i32)
}

#[async_trait::async_trait]
pub trait VideoEncoder: Send {
    /// Takes `Arc<Frame>` so the media_pump's last-good-frame cache can
    /// share ownership with the encode call without cloning the BGRA
    /// buffer (up to 33 MB at 4K, 8 MB at 1080p). The backend reads the
    /// frame and doesn't need to mutate it.
    async fn encode(&mut self, frame: Arc<Frame>) -> Result<Vec<EncodedPacket>>;
    /// Force the next frame to be a keyframe (IDR).
    fn request_keyframe(&mut self);
    /// Dynamically adjust bitrate in response to TWCC/REMB feedback.
    fn set_bitrate(&mut self, bps: u32);
    /// Recover from packet loss by invalidating the previous frame as
    /// a reference and forcing the next frame to be intra-coded
    /// (without necessarily being a full IDR). Default impl falls
    /// back to `request_keyframe`, which is correct but heavier
    /// (an IDR at 1080p is 60-100 KB vs an intra-refresh slice at
    /// ~5-15 KB). Backends that expose intra-only / non-IDR controls
    /// (NVENC's reference-frame invalidation, openh264's slice-level
    /// intra) can override to send a smaller recovery frame and
    /// avoid the bitrate spike that plays badly with congestion
    /// control. `lost_frame_number` is the RTP sequence number that
    /// was reported lost, for backends that want to invalidate a
    /// specific past frame as the reference.
    fn request_reference_invalidation(&mut self, lost_frame_number: u32) {
        let _ = lost_frame_number;
        self.request_keyframe();
    }
    /// Hint at per-region encoding priority for the next encoded
    /// frame. `rects` are the regions that changed since the previous
    /// frame; backends that expose ROI delta-QP (NVENC ROI maps,
    /// VideoToolbox attachments) should give those regions a low
    /// (high-quality) QP and the unchanged macroblocks a high
    /// (low-bitrate) QP. The single biggest efficiency lever for
    /// desktop content (see `docs/encoders.md`) — typical
    /// idle desktops drop 5-10× in bandwidth at the same perceived
    /// quality. `frame_dims` is the encode resolution (post-downscale)
    /// so backends can clip rects to the encoder grid.
    ///
    /// Default impl is a no-op. openh264 0.9.3 has no public ROI hook;
    /// MF + windows 0.58 only exposes `AVEncVideoROIEnabled` boolean
    /// (the per-frame map setter sits behind a non-exported GUID),
    /// so MF override today is also no-op-with-debug-log. Real ROI
    /// landed in HW backends will plug in here without touching the
    /// caller.
    fn set_roi_hints(&mut self, rects: &[DirtyRect], frame_dims: (u32, u32)) {
        let _ = (rects, frame_dims);
    }
    /// FR-112 P2b — the rate the pump feeds this encoder at, for a backend
    /// whose rate control budgets each frame's bits from it. OpenH264's is
    /// `max_frame_rate`: configured for 30 and fed 60 frames a second, it spends
    /// a 30 fps frame's bits on every one of them. Called when the pump's rate
    /// changes. Default: a no-op.
    fn set_frame_rate(&mut self, fps: u32) {
        let _ = fps;
    }
    /// Stable name for logging, e.g. `"openh264"`, `"nvenc-h264"`.
    fn name(&self) -> &'static str;

    /// Whether this backend is running on dedicated video-encode
    /// hardware (NVENC, QSV, AMF, Apple VideoToolbox). Defaults to
    /// `false` — only the MF path overrides when the cascade lands
    /// on a HW MFT. Callers use this to decide whether to apply the
    /// auto-downscale fallback: a SW HEVC encoder at 4K on an iGPU
    /// box can't sustain 30 fps, and forcing Fit@1080p is a much
    /// better default than asking the operator to notice and fix it.
    fn is_hardware(&self) -> bool {
        false
    }
}

pub struct NoopEncoder;

#[async_trait::async_trait]
impl VideoEncoder for NoopEncoder {
    async fn encode(&mut self, _frame: Arc<Frame>) -> Result<Vec<EncodedPacket>> {
        Ok(Vec::new())
    }
    fn request_keyframe(&mut self) {}
    fn set_bitrate(&mut self, _bps: u32) {}
    fn request_reference_invalidation(&mut self, _lost_frame_number: u32) {}
    fn set_roi_hints(&mut self, _rects: &[DirtyRect], _frame_dims: (u32, u32)) {}
    fn name(&self) -> &'static str {
        "noop"
    }
}

/// Operator preference for encoder selection. Defaults to `Auto` which
/// picks the fastest working backend: MF on Windows when available, else
/// openh264, else Noop. `Hardware` forces HW first and falls back to SW;
/// `Software` forces openh264 and never tries HW. Mostly a debug/escape-
/// hatch for drivers with known artefacts at our target bitrates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EncoderPreference {
    #[default]
    Auto,
    Hardware,
    Software,
}

impl std::str::FromStr for EncoderPreference {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" | "" => Ok(Self::Auto),
            "hardware" | "hw" | "mf" => Ok(Self::Hardware),
            "software" | "sw" | "openh264" => Ok(Self::Software),
            other => Err(format!("unknown encoder preference: {other:?}")),
        }
    }
}

impl EncoderPreference {
    /// The canonical spelling — what the LocalAPI reports and the config
    /// key accepts (`auto` | `hardware` | `software`), never an alias.
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Hardware => "hardware",
            Self::Software => "software",
        }
    }
}

/// FR-84 D4 — the encoder preference `run` RESOLVED (CLI > env > config >
/// `Auto`), published once so the LocalAPI reports what is actually in force
/// rather than re-deriving it from a config that a CLI flag or an env var may
/// have overridden. Unset in a process that never resolved one (`meshharbord
/// caps`, tests) — reported as absent, never guessed.
static RESOLVED_PREFERENCE: std::sync::OnceLock<EncoderPreference> = std::sync::OnceLock::new();

/// Record the preference `run` resolved. First writer wins; later calls are
/// ignored, like every other once-per-process fact here.
pub fn set_resolved_preference(p: EncoderPreference) {
    let _ = RESOLVED_PREFERENCE.set(p);
}

/// The preference `run` resolved, if this process resolved one.
pub fn resolved_preference() -> Option<EncoderPreference> {
    RESOLVED_PREFERENCE.get().copied()
}

/// Open the best-available encoder for the given input size.
///
/// Selection cascade:
///
/// | Preference | Order tried                                                 |
/// |------------|-------------------------------------------------------------|
/// | Auto       | mf (Windows with mf-encoder feature) → openh264 → Noop      |
/// | Hardware   | mf (required on Windows) → openh264 → Noop                  |
/// | Software   | openh264 → Noop                                             |
///
/// Auto now prefers MF-HW on Windows thanks to the probe-and-rollback
/// cascade in commit 1A.1 (adapter × MFT enumeration + single-frame
/// probe) — the failure modes that demoted MF from Auto in 0.1.25
/// (rate-control overshoot on the SW MFT, NVENC activation without
/// adapter matching, QSV async-only starvation) are all handled:
/// the SW MFT's async delegation is caught by blanket
/// MF_TRANSFORM_ASYNC_UNLOCK, adapter-bound D3D devices let NVENC
/// bind to the right GPU, and async-only MFTs route to the async
/// pipeline (commit 1A.2) or get skipped cleanly. The final fallback
/// inside the cascade is still the default-adapter SW MFT, so any
/// box with a working CLSID_MSH264EncoderMFT produces output.
///
/// #2283: under Auto, that fallback is not kept when it ignored the D3D
/// manager, which leaves Microsoft's encoder with no GPU behind it. On a
/// VM's Basic Render Driver it held frames for ~850 ms of input to photon
/// on the RTP track, against 37 ms for OpenH264 on the same host. OpenH264
/// takes its place wherever it is compiled in ([`keeps_mf`]).
///
/// Escape hatch: setting `MESHHARBORD_HW_AUTO=0` reverts Auto to
/// openh264-first (for diagnosing regressions in the field without
/// a rebuild). `--encoder software` and `encoder_preference=software`
/// still force openh264 unconditionally.
///
/// Each fallback is logged; the picked backend reports via
/// `.name()` so pump-level observability can attribute.
/// Whether `open_default` should attempt Media Foundation hardware probing first.
///
/// When the out-of-process `caps-probe` child failed or hung during this daemon
/// run (`hw_probe_failed == true`), the daemon treats this run as "no hardware
/// encoding" and MUST NOT enter in-process MF probing (even under `Auto` or
/// `Hardware` preference).
pub(crate) fn should_try_mf_first(
    preference: EncoderPreference,
    hw_auto_off: bool,
    hw_probe_failed: bool,
) -> bool {
    if hw_probe_failed {
        return false;
    }
    match preference {
        EncoderPreference::Hardware => true,
        EncoderPreference::Auto => !hw_auto_off,
        EncoderPreference::Software => false,
    }
}

/// Testable core of [`open_default`]: invokes `try_mf` only when
/// [`should_try_mf_first`] permits, otherwise goes straight to `open_sw`
/// (`openh264`) and finally `NoopEncoder`.
pub(crate) fn open_default_with<FMf, FSw>(
    width: u32,
    height: u32,
    preference: EncoderPreference,
    hw_auto_off: bool,
    hw_probe_failed: bool,
    try_mf: FMf,
    open_sw: FSw,
) -> Box<dyn VideoEncoder>
where
    FMf: FnOnce(u32, u32) -> Option<Box<dyn VideoEncoder>>,
    FSw: FnOnce(u32, u32) -> Option<Box<dyn VideoEncoder>>,
{
    let try_mf_first = should_try_mf_first(preference, hw_auto_off, hw_probe_failed);
    if try_mf_first {
        if let Some(enc) = try_mf(width, height) {
            return enc;
        }
    } else if hw_probe_failed && preference != EncoderPreference::Software {
        tracing::warn!(
            width,
            height,
            ?preference,
            "caps-probe child failed or hung in this run — skipping in-process MF probe and using software encoder directly"
        );
    } else if preference == EncoderPreference::Auto {
        tracing::info!(
            "MESHHARBORD_HW_AUTO=0 — skipping MF-HW on Auto, going straight to openh264"
        );
    }

    if let Some(enc) = open_sw(width, height) {
        return enc;
    }
    Box::new(NoopEncoder)
}

pub fn open_default(
    width: u32,
    height: u32,
    preference: EncoderPreference,
) -> Box<dyn VideoEncoder> {
    let hw_auto_off = hw_auto_disabled();
    let hw_probe_failed = caps::hw_probe_failed_for_run();
    open_default_with(
        width,
        height,
        preference,
        hw_auto_off,
        hw_probe_failed,
        |width, height| {
            #[cfg(all(target_os = "windows", feature = "mf-encoder"))]
            {
                match mf::MfEncoder::new(width, height) {
                    Ok(e)
                        if !keeps_mf(
                            preference,
                            e.is_pure_software(),
                            cfg!(feature = "openh264-encoder"),
                        ) =>
                    {
                        tracing::info!(
                            width,
                            height,
                            "mf-encoder ended on Microsoft's software MFT with no GPU behind it — \
                             using openh264 instead (#2283)"
                        );
                        drop(e);
                        None
                    }
                    Ok(e) => {
                        if e.is_hardware() {
                            tracing::info!(
                                width,
                                height,
                                preference = ?preference,
                                "encoder selected: mf-h264 (hardware)"
                            );
                        } else {
                            tracing::info!(
                                width,
                                height,
                                preference = ?preference,
                                "encoder selected: mf-h264 (software MFT)"
                            );
                        }
                        Some(Box::new(e) as Box<dyn VideoEncoder>)
                    }
                    Err(e) => {
                        tracing::warn!(
                            %e,
                            "mf-encoder init failed — falling back to openh264"
                        );
                        None
                    }
                }
            }
            #[cfg(not(all(target_os = "windows", feature = "mf-encoder")))]
            {
                let _ = (width, height);
                if preference == EncoderPreference::Hardware {
                    tracing::warn!(
                        "Hardware encoder requested but this build has no HW backend \
                         compiled in (rebuild with --features mf-encoder on Windows); \
                         falling back to software"
                    );
                }
                // On Auto with no mf-encoder feature, fall through silently —
                // openh264 is the expected default for Linux/macOS and for
                // Windows builds that didn't opt into MF.
                None
            }
        },
        |width, height| {
            #[cfg(feature = "openh264-encoder")]
            {
                match openh264_backend::Openh264Encoder::new(width, height) {
                    Ok(e) => {
                        tracing::info!(width, height, "encoder selected: openh264 (software)");
                        return Some(Box::new(e) as Box<dyn VideoEncoder>);
                    }
                    Err(e) => {
                        tracing::warn!(%e, "openh264 init failed — falling back to NoopEncoder");
                    }
                }
            }
            #[cfg(not(feature = "openh264-encoder"))]
            {
                let _ = (width, height);
                tracing::info!(
                    "built without openh264-encoder feature — using NoopEncoder. \
                     Rebuild with `--features openh264-encoder` (or `--features media`)."
                );
            }
            None
        },
    )
}

/// Open a codec-specific encoder, falling back to H.264 if the
/// requested codec has no compiled-in backend on this host.
///
/// `codec` is the MIME-style short name from
/// `caps::pick_best_codec` (`"h264"`, `"h265"`, `"av1"`, etc.).
/// Today only `"h264"` and `"h265"` have encoder backends; anything
/// else demotes to H.264 with a warning so the session still works
/// (the browser negotiated H.264 too, that's the universal default).
///
/// H.265 path: gated on `target_os = "windows"` + `mf-encoder` feature.
/// The HEVC cascade is HW-only (Windows ships no software HEVC encoder
/// CLSID); on failure we fall back to `open_default` which still walks
/// the H.264 cascade + openh264 fallback. The browser is already told
/// (via `set_codec_preferences`) which codec to expect — demotion at
/// this layer means the peer must re-advertise H.264 in the SDP
/// answer, which the caller in `peer.rs` handles.
/// FR-78 P2 — open ONE named FFmpeg encoder (`hevc_d3d12va`, `av1_vulkan`,
/// `h264_vaapi`, …) at the probe's settings, bypassing every cascade, so a
/// backend that never wins the cascade on a host (the vendor SDK sits above
/// it) can still be driven with real bytes by `encoder-smoke --name` and the
/// FR-62 ladder. `None` when the name is not one of the tables', the build
/// carries no FFmpeg, or no device on this host accepts it — the same open
/// the capability probe runs, so a cell the probe advertised opens here too.
/// Returns the codec's wire name with the encoder. Bypasses the denylist as
/// well, by design: the name is the operator's explicit request, and a
/// denied cell is exactly what `--name` exists to drive under the harness
/// before it is allowed back.
pub fn open_named(
    name: &str,
    width: u32,
    height: u32,
) -> Option<(Box<dyn VideoEncoder>, &'static str)> {
    #[cfg(feature = "ffmpeg-encoder")]
    {
        use meshharbor_remote_control::models::VideoBackend;
        let Some(name) = ffmpeg::FfmpegEncoder::static_name(name) else {
            tracing::warn!(name, "open_named: not a cascade-table encoder name");
            return None;
        };
        let codec = VideoBackend::from_ffmpeg_name(name).map(|(c, _)| c.wire())?;
        match ffmpeg::FfmpegEncoder::new_named_probe(name, width, height, false) {
            Ok(enc) => Some((Box::new(enc), codec)),
            Err(e) => {
                tracing::warn!(name, %e, "open_named: the encoder did not open on this host");
                None
            }
        }
    }
    #[cfg(not(feature = "ffmpeg-encoder"))]
    {
        let _ = (name, width, height);
        tracing::warn!("open_named: this build carries no FFmpeg backend");
        None
    }
}

pub fn open_for_codec(
    codec: &str,
    width: u32,
    height: u32,
    preference: EncoderPreference,
) -> (Box<dyn VideoEncoder>, &'static str) {
    let normalised = codec.to_ascii_lowercase();
    match normalised.as_str() {
        "av1" => open_for_codec_av1(width, height),
        "h265" | "hevc" => open_for_codec_hevc(width, height),
        _ => {
            if normalised != "h264" {
                tracing::warn!(
                    codec = %normalised,
                    "encoder: unknown codec — defaulting to H.264 (may not match negotiated track)"
                );
            }
            (open_default(width, height, preference), "h264")
        }
    }
}

/// Open a codec-specific encoder off the Tokio worker pool (`spawn_blocking`)
/// so a slow or wedged driver/encoder constructor never stalls runtime worker
/// threads servicing ICE/DTLS/signaling.
pub async fn open_for_codec_async(
    codec: String,
    width: u32,
    height: u32,
    preference: EncoderPreference,
) -> (Box<dyn VideoEncoder>, &'static str) {
    match tokio::task::spawn_blocking(move || open_for_codec(&codec, width, height, preference))
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(%e, "open_for_codec_async blocking task failed — falling back to NoopEncoder");
            (Box::new(NoopEncoder), "h264")
        }
    }
}

/// AV1 opener, factored out so the `#[cfg]` branches don't clutter the
/// main match. See `open_for_codec` for fail-closed reasoning — when
/// AV1 init fails we return a `NoopEncoder` rather than demoting to
/// HEVC/H.264 bytes because the track is already bound to `video/AV1`
/// in the peer and substituting a different codec's bitstream would
/// produce decoder garbage on the other end.
fn open_for_codec_av1(width: u32, height: u32) -> (Box<dyn VideoEncoder>, &'static str) {
    if caps::hw_probe_failed_for_run() {
        tracing::warn!(
            width,
            height,
            "caps-probe child failed or hung during this run — skipping in-process mf-av1 open"
        );
        return (Box::new(NoopEncoder), "av1");
    }
    #[cfg(all(target_os = "windows", feature = "mf-encoder"))]
    {
        match mf::MfEncoder::new_av1(width, height) {
            Ok(e) => {
                tracing::info!(width, height, "encoder selected: mf-av1 (hardware)");
                (Box::new(e), "av1")
            }
            Err(e) => {
                tracing::warn!(
                    %e,
                    "mf-av1 init failed; track is bound to video/AV1 so no bitstream demotion is safe. Session will have no video until reconnect with a lower Quality preference."
                );
                (Box::new(NoopEncoder), "av1")
            }
        }
    }
    #[cfg(not(all(target_os = "windows", feature = "mf-encoder")))]
    {
        let _ = (width, height);
        tracing::warn!(
            "AV1 requested but this build has no MF AV1 backend — session will have no video until reconnect with a lower Quality preference."
        );
        (Box::new(NoopEncoder), "av1")
    }
}

/// HEVC opener — same fail-closed semantics as `open_for_codec_av1`.
///
/// rc.72: when `MESHHARBORD_USE_FFMPEG=1` is set AND the
/// `ffmpeg-encoder` feature is compiled in, try the FFmpeg backend first
/// (`hevc_nvenc` → `hevc_qsv` → `hevc_amf`). Falls through to MF on
/// FFmpeg construction failure so a misconfigured opt-in doesn't break
/// existing sessions. Unset = MF default (preserves rc.71 behaviour).
fn open_for_codec_hevc(width: u32, height: u32) -> (Box<dyn VideoEncoder>, &'static str) {
    if caps::hw_probe_failed_for_run() {
        tracing::warn!(
            width,
            height,
            "caps-probe child failed or hung during this run — skipping in-process HEVC hardware open"
        );
        return (Box::new(NoopEncoder), "h265");
    }
    #[cfg(feature = "ffmpeg-encoder")]
    {
        if ffmpeg::available() {
            match ffmpeg::FfmpegEncoder::new_hevc(width, height) {
                Ok(e) => {
                    tracing::info!(
                        width,
                        height,
                        encoder = e.name(),
                        "encoder selected: ffmpeg HEVC (hardware via vendor SDK)"
                    );
                    return (Box::new(e), "h265");
                }
                Err(err) => {
                    tracing::warn!(
                        %err,
                        "MESHHARBORD_USE_FFMPEG=1 but ffmpeg HEVC construction failed; falling back to MF cascade"
                    );
                }
            }
        }
    }
    #[cfg(all(target_os = "windows", feature = "mf-encoder"))]
    {
        match mf::MfEncoder::new_hevc(width, height) {
            Ok(e) => {
                tracing::info!(width, height, "encoder selected: mf-h265 (hardware)");
                (Box::new(e), "h265")
            }
            Err(e) => {
                tracing::warn!(
                    %e,
                    "mf-h265 init failed; track is bound to video/HEVC so no bitstream demotion is safe. Session will have no video until reconnect with a lower Quality preference."
                );
                (Box::new(NoopEncoder), "h265")
            }
        }
    }
    #[cfg(not(all(target_os = "windows", feature = "mf-encoder")))]
    {
        let _ = (width, height);
        tracing::warn!(
            "HEVC requested but this build has no MF HEVC backend — session will have no video until reconnect with a lower Quality preference."
        );
        (Box::new(NoopEncoder), "h265")
    }
}

/// #2283 — does the session keep an MF H.264 encoder that opened? Not under
/// Auto when it is Microsoft's software MFT with no GPU behind it and
/// OpenH264 can stand in. An explicit `hardware` preference keeps it: the
/// operator asked for MF.
#[cfg_attr(
    not(all(target_os = "windows", feature = "mf-encoder")),
    allow(dead_code)
)]
fn keeps_mf(preference: EncoderPreference, pure_software: bool, openh264: bool) -> bool {
    !(preference == EncoderPreference::Auto && pure_software && openh264)
}

/// Check the `MESHHARBORD_HW_AUTO` escape hatch. Any value equal to
/// `"0"`, `"false"`, `"no"`, or `"off"` (case-insensitive) disables the
/// MF-HW-first branch of the Auto cascade. Unset or any other value
/// leaves the default (MF-HW first) in place.
fn hw_auto_disabled() -> bool {
    node_env("HW_AUTO")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-112 P2 — at 30 the base is exactly today's; at 60 it grows by √2,
    /// not 2×; it never leaves the bitrate bounds.
    #[test]
    fn the_software_base_is_todays_at_30_and_grows_by_root_two_at_60() {
        let (w, h) = (2048, 1080);
        assert_eq!(
            bitrate_base_for_fps(w, h, 30),
            initial_bitrate_for_fps(w, h, 30)
        );
        let at_60 = bitrate_base_for_fps(w, h, 60) as f64;
        let at_30 = initial_bitrate_for_fps(w, h, 30) as f64;
        assert!(
            (at_60 / at_30 - 2f64.sqrt()).abs() < 1e-3,
            "×√2, got ×{}",
            at_60 / at_30
        );
        assert!(
            bitrate_base_for_fps(w, h, 60) < initial_bitrate_for_fps(w, h, 60),
            "below the linear base that starved the encoder"
        );
        assert_eq!(bitrate_base_for_fps(7680, 4320, 60), MAX_BITRATE_BPS);
        assert_eq!(bitrate_base_for_fps(320, 240, 15), MIN_BITRATE_BPS);
    }

    /// #2283: only Auto drops the GPU-less software MFT, and only for
    /// OpenH264. A hardware MFT, a fallback that took the D3D manager, an
    /// explicit `hardware` preference, or a build without OpenH264 keeps
    /// what MF opened.
    #[test]
    fn auto_drops_only_the_gpu_less_software_mft_for_openh264() {
        use EncoderPreference::{Auto, Hardware, Software};
        assert!(!keeps_mf(Auto, true, true), "the case #2283 measured");
        assert!(
            keeps_mf(Auto, false, true),
            "a hardware MFT, or one with a GPU behind it"
        );
        assert!(keeps_mf(Auto, true, false), "no OpenH264 to stand in");
        assert!(keeps_mf(Hardware, true, true), "the operator asked for MF");
        // Software never opens MF at all; the predicate leaves it alone too.
        assert!(keeps_mf(Software, true, true));
    }

    /// The AIMD floor scales with encoded area on unconstrained sessions
    /// (1.5 M was a 1080p legibility tuning; at 5.2 MPix it is mush) and
    /// stays flat on constrained ones (a floor above the relay clamp
    /// would pin the target at the ceiling and disable the MD).
    #[test]
    fn area_min_bitrate_scales_unconstrained_only() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // ≤ ~2.5 MPix keeps the legacy floor.
        assert_eq!(area_min_bitrate_bps(1920, 1200, false), MIN_BITRATE_BPS);
        // 2880×1800 (the Rozalina panel) → ~3.1 Mbps.
        assert_eq!(area_min_bitrate_bps(2880, 1800, false), 3_110_400);
        // 4K caps at 4 Mbps.
        assert_eq!(area_min_bitrate_bps(3840, 2160, false), 4_000_000);
        // Constrained sessions are exempt regardless of area.
        assert_eq!(area_min_bitrate_bps(3840, 2160, true), MIN_BITRATE_BPS);
    }

    /// FR-10 — deferred-apply spacing on thrifty relays: small moves wait
    /// out 15 s, a ≥40 % move (genuine collapse/recovery) lands promptly,
    /// and the first-ever apply is always allowed.
    #[test]
    fn relay_deferred_apply_spacing() {
        use std::time::Duration;
        // First apply of the session — allowed.
        assert!(relay_deferred_apply_allowed(None, 2_000_000, 1_500_000));
        // Small rung-hop 3 s after the last apply — held.
        assert!(!relay_deferred_apply_allowed(
            Some(Duration::from_secs(3)),
            2_000_000,
            1_500_000
        ));
        // Same hop after the interval — allowed.
        assert!(relay_deferred_apply_allowed(
            Some(Duration::from_secs(16)),
            2_000_000,
            1_500_000
        ));
        // A collapse (3 M → 1.5 M = 2×) applies promptly regardless.
        assert!(relay_deferred_apply_allowed(
            Some(Duration::from_secs(1)),
            3_000_000,
            1_500_000
        ));
        // ...and so does a big recovery (1.5 M → 3 M).
        assert!(relay_deferred_apply_allowed(
            Some(Duration::from_secs(1)),
            1_500_000,
            3_000_000
        ));
    }

    /// The stall threshold is on by default and sits above the post-FR-18
    /// p99, so it fires on the SCTP tail rather than on ordinary jitter.
    #[test]
    fn send_stall_threshold_defaults_above_the_healthy_tail() {
        let d = send_stall_threshold().expect("on by default");
        assert!(d >= std::time::Duration::from_millis(200));
        assert!(d <= std::time::Duration::from_millis(1000));
    }

    /// FR-10 follow-up — the startup ramp must not become a rebuild storm.
    ///
    /// Replays the AIMD climb measured on CORPLAP-3 (2.55 M start, an early
    /// dip, then a steady climb to the 3 M relay ceiling over ~26 s). Every
    /// step is a small move, so after the first apply the spacing must hold
    /// them: the whole ramp costs ONE further re-open, not six.
    #[test]
    fn startup_ramp_costs_one_rebuild_not_six() {
        use std::time::Duration;
        let ramp = [
            (0u64, 2_550_000u32),
            (2, 2_167_500),
            (6, 2_355_000),
            (12, 2_542_500),
            (16, 2_730_000),
            (22, 2_917_500),
            (26, 3_000_000),
        ];
        let mut current = 2_550_000u32;
        let mut last_apply_at: Option<u64> = None;
        let mut applies = 0;
        for (t, target) in ramp {
            let since = last_apply_at.map(|a| Duration::from_secs(t - a));
            if rebuild_apply_allowed(true, true, since, current, target) {
                applies += 1;
                current = target;
                last_apply_at = Some(t);
            }
        }
        assert_eq!(
            applies, 2,
            "the ramp should cost one apply plus one after the interval, got {applies}"
        );
    }

    /// The same ramp on a DIRECT transport, or with the thrift hatch off,
    /// keeps the old behaviour: every move applies.
    #[test]
    fn spacing_is_constrained_and_thrift_only() {
        use std::time::Duration;
        for (constrained, thrift) in [(false, true), (true, false), (false, false)] {
            assert!(
                rebuild_apply_allowed(
                    constrained,
                    thrift,
                    Some(Duration::from_secs(1)),
                    2_000_000,
                    2_100_000
                ),
                "constrained={constrained} thrift={thrift} must not be spaced"
            );
        }
    }

    /// rc.443 — the encode-error ladder: retry twice, rebuild at 3 and 6,
    /// exit at 9; any success resets.
    #[test]
    fn encode_error_ladder_escalates_retry_rebuild_exit() {
        use EncodeErrorAction::*;
        let mut l = EncodeErrorLadder::default();
        let seq: Vec<_> = (0..9).map(|_| l.on_error()).collect();
        assert_eq!(
            seq,
            [
                Retry, Retry, Rebuild, Retry, Retry, Rebuild, Retry, Retry, ExitPump
            ]
        );
        // A success anywhere resets the ladder to the beginning.
        l.on_success();
        assert_eq!(l.consecutive(), 0);
        assert_eq!(l.on_error(), Retry);
    }

    // P8 Phase 5 — the quality-stats → QP recovery. NVENC/QSV pass
    // frameAvgQP × FF_QP2LAMBDA(118) exactly; 0/short payloads are
    // telemetry gaps, never a zero QP.
    #[test]
    fn qp_from_quality_stats_recovers_exact_multiples() {
        let mut payload = [0u8; 8];
        payload[..4].copy_from_slice(&(24u32 * 118).to_le_bytes());
        assert_eq!(qp_from_quality_stats(&payload), Some(24));
        payload[..4].copy_from_slice(&(51u32 * 118).to_le_bytes());
        assert_eq!(qp_from_quality_stats(&payload), Some(51));
    }

    #[test]
    fn qp_from_quality_stats_gaps_are_none() {
        assert_eq!(qp_from_quality_stats(&[0u8; 8]), None, "zero quality");
        assert_eq!(qp_from_quality_stats(&[1, 2]), None, "short payload");
        assert_eq!(qp_from_quality_stats(&[]), None, "empty payload");
    }

    #[test]
    fn hw_auto_disabled_reads_env() {
        // Both spellings must work: `node_env` prefers MESHHARBORD_* and falls
        // back to the retired MESHHARBOR_AGENT_* alias, and hosts in the field
        // still carry the alias in service units and wrapper scripts. Driving
        // the loop over both proves the PRIMARY name — which nothing covered
        // before FR-21 — and the fallback in one pass.
        //
        // SAFETY: set_var/remove_var are unsafe in Rust 2024 because
        // concurrent reads from other threads can race. This module has one
        // test that touches these vars, and it clears BOTH before each read.
        // Clearing only one would let an inherited value of the other decide
        // every assertion below, silently — which is what it did before.
        // FR-46 P2b: only the CURRENT spelling is read. The retired one is
        // asserted separately below — it must be inert, not merely absent.
        const NAMES: [&str; 1] = ["MESHHARBORD_HW_AUTO"];
        const RETIRED: &str = "MESHHARBOR_AGENT_HW_AUTO";
        let clear = || {
            for n in NAMES.iter().copied().chain([RETIRED]) {
                unsafe { std::env::remove_var(n) };
            }
        };

        clear();
        assert!(!hw_auto_disabled(), "unset defaults to MF-first");

        for name in NAMES {
            for truthy in ["0", "false", "FALSE", "No", "off"] {
                clear();
                unsafe { std::env::set_var(name, truthy) };
                assert!(
                    hw_auto_disabled(),
                    "{name}={truthy:?} should disable the MF-first branch"
                );
            }
            for enabled in ["1", "true", "yes", "on", ""] {
                clear();
                unsafe { std::env::set_var(name, enabled) };
                assert!(
                    !hw_auto_disabled(),
                    "{name}={enabled:?} should leave MF-first active"
                );
            }
        }

        // FR-46 P2b: the retired spelling is INERT. Asserted on its own rather
        // than dropped from the loop above, because "we stopped testing it" and
        // "it stopped working" look identical in a diff, and only one of them
        // is what this change intended.
        clear();
        // RAW-ENV-DELIBERATE: `test_env::set_as` refuses a prefix that is no
        // longer in the read chain, and this needs the retired one set alone.
        unsafe { std::env::set_var(RETIRED, "0") };
        assert!(
            !hw_auto_disabled(),
            "{RETIRED} must be ignored — it is retired, not an alias"
        );
        clear();
    }

    #[test]
    fn priority_from_wire_and_label_round_trip() {
        assert_eq!(priority::from_wire("balanced"), Some(priority::BALANCED));
        assert_eq!(priority::from_wire("sharp"), Some(priority::SHARPER));
        assert_eq!(priority::from_wire("sharper"), Some(priority::SHARPER));
        assert_eq!(priority::from_wire("smooth"), Some(priority::SMOOTHER));
        assert_eq!(priority::from_wire("smoother"), Some(priority::SMOOTHER));
        assert_eq!(priority::from_wire("nonsense"), None);
        assert_eq!(priority::label(priority::BALANCED), "balanced");
        assert_eq!(priority::label(priority::SHARPER), "sharper");
        assert_eq!(priority::label(priority::SMOOTHER), "smoother");
        // An out-of-range code decays to the safe default label.
        assert_eq!(priority::label(99), "balanced");
    }

    #[test]
    fn priority_relay_cap_resolves_per_dial() {
        // rc.445 — PRIORITY_RES_CAP is also toggled by media_share's
        // eligibility test; serialise via the shared env lock.
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Isolate from any operator env override so the defaults are asserted.
        // SAFETY: guarded by RELAY_ENV_LOCK against the known writers.
        unsafe {
            tunnel_core::env::test_env::clear("RELAY_MAX_EDGE");
            tunnel_core::env::test_env::clear("SMOOTH_MAX_EDGE");
            tunnel_core::env::test_env::clear("PRIORITY_RES_CAP");
        }
        // rc.445 DEFAULT: no dial dims-caps on any path — a mid-motion rung
        // flip costs a blocking encoder open (field-measured 0.65-0.87 s on
        // Iris Xe) and the field verdict was "never flipping beats the rung".
        for dial in [
            priority::BALANCED,
            priority::SHARPER,
            priority::SMOOTHER,
            42,
        ] {
            assert_eq!(priority_relay_cap(dial, true), None);
            assert_eq!(priority_relay_cap(dial, false), None);
        }
        // The restore switch brings back the rc.443 caps for A/B.
        unsafe { tunnel_core::env::test_env::set_as("MESHHARBORD_", "PRIORITY_RES_CAP", "1") };
        assert_eq!(priority_relay_cap(priority::BALANCED, true), Some(1280));
        assert_eq!(priority_relay_cap(priority::BALANCED, false), None);
        assert_eq!(priority_relay_cap(priority::SHARPER, true), None);
        assert_eq!(priority_relay_cap(priority::SHARPER, false), None);
        assert_eq!(priority_relay_cap(priority::SMOOTHER, true), Some(1024));
        assert_eq!(priority_relay_cap(priority::SMOOTHER, false), Some(1024));
        assert_eq!(priority_relay_cap(42, true), Some(1280));
        unsafe { tunnel_core::env::test_env::clear("PRIORITY_RES_CAP") };
    }

    /// FR-70 M3a — the per-call reader is the pure form over the caps it
    /// reads, with the switch off (the shipped default) and on.
    #[test]
    fn priority_relay_cap_for_is_priority_relay_cap_over_explicit_caps() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // SAFETY: guarded by RELAY_ENV_LOCK against the known writers.
        unsafe {
            tunnel_core::env::test_env::clear("RELAY_MAX_EDGE");
            tunnel_core::env::test_env::clear("SMOOTH_MAX_EDGE");
            tunnel_core::env::test_env::clear("PRIORITY_RES_CAP");
        }
        let dials = [
            priority::BALANCED,
            priority::SHARPER,
            priority::SMOOTHER,
            42,
        ];
        let caps = PriorityCaps::from_env();
        assert_eq!(
            caps,
            PriorityCaps {
                dims_caps: false,
                smooth_long_edge: Some(1024),
                relay_long_edge: Some(1280),
            }
        );
        for dial in dials {
            for constrained in [false, true] {
                assert_eq!(
                    priority_relay_cap_for(dial, constrained, &caps),
                    priority_relay_cap(dial, constrained)
                );
                assert_eq!(priority_relay_cap_for(dial, constrained, &caps), None);
            }
        }
        unsafe { tunnel_core::env::test_env::set_as("MESHHARBORD_", "PRIORITY_RES_CAP", "1") };
        let caps = PriorityCaps::from_env();
        assert!(caps.dims_caps);
        for dial in dials {
            for constrained in [false, true] {
                assert_eq!(
                    priority_relay_cap_for(dial, constrained, &caps),
                    priority_relay_cap(dial, constrained),
                    "dial {dial} constrained {constrained}"
                );
            }
        }
        assert_eq!(
            priority_relay_cap_for(priority::BALANCED, true, &caps),
            Some(1280)
        );
        assert_eq!(
            priority_relay_cap_for(priority::SMOOTHER, false, &caps),
            Some(1024)
        );
        assert_eq!(priority_relay_cap_for(priority::SHARPER, true, &caps), None);
        unsafe { tunnel_core::env::test_env::clear("PRIORITY_RES_CAP") };
    }

    #[test]
    fn dial_rate_factor_defaults_per_dial() {
        unsafe {
            tunnel_core::env::test_env::clear("SMOOTHER_RATE_PCT");
            tunnel_core::env::test_env::clear("BALANCED_RATE_PCT");
        }
        assert_eq!(dial_rate_factor_pct(priority::SHARPER), 100);
        assert_eq!(dial_rate_factor_pct(priority::SMOOTHER), 70);
        assert_eq!(dial_rate_factor_pct(priority::BALANCED), 85);
        // Unknown codes decay to Balanced, mirroring the cap fn.
        assert_eq!(dial_rate_factor_pct(42), 85);
    }

    // P7 — idle-refine scope matrix + the Balanced kill-switch env (P7c
    // flipped Balanced+relay from opt-in to default ON).
    #[test]
    fn idle_refine_applies_matrix() {
        let _guard = RELAY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: same hermetic save/restore contract as the sibling env
        // tests; serialised on RELAY_ENV_LOCK.
        let prior = std::env::var("MESHHARBORD_IDLE_REFINE_BALANCED").ok();
        unsafe { tunnel_core::env::test_env::clear("IDLE_REFINE_BALANCED") };

        // Smoother refines on EVERY path (its cap applies on every path).
        assert!(idle_refine_applies(priority::SMOOTHER, true));
        assert!(idle_refine_applies(priority::SMOOTHER, false));
        // Sharper has no cap to lift.
        assert!(!idle_refine_applies(priority::SHARPER, true));
        assert!(!idle_refine_applies(priority::SHARPER, false));
        // Balanced: default ON since P7c — relay only (no cap on direct).
        assert!(idle_refine_applies(priority::BALANCED, true));
        assert!(!idle_refine_applies(priority::BALANCED, false));
        // The kill switch restores the un-refined Balanced rung.
        unsafe { tunnel_core::env::test_env::set_as("MESHHARBORD_", "IDLE_REFINE_BALANCED", "0") };
        assert!(!idle_refine_applies(priority::BALANCED, true));
        assert!(!idle_refine_applies(priority::BALANCED, false));
        // The old opt-in spelling stays valid.
        unsafe { tunnel_core::env::test_env::set_as("MESHHARBORD_", "IDLE_REFINE_BALANCED", "1") };
        assert!(idle_refine_applies(priority::BALANCED, true));
        assert!(!idle_refine_applies(priority::BALANCED, false));

        match prior {
            Some(v) => unsafe {
                tunnel_core::env::test_env::set_as("MESHHARBORD_", "IDLE_REFINE_BALANCED", v)
            },
            None => unsafe { tunnel_core::env::test_env::clear("IDLE_REFINE_BALANCED") },
        }
    }

    #[test]
    fn shared_split_divides_constrained_ceiling_by_viewers() {
        use super::shared_split_ceiling_bps as split;
        const FLOOR: u32 = 1_500_000;
        // Single viewer: never split, on any transport.
        assert_eq!(split(6_000_000, 1, FLOOR, true, true), 6_000_000);
        // Direct transport: never split even with many viewers (each viewer
        // has its own good path; the relay uplink is not the bottleneck).
        assert_eq!(split(6_000_000, 3, FLOOR, false, true), 6_000_000);
        // Disabled (kill switch): never split.
        assert_eq!(split(6_000_000, 2, FLOOR, true, false), 6_000_000);
        // Two constrained viewers with headroom: half each, sum == the pipe.
        assert_eq!(split(6_000_000, 2, FLOOR, true, true), 3_000_000);
        // Three viewers: a third each.
        assert_eq!(split(6_000_000, 3, FLOOR, true, true), 2_000_000);
        // Floored: a thin relay can't split below usable quality — the
        // reactive backpressure/AIMD path trims the residual oversubscription.
        assert_eq!(split(2_500_000, 2, FLOOR, true, true), FLOOR);
    }

    // rc.191 — BOTH tests below read/write MESHHARBORD_RELAY_MAX_KBPS;
    // cargo's parallel runner interleaved them once the peer::tests grew
    // (field flake 2026-07-16: the clamp test observed the reader test's
    // mid-flight "4200" write). Serialise them on one lock — module-scoped
    // since P8b (see the definition next to `mod policy`).
    use super::RELAY_ENV_LOCK;

    #[test]
    fn relay_max_bps_reads_env() {
        let _guard = RELAY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // `relay_max_bps` reads through `node_env`, which prefers MESHHARBORD_*
        // and falls back to the retired MESHHARBOR_AGENT_*. This test used to set
        // ONLY the retired name, so it proved the third link of that chain and
        // left the spelling the code and docs actually use covered by nothing —
        // and, because it cleared only that one name, an inherited
        // MESHHARBORD_RELAY_MAX_KBPS would have decided every assertion below.
        //
        // SAFETY: set_var/remove_var are unsafe in Rust 2024 because concurrent
        // reads can race. Every test that touches these vars holds
        // RELAY_ENV_LOCK, and `clear` removes BOTH spellings before each read.
        // FR-46 P2b — see hw_auto_disabled_reads_env.
        const NAMES: [&str; 1] = ["MESHHARBORD_RELAY_MAX_KBPS"];
        const RETIRED: &str = "MESHHARBOR_AGENT_RELAY_MAX_KBPS";
        let prior: Vec<Option<String>> = NAMES.iter().map(|n| std::env::var(n).ok()).collect();
        let clear = || {
            for n in NAMES.iter().copied().chain([RETIRED]) {
                unsafe { std::env::remove_var(n) };
            }
        };

        clear();
        assert_eq!(
            relay_max_bps(),
            3_000_000,
            "unset defaults to the 3 Mbps relay ceiling"
        );

        for name in NAMES {
            clear();
            unsafe { std::env::set_var(name, "1500") };
            assert_eq!(
                relay_max_bps(),
                1_500_000,
                "{name}: kbps is multiplied by 1000"
            );

            // Whitespace-trimmed; a 0 / garbage value falls back to the default.
            unsafe { std::env::set_var(name, "  4200 ") };
            assert_eq!(
                relay_max_bps(),
                4_200_000,
                "{name}: value is trimmed before parse"
            );
            unsafe { std::env::set_var(name, "0") };
            assert_eq!(
                relay_max_bps(),
                3_000_000,
                "{name}: 0 is rejected -> default"
            );
            unsafe { std::env::set_var(name, "nope") };
            assert_eq!(relay_max_bps(), 3_000_000, "{name}: non-numeric -> default");
        }

        // FR-46 P2b: the retired spelling is INERT — it does not override, and
        // it does not apply on its own either. Asserted rather than dropped:
        // "we stopped testing it" and "it stopped working" look identical in a
        // diff, and only one of them is what this change intended.
        clear();
        // RAW-ENV-DELIBERATE: `test_env::set_as` refuses a prefix that is no
        // longer in the read chain, and this needs the retired one set alone.
        unsafe { std::env::set_var(RETIRED, "4200") };
        assert_eq!(
            relay_max_bps(),
            3_000_000,
            "{RETIRED} must be ignored — the default stands"
        );

        // Restore the pre-test environment.
        clear();
        for (n, v) in NAMES.iter().zip(prior) {
            if let Some(v) = v {
                unsafe { std::env::set_var(n, v) };
            }
        }
    }

    #[test]
    fn relay_clamp_caps_vp9_444_target() {
        let _guard = RELAY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The `x.min(relay_max_bps())` clamp the pump applies must pull a
        // 0.20-bpp 2560x1600@30 VP9-444 target (12_441_600 bps) down to the
        // 3 Mbps relay ceiling. Only the CURRENT spelling needs clearing: FR-46
        // P2b retired the other, so an inherited one cannot decide this ceiling.
        const NAMES: [&str; 1] = ["MESHHARBORD_RELAY_MAX_KBPS"];
        let prior: Vec<Option<String>> = NAMES.iter().map(|n| std::env::var(n).ok()).collect();
        for n in NAMES {
            unsafe { std::env::remove_var(n) };
        }

        let vp9_444_target: u32 = 12_441_600;
        assert_eq!(vp9_444_target.min(relay_max_bps()), 3_000_000);

        for (n, v) in NAMES.iter().zip(prior) {
            if let Some(v) = v {
                unsafe { std::env::set_var(n, v) };
            }
        }
    }

    /// Loopback-TURN corp-relay (Phase 3): the relay-address predicate. The local
    /// agent's own fast TURN (loopback / overlay relay addresses) must NOT be
    /// treated as a capped relay; a public coturn relay still must be.
    #[test]
    fn relay_addr_fast_local_excludes_loopback_and_overlay() {
        // Loopback + overlay CGNAT (100.64.0.0/10) + overlay ULA (fc00::/7).
        assert!(relay_addr_is_fast_local("127.0.0.1"));
        assert!(relay_addr_is_fast_local("::1"));
        assert!(relay_addr_is_fast_local("100.64.0.7"));
        assert!(relay_addr_is_fast_local("100.127.255.255"));
        assert!(relay_addr_is_fast_local("fd00::1"));
        // Public / other-private / garbage → still capped (not fast-local).
        assert!(!relay_addr_is_fast_local("100.63.255.255")); // below /10
        assert!(!relay_addr_is_fast_local("100.128.0.0")); // above /10
        assert!(!relay_addr_is_fast_local("8.8.8.8"));
        assert!(!relay_addr_is_fast_local("192.168.1.10"));
        assert!(!relay_addr_is_fast_local("2001:4860:4860::8888"));
        assert!(!relay_addr_is_fast_local("garbage"));
    }

    struct FakeSwOpenh264;
    #[async_trait::async_trait]
    impl VideoEncoder for FakeSwOpenh264 {
        async fn encode(&mut self, _frame: Arc<Frame>) -> Result<Vec<EncodedPacket>> {
            Ok(Vec::new())
        }
        fn request_keyframe(&mut self) {}
        fn set_bitrate(&mut self, _bps: u32) {}
        fn name(&self) -> &'static str {
            "openh264"
        }
    }

    #[tokio::test]
    async fn hung_caps_probe_child_forces_software_encoder_without_in_process_mf_probe() {
        let _guard = caps::HW_PROBE_FAILED_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        caps::clear_hw_probe_failed_for_run();

        // Simulate the caps-probe child hanging / timing out (outcome = None).
        let (probed_caps, child_succeeded) = caps::resolve_child_probe_outcome(None, Some(1), &[]);
        assert!(!child_succeeded);
        assert!(caps::hw_probe_failed_for_run());
        #[cfg(feature = "openh264-encoder")]
        assert_eq!(probed_caps.hw_encoders, vec!["openh264-sw".to_string()]);
        #[cfg(not(feature = "openh264-encoder"))]
        assert!(
            probed_caps
                .hw_encoders
                .iter()
                .all(|e| e.ends_with("-sw") || e == "noop")
        );

        // Verify that under Auto, Hardware, and Software preferences, open_default_with
        // selects software encoding (openh264) and NEVER invokes the in-process MF
        // probe closure.
        for pref in [
            EncoderPreference::Auto,
            EncoderPreference::Hardware,
            EncoderPreference::Software,
        ] {
            let mut mf_probe_called = false;
            let enc = open_default_with(
                320,
                180,
                pref,
                false,
                caps::hw_probe_failed_for_run(),
                |_w, _h| {
                    mf_probe_called = true;
                    panic!("in-process MF probe must not be called when caps-probe child hung");
                },
                |_w, _h| Some(Box::new(FakeSwOpenh264) as Box<dyn VideoEncoder>),
            );
            assert!(
                !mf_probe_called,
                "MF probe must not run for preference {pref:?} after child probe hang"
            );
            assert_eq!(enc.name(), "openh264");
            assert!(!enc.is_hardware());
        }

        // Also verify the async session opener (`open_for_codec_async`) runs off
        // the Tokio worker thread and selects software encoding while hw_probe_failed_for_run() is set.
        let (enc, codec) =
            open_for_codec_async("h264".to_string(), 320, 180, EncoderPreference::Auto).await;
        assert_eq!(codec, "h264");
        #[cfg(feature = "openh264-encoder")]
        assert_eq!(enc.name(), "openh264");
        assert!(!enc.is_hardware());

        // And AV1 / HEVC fail closed immediately without touching MF/FFmpeg drivers.
        let (av1_enc, av1_codec) =
            open_for_codec_async("av1".to_string(), 320, 180, EncoderPreference::Auto).await;
        assert_eq!(av1_codec, "av1");
        assert_eq!(av1_enc.name(), "noop");
        let (hevc_enc, hevc_codec) =
            open_for_codec_async("h265".to_string(), 320, 180, EncoderPreference::Auto).await;
        assert_eq!(hevc_codec, "h265");
        assert_eq!(hevc_enc.name(), "noop");

        caps::clear_hw_probe_failed_for_run();
    }
}
// RETIRED-NAME-ANCHOR-END
