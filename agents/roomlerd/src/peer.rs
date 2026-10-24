// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Thin wrapper around a `webrtc-rs` `RTCPeerConnection`.
//!
//! Owns the per-session WebRTC state: codecs, ICE, data channels, and (when
//! a capture/encoder backend is compiled in) a video track that's fed from
//! a spawned media pump task.
//!
//! Media pump lifecycle:
//!   1. On new(): add an `H264` track and spawn the pump.
//!   2. The pump asks `capture::open_default` for frames; if the build
//!      doesn't include `scrap-capture`, it gets a NoopCapture and never
//!      emits anything — track is added but carries no samples. The
//!      browser still negotiates the m=video section.
//!   3. On each frame, `encode::open_default` produces H.264 NALUs that
//!      become a `webrtc::media::Sample`. Sample duration is derived from
//!      the capture rate.
//!   4. On close(): cancels the pump, closes the PC.

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use roomler_ai_remote_control::signaling::{ClientMsg, IceServer, TransferDirection};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use tunnel_core::env::node_env;
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
// Only the VP9-444 DC pump consumes the per-session transport detection today
// (the FFmpeg pump joins in Phase B); keep the import off the signalling-only
// / FFmpeg-only builds so `clippy -D warnings` stays clean.
#[cfg(any(feature = "vp9-444", feature = "ffmpeg-encoder"))]
use webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::media::Sample;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::rtp_transceiver::RTCPFeedback;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;

use crate::capture;
use crate::encode;
use crate::input;
use crate::lock_overlay;
use crate::lock_state;
use crate::logs_fetch;

/// rc.26 — true when the current process is running as the SystemContext
/// worker (LocalSystem in the user's interactive session). Captured
/// once per session; the answer doesn't change at runtime (process
/// identity is fixed at spawn time). Used to gate two lock-screen
/// policies that are correct for user-context but wrong for
/// SystemContext:
///
///  - **Capture overlay substitution** (`media_pump` / `media_pump_vp9_444_dc`):
///    user-context can't see Winlogon → we substitute a "Host is
///    locked" overlay frame so the operator sees something instead of
///    a frozen black image. SystemContext capture rebinds to
///    `winsta0\Winlogon` and produces real lock-screen pixels —
///    substituting an overlay over those wastes the work and prevents
///    the operator from seeing the password prompt.
///
///  - **Input suppression** (`attach_input_handler`): user-context
///    `SendInput` can't drive Winlogon (no SE_TCB privilege).
///    SystemContext (LocalSystem) holds SE_TCB and can. Suppressing
///    input under SystemContext blocks remote unlock for no security
///    reason — the operator already has agent access.
///
/// Compiled out on non-Windows; the gates collapse to "always false"
/// (matches the rc.25 behaviour on Linux/macOS, where there is no
/// lock-screen capture-rebind story).
#[cfg(all(feature = "system-context", target_os = "windows"))]
fn is_system_context_worker() -> bool {
    use crate::system_context::worker_role;
    matches!(
        worker_role::probe_self(),
        Ok(worker_role::WorkerRole::SystemContext)
    )
}

#[cfg(not(all(feature = "system-context", target_os = "windows")))]
fn is_system_context_worker() -> bool {
    false
}

/// Target capture rate on the **software** path. openh264 pegs a CPU core
/// above ~35 fps at 1080p; 30 is the stable ceiling. See `target_fps_for`
/// for the hardware path which lifts to 60.
const TARGET_FPS_SW: u32 = 30;

/// Target capture rate on the **hardware** path. MF-HW + WGC handle
/// 2560×1600 @ 60 and 4K @ 60 comfortably on RTX-class GPUs. Bumping the
/// capture rate is the single biggest perceptual win against RustDesk's
/// native 60 fps pipeline — halves motion blur / step latency on pointer
/// and scroll.
const TARGET_FPS_HW: u32 = 60;

/// Pick a target capture rate consistent with the chosen encoder. On
/// Auto with `mf-encoder` compiled in we assume the cascade will land on
/// MF-HW (probe-gated at startup, falls back cleanly) and bias toward
/// 60. Everywhere else the 30 fps SW floor stays.
fn target_fps_for(pref: encode::EncoderPreference) -> u32 {
    match pref {
        encode::EncoderPreference::Hardware => TARGET_FPS_HW,
        #[cfg(all(target_os = "windows", feature = "mf-encoder"))]
        encode::EncoderPreference::Auto => TARGET_FPS_HW,
        _ => TARGET_FPS_SW,
    }
}

/// FR-112 P2b — the RTP pump's starting target: under the software tier every
/// encoder starts at 60 (a software one is then paced down to what it
/// sustains, never below 30); without it, [`target_fps_for`].
fn target_fps_with_tier(pref: encode::EncoderPreference, sw_tier: bool) -> u32 {
    if sw_tier {
        TARGET_FPS_HW
    } else {
        target_fps_for(pref)
    }
}

/// Quality preference advertised by the controller over the `control`
/// data channel. Encoded as `AtomicU8` so the media pump can poll it
/// per-frame without locking. Translated to a bitrate clamp on the
/// active encoder; future revisions may also clamp fps and downscale
/// when capture-side knobs (1F.1) are wired through.
mod quality {
    pub(super) const AUTO: u8 = 0;
    pub(super) const LOW: u8 = 1;
    pub(super) const HIGH: u8 = 2;

    /// Parse the wire-format string into the atomic value. Anything
    /// unrecognised maps to `AUTO` and is logged by the caller.
    pub(super) fn from_wire(s: &str) -> Option<u8> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(LOW),
            "auto" => Some(AUTO),
            "high" => Some(HIGH),
            _ => None,
        }
    }

    pub(super) fn label(v: u8) -> &'static str {
        match v {
            LOW => "low",
            HIGH => "high",
            _ => "auto",
        }
    }

    /// Map a quality preference to the bitrate target, scaled off the
    /// resolution-derived baseline. Low halves it (better fit for
    /// metered uplinks), High adds 50%. Ceiling lifted 30 → 50 Mbps in
    /// rc.36 (the field-test host / a second field-test host field test 2026-05-17) after the
    /// rc.33–rc.35 cycles still left fine-text legibility worse than
    /// RustDesk on common screen-content events (window-uncover,
    /// Outlook open). At 4K60 + High the resolution-derived base
    /// (`0.20 bpp × 3840×2160×60 ≈ 99.5 Mbps`) clamps to the
    /// `MAX_BITRATE_BPS = 40 Mbps` cap on the way in; `× 1.5` for
    /// High then lands on 50 Mbps after the post-multiply clamp —
    /// generous enough that scene-change frames can splurge without
    /// hitting the rate-control ceiling.
    pub(super) fn target_bitrate(quality: u8, base_bps: u32) -> u32 {
        const MAX_HIGH_BPS: u32 = 50_000_000;
        match quality {
            LOW => (base_bps / 2).max(500_000),
            HIGH => base_bps.saturating_mul(3) / 2,
            _ => base_bps,
        }
        .min(MAX_HIGH_BPS)
    }
}

/// Controller-requested encode resolution. `Native` keeps the agent's
/// monitor resolution; `Fixed` downscales post-capture to the target
/// dims before the encoder sees the frame. Lives in a shared
/// `Arc<Mutex<_>>` mutated by the `control` DC handler on `rc:resolution`
/// and polled by the media pump before each encode. The encoder's
/// existing dims-change rebuild path handles the teardown / reinit
/// when the effective frame size shifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetResolution {
    /// Agent picks — whatever the capture backend produces natively.
    Native,
    /// Controller-specified target. Downscale native → (w, h) before
    /// encode. Upscaling is a no-op: we cap at native so an over-large
    /// request (Fit mode on a viewport bigger than the source) doesn't
    /// waste encoder budget on upsampled pixels.
    Fixed { width: u32, height: u32 },
}

/// Pick the capture downscale policy consistent with an encoder
/// preference. HW encoders can eat 4K frames without breaking a sweat;
/// SW openh264 needs the 2× downsample to stay above ~30 fps at 1080p,
/// and can barely do 10 fps at native 4K without it.
fn downscale_for(pref: encode::EncoderPreference) -> capture::DownscalePolicy {
    match pref {
        encode::EncoderPreference::Software => capture::DownscalePolicy::Auto,
        encode::EncoderPreference::Hardware => capture::DownscalePolicy::Never,
        encode::EncoderPreference::Auto => {
            // On Windows with mf-encoder compiled in, the cascade picks
            // MF-HW first (probe-gated at startup, falls back to
            // openh264 cleanly if probe fails). The HW path handles 4K
            // at native resolution; the 2× CPU box filter is dead
            // weight that costs perceived resolution. Skip it — if the
            // cascade falls back to SW, the encoder itself will refuse
            // 4K@60 and the user still gets a working session at
            // degraded fps, which is strictly better than losing
            // native resolution unconditionally.
            #[cfg(all(target_os = "windows", feature = "mf-encoder"))]
            {
                capture::DownscalePolicy::Never
            }
            #[cfg(not(all(target_os = "windows", feature = "mf-encoder")))]
            {
                capture::DownscalePolicy::Auto
            }
        }
    }
}

pub struct AgentPeer {
    pc: Arc<RTCPeerConnection>,
    session_id: bson::oid::ObjectId,
    media_pump: Option<JoinHandle<()>>,
    /// System-audio → Opus pump. `Some` only when the session
    /// negotiated `audio_enabled` AND the `audio` feature is compiled
    /// in. Held so `close()` can abort it alongside the video pump.
    #[cfg(feature = "audio")]
    audio_pump: Option<JoinHandle<()>>,
    /// Reads RTCP from the video sender to handle PLI/FIR. Held so that
    /// `close()` can abort it — otherwise it outlives the AgentPeer and
    /// leaks under session churn until `video_sender.read_rtcp()` errors
    /// on its own, which isn't guaranteed to happen promptly.
    rtcp_reader: Option<JoinHandle<()>>,
    /// Wave 2 — the viewer's own decoded-fps report (`rc:decodestat`),
    /// packed as `(fps & 0xFFFF) | (struggling << bit)`. Held so session
    /// telemetry can report the fps the USER actually saw rather than
    /// what we hoped to send.
    viewer_report: Arc<crate::encode::viewer_rate::ViewerFeedback>,
    /// FR-85 P3b — what this session's `record` DataChannel needs from the
    /// signalling loop. Set once by [`Self::set_record_ctx`] before the offer
    /// is answered, so it is in place before any channel can open.
    #[cfg(feature = "recording")]
    record_ctx: Arc<std::sync::OnceLock<crate::recording::remote::SessionCtx>>,
    /// FR-99 P1b — what this session's `privacy` DataChannel needs (who is
    /// connected, and the overlay that draws the curtain). Set once by
    /// [`Self::set_privacy_ctx`] before the offer is answered.
    privacy_ctx: Arc<std::sync::OnceLock<crate::privacy::PrivacyCtx>>,
    /// Fires when this session ends: [`Self::close`] or the drop, whichever
    /// comes first. The DataChannel handlers that hold something past their
    /// channel (the cursor poller, the clipboard watch, an upload's open
    /// file) let go on it ([`on_session_end`]).
    ///
    /// ⚠️ A channel's own `on_close` is not that signal. A channel the DEVICE
    /// closed — every network drop, where the device's watchdog closes the
    /// peer — often stops at `Closing` and never fires it (a race in
    /// webrtc-rs's read loop), and nothing that held on to the channel is
    /// ever told. The same shape as the arbiter entries the `Drop` below
    /// releases.
    session_end: tokio_util::sync::CancellationToken,
    /// #1882 — may this session use the overlay? Read by
    /// [`Self::add_remote_candidate`] and [`Self::handle_offer`]; the local
    /// half is already in the `SettingEngine`.
    rc_overlay: crate::rc_overlay::RcOverlay,
    /// FR-101 P4b-2 — the control channel, once the viewer opens it: the same
    /// stash the lock-state emitter writes through, kept here for the idle
    /// limit's warning ([`Self::idle_handles`]).
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    /// FR-93 P5h — this session's controller is told when the computer goes
    /// to sleep, for as long as the session lives ([`crate::sleep_notice`]).
    _sleep_notice: crate::sleep_notice::Registration,
    /// FR-102 P9c — the carrier this session rides, recorded once after the
    /// peer reached `Connected` ([`crate::session_carrier::observe`]) and
    /// carried on every `rc:session.stats` from then on. Set once; a later
    /// path change is not recorded.
    carrier: Arc<std::sync::OnceLock<crate::session_carrier::SessionCarrier>>,
    /// FR-43 P2b-2 — THE seam: the sender this peer was constructed with.
    /// Everything about this session leaves through it — the peer's own ICE
    /// and `Terminate`, and (FR-102 P9d) every `rc:session.stats` the
    /// signalling loop sends for it ([`Self::outbound`]) — so a delegated
    /// session needs exactly one routing decision, taken once, in
    /// `handle_server_msg`. For an own session it is the loop's `outbound_tx`,
    /// flushed to the control WS one hop later; for a delegated one it is the
    /// delegation channel, relayed by the daemon under the DAEMON's identity,
    /// which is the identity the session row carries.
    outbound: mpsc::Sender<ClientMsg>,
}

/// FR-16 L0 — the in-process latency harness's one seam into a session.
///
/// `AgentPeer::new` builds its own `SettingEngine`, so a test cannot hand it a
/// virtual network. This hook runs on every new session's engine just before
/// the API is built: `agents/roomlerd/tests/l4_latency.rs` uses it to put the
/// agent on a webrtc-util `vnet` beside its controller, with a set delay,
/// jitter and loss. Compiled only into the test-only `synthetic-frame-source`
/// build; a production agent has no way to reach it.
#[cfg(feature = "synthetic-frame-source")]
pub mod l0 {
    use std::sync::{Arc, Mutex};

    use webrtc::api::setting_engine::SettingEngine;

    pub type SettingEngineHook = Arc<dyn Fn(&mut SettingEngine) + Send + Sync>;

    static HOOK: Mutex<Option<SettingEngineHook>> = Mutex::new(None);

    /// Install the hook every new session runs on its `SettingEngine`, or
    /// clear it with `None`.
    pub fn set_setting_engine_hook(hook: Option<SettingEngineHook>) {
        *HOOK.lock().unwrap_or_else(|p| p.into_inner()) = hook;
    }

    pub(crate) fn apply(setting: &mut SettingEngine) {
        let hook = HOOK.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(hook) = hook {
            hook(setting);
        }
    }
}

/// One `rc:session.stats` sample: what this session actually did.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionTelemetry {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub rtt_ms: f32,
    pub fps: f32,
    pub keyframe_requests: u32,
    pub input_events: u64,
    /// P8 Phase 4 — cumulative shared-pipeline seconds (owner session).
    pub shared_seconds: u64,
    /// … of which the viewers' dials were not all equal.
    pub mixed_dial_seconds: u64,
    /// FR-102 P9c — the carrier recorded for this session, once it is
    /// known; `None` until the observation after `Connected` has landed.
    pub carrier: Option<crate::session_carrier::SessionCarrier>,
}

impl AgentPeer {
    /// Phase Y.3: `negotiated_transport` is the video transport
    /// chosen by signalling (`AgentCaps.transports` ∩ browser
    /// `preferred_transport`). `None` → legacy WebRTC video track.
    /// `Some("data-channel-vp9-444")` → media pump bypasses the
    /// track and writes length-prefixed VP9 frames into the
    /// `video-bytes` DC opened by the controller. See the
    /// `on_data_channel` branch in `new()` for where the DC
    /// handle is stashed.
    ///
    /// rc.62 — `chroma_pref` is the per-session VP9 chroma override
    /// forwarded from `ClientMsg::SessionRequest::chroma_pref`. When
    /// `Some("yuv420" | "yuv444")` the VP9-444 pump uses it instead
    /// of the agent's `ROOMLERD_VP9_CHROMA` env var. `None` →
    /// fall back to env var (= operator default).
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        session_id: bson::oid::ObjectId,
        ice_servers: &[IceServer],
        outbound: mpsc::Sender<ClientMsg>,
        encoder_preference: encode::EncoderPreference,
        chosen_codec: String,
        // #2231 — the codec the RTP video track is created and pinned with:
        // `chosen_codec`, except on a DataChannel transport whose offer lacks
        // it (`rtp_track_codec`). The pump always encodes `chosen_codec`.
        track_codec: String,
        negotiated_transport: Option<String>,
        chroma_pref: Option<String>,
        // FR-17 — this controller can parse the framed DataChannel wire
        // format (`[frame_seq | chunk_idx | chunk_count]` per message).
        // False = the legacy unframed format. Negotiated, never assumed:
        // framing bytes a peer cannot parse is unrecoverable, so the
        // default on every unknown path is the old format.
        chunk_framing: bool,
        // Opt-in system-audio track. Only acted on when the `audio`
        // feature is compiled in; underscored-through otherwise so the
        // default-feature build doesn't warn on the unused binding.
        #[cfg_attr(not(feature = "audio"), allow(unused_variables))] audio_enabled: bool,
        // Session permission bitfield from `rc:request` (v2 — enforced
        // per-DC; the clipboard handler and the P6 arbiter registration
        // consume it).
        permissions: roomler_ai_remote_control::permissions::Permissions,
        // P6 — controller display name for the participants rail + ghost
        // cursor labels (from `rc:request`).
        controller_name: String,
        // P6 — the device policy's input arbitration mode directive
        // ("free"/"exclusive"; None = agent default, which is free). Only
        // the FIRST session's hint seeds the mode — see input::arbiter.
        input_mode: Option<String>,
        // #1882 — the device's `rc_overlay` decision for this session (see
        // `crate::rc_overlay`). Off, the default, keeps every overlay address
        // out of this session's ICE.
        rc_overlay: crate::rc_overlay::RcOverlay,
        // FR-93 P6c — the daemon's session registry: the media pump ends this
        // session through it, as the person's Disconnect does, when they stop
        // the share with the desktop's own control.
        rc_sessions: crate::rc_sessions::RcSessionRegistry,
        // FR-102 P9d — the signalling loop learns the carrier observation has
        // landed for this session through this channel, so it can send ONE
        // `rc:session.stats` promptly instead of waiting for the 30 s tick (a
        // short session may contain no tick after the observation). The sender
        // belongs to the loop whose `peers` map holds this peer (the daemon, a
        // standalone agent, or — for a delegated session — the macOS GUI
        // worker). ⚠️ That loop is NOT necessarily the one whose WS serves the
        // session: the sample itself leaves through `outbound` above, the
        // peer's own sender (the seam), which for a delegated session is the
        // delegation channel to the daemon, never the worker's own WS.
        carrier_ready_tx: mpsc::Sender<bson::oid::ObjectId>,
    ) -> Result<Self> {
        let mut engine = MediaEngine::default();
        engine
            .register_default_codecs()
            .context("register default codecs")?;
        // FR-98 C6 — only a session that sends `playout-delay` registers it,
        // so with the switch off the answer stays byte-identical.
        if crate::rtp_playout::enabled() {
            crate::rtp_playout::register(&mut engine)?;
            info!(%session_id, "rtp playout-delay 0/0 offered on the video track (FR-98 C6)");
        }

        // Install NACK responder + TWCC + RTCP reports. Without these
        // interceptors the sender silently drops NACK retransmit requests,
        // so any lost RTP packet becomes a frozen decoder until the next
        // IDR. Browser observed 293 NACKs per minute with 0.1.4 going
        // nowhere — this is the missing piece.
        let mut registry = webrtc::interceptor::registry::Registry::new();
        registry =
            webrtc::api::interceptor_registry::register_default_interceptors(registry, &mut engine)
                .context("register default interceptors")?;

        // Keep the OVERLAY interface out of ICE. The STUN query that rides
        // that interface comes back reflected as the node's own overlay
        // address, and webrtc-rs offers it as a perfectly ordinary
        // `typ=srflx` candidate.
        //
        // (This used to say the controller's browser is never on the mesh,
        // so an overlay candidate could never pair. #1882 measured the
        // opposite: an operator's browser runs on an overlay node, its
        // wintun address is a host candidate, and a Mac — whose `utunN` this
        // name rule cannot see — paired host↔host over the overlay. Whether
        // a session may do that is now the device's call; see the IP filter
        // below and `crate::rc_overlay`.)
        //
        // Field 2026-08-07 (winhost-a, Check Point profile blocking STUN on the
        // physical NIC): the ONLY srflx it gathered was
        // `typ=srflx address=100.64.0.28` — its own overlay IP. That masked
        // the fact it had no public reflexive candidate at all, so every
        // session negotiated, "started", and then died at a constant ~10.9 s
        // when media never flowed (388 sessions in 24 h). winhost-b, same LAN
        // and same Check Point build, offered a real `37.63.112.129` and
        // worked. The filter does not FIX a host that cannot reach STUN — it
        // stops that failure from disguising itself as a usable candidate.
        //
        // Filter by interface NAME, deliberately not by CIDR: the overlay
        // lives in 100.64.0.0/10, which is real CGNAT space that some ISPs
        // hand out to customers, so a CIDR rule would strip a legitimate host
        // candidate from anyone behind carrier-grade NAT.
        let mut setting = webrtc::api::setting_engine::SettingEngine::default();
        setting.set_interface_filter(Box::new(|name: &str| !is_overlay_iface(name)));
        // #1882 — unless the device lets remote desktop use the overlay, keep
        // its ADDRESSES out of the host candidates too, whatever the interface
        // is called: the overlay's own blocks and the derived-v6 ULA, never the
        // whole CGNAT `/10` (the CGNAT caveat above still holds). Remote
        // candidates and ICE servers get the same rule below and in
        // `add_remote_candidate`.
        if !rc_overlay.allow {
            let keep = rc_overlay.clone();
            setting.set_ip_filter(Box::new(move |ip| keep.keeps_local(ip)));
        }
        // FR-101 P1 — GCM-only DTLS, with its switch back, and the SRTP/SRTCP
        // replay windows pinned at 64 (webrtc-srtp's session default too).
        let transport = crate::rc_transport::Policy::from_env();
        transport.apply(&mut setting);
        // FR-16 L0 — the loopback harness routes this session's ICE through a
        // webrtc-util vnet (a set delay, jitter and loss). Only the test-only
        // `synthetic-frame-source` build carries the hook. Applied last, so
        // the harness runs on the production transport policy above.
        #[cfg(feature = "synthetic-frame-source")]
        l0::apply(&mut setting);
        info!(
            session = %session_id,
            overlay_blocks = rc_overlay.v4_nets.len(),
            srtp_replay_window = transport.replay_window,
            dtls_gcm_only = transport.gcm_only,
            "rc ICE: overlay {}",
            rc_overlay.describe()
        );
        let api = APIBuilder::new()
            .with_media_engine(engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(setting)
            .build();

        // rc.162: hostile-NAT hosts (WSL2 + wsl-vpnkit, other userspace-VPN
        // stacks) mangle UDP source ports, breaking the TURN allocation
        // refresh — the media peer flaps Connected/Disconnected and the
        // desktop freezes. `ROOMLERD_ICE_RELAY_TCP=1` pins the media to
        // the TURNS/TCP relay (the vendored webrtc-ice TCP branch), a single
        // stable TCP connection that survives it — the same escape hatch the
        // tunnel uses on corp VPNs. Opt-in: the default path is unchanged.
        let relay_tcp = node_env("ICE_RELAY_TCP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        // #1882 — an ICE server on an overlay address (the loopback-TURN
        // relay) is an overlay path. Gone unless the device allows it; the
        // Hub withholds it too, but an older server does not.
        let ice_servers = &rc_overlay.ice_servers(ice_servers);
        let mut config = RTCConfiguration {
            ice_servers: if relay_tcp {
                map_ice_servers_relay_tcp(ice_servers)
            } else {
                map_ice_servers(ice_servers)
            },
            ..Default::default()
        };
        if relay_tcp {
            config.ice_transport_policy = RTCIceTransportPolicy::Relay;
        }

        let pc = Arc::new(
            api.new_peer_connection(config)
                .await
                .context("new_peer_connection")?,
        );

        // Add a sendonly video track up front so the SDP answer
        // advertises it. The `chosen_codec` (`"h264"` / `"h265"`) is the
        // intersection result from `caps::pick_best_codec(browser,
        // agent)` computed in signaling. The capability selected here
        // must match one of webrtc-rs's `register_default_codecs`
        // entries byte-for-byte on clock_rate + fmtp line +
        // rtcp_feedback, otherwise the SDP negotiation fails to resolve
        // a payload type and the packetizer has nothing to emit.
        //
        // webrtc-rs's default H.265 registration is PT 126, no fmtp
        // line, same rtcp feedback as H.264 — matches Chrome
        // Canary/Beta/Stable 127+ which accept the same shape.
        //
        // #2231 — on a DataChannel transport this track carries no frame (the
        // DC pump owns the video); it only keeps the SDP answer valid. Its
        // codec is `track_codec`, which `rtp_track_codec` moves off the pump's
        // codec when the offer cannot take that one.
        if track_codec != chosen_codec {
            info!(
                %session_id,
                pump_codec = %chosen_codec,
                track_codec = %track_codec,
                "RTP video track takes a codec the offer carries; the DataChannel carries the video"
            );
        }
        // RETIRED-NAME-ANCHOR(4): this is the WebRTC STREAM ID, which travels in the
        // SDP as the msid. No viewer code keys on it today, but it is a wire value
        // and a rename would be observable to any consumer that does. Frozen until
        // something proves nothing reads it. See docs/fr/FR-21.
        let video_track = Arc::new(TrackLocalStaticSample::new(
            build_video_codec_cap(&track_codec),
            "video".to_string(),
            "roomler-agent".to_string(),
        ));
        let video_sender = pc
            .add_track(video_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .context("add_track(video)")?;

        // Opt-in system-audio: add a sendonly Opus track + spawn the
        // audio pump. Gated on both the `audio` Cargo feature and the
        // per-session `audio_enabled` directive. The Opus capability
        // must match the MediaEngine's default Opus registration
        // byte-for-byte (see `build_audio_codec_cap`) or SDP negotiation
        // can't resolve PT 111. The track is added BEFORE the SDP answer
        // is created so the m=audio section is advertised; when audio is
        // off we add no track and the SDP carries video only (fully
        // backward-compatible with controllers that never request audio).
        //
        // Control-DC stash so the lock-state emitter task (spawned
        // alongside the media pump below) can write `rc:host_locked`
        // messages without a separate channel lookup. Tokio mutex
        // mirrors `video_bytes_dc`'s rationale: the on_data_channel
        // callback writes from an async context, the emitter reads
        // from its own task, both very briefly. FR-97 P3c-1 — created
        // before the audio track, so the audio pump can tell the
        // controller why it has no sound.
        let control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        #[cfg(feature = "audio")]
        let audio_pump_handle: Option<JoinHandle<()>> = if audio_enabled {
            // RETIRED-NAME-ANCHOR(4): wire-visible stream id, as above.
            let audio_track = Arc::new(TrackLocalStaticSample::new(
                build_audio_codec_cap(),
                "audio".to_owned(),
                "roomler-agent".to_owned(),
            ));
            pc.add_track(audio_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
                .await
                .context("add_track(audio)")?;
            info!(%session_id, "audio: Opus track added — spawning audio pump");
            Some(tokio::spawn(audio_pump(
                session_id,
                audio_track,
                control_dc.clone(),
            )))
        } else {
            None
        };

        // Pin the SDP answer's m=video codec list to the chosen codec.
        // Without this, webrtc-rs offers H.264 + H.265 + AV1 + VP8 + VP9
        // in one m-section, and a browser free to pick its first
        // preference may negotiate a codec our encoder doesn't emit
        // (e.g. VP9 from Firefox). set_codec_preferences on the
        // transceiver filters the offered codec list in the SDP.
        // Find the transceiver that owns the sender we just created.
        // `t.sender()` returns a Future<Output = Arc<RTCRtpSender>>, so
        // the candidates have to be awaited one at a time inside the
        // loop. There's typically only one transceiver at this point
        // (we just added the single video track), so this is cheap.
        let mut matched_transceiver = None;
        for t in pc.get_transceivers().await {
            let sender = t.sender().await;
            if std::sync::Arc::ptr_eq(&sender, &video_sender) {
                matched_transceiver = Some(t);
                break;
            }
        }
        if let Some(transceiver) = matched_transceiver {
            let codec_params = codec_params_for(&track_codec);
            if let Err(e) = transceiver.set_codec_preferences(vec![codec_params]).await {
                // Not fatal — transceiver still works, SDP just offers
                // the default union. Log as warning so a field incident
                // is diagnosable.
                warn!(%session_id, %e, codec = %track_codec, "set_codec_preferences failed — SDP will carry default codec union");
            } else {
                info!(%session_id, codec = %track_codec, "SDP codec preferences pinned");
            }
        }

        // Shared keyframe-request flag. The RTCP reader task flips it on
        // PLI / FIR; media_pump consumes it before each encode and calls
        // force_intra_frame() on the openh264 encoder. Without this, lost
        // packets freeze the decoder until the next periodic IDR.
        //
        // Rate-limited: a browser under load can spam PLIs (we saw 43 in
        // a few seconds). Each keyframe at 4K is ~350 KB. Back-to-back
        // IDRs spike bandwidth → more loss → more PLI → collapse. Cap
        // keyframe responses to at most one per MIN_KEYFRAME_GAP.
        let keyframe_requested = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Controller's quality preference, mutated by the `control`
        // data channel handler and polled by the media pump. AUTO is
        // the safe default until the controller advertises otherwise.
        let quality_state = Arc::new(std::sync::atomic::AtomicU8::new(quality::AUTO));
        // Latest receiver-estimated bitrate (REMB) in bps. 0 means no
        // hint yet; media_pump treats that as "use the resolution-
        // derived baseline + quality clamp". Modern Chromium often
        // sends TWCC instead of REMB, but advertises both — when REMB
        // arrives we honour it, when only TWCC arrives we currently
        // can't decode the bandwidth estimate (webrtc-rs 0.12 doesn't
        // expose its TWCC sender's BWE) and fall back to baseline.
        let remb_bps = Arc::new(std::sync::atomic::AtomicU32::new(0));
        // Reference-frame invalidation: set when the rtcp reader sees a
        // burst of NACK packets above a threshold within a short
        // window, indicating that the interceptor's retransmission
        // didn't recover the loss. Cheaper than a full IDR (which
        // adds 60-100 KB at 1080p and triggers TWCC throttling).
        // Default trait impl falls back to keyframe; backends that
        // expose proper intra-refresh override.
        let invalidation_requested = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Controller-chosen encode resolution. Defaults to Native; the
        // `rc:resolution` control-DC message (Phase 2 of the viewer-
        // controls sprint) writes this and the media pump applies on
        // the next frame. Std Mutex (not tokio) because reads from the
        // sync pump loop and writes from the async DC callback are
        // both brief.
        let target_resolution = Arc::new(std::sync::Mutex::new(TargetResolution::Native));
        // Native (pre-downscale) capture dimensions, published by the
        // active media pump each frame (packed w:h) so the cursor pump can
        // express the OS cursor position in the encoded frame's pixel
        // space when the controller downscales. 0 = no frame captured yet.
        // rc.183 — remote-cursor offset fix at non-native resolutions.
        let capture_native_dims = Arc::new(std::sync::atomic::AtomicU64::new(0));
        // rc.190 — the dims the active pump ACTUALLY encodes (post
        // `apply_target_resolution` + agent-side relay/SW caps), packed like
        // `capture_native_dims`. The cursor pump derives its native→encoded
        // scale from THIS (actual truth) instead of re-deriving from the
        // controller's TargetResolution — which went stale the moment the
        // agent-side caps could pick a smaller target than the controller
        // asked for. 0 = no frame encoded yet (cursor stays native-space).
        let encoded_dims = Arc::new(std::sync::atomic::AtomicU64::new(0));
        // rc.188 — viewer-rate feedback. The control handler packs the browser's
        // `rc:decodestat` (measured decoded fps + a "struggling" bit) into this
        // atomic; the DC video pumps swap+decode it once a second and feed
        // `viewer_rate::ViewerRateController`, which caps send-fps to what the
        // viewer can actually sustain. Packing: `(fps & 0xFFFF) | (struggling <<
        // VIEWER_STRUGGLE_BIT)`; 0 = no signal this window (treated as clean).
        let viewer_report = Arc::new(crate::encode::viewer_rate::ViewerFeedback::new());
        // rc.199 — viewer "Priority" dial (`rc:priority`). The control handler
        // decodes the wire mode into this per-session atomic; both DC video
        // pumps read it to resolve the relay resolution cap they feed
        // `effective_target_resolution` (balanced=link-physics cap on relay,
        // sharper=native override, smoother=fewer pixels everywhere). Mirrors
        // the `viewer_report` shared-atomic plumbing. 0 = balanced (default).
        let priority = Arc::new(std::sync::atomic::AtomicU8::new(
            crate::encode::priority::BALANCED,
        ));
        // Phase Y.3 (docs/encoders.md). When the browser opens a
        // `video-bytes` data channel — only happens when both sides
        // negotiated `data-channel-vp9-444` transport in caps — we
        // stash the DC handle here so the media pump can write
        // length-prefixed VP9 frames into it instead of the WebRTC
        // video track. None until the channel arrives; the pump
        // checks each iteration. Tokio mutex because the on_data_channel
        // callback writes from an async context and the pump reads
        // from its own task — both brief, no contention.
        let video_bytes_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        // P6 — cursor-DC stash: the arbiter writes `cursor:peer` (ghost
        // cursor) messages to OTHER sessions through this handle.
        let cursor_dc_stash: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        // P6 — register this session with the process-global InputArbiter:
        // it appears on every session's participants rail, and (when it
        // holds INPUT) its events flow through the single fenced injection
        // worker. Deregistration rides the control DC's on_close (the same
        // canonical teardown signal display-match restore uses).
        {
            use roomler_ai_remote_control::permissions::Permissions;
            crate::input::arbiter::global().session_open(
                session_id,
                controller_name,
                permissions.contains(Permissions::INPUT),
                input_mode
                    .as_deref()
                    .and_then(crate::input::arbiter::Mode::parse),
                control_dc.clone(),
                cursor_dc_stash.clone(),
            );
        }
        let rtcp_reader = {
            let flag = keyframe_requested.clone();
            let remb = remb_bps.clone();
            let invalidate = invalidation_requested.clone();
            let sid = session_id;
            tokio::spawn(async move {
                use webrtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
                use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
                use webrtc::rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
                use webrtc::rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
                const MIN_KEYFRAME_GAP: Duration = Duration::from_millis(500);
                const MIN_INVALIDATION_GAP: Duration = Duration::from_millis(200);
                // NACK burst detector: trip invalidation when ≥ this
                // many NACKed sequence numbers arrive within the
                // window. Single-NACK is normal background loss the
                // interceptor handles via retransmission; bursts mean
                // the retransmission didn't recover and we need to
                // resync the decoder. Conservative threshold — too
                // sensitive triggers thrashing on edge networks.
                const NACK_BURST_THRESHOLD: u32 = 8;
                const NACK_WINDOW: Duration = Duration::from_secs(1);
                // Boot-safe seeds — see `crate::clock::instant_before`.
                let mut last_keyframe = crate::clock::instant_before(MIN_KEYFRAME_GAP);
                let mut last_invalidation = crate::clock::instant_before(MIN_INVALIDATION_GAP);
                let mut nack_count_in_window: u32 = 0;
                let mut nack_window_started = std::time::Instant::now();
                loop {
                    match video_sender.read_rtcp().await {
                        Ok((pkts, _)) => {
                            let mut asks_keyframe = false;
                            for p in pkts {
                                let p_any = p.as_any();
                                if p_any.downcast_ref::<PictureLossIndication>().is_some()
                                    || p_any.downcast_ref::<FullIntraRequest>().is_some()
                                {
                                    asks_keyframe = true;
                                }
                                if let Some(remb_pkt) =
                                    p_any.downcast_ref::<ReceiverEstimatedMaximumBitrate>()
                                {
                                    // REMB carries the receiver's
                                    // bandwidth estimate in bps. Surface
                                    // verbatim; media_pump applies its
                                    // own safety factor + hysteresis.
                                    let bps = remb_pkt.bitrate as u32;
                                    if bps > 0 {
                                        debug!(session = %sid, remb_bps = bps, "REMB received");
                                        remb.store(bps, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                                if let Some(nack) = p_any.downcast_ref::<TransportLayerNack>() {
                                    // Reset the window if it's lapsed,
                                    // otherwise add to the count. Each
                                    // NACK packet contains nack_pairs
                                    // covering 1+ packet IDs; sum the
                                    // population count of each loss
                                    // bitmap as the actual loss count.
                                    let now = std::time::Instant::now();
                                    if now.duration_since(nack_window_started) > NACK_WINDOW {
                                        nack_window_started = now;
                                        nack_count_in_window = 0;
                                    }
                                    let lost: u32 = nack
                                        .nacks
                                        .iter()
                                        .map(|np| 1 + (np.lost_packets as u32).count_ones())
                                        .sum();
                                    nack_count_in_window =
                                        nack_count_in_window.saturating_add(lost);
                                    if nack_count_in_window >= NACK_BURST_THRESHOLD
                                        && now.duration_since(last_invalidation)
                                            >= MIN_INVALIDATION_GAP
                                    {
                                        info!(
                                            session = %sid,
                                            nack_count_in_window,
                                            "NACK burst → requesting reference invalidation"
                                        );
                                        invalidate
                                            .store(true, std::sync::atomic::Ordering::Relaxed);
                                        last_invalidation = now;
                                        // Reset the window so a single
                                        // burst doesn't keep firing.
                                        nack_window_started = now;
                                        nack_count_in_window = 0;
                                    }
                                }
                            }
                            if asks_keyframe {
                                let now = std::time::Instant::now();
                                if now.duration_since(last_keyframe) >= MIN_KEYFRAME_GAP {
                                    info!(session = %sid, "PLI/FIR → forcing keyframe");
                                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                                    last_keyframe = now;
                                }
                                // else: silently drop — we already sent
                                // an IDR within the last 500ms.
                            }
                        }
                        Err(_e) => {
                            // Sender closed; exit the reader.
                            return;
                        }
                    }
                }
            })
        };

        // Forward locally-gathered ICE candidates — and rc.293, LOG them.
        //
        // The gather used to be SILENT: candidates were serialised and
        // forwarded with no record, so "which candidates did this host
        // actually produce?" could only be answered from the far end's
        // `chrome://webrtc-internals` — and only if a browser was involved at
        // all. Field 2026-08-02 (CORPLAP-3, Cisco AnyConnect full tunnel):
        // the agent contributed ONLY an overlay host candidate and a relay —
        // no srflx — even though a hand-run STUN Binding from its VPN adapter
        // reached coturn fine (40-byte reply). Nothing in the log could say
        // whether the srflx was never gathered or gathered-then-lost, which is
        // the difference between an ICE-gather bug and a signalling bug. The
        // rc.180 `ICE_RELAY_TCP` hunt was fought blind for the same reason.
        // One line per candidate (a one-shot burst of a handful per session)
        // plus a summary on the end-of-gather `None` sentinel makes it
        // permanently greppable.
        {
            let tx = outbound.clone();
            let tally = Arc::new(GatherTally::default());
            pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
                let tx = tx.clone();
                let tally = tally.clone();
                Box::pin(async move {
                    let Some(c) = c else {
                        // webrtc-rs signals end-of-gather with `None`.
                        tally.log_summary(session_id, relay_tcp);
                        return;
                    };
                    tally.note(c.typ);
                    info!(
                        %session_id,
                        typ = %c.typ,
                        protocol = %c.protocol,
                        address = %c.address,
                        port = c.port,
                        related = %format_args!("{}:{}", c.related_address, c.related_port),
                        "ICE: gathered local candidate"
                    );
                    let json = match c.to_json() {
                        Ok(j) => j,
                        Err(e) => {
                            warn!(%e, "failed to serialize ICE candidate");
                            return;
                        }
                    };
                    let Ok(candidate) = serde_json::to_value(&json) else {
                        return;
                    };
                    let _ = tx
                        .send(ClientMsg::Ice {
                            session_id,
                            candidate,
                        })
                        .await;
                })
            }));
        }

        // PC state → logs + fatal Terminate on Failed + cross-process
        // peer-presence marker for the M3 A1 supervisor.
        //
        // RETIRED-NAME-ANCHOR(4): names the PRE-RENAME appdirs segment a host installed
        // before P4b still has; appdirs::app_segment resolves it, so it is an input.
        // The marker file (`%PROGRAMDATA%\roomler-agent\
        // peer-connected.lock`) is the supervisor's signal for
        // "swap user-context worker for SystemContext worker
        // because a controller is currently driving this host".
        // See `system_context::peer_presence` for the contract.
        // On `Connected` we touch the marker (and the periodic
        // refresher task below keeps the mtime fresh); on
        // `Disconnected` / `Closed` / `Failed` we remove it so the
        // supervisor's next cycle reverts to the user-context arm.
        // FR-102 P9c — the carrier slot, filled once after `Connected`.
        let carrier: Arc<std::sync::OnceLock<crate::session_carrier::SessionCarrier>> =
            Arc::new(std::sync::OnceLock::new());
        {
            let tx = outbound.clone();
            let carrier_slot = carrier.clone();
            let pc_for_carrier = Arc::downgrade(&pc);
            let carrier_ready_tx = carrier_ready_tx.clone();
            pc.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
                info!(session = %session_id, state = ?s, "PC state change");
                let tx = tx.clone();
                // FR-102 P9c — record what the session rides, once. A weak
                // handle: the observation must not keep a closed peer alive,
                // and a peer gone before the settle records nothing.
                if matches!(s, RTCPeerConnectionState::Connected) && carrier_slot.get().is_none() {
                    let slot = carrier_slot.clone();
                    let weak = pc_for_carrier.clone();
                    // FR-102 P9d — tell the signalling loop the moment the
                    // carrier is known, so it sends one `rc:session.stats` now.
                    // A clone per spawn; the observation itself still holds only
                    // a WEAK peer handle.
                    let carrier_ready_tx = carrier_ready_tx.clone();
                    tokio::spawn(async move {
                        let Some(pc) = weak.upgrade() else { return };
                        let observed = crate::session_carrier::observe(&pc, session_id).await;
                        let _ = slot.set(observed);
                        // Best-effort: a full/closed channel just means this one
                        // session waits for the next 30 s tick, the pre-P9d
                        // behaviour. `unknown` signals too — recorded beats
                        // absent (P9c's "never direct for an unknown tier").
                        let _ = carrier_ready_tx.try_send(session_id);
                    });
                }
                Box::pin(async move {
                    #[cfg(all(feature = "system-context", target_os = "windows"))]
                    {
                        match s {
                            RTCPeerConnectionState::Connected => {
                                if let Err(e) = crate::system_context::peer_presence::signal_connected() {
                                    tracing::warn!(%e, "peer_presence::signal_connected failed — supervisor cannot swap to SystemContext worker");
                                }
                            }
                            RTCPeerConnectionState::Disconnected
                            | RTCPeerConnectionState::Closed
                            | RTCPeerConnectionState::Failed => {
                                if let Err(e) = crate::system_context::peer_presence::signal_disconnected() {
                                    tracing::debug!(%e, "peer_presence::signal_disconnected — already gone or unreachable");
                                }
                            }
                            _ => {}
                        }
                    }
                    if matches!(s, RTCPeerConnectionState::Failed) {
                        let _ = tx
                            .send(ClientMsg::Terminate {
                                session_id,
                                reason: roomler_ai_remote_control::models::EndReason::Error,
                                limit: None,
                            })
                            .await;
                    }
                })
            }));
        }

        // M3 A1 peer-presence heartbeat. Refreshes the marker file's
        // mtime every 5 s while the WebRTC peer is in `Connected`
        // state; the supervisor's `is_signaled` returns false once
        // the file's mtime is older than `PRESENCE_MAX_AGE` (15 s).
        // This task is spawned once per session and exits when the
        // peer connection drops or fails — its `Arc<RTCPeerConnection>`
        // weak-clone won't keep the connection alive.
        #[cfg(all(feature = "system-context", target_os = "windows"))]
        {
            let pc_for_heartbeat = std::sync::Arc::downgrade(&pc);
            tokio::spawn(async move {
                use crate::system_context::peer_presence;
                let mut tick = tokio::time::interval(peer_presence::HEARTBEAT_INTERVAL);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut ticks: u64 = 0;
                let mut had_success = false;
                loop {
                    tick.tick().await;
                    let Some(pc) = pc_for_heartbeat.upgrade() else {
                        // Peer connection dropped; remove the marker
                        // so the supervisor doesn't see a stale
                        // "connected" signal until PRESENCE_MAX_AGE
                        // expires.
                        let _ = peer_presence::signal_disconnected();
                        return;
                    };
                    if matches!(pc.connection_state(), RTCPeerConnectionState::Connected) {
                        match peer_presence::signal_connected() {
                            Ok(()) => {
                                ticks = ticks.saturating_add(1);
                                // Log the FIRST successful write loudly
                                // so a "supervisor never sees marker"
                                // investigation can immediately rule
                                // out "worker never wrote it". After
                                // that, every 12th tick (~60 s) so
                                // the log stays clean during a long
                                // session.
                                if !had_success {
                                    let path = peer_presence::marker_path().display().to_string();
                                    tracing::info!(
                                        marker_path = %path,
                                        "peer_presence: first heartbeat written successfully"
                                    );
                                    had_success = true;
                                } else if ticks.is_multiple_of(12) {
                                    tracing::debug!(ticks, "peer_presence: heartbeat still alive");
                                }
                            }
                            Err(e) => {
                                let path = peer_presence::marker_path().display().to_string();
                                tracing::warn!(
                                    %e,
                                    marker_path = %path,
                                    "peer_presence heartbeat write failed — supervisor cannot swap to SystemContext worker"
                                );
                            }
                        }
                    }
                }
            });
        }

        // rc.190 (B3) — stuck-session watchdog. Field incident DEVBOX
        // 2026-07-16: ICE never nominated a pair ("pingAllCandidates called
        // with no candidate pairs"), the PC sat in Connecting FOREVER (never
        // transitioning to Failed), the hub kept the session row alive → the
        // host showed "Being viewed by …" and every reconnect attempt got
        // AgentBusy until the agent restarted. The rc.185 hub reap only
        // fires when the controller's WS closed — a live browser tab
        // retrying against a wedged session holds it open. This task ends
        // the session when the peer (a) never reaches Connected within
        // CONNECT_DEADLINE, or (b) sits in Disconnected past
        // DISCONNECTED_GRACE. `Failed` needs no handling here — the
        // state-change handler above already Terminates on it. Kill switch:
        // `ROOMLERD_SESSION_WATCHDOG=0`.
        {
            let pc_watch = std::sync::Arc::downgrade(&pc);
            let tx_watch = outbound.clone();
            tokio::spawn(async move {
                const CONNECT_DEADLINE: Duration = Duration::from_secs(45);
                const DISCONNECTED_GRACE: Duration = Duration::from_secs(20);
                if matches!(
                    tunnel_core::env::node_env("SESSION_WATCHDOG").as_deref(),
                    Some("0") | Some("false")
                ) {
                    return;
                }
                let started = std::time::Instant::now();
                let mut connected_once = false;
                let mut disconnected_since: Option<std::time::Instant> = None;
                let mut tick = tokio::time::interval(Duration::from_secs(5));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    // Session torn down normally → the Arc dropped; exit.
                    let Some(pc) = pc_watch.upgrade() else { return };
                    let state = pc.connection_state();
                    if matches!(state, RTCPeerConnectionState::Connected) {
                        connected_once = true;
                    }
                    if matches!(state, RTCPeerConnectionState::Disconnected) {
                        disconnected_since.get_or_insert_with(std::time::Instant::now);
                    } else {
                        disconnected_since = None;
                    }
                    match session_watchdog_verdict(
                        state,
                        connected_once,
                        started.elapsed(),
                        disconnected_since.map(|t| t.elapsed()),
                        CONNECT_DEADLINE,
                        DISCONNECTED_GRACE,
                    ) {
                        WatchdogVerdict::Wait => {}
                        WatchdogVerdict::Disarm => return,
                        WatchdogVerdict::Kill => {
                            warn!(
                                session = %session_id,
                                state = ?state,
                                connected_once,
                                elapsed_s = started.elapsed().as_secs(),
                                "session watchdog: peer never became (or stopped being) usable — terminating stuck session"
                            );
                            // Task #8 — the send fails when the control WS
                            // this channel belonged to already died (per-
                            // connection channel). NEVER silent: the hub
                            // misses this Terminate and the session row
                            // zombifies until the register_agent resync
                            // reaps it on the next reconnect.
                            if let Err(e) = tx_watch
                                .send(ClientMsg::Terminate {
                                    session_id,
                                    reason: roomler_ai_remote_control::models::EndReason::Error,
                                    limit: None,
                                })
                                .await
                            {
                                warn!(
                                    session = %session_id, %e,
                                    "session watchdog: Terminate undeliverable (control WS gone) — \
                                     the hub reaps this session at the next agent register"
                                );
                            }
                            let _ = pc.close().await;
                            return;
                        }
                    }
                }
            });
        }

        // Spawn the lock-screen monitor BEFORE wiring the data-channel
        // callback so the input handler can subscribe to LockState
        // transitions and drop input events early when the host is
        // locked. Without this the events would be dispatched to
        // SendInput which silently routes them to the wrong desktop
        // (the user-context worker is on `winsta0\Default`, but the
        // input desktop is `winsta0\Winlogon`) — they appear to "work"
        // from the WS side but achieve nothing on the host. Dropping
        // them in user-space avoids polluting `enigo` logs and lets
        // a future browser-side hint surface "input suppressed" to
        // the operator.
        //
        // #1738 — the session's end token is made here, first, so the
        // monitor and its emitter end WITH the session: dropping the
        // monitor's handle only detaches it (tokio never aborts on drop),
        // and the emitter's `changed()` wait kept the monitor's channel
        // open, so each session used to leave the pair polling for the
        // life of the daemon.
        let session_end = tokio_util::sync::CancellationToken::new();
        // Until `Ok(Self)` owns the token, nothing else would cancel it: a
        // `?` or a panic added below this line would leak the monitor and
        // every task that races the token. The guard makes that leak
        // impossible, not merely absent (found in review); disarmed at the end.
        let construction_guard = session_end.clone().drop_guard();
        let (lock_state_rx, _lock_state_monitor) = lock_state::spawn_monitor(session_end.clone());

        // Route data channels by label. `input` goes to the OS injector;
        // `control` parses rc:* JSON (quality preference, etc.);
        // `cursor` receives an agent-driven stream of position / shape
        // messages pumped from CursorTracker; `clipboard` round-trips
        // text between the agent's OS clipboard and the browser;
        // `files` accepts uploads that land in the controlled host's
        // Downloads folder.
        let quality_for_dc = quality_state.clone();
        let target_res_for_dc = target_resolution.clone();
        let native_dims_for_dc = capture_native_dims.clone();
        let encoded_dims_for_dc = encoded_dims.clone();
        // rc.130 — the control DC handler forces an encoder keyframe on the
        // browser's `rc:keyframe` (sent when its decode queue backs up and it
        // drops deltas to resync). Same atomic the media pumps already poll.
        let keyframe_for_dc = keyframe_requested.clone();
        let viewer_report_for_dc = viewer_report.clone();
        let priority_for_dc = priority.clone();
        let video_bytes_dc_for_callback = video_bytes_dc.clone();
        let control_dc_for_callback = control_dc.clone();
        let cursor_dc_for_callback = cursor_dc_stash.clone();
        let lock_state_rx_for_dc = lock_state_rx.clone();
        #[cfg(feature = "recording")]
        let record_ctx: Arc<std::sync::OnceLock<crate::recording::remote::SessionCtx>> =
            Arc::new(std::sync::OnceLock::new());
        #[cfg(feature = "recording")]
        let record_ctx_for_callback = record_ctx.clone();
        let privacy_ctx: Arc<std::sync::OnceLock<crate::privacy::PrivacyCtx>> =
            Arc::new(std::sync::OnceLock::new());
        let privacy_ctx_for_callback = privacy_ctx.clone();
        let session_end_for_callback = session_end.clone();
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let label = dc.label().to_string();
            info!(session = %session_id, %label, "data channel opened");
            let quality_for_dc = quality_for_dc.clone();
            let target_res_for_dc = target_res_for_dc.clone();
            let native_dims_for_dc = native_dims_for_dc.clone();
            let encoded_dims_for_dc = encoded_dims_for_dc.clone();
            let keyframe_for_dc = keyframe_for_dc.clone();
            let viewer_report_for_dc = viewer_report_for_dc.clone();
            let priority_for_dc = priority_for_dc.clone();
            let video_bytes_stash = video_bytes_dc_for_callback.clone();
            let control_stash = control_dc_for_callback.clone();
            let cursor_stash = cursor_dc_for_callback.clone();
            let lock_state_rx_for_input = lock_state_rx_for_dc.clone();
            #[cfg(feature = "recording")]
            let record_ctx = record_ctx_for_callback.clone();
            let privacy_ctx = privacy_ctx_for_callback.clone();
            let session_end = session_end_for_callback.clone();
            Box::pin(async move {
                use roomler_ai_remote_control::permissions::Permissions;
                match label.as_str() {
                    // Multi-user P3 — the session's INPUT grant is enforced
                    // HERE, mirroring the clipboard gate below (previously the
                    // input DC injected unconditionally, so a view-only grant
                    // was decorative). The server's single-INPUT-holder rule
                    // strips INPUT from a 2nd concurrent session; without this
                    // gate that stripping would be advisory.
                    "input" if !permissions.contains(Permissions::INPUT) => {
                        info!(
                            session = %session_id,
                            "input DC attached in DROP-ONLY mode — session lacks INPUT \
                             permission (view-effective)"
                        );
                        attach_log_only(dc, session_id);
                    }
                    "input" => attach_input_handler(dc, lock_state_rx_for_input, session_id),
                    "control" => {
                        // Stash a clone for the lock-state emitter
                        // BEFORE handing the DC to the inbound handler.
                        // attach_control_handler consumes the Arc by
                        // value to install on_message; without the
                        // pre-clone-and-stash, the emitter task would
                        // have no way to write outbound messages.
                        *control_stash.lock().await = Some(dc.clone());
                        // P6 field fix — the arbiter registration + the
                        // shared-pipeline badge replay both happened at
                        // `AgentPeer::new`, when this stash was still None,
                        // so a FOLLOWER never received `rc:control.state`
                        // (no participants rail; no Request-control button
                        // in exclusive mode) nor `rc:video-info` (no
                        // `shared ×N` badge). Deliver both now.
                        crate::input::arbiter::global().control_ready(session_id);
                        crate::media_share::replay_video_info(session_id);
                        // FR-92 — the current keep-busy state, once, now that
                        // there is a channel for it; later changes ride the
                        // session's emitter.
                        if crate::keep_busy::subscribe().is_some() {
                            let dc_init = dc.clone();
                            tokio::spawn(async move {
                                let _ = dc_init.send_text(crate::keep_busy::state_json(None)).await;
                            });
                        }
                        // FR-97 P3e — the current keyboard layout, once, for the
                        // same reason: the session's layout emitter starts before
                        // this channel opens, so the snapshot it starts with finds
                        // no channel, and goes out again only when the layout
                        // changes.
                        #[cfg(all(
                            any(target_os = "windows", target_os = "linux"),
                            feature = "enigo-input"
                        ))]
                        if crate::input::layout::offered()
                            && let Some(snap) = crate::input::layout::current()
                        {
                            let dc_init = dc.clone();
                            tokio::spawn(async move {
                                let _ = dc_init.send_text(layout_json(&snap)).await;
                            });
                        }
                        attach_control_handler(
                            dc,
                            session_id,
                            quality_for_dc,
                            target_res_for_dc,
                            keyframe_for_dc,
                            viewer_report_for_dc,
                            priority_for_dc,
                        )
                    }
                    "cursor" => {
                        // P6 — stash a clone so the arbiter can push
                        // `cursor:peer` (ghost cursors) to this session.
                        *cursor_stash.lock().await = Some(dc.clone());
                        attach_cursor_handler(
                            dc,
                            session_id,
                            native_dims_for_dc,
                            encoded_dims_for_dc,
                            session_end,
                        );
                    }
                    #[cfg(feature = "clipboard")]
                    "clipboard" => {
                        attach_clipboard_handler(dc, session_id, permissions, &session_end)
                    }
                    // Multi-user P3 — same enforcement for FILES. New viewers
                    // request the FILES bit by default; a session narrowed to
                    // view-effective gets explicit errors instead of silent
                    // transfers.
                    "files" if !permissions.contains(Permissions::FILES) => {
                        attach_files_denied(dc, session_id, &session_end)
                    }
                    "files" => attach_files_handler(dc, session_id, &session_end),
                    // FR-85 P3b — the same attach-time gate for RECORD: the
                    // hub strips it unless the controller may record AND this
                    // device's owner opted in, and a grant without it gets a
                    // channel that refuses, never one that records.
                    #[cfg(feature = "recording")]
                    "record" if !permissions.contains(Permissions::RECORD) => {
                        crate::recording::remote::attach_refusing(dc, session_id, "not_granted")
                    }
                    #[cfg(feature = "recording")]
                    "record" => match record_ctx.get() {
                        Some(ctx) => crate::recording::remote::attach(dc, ctx.clone()),
                        None => {
                            crate::recording::remote::attach_refusing(dc, session_id, "unavailable")
                        }
                    },
                    // FR-99 P1b — the same attach-time gate for PRIVACY: the
                    // hub grants it only to a device that advertises
                    // `privacy-mode`, and a grant without it gets a channel
                    // that refuses, never one that draws a curtain. The owner's
                    // own gate is read again at every "on" (`privacy.rs`).
                    "privacy" if !permissions.contains(Permissions::PRIVACY) => {
                        crate::privacy::attach_refusing(dc, session_id, "not_granted")
                    }
                    "privacy" => match privacy_ctx.get() {
                        Some(ctx) => crate::privacy::attach(dc, ctx.clone()),
                        None => crate::privacy::attach_refusing(dc, session_id, "unavailable"),
                    },
                    "video-bytes" => {
                        // Phase Y.3 stash. The media pump (when caps
                        // negotiated this transport) consults this
                        // handle each iteration and routes encoded
                        // frames here instead of the WebRTC video
                        // track. Logging the open event so a future
                        // regression where the channel arrives but the
                        // pump doesn't see it is greppable.
                        //
                        // FR-17 — log the NEGOTIATED delivery mode. The
                        // controller chooses ordering at
                        // `createDataChannel`, so nothing server-side
                        // otherwise records which mode a session ran in,
                        // and an A/B between ordered and unordered was
                        // only attributable by trusting the order the
                        // runs happened in. `accept_data_channels`
                        // derives these from the DCEP `ChannelType`, so
                        // they are the negotiated truth rather than a
                        // local default.
                        info!(
                            session = %session_id,
                            ordered = dc.ordered(),
                            max_retransmits = ?dc.max_retransmits(),
                            "video-bytes DC stashed for Y.3 media-pump branch"
                        );
                        *video_bytes_stash.lock().await = Some(dc.clone());
                        // A shared-pipeline FOLLOWER forces its join-IDR ~33 ms
                        // after registering (during AgentPeer::new), long before
                        // this DC finished negotiating — and the follower chunker
                        // drops anything that arrives while the DC is None/!Open,
                        // so that IDR was lost and the follower is `synced` with
                        // no keyframe: a BLACK SCREEN until the next natural IDR
                        // (field 2026-08-30, two viewers of CORPLAP-3). Now the
                        // DC is live, re-sync onto a fresh IDR. No-op for a leader.
                        crate::media_share::resync_follower(session_id);
                        attach_log_only(dc, session_id);
                    }
                    _ => attach_log_only(dc, session_id),
                }
            })
        }));

        // Spawn the host-locked emitter: watches the lock_state
        // monitor's transitions and emits `rc:host_locked` over the
        // `control` data channel so the viewer can render an explicit
        // toolbar badge alongside the in-stream padlock overlay.
        // #1738 — it ends with the SESSION. Every await in it is raced
        // against the session's end: `changed()` waits on the monitor's
        // sender, and a send on a channel a network drop left `Closing`
        // can park for good (#1730).
        {
            let mut rx = lock_state_rx.clone();
            let stash = control_dc.clone();
            let until = session_end.clone();
            let sid = session_id;
            tokio::spawn(async move {
                let run = async move {
                    // Send the initial state once the control DC is
                    // available. The first `changed().await` fires only
                    // on subsequent transitions, but the operator's UI
                    // needs to know if the host is *already* locked at
                    // session start.
                    let mut prev = *rx.borrow();
                    emit_host_locked(&stash, prev == lock_state::LockState::Locked).await;
                    while rx.changed().await.is_ok() {
                        let current = *rx.borrow();
                        if current != prev {
                            emit_host_locked(&stash, current == lock_state::LockState::Locked)
                                .await;
                            // FR-108 P1b — a display-match request answered
                            // `locked` is decided again at the unlock (the
                            // worker could not switch the secure desktop).
                            if prev == lock_state::LockState::Locked
                                && let Ok(Some(answer)) = tokio::task::spawn_blocking(move || {
                                    crate::display_match::on_unlock(sid)
                                })
                                .await
                            {
                                emit_display_match(&stash, answer).await;
                            }
                            prev = current;
                        }
                    }
                };
                tokio::select! {
                    biased;
                    _ = until.cancelled() => {}
                    _ = run => {}
                }
            });
        }
        // FR-97 P3b — Linux: a lock screen is a screen like any other, so
        // logind's hint goes to the viewer's chip only (`input: "passes"`),
        // never to the pump's overlay or the input path. Each transition is
        // retried until the control DC carries it (FR-80's helper): a host
        // already locked when the session starts is the case that most needs
        // saying, and the DC is rarely open yet then.
        // FR-97 P2d-1 — a Mac too, from the session dictionary, with
        // `input: "unknown"`: whether its lock screen takes injected keys is
        // not measured, so the chip claims neither way.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if lock_state::lock_hint_enabled() {
            let stash = control_dc.clone();
            let until = session_end.clone();
            #[cfg(target_os = "linux")]
            let sid = session_id;
            tokio::spawn(async move {
                let run = async move {
                    let mut said = false;
                    #[cfg(target_os = "linux")]
                    let mut seen = false;
                    loop {
                        let locked = tokio::task::spawn_blocking(lock_state::locked_hint)
                            .await
                            .unwrap_or(false);
                        #[cfg(target_os = "linux")]
                        {
                            // FR-97 P3e-2 — display match's presence takes the
                            // lock from here: each read is a `loginctl` run.
                            crate::presence::note_linux_lock_hint(locked);
                            // FR-97 P3e-2 — a display-match request answered
                            // `locked` on a person's own X11 display is decided
                            // again at the unlock, as on Windows (FR-108 P1b).
                            if seen
                                && !locked
                                && let Ok(Some(answer)) = tokio::task::spawn_blocking(move || {
                                    crate::display_match::on_unlock(sid)
                                })
                                .await
                            {
                                emit_display_match(&stash, answer).await;
                            }
                            seen = locked;
                        }
                        if locked != said
                            && send_control_notice(
                                &stash,
                                &host_locked_advisory_payload(
                                    locked,
                                    lock_state::LOCK_SCREEN_INPUT,
                                ),
                                Duration::from_millis(500),
                                Duration::from_secs(30),
                                Duration::from_secs(2),
                            )
                            .await
                        {
                            said = locked;
                        }
                        tokio::time::sleep(lock_state::HINT_POLL).await;
                    }
                };
                tokio::select! {
                    biased;
                    _ = until.cancelled() => {}
                    _ = run => {}
                }
            });
        }

        // FR-108 P1b — while this session holds a display mode it applied, a
        // person who comes back (or the owner's `never`) gets the screen back
        // within a quarter second, and the viewer is told. It ends with the
        // session. FR-97 P3e-2 — Linux too: a person's own X11 display, read
        // by the X idle clock; a virtual desktop holds its mode but for the
        // owner's `never`.
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            let stash = control_dc.clone();
            let until = session_end.clone();
            let sid = session_id;
            tokio::spawn(async move {
                let run = async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tick.tick().await;
                        if !crate::display_match::owns_mode(sid) {
                            continue;
                        }
                        if let Ok(Some(answer)) =
                            tokio::task::spawn_blocking(move || crate::display_match::on_tick(sid))
                                .await
                        {
                            emit_display_match(&stash, answer).await;
                        }
                    }
                };
                tokio::select! {
                    biased;
                    _ = until.cancelled() => {}
                    _ = run => {}
                }
            });
        }

        // rc.227 — layout emitter: forwards `input::layout` snapshots
        // (active + installed keyboard layouts) as `rc:layout` over
        // the control DC so the viewer can render the layout chip +
        // manual picker. UNLIKE the host-locked emitter above, the
        // layout watch sender is PROCESS-GLOBAL and never closes, so
        // `rx.changed()` alone would keep this task alive forever —
        // one leaked emitter per session. #1738 — the session's end is
        // the session-scoped exit: a send on a channel a network drop
        // left `Closing` can park instead of failing (#1730), so the
        // send-failure break alone is not one.
        // FR-97 P3e — on an X11 desktop the snapshots come from
        // `input::layout_x11`, whose reader runs while a session subscribes;
        // a host that offers no layout (Wayland, a system install) starts
        // no emitter.
        #[cfg(all(
            any(target_os = "windows", target_os = "linux"),
            feature = "enigo-input"
        ))]
        if crate::input::layout::offered() {
            let mut rx = crate::input::layout::subscribe();
            let stash = control_dc.clone();
            let until = session_end.clone();
            tokio::spawn(async move {
                let run = async move {
                    // Warm-start with the last-known snapshot (None until
                    // the first input event of the process, or on X11 the
                    // reader's first read). Sent only if the control DC is
                    // already open; otherwise its `control` arm sends it.
                    let initial = rx.borrow().clone();
                    if let Some(s) = initial
                        && !emit_layout(&stash, &s).await
                    {
                        return;
                    }
                    while rx.changed().await.is_ok() {
                        let snap = rx.borrow().clone();
                        if let Some(s) = snap
                            && !emit_layout(&stash, &s).await
                        {
                            return;
                        }
                    }
                };
                tokio::select! {
                    biased;
                    _ = until.cancelled() => {}
                    _ = run => {}
                }
            });
        }

        // FR-92 — keep-busy emitter: forwards the engine's state as
        // `rc:keep-busy.state` over the control DC on every change. Like the
        // layout emitter, the watch sender is PROCESS-GLOBAL and never
        // closes, so the session's end is the exit (#1738). The first value
        // goes out when the control DC opens (the `control` arm), because
        // the stash is still empty here.
        if let Some(mut rx) = crate::keep_busy::subscribe() {
            let stash = control_dc.clone();
            let until = session_end.clone();
            tokio::spawn(async move {
                let run = async move {
                    while rx.changed().await.is_ok() {
                        let payload = {
                            let s = rx.borrow();
                            crate::keep_busy::wire::state_payload(&s, None).to_string()
                        };
                        let dc = stash.lock().await.clone();
                        if let Some(dc) = dc
                            && dc.send_text(payload).await.is_err()
                        {
                            return;
                        }
                    }
                };
                tokio::select! {
                    biased;
                    _ = until.cancelled() => {}
                    _ = run => {}
                }
            });
        }

        // Start the capture→encode→track pump. The pump is self-regulating:
        // with no capture backend compiled in, open_default returns a Noop
        // that parks forever, producing no samples. Phase Y.3:
        // `negotiated_transport` + `video_bytes_dc` let the pump route
        // VP9 4:4:4 frames over the DC instead of the track when the
        // session negotiated `data-channel-vp9-444`.
        let pump = tokio::spawn(media_pump(
            session_id,
            video_track,
            keyframe_requested,
            invalidation_requested.clone(),
            quality_state.clone(),
            remb_bps.clone(),
            encoder_preference,
            chosen_codec,
            target_resolution.clone(),
            negotiated_transport,
            chroma_pref,
            chunk_framing,
            video_bytes_dc.clone(),
            lock_state_rx,
            // rc.87 — control DC so the DC video pumps can emit
            // `rc:video-info` (real encoder/codec/chroma) to the browser
            // for an honest stats badge.
            control_dc.clone(),
            pc.clone(),
            capture_native_dims,
            encoded_dims,
            viewer_report.clone(),
            priority,
            rc_sessions,
        ));

        // FR-93 P5h — told when this computer goes to sleep.
        let sleep_notice = crate::sleep_notice::register(session_id, control_dc.clone());
        Ok(Self {
            pc,
            session_id,
            media_pump: Some(pump),
            #[cfg(feature = "audio")]
            audio_pump: audio_pump_handle,
            rtcp_reader: Some(rtcp_reader),
            viewer_report: viewer_report.clone(),
            #[cfg(feature = "recording")]
            record_ctx,
            privacy_ctx,
            session_end: {
                construction_guard.disarm();
                session_end
            },
            rc_overlay,
            control_dc,
            _sleep_notice: sleep_notice,
            carrier,
            outbound,
        })
    }

    /// FR-43 P2b-2 / FR-102 P9d — the sender this peer was constructed with:
    /// the seam every message about this session leaves through. The
    /// signalling loop's `rc:session.stats` for this session go here too, so
    /// a delegated session's sample reaches the server under the identity the
    /// session row carries (the daemon's), never up the worker's own WS, where
    /// `merge_live_stats` would match nothing and drop it without a word.
    pub(crate) fn outbound(&self) -> &mpsc::Sender<ClientMsg> {
        &self.outbound
    }

    /// Test seam — record the carrier as the observation after `Connected`
    /// would. A peer a unit test never connects has no nominated pair to read.
    #[cfg(test)]
    pub(crate) fn record_carrier_for_test(&self, carrier: crate::session_carrier::SessionCarrier) {
        let _ = self.carrier.set(carrier);
    }

    /// FR-101 P4b-2 — what the idle limit needs from this session: the token
    /// that fires when it ends, and the control channel its warning rides.
    pub(crate) fn idle_handles(
        &self,
    ) -> (
        tokio_util::sync::CancellationToken,
        crate::session_idle::ControlStash,
    ) {
        (self.session_end.clone(), self.control_dc.clone())
    }

    /// FR-85 P3b — give this session's `record` channel what it needs. Call
    /// before [`Self::handle_offer`]; a channel that opens without it refuses
    /// every request as `unavailable`.
    #[cfg(feature = "recording")]
    pub fn set_record_ctx(&self, ctx: crate::recording::remote::SessionCtx) {
        let _ = self.record_ctx.set(ctx);
    }

    /// FR-99 P1b — give this session's `privacy` channel what it needs. Call
    /// before [`Self::handle_offer`]; a channel that opens without it refuses
    /// every request as `unavailable`.
    pub fn set_privacy_ctx(&self, ctx: crate::privacy::PrivacyCtx) {
        let _ = self.privacy_ctx.set(ctx);
    }

    /// Wave 2 — a telemetry sample for `rc:session.stats`.
    ///
    /// Transport numbers come from the peer connection's own ICE
    /// candidate-pair stats (the selected pair carries the session's real
    /// byte counters and RTT), so nothing has to be threaded through the
    /// media pump. `fps` is the VIEWER's measured decoded rate — the
    /// number that describes what the operator experienced — and the two
    /// counters come from the shared per-session registry.
    pub async fn telemetry(&self) -> SessionTelemetry {
        use crate::session_telemetry;
        use std::sync::atomic::Ordering;
        use webrtc::stats::StatsReportType;

        let mut out = SessionTelemetry::default();
        let report = self.pc.get_stats().await;
        // Sum the candidate pairs: only the nominated one carries
        // traffic, and summing avoids depending on which entry that is.
        for v in report.reports.values() {
            if let StatsReportType::CandidatePair(p) = v {
                out.bytes_sent = out.bytes_sent.saturating_add(p.bytes_sent);
                out.bytes_recv = out.bytes_recv.saturating_add(p.bytes_received);
                if p.current_round_trip_time > 0.0 {
                    out.rtt_ms = (p.current_round_trip_time * 1000.0) as f32;
                }
            }
        }
        // Low 16 bits = decoded fps; 0 = the viewer reported nothing in
        // the last window (a paused tab), which is not a measured zero.
        out.fps = f32::from(self.viewer_report.peek_fps() as u16);
        let c = session_telemetry::counters(self.session_id);
        out.keyframe_requests = c.keyframe_requests.load(Ordering::Relaxed);
        out.input_events = c.input_events.load(Ordering::Relaxed);
        out.shared_seconds = c.shared_seconds.load(Ordering::Relaxed);
        out.mixed_dial_seconds = c.mixed_dial_seconds.load(Ordering::Relaxed);
        // FR-102 P9c — the recorded carrier rides every sample once known.
        out.carrier = self.carrier.get().copied();
        out
    }

    pub fn session_id(&self) -> bson::oid::ObjectId {
        self.session_id
    }

    pub async fn handle_offer(&self, offer_sdp: String) -> Result<String> {
        // SDP codec-name normalisation for H.265:
        // RFC 7798 specifies the SDP rtpmap subtype as `H265` ("H265/90000"),
        // and every browser (Chrome, Edge, Safari) emits exactly that in its
        // offer. But webrtc-rs 0.12's `register_default_codecs` keys its
        // internal HEVC entry on the mime string "video/HEVC" — and its
        // fuzzy-search is a naive string compare, not alias-aware
        // (video/H265 vs video/HEVC don't match case-insensitively). So a
        // raw Chrome H265 offer gets dropped during codec matching and
        // `create_answer` then fails because no video codec survived.
        //
        // Workaround: swap `H265` → `HEVC` in the incoming offer so the
        // webrtc-rs internal view uses the "video/HEVC" mime consistently,
        // and reverse the swap on the outgoing answer so the browser sees
        // spec-compliant rtpmap names. This is lossy only for the `name`
        // field of the rtpmap line; everything else (PT, clock rate, fmtp)
        // is untouched.
        let munged_offer = offer_sdp.replace("H265/90000", "HEVC/90000");
        // #1882 — an offer that carries its candidates (a browser that
        // gathered before offering) loses the overlay-addressed ones here,
        // where no trickle filter would see them.
        let munged_offer = self.rc_overlay.strip_sdp(&munged_offer);
        let offer = RTCSessionDescription::offer(munged_offer).context("parse offer")?;
        self.pc
            .set_remote_description(offer)
            .await
            .context("set_remote_description")?;

        let answer = self.pc.create_answer(None).await.context("create_answer")?;
        self.pc
            .set_local_description(answer.clone())
            .await
            .context("set_local_description")?;

        // Reverse the HEVC → H265 munge on the outgoing answer so the
        // browser's SDP parser recognises the rtpmap subtype.
        let munged_answer = answer.sdp.replace("HEVC/90000", "H265/90000");
        Ok(munged_answer)
    }

    pub async fn add_remote_candidate(&self, candidate: serde_json::Value) -> Result<()> {
        let init: RTCIceCandidateInit = match candidate {
            serde_json::Value::String(s) => RTCIceCandidateInit {
                candidate: s,
                ..Default::default()
            },
            other => serde_json::from_value(other)
                .map_err(|e| anyhow!("bad ICE candidate shape: {e}"))?,
        };
        // #1882 — a candidate on a mesh address is an overlay pair waiting to
        // happen even though this side offered no overlay candidate: the
        // srflx and relay sockets are bound to `0.0.0.0`, so a check to it
        // routes into the TUN. Dropped, unless the device allows the overlay.
        if !self.rc_overlay.keeps_remote_candidate(&init.candidate) {
            debug!(
                session = %self.session_id,
                candidate = %init.candidate,
                "rc ICE: remote candidate on the overlay dropped (rc_overlay off)"
            );
            return Ok(());
        }
        // Relay-escape — Chrome hides its LAN host candidates behind mDNS
        // `.local` names (the controller page holds no cam/mic permission),
        // and webrtc-ice's in-process QueryOnly resolution is unreliable on
        // Windows (the native mDNS resolver owns udp/5353, doubly so under
        // the SYSTEM service) — so those candidates were effectively
        // dropped and the direct LAN pair depended on prflx-discovery luck
        // racing the pre-warmed TURN pair (field 2026-07-13: same-LAN
        // sessions nominating the Germany relay most connects). Resolve the
        // name via the OS resolver and rewrite the candidate so a real
        // host↔host pair forms. Spawned so the ~750 ms worst-case
        // resolution never stalls the signaling loop — ICE doesn't care
        // about candidate arrival order. On resolution failure the original
        // is added unmodified (status quo). See `mdns_resolve` module docs.
        if crate::mdns_resolve::candidate_mdns_name(&init.candidate).is_some() {
            let pc = self.pc.clone();
            let session_id = self.session_id;
            let rc_overlay = self.rc_overlay.clone();
            let mut init = init;
            tokio::spawn(async move {
                match crate::mdns_resolve::resolve_mdns_candidate(&init.candidate).await {
                    Some(rewritten) => init.candidate = rewritten,
                    None => {
                        debug!(
                            session = %session_id,
                            "mDNS candidate resolution failed — adding unmodified (prflx fallback)"
                        );
                    }
                }
                // #1882 — the name hid the address; the OS resolver returns the
                // candidate's own record, which for the browser's wintun
                // candidate IS its overlay address.
                if !rc_overlay.keeps_remote_candidate(&init.candidate) {
                    debug!(
                        session = %session_id,
                        "rc ICE: mDNS candidate resolved onto the overlay — dropped (rc_overlay off)"
                    );
                    return;
                }
                if let Err(e) = pc.add_ice_candidate(init).await {
                    debug!(session = %session_id, %e, "add_ice_candidate (mDNS path) failed");
                }
            });
            return Ok(());
        }
        self.pc
            .add_ice_candidate(init)
            .await
            .context("add_ice_candidate")
    }

    /// Stop SERVING this session without closing its transport: the channel
    /// handlers let go (clipboard, files, the cursor), the media pumps stop,
    /// and the input arbiter forgets the session, so its next event is denied
    /// and any key or button it holds is released. No channel closes, so the
    /// browser sees nothing yet.
    ///
    /// FR-27 P10 — the host's Disconnect calls this at the click, then keeps
    /// the bare connection for a grace so the server's word reaches the
    /// viewer before the peer dies. Without it the grace was a window in
    /// which the controller still drove the machine its owner had just taken
    /// back. Idempotent: [`Self::close`] and the drop repeat every step.
    /// An independent shared-lease timer owns these handles, not this pump's poll.
    pub fn shared_lease_stop(&self) -> std::sync::Arc<dyn Fn() + Send + Sync> {
        let end = self.session_end.clone();
        let media = self.media_pump.as_ref().map(|t| t.abort_handle());
        #[cfg(feature = "audio")]
        let audio = self.audio_pump.as_ref().map(|t| t.abort_handle());
        let rtcp = self.rtcp_reader.as_ref().map(|t| t.abort_handle());
        let pc = self.pc.clone();
        let sid = self.session_id;
        std::sync::Arc::new(move || {
            end.cancel();
            if let Some(t) = &media {
                t.abort();
            }
            #[cfg(feature = "audio")]
            if let Some(t) = &audio {
                t.abort();
            }
            if let Some(t) = &rtcp {
                t.abort();
            }
            crate::input::arbiter::global().session_closed(sid);
            let pc = pc.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(3), pc.close()).await;
            });
        })
    }
    pub fn stop_serving(&self) {
        // First: the channel handlers let go whatever the channels do next.
        self.session_end.cancel();
        if let Some(pump) = &self.media_pump {
            pump.abort();
        }
        #[cfg(feature = "audio")]
        if let Some(pump) = &self.audio_pump {
            pump.abort();
        }
        if let Some(reader) = &self.rtcp_reader {
            reader.abort();
        }
        crate::input::arbiter::global().session_closed(self.session_id);
    }

    pub async fn close(&self) {
        self.stop_serving();
        if let Err(e) = self.pc.close().await {
            warn!(session = %self.session_id, %e, "PC close failed");
        }
    }
}

/// P6 field fix (2026-08-05) — session-scoped teardown that MUST run on
/// every exit path.
///
/// The arbiter registration and the display-match ownership were both
/// released from the control DC's `on_close`. Field-observed on fleet-host-2: that
/// callback does NOT fire when the whole PeerConnection is torn down, so
/// arbiter entries LEAKED (server reported 0 open sessions while a fresh
/// registration logged `sessions=3`). A leaked entry inflates the
/// participants rail and — worse — can leave the exclusive-mode floor held
/// by a session that no longer exists.
///
/// `AgentPeer` is owned by the signalling loop's `peers` map, so its Drop
/// is the one point every path funnels through (Terminate, agent-side
/// hangup, WS drop, displacement, task abort). Both calls are idempotent,
/// so the `on_close` hook stays as a belt for the DC-only case.
impl Drop for AgentPeer {
    fn drop(&mut self) {
        let session_id = self.session_id;
        // The DataChannel handlers' own session end (idempotent; `close`
        // usually got here first).
        self.session_end.cancel();
        crate::input::arbiter::global().session_closed(session_id);
        // Wave 2 — release this session's telemetry counters; a
        // long-lived agent must not accumulate one entry per session.
        crate::session_telemetry::forget(session_id);
        // `restore_for` touches the OS display API; keep it off this
        // (possibly async-context) thread. Ownership-gated + idempotent.
        std::thread::spawn(move || {
            // FR-108 P1b — nothing waits for this session's unlock any more.
            crate::display_match::forget(session_id);
            if crate::display_match::restore_for(session_id) {
                tracing::info!(session = %session_id, "display-match: restored on peer drop (owner)");
            }
        });
        // #2024 — the session's encoder is freed as its pump drops, but glibc
        // keeps the pages in the arenas of the threads that freed them; a trim
        // a few seconds later gives them back (~110 MB a session, measured).
        crate::mem_trim::after_session_ended();
    }
}

/// Detect whether THIS session's negotiated ICE path runs through a TURN
/// relay, by inspecting the selected candidate pair. A relayed path (TURN,
/// especially over TCP on WSL / corp-UDP-blocked nets) is bandwidth- and
/// head-of-line-constrained, so the DC pumps clamp their bitrate ceiling to
/// `relay_max_bps()` for it. Unlike the process-wide
/// `ROOMLERD_ICE_RELAY_TCP` env flag, this is PER SESSION — the same
/// agent process serves both direct-local and cross-host-relay controllers
/// (e.g. the WSL virtual-desktop agent advertises a direct mirrored-network
/// path to a LAN browser AND a TURN-relayed path to a remote one), so the
/// env flag mis-classifies one of them.
///
/// The explicit env flag still wins as an OVERRIDE: vd-mode / the corp path
/// force `ice_transport_policy=Relay` up front, so the path IS relayed and
/// there's nothing to detect. Otherwise poll the selected pair briefly (ICE
/// may not have nominated the instant the pump starts) and fall back to
/// "unconstrained" if it hasn't nominated within ~3 s — the AIMD converges
/// regardless of the initial guess.
///
/// Gated on `any(vp9-444, ffmpeg-encoder)` — both DataChannel pumps call it
/// (Phase B added the FFmpeg HEVC/vp9_qsv pump as the second caller).
#[cfg(any(feature = "vp9-444", feature = "ffmpeg-encoder"))]
async fn detect_constrained_transport(
    pc: &Arc<RTCPeerConnection>,
    session_id: bson::oid::ObjectId,
) -> bool {
    if crate::encode::transport_is_constrained() {
        return true;
    }
    // Bind each Arc so the borrowed `&RTCIceTransport` outlives the chain.
    let sctp = pc.sctp();
    let dtls = sctp.transport();
    let ice = dtls.ice_transport();
    for _ in 0..30 {
        if let Some(pair) = ice.get_selected_candidate_pair().await {
            let local = pair.local();
            let remote = pair.remote();
            // Loopback-TURN corp-relay (Phase 3): a relay candidate at a
            // loopback/overlay address is the local agent's own fast TURN (the
            // loopback-TURN), NOT the capped far coturn — so it must not count
            // as constrained. A public relay (real coturn) still does.
            let relay = (local.typ == RTCIceCandidateType::Relay
                && !crate::encode::relay_addr_is_fast_local(&local.address))
                || (remote.typ == RTCIceCandidateType::Relay
                    && !crate::encode::relay_addr_is_fast_local(&remote.address));
            // Relay-escape — log the ADDRESSES, not just the types: a
            // "direct" Srflx↔Prflx pair whose remote is the router's WAN IP
            // is a NAT hairpin, while a 192.168.x remote is the true LAN
            // path. Types alone couldn't tell them apart in the field.
            info!(
                %session_id,
                relay,
                local_typ = ?local.typ,
                local_proto = ?local.protocol,
                local_addr = %format!("{}:{}", local.address, local.port),
                remote_typ = ?remote.typ,
                remote_proto = ?remote.protocol,
                remote_addr = %format!("{}:{}", remote.address, remote.port),
                "per-session ICE path detected (adaptive bitrate)"
            );
            return relay || overlay_remote_is_relay_tier(&remote.address, session_id).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    warn!(
        %session_id,
        "ICE candidate pair not nominated within 3s — treating as direct (unconstrained)"
    );
    false
}

/// FR-35 P2 — the nominated pair's REMOTE address (the viewer host), the key
/// the per-peer rate memory is kept under. `detect_constrained_transport` has
/// already waited for the nomination, so this normally returns at once.
#[cfg(any(feature = "vp9-444", feature = "ffmpeg-encoder"))]
async fn nominated_remote_ip(pc: &Arc<RTCPeerConnection>) -> Option<String> {
    // Bind each hop:  yields a temporary Arc and
    // borrows it (E0716 in CI when chained).
    let sctp = pc.sctp();
    let dtls = sctp.transport();
    let ice = dtls.ice_transport();
    for _ in 0..30 {
        if let Some(pair) = ice.get_selected_candidate_pair().await {
            return Some(pair.remote().address.clone());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// FR-79 V2 — the carrier under an overlay pair, as the memory key's second
/// half. Asks the same LocalAPI the constrained-transport probe asks; a
/// non-overlay remote (a TURN server's own address, say) is already its own
/// key, and anything unknown or mid-churn returns `None`, which leaves the
/// bare-address key this had before.
#[cfg(any(feature = "vp9-444", feature = "ffmpeg-encoder"))]
async fn overlay_carrier_tag(remote_addr: &str) -> Option<String> {
    if !addr_is_overlay_range(remote_addr) {
        return None;
    }
    let query = async {
        let mut client = tunnel_core::localapi::connect().await.ok()?;
        let peers = client.peers().await.ok()?;
        peers.into_iter().find(|p| {
            p.overlay_ip.as_deref() == Some(remote_addr)
                || p.overlay_ip6.as_deref() == Some(remote_addr)
        })
    };
    let peer = tokio::time::timeout(Duration::from_millis(400), query)
        .await
        .ok()??;
    let connection = format!("{:?}", peer.connection).to_lowercase();
    crate::encode::rate_memory::carrier_tag(
        &connection,
        peer.relay_kind.as_deref(),
        peer.relay_transport.as_deref(),
    )
}

/// FR-35 P2 — persists the session's stable rate for its peer when the pump
/// ends, whichever way it ends. The pump stores the governor's current stable
/// rate into `stable` once per viewer window; `0` = nothing worth keeping.
#[cfg(any(feature = "vp9-444", feature = "ffmpeg-encoder"))]
struct RateMemoryGuard {
    path: Option<std::path::PathBuf>,
    peer: Option<String>,
    stable: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// FR-79 V4 — what the OPENER measured about this carrier, when its burst
    /// queued enough for the estimator to say anything. Second-choice
    /// evidence: the session belief above is the whole session's answer.
    opener_measured: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

#[cfg(any(feature = "vp9-444", feature = "ffmpeg-encoder"))]
impl Drop for RateMemoryGuard {
    fn drop(&mut self) {
        let (Some(path), Some(peer)) = (self.path.as_ref(), self.peer.as_ref()) else {
            return;
        };
        // FR-79 V4 — a session writes what it MEASURED about this carrier, or
        // nothing at all. The belief the validity gate accepted is the
        // session's own answer; the opener's measurement stands in for a
        // session too short to have produced one. With neither, the entry
        // keeps its value AND its age, because refreshing a timestamp on no
        // evidence would keep a stale number alive past its TTL.
        let evidence = [
            self.stable.load(std::sync::atomic::Ordering::Relaxed),
            self.opener_measured
                .load(std::sync::atomic::Ordering::Relaxed),
        ]
        .into_iter()
        .find(|v| *v > 0);
        let mut mem = crate::encode::rate_memory::RateMemory::load(path);
        let kept = mem.record_session(peer, evidence, crate::encode::rate_memory::now_unix());
        if kept == 0 {
            return;
        }
        match mem.save(path) {
            Ok(()) => info!(
                peer,
                evidence_bps = ?evidence,
                kept_bps = kept,
                "FR-79 V4 rate memory: the carrier's measured rate remembered for the pair"
            ),
            Err(e) => {
                warn!(peer, %e, "FR-35 rate memory: could not persist (memory stays off for this pair)")
            }
        }
    }
}

/// Relay-escape — mid-session re-read of the selected ICE pair. The DC
/// pumps poll this every [`TRANSPORT_RECHECK_INTERVAL`] so a pair switch
/// (Chrome renominates relay→direct once the mDNS-resolved host pair
/// succeeds, or direct→relay on a path failure) updates the bitrate clamp
/// LIVE instead of staying pinned to the guess made at pump start.
/// `None` = no pair currently nominated (transient) — keep the last value.
#[cfg(any(feature = "vp9-444", feature = "ffmpeg-encoder"))]
const TRANSPORT_RECHECK_INTERVAL: Duration = Duration::from_secs(5);

/// rc.293 — per-session tally of the ICE candidate types this host gathered,
/// so the end-of-gather summary answers "did we produce a server-reflexive
/// candidate?" in one grep. Atomics because `on_ice_candidate` is an `Fn`
/// invoked concurrently across the gather burst.
#[derive(Default)]
struct GatherTally {
    host: std::sync::atomic::AtomicU32,
    srflx: std::sync::atomic::AtomicU32,
    prflx: std::sync::atomic::AtomicU32,
    relay: std::sync::atomic::AtomicU32,
}

impl GatherTally {
    // Fully qualified: the `RTCIceCandidateType` import at the top of this
    // file is cfg-gated to the vp9-444 / ffmpeg-encoder builds (it keeps
    // `clippy -D warnings` clean on FFmpeg-only builds), and this tally is
    // unconditional.
    fn note(&self, typ: webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType) {
        use webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType as T;
        let slot = match typ {
            T::Host => &self.host,
            T::Srflx => &self.srflx,
            T::Prflx => &self.prflx,
            T::Relay => &self.relay,
            T::Unspecified => return,
        };
        slot.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// One summary line at end-of-gather, plus a WARN when this host offered
    /// nothing hole-punchable — the state that silently forces every session
    /// onto the relay. Suppressed under `relay_tcp`, where relay-only is the
    /// deliberate configuration (`ice_transport_policy = Relay`) rather than a
    /// symptom.
    fn log_summary(&self, session_id: bson::oid::ObjectId, relay_tcp: bool) {
        use std::sync::atomic::Ordering::Relaxed;
        let (host, srflx, prflx, relay) = (
            self.host.load(Relaxed),
            self.srflx.load(Relaxed),
            self.prflx.load(Relaxed),
            self.relay.load(Relaxed),
        );
        info!(
            %session_id, host, srflx, prflx, relay, relay_tcp,
            "ICE: local gather complete"
        );
        if srflx == 0 && !relay_tcp {
            warn!(
                %session_id, host, relay,
                "ICE: gathered NO server-reflexive candidate — this host offers no \
                 hole-punchable address, so media falls back to the relay. Usual cause: \
                 STUN unreachable over UDP from every local interface (corp VPN / \
                 firewall capturing or blocking the path to the STUN/TURN servers)."
            );
        }
    }
}

#[cfg(any(feature = "vp9-444", feature = "ffmpeg-encoder"))]
async fn current_pair_is_relay(
    pc: &Arc<RTCPeerConnection>,
    session_id: bson::oid::ObjectId,
    previous: bool,
) -> Option<bool> {
    let sctp = pc.sctp();
    let dtls = sctp.transport();
    let ice = dtls.ice_transport();
    let pair = ice.get_selected_candidate_pair().await?;
    let local = pair.local();
    let remote = pair.remote();
    // Loopback-TURN corp-relay (Phase 3): a loopback/overlay relay is the local
    // agent's own fast TURN, not the capped far coturn — see
    // `relay_addr_is_fast_local`. Mirrors `detect_constrained_transport`.
    let relay = (local.typ == RTCIceCandidateType::Relay
        && !crate::encode::relay_addr_is_fast_local(&local.address))
        || (remote.typ == RTCIceCandidateType::Relay
            && !crate::encode::relay_addr_is_fast_local(&remote.address));
    let relay = relay || overlay_remote_is_relay_tier(&remote.address, session_id).await;
    if relay != previous {
        info!(
            %session_id,
            was_relay = previous,
            now_relay = relay,
            local_addr = %format!("{}:{}", local.address, local.port),
            remote_typ = ?remote.typ,
            remote_addr = %format!("{}:{}", remote.address, remote.port),
            "transport path changed mid-session — updating bitrate clamp (relay-escape)"
        );
    }
    Some(relay)
}

/// Overlay-aware constrained detection (2026-07-27, WINHOST-C field): a
/// nominated pair whose REMOTE lives on the overlay is only as good as the
/// overlay CARRIER underneath it. A relay-tier carrier (coturn / DERP) has
/// WAN RTT + churn but masquerades as a "direct" host↔host pair — the pump
/// then firehoses unclamped into a relay pipe and collapses (live capture:
/// 821 kbps / 17 fps with 1.5–7.5 s decode stalls). This also closes the same
/// blind spot in the loopback-TURN fast-local exemption: a local-relay pair
/// still EGRESSES over the overlay carrier, so it must clamp when that
/// carrier is relay-tier.
///
/// Asks the local daemon over LocalAPI (`Request::Peers`, the `roomler peers`
/// verb) which tier currently carries the peer that owns the remote address.
/// Anything other than a live `Direct` carrier counts as constrained —
/// `Relay`/`Tunnel` are capped paths, `Blocked`/`Offline` mean the carrier is
/// mid-churn (the media pair is about to feel it).
///
/// Fail-OPEN by design: hatch off, non-overlay remote, daemon unreachable,
/// peer unknown, or a slow pipe (>400 ms) → `false`, i.e. exactly today's
/// behaviour — a broken LocalAPI can never degrade a healthy direct session.
/// Escape hatch: `ROOMLERD_OVERLAY_TIER_DETECT=0`.
#[cfg(any(feature = "vp9-444", feature = "ffmpeg-encoder"))]
async fn overlay_remote_is_relay_tier(remote_addr: &str, session_id: bson::oid::ObjectId) -> bool {
    use tunnel_core::localapi::ConnectionType;

    // node_env: accepts ROOMLERD_/ROOMLER_NODE_ prefixes + the
    // `overlay_tier_detect` config key via the S2 fallback map.
    if tunnel_core::env::node_env("OVERLAY_TIER_DETECT").as_deref() == Some("0") {
        return false;
    }
    if !addr_is_overlay_range(remote_addr) {
        return false;
    }
    let query = async {
        let mut client = tunnel_core::localapi::connect().await.ok()?;
        let peers = client.peers().await.ok()?;
        peers.into_iter().find(|p| {
            p.overlay_ip.as_deref() == Some(remote_addr)
                || p.overlay_ip6.as_deref() == Some(remote_addr)
        })
    };
    match tokio::time::timeout(Duration::from_millis(400), query).await {
        Ok(Some(peer)) => {
            let constrained = !matches!(peer.connection, ConnectionType::Direct);
            if constrained {
                info!(
                    %session_id,
                    peer = %peer.name,
                    carrier = ?peer.connection,
                    upgrading = peer.upgrading,
                    rtt_ms = ?peer.rtt_ms,
                    "overlay carrier under the nominated pair is not direct — treating transport as constrained"
                );
            }
            constrained
        }
        // Peer unknown / daemon not running — nothing to learn, fail open.
        Ok(None) => false,
        // LocalAPI slower than the media pump can afford — fail open.
        Err(_) => false,
    }
}

/// True when an ICE candidate address string is inside the Roomler overlay
/// ranges: CGNAT `100.64.0.0/10` (v4) or the mesh ULA `fd72:6f6f:6d6c::/48`
/// (v6, the exact prefix the runtime derives peer v6 addresses from — NOT all
/// of fc00::/7, so a user's own VPN ULA never triggers a daemon query).
/// mDNS names and garbage don't parse → `false`.
///
/// Ungated since FR-102 P9c: [`crate::session_carrier`] reads it in every
/// build to tell an overlay pair from a public one, so it can no longer be
/// gated to the encoder features that first needed it.
pub(crate) fn addr_is_overlay_range(addr: &str) -> bool {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            s[0] == 0xfd72 && s[1] == 0x6f6f && s[2] == 0x6d6c
        }
        Err(_) => false,
    }
}

/// Per-session media pump. Captures frames, encodes to the negotiated
/// codec, writes Samples into the WebRTC track. Rebuilds the encoder
/// if the capture resolution changes mid-session (e.g. dock/undock).
///
/// Phase Y.3: when `negotiated_transport == Some("data-channel-vp9-444")`
/// AND the `vp9-444` Cargo feature is compiled in, the pump runs an
/// alternate fast-path that builds a libvpx Vp9Encoder, length-prefixes
/// each encoded frame, and writes them into the `video-bytes`
/// RTCDataChannel that the controller opened (see peer.rs line ~494
/// `on_data_channel` arm and `docs/encoders.md` for the wire
/// format). The webrtc track stays bound but receives no samples in
/// that mode — the browser side renders from the worker-decoded
/// canvas instead of `<video>`.
#[allow(clippy::too_many_arguments)]
async fn media_pump(
    session_id: bson::oid::ObjectId,
    track: Arc<TrackLocalStaticSample>,
    keyframe_requested: Arc<std::sync::atomic::AtomicBool>,
    invalidation_requested: Arc<std::sync::atomic::AtomicBool>,
    quality_state: Arc<std::sync::atomic::AtomicU8>,
    remb_bps: Arc<std::sync::atomic::AtomicU32>,
    encoder_preference: encode::EncoderPreference,
    chosen_codec: String,
    target_resolution: Arc<std::sync::Mutex<TargetResolution>>,
    negotiated_transport: Option<String>,
    chroma_pref: Option<String>,
    // FR-17 — the controller can parse the framed DataChannel wire format.
    chunk_framing: bool,
    video_bytes_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    lock_state_rx: tokio::sync::watch::Receiver<lock_state::LockState>,
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    // Adaptive bitrate — the peer connection, so the DC pumps can detect
    // THIS session's actual ICE path (relay vs direct) at runtime instead
    // of the process-wide `ROOMLERD_ICE_RELAY_TCP` env flag.
    pc: Arc<RTCPeerConnection>,
    // Published each frame with the native (pre-downscale) capture dims so
    // the cursor pump can scale the OS cursor position into the encoded
    // frame's space (rc.183). Packed w:h; 0 until the first frame.
    capture_native_dims: Arc<std::sync::atomic::AtomicU64>,
    // rc.190 — published each frame with the dims the pump ACTUALLY encodes
    // (post apply_target_resolution + relay/SW caps); the cursor pump scales
    // native→encoded from this. Packed w:h; 0 until the first frame.
    encoded_dims: Arc<std::sync::atomic::AtomicU64>,
    // rc.188 — packed viewer decode report (`rc:decodestat`); the DC pumps
    // fold it into the viewer-rate fps cap. Only the DC pumps consume it.
    viewer_report: Arc<crate::encode::viewer_rate::ViewerFeedback>,
    // rc.199 — per-session Priority dial (`rc:priority`); forwarded to whichever
    // DC pump this session routes to. Like `viewer_report`, only the DC pumps
    // consume it (relay resolution cap), so the signalling-only build parks it.
    priority: Arc<std::sync::atomic::AtomicU8>,
    // FR-93 P6c — where a pump ends its session when the person at the screen
    // stops the share (`end_stopped_at_screen`).
    rc_sessions: crate::rc_sessions::RcSessionRegistry,
) {
    // `pc` is consumed only by the VP9-444 DC pump's per-session transport
    // detection (feature-gated); keep the signalling-only / non-vp9 build
    // warning-clean.
    #[cfg(not(feature = "vp9-444"))]
    let _ = &pc;
    // `viewer_report` is consumed only by the DC video pumps (vp9-444 +
    // ffmpeg-encoder); keep the signalling-only build warning-clean.
    #[cfg(not(any(feature = "vp9-444", feature = "ffmpeg-encoder")))]
    let _ = &viewer_report;
    // Same story for the Priority dial — DC-pump-only.
    #[cfg(not(any(feature = "vp9-444", feature = "ffmpeg-encoder")))]
    let _ = &priority;
    // FR-17 framing is a property of the `video-bytes` DC, which only
    // the DC pumps own; the webrtc-track path has no chunks to frame.
    #[cfg(not(any(feature = "vp9-444", feature = "ffmpeg-encoder")))]
    let _ = chunk_framing;
    // Tracks the lock-state value seen on the previous loop iteration
    // so we can request an encoder keyframe on each transition. The
    // browser decoder otherwise has to wait for the next periodic
    // intra-refresh to actually render the overlay (or the resumed
    // desktop on unlock), which on a live session can be 1-2 seconds
    // of stale-then-suddenly-correct frames.
    let mut was_locked_last_iter = matches!(*lock_state_rx.borrow(), lock_state::LockState::Locked);
    // Phase A — pump-local resampler (cached taps + pooled intermediate).
    let mut resampler = crate::encode::resample::Resampler::new();
    // Phase B — the backend cap last handed to the capturer (change-gated).
    // rc.26 — probe SystemContext once at pump start. Captured into a
    // local bool so the per-frame check is a single comparison.
    // SystemContext capture rebinds to winsta0\Winlogon on lock; the
    // operator should see real lock-screen pixels (and be able to
    // type the password), NOT the "Host is locked" overlay placeholder.
    let sys_ctx_worker = is_system_context_worker();
    if sys_ctx_worker {
        info!(
            %session_id,
            "media_pump: SystemContext worker — lock overlay disabled (real Winlogon frames will stream)"
        );
    }
    // rc.77 — HEVC over DataChannel fork (Option B). Same shape as
    // the VP9-444 path below: when the session negotiated HEVC over
    // the `video-bytes` channel, route to the FFmpeg-encoder DC pump.
    // Falls through to the VP9-444 path or legacy track-based pump
    // when not selected — including when the feature is compiled in
    // but `ROOMLERD_USE_FFMPEG=1` isn't set on this process
    // (caps probe wouldn't have advertised the transport, but a
    // mismatched / old controller could still ask for it).
    // rc.190 — AV1 over DataChannel. Mirrors the HEVC block below; the
    // caps probe only advertises `data-channel-av1` on hosts with AV1
    // encode silicon, so reaching here with the feature off / FFmpeg
    // unavailable means a mismatched or stale controller — fall through
    // to the WebRTC track like every other unsatisfiable transport ask.
    if matches!(negotiated_transport.as_deref(), Some("data-channel-av1")) {
        #[cfg(feature = "ffmpeg-encoder")]
        {
            if crate::encode::ffmpeg::available() {
                tracing::info!(
                    %session_id,
                    "media pump: AV1 over DataChannel (rc.190 — FFmpeg via vendor SDK)"
                );
                return run_ffmpeg_dc_session(
                    FfmpegDcCodec::Av1,
                    session_id,
                    video_bytes_dc,
                    keyframe_requested,
                    target_resolution,
                    lock_state_rx,
                    quality_state,
                    control_dc.clone(),
                    pc.clone(),
                    capture_native_dims,
                    encoded_dims,
                    viewer_report,
                    priority,
                    false,
                    chunk_framing,
                    rc_sessions,
                )
                .await;
            }
            tracing::warn!(
                %session_id,
                "negotiated_transport=data-channel-av1 but ROOMLERD_USE_FFMPEG isn't set — falling back to WebRTC video track"
            );
        }
        #[cfg(not(feature = "ffmpeg-encoder"))]
        {
            tracing::warn!(
                %session_id,
                "negotiated_transport=data-channel-av1 but agent was built without `ffmpeg-encoder` feature — falling back to WebRTC video track"
            );
        }
    }
    if matches!(negotiated_transport.as_deref(), Some("data-channel-hevc")) {
        #[cfg(feature = "ffmpeg-encoder")]
        {
            if crate::encode::ffmpeg::available() {
                tracing::info!(
                    %session_id,
                    "media pump: HEVC over DataChannel (rc.77 — FFmpeg via vendor SDK)"
                );
                return run_ffmpeg_dc_session(
                    FfmpegDcCodec::Hevc,
                    session_id,
                    video_bytes_dc,
                    keyframe_requested,
                    target_resolution,
                    lock_state_rx,
                    quality_state,
                    control_dc.clone(),
                    pc.clone(),
                    capture_native_dims,
                    encoded_dims,
                    viewer_report,
                    priority,
                    // P7 — the viewer's 4:4:4 request (Rext, hevc_nvenc only;
                    // rc:session.request `chroma_pref`, previously honoured
                    // only by the VP9-444 transport).
                    matches!(chroma_pref.as_deref(), Some("yuv444")),
                    chunk_framing,
                    rc_sessions,
                )
                .await;
            }
            tracing::warn!(
                %session_id,
                "negotiated_transport=data-channel-hevc but ROOMLERD_USE_FFMPEG isn't set — falling back to WebRTC video track"
            );
        }
        #[cfg(not(feature = "ffmpeg-encoder"))]
        {
            tracing::warn!(
                %session_id,
                "negotiated_transport=data-channel-hevc but agent was built without `ffmpeg-encoder` feature — falling back to WebRTC video track"
            );
        }
    }
    if matches!(negotiated_transport.as_deref(), Some("data-channel-h264")) {
        #[cfg(feature = "ffmpeg-encoder")]
        {
            if crate::encode::ffmpeg::available() {
                tracing::info!(
                    %session_id,
                    "media pump: H.264 over DataChannel (P2 — FFmpeg via vendor SDK)"
                );
                return run_ffmpeg_dc_session(
                    FfmpegDcCodec::H264,
                    session_id,
                    video_bytes_dc,
                    keyframe_requested,
                    target_resolution,
                    lock_state_rx,
                    quality_state,
                    control_dc.clone(),
                    pc.clone(),
                    capture_native_dims,
                    encoded_dims,
                    viewer_report,
                    priority,
                    matches!(chroma_pref.as_deref(), Some("yuv444")),
                    chunk_framing,
                    rc_sessions,
                )
                .await;
            }
            tracing::warn!(
                %session_id,
                "negotiated_transport=data-channel-h264 but ROOMLERD_USE_FFMPEG isn't set — falling back to WebRTC video track"
            );
        }
        #[cfg(not(feature = "ffmpeg-encoder"))]
        {
            tracing::warn!(
                %session_id,
                "negotiated_transport=data-channel-h264 but agent was built without `ffmpeg-encoder` feature — falling back to WebRTC video track"
            );
        }
    }
    // Y.3 fork: route to the DC pump when the session negotiated VP9
    // 4:4:4 over the `video-bytes` channel. Falls through to the
    // legacy track-based pump otherwise — including when the feature
    // is compiled in but the negotiation didn't pick VP9 (mismatched
    // browser / older controller / operator override).
    if matches!(
        negotiated_transport.as_deref(),
        Some("data-channel-vp9-444")
    ) {
        // rc.83 — Intel HW VP9 via FFmpeg vp9_qsv. When the env var is
        // set AND the operator's host has a working vp9_qsv encoder,
        // route the same `data-channel-vp9-444` transport through the
        // FFmpeg pump (Intel iGPU instead of libvpx SW). Probe before
        // we commit to this path so a missing-driver host transparently
        // falls back to libvpx. Profile constraint: vp9_qsv is 4:2:0-
        // only, so when the operator forced chroma=4:4:4 (via session
        // request OR env var) we keep the libvpx SW path which is the
        // only one that emits VP9 profile 1.
        #[cfg(feature = "ffmpeg-encoder")]
        {
            let wants_444 = matches!(chroma_pref.as_deref(), Some("yuv444"));
            if crate::encode::ffmpeg::available() {
                use crate::encode::ffmpeg::FfmpegEncoder;
                // FR-77 P3b — a 4:4:4 session tries the HARDWARE profile-1
                // cell first (vp9_qsv over packed VUYX, `cells::names_444`);
                // a 4:2:0 session takes vp9_qsv exactly as before (rc.83).
                // The quick probe opens the exact cell at the caps-probe
                // resolution, so a host that cannot open it falls to libvpx —
                // the path that emits profile 1 in software — transparently.
                let probe = if wants_444 {
                    crate::encode::cells::names_444(
                        roomler_ai_remote_control::models::VideoCodec::Vp9,
                    )
                    .first()
                    .copied()
                    .and_then(|name| FfmpegEncoder::new_named_probe(name, 480, 270, true).ok())
                } else {
                    FfmpegEncoder::new_vp9(480, 270).ok()
                };
                if let Some(enc) = probe {
                    drop(enc);
                    tracing::info!(
                        %session_id,
                        chroma444 = wants_444,
                        "media pump: VP9 over DataChannel via FFmpeg vp9_qsv (Intel HW; rc.83 Iris Xe fps unlock; FR-77 P3b profile 1 over VUYX)"
                    );
                    return run_ffmpeg_dc_session(
                        FfmpegDcCodec::Vp9,
                        session_id,
                        video_bytes_dc,
                        keyframe_requested,
                        target_resolution,
                        lock_state_rx,
                        quality_state,
                        control_dc.clone(),
                        pc.clone(),
                        capture_native_dims,
                        encoded_dims,
                        viewer_report,
                        priority,
                        wants_444,
                        chunk_framing,
                        rc_sessions,
                    )
                    .await;
                }
            }
        }
        #[cfg(feature = "vp9-444")]
        {
            tracing::info!(
                %session_id,
                "media pump: VP9-444 over DataChannel (Phase Y.3 libvpx SW path)"
            );
            return run_vp9_444_dc_session(
                session_id,
                video_bytes_dc,
                keyframe_requested,
                target_resolution,
                lock_state_rx,
                quality_state,
                chroma_pref,
                control_dc.clone(),
                pc,
                capture_native_dims,
                encoded_dims,
                viewer_report,
                priority,
                chunk_framing,
                rc_sessions,
            )
            .await;
        }
        #[cfg(not(feature = "vp9-444"))]
        {
            let _ = chroma_pref;
            tracing::warn!(
                %session_id,
                "negotiated_transport=data-channel-vp9-444 but agent was built without `vp9-444` feature — falling back to WebRTC video track"
            );
        }
    }
    // Suppress the "field never read" warning when the legacy path
    // ignores video_bytes_dc (no vp9-444 feature, or webrtc track
    // mode). The handle is still created in peer.rs because the
    // on_data_channel callback unconditionally stashes any DC named
    // `video-bytes` for forward-compat with future agent builds.
    let _ = &video_bytes_dc;
    // rc.87 — control_dc is only consumed by the DC video pumps
    // (HEVC/VP9 FFmpeg paths) for the `rc:video-info` send. The legacy
    // WebRTC-track pump below doesn't use it; silence unused on builds
    // that fall through here (no ffmpeg-encoder feature, or webrtc
    // transport).
    let _ = &control_dc;
    // Capture downscale policy mirrors the encoder preference. When the
    // HW encoder is in play (or will be, on Auto + Windows), we want
    // native-resolution frames; the HW path handles 4K fine and any
    // downscale here would discard detail for no gain. When the encoder
    // is software openh264, we keep the Auto policy so high-res sources
    // still get the 2× downsample to hit the encoder's throughput
    // ceiling.
    let downscale = downscale_for(encoder_preference);
    // `target_fps` becomes mut because the auto-fps-cap heuristic (see
    // the auto_downscale_evaluated block below) may drop it from the
    // optimistic Auto-on-Windows 60 to 30 if the encoder cascade ends
    // up on a SW MFT. Keep it as the single source of truth so
    // `frame_duration_floor` stays consistent.
    // FR-112 P2b — under the software tier (Linux by default) a software
    // encoder targets 60 too, paced down to what it sustains, never below 30.
    let sw_tier = crate::encode::sw_fps_60_enabled();
    let mut target_fps = target_fps_with_tier(encoder_preference, sw_tier);
    tracing::info!(
        %session_id,
        ?encoder_preference,
        ?downscale,
        target_fps,
        "media pump starting"
    );
    let mut capturer = capture::open_default_async(
        target_fps,
        downscale,
        media_waiting_hook(session_id, control_dc.clone()),
    )
    .await;
    // FR-80 — a capturer that cannot capture says so, and the controller is
    // told once, here, instead of the operator reading a stall. Every real
    // backend answers `None`, so a healthy session sends nothing.
    if let Some(reason) = capturer.unavailable() {
        spawn_capture_unavailable_notice(session_id, control_dc.clone(), reason.clone());
    }
    // FR-93 P6g — and an arm the compositor shows nothing for still says, at
    // the screen, who is viewing it.
    tell_the_screen(session_id, capturer.arm(), &rc_sessions);
    // FR-93 P1 — and what its input will reach. After the capture opened: a
    // portal capture registers its input route as it opens.
    spawn_input_reach_notice(session_id, control_dc.clone());
    // P3 — bounded reopen backoff for the capture-error arm (500 ms → 10 s
    // on consecutive failures; quiet spell resets). See `ReopenBackoff`.
    let mut reopen_backoff = capture::ReopenBackoff::new();
    let mut encoder: Option<Box<dyn encode::VideoEncoder>> = None;
    let mut encoder_dims: Option<(u32, u32)> = None;
    // One-shot guard for the SW-HEVC-at-high-res auto-downscale
    // heuristic. Flips to true after the first encoder build so we
    // evaluate the policy once per session — a mid-session operator
    // override via `rc:resolution` must not be clobbered by a
    // re-evaluation on an incidental encoder rebuild (DPI flip, etc.).
    let mut auto_downscale_evaluated = false;
    // FR-112 P2b — the software tier, live once the cascade lands on a
    // software encoder: its pace (from the heartbeat's encode cost), the
    // cadence gate's next slot, and the frame rate last handed to the encoder.
    let mut sw_live = false;
    let mut sw_pace = crate::encode::encode_pressure::SoftwarePace::new();
    let mut sw_pace_due: Option<std::time::Instant> = None;
    let mut sw_rate_applied: Option<u32> = None;
    // Floor on the gap the RTP clock advances by before each frame. DXGI
    // Desktop Duplication only emits a frame when the screen changes, so on
    // an idle desktop the real gap between two frames can be seconds. RTP
    // timestamp increments are `gap * clock_rate`; if the step stayed at
    // target_fps (16.6 ms at 60 fps, 33 ms at 30 fps) while wallclock advances
    // by 1 s, the browser's playout clock starves and the video element goes
    // black. Measure the wallclock gap per frame and spend it before the
    // frame is stamped (#2284).
    let mut frame_duration_floor = Duration::from_micros(1_000_000 / target_fps as u64);
    let mut last_sample_at: Option<std::time::Instant> = None;
    // FR-98 C6 — read once per open, never per frame (FR-70). The extension
    // goes on a packet only if this session's answer negotiated it.
    let playout_zero = crate::rtp_playout::enabled().then(|| [crate::rtp_playout::zero()]);

    // Keep the most recent captured frame around so we can re-feed it to
    // the encoder during idle periods. DXGI Desktop Duplication only
    // signals when the screen changes — on an idle desktop the agent can
    // go seconds without producing a frame, which makes the browser's
    // decoder enter a pause state. The user then perceives several
    // seconds of lag when they finally do something, because the stream
    // has to resume from the pause. Re-encoding the last frame at the
    // idle floor keeps the RTP stream flowing and the decoder unpaused.
    // Arc<Frame> so repeated idle keepalives share the big BGRA buffer
    // with the encoder (which only reads). Without Arc, each keepalive
    // cloned the entire frame — up to 33 MB at 4K, 8 MB at 1080p —
    // every keepalive tick.
    let mut last_good_frame: Option<std::sync::Arc<crate::capture::Frame>> = None;
    // VFR (1F.1): idle floor at 1 fps. Was 500 ms (≈2 fps). The
    // browser's jitter buffer + the encoder's intra-refresh
    // (1B.1) tolerate the longer gap, and on a static desktop
    // there is nothing for the controller to react to anyway —
    // the only thing this duty cycle preserves is the RTP clock
    // and the decoder unpause. Once dirty-rect metadata lands
    // (1C.2 / WGC backend), this can drop further: re-encode
    // only when dirty_rects.is_empty() == false; otherwise emit
    // a NAL-free heartbeat tied to the wallclock.
    const IDLE_KEEPALIVE: Duration = Duration::from_millis(1_000);
    let mut last_capture_at = std::time::Instant::now();
    // FR-93 P3e — a capture waiting on its host (a display switched off).
    let mut capture_wait = CaptureWait::default();

    // Observability: count frames in/out and bytes written, log every 30
    // encoded frames (~once per second at 30fps). Without this a silent
    // stall in capture or encode is indistinguishable from a working pump.
    let mut frames_captured: u64 = 0;
    let mut frames_empty: u64 = 0;
    // FR-29 P2 — damage observability. Without these the backend can report
    // perfect dirty rects and nothing on the host can tell: both would-be
    // consumers (`set_roi_hints`, `note_real_frame_area`) are inert today, so
    // the heartbeat is the ONLY place the tracked/unknown split becomes
    // visible. P1's lesson was that an optimisation you cannot observe is one
    // you cannot trust.
    let mut damage_tracked_frames: u64 = 0;
    let mut damage_permille_sum: u64 = 0;
    let mut damage_union_sum: u64 = 0;
    let mut damage_bbox_sum: u64 = 0;
    let mut damage_rects_sum: u64 = 0;
    let mut frames_encoded: u64 = 0;
    let mut frames_keepalive: u64 = 0;
    let mut bytes_written: u64 = 0;
    let mut write_errors: u64 = 0;
    // Per-stage wall-time accumulators (microseconds) so the heartbeat
    // can attribute the per-frame budget. When users report "only 7 fps"
    // the breakdown makes it obvious whether capture is blocking
    // (WGC CPU readback on iGPU) or encode is saturated (fallback to
    // a weak MFT after an adapter cascade demoted to Intel UHD).
    let mut capture_time_us: u64 = 0;
    let mut encode_time_us: u64 = 0;
    // Reset the accumulators at each heartbeat so averages are over
    // the preceding ~30-frame window, not the entire session.
    let mut heartbeat_frames_base: u64 = 0;
    let mut heartbeat_capture_us_base: u64 = 0;
    // FR-29 P2 — windowed like every other average in this heartbeat. A
    // CUMULATIVE damage average is worse than none: it is dominated by
    // whatever the screen was doing minutes ago, which is exactly how a
    // busy-period 1000permille reading survived into an idle window and
    // made a precise tracker look saturated.
    let mut heartbeat_damage_frames_base: u64 = 0;
    let mut heartbeat_damage_permille_base: u64 = 0;
    let mut heartbeat_damage_union_base: u64 = 0;
    let mut heartbeat_damage_bbox_base: u64 = 0;
    let mut heartbeat_damage_rects_base: u64 = 0;
    let mut heartbeat_encode_us_base: u64 = 0;

    // Last applied quality preference. Initialised to a sentinel
    // (0xFF) so the first loop iteration unconditionally pushes the
    // current AUTO/Low/High choice into the encoder, even when no
    // controller message has arrived yet (covers the case where the
    // encoder is rebuilt mid-session and needs the bitrate re-applied).
    let mut last_applied_quality: u8 = 0xFF;
    // Last bitrate we pushed into the encoder. Used for hysteresis on
    // REMB-driven changes — reapply only if the new target moves
    // outside ±15% of the current one. Without hysteresis, REMB
    // wobble (every ~2 s) thrashes set_bitrate even on a stable link.
    let mut last_applied_bitrate: u32 = 0;
    // 0.85 safety factor against REMB so we don't drive right up to
    // the bandwidth ceiling — one congestion-control cycle later we'd
    // overshoot, packet loss spikes, REMB drops, oscillation.
    const REMB_SAFETY_FACTOR_NUM: u32 = 85;
    const REMB_SAFETY_FACTOR_DEN: u32 = 100;
    // Hysteresis band: only push a new bitrate if it differs from the
    // current applied one by more than this fraction.
    const HYSTERESIS_PCT: u32 = 15;

    loop {
        // FR-112 P2b — cadence pacing, as the VP9-444 pump's: a software
        // encoder that cannot hold 60 takes frames on an even grid at the rate
        // it sustains, never below 30. Slots run from consumption, so a frame
        // that takes longer than the interval degrades to the natural cadence.
        if sw_live {
            if let Some(paced) = sw_pace.paced() {
                let interval = Duration::from_micros(1_000_000 / paced.max(1) as u64);
                let now = std::time::Instant::now();
                if let Some(due) = sw_pace_due
                    && due > now
                {
                    tokio::time::sleep(due - now).await;
                }
                sw_pace_due = Some(std::time::Instant::now() + interval);
            } else {
                sw_pace_due = None;
            }
        }
        let capture_started = std::time::Instant::now();
        // Bound to a local first so the mutable borrow of `capturer` ends
        // here — the idle arm below reads `capturer.frames_unchanged()`, and
        // a temporary living to the end of the `match` would keep the borrow.
        let next_frame = capturer.next_frame().await;
        let frame: std::sync::Arc<crate::capture::Frame> = match next_frame {
            Ok(Some(f)) => {
                capture_time_us =
                    capture_time_us.saturating_add(capture_started.elapsed().as_micros() as u64);
                frames_captured += 1;
                last_capture_at = std::time::Instant::now();
                capture_wait.on_frame();
                let arc = std::sync::Arc::new(f);
                last_good_frame = Some(arc.clone());
                // FR-101 P4b-2 — a real capture, never a keepalive: the idle limit's
                // screen leg (free unless a live session has a limit).
                crate::session_idle::note_frame(&arc);
                arc
            }
            Ok(None) => {
                frames_empty += 1;
                // FR-93 P3e — the display is off (P5f: this user's session is
                // in the background): the controller is told, and no keepalive
                // re-encodes the last frame (a decoded frame would clear the
                // viewer's notice).
                if capture_wait.hold(capturer.waits_for(), session_id, &control_dc) {
                    // P5f — and the pump stays abortable. Mutter's frame wait
                    // blocks in place and never yields, so without this the
                    // loop never reached an await that yields: a viewer that
                    // left during the wait left its pump running, holding
                    // the screencast (GNOME's sharing indicator up) and the
                    // shared pipeline, which took each new viewer on as a
                    // follower of a pump that sent nothing.
                    tokio::task::yield_now().await;
                    continue;
                }
                // Log every ~5s worth of empty polls so an idle desktop is
                // visible without flooding. DXGI only fires on screen change,
                // so this can spike briefly then settle.
                if frames_empty.is_multiple_of(150) {
                    // FR-29 — this log is now the ONLY periodic signal an idle
                    // Linux host emits. The media heartbeat fires per 30
                    // ENCODED frames, and once the damage tracker starts
                    // proving captures unnecessary nothing is encoded, so the
                    // heartbeat goes quiet exactly when the optimisation is
                    // working. Carry the counters here so a healthy idle host
                    // stays legible instead of looking hung.
                    info!(
                        %session_id,
                        frames_empty,
                        frames_unchanged = capturer.frames_unchanged(),
                        frames_captured,
                        frames_encoded,
                        "capture produced no frame (idle screen)"
                    );
                }
                // If the screen has been idle for IDLE_KEEPALIVE and we
                // have a cached frame, re-encode it. openh264 will emit
                // a tiny (~tens of bytes) P-frame since nothing changed,
                // which keeps the browser's decoder unpaused.
                if last_capture_at.elapsed() >= IDLE_KEEPALIVE {
                    if let Some(ref f) = last_good_frame {
                        frames_keepalive += 1;
                        last_capture_at = std::time::Instant::now();
                        f.clone()
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            Err(e) => {
                // DXGI Desktop Duplication is fragile — it returns
                // transient errors on display-mode changes, DPI switches,
                // UAC dimmer entry/exit, lock screen transitions, RDP
                // takeover, fullscreen toggles, GPU driver recycles, etc.
                // These used to kill the pump, leaving the data channels
                // alive (mouse/keyboard still worked) but video frozen
                // forever until session reconnect. Rebuild the capturer
                // and the encoder, keep the pump running. P3: bounded
                // exponential backoff (500 ms → 10 s on consecutive
                // failures) — a PERSISTENT denial (DDA app limit with N
                // concurrent sessions) must not re-run the open cascade
                // twice a second forever.
                //
                // FR-93 P6c — except the person at the screen stopping the
                // share with the desktop's own control: the session ends as
                // their Disconnect would, and the capture is never reopened
                // behind their back.
                if capture::stopped_at_screen(&e) {
                    match end_stopped_at_screen(session_id, &rc_sessions, None).await {}
                }
                warn!(%session_id, %e, "capture error — rebuilding capturer");
                tokio::time::sleep(reopen_backoff.delay()).await;
                capturer = capture::open_default_async(
                    target_fps,
                    downscale,
                    media_waiting_hook(session_id, control_dc.clone()),
                )
                .await;
                // Force the encoder to rebuild on the next frame — new
                // capturer may come back at a different resolution (e.g.
                // after a DPI change) and openh264 can't be resized
                // mid-stream without re-init.
                encoder = None;
                encoder_dims = None;
                continue;
            }
        };

        // Apply the controller-chosen target resolution. Native = no
        // change. Fixed = downscale (upscaling is refused — we cap at
        // native since upsampling wastes encoder budget on interpolated
        // pixels that carry no new information). On resolution change
        // the `encoder_dims` check below rebuilds the encoder.
        // Publish the native (pre-downscale) dims so the cursor pump can
        // map the OS cursor into the encoded frame's pixel space (rc.183).
        // `frame` here is still native — apply_target_resolution is what
        // downscales it. On HW paths (DownscalePolicy::Never) this is the
        // true monitor resolution; that's every host that hits the DC
        // video pumps in the field.
        capture_native_dims.store(
            pack_dims(frame.width, frame.height),
            std::sync::atomic::Ordering::Relaxed,
        );
        let frame = crate::encode::resample::apply_target_resolution(
            &mut resampler,
            frame,
            *target_resolution.lock().unwrap(),
        );
        // rc.190 — publish the dims we actually encode so the cursor pump
        // scales from truth (this pump's auto-downscale mutates the shared
        // target_resolution, so user-target == effective here).
        encoded_dims.store(
            pack_dims(frame.width, frame.height),
            std::sync::atomic::Ordering::Relaxed,
        );

        // Lock-screen overlay (M3 phase 3, Z-path). When the user-
        // context worker can't see the real desktop (input desktop
        // has transitioned to `winsta0\Winlogon`), the captured
        // frame is black/stale and useless. Substitute a static
        // "Host is locked" overlay at the same dimensions so the
        // operator sees something distinctive instead of frozen
        // black, and the encoder pump keeps the RTP stream healthy.
        // Force a keyframe on the transition into Locked so the
        // browser decoder doesn't need to wait for the next intra-
        // refresh to render the overlay.
        //
        // rc.26 — `sys_ctx_worker` short-circuits the overlay: under
        // SystemContext the capture has already rebound to Winlogon
        // and the real lock-screen pixels are in `frame`. Still pulse
        // a keyframe on each transition so the new captured surface
        // snaps into view.
        let frame = if *lock_state_rx.borrow() == lock_state::LockState::Locked {
            if !was_locked_last_iter {
                keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
                crate::session_telemetry::counters(session_id).note_keyframe();
                was_locked_last_iter = true;
            }
            if sys_ctx_worker {
                frame
            } else {
                lock_overlay::produce(frame.width, frame.height, frame.monotonic_us, frame.monitor)
            }
        } else {
            if was_locked_last_iter {
                // Force a keyframe on the unlock transition too so
                // the resumed real desktop snaps into view at full
                // quality immediately.
                keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
                crate::session_telemetry::counters(session_id).note_keyframe();
                was_locked_last_iter = false;
            }
            frame
        };

        // (Re)build the encoder if the frame dimensions change.
        if encoder_dims != Some((frame.width, frame.height)) {
            info!(
                %session_id,
                w = frame.width, h = frame.height,
                codec = %chosen_codec,
                "initialising encoder for frame dims"
            );
            let (enc, actual) = encode::open_for_codec(
                &chosen_codec,
                frame.width,
                frame.height,
                encoder_preference,
            );
            if actual != chosen_codec {
                // Runtime demotion (e.g. HEVC cascade failed at actual
                // dims despite enumeration passing). The track was
                // already bound to the negotiated codec's mime type
                // and the SDP answer sent — we can't switch mid-session.
                // Log loudly so a field incident is diagnosable, then
                // keep going: the browser will receive bytes it can't
                // decode and show a black frame. The controller can
                // reconnect or toggle Quality to re-negotiate.
                warn!(
                    %session_id,
                    requested = %chosen_codec,
                    actual = %actual,
                    "encoder demotion — browser will see undecodable stream until renegotiation"
                );
            }
            encoder = Some(enc);
            encoder_dims = Some((frame.width, frame.height));
            // Force the quality preference back through the new
            // encoder — set_bitrate state lives on the encoder
            // instance, so a rebuild starts from the resolution-
            // derived default until we re-apply.
            last_applied_quality = 0xFF;
            // FR-112 P2b — and the frame rate, which lives there too.
            sw_rate_applied = None;

            // Loudly surface the Noop case. Previously this only
            // showed up in the ~1 s heartbeat log as `backend="noop"`,
            // which looks like normal progress to anyone not
            // reading carefully. A Noop encoder means the browser
            // gets only SDP setup bytes and a permanent black
            // frame — it's the single biggest "session looks alive
            // but nothing works" footgun in the stack. Shout at
            // session-build time so field reports land on a log
            // line that explains the symptom in one read.
            if encoder.as_ref().map(|e| e.name()) == Some("noop") {
                warn!(
                    %session_id,
                    codec = %chosen_codec,
                    w = frame.width, h = frame.height,
                    "encoder resolved to NoopEncoder — NO VIDEO WILL SHIP for this session. Cascade above tells you why. Workarounds: toggle codec override to H.264 + reconnect, or switch Quality to `low` to force a smaller profile."
                );
            }

            // Auto-downscale heuristic. SW HEVC (MS's
            // HEVCVideoExtensionEncoder is the only SW HEVC on
            // Windows) can't sustain 30 fps at 4K on any machine we
            // have, and the cascade lands there whenever the HW
            // HEVC MFTs fail — NVENC Blackwell (0x8000FFFF), Intel
            // QSV async-only (0x80004005), AMD on shared-memory
            // configurations. We want the operator to see
            // smooth 30-60 fps out of the box rather than a
            // 7 fps stream they have to know how to fix. Cap the
            // CAPTURE resolution at 1920×1080 — that's the breakpoint
            // where SW HEVC on modern Intel/AMD laptops typically
            // sustains 30 fps. Only applies on first session start
            // (per `auto_downscale_evaluated`) and only when the
            // operator hasn't already set an explicit override
            // via `rc:resolution`.
            if !auto_downscale_evaluated {
                auto_downscale_evaluated = true;
                let enc_ref = encoder.as_ref().unwrap();
                let backend_is_sw = !enc_ref.is_hardware();
                // Tier the downscale by codec weight. HEVC + AV1
                // SW encode is ~3x heavier than H.264, so cap them
                // hard at 1080p-class. H.264 SW is faster but 1920x1200
                // at 30 fps still eats ~21 ms / frame on an Intel
                // iGPU — close to our 33 ms budget and leaving no
                // headroom for capture jitter. Drop H.264 SW above
                // 720p-class down to a 720p-equivalent where encode
                // is comfortably under 12 ms / frame.
                //
                // rc.38 — preserve source aspect when picking the
                // target (see module-scope `aspect_preserved_target`;
                // hoisted in rc.190 so the DC pumps' resolution caps
                // share the exact same math).
                let heavy_codec = chosen_codec == "h265" || chosen_codec == "av1";
                let h264 = chosen_codec == "h264";
                let above_1080p =
                    (frame.width as u64) * (frame.height as u64) > (1920u64 * 1080u64);
                let above_720p = (frame.width as u64) * (frame.height as u64) > (1280u64 * 720u64);
                let mut auto_downscale_just_fired = false;
                if backend_is_sw && heavy_codec && above_1080p {
                    let (tw, th) = aspect_preserved_target(frame.width, frame.height, 1920);
                    let mut guard = target_resolution.lock().unwrap();
                    if matches!(*guard, TargetResolution::Native) {
                        *guard = TargetResolution::Fixed {
                            width: tw,
                            height: th,
                        };
                        auto_downscale_just_fired = true;
                        tracing::warn!(
                            %session_id,
                            native_w = frame.width,
                            native_h = frame.height,
                            target_w = tw,
                            target_h = th,
                            codec = %chosen_codec,
                            encoder = enc_ref.name(),
                            "auto-downscale: SW heavy codec on high-res source — capping capture at aspect-preserved ≤1920 long-edge to preserve fps. Operator can override via rc:resolution."
                        );
                    }
                } else if backend_is_sw && h264 && above_720p {
                    let (tw, th) = aspect_preserved_target(frame.width, frame.height, 1280);
                    let mut guard = target_resolution.lock().unwrap();
                    if matches!(*guard, TargetResolution::Native) {
                        *guard = TargetResolution::Fixed {
                            width: tw,
                            height: th,
                        };
                        auto_downscale_just_fired = true;
                        tracing::warn!(
                            %session_id,
                            native_w = frame.width,
                            native_h = frame.height,
                            target_w = tw,
                            target_h = th,
                            codec = %chosen_codec,
                            encoder = enc_ref.name(),
                            "auto-downscale: SW H.264 on high-res source — capping capture at aspect-preserved ≤1280 long-edge so encode stays under the 33 ms 30-fps budget. Operator can override via rc:resolution."
                        );
                    }
                }

                // Auto-fps-cap. When the H.264 cascade lands on a SW
                // MFT (Intel QSV defers to the as-yet-unbuilt async
                // pipeline, MS SW MFT wins by default), capture
                // becomes the bottleneck — the BGRA readback alone
                // is ~20 ms on Intel UHD-class iGPUs, against a
                // 16.6 ms budget at 60 fps. WGC then drops 35-45 %
                // of frames and the resulting jitter triggers
                // browser NACK bursts. Drop the rate to 30 fps
                // (33 ms budget) which absorbs the readback cost
                // and produces an even cadence. Field log
                // 2026-04-27 from RoziLaptop -> Schetovodstvo-PZ
                // (Intel UHD 730) — the same heuristic as the
                // resolution cap, just for the time axis. Skipped
                // when target_fps was already <= 30 (operator
                // chose Software preference, or capture-side
                // downcap from a future tier).
                //
                // FR-112 P2b — except under the software tier, where a
                // software encoder keeps 60 and the pace brings it down
                // to what it sustains (the readback this cap absorbs is
                // WGC's, on Windows, where the tier is opt-in).
                sw_live = sw_tier && backend_is_sw;
                if sw_live {
                    info!(
                        %session_id,
                        target_fps,
                        codec = %chosen_codec,
                        encoder = enc_ref.name(),
                        "FR-112: software encoder at a 60 fps target, paced to what it sustains (never below 30; ROOMLERD_SW_FPS_60=0 restores 30)"
                    );
                }
                if backend_is_sw && target_fps > 30 && !sw_live {
                    let new_fps: u32 = 30;
                    tracing::warn!(
                        %session_id,
                        old_fps = target_fps,
                        new_fps,
                        codec = %chosen_codec,
                        encoder = enc_ref.name(),
                        "auto-fps-cap: SW backend at >30 fps target — rebuilding capturer at 30 fps to clear the capture-bottleneck drop rate"
                    );
                    target_fps = new_fps;
                    frame_duration_floor = Duration::from_micros(1_000_000 / target_fps as u64);
                    capturer = capture::open_default_async(
                        target_fps,
                        downscale,
                        media_waiting_hook(session_id, control_dc.clone()),
                    )
                    .await;
                }

                // rc.38 — when auto-downscale changes target_resolution
                // from Native → Fixed, the encoder we just built is at
                // the NATIVE dims and would emit a first frame at those
                // dims. The next loop iteration would then downscale +
                // rebuild the encoder, causing the WebRTC track to see
                // a frame-1 → frame-2 resolution flip. Chrome's
                // `<video>.videoWidth` latches to frame-1 dims and the
                // browser-side input normalisation (letterboxedNormalise)
                // then uses a stale aspect ratio against the actual
                // rendered surface — clicks land at wrong OS pixels
                // (the field-test host field bug 2026-05-17).
                //
                // Fix: drop the native-dim encoder + skip writing this
                // frame to the track. The next iteration will rebuild
                // at the downscaled dims and emit frame-1 there. Costs
                // one captured frame's latency at session start
                // (~30 ms); track never sees a resize.
                if auto_downscale_just_fired {
                    encoder = None;
                    encoder_dims = None;
                    keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
                    crate::session_telemetry::counters(session_id).note_keyframe();
                    tracing::info!(
                        %session_id,
                        "auto-downscale fired on first encoder build — dropping native-dim encoder so the track's first frame is at the downscaled dims (avoids browser videoWidth resize race)"
                    );
                    continue;
                }
            }
        }

        let enc = encoder.as_mut().unwrap();
        if keyframe_requested.swap(false, std::sync::atomic::Ordering::Relaxed) {
            enc.request_keyframe();
        }
        if invalidation_requested.swap(false, std::sync::atomic::Ordering::Relaxed) {
            // 0 = "we don't know which frame was lost; just give us
            // an intra recovery". Backends with ref-tracking can use
            // a meaningful value once peer.rs surfaces it.
            enc.request_reference_invalidation(0);
        }
        // ROI hints from per-frame tracked damage (P8a: `Damage` enum —
        // `rects()` is empty for both Unknown and provably-unchanged, and
        // every encoder's hook is a no-op today, so the distinction
        // doesn't matter at this call site yet).
        if !frame.damage.rects().is_empty() {
            enc.set_roi_hints(frame.damage.rects(), (frame.width, frame.height));
        }
        // FR-29 P2 — record what the backend claimed to know about this frame.
        if let Some(pm) = frame
            .damage
            .area_permille(u64::from(frame.width) * u64::from(frame.height))
        {
            damage_tracked_frames += 1;
            damage_permille_sum += u64::from(pm);
            // FR-29 — the two numbers that decide whether P3 is worth building.
            // `area_permille` sums overlapping rects and saturates, so it can
            // never answer "how much would a partial readback have to read".
            // The union answers it for a perfect per-rect readback; the bbox
            // answers it for the simple one-GetImage form.
            damage_union_sum += u64::from(
                frame
                    .damage
                    .union_permille(frame.width, frame.height)
                    .unwrap_or(0),
            );
            damage_bbox_sum += u64::from(
                frame
                    .damage
                    .bbox_permille(frame.width, frame.height)
                    .unwrap_or(0),
            );
            // FR-29 — few huge rects or many small ones? union==bbox==1000 is
            // consistent with BOTH, and they imply opposite things about P3.
            damage_rects_sum += frame.damage.rects().len() as u64;
        }

        // Adaptive bitrate: combine quality preference (controller
        // intent) with REMB (network capacity) and apply on change
        // or out-of-hysteresis movement. MF + openh264 both honour
        // set_bitrate now (1F.2). Cheap on every frame: two atomic
        // loads + integer math + a single comparison.
        // FR-112 P2b — the encoder budgets each frame's bits from its frame
        // rate: hand it the rate the pump runs at, whenever that changes.
        let runs_at = sw_pace.paced().unwrap_or(target_fps);
        if sw_live && sw_rate_applied != Some(runs_at) {
            enc.set_frame_rate(runs_at);
            sw_rate_applied = Some(runs_at);
        }
        let q_now = quality_state.load(std::sync::atomic::Ordering::Relaxed);
        let remb_now = remb_bps.load(std::sync::atomic::Ordering::Relaxed);
        if let Some((w, h)) = encoder_dims {
            // FR-112 P2b — under the tier the base follows the rate the pump
            // runs at, by √(fps/30); otherwise 0.4.141's linear base.
            let base = if sw_live {
                encode::bitrate_base_for_fps(w, h, runs_at)
            } else {
                encode::initial_bitrate_for_fps(w, h, target_fps)
            };
            let quality_target = quality::target_bitrate(q_now, base);
            // If REMB hasn't reported, defer to the quality-derived
            // target. Once it does, take min(quality, remb*safety) so
            // the controller can ratchet down further on a metered
            // link but never push past what the receiver thinks the
            // path can carry.
            let target = if remb_now == 0 {
                quality_target
            } else {
                let remb_safe =
                    (remb_now / REMB_SAFETY_FACTOR_DEN).saturating_mul(REMB_SAFETY_FACTOR_NUM);
                // Floor: 500 kbps was unreadable at 1080p HEVC (green
                // chroma artefacts, blurred PowerShell text — the
                // 2026-04-24 field report). Use the larger of a flat
                // MIN_BITRATE_BPS and 25 % of the resolution-derived
                // target. At 1080p this is ~2.5 Mbps (vs 500 kbps
                // previously) — still severely degraded on a bad
                // link but keeps small-font text legible. REMB
                // reports below this get clamped up; if the link
                // really can't carry that much we'll see packet loss
                // escalate which REMB then ratchets further down and
                // the hysteresis re-applies.
                let floor = encode::MIN_BITRATE_BPS.max(base / 4);
                quality_target.min(remb_safe.max(floor))
            };
            // Hysteresis: only push when quality changed (operator
            // input always wins immediately) OR target moves outside
            // ±HYSTERESIS_PCT of last applied.
            let quality_changed = q_now != last_applied_quality;
            let drift_too_big = if last_applied_bitrate == 0 {
                true // first apply: always push
            } else {
                let band = (last_applied_bitrate / 100).saturating_mul(HYSTERESIS_PCT);
                target.abs_diff(last_applied_bitrate) > band
            };
            if quality_changed || drift_too_big {
                enc.set_bitrate(target);
                info!(
                    %session_id,
                    quality = quality::label(q_now),
                    base_bps = base,
                    remb_bps = remb_now,
                    target_bps = target,
                    "applying adaptive bitrate"
                );
                last_applied_quality = q_now;
                last_applied_bitrate = target;
            }
        }
        let encode_started = std::time::Instant::now();
        let packets = match enc.encode(frame).await {
            Ok(p) => p,
            Err(e) => {
                warn!(%session_id, %e, "encode error — stopping media pump");
                return;
            }
        };
        encode_time_us = encode_time_us.saturating_add(encode_started.elapsed().as_micros() as u64);

        // Wallclock-based RTP timestamps, so they advance at real time, not
        // at an assumed 30 fps. #2284: the gap since the previous frame is
        // spent BEFORE this frame is stamped, so each frame carries its own
        // time. Passed as `duration`, it advanced the clock after the frame
        // instead, and every frame carried the previous one's time: on
        // damage-driven frames a receiver read each change in the gaps as
        // network jitter (Chrome's buffer grew to 326 ms, FR-98 P5). The
        // first frame advances by nothing.
        let now = std::time::Instant::now();
        // Clamp: floor at the nominal frame duration, cap at 1 s so a
        // multi-second idle doesn't cause an enormous RTP timestamp jump.
        let wallclock_gap = match last_sample_at {
            Some(t) => now
                .duration_since(t)
                .clamp(frame_duration_floor, Duration::from_secs(1)),
            None => Duration::ZERO,
        };
        last_sample_at = Some(now);
        let extensions: &[webrtc::rtp::extension::HeaderExtension] =
            playout_zero.as_ref().map_or(&[], |ext| &ext[..]);

        // Each packet one encode returns is a frame of its own: MF can hand
        // back frames it had buffered, and openh264 (one spatial layer)
        // returns one. Share the gap out, so each frame gets a time of its
        // own and the newest lands at `now`.
        let frames_out = packets.len().max(1) as u32;
        let mut packet_bytes: u64 = 0;
        for (i, p) in packets.into_iter().enumerate() {
            packet_bytes += p.data.len() as u64;
            let sample = Sample {
                data: Bytes::from(p.data),
                timestamp: SystemTime::now(),
                duration: frame_duration_floor,
                packet_timestamp: 0,
                prev_dropped_packets: 0,
                prev_padding_packets: 0,
            };
            let gap = match (wallclock_gap.is_zero(), i) {
                // The stream's first frame.
                (true, 0) => Duration::ZERO,
                (true, _) => Duration::from_millis(1),
                (false, _) => wallclock_gap / frames_out,
            };
            let written = track.write_sample_after_gap(&sample, gap, extensions).await;
            if let Err(e) = written {
                write_errors += 1;
                // Elevated from debug — silent drops were hiding the real
                // problem during first-bringup on Windows.
                warn!(%session_id, %e, write_errors, "write_sample failed");
            }
        }

        frames_encoded += 1;
        bytes_written += packet_bytes;

        if frames_encoded == 1 {
            let backend = encoder.as_ref().map(|e| e.name()).unwrap_or("none");
            info!(
                %session_id,
                backend,
                first_frame_bytes = packet_bytes,
                "first encoded frame written to track"
            );
        }
        if frames_encoded.is_multiple_of(30) {
            let backend = encoder.as_ref().map(|e| e.name()).unwrap_or("none");
            // Average per-stage microseconds over the preceding 30-frame
            // window (not the whole session), so transient stalls
            // don't get smeared away by hours of steady operation.
            let frames_in_window = frames_encoded.saturating_sub(heartbeat_frames_base).max(1);
            let capture_us_window = capture_time_us.saturating_sub(heartbeat_capture_us_base);
            let encode_us_window = encode_time_us.saturating_sub(heartbeat_encode_us_base);
            let avg_capture_ms = capture_us_window / (1_000 * frames_in_window);
            let avg_encode_ms = encode_us_window / (1_000 * frames_in_window);
            // FR-29 — read from the backend, NOT derived from frames_empty.
            // The two are different conditions that both surface as Ok(None):
            // frames_empty means the pump was starved, frames_unchanged means
            // the backend proved a capture was unnecessary. Reporting one as
            // the other would turn a healthy idle host into a false alarm.
            let frames_unchanged = capturer.frames_unchanged();
            // FR-29 P2 — `damage_tracked_frames` is the falsifiable bit: on a
            // backend that reports Damage::Unknown it stays 0 no matter how
            // busy the screen is, so a non-zero value is proof the tracker is
            // producing real rects rather than the field merely existing.
            let damage_frames_window =
                damage_tracked_frames.saturating_sub(heartbeat_damage_frames_base);
            let damage_permille_window =
                damage_permille_sum.saturating_sub(heartbeat_damage_permille_base);
            let avg_damage_permille = damage_permille_window
                .checked_div(damage_frames_window)
                .unwrap_or(0);
            // FR-29 P3 viability, measured rather than assumed: `union` is what
            // a perfect per-rect readback would touch, `bbox` what the simple
            // one-GetImage form would. If both sit near 1000 there is nothing
            // for a partial readback to win and P3 should not be built.
            let avg_damage_union_permille = damage_union_sum
                .saturating_sub(heartbeat_damage_union_base)
                .checked_div(damage_frames_window)
                .unwrap_or(0);
            let avg_damage_bbox_permille = damage_bbox_sum
                .saturating_sub(heartbeat_damage_bbox_base)
                .checked_div(damage_frames_window)
                .unwrap_or(0);
            let avg_damage_rects = damage_rects_sum
                .saturating_sub(heartbeat_damage_rects_base)
                .checked_div(damage_frames_window)
                .unwrap_or(0);
            // FR-112 P2b — the software tier steps once per heartbeat, on the
            // window's encode cost.
            if sw_live {
                let window_ms = encode_us_window as f32 / (1000.0 * frames_in_window as f32);
                let _ = sw_pace.observe(window_ms, target_fps);
            }
            info!(
                %session_id,
                backend,
                frames_captured, frames_empty, frames_unchanged, frames_encoded, frames_keepalive,
                damage_tracked_frames = damage_frames_window,
                avg_damage_permille,
                avg_damage_union_permille,
                avg_damage_bbox_permille,
                avg_damage_rects,
                bytes_written, write_errors,
                avg_capture_ms, avg_encode_ms,
                target_fps,
                paced_fps = ?sw_pace.paced(),
                "media pump heartbeat (≈1s window)"
            );
            heartbeat_frames_base = frames_encoded;
            heartbeat_capture_us_base = capture_time_us;
            heartbeat_damage_frames_base = damage_tracked_frames;
            heartbeat_damage_permille_base = damage_permille_sum;
            heartbeat_damage_union_base = damage_union_sum;
            heartbeat_damage_bbox_base = damage_bbox_sum;
            heartbeat_damage_rects_base = damage_rects_sum;
            heartbeat_encode_us_base = encode_time_us;
        }
    }
}

/// Length-prefix an encoded VP9 frame for the `video-bytes` DC. The
/// header layout matches `ui/src/workers/rc-vp9-444-worker.ts`
/// (lines 16-23 of that file):
///
/// ```text
/// u32 size_le;       // payload length, little-endian
/// u8  flags;         // bit 0 = keyframe
/// u64 timestamp_us;  // monotonic capture timestamp
/// [u8] payload;      // raw VP9 frame
/// ```
///
/// Exported `pub(crate)` so the unit tests can lock the wire format.
/// FR-1 P7 — the process-wide monotonic epoch behind both DC video wire
/// timestamps and the `rc:clock` echo. One shared clock is the whole point:
/// the browser probes it over the control DC, learns the offset to its own
/// clock, and can then read any frame's wire timestamp as a true end-to-end
/// age. (Before this the ffmpeg pump stamped from its own start and the
/// vp9 pump forwarded the capture backend's epoch — three different zeros.)
fn agent_epoch() -> std::time::Instant {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(std::time::Instant::now)
}

/// Microseconds since the process epoch. Stays under 2^53 (JS-exact) for
/// ~285 years of uptime, and never runs backwards across pump rebuilds —
/// which the old per-pump zero did, handing the decoder a timestamp jump
/// on every encoder swap.
pub(crate) fn agent_epoch_us() -> u64 {
    agent_epoch().elapsed().as_micros() as u64
}

/// Pure reply builder for `rc:clock` (unit-locked). `t0` is echoed as the
/// JSON value it arrived as — the browser subtracts it from its own clock,
/// so any parse/normalise step here could only corrupt the RTT.
pub(crate) fn clock_echo_json(t0: &serde_json::Value, agent_us: u64) -> String {
    serde_json::json!({"t": "rc:clock.echo", "t0": t0, "agent_us": agent_us}).to_string()
}

/// FR-17 — bytes of the per-message framing prefix: `frame_seq` u32 LE,
/// `chunk_idx` u16 LE, `chunk_count` u16 LE.
/// `dead_code` allowance mirrors [`frame_video_bytes`]: both DC pumps
/// are feature-gated, so a signalling-only build has no caller. The
/// codec itself is portable and its tests run unconditionally.
#[allow(dead_code)]
pub(crate) const CHUNK_HEADER_BYTES: usize = 8;

/// FR-17 — prefix one outbound DataChannel message so the receiver can tell
/// WHICH frame it belongs to and notice a missing one.
///
/// Today the channel is reliable + ordered, so a gap cannot occur and this
/// changes nothing on the wire beyond 8 bytes per 16 KiB message (0.05 %).
/// It ships first, alone, precisely so that the stage that DOES give up
/// ordering flips one property against a receiver whose gap handling has
/// already been exercised — rather than debugging two changes at once.
///
/// `frame_seq` wraps at u32: ~19 000 hours at 60 fps, and the receiver only
/// ever compares it for equality with the frame it is assembling, so a wrap
/// costs at most one discarded frame.
#[allow(dead_code)]
pub(crate) fn chunk_framed(
    frame_seq: u32,
    chunk_idx: u16,
    chunk_count: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHUNK_HEADER_BYTES + payload.len());
    out.extend_from_slice(&frame_seq.to_le_bytes());
    out.extend_from_slice(&chunk_idx.to_le_bytes());
    out.extend_from_slice(&chunk_count.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// `dead_code` allowance is for builds without the `vp9-444` feature
/// where the function has no caller — the tests still exercise it
/// under either feature flag setting.
#[allow(dead_code)]
pub(crate) fn frame_video_bytes(payload: &[u8], is_keyframe: bool, timestamp_us: u64) -> Vec<u8> {
    const HEADER_BYTES: usize = 13;
    let mut out = Vec::with_capacity(HEADER_BYTES + payload.len());
    let size = payload.len() as u32;
    out.extend_from_slice(&size.to_le_bytes());
    out.push(if is_keyframe { 0x01 } else { 0x00 });
    out.extend_from_slice(&timestamp_us.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// P5 — VP9 chroma resolution shared by the session dispatcher (pipeline
/// key) and the pump's encoder build: session pref → env → 4:4:4 default.
#[cfg(feature = "vp9-444")]
fn vp9_chroma_is_444(chroma_pref: Option<&str>) -> bool {
    chroma_pref
        .and_then(|s| match s.trim().to_ascii_lowercase().as_str() {
            "yuv420" | "420" => Some(false),
            "yuv444" | "444" => Some(true),
            _ => None,
        })
        .unwrap_or_else(|| {
            matches!(
                crate::encode::libvpx::vp9_chroma_from_env(),
                crate::encode::libvpx::Vp9Chroma::Yuv444
            )
        })
}

/// P5 — session-level entry for the FFmpeg DC transports. JOIN a live
/// same-profile shared pipeline as a follower when one exists (no capturer,
/// no encoder — the owner's stream fans out to this session's DC); else run
/// the pump as the owner. A follower whose pipeline closed re-dispatches
/// (the first re-dispatcher becomes the new owner, the rest re-join); a
/// SPILLED follower goes straight to its own pump and does not re-join the
/// pipeline that evicted it.
#[cfg(feature = "ffmpeg-encoder")]
#[allow(clippy::too_many_arguments)]
async fn run_ffmpeg_dc_session(
    codec: FfmpegDcCodec,
    session_id: bson::oid::ObjectId,
    video_bytes_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    keyframe_requested: Arc<std::sync::atomic::AtomicBool>,
    target_resolution: Arc<std::sync::Mutex<TargetResolution>>,
    lock_state_rx: tokio::sync::watch::Receiver<lock_state::LockState>,
    quality_state: Arc<std::sync::atomic::AtomicU8>,
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    pc: Arc<RTCPeerConnection>,
    capture_native_dims: Arc<std::sync::atomic::AtomicU64>,
    encoded_dims: Arc<std::sync::atomic::AtomicU64>,
    viewer_report: Arc<crate::encode::viewer_rate::ViewerFeedback>,
    priority: Arc<std::sync::atomic::AtomicU8>,
    // P7 — the viewer's HEVC Rext 4:4:4 request (chroma_pref == "yuv444" on
    // the hevc transport). Keys the shared pipeline (a Rext stream and a
    // Main-profile stream configure DIFFERENT viewer decoders and must
    // never share an encoder — the Vp9Dc chroma-keyed precedent) and is
    // threaded into the pump.
    chroma444: bool,
    // FR-17 — the controller negotiated per-chunk framing for this
    // session (it advertised `chunk-framing` support in
    // `rc:session.request`). Threaded down to the send task rather
    // than read from a global: it is a per-SESSION property, and a
    // shared pipeline can serve viewers that disagree.
    chunk_framing: bool,
    // FR-93 P6c — see `media_pump`.
    rc_sessions: crate::rc_sessions::RcSessionRegistry,
) {
    // P7 — chroma-discriminated hard-profile label (HEVC only; every other
    // codec ignores the flag).
    let profile_label: &'static str = codec.pipeline_label(chroma444);
    loop {
        let sink = crate::media_share::FollowerSink {
            session_id,
            video_bytes_dc: video_bytes_dc.clone(),
            control_dc: control_dc.clone(),
            keyframe_requested: keyframe_requested.clone(),
            target_resolution: target_resolution.clone(),
            quality_state: quality_state.clone(),
            viewer_report: viewer_report.clone(),
            priority: priority.clone(),
            capture_native_dims: capture_native_dims.clone(),
            encoded_dims: encoded_dims.clone(),
            chunk_framing,
        };
        if let Some(guard) = crate::media_share::try_join(
            crate::media_share::PipelineKey::FfmpegDc(profile_label),
            sink,
            ffmpeg_target_fps(false),
        ) {
            match guard.detached().await {
                crate::media_share::DetachReason::PipelineClosed => {
                    info!(%session_id, codec = codec.label(), "P5: shared pipeline closed — re-dispatching");
                    continue;
                }
                crate::media_share::DetachReason::Spilled => {
                    info!(%session_id, codec = codec.label(), "P5: spilled from shared pipeline — starting own pump");
                }
            }
        }
        return media_pump_ffmpeg_dc(
            codec,
            session_id,
            video_bytes_dc,
            keyframe_requested,
            target_resolution,
            lock_state_rx,
            quality_state,
            control_dc,
            pc,
            capture_native_dims,
            encoded_dims,
            viewer_report,
            priority,
            chroma444,
            chunk_framing,
            rc_sessions,
        )
        .await;
    }
}

/// P5 — session-level entry for the libvpx VP9-444 DC transport; twin of
/// [`run_ffmpeg_dc_session`], keyed by chroma (444/420 are different VP9
/// profiles and cannot share a stream).
#[cfg(feature = "vp9-444")]
#[allow(clippy::too_many_arguments)]
async fn run_vp9_444_dc_session(
    session_id: bson::oid::ObjectId,
    video_bytes_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    keyframe_requested: Arc<std::sync::atomic::AtomicBool>,
    target_resolution: Arc<std::sync::Mutex<TargetResolution>>,
    lock_state_rx: tokio::sync::watch::Receiver<lock_state::LockState>,
    quality_state: Arc<std::sync::atomic::AtomicU8>,
    chroma_pref: Option<String>,
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    pc: Arc<RTCPeerConnection>,
    capture_native_dims: Arc<std::sync::atomic::AtomicU64>,
    encoded_dims: Arc<std::sync::atomic::AtomicU64>,
    viewer_report: Arc<crate::encode::viewer_rate::ViewerFeedback>,
    priority: Arc<std::sync::atomic::AtomicU8>,
    // FR-17 — the controller negotiated per-chunk framing for this
    // session (it advertised `chunk-framing` support in
    // `rc:session.request`). Threaded down to the send task rather
    // than read from a global: it is a per-SESSION property, and a
    // shared pipeline can serve viewers that disagree.
    chunk_framing: bool,
    // FR-93 P6c — see `media_pump`.
    rc_sessions: crate::rc_sessions::RcSessionRegistry,
) {
    loop {
        let sink = crate::media_share::FollowerSink {
            session_id,
            video_bytes_dc: video_bytes_dc.clone(),
            control_dc: control_dc.clone(),
            keyframe_requested: keyframe_requested.clone(),
            target_resolution: target_resolution.clone(),
            quality_state: quality_state.clone(),
            viewer_report: viewer_report.clone(),
            priority: priority.clone(),
            capture_native_dims: capture_native_dims.clone(),
            encoded_dims: encoded_dims.clone(),
            chunk_framing,
        };
        if let Some(guard) = crate::media_share::try_join(
            crate::media_share::PipelineKey::Vp9Dc {
                chroma_444: vp9_chroma_is_444(chroma_pref.as_deref()),
            },
            sink,
            vp9_444_target_fps_from_env(),
        ) {
            match guard.detached().await {
                crate::media_share::DetachReason::PipelineClosed => {
                    info!(%session_id, "P5: shared VP9 pipeline closed — re-dispatching");
                    continue;
                }
                crate::media_share::DetachReason::Spilled => {
                    info!(%session_id, "P5: spilled from shared VP9 pipeline — starting own pump");
                }
            }
        }
        return media_pump_vp9_444_dc(
            session_id,
            video_bytes_dc,
            keyframe_requested,
            target_resolution,
            lock_state_rx,
            quality_state,
            chroma_pref,
            control_dc,
            pc,
            capture_native_dims,
            encoded_dims,
            viewer_report,
            priority,
            chunk_framing,
            rc_sessions,
        )
        .await;
    }
}

/// Phase Y.3 alternate media pump: capture → libvpx VP9 4:4:4 encode
/// → length-prefixed `video-bytes` DC. No webrtc track involvement.
///
/// Behaviour parity with the legacy pump where it matters:
/// - Resolution-change rebuild (encoder is keyed on (w, h))
/// - Keyframe-on-request (browser PLI / fresh-DC equivalent)
/// - Heartbeat log every ~30 frames so a stalled pump is greppable
/// - Idle keepalive at 1 fps so the decoder doesn't pause
///
/// rc.33 additions (RustDesk-parity smoothness sprint):
/// - Resolution + quality-derived bitrate target (was hard-cap 8 Mbps);
///   `rc:quality` from the controller now moves this on the fly.
/// - DC backpressure AIMD: `dc.buffered_amount` over 1 MiB cuts the
///   target by 20% (MD); under 64 KiB for ≥ 5 s adds 10% (AI). Replaces
///   the absent REMB feedback path for the DC-transport.
/// - Optional 60 fps via `ROOMLERD_VP9_FPS` env var (operator
///   opt-in escape hatch — full warmup-probe / control-DC plumbing
///   deferred to a follow-up).
#[cfg(feature = "vp9-444")]
#[allow(clippy::too_many_arguments)]
async fn media_pump_vp9_444_dc(
    session_id: bson::oid::ObjectId,
    video_bytes_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    keyframe_requested: Arc<std::sync::atomic::AtomicBool>,
    target_resolution: Arc<std::sync::Mutex<TargetResolution>>,
    lock_state_rx: tokio::sync::watch::Receiver<lock_state::LockState>,
    quality_state: Arc<std::sync::atomic::AtomicU8>,
    chroma_pref: Option<String>,
    // Badge-truth — the control DC, so this pump finally sends
    // `rc:video-info` (codec/encoder/chroma/transport) like the FFmpeg
    // pump has since rc.87. Pre-badge-truth, libvpx sessions showed the
    // browser's fallback label with no transport — one of the two causes
    // of the field's "neither relay nor direct" badges.
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    pc: Arc<RTCPeerConnection>,
    // rc.183 — publish native pre-downscale dims for the cursor pump.
    capture_native_dims: Arc<std::sync::atomic::AtomicU64>,
    // rc.190 — publish the ACTUAL encoded dims (post caps) for the cursor pump.
    encoded_dims: Arc<std::sync::atomic::AtomicU64>,
    // rc.188 — packed viewer decode report for the viewer-rate fps cap.
    viewer_report: Arc<crate::encode::viewer_rate::ViewerFeedback>,
    // rc.199 — per-session Priority dial (`rc:priority`); resolves the relay
    // resolution cap this pump feeds `effective_target_resolution`.
    priority: Arc<std::sync::atomic::AtomicU8>,
    // FR-17 — the controller negotiated per-chunk framing for this
    // session (it advertised `chunk-framing` support in
    // `rc:session.request`). Threaded down to the send task rather
    // than read from a global: it is a per-SESSION property, and a
    // shared pipeline can serve viewers that disagree.
    chunk_framing: bool,
    // FR-93 P6c — see `media_pump`.
    rc_sessions: crate::rc_sessions::RcSessionRegistry,
) {
    // See `media_pump`: tracks lock-state transitions so we can
    // request a keyframe on the lock/unlock boundary.
    let mut was_locked_last_iter = matches!(*lock_state_rx.borrow(), lock_state::LockState::Locked);
    // rc.26 — same gate as the legacy pump. Under SystemContext the
    // captured frame IS the real Winlogon screen; substituting an
    // overlay over it would hide the password prompt and block remote
    // unlock.
    let sys_ctx_worker = is_system_context_worker();
    if sys_ctx_worker {
        info!(
            %session_id,
            "media_pump_vp9_444_dc: SystemContext worker — lock overlay disabled"
        );
    }
    use crate::encode::libvpx::Vp9Encoder;

    // rc.33: opt-in 60 fps via env var. Default 30 (the pre-rc.33
    // behaviour). Operators on hosts that can sustain SW VP9 encode at
    // 4K@60 with cpu-used 6 can flip `ROOMLERD_VP9_FPS=60` to
    // halve perceptual motion latency. No warmup probe in rc.33 — the
    // env var is operator-acknowledged; a CPU-starved host will see
    // frame drops surface in the heartbeat log (`frames_encoded /
    // frames_captured` ratio < 0.95).
    let target_fps: u32 = vp9_444_target_fps_from_env();
    let frame_duration_floor = Duration::from_micros(1_000_000 / target_fps as u64);
    // FR-112 P2 — the software tier: pace to what the encoder sustains, and a
    // bitrate base that follows the rate actually run at.
    let sw_tier = crate::encode::sw_fps_60_enabled();
    let mut pace_due: Option<std::time::Instant> = None;
    // BGRA capture; never downscale (libvpx + dcv_color_primitives
    // BGRA→I444 is fast enough at 1080p without the 2× capture
    // downsample). Operator-controlled `rc:resolution` still applies
    // via target_resolution on the post-capture path.
    let downscale = crate::capture::DownscalePolicy::Never;
    info!(
        %session_id,
        target_fps,
        "VP9-444 DC pump starting"
    );
    let mut capturer = capture::open_default_async(
        target_fps,
        downscale,
        media_waiting_hook(session_id, control_dc.clone()),
    )
    .await;
    // FR-80 — a capturer that cannot capture says so, and the controller is
    // told once, here, instead of the operator reading a stall. Every real
    // backend answers `None`, so a healthy session sends nothing.
    if let Some(reason) = capturer.unavailable() {
        spawn_capture_unavailable_notice(session_id, control_dc.clone(), reason.clone());
    }
    // FR-93 P6g — and an arm the compositor shows nothing for still says, at
    // the screen, who is viewing it.
    tell_the_screen(session_id, capturer.arm(), &rc_sessions);
    // FR-93 P1 — and what its input will reach. After the capture opened: a
    // portal capture registers its input route as it opens.
    spawn_input_reach_notice(session_id, control_dc.clone());
    // P3 — bounded reopen backoff for the capture-error arm (500 ms → 10 s
    // on consecutive failures; quiet spell resets). See `ReopenBackoff`.
    let mut reopen_backoff = capture::ReopenBackoff::new();
    // FR-70 M1b — the same handle the FFmpeg pump got in M1a: inline
    // (today's plain call on the worker, verbatim) or on its own thread.
    let media_thread = crate::encode::media_thread_enabled();
    let mut encoder: Option<crate::encode::thread::EncoderHandle<Vp9Encoder>> = None;
    let mut encoder_dims: Option<(u32, u32)> = None;
    let mut last_capture_at = std::time::Instant::now();
    let mut last_good_frame: Option<std::sync::Arc<crate::capture::Frame>> = None;
    // FR-93 P3e — a capture waiting on its host (a display switched off).
    let mut capture_wait = CaptureWait::default();
    // rc.187 stale-frame fix, burst-gated 2026-07-27 (see
    // rate_profile::SettleKeyframeGate): the first idle keepalive after a
    // MOTION BURST settles forces a keyframe so a viewer that dropped frames
    // mid-motion resyncs. Isolated blips no longer qualify — a blinking text
    // caret (~530 ms toggle) counted as "motion" and forced a ~2 Hz IDR
    // metronome (field DEVBOX→WINHOST-B 2026-07-27: text pulsing blur→crystal
    // every half second on all codecs).
    let mut settle_kf = crate::encode::rate_profile::SettleKeyframeGate::from_env();
    // rc.130 — 60 ms (was 1 s), matching the FFmpeg pump. libvpx is synchronous
    // (g_lag_in_frames=0) so there's no encoder-output queue to drain here, but
    // the faster keepalive still feeds the browser decoder more tightly and
    // pushes the last idle frame through the (now bounded, see the send task
    // below) DC path promptly. Fires only on capture-None.
    const IDLE_KEEPALIVE: Duration = Duration::from_millis(60);

    // rc.166 freeze fix — relay-aware bitrate clamp + tighter backpressure.
    // The WSL / corp path forces all media over a single TURN-TCP relay
    // (ROOMLERD_ICE_RELAY_TCP=1), which carries only ~1-4 Mbps and is
    // head-of-line-blocked. The 0.20-bpp VP9-444 target (~12 Mbps at
    // 2560×1600) collapses it. Clamp the encoder to relay_max_bps (3 Mbps
    // default) and, per Change D, trip AIMD at a shallower 256 KiB buffered
    // watermark so we shed BEFORE the relay's tiny pipe backs up seconds deep.
    // Adaptive bitrate (A1) — detect THIS session's actual ICE path rather
    // than reading the process-wide env flag. The env flag still wins as an
    // explicit override (see `detect_constrained_transport`).
    let mut constrained_transport = detect_constrained_transport(&pc, session_id).await;
    // FR-74 P3 — the worst quality libvpx may pick on a DIRECT transport
    // (`rc_max_quantizer`; relay keeps the uncapped 63). Resolved once: the
    // env is process-stable. See `Vp9Encoder::set_max_quantizer` for why a
    // cap and not a rate mode.
    let vp9_direct_max_q = crate::encode::libvpx::vp9_direct_max_q_from_env();
    let mut bitrate_cap: u32 = if constrained_transport {
        crate::encode::relay_max_bps()
    } else {
        u32::MAX
    };
    // Change D: trigger AIMD earlier on the shallow relay-TCP pipe.
    let mut dc_buffered_high: u64 = if constrained_transport {
        256 * 1024
    } else {
        DC_BUFFERED_HIGH_BYTES
    };
    if constrained_transport {
        info!(%session_id, bitrate_cap, dc_buffered_high, "VP9-444 DC pump: constrained (relay-TCP) transport — clamping bitrate + tightening backpressure");
    }
    // Relay-escape — re-check the selected pair periodically (see the loop).
    let mut last_transport_check = std::time::Instant::now();
    // Badge-truth — `rc:video-info` state (retry-until-delivered, mirroring
    // the FFmpeg pump). `chroma_wire` tracks the ACTUAL chroma the encoder
    // was built with (session pref / env / default), set at each rebuild.
    let mut video_info_sent = false;
    let mut last_video_info_attempt: Option<std::time::Instant> = None;
    let mut chroma_wire: &'static str = "yuv444";
    // P5 — shared-floor pipeline (twin of the FFmpeg pump's registration).
    // The hard key includes chroma: 444 vs 420 are different VP9 profiles,
    // so their viewers can't share a stream.
    let pipeline = crate::media_share::Pipeline::register(
        crate::media_share::PipelineKey::Vp9Dc {
            chroma_444: vp9_chroma_is_444(chroma_pref.as_deref()),
        },
        session_id,
    );
    let mut last_viewers: usize = 0;

    let mut frames_captured: u64 = 0;
    let mut frames_encoded: u64 = 0;
    // rc.166 freeze fix — these three are now owned by a dedicated DC send
    // task (spawned below, mirroring the FFmpeg pump rc.106 pattern) and
    // shared back as atomics so the heartbeat can still read them. Moving the
    // chunked `dc.send().await` off the pump's hot path stops a big
    // (IDR / high-motion) frame from stalling capture+encode on the send —
    // the 27s screen+input freeze the WSL relay-TCP path hit under motion.
    let frames_sent = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let bytes_written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let send_errors = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut dc_unopen_drops: u64 = 0;
    let mut frames_skipped_backpressure: u64 = 0;
    let mut scene_change_keyframes: u64 = 0;
    // FR-10 — settle-IDRs suppressed by relay IDR thrift (heartbeat truth).
    let relay_idr_thrift = crate::encode::relay_idr_thrift_enabled();
    let mut settle_kf_suppressed: u64 = 0;
    // rc.190 — one-shot (per value) log marker for the agent-side resolution
    // caps, so the field log explains WHY the stream is smaller than asked.
    // FR-70 P1 — the last resolution plan (user target, effective target,
    // reason). Any change re-sends `rc:video-info` so the viewer's badge can
    // name the cap in force; a change while the two targets differ is also
    // logged (the rc.190 "cap engaged" line, now keyed on the reason too).
    let mut last_dims_plan: Option<(
        TargetResolution,
        TargetResolution,
        crate::encode::policy::RungReason,
    )> = None;
    // P7 — downscale-stage timing (this pump has no per-stage accumulators
    // like the ffmpeg pump's rc.88 trio, so track ops explicitly). Phase A —
    // scale_ops counts REAL resamples only.
    let mut scale_us: u64 = 0;
    let mut scale_ops: u64 = 0;
    // FR-112 P1 — the encode's own cost per window, as the RTP pump reports it:
    // without it a frame rate held by the encoder is indistinguishable from one
    // held by the capture or the link.
    let mut encode_us: u64 = 0;
    let mut encode_ops: u64 = 0;
    // Phase A — pump-local resampler (cached taps + pooled intermediate).
    let mut resampler = crate::encode::resample::Resampler::new();
    // Phase B — the backend cap last handed to the capturer (change-gated).
    let mut last_output_cap: Option<(u32, u32)> = None;
    // P8 Phase 5 — per-window QP telemetry (record-only; libvpx qindex
    // scale). See the ffmpeg pump's twin.
    let mut qp_sum: u64 = 0;
    let mut qp_max: i32 = 0;
    let mut qp_n: u64 = 0;
    // P8b stage 2 — the keyframe-force policy machine (backstop retry +
    // force-ignored rebuild fallback, mirrored from the ffmpeg pump for
    // parity: libvpx force flags are synchronous, so the fallback should
    // never fire here — the mirror just guarantees NO pump can wedge on
    // an unanswered force). This pump's lock handling stays its own
    // (overlay-frame substitution via the `keyframe_requested` atomic),
    // so the gate's lock edge is unused here.
    let mut kf_gate = crate::encode::kf_policy::KeyframeGate::new(false);

    // rc.39 — agent-side scene-change keyframe trigger. Heuristic:
    // after each encode, if the latest delta packet's size exceeds
    // SCENE_CHANGE_SPIKE_RATIO× the recent average AND >=
    // SCENE_CHANGE_MIN_BYTES, we assume a scene-change happened.
    // Force a keyframe on the NEXT frame so the operator sees a clean
    // refresh within 2 frames instead of waiting for the periodic IDR.
    //
    // rc.43 — RETUNED for VBR-mode regression. Field log the field-test host
    // 2026-05-18 (rc.42 + VBR opt-in) showed 33 forced keyframes in
    // 3.5 minutes — one every 6 seconds — because VBR's natural delta
    // size variance (3-10× depending on motion) was tripping the
    // rc.39 ratio=4 + 50 KB thresholds far too often. Each forced
    // keyframe was 200-900 KB; those big keyframe SCTP chunks shared
    // the same DC transport as the cursor DC and stalled cursor:pos
    // updates for 100-200 ms each, producing visibly sluggish mouse.
    // Three tweaks:
    //
    //   (1) rate-limit: at most one forced keyframe per
    //       SCENE_CHANGE_MIN_INTERVAL (1.5 s). Prevents the keyframe
    //       cascade where each forced keyframe inflates the bitrate
    //       envelope and re-triggers the heuristic on the next frame.
    //
    //   (2) MIN_BYTES 50 KB → 150 KB. VBR motion deltas routinely
    //       hit 100 KB even without an actual scene change; require
    //       a stronger signal to act.
    //
    //   (3) SPIKE_RATIO 4× → 8×. Natural VBR variance is ~5×; need
    //       a steeper spike to count.
    //
    // Combined: scene-change still fires reliably on window-uncover
    // (typical ratio >> 8 + size >> 150 KB) but stops mis-firing on
    // pure motion frames.
    //
    // Ring buffer of recent delta-frame sizes (skip the keyframes
    // themselves, which are naturally large).
    let mut recent_delta_sizes: std::collections::VecDeque<usize> =
        std::collections::VecDeque::with_capacity(30);
    const SCENE_CHANGE_SPIKE_RATIO: usize = 8;
    const SCENE_CHANGE_MIN_BYTES: usize = 150_000;
    const SCENE_CHANGE_MIN_INTERVAL: Duration = Duration::from_millis(1500);
    let mut last_scene_change_kf_at: Option<std::time::Instant> = None;
    // rc.234 — the forced scene-change IDR is OFF by default: with periodic
    // IDRs gone (VPX_KF_DISABLED + the request-gated retry) it was the last
    // remaining routine IDR source, and each forced IDR under the rate cap
    // repainted the "blur pulse on every scroll / window switch" the whole
    // rc.234 round exists to kill. The encoder codes an uncovered region as
    // intra blocks within the same budget anyway. The DETECTOR stays live —
    // the rc.45 cpu-used motion boost rides it. `ROOMLERD_SCENE_KF=1`
    // restores the rc.39/43 forcing.
    let scene_kf_enabled = node_env("SCENE_KF").as_deref() == Some("1");

    // rc.45 — dynamic cpu-used boost during motion. the field-test host field
    // test 2026-05-18 (rc.43) confirmed scene-change keyframe cascade
    // is fixed (5× reduction in forced IDRs) but heavy-motion fps is
    // still 8-12 because SW VP9 4:4:4 at 1920×1200 + cpu-used=6 on
    // Iris Xe takes 80-120 ms per motion frame. cpu-used=8 cuts that
    // ~50 %, recovering 15-25 fps during motion. Quality drop is
    // ~20 % per-frame; barely visible during motion-blur anyway.
    //
    // Heuristic: piggyback on the existing scene-change detector. When
    // a scene-change spike fires, BOOST cpu-used from base (env or
    // default 6) to 8 for the next BOOST_DURATION frames. After the
    // boost expires, drop back to base. Sustained-motion windows
    // re-trigger the boost as long as motion continues; static
    // periods restore quality automatically.
    let base_cpu_used = crate::encode::libvpx::cpu_used_from_env();
    const MOTION_BOOST_CPU_USED: std::os::raw::c_int = 8;
    const MOTION_BOOST_DURATION_FRAMES: u64 = 60;
    let mut motion_boost_until_frame: u64 = 0;
    let mut current_cpu_used: std::os::raw::c_int = base_cpu_used;

    // rc.33 — bitrate / quality state. Pre-rc.33 the encoder ran at
    // its `DEFAULT_BITRATE_BPS = 8 Mbps` ceiling regardless of source
    // resolution; at 4K this is ~1/3 of what RustDesk sends and is the
    // dominant cause of blocky motion frames. We now drive
    // `enc.set_bitrate(target)` after each encoder rebuild AND on
    // `rc:quality` change AND on AIMD watermark crossings.
    //
    // Sentinel 0xFF on `last_applied_quality` so the first iteration
    // unconditionally applies the current preference even when the
    // controller hasn't yet pushed `rc:quality`.
    let mut last_applied_quality: u8 = 0xFF;
    // High watermark for the SECONDARY buffer-overflow decrease trigger
    // (`dc_buffered_high` above resolves it to 256 KiB on a constrained relay,
    // this 1 MiB const otherwise).
    const DC_BUFFERED_HIGH_BYTES: u64 = 1_048_576; // 1 MiB

    // rc.166 freeze fix — dedicated DC send task, ported from the FFmpeg pump
    // (rc.106). The chunked `dc.send().await` is SCTP-flow-controlled; on a
    // multi-MB frame over the relay-TCP path it blocks for tens of ms → whole
    // seconds under the 27s freeze. Doing it inline (pre-rc.166) stalled
    // capture + input. Hand framed frames to this task over a small bounded
    // channel; the pump never blocks on the link (see the `try_send` in the
    // loop). A SINGLE consumer keeps the 16 KiB chunk order intact (the browser
    // reassembler needs it). Depth is intentionally shallow so we stay
    // low-latency — under sustained congestion the pump sheds load rather than
    // building a stale backlog.
    const VP9_SEND_QUEUE_DEPTH: usize = 2; // shallower than FFmpeg's 4 — VP9-444 frames are large; minimise input head-of-line delay
    let send_depth = if constrained_transport {
        VP9_SEND_QUEUE_DEPTH
    } else {
        // Direct/LAN path (localhost under WSL mirrored networking): plenty of
        // bandwidth + sub-ms latency, so a deeper queue absorbs high-motion
        // frame bursts instead of shedding them (the "movement stutter").
        // Input rides a SEPARATE DC, so a deeper video queue adds no input lag.
        8
    };
    let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(send_depth);
    // P8c — the rate governor owns this pump's AIMD (rc.171 — driven off
    // SEND-CHANNEL OCCUPANCY at the capacity gate, the real webrtc-rs
    // backpressure signal; `dc.buffered_amount()` stays low under SCTP flow
    // control even while saturated) and the rc.188 viewer-rate fps cap.
    // The encode-pressure/tier halves sit unused here (libvpx has its own
    // cpu_used/quality levers). See `encode::governor` module docs — incl.
    // the preserved rebuild divergence (`on_encoder_rebuilt_mirror_only`).
    let mut governor = crate::encode::governor::RateGovernor::new(
        target_fps,
        send_depth,
        crate::encode::governor::GovernorFlags::from_env(),
        // FR-35 — the ceiling learner is field-verified on the FFmpeg pump
        // only; this pump keeps today's fixed ceiling in P1.
        0,
        None,
        std::time::Instant::now(),
    );
    {
        let video_bytes_dc = video_bytes_dc.clone();
        let frames_sent = frames_sent.clone();
        let bytes_written = bytes_written.clone();
        let send_errors = send_errors.clone();
        let task_session = session_id;
        let goodput_sink = governor.goodput_sink();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            const SCTP_CHUNK_SIZE: usize = 16 * 1024;
            // FR-17 — see the ffmpeg pump: the sequence lives in the send
            // task because that is what puts messages on the wire.
            let mut frame_seq: u32 = 0;
            // Measured-rate v2 — time each frame's chunked serialisation;
            // the sink keeps only genuinely blocked sends (≥10 ms of SCTP
            // flow control), so buffer headroom never biases the estimate
            // (`encode::goodput`).
            while let Some(first) = send_rx.recv().await {
                let mut next = Some(first);
                while let Some(wire) = next.take() {
                    if let Some(dc) = video_bytes_dc.lock().await.clone() {
                        let total = wire.len();
                        let ser_start = std::time::Instant::now();
                        let mut off = 0usize;
                        let mut ok = true;
                        let chunk_count = total.div_ceil(SCTP_CHUNK_SIZE).max(1) as u16;
                        let mut chunk_idx: u16 = 0;
                        frame_seq = frame_seq.wrapping_add(1);
                        while off < total {
                            let end = (off + SCTP_CHUNK_SIZE).min(total);
                            let res = if chunk_framing {
                                let framed = chunk_framed(
                                    frame_seq,
                                    chunk_idx,
                                    chunk_count,
                                    &wire.slice(off..end),
                                );
                                dc.send(&bytes::Bytes::from(framed)).await
                            } else {
                                dc.send(&wire.slice(off..end)).await
                            };
                            chunk_idx = chunk_idx.saturating_add(1);
                            if let Err(e) = res {
                                let n = send_errors.fetch_add(1, Relaxed) + 1;
                                tracing::warn!(session = %task_session, %e, send_errors = n, "VP9-444 DC send task: DC send failed");
                                ok = false;
                                break;
                            }
                            off = end;
                        }
                        if ok {
                            frames_sent.fetch_add(1, Relaxed);
                            bytes_written.fetch_add(total as u64, Relaxed);
                            goodput_sink.record(total as u64, ser_start.elapsed());
                        }
                    }
                    next = send_rx.try_recv().ok();
                }
            }
            tracing::debug!(session = %task_session, "VP9-444 DC send task exiting (channel closed)");
        });
    }

    loop {
        // rc.443 — owner-liveness beat, FIRST statement of the loop: a
        // joiner finding this stale evicts the pipeline (a wedged encode
        // can block this task forever with no way to drop the Pipeline).
        pipeline.beat();
        // Relay-escape — every TRANSPORT_RECHECK_INTERVAL re-read the
        // selected ICE pair: Chrome renominates mid-session (relay→direct
        // once the mDNS-resolved host pair succeeds; direct→relay on a path
        // failure) and the bitrate clamp should follow LIVE instead of
        // staying pinned to the pump-start guess. The env override still
        // pins constrained (the ICE policy itself is forced to relay —
        // nothing to re-detect). The send-queue depth + buffered watermark
        // stay as chosen at start (the channel size is fixed at
        // construction); the ceiling is the lever that matters.
        if last_transport_check.elapsed() >= TRANSPORT_RECHECK_INTERVAL {
            last_transport_check = std::time::Instant::now();
            if !crate::encode::transport_is_constrained() {
                let relay_now = current_pair_is_relay(&pc, session_id, constrained_transport).await;
                if let Some(relay) = relay_now
                    && relay != constrained_transport
                {
                    constrained_transport = relay;
                    bitrate_cap = if relay {
                        crate::encode::relay_max_bps()
                    } else {
                        u32::MAX
                    };
                    dc_buffered_high = if relay {
                        256 * 1024
                    } else {
                        DC_BUFFERED_HIGH_BYTES
                    };
                    // FR-74 P3 — the worst-quality cap follows the transport:
                    // uncapped on a relay (the rate cap rules there), capped
                    // on a direct path.
                    if let Some(h) = encoder.as_mut() {
                        let q = if relay {
                            crate::encode::libvpx::VP9_MAX_Q_UNCAPPED
                        } else {
                            vp9_direct_max_q
                        };
                        h.with(move |e| e.set_max_quantizer(q)).await;
                        info!(
                            %session_id,
                            relay,
                            max_q = q,
                            "FR-74 P3: VP9-444 worst-quality cap re-applied after a transport flip"
                        );
                    }
                    // Badge-truth: refresh the browser badge with the new
                    // transport via the retry block below.
                    video_info_sent = false;
                }
            }
        }

        // Badge-truth — deliver `rc:video-info` reliably (twin of the FFmpeg
        // pump's block): libvpx sessions never sent it at all, so the badge
        // fell back to a transport-less selection-derived label. Attempted
        // whenever undelivered (encoder built + 500 ms since last try);
        // rebuilds and transport flips clear `video_info_sent`.
        // P5 — a viewer joining/leaving the shared pipeline refreshes the
        // badge (its "viewers" count changed for everyone).
        let viewers = 1 + pipeline.follower_count();
        if viewers != last_viewers {
            last_viewers = viewers;
            video_info_sent = false;
        }

        if !video_info_sent
            && last_video_info_attempt.is_none_or(|t| t.elapsed() >= VIDEO_INFO_RETRY)
            && encoder.is_some()
        {
            last_video_info_attempt = Some(std::time::Instant::now());
            // rc.199 — stamp the native capture dims so the browser can label
            // a capped stream. The store lands LATER in this loop body than
            // this block, so the first pass may still read 0; hold the badge
            // (don't set `video_info_sent`) until they're known — one 500 ms
            // retry closes the gap and the first delivered info carries dims.
            let (native_w, native_h) =
                unpack_dims(capture_native_dims.load(std::sync::atomic::Ordering::Relaxed));
            if native_w > 0 {
                // FR-33 P3 — name the LAN capture when it is the reason THIS
                // viewer is relayed (per-prefix, like the P2 gate).
                let reason = lan_capture_reason(&pc, constrained_transport).await;
                // FR-70 P1 — the cap in force and why (see the FFmpeg twin).
                let cap_reason = last_dims_plan
                    .filter(|(user, effective, _)| effective != user)
                    .map(|(_, _, r)| r.as_str());
                let payload = video_info_payload(
                    "vp9",
                    "libvpx",
                    false,
                    chroma_wire,
                    constrained_transport,
                    native_w,
                    native_h,
                    viewers,
                    reason,
                    cap_reason,
                    None,
                    capturer.arm(),
                    None,
                );
                let cdc = control_dc.lock().await.clone();
                if let Some(cdc) = cdc
                    && cdc.send_text(payload.clone()).await.is_ok()
                {
                    video_info_sent = true;
                    // P5 — mirror to the followers' badges.
                    pipeline.publish_video_info(payload);
                }
            }
        }

        // rc.166 freeze fix — BACKPRESSURE GATE (ported from FFmpeg pump
        // rc.111). Gate frame PRODUCTION on the send channel having capacity.
        // When the send task can't drain the relay-TCP link fast enough the
        // bounded channel fills; skip BEFORE capture+encode so we don't waste a
        // VP9 encode on a frame we can't send AND — unlike the AIMD-skip below
        // — we do NOT request a keyframe here: skipping before encode leaves the
        // encoder's reference chain intact (the next encoded frame just deltas
        // from the last ENCODED one across the gap), same rationale as the
        // FFmpeg rc.111 comment. Check is_closed() FIRST so a dead send task
        // exits the pump instead of livelocking on a permanently-0 capacity.
        if send_tx.is_closed() {
            warn!(%session_id, "VP9-444 DC pump: send task gone — exiting pump");
            return;
        }
        if send_tx.capacity() == 0 || pipeline.followers_congested() {
            frames_skipped_backpressure += 1;
            // Adaptive bitrate (rc.171) — a FULL send channel is the real DC
            // backpressure signal. Drive the multiplicative decrease HERE,
            // before the `continue`, so it runs DURING sustained congestion
            // (pre-rc.171 the loop bailed at this gate and the AIMD below
            // never ran → bitrate pinned at 12.4 Mbps, the ~2 fps starvation
            // bug). Apply to the existing encoder immediately so the next
            // frame that DOES get through is already smaller.
            // P5 — a congested follower gates production identically (the
            // shared stream paces to the slowest link; see media_share).
            if let Some(applied) = governor.on_backpressure_skip(std::time::Instant::now())
                && let Some(enc) = encoder.as_mut()
            {
                enc.set_bitrate(applied.bps).await;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
            continue;
        }

        // FR-112 P2 — cadence pacing, as the FFmpeg pump's (FR-1 P5): when the
        // software encoder cannot hold the target, take frames on an even grid
        // at the rate it sustains instead of a ragged mix of 16 and 33 ms gaps.
        // Slots run from consumption, so an encode longer than the interval
        // degrades to the natural cadence, never a burst. Never below 30, the
        // pace 0.4.141 ran at (`paced_software_fps`).
        if let Some(paced) = governor.paced_software_fps() {
            let interval = Duration::from_micros(1_000_000 / paced.max(1) as u64);
            let now = std::time::Instant::now();
            if let Some(due) = pace_due
                && due > now
            {
                tokio::time::sleep(due - now).await;
            }
            pace_due = Some(std::time::Instant::now() + interval);
        } else {
            pace_due = None;
        }

        // A local first, so `capturer`'s borrow ends before the idle arm asks
        // it what it waits for (FR-93 P3e).
        let next_frame = capturer.next_frame().await;
        let frame: std::sync::Arc<crate::capture::Frame> = match next_frame {
            Ok(Some(f)) => {
                frames_captured += 1;
                last_capture_at = std::time::Instant::now();
                capture_wait.on_frame();
                let arc = std::sync::Arc::new(f);
                last_good_frame = Some(arc.clone());
                // FR-101 P4b-2 — a real capture, never a keepalive: the idle limit's
                // screen leg (free unless a live session has a limit).
                crate::session_idle::note_frame(&arc);
                // Motion continues — the settle gate counts the episode.
                settle_kf.note_real_frame();
                arc
            }
            Ok(None) => {
                // FR-93 P3e — the display is off (P5f: this user's session is
                // in the background): the controller is told, and no keepalive
                // re-encodes the last frame (a decoded frame would clear the
                // viewer's notice).
                if capture_wait.hold(capturer.waits_for(), session_id, &control_dc) {
                    // P5f — and the pump stays abortable. Mutter's frame wait
                    // blocks in place and never yields, so without this the
                    // loop never reached an await that yields: a viewer that
                    // left during the wait left its pump running, holding
                    // the screencast (GNOME's sharing indicator up) and the
                    // shared pipeline, which took each new viewer on as a
                    // follower of a pump that sent nothing.
                    tokio::task::yield_now().await;
                    continue;
                }
                if last_capture_at.elapsed() >= IDLE_KEEPALIVE {
                    if let Some(ref f) = last_good_frame {
                        last_capture_at = std::time::Instant::now();
                        // rc.187 (burst-gated) — first keepalive after a real
                        // motion burst settles = keyframe, so a viewer that
                        // dropped frames mid-motion resyncs to the settled
                        // state instead of freezing on the old position.
                        // FR-10 — suppressed on thrifty constrained sessions
                        // (quality refresh, not correctness; the lump costs
                        // more than the crispness buys on a thin relay).
                        if let Some(burst) =
                            settle_kf.should_fire_on_settle(std::time::Instant::now())
                        {
                            if constrained_transport && relay_idr_thrift {
                                settle_kf_suppressed += 1;
                            } else {
                                keyframe_requested
                                    .store(true, std::sync::atomic::Ordering::Relaxed);
                                crate::session_telemetry::counters(session_id).note_keyframe();
                                tracing::info!(
                                    %session_id,
                                    burst,
                                    "idle-settle keyframe (motion burst ended)"
                                );
                            }
                        }
                        f.clone()
                    } else {
                        tokio::time::sleep(frame_duration_floor).await;
                        continue;
                    }
                } else {
                    tokio::time::sleep(frame_duration_floor / 2).await;
                    continue;
                }
            }
            Err(e) => {
                // FR-93 P6c — the track pump's rule: stopped at the screen
                // ends the session (this pipeline's followers first).
                if capture::stopped_at_screen(&e) {
                    match end_stopped_at_screen(session_id, &rc_sessions, Some(&pipeline)).await {}
                }
                // P3 — bounded backoff, same rationale as the track pump.
                warn!(%session_id, %e, "VP9-444 capture error — rebuilding capturer");
                tokio::time::sleep(reopen_backoff.delay()).await;
                capturer = capture::open_default_async(
                    target_fps,
                    downscale,
                    media_waiting_hook(session_id, control_dc.clone()),
                )
                .await;
                encoder = None;
                encoder_dims = None;
                continue;
            }
        };

        // Apply controller-chosen resolution + the libvpx even-dim
        // requirement. The encoder rejects odd dims — round down by 1
        // to cover the rare case where the resolution control message
        // landed an odd value.
        // Publish the native (pre-downscale) dims so the cursor pump can
        // map the OS cursor into the encoded frame's pixel space (rc.183).
        // `frame` here is still native — apply_target_resolution is what
        // downscales it. On HW paths (DownscalePolicy::Never) this is the
        // true monitor resolution; that's every host that hits the DC
        // video pumps in the field.
        let (cap_native_w, cap_native_h) = frame.native_dims();
        let native_dims_packed = pack_dims(cap_native_w, cap_native_h);
        capture_native_dims.store(native_dims_packed, std::sync::atomic::Ordering::Relaxed);
        // rc.190 — compose the controller's request with the agent-side caps:
        // B2 soft cap (libvpx is ALWAYS software — a 4K panel crawled at
        // ~25 fps burning the host CPU, field WINHOST-H 2026-07-16) fills in
        // when the controller left Native; B1 hard cap clamps everything on
        // a constrained relay (a ~3 Mbps TURN-TCP path can't carry more).
        // P5 — resolution + Priority floor-merge across the shared
        // pipeline's viewers (most conservative wins while shared).
        let user_target = pipeline.merged_target(*target_resolution.lock().unwrap());
        // P8b — same `plan_dims` composition as the FFmpeg pump; this SW
        // pump's divergences are visible as INPUTS (no idle refine, SW CPU
        // cap in the soft slot) instead of a parallel code path. rc.199
        // semantics preserved: Priority-resolved relay hard cap + the
        // always-applied SW soft cap.
        let dims_plan = crate::encode::policy::plan_dims(&crate::encode::policy::DimsInputs {
            native_w: cap_native_w,
            native_h: cap_native_h,
            merged_target: user_target,
            merged_priority_cap: pipeline.merged_priority_cap(
                crate::encode::priority_relay_cap(
                    priority.load(std::sync::atomic::Ordering::Relaxed),
                    constrained_transport,
                ),
                constrained_transport,
            ),
            // The VP9-444 pump has no slow-link profile (FR-59 P5 is the
            // FFmpeg pump's); nothing to attribute here.
            slow_link_cap: None,
            refined: false,
            refined_cap: None,
            soft_cap: crate::encode::sw_res_cap_long_edge(),
        });
        let effective_target = dims_plan.effective_target;
        // Phase B — hand the effective box to the capture backend so a
        // GPU-capable one can scale BEFORE the readback (applies from the
        // next frame; the CPU resample below stays the fallback + truth).
        let backend_cap = match effective_target {
            TargetResolution::Native => None,
            TargetResolution::Fixed { width, height } => Some((width, height)),
        };
        if backend_cap != last_output_cap {
            last_output_cap = backend_cap;
            capturer.set_output_cap(backend_cap);
        }
        let plan_key = (user_target, effective_target, dims_plan.reason);
        if last_dims_plan != Some(plan_key) {
            if effective_target != user_target {
                info!(
                    %session_id,
                    ?user_target,
                    ?effective_target,
                    reason = dims_plan.reason.as_str(),
                    native_w = cap_native_w,
                    native_h = cap_native_h,
                    constrained = constrained_transport,
                    "VP9-444 DC pump: agent-side resolution cap engaged (relay/SW-encode)"
                );
            }
            last_dims_plan = Some(plan_key);
            // FR-70 P1 — the badge carries the cap and its reason; refresh it.
            video_info_sent = false;
        }
        let scale_start = std::time::Instant::now();
        let pre_scale_dims = (frame.width, frame.height);
        let frame = crate::encode::resample::apply_target_resolution(
            &mut resampler,
            frame,
            effective_target,
        );
        scale_us += scale_start.elapsed().as_micros() as u64;
        // Phase A metric fix — count only REAL resamples (a passthrough
        // costs ~0 and used to dilute avg_scale_ms below the true
        // per-downscale cost the field reads).
        if (frame.width, frame.height) != pre_scale_dims {
            scale_ops += 1;
        }
        // rc.190 — publish the ACTUAL encoded dims for the cursor pump's
        // native→encoded scaling (the caps can pick a smaller target than
        // the controller asked for, so TargetResolution alone is stale).
        let encoded_dims_packed = pack_dims(frame.width, frame.height);
        encoded_dims.store(encoded_dims_packed, std::sync::atomic::Ordering::Relaxed);

        // Lock-screen overlay (M3 phase 3, Z-path). Same logic as
        // the legacy track pump — when the user-context worker
        // can't see the real desktop (input desktop on Winlogon),
        // substitute a static "Host is locked" overlay frame.
        // rc.26 — short-circuit when sys_ctx_worker; see media_pump.
        let frame = if *lock_state_rx.borrow() == lock_state::LockState::Locked {
            if !was_locked_last_iter {
                keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
                crate::session_telemetry::counters(session_id).note_keyframe();
                was_locked_last_iter = true;
            }
            if sys_ctx_worker {
                frame
            } else {
                lock_overlay::produce(frame.width, frame.height, frame.monotonic_us, frame.monitor)
            }
        } else {
            if was_locked_last_iter {
                keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
                crate::session_telemetry::counters(session_id).note_keyframe();
                was_locked_last_iter = false;
            }
            frame
        };

        let w = frame.width & !1;
        let h = frame.height & !1;
        if w != frame.width || h != frame.height {
            // Drop this frame; the next one will arrive at-or-near the
            // same dims and we'll handle the rebuild then. Safer than
            // shrinking the buffer in-place and risking off-by-one.
            continue;
        }

        if encoder_dims != Some((w, h)) {
            // rc.61 — resolve chroma format. Priority order:
            //   1. Per-session `chroma_pref` from `rc:session.request`
            //      (rc.62 — controller's UI choice).
            //   2. `ROOMLERD_VP9_CHROMA` env var (rc.61, operator
            //      default at the host).
            //   3. Yuv444 (pre-rc.61 default, sharpest text).
            // Read at every rebuild so a mid-session env-var flip
            // (operator changes it via the SCM service env block +
            // restart) takes effect on the next dim change without
            // needing a separate hook.
            let chroma = chroma_pref
                .as_deref()
                .and_then(|s| match s.trim().to_ascii_lowercase().as_str() {
                    "yuv420" | "420" => Some(crate::encode::libvpx::Vp9Chroma::Yuv420),
                    "yuv444" | "444" => Some(crate::encode::libvpx::Vp9Chroma::Yuv444),
                    _ => None,
                })
                .unwrap_or_else(crate::encode::libvpx::vp9_chroma_from_env);
            info!(%session_id, w, h, target_fps, chroma = chroma.as_str(), chroma_source = if chroma_pref.is_some() { "session_request" } else { "env_var" }, "VP9-444 encoder rebuild for dims");
            match Vp9Encoder::new_with_fps_chroma(w, h, target_fps, chroma) {
                Ok(e) => {
                    let handle = crate::encode::thread::EncoderHandle::new(
                        e,
                        media_thread,
                        &session_id.to_hex()[18..],
                    );
                    if media_thread {
                        info!(
                            %session_id,
                            threaded = handle.is_threaded(),
                            "FR-70 M1: encoder handed to its own thread"
                        );
                    }
                    encoder = Some(handle);
                    encoder_dims = Some((w, h));
                    // Badge-truth — record the ACTUAL chroma for the
                    // `rc:video-info` retry block and (re)announce it.
                    chroma_wire = chroma.as_str();
                    video_info_sent = false;
                    // rc.33 — force quality re-apply on the new
                    // encoder. set_bitrate state lives on the
                    // encoder instance, so a rebuild reverts to the
                    // boot-time default bitrate until we push the
                    // resolution-derived quality target through.
                    last_applied_quality = 0xFF;
                    governor.on_encoder_rebuilt_mirror_only();
                    // rc.45 — encoder rebuild starts at base cpu-used
                    // (apply_screen_content_controls reads the env
                    // var). Reset our tracking so the next motion
                    // boost properly logs the from-value.
                    current_cpu_used = base_cpu_used;
                    motion_boost_until_frame = 0;
                    // FR-74 P3 — on a direct transport, cap the worst quality
                    // libvpx may pick: its one-pass CBR resets q to 255 on
                    // every wheel notch of a text scroll and walks it down
                    // ~7 per frame, so a choppy scroll was rendered at the
                    // worst quality while spending a fifth of its target.
                    // The cap holds the notch frames at a readable quality;
                    // everything else (refine to lossless, the target as an
                    // average bound) stays. Relay keeps libvpx's 63.
                    if !constrained_transport && let Some(h) = encoder.as_mut() {
                        let q = vp9_direct_max_q;
                        h.with(move |e| e.set_max_quantizer(q)).await;
                        info!(
                            %session_id,
                            max_q = q,
                            "FR-74 P3: VP9-444 worst quality capped on the direct path"
                        );
                    }
                }
                Err(e) => {
                    warn!(%session_id, %e, "Vp9Encoder::new failed — pump exits");
                    return;
                }
            }
        }
        // Force-ignored fallback parity — checked BEFORE the `enc` borrow so
        // the rebuild can drop the encoder (see `kf_policy`; the ffmpeg
        // pump's block is the field-proven original). `continue` lets the
        // next iteration's dims-mismatch check reconstruct; the fresh
        // encoder's first frame is a guaranteed key-flagged IDR. The gate
        // owns the rc.217 cooldown (a cooling-down force is abandoned).
        if let crate::encode::kf_policy::RebuildVerdict::Rebuild { pending_ms } =
            kf_gate.rebuild_fallback(std::time::Instant::now())
        {
            warn!(
                %session_id,
                pending_ms,
                "VP9-444 DC pump: encoder ignored forced keyframe — rebuilding to emit a guaranteed IDR"
            );
            encoder = None;
            encoder_dims = None;
            continue;
        }
        let enc = encoder.as_mut().unwrap();
        let mut force_keyframe_this_iter = false;
        // P5 — any viewer of the shared stream can ask (own atomic, a
        // follower's atomic, or the pipeline's join/resync flag).
        let own_kf = keyframe_requested.swap(false, std::sync::atomic::Ordering::Relaxed);
        let shared_kf = pipeline.take_keyframe_requested();
        if own_kf || shared_kf {
            enc.request_keyframe().await;
            force_keyframe_this_iter = true;
        }
        // Unanswered-force retry — see `kf_policy::KEYFRAME_BACKSTOP`
        // (rc.234: due ONLY while a force is armed, never a metronome).
        if kf_gate.backstop_due(std::time::Instant::now()) {
            enc.request_keyframe().await;
            force_keyframe_this_iter = true;
            if kf_gate.take_backstop_log() {
                info!(
                    %session_id,
                    "VP9-444 DC pump: keyframe force retry engaged (unanswered for 4s)"
                );
            }
        }
        // Arm on the first unanswered force (origin kept); the send loop
        // stands the gate down when a key-flagged frame actually goes out.
        kf_gate.arm_if_forced(force_keyframe_this_iter, std::time::Instant::now());

        // rc.188 — viewer-rate fps cap (mirror of the media_pump_ffmpeg_dc
        // block). Once a second, fold the browser's measured decode report
        // (`rc:decodestat`: decoded fps + a struggling bit) into a send-fps cap
        // and derive the frame-skip divisor; then drop (divisor-1) of every
        // `divisor` delta frames so the agent stops sending faster than the
        // viewer can decode. Keyframes are never skipped. P5 (in the fold
        // closure) — floor: fold every follower's decode report in, take
        // the max divisor, and step the spill gate (see media_share).
        if let Some(vw) = governor.tick_viewer_window(
            std::time::Instant::now(),
            target_fps,
            || viewer_report.take_report(),
            // FR-15 — the viewer's paint age; acted on only when the
            // transport is constrained (direct has its own measured
            // ceiling + byte gate), learned always so the heartbeat can
            // report it on every transport.
            || viewer_report.take_age(),
            // FR-59 P3 — the viewer's link report (arrival rate + how much
            // its transit queue grew). Needs no clock probe, so it speaks
            // in the windows the age above cannot.
            || viewer_report.take_link(),
            constrained_transport,
            |own_div| pipeline.step_viewer_windows(own_div, target_fps),
            bytes_written.load(std::sync::atomic::Ordering::Relaxed),
        ) && (vw.changed
            || vw.struggling
            || vw.age_over
            || vw.link_congested
            || vw.drain_for_ms.is_some())
        {
            info!(
                %session_id,
                reported_fps = vw.reported_fps,
                struggling = vw.struggling,
                age_over = vw.age_over,
                link_congested = vw.link_congested,
                link_ceiling_bps = ?vw.link_ceiling_bps,
                drain_for_ms = ?vw.drain_for_ms,
                age_ms = vw.age_ms.map(|(a, _)| a),
                age_floor_ms = vw.age_ms.and(governor.viewer_age().map(|(_, f)| f)),
                cap_fps = vw.cap_fps,
                skip_divisor = vw.skip_divisor,
                frames_skipped_decode = governor.frames_skipped_decode(),
                "VP9-444 DC pump: viewer-rate fps cap"
            );
        }
        // FR-59 P4 — the transit queue is deeper than a rate cut can clear
        // in reasonable time, so stop feeding it and let it drain. Skipping
        // production (rather than discarding what is already queued) is the
        // only lever that reaches a queue living in the relay and the
        // carrier: those bytes are already gone and cannot be recalled.
        // Bounded sub-second, and NO forced keyframe on resume — a pause
        // loses no frames, so the delta chain survives it intact.
        if governor.draining(std::time::Instant::now()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        }
        if governor.should_skip_delta_frame(force_keyframe_this_iter) {
            continue;
        }

        // rc.33/rc.171 — resolution + quality-derived bitrate CEILING, fed to
        // the AIMD controller. The controller (not this block) owns the actual
        // applied bitrate: it starts at the ceiling and tracks the link down
        // under congestion / back up on recovery. The ceiling still lifts 4K
        // Quality=High to ~25-30 Mbps (the largest motion-smoothness lever)
        // and clamps to the relay cap on a constrained transport.
        // P5 — quality floor-merges across the shared pipeline's viewers.
        let q_now = pipeline.min_quality(quality_state.load(std::sync::atomic::Ordering::Relaxed));
        if let Some((ew, eh)) = encoder_dims {
            // FR-112 P2 — the base follows the rate the pump actually runs at
            // (paced when the encoder cannot hold the target, never below 30),
            // by √(fps/30); the kill switch keeps 0.4.141's linear base at the
            // target.
            let base = if sw_tier {
                let runs_at = governor.paced_software_fps().unwrap_or(target_fps);
                encode::bitrate_base_for_fps(ew, eh, runs_at)
            } else {
                encode::initial_bitrate_for_fps(ew, eh, target_fps)
            };
            // rc.185 — chroma-aware ceiling. `initial_bitrate_for_fps` is
            // pixel×fps only; it doesn't know the chroma format. 4:4:4 (VP9
            // profile 1) carries FULL U/V planes — ~1.5× the pixel data of
            // 4:2:0's quarter-res chroma — so at the same ceiling it must ride
            // QP higher under motion (rc_max_quantizer=63) → the "text starts
            // blurry, sharpens when static, re-blurs on movement" the field
            // reported on 4:4:4 but NOT 4:2:0. Give 4:4:4 the ~1.5× headroom
            // its extra chroma needs so text stays crisp under motion. The
            // relay clamp (`bitrate_cap`) still bounds it on a constrained link.
            let base = if chroma_wire == "yuv444" {
                base.saturating_mul(3) / 2
            } else {
                base
            };
            let ceiling = quality::target_bitrate(q_now, base).min(bitrate_cap);
            // 2026-08-26 — area-scaled AIMD floor (flat 1.5 M on a
            // constrained transport; see `encode::area_min_bitrate_bps`).
            let aimd_floor = crate::encode::area_min_bitrate_bps(w, h, constrained_transport);
            // Shared-pipeline egress split (see `shared_split_ceiling_bps`):
            // N viewers of one constrained encoder send N copies over the same
            // relay uplink; divide the ceiling by the live viewer count.
            let ceiling = crate::encode::shared_split_ceiling_bps(
                ceiling,
                (1 + pipeline.follower_count()) as u32,
                aimd_floor,
                constrained_transport,
                crate::encode::shared_rate_split_enabled(),
            );
            if let Some(applied) = governor.pre_encode_tick(
                ceiling,
                aimd_floor,
                constrained_transport,
                send_tx.capacity(),
                std::time::Instant::now(),
            ) {
                enc.set_bitrate(applied.bps).await;
                if q_now != last_applied_quality || applied.changed {
                    info!(
                        %session_id,
                        quality = quality::label(q_now),
                        base_bps = base,
                        ceiling_bps = ceiling,
                        target_bps = applied.bps,
                        "VP9-444 set_bitrate (AIMD)"
                    );
                }
            }
            last_applied_quality = q_now;
        }

        let encode_start = std::time::Instant::now();
        let packets = match enc.encode(&frame).await {
            Ok(p) => p,
            Err(e) => {
                warn!(%session_id, %e, "VP9-444 encode error — pump exits");
                return;
            }
        };
        encode_us += encode_start.elapsed().as_micros() as u64;
        encode_ops += 1;
        frames_encoded += packets.len() as u64;

        // P8 Phase 5 — fold the encoder's QP reports into the window.
        for pkt in &packets {
            if let Some(q) = pkt.qp {
                qp_sum += q.max(0) as u64;
                qp_max = qp_max.max(q);
                qp_n += 1;
            }
        }

        // rc.39 — scene-change detection. Inspect each delta packet's
        // size against the rolling average; on a sufficient spike,
        // arm keyframe_requested so the *next* encode emits an IDR.
        // Recovery becomes 2 frames (1 oversized delta + 1 sharp IDR)
        // instead of waiting up to kf_max_dist frames.
        let mut should_force_kf = false;
        for pkt in &packets {
            if pkt.is_keyframe {
                // A keyframe just landed (likely the periodic IDR or
                // a previous scene-change trigger). Reset the rolling
                // window — keyframe sizes would skew the average for
                // many seconds.
                recent_delta_sizes.clear();
                continue;
            }
            let size = pkt.data.len();
            if !recent_delta_sizes.is_empty() {
                let sum: usize = recent_delta_sizes.iter().sum();
                let avg = sum / recent_delta_sizes.len();
                if avg > 0
                    && size >= SCENE_CHANGE_MIN_BYTES
                    && size > avg * SCENE_CHANGE_SPIKE_RATIO
                {
                    should_force_kf = true;
                    tracing::info!(
                        %session_id,
                        size,
                        avg,
                        ratio = size as f32 / avg as f32,
                        "VP9-444 scene-change detected (delta-size spike) — forcing keyframe next frame"
                    );
                }
            }
            recent_delta_sizes.push_back(size);
            if recent_delta_sizes.len() > 30 {
                recent_delta_sizes.pop_front();
            }
        }
        if should_force_kf {
            // rc.43 — rate-limit. The recovery target is ~2 frames after
            // a real scene change; a 1.5 s cooldown is well past any
            // realistic single uncover-event recovery while preventing
            // the cascade where each forced keyframe inflates the
            // bitrate envelope and re-triggers the heuristic on the
            // next encode pass.
            let now = std::time::Instant::now();
            let within_cooldown = last_scene_change_kf_at
                .map(|t| now.duration_since(t) < SCENE_CHANGE_MIN_INTERVAL)
                .unwrap_or(false);
            if within_cooldown {
                tracing::debug!(
                    %session_id,
                    "VP9-444 scene-change candidate suppressed (rate-limit cooldown active)"
                );
            } else {
                if scene_kf_enabled {
                    keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
                    crate::session_telemetry::counters(session_id).note_keyframe();
                    scene_change_keyframes += 1;
                }
                last_scene_change_kf_at = Some(now);

                // rc.45 — piggyback motion-cpu-used boost on every
                // scene-change firing. The same signal that flags
                // "this frame needed a lot of new bits" also flags
                // "we're in a motion window where fps matters more
                // than per-frame quality". Boost stays armed for
                // MOTION_BOOST_DURATION_FRAMES; sustained motion
                // re-arms it; static periods let it expire and
                // restore base quality.
                if current_cpu_used != MOTION_BOOST_CPU_USED {
                    enc.with(|e| e.set_speed(MOTION_BOOST_CPU_USED)).await;
                    tracing::info!(
                        %session_id,
                        from = current_cpu_used,
                        to = MOTION_BOOST_CPU_USED,
                        "VP9-444 motion boost engaged — cpu-used raised (faster encode, lower per-frame quality)"
                    );
                    current_cpu_used = MOTION_BOOST_CPU_USED;
                }
                motion_boost_until_frame = frames_encoded + MOTION_BOOST_DURATION_FRAMES;
            }
        }

        // rc.45 — decay the motion boost when the duration elapses.
        // After MOTION_BOOST_DURATION_FRAMES frames without a new
        // scene-change refresh, drop cpu-used back to the base value
        // so static text snaps back to sharp encoding.
        if motion_boost_until_frame > 0
            && frames_encoded >= motion_boost_until_frame
            && current_cpu_used != base_cpu_used
        {
            enc.with(move |e| e.set_speed(base_cpu_used)).await;
            tracing::info!(
                %session_id,
                from = current_cpu_used,
                to = base_cpu_used,
                "VP9-444 motion boost expired — cpu-used restored to base"
            );
            current_cpu_used = base_cpu_used;
            motion_boost_until_frame = 0;
        }

        // Pull the DC handle once per frame. `try_lock` would race
        // with the on_data_channel callback that stashes it; the
        // contention here is microseconds.
        let dc_opt = video_bytes_dc.lock().await.clone();
        let Some(dc) = dc_opt else {
            // DC not yet open — drop frames until the controller
            // opens it. Common during the first ~100 ms of a session
            // (offer/answer + ICE + SCTP handshake). Counted so a
            // controller that never opens the DC is greppable.
            //
            // CRITICAL: also re-request a keyframe so the FIRST frame
            // the browser worker actually receives (whenever the DC
            // finally opens) is a keyframe. Without this, the encoder
            // proceeds along its 240-frame keyframe interval, so the
            // first delivered frame is a delta and the browser's
            // VideoDecoder rejects it with
            // "A key frame is required after configure() or flush()"
            // — every subsequent delta also fails since the decoder
            // never advanced past the configured-but-unfed state.
            dc_unopen_drops += packets.len() as u64;
            keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
            crate::session_telemetry::counters(session_id).note_keyframe();
            continue;
        };
        if dc.ready_state() != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
            dc_unopen_drops += packets.len() as u64;
            keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
            crate::session_telemetry::counters(session_id).note_keyframe();
            continue;
        }

        // Secondary congestion signal (rc.171) — the PRIMARY AIMD driver is
        // send-channel occupancy (see the capacity gate + the ceiling/observe
        // block above). But if the SCTP buffer DOES spike over the high
        // watermark, note it to the controller (a rate-limited decrease) and
        // shed this frame so we don't pile more bytes on an already-backed-up
        // queue. On webrtc-rs this rarely fires (dc.send().await blocks first,
        // keeping buffered_amount low), but it's a cheap belt-and-suspenders
        // check that also preserves the shed-on-overflow behaviour.
        let buffered = dc.buffered_amount().await as u64;
        if buffered > dc_buffered_high {
            if let Some(applied) = governor.on_send_overflow(std::time::Instant::now()) {
                enc.set_bitrate(applied.bps).await;
                info!(
                    %session_id,
                    buffered,
                    new_target = applied.bps,
                    "VP9-444 AIMD decrease (DC buffer over high watermark)"
                );
            }
            // Skip this frame entirely + ask the controller for a keyframe on
            // resume so the decoder doesn't choke on a delta-after-gap.
            frames_skipped_backpressure += packets.len() as u64;
            keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
            crate::session_telemetry::counters(session_id).note_keyframe();
            continue;
        }

        // rc.166 freeze fix — hand each framed packet to the dedicated send
        // task (see above the loop) rather than chunk-sending inline. The send
        // task owns the 16 KiB SCTP chunking + the flow-controlled
        // `dc.send().await`; `try_send` NEVER blocks the capture/encode loop.
        // If the send task is behind (the relay-TCP link can't drain a big
        // motion/IDR frame fast enough) the bounded channel fills and we shed
        // THIS frame + request a keyframe so the browser resyncs cleanly when
        // the queue drains. A single consumer preserves 16 KiB chunk order for
        // the browser reassembler. (frames_sent / bytes_written / send_errors
        // are incremented by the send task via the shared atomics now.)
        for p in packets {
            // FR-1 P7 — process-epoch stamp (see `agent_epoch_us`): the
            // browser maps this onto its own clock via the rc:clock probe.
            // Stamped at framing, so send-queue wait is inside the age.
            let ts_us = agent_epoch_us();
            let wire = bytes::Bytes::from(frame_video_bytes(&p.data, p.is_keyframe, ts_us));
            // P5 — fan out to the shared pipeline's followers first.
            pipeline.fan_out(
                &wire,
                p.is_keyframe,
                native_dims_packed,
                encoded_dims_packed,
            );
            match send_tx.try_send(wire) {
                Ok(()) => {
                    // A key frame that actually entered the send queue
                    // answers any pending forced-keyframe request (the
                    // force-ignored fallback and the retry stand down).
                    if p.is_keyframe {
                        kf_gate.on_key_frame_queued();
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    frames_skipped_backpressure += 1;
                    keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
                    crate::session_telemetry::counters(session_id).note_keyframe();
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    warn!(%session_id, "VP9-444 DC pump: send task gone — exiting pump");
                    return;
                }
            }
        }

        if frames_encoded.is_multiple_of(30) {
            // rc.36 — surface target_fps so field operators can verify
            // ROOMLERD_VP9_FPS env-var was honored. If target_fps
            // shows 30 when the operator set 60, the env var didn't
            // reach the agent process (wrong service-block scope, or
            // process wasn't restarted to inherit the new block).
            // rc.166 freeze fix — the send-owned counters are snapshotted from
            // the atomics for the log line.
            let frames_sent = frames_sent.load(std::sync::atomic::Ordering::Relaxed);
            let bytes_written = bytes_written.load(std::sync::atomic::Ordering::Relaxed);
            let send_errors = send_errors.load(std::sync::atomic::Ordering::Relaxed);
            // P7 — avg downscale cost over this window (Lanczos at deep rungs
            // is the only heavy stage that isn't the SW encoder itself).
            let avg_scale_ms = (scale_us / scale_ops.max(1)) as f64 / 1000.0;
            scale_us = 0;
            scale_ops = 0;
            // FR-112 P1 — the window's encode cost (BGRA → YUV + libvpx, on the
            // encoder thread when `media_thread` is on).
            let avg_encode_ms = (encode_us / encode_ops.max(1)) as f64 / 1000.0;
            // FR-112 P2 — the software tier steps once per window, on windows
            // that encoded something: an idle window says nothing about the
            // encoder.
            if sw_tier && encode_ops > 0 {
                governor.pace_software(avg_encode_ms as f32, target_fps);
            }
            encode_us = 0;
            encode_ops = 0;
            // P8 Phase 4 — shared / mixed-dial pipeline seconds (SVC
            // go/no-go dataset; ~1 s window — see the ffmpeg twin).
            if pipeline.follower_count() > 0 {
                let mixed = pipeline.dials_mixed(
                    priority.load(std::sync::atomic::Ordering::Relaxed),
                    *target_resolution.lock().unwrap(),
                );
                crate::session_telemetry::counters(session_id).note_shared_window(1, mixed);
            }
            // P8 Phase 5 — window QP stats (libvpx qindex scale);
            // None = no report this window.
            let avg_qp = (qp_n > 0).then(|| (qp_sum / qp_n) as u32);
            let max_qp = (qp_n > 0).then_some(qp_max);
            info!(
                %session_id,
                target_fps,
                cpu_used = current_cpu_used,
                frames_captured, frames_encoded, frames_sent, bytes_written,
                send_errors, dc_unopen_drops,
                frames_skipped_backpressure,
                scene_change_keyframes,
                settle_kf_suppressed,
                avg_scale_ms,
                avg_encode_ms,
                paced_fps = ?governor.paced_software_fps(),
                target_bps = governor.applied_bps(),
                avg_qp = ?avg_qp,
                max_qp = ?max_qp,
                // FR-15 — the viewer's own paint age + the learned path
                // floor. None = pre-FR-15 viewer (the loop stays off).
                viewer_age_ms = ?governor.viewer_age().map(|(a, _)| a),
                viewer_age_floor_ms = ?governor.viewer_age().map(|(_, f)| f),
                viewer_age_implausible = governor.viewer_age_implausible(),
                // FR-70 M0 — the fused age split by plane (transit is an
                // upper bound here: this pump keeps no send-wait figure).
                age_split = ?governor.viewer_age_split(None),
                // FR-71 T1a — which plane was the limiter last window, in
                // SHADOW (nothing acts on it until T1b), and windows per
                // verdict: [unknown, clear, overproduced, transit_stalled,
                // viewer_late]. A repeat of finding 4 reads `transit-stalled`
                // here while `target_bps` shows the cut T1b will remove.
                pipe_state = ?governor.pipe_state().map(|s| s.as_str()),
                pipe_states = ?governor.pipe_state_counts(),
                evidence_rejected = ?governor.evidence_rejected(),
                // FR-79 V3b (SHADOW) — the ONE belief beside the old composition:
                // believed / demonstrated floor / pushed-back capacity, and the
                // (deliveries, capacities) that produced them. Nothing reads these
                // yet; they exist so the field can say whether the belief is sane
                // before a loop acts on it.
                pipe_belief = ?governor.belief_bps(std::time::Instant::now()),
                pipe_belief_n = ?governor.belief_counts(),
                pipe_gap_stalls = governor.pipe_gap_stalls(),
                // FR-59 P1 — see the FFmpeg pump's heartbeat.
                slow_link_floor_bps = ?governor.relieved_floor_bps(),
                // FR-70 P1 — what stands in for a pipe measurement while
                // there is none: the remembered seed, or the last live
                // measurement, DECAYING toward the band on clean windows.
                // None = no prior in force. Read it against `goodput_bps`
                // and `slow_link_floor_bps`: a relief letting go while the
                // goodput stays None is the decay, working — and a session
                // that sits at `prior_bps=Some(200000)` for minutes with
                // both of those unchanged is the pin this phase removed.
                prior_bps = ?governor.prior_bps(),
                // FR-59 P3/P4 — (congested windows, drains ordered, live
                // queue-depth estimate in ms) from the viewer-side loop.
                link_stats = ?governor.link_stats(),
                "VP9-444 DC pump heartbeat (≈1s window)"
            );
            qp_sum = 0;
            qp_max = 0;
            qp_n = 0;
        }
    }
}

/// rc.83 — Codec selector for the unified FFmpeg DC pump. Lets one
/// pump function serve both HEVC (over `data-channel-hevc`) and VP9
/// (over `data-channel-vp9-444` when FFmpeg vp9_qsv is preferred over
/// libvpx SW) without duplicating the capture → encode → frame →
/// send loop.
#[cfg(feature = "ffmpeg-encoder")]
#[derive(Debug, Clone, Copy)]
enum FfmpegDcCodec {
    Hevc,
    Vp9,
    /// rc.190 — AV1 over `data-channel-av1`. HW-only (av1_nvenc/qsv/amf),
    /// probe-gated in caps.rs; packets are raw OBU temporal units which
    /// WebCodecs `av01.*` decodes without a description, same 13-byte DC
    /// framing as HEVC/VP9.
    Av1,
    /// P2 (Parsec-class plan) — H.264 over `data-channel-h264`. HW-only
    /// (h264_nvenc/qsv/amf), probe-gated in caps.rs; Annex-B with in-band
    /// SPS/PPS which WebCodecs `avc1.*` decodes without a description
    /// (same registry contract as the `hev1` path), same 13-byte framing.
    /// Gives H.264 the reliable-DC + canvas pipeline instead of the RTP
    /// track + `<video>` jitter buffer.
    H264,
}

#[cfg(feature = "ffmpeg-encoder")]
impl FfmpegDcCodec {
    /// Phase B — `fps` + `maxrate_bps` are the pump's per-session values
    /// (real `target_fps`, relay-aware ceiling), threaded into the encoder so
    /// its framerate + burst cap match the actual link instead of a fixed 30.
    /// `cq_bias`: SIGNED quality bias from `policy::rate_plan` (positive =
    /// the P7 deep-rung sharpening, negative = the constrained-motion
    /// relief), applied at open. `constrained`: this session's transport
    /// verdict — sizes the HRD window (relay ⇒ trimmed, so a single IDR
    /// can't book seconds of the clamped pipe). `chroma444`: the viewer's
    /// Rext 4:4:4 request — HEVC-only (nvenc), silently 4:2:0 elsewhere;
    /// read the returned encoder's `chroma444()` for the truth.
    /// `preferred`: the session's last successfully-opened backend name
    /// (rc.445) — tried alone first so a REBUILD skips the dead cascade
    /// prefix (field: every corplap rebuild burned ~100-300 ms failing
    /// av1_nvenc's tiered open before av1_qsv answered). Falls through to
    /// the full cascade on failure. Skipped for chroma444 sessions (their
    /// open has its own two-stage fallback).
    #[allow(clippy::too_many_arguments)]
    fn open(
        self,
        w: u32,
        h: u32,
        fps: u32,
        maxrate_bps: usize,
        cq_bias: i32,
        chroma444: bool,
        constrained: bool,
        preferred: Option<&'static str>,
    ) -> anyhow::Result<crate::encode::ffmpeg::FfmpegEncoder> {
        use crate::encode::ffmpeg::FfmpegEncoder;
        if !chroma444
            && let Some(name) = preferred
            && let Ok(enc) =
                FfmpegEncoder::new_preferred(name, w, h, fps, maxrate_bps, cq_bias, constrained)
        {
            return Ok(enc);
        }
        match self {
            Self::Hevc => FfmpegEncoder::new_hevc_adaptive(
                w,
                h,
                fps,
                maxrate_bps,
                cq_bias,
                chroma444,
                constrained,
            ),
            Self::Vp9 => FfmpegEncoder::new_vp9_adaptive(
                w,
                h,
                fps,
                maxrate_bps,
                cq_bias,
                chroma444,
                constrained,
            ),
            Self::Av1 => {
                FfmpegEncoder::new_av1_adaptive(w, h, fps, maxrate_bps, cq_bias, constrained)
            }
            Self::H264 => FfmpegEncoder::new_h264_adaptive(
                w,
                h,
                fps,
                maxrate_bps,
                cq_bias,
                chroma444,
                constrained,
            ),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Hevc => "HEVC",
            Self::Vp9 => "VP9",
            Self::Av1 => "AV1",
            Self::H264 => "H264",
        }
    }

    /// FR-77 P3b — the shared-pipeline key. A 4:4:4 session must never share
    /// a pump with a 4:2:0 one of the same codec: the bitstreams carry
    /// different profiles and the viewers configured different decoders.
    fn pipeline_label(self, chroma444: bool) -> &'static str {
        match (self, chroma444) {
            (Self::Hevc, true) => "HEVC-444",
            (Self::Vp9, true) => "VP9-444",
            (Self::H264, true) => "H264-444",
            _ => self.label(),
        }
    }

    /// Wire codec name for the `rc:video-info` message — matches the
    /// `AgentCaps.codecs` / negotiation vocabulary the browser uses.
    fn wire_codec(self) -> &'static str {
        match self {
            Self::Hevc => "h265",
            Self::Vp9 => "vp9",
            Self::Av1 => "av1",
            Self::H264 => "h264",
        }
    }

    /// Default chroma the FFmpeg path emits: `vp9_qsv` (profile 0),
    /// `av1_*` (Main) and `h264_*` are 4:2:0 8-bit. P7 — HEVC can also run
    /// Rext 4:4:4 (hevc_nvenc); the pump overrides this default with the
    /// ACTIVE encoder's `chroma444()` when building `rc:video-info`, so
    /// the badge reports the truth even after an open-time fallback.
    fn wire_chroma(self) -> &'static str {
        "yuv420"
    }
}

/// `rc:video-info` payload — ONE builder shared by BOTH DC pumps (FFmpeg
/// HEVC/vp9_qsv and libvpx VP9-444) so every session type reports the same
/// shape. `transport` is "relay"/"direct" so the browser's stats badge shows
/// WHICH path this session actually took (field 2026-07-13: same-LAN
/// sessions silently landing on the Germany TURN relay were
/// indistinguishable from direct ones without log access).
///
/// Badge-truth rc: the libvpx pump historically sent NO video-info at all,
/// and the FFmpeg pump sent it exactly once at encoder build — which raced
/// the control-DC open on slow (relay) sessions and silently lost the
/// message (rc.87 latent bug, surfaced by the transport field: every
/// "neither relay nor direct" badge in the 2026-07-13 field matrix was a
/// relay or VP9 session). Both pumps now retry until delivered.
///
/// Always compiled (pump features gate the CALLERS) so the default-build
/// unit test locks the wire shape, mirroring the signaling serde locks.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
#[allow(clippy::too_many_arguments)]
fn video_info_payload(
    codec: &str,
    encoder: &str,
    hardware: bool,
    chroma: &str,
    constrained: bool,
    // rc.199 — the native (pre-downscale) capture dims. The browser compares
    // them against the ACTUAL decoded frame size to decide whether the stream
    // is capped, and by transport ("relay") labels WHY. `0` (no frame yet) →
    // the browser omits the annotation, so the field is backward-compatible.
    native_w: u32,
    native_h: u32,
    // P5 — how many viewers this encoded stream serves (1 = solo, >1 =
    // shared-floor pipeline). The browser badge shows "shared ×N" so a
    // capped/min-merged stream is explainable from the viewer side.
    viewers: usize,
    // FR-33 P3 — WHY the transport is what it is, when the agent can name
    // it: `Some("lan-captured")` = a VPN captures this host's LAN prefix and
    // the viewer sits inside it, so the LAN pair could never form. Omitted
    // from the wire when `None` (old viewers ignore it, old agents omit it).
    transport_reason: Option<&str>,
    // FR-70 P1 — WHY the stream is encoded below the operator's resolution
    // choice, when it is: the `policy::RungReason` wire name of the cap in
    // force (`"slow-link-cap"`, `"priority-cap"`, `"soft-cap"`, …), present
    // ONLY while the effective target differs from the user's. Before this
    // the viewer inferred "relay-limited" from `transport` alone and advised
    // Priority → Sharper, which lifts a dial cap and does nothing against
    // the slow-link profile — the operator's own report on 2026-09-04.
    cap_reason: Option<&str>,
    // FR-70 P1 — a short human detail for the cap, e.g. `"remembered
    // 200 kbps"` for the slow-link profile (the rate the memory keyed it on).
    cap_detail: Option<&str>,
    // FR-93 P2 — the Linux arm serving this session, and whether it asked the
    // person at the screen (FR-45 AC8 option b). Omitted elsewhere, so old
    // viewers and non-Linux agents are byte-identical.
    arm: Option<crate::capture::CaptureArm>,
    // FR-119 P1 — the frame rate the stream runs at, and the viewer's ask with
    // the reason it was not granted, already in their wire form with a
    // leading comma (`frame_rate::RateState::video_info_fields`; P2b-2 adds
    // `fps_trial`). `None` whenever `fps-high` is off, so every payload is
    // byte-identical to before.
    fps: Option<String>,
) -> String {
    let reason = transport_reason
        .map(|r| format!(r#","transport_reason":"{r}""#))
        .unwrap_or_default();
    let arm = arm
        .map(|a| {
            format!(
                r#","capture_arm":"{}","attended":{}"#,
                a.wire(),
                a.attended()
            )
        })
        .unwrap_or_default();
    let cap = cap_reason
        .map(|r| format!(r#","cap_reason":"{r}""#))
        .unwrap_or_default();
    let detail = cap_detail
        .filter(|_| cap_reason.is_some())
        .map(|d| format!(r#","cap_detail":"{d}""#))
        .unwrap_or_default();
    let fps = fps.unwrap_or_default();
    format!(
        r#"{{"t":"rc:video-info","codec":"{codec}","encoder":"{encoder}","hardware":{hardware},"chroma":"{chroma}","transport":"{}","native_w":{native_w},"native_h":{native_h},"viewers":{viewers}{reason}{cap}{detail}{arm}{fps}}}"#,
        if constrained { "relay" } else { "direct" },
    )
}

/// FR-80 — `rc:media-unavailable`: this session will produce no pixels, and
/// here is why. The sibling of [`video_info_payload`], and deliberately a
/// separate message rather than a field on it: `rc:video-info` is built from
/// a frame that has been captured, so a session with no capture never reaches
/// it — which is exactly the hole this closes.
///
/// JSON escaping: `code` is a closed vocabulary and `hint` is a literal, so
/// only `detail` (a backend's own error text) can carry a quote or a
/// backslash. It is escaped rather than trusted.
///
/// Always compiled (the pump features gate the CALLERS) so the default-build
/// unit test locks the wire shape, mirroring `video_info_payload`.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn capture_unavailable_payload(reason: &crate::capture::CaptureUnavailable) -> String {
    let mut detail = String::with_capacity(reason.detail.len() + 8);
    for ch in reason.detail.chars() {
        match ch {
            '"' => detail.push_str("\\\""),
            '\\' => detail.push_str("\\\\"),
            // Any control character, not just the two that usually appear:
            // a backend's error text is not ours to trust, and one stray
            // byte must not produce a payload the viewer cannot parse.
            c if (c as u32) < 0x20 => detail.push(' '),
            c => detail.push(c),
        }
    }
    format!(
        r#"{{"t":"rc:media-unavailable","code":"{}","detail":"{detail}","hint":"{}"}}"#,
        reason.code.wire(),
        reason.code.hint(),
    )
}

/// FR-80 — deliver [`capture_unavailable_payload`] to the controller, retrying
/// until it lands.
///
/// Spawned rather than folded into the pump loop for two reasons. The control
/// DC is usually NOT open yet when capture is opened (it is opened first, and
/// on a relay session the DC lags by seconds) — the rc.87 race that made
/// `rc:video-info` retry in the first place. And the pump loop's own
/// retry-until-delivered state hangs off a captured frame, which a pump with
/// no capture never has.
///
/// Bounded: a session that never opens its control DC must not leave a task
/// spinning for the life of the process.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn spawn_capture_unavailable_notice(
    session_id: bson::oid::ObjectId,
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    reason: crate::capture::CaptureUnavailable,
) {
    const RETRY_EVERY: std::time::Duration = std::time::Duration::from_millis(500);
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
    // #1738 — each send is bounded: one on a channel a network drop left
    // `Closing` can park for good (#1730), and the deadline below is only a
    // deadline if the loop gets back to it (found in review).
    const SEND_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
    let payload = capture_unavailable_payload(&reason);
    warn!(
        %session_id,
        code = reason.code.wire(),
        detail = %reason.detail,
        "capture unavailable — this session will produce no pixels; telling the controller"
    );
    tokio::spawn(async move {
        if !send_control_notice(&control_dc, &payload, RETRY_EVERY, DEADLINE, SEND_BUDGET).await {
            warn!(
                %session_id,
                "capture-unavailable notice never reached the controller — its control channel \
                 did not open within the deadline"
            );
        }
    });
}

/// FR-97 P3c-1 — this session's audio track will carry no sound, and why.
///
/// The audio twin of FR-80's `rc:media-unavailable`, under its own name so a
/// viewer that predates it ignores it rather than reading "no pixels".
///
/// Always compiled (the `audio` feature gates the CALLER) so the default-build
/// unit test locks the wire shape, as `capture_unavailable_payload`'s does.
#[cfg_attr(not(feature = "audio"), allow(dead_code))]
fn audio_unavailable_payload(reason: &crate::audio_source::AudioUnavailable) -> String {
    serde_json::json!({
        "t": "rc:audio-unavailable",
        "code": reason.code.wire(),
        "detail": reason.detail,
        "hint": reason.code.hint(),
    })
    .to_string()
}

/// FR-97 P3c-1 — deliver [`audio_unavailable_payload`] to the controller, with
/// FR-80's retry: the control DC usually opens after the audio pump starts
/// (the pump is spawned before the SDP answer exists).
#[cfg(feature = "audio")]
fn spawn_audio_unavailable_notice(
    session_id: bson::oid::ObjectId,
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    reason: crate::audio_source::AudioUnavailable,
) {
    const RETRY_EVERY: std::time::Duration = std::time::Duration::from_millis(500);
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
    const SEND_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
    let payload = audio_unavailable_payload(&reason);
    warn!(
        %session_id,
        code = reason.code.wire(),
        detail = %reason.detail,
        "audio unavailable — this session's audio track carries no sound; telling the controller"
    );
    tokio::spawn(async move {
        if !send_control_notice(&control_dc, &payload, RETRY_EVERY, DEADLINE, SEND_BUDGET).await {
            warn!(
                %session_id,
                "audio-unavailable notice never reached the controller — its control channel \
                 did not open within the deadline"
            );
        }
    });
}

/// FR-93 P6g — a session served by an arm the compositor shows nothing for
/// says so at the screen. The DRM arm reads the scanout below GNOME and KDE, so
/// neither raises its screen-sharing indicator: the companion's banner, or a
/// notification with **Disconnect**, takes its place
/// ([`crate::indicator::notify::viewing`]). Called once per pump, after its
/// first open: a reopen keeps its arm.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn tell_the_screen(
    session_id: bson::oid::ObjectId,
    arm: Option<crate::capture::CaptureArm>,
    rc_sessions: &crate::rc_sessions::RcSessionRegistry,
) {
    #[cfg(all(target_os = "linux", feature = "portal-capture"))]
    if arm == Some(crate::capture::CaptureArm::Drm) {
        crate::indicator::notify::viewing(session_id, rc_sessions.clone());
    }
    #[cfg(not(all(target_os = "linux", feature = "portal-capture")))]
    let _ = (session_id, arm, rc_sessions);
}

/// FR-93 P2d-2 — `rc:media-waiting`: this session's capture is waiting for the
/// person at the screen to answer a dialog (the desktop portal's "share your
/// screen"), and the dialog gives up in `waits_ms`. Without it the viewer saw
/// a blank canvas and re-created the session every 10 s, so the session the
/// person finally answered for was rarely the one on screen.
///
/// A duration, not a time of day, so the viewer reads it on its own clock.
/// `for` names what is awaited: one value today, and an unknown one is kept by
/// the viewer, like an unknown FR-80 code.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn media_waiting_payload(wait: crate::capture::OpenWait) -> String {
    use crate::capture::WaitFor;
    // FR-93 P5b — `for` names what the open waits for: the viewer titles the
    // notice by it, and an older viewer shows any `for` with the hint.
    let (for_, hint) = match wait.why {
        WaitFor::Dialog { control: false } => ("person_at_screen", MEDIA_WAITING_HINT),
        WaitFor::Dialog { control: true } => ("person_at_screen", MEDIA_WAITING_HINT_CONTROL),
        WaitFor::Unlock => ("screen_unlock", MEDIA_WAITING_HINT_UNLOCK),
        // FR-93 P3e — a display the compositor switched off (DRM).
        WaitFor::DisplayWake => ("display_wake", MEDIA_WAITING_HINT_WAKE),
        // FR-93 P5f — this user's session in the background (a user switch).
        WaitFor::SessionAway => ("session_away", MEDIA_WAITING_HINT_AWAY),
        // FR-93 P5h — the computer is going to sleep (`crate::sleep_notice`).
        WaitFor::HostSleep => ("host_sleep", MEDIA_WAITING_HINT_SLEEP),
        // FR-95 P2 — the same `for`, so a viewer titles them as it already
        // does; a system install's own sentence.
        WaitFor::GuardLocked => ("screen_unlock", MEDIA_WAITING_HINT_UNLOCK_SYSTEM),
        WaitFor::GuardAway => ("session_away", MEDIA_WAITING_HINT_AWAY_SYSTEM),
    };
    format!(
        r#"{{"t":"rc:media-waiting","for":"{for_}","waits_ms":{},"hint":"{hint}"}}"#,
        wait.gives_up_in.as_millis(),
    )
}

/// What the viewer shows under "waiting for the person at the screen". A
/// literal, so it carries no quote or backslash to escape.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
const MEDIA_WAITING_HINT: &str = "The person at this computer is being asked to share their screen. \
     The picture starts as soon as they choose to share it.";

/// FR-93 P5b — the hint when the dialog asks for remote control (P4b's
/// automatic portal). A refusal there is asked again for the screen only, in
/// the same wait, so the sentence names both.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
const MEDIA_WAITING_HINT_CONTROL: &str = "The person at this computer is being asked to allow \
     remote control (or to share just their screen). The picture starts as soon as they allow it.";

/// FR-93 P5b (#2145) — the hint while GNOME's screen is locked. True to what
/// can be done: GNOME shares no locked screen with a per-user install and takes
/// no remote input there, so it is unlocked at the computer; a system install
/// with `drm_capture` + `uinput` shows the lock screen and can unlock it.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
const MEDIA_WAITING_HINT_UNLOCK: &str = "This computer's screen is locked. GNOME shares no locked \
     screen with this per-user install and takes no remote input there, so it has to be unlocked \
     at the computer; the picture comes back by itself. A system install with drm_capture and \
     uinput can show and unlock a locked screen.";

/// FR-93 P3e — the hint while the display is off (DRM, a system install).
/// Input wakes it: the viewer's reaches the host through `uinput`, which the
/// compositor counts as the person at the screen.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
const MEDIA_WAITING_HINT_WAKE: &str = "This computer's display is off: it went to sleep. Moving the \
     mouse or pressing a key wakes it, from this viewer when it controls the computer, or at the \
     computer itself; the picture comes back by itself.";

/// FR-93 P5f — the hint while this user's session is in the background. A
/// per-user install shares only its own user's session, and it is switched
/// back at the computer.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
const MEDIA_WAITING_HINT_AWAY: &str = "This computer is showing the login screen or another user's \
     session. This install shares only its own user's session, so the picture comes back by itself \
     when that session is on screen again.";

/// FR-95 P2 — the hint while the person a system install's automatic capture
/// is bound to has locked their screen. It reads nothing and injects nothing
/// there, so the screen is unlocked at the computer.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
const MEDIA_WAITING_HINT_UNLOCK_SYSTEM: &str = "This computer's screen is locked. This install \
     switched capture on by itself for the person at the screen, so it shows nothing while their \
     screen is locked and takes no input there: it has to be unlocked at the computer, and the \
     picture comes back by itself. A system install with drm_capture and uinput set can show and \
     unlock a locked screen.";

/// FR-95 P2 — the hint while that person is not on screen.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
const MEDIA_WAITING_HINT_AWAY_SYSTEM: &str = "This computer is showing the login screen or another \
     person's session. This install switched capture on by itself for the person who was told they \
     are being viewed, so it shows nothing until that session is back on screen, and the picture \
     comes back by itself then. If they logged out, or someone else logged in, connect again.";

/// FR-93 P5h — the hint as the computer goes to sleep. Nothing can be done
/// from the viewer: a sleeping computer is woken at the computer (or by a
/// timer it set), and the viewer reconnects by itself once it is back.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
const MEDIA_WAITING_HINT_SLEEP: &str = "This computer is going to sleep. The session comes back by \
     itself once the computer wakes; a desktop that locks when it sleeps then waits for its unlock.";

/// FR-93 P5h — the `rc:media-waiting` a session's controller is sent as the
/// computer goes to sleep, or `None` under P2d-2's kill switch
/// (`ROOMLERD_MEDIA_WAITING=0`), which silences every waiting notice. No sleep
/// has a known end, so it counts as long as any other host wait.
#[cfg_attr(
    not(all(target_os = "linux", feature = "portal-capture")),
    allow(dead_code)
)]
pub(crate) fn host_sleep_notice() -> Option<String> {
    media_waiting_enabled().then(|| {
        media_waiting_payload(crate::capture::OpenWait {
            gives_up_in: std::time::Duration::from_secs(60 * 60),
            why: crate::capture::WaitFor::HostSleep,
        })
    })
}

/// FR-93 P2d-2 kill switch `ROOMLERD_MEDIA_WAITING=0`: no `rc:media-waiting`
/// is sent, and the viewer behaves as before P2d-2. P3e's pumps then keep
/// their keepalives through a dark display too, as before P3e: with nothing
/// said, a viewer that saw no frames would re-create its session every ~10 s.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn media_waiting_enabled() -> bool {
    tunnel_core::env::flag("MEDIA_WAITING", true)
}

/// FR-93 P3e — a running capture that waits on its host (a display switched
/// off; P5f: this user's session in the background). The controller is told
/// once per wait, and again before the last telling runs out, so the notice
/// outlives a wait of any length; while it waits the pump sends no keepalive,
/// because the viewer clears its notice at the first decoded frame and a
/// keepalive would be one.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
#[derive(Default)]
struct CaptureWait {
    told: Option<(crate::capture::WaitFor, std::time::Instant)>,
    /// FR-93 P5f — a wait not told yet: what for, and since when the pump
    /// has held, sending nothing.
    quiet: Option<(crate::capture::WaitFor, std::time::Instant)>,
}

impl CaptureWait {
    /// How long the controller is told the wait may last. Nothing ends a
    /// blank on its own, so the viewer shows no deadline for one; it only
    /// holds its watchdog until then.
    const TOLD_FOR: Duration = Duration::from_secs(60 * 60);
    /// A wait still going is told again this often.
    const RETELL: Duration = Duration::from_secs(30 * 60);
    /// FR-93 P5f — how long the pump holds, sending nothing, before it tells
    /// the controller. The viewer ends a wait at its first watchdog tick (one
    /// a second) that counted a frame, and the notice travels on the control
    /// channel while the last frames travel on the video one, so a keepalive
    /// sent just before the notice could be counted just after it. Measured
    /// on the lab's GNOME guest: the notice cleared that way, and with the
    /// keepalives held the viewer re-created the session 10 s later.
    const QUIET_BEFORE_TELL: Duration = Duration::from_secs(2);

    /// After a "no frame": `None` when the capture waits for nothing (the
    /// pump goes on as before, keepalive and all); else what it waits for,
    /// and whether the controller is to be told now.
    fn on_empty(
        &mut self,
        waits: Option<crate::capture::WaitFor>,
        now: std::time::Instant,
    ) -> Option<(crate::capture::WaitFor, bool)> {
        let Some(why) = waits else {
            self.told = None;
            self.quiet = None;
            return None;
        };
        let fresh = matches!(
            self.told,
            Some((w, at)) if w == why && now.saturating_duration_since(at) < Self::RETELL
        );
        if fresh {
            return Some((why, false));
        }
        let since = match self.quiet {
            Some((w, since)) if w == why => since,
            _ => {
                self.quiet = Some((why, now));
                now
            }
        };
        if now.saturating_duration_since(since) < Self::QUIET_BEFORE_TELL {
            return Some((why, false));
        }
        self.quiet = None;
        self.told = Some((why, now));
        Some((why, true))
    }

    /// A frame: whatever the capture waited for is over.
    fn on_frame(&mut self) {
        self.told = None;
        self.quiet = None;
    }

    /// The pumps' half: on a "no frame", `true` when the capture waits on its
    /// host (told now, earlier, or once the pump has been quiet for
    /// [`Self::QUIET_BEFORE_TELL`]), so no keepalive goes out.
    fn hold(
        &mut self,
        waits: Option<crate::capture::WaitFor>,
        session_id: bson::oid::ObjectId,
        control_dc: &Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    ) -> bool {
        if !media_waiting_enabled() {
            return false;
        }
        let Some((why, tell)) = self.on_empty(waits, std::time::Instant::now()) else {
            return false;
        };
        if tell {
            media_waiting_hook(session_id, control_dc.clone())(crate::capture::OpenWait {
                gives_up_in: Self::TOLD_FOR,
                why,
            });
        }
        true
    }
}

/// FR-93 P2d-2 — the hook a pump hands its capture open
/// ([`crate::capture::open_default_async`]): if the open parks on the person at
/// the screen (a portal dialog, P5b's locked screen, P3e's dark display), tell
/// the controller, retrying until the control channel takes it.
/// `ROOMLERD_MEDIA_WAITING=0` turns the notice off.
///
/// The hook fires on the blocking pool, so it holds the runtime's handle
/// rather than relying on a context that thread may not have entered.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn media_waiting_hook(
    session_id: bson::oid::ObjectId,
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
) -> crate::capture::OnOpenWait {
    if !media_waiting_enabled() {
        return Box::new(|_| {});
    }
    let runtime = tokio::runtime::Handle::current();
    let asking: std::sync::Mutex<Option<crate::rc_sessions::AskingMark>> =
        std::sync::Mutex::new(None);
    Box::new(move |wait| {
        const RETRY_EVERY: std::time::Duration = std::time::Duration::from_millis(500);
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
        const SEND_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
        // FR-93 P6h — while the desktop's own dialog asks the person at the
        // screen, nothing is shared yet, and the companion's "Being viewed"
        // banner would cover the very window that asks (measured on KDE,
        // where both are centred). The session lists as `asking` until this
        // hook goes with its open, or the open moves on to another wait.
        let mark = matches!(wait.why, crate::capture::WaitFor::Dialog { .. })
            .then(|| crate::rc_sessions::AskingMark::new(session_id));
        *asking.lock().unwrap_or_else(|p| p.into_inner()) = mark;
        let payload = media_waiting_payload(wait);
        info!(
            %session_id,
            gives_up_in_s = wait.gives_up_in.as_secs(),
            why = ?wait.why,
            "capture: waiting on the host (a portal dialog, an unlock, a display waking, a user switch); telling the controller"
        );
        // FR-93 P5g — one open can wait twice (the switch, then the unlock).
        let control_dc = control_dc.clone();
        runtime.spawn(async move {
            // Bounded by the wait's own deadline too: past it, the notice
            // would describe a wait that is already over.
            let deadline = DEADLINE.min(wait.gives_up_in);
            if !send_control_notice(&control_dc, &payload, RETRY_EVERY, deadline, SEND_BUDGET).await
            {
                warn!(
                    %session_id,
                    "media-waiting notice never reached the controller within its deadline"
                );
            }
        });
    })
}

/// Retry one control-DC message until it is sent or `deadline` passes. The
/// channel usually opens AFTER capture (and seconds late on a relay), so a
/// one-shot send would be lost. `true` once it went out. FR-93 P5h's sleep
/// notice sends through it too (`crate::sleep_notice`), and FR-97 P3c-1's
/// audio notice.
#[cfg_attr(
    not(any(
        feature = "vp9-444",
        feature = "ffmpeg-encoder",
        feature = "audio",
        all(target_os = "linux", feature = "portal-capture")
    )),
    allow(dead_code)
)]
pub(crate) async fn send_control_notice(
    control_dc: &Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    payload: &str,
    retry_every: std::time::Duration,
    deadline: std::time::Duration,
    send_budget: std::time::Duration,
) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        let cdc = control_dc.lock().await.clone();
        if let Some(cdc) = cdc
            && matches!(
                tokio::time::timeout(send_budget, cdc.send_text(payload.to_string())).await,
                Ok(Ok(_))
            )
        {
            return true;
        }
        tokio::time::sleep(retry_every).await;
    }
    false
}

/// FR-93 P6c — how long an owner whose capture was stopped at the screen waits
/// for its followers' sessions to end before ending its own.
const FOLLOWERS_GONE_WAIT: Duration = Duration::from_secs(2);

/// FR-93 P6c — the person at the screen stopped the share with the desktop's
/// own control: Stop on GNOME's screen-sharing indicator, End on KDE's. Every
/// session watching through this capture ends the way their Disconnect ends
/// one (FR-27 P10's kill path): the controller reads that the person at the
/// device ended it and does not reconnect, and a recording stops. Before this
/// the pump reopened the capture, which made the desktop's control a no-op:
/// GNOME's Stop was undone 0.5 s later by a new unattended screencast, KDE's
/// End by the token's restore 3 s later.
///
/// A shared pipeline's followers go first. Had the owner gone first, they
/// would detach, re-dispatch, and one of them would reopen the capture the
/// person had just stopped. A Disconnect that cannot be queued yet (no entry,
/// a full queue) is asked again every second.
///
/// Never returns, and never reopens: the session's teardown aborts the pump,
/// whose task this is.
async fn end_stopped_at_screen(
    session_id: bson::oid::ObjectId,
    rc_sessions: &crate::rc_sessions::RcSessionRegistry,
    pipeline: Option<&crate::media_share::Pipeline>,
) -> std::convert::Infallible {
    let followers = pipeline.map(|p| p.follower_sessions()).unwrap_or_default();
    warn!(
        %session_id,
        followers = followers.len(),
        "capture: the person at the screen stopped the share with the desktop's own control; \
         ending the session as their Disconnect does, the capture not reopened (FR-93 P6c)"
    );
    if let Some(p) = pipeline {
        for f in &followers {
            if !rc_sessions.disconnect(f) {
                warn!(%session_id, follower = %f, "capture stopped at the screen: a follower's session could not be ended");
            }
        }
        let until = std::time::Instant::now() + FOLLOWERS_GONE_WAIT;
        while p.follower_count() > 0 && std::time::Instant::now() < until {
            p.beat();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let mut asks = 0u32;
    let mut ended = false;
    loop {
        if !ended {
            ended = rc_sessions.disconnect(&session_id);
            if !ended && asks.is_multiple_of(30) {
                warn!(%session_id, asks, "capture stopped at the screen: the session's Disconnect could not be queued yet");
            }
            asks += 1;
        }
        if let Some(p) = pipeline {
            p.beat();
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// FR-93 P1 — tell the controller, once, when this session's input will NOT
/// reach the whole desktop (`rc:input-reach`). An injector that reaches
/// nothing does not fail (XTest into Xwayland succeeds and moves nobody's
/// pointer), so without this a session on such a host looked interactive and
/// did nothing. A session whose input reaches everything sends nothing, like
/// FR-80's notice, and an older viewer ignores the message.
///
/// The verdict probes the X server and reads `/proc`, so it runs on the
/// blocking pool. `None` is P1's kill switch, which tells nothing (P1a).
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn spawn_input_reach_notice(
    session_id: bson::oid::ObjectId,
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
) {
    tokio::spawn(async move {
        let Ok(Some(reach)) = tokio::task::spawn_blocking(crate::input::reach::told).await else {
            return;
        };
        if reach.reach == crate::input::reach::Reach::Full {
            debug!(%session_id, reason = %reach.reason, "input: this session's input reaches the whole desktop");
            return;
        }
        warn!(
            %session_id,
            reach = reach.reach.wire(),
            reason = %reach.reason,
            "input: this session's input will not reach the whole desktop; telling the controller"
        );
        let payload = crate::input::reach::payload(&reach);
        let sent = send_control_notice(
            &control_dc,
            &payload,
            std::time::Duration::from_millis(500),
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(2),
        )
        .await;
        if !sent {
            warn!(%session_id, "input-reach notice never reached the controller");
        }
    });
}

/// FR-33 P3 — the pure half of [`lan_capture_reason`]: name the capture as
/// the transport reason only when BOTH (a) this session runs on a real relay
/// and (b) the viewer offered a host / peer-reflexive candidate whose
/// address lies inside one of THIS host's captured LAN prefixes. (b) is what
/// keeps the label honest: a viewer on another network is relayed by the
/// corp NAT, and the LAN capture is not its reason — the same per-prefix
/// scoping the P2 eligibility gate uses. `in_capture` answers "is this v4
/// address inside a captured prefix" (the netstate snapshot's
/// `LanCapture::contains_v4`, or a test closure).
#[cfg_attr(not(feature = "overlay-l3"), allow(dead_code))]
fn lan_capture_reason_for(
    constrained: bool,
    remote_lan_addrs: &[std::net::IpAddr],
    in_capture: impl Fn(std::net::Ipv4Addr) -> bool,
) -> Option<&'static str> {
    if !constrained {
        return None;
    }
    remote_lan_addrs
        .iter()
        .any(|a| match a {
            std::net::IpAddr::V4(v4) => in_capture(*v4),
            std::net::IpAddr::V6(_) => false,
        })
        .then_some("lan-captured")
}

/// FR-33 P3 — this session's `transport_reason`, from the peer connection's
/// own remote-candidate stats (host AND prflx: under Check Point the viewer's
/// LAN address shows up as prflx, because its packets ARRIVE and only our
/// replies die) against the host's live capture set. `None` = nothing to
/// name; the browser then shows plain `relay`. Read at `rc:video-info` time
/// only (once per session or transport flip), so the stats walk is free.
/// Without `overlay-l3` there is no netstate monitor in this binary, so the
/// answer is honestly `None` (the stub below).
///
/// Gated on `overlay-l3` ALONE, with the pump features gating only the
/// callers (the `video_info_payload` pattern): no per-PR lane compiles
/// `overlay-l3` together with a pump feature — only the release builds do —
/// so a body gated on both would first compile at release time. This way
/// the per-PR `clippy --features overlay-l3` lane compiles the real body.
#[cfg(feature = "overlay-l3")]
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
async fn lan_capture_reason(
    pc: &Arc<RTCPeerConnection>,
    constrained: bool,
) -> Option<&'static str> {
    use webrtc::ice::candidate::CandidateType;
    use webrtc::stats::StatsReportType;
    if !constrained {
        return None;
    }
    let captures = tunnel_core::overlay::netstate::handle()
        .map(|h| h.snapshot().lan_captures.clone())
        .unwrap_or_default();
    if captures.is_empty() {
        return None;
    }
    let remote: Vec<std::net::IpAddr> = pc
        .get_stats()
        .await
        .reports
        .values()
        .filter_map(|r| match r {
            StatsReportType::RemoteCandidate(c)
                if matches!(
                    c.candidate_type,
                    CandidateType::Host | CandidateType::PeerReflexive
                ) =>
            {
                c.ip.parse().ok()
            }
            _ => None,
        })
        .collect();
    let reason = lan_capture_reason_for(true, &remote, |ip| {
        captures.iter().any(|c| c.contains_v4(ip))
    });
    // LOG every silent drop: this branch runs only on a relayed session on a
    // captured host, i.e. exactly when an operator will ask why the pill
    // did or did not name the VPN. Field 2026-09-04: the first P3 check
    // stayed unnamed and it took a browser-side probe to learn the viewer
    // had offered NO host/srflx candidates at all (Chrome's non-proxied-UDP
    // block); this line answers that from the daemon log next time.
    info!(
        reason = reason.unwrap_or("-"),
        viewer_lan_candidates = ?remote,
        captured = ?captures.iter().map(|c| c.prefix.as_str()).collect::<Vec<_>>(),
        "rc: LAN-capture transport reason (FR-33 P3)"
    );
    reason
}

/// FR-33 P3 — the non-`overlay-l3` stub: no netstate monitor, nothing to
/// name. Same signature so the pumps compile identically under both builds.
#[cfg(not(feature = "overlay-l3"))]
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
async fn lan_capture_reason(
    _pc: &Arc<RTCPeerConnection>,
    _constrained: bool,
) -> Option<&'static str> {
    None
}

/// Retry cadence for an undelivered `rc:video-info` — the control DC opens
/// within a second or two of session start (longer on relay), so a 500 ms
/// re-attempt converges fast without hammering the mutex.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
const VIDEO_INFO_RETRY: Duration = Duration::from_millis(500);

/// rc.77/rc.83 — Unified FFmpeg-encoder DataChannel pump.
///
/// Mirrors `media_pump_vp9_444_dc` structurally but uses
/// `FfmpegEncoder` (which dispatches to vendor SDKs) and emits raw
/// codec bytes length-prefixed over the `video-bytes` DC. Shares the
/// same 13-byte header as the VP9 path so `frame_video_bytes` is
/// reused verbatim.
///
/// `codec` chooses which encoder dispatch the FfmpegEncoder uses:
/// - `Hevc` → `hevc_nvenc` / `hevc_qsv` / `hevc_amf` (rc.77 path)
/// - `Vp9` → `vp9_qsv` (rc.83 path — Intel-only HW VP9, unblocks
///   the Iris Xe CPU-bound 17 fps → 60 fps target)
///
/// Capture → encode → frame → send, with (Phase B) a per-session AIMD
/// backpressure controller mirroring `media_pump_vp9_444_dc`: it detects THIS
/// session's ICE path (relay vs direct), picks the target fps + a relay-aware
/// maxrate ceiling accordingly, and drives `FfmpegEncoder::set_bitrate` off
/// send-channel occupancy so the HEVC/vp9_qsv burst cap tracks the actual link.
/// (No scene-change detection / ROI hints yet — those remain future work.)
#[cfg(feature = "ffmpeg-encoder")]
#[allow(clippy::too_many_arguments)]
async fn media_pump_ffmpeg_dc(
    codec: FfmpegDcCodec,
    session_id: bson::oid::ObjectId,
    video_bytes_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    keyframe_requested: Arc<std::sync::atomic::AtomicBool>,
    target_resolution: Arc<std::sync::Mutex<TargetResolution>>,
    lock_state_rx: tokio::sync::watch::Receiver<lock_state::LockState>,
    _quality_state: Arc<std::sync::atomic::AtomicU8>,
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    // Phase B — the peer connection, so the pump can detect THIS session's
    // actual ICE path (relay vs direct) at runtime for the per-session
    // bitrate/fps clamp instead of the process-wide env flag.
    pc: Arc<RTCPeerConnection>,
    // rc.183 — publish native pre-downscale dims for the cursor pump.
    capture_native_dims: Arc<std::sync::atomic::AtomicU64>,
    // rc.190 — publish the ACTUAL encoded dims (post caps) for the cursor pump.
    encoded_dims: Arc<std::sync::atomic::AtomicU64>,
    // rc.188 — packed viewer decode report for the viewer-rate fps cap.
    viewer_report: Arc<crate::encode::viewer_rate::ViewerFeedback>,
    // rc.199 — per-session Priority dial (`rc:priority`); resolves the relay
    // resolution cap this pump feeds `effective_target_resolution`.
    priority: Arc<std::sync::atomic::AtomicU8>,
    // P7 — the viewer's `chroma_pref == "yuv444"` request. Only the HEVC
    // codec honours it (Rext via hevc_nvenc, see FfmpegEncoder::
    // new_hevc_adaptive); the other codecs ignore it. May silently fall
    // back to 4:2:0 at open time — `rc:video-info` reports the truth.
    chroma444: bool,
    // FR-17 — the controller negotiated per-chunk framing for this
    // session (it advertised `chunk-framing` support in
    // `rc:session.request`). Threaded down to the send task rather
    // than read from a global: it is a per-SESSION property, and a
    // shared pipeline can serve viewers that disagree.
    chunk_framing: bool,
    // FR-93 P6c — see `media_pump`.
    rc_sessions: crate::rc_sessions::RcSessionRegistry,
) {
    use crate::encode::VideoEncoder;

    let codec_label = codec.label();
    // P7 — the session's ACTIVE chroma: starts as the request (HEVC only),
    // downgraded by the open-time fallback; drives the maxrate chroma
    // factor + the video-info chroma string.
    let mut cell_444 = chroma444 && !matches!(codec, FfmpegDcCodec::Av1);
    // P5 — shared-floor pipeline: this pump is the OWNER for its hard
    // profile (transport codec). Same-profile sessions join as followers
    // through `run_ffmpeg_dc_session`; their inputs merge into this loop as
    // a floor (any-viewer keyframe, max frame-skip divisor, min dials,
    // production gated on the slowest queue) and every encoded packet fans
    // out to them. Standalone (never followed) when the key was already
    // owned by another pump. Dropping it — including task abort at session
    // teardown — detaches all followers, which then re-dispatch.
    // P7 — the key is chroma-discriminated for HEVC ("HEVC-444" vs "HEVC",
    // mirroring run_ffmpeg_dc_session): a Rext stream and a Main-profile
    // stream configure different viewer decoders and must never share.
    // Keyed on the REQUEST (not the open-time fallback): followers joined
    // the same requested profile, and a Rext-configured viewer decoder
    // accepts a Main-profile bitstream if the open fell back.
    let pipeline = crate::media_share::Pipeline::register(
        crate::media_share::PipelineKey::FfmpegDc(codec.pipeline_label(cell_444)),
        session_id,
    );
    let mut last_viewers: usize = 0;
    // FR-119 P1 — `fps-high`, read once per pump (FR-70: no knob is read in the
    // frame path). P2b-2 — the answer `rc:video-info` last carried, and
    // whether a trial ran, so a new one (a new ask, a new rate, a trial
    // starting or ending) re-sends it.
    let fps_high = crate::encode::fps_high_enabled();
    let mut fps_told: Option<(crate::encode::frame_rate::Answer, bool, Option<u16>)> = None;
    // rc.87 — emit `rc:video-info` so the browser stats badge shows the
    // TRUTH (real encoder + HW + chroma + transport). Badge-truth rc:
    // RETRIED until delivered (see the loop-top block) — the old
    // send-once-at-encoder-build raced the control-DC open on slow (relay)
    // sessions and silently lost the message.
    let mut video_info_sent = false;
    let mut last_video_info_attempt: Option<std::time::Instant> = None;

    // Mirror the VP9 pump's overlay gate. Under SystemContext the
    // captured frame IS the real Winlogon screen; an overlay over it
    // would hide the password prompt and block remote unlock.
    let sys_ctx_worker = is_system_context_worker();
    if sys_ctx_worker {
        info!(
            %session_id,
            codec_label,
            "media_pump_ffmpeg_dc: SystemContext worker — lock overlay disabled"
        );
    }
    // P8b stage 2 — the keyframe-force policy machine (lock edge, backstop
    // retry, force-ignored rebuild fallback + rc.217 cooldown, rc.106
    // resync scheduling). See `encode::kf_policy` module docs; this pump
    // stays the executor (it holds the encoder and writes the logs).
    let mut kf_gate = crate::encode::kf_policy::KeyframeGate::new(matches!(
        *lock_state_rx.borrow(),
        lock_state::LockState::Locked
    ));

    // Phase B — detect THIS session's ICE path (relay vs direct) up front so
    // the target fps + maxrate ceiling + send-queue depth all match the actual
    // link, and the AIMD clamps per session rather than off the process-wide
    // env flag. The env flag still wins as an explicit override (see
    // `detect_constrained_transport`). ICE may not have nominated yet, so this
    // briefly polls; the AIMD converges regardless of the initial guess.
    // Relay-escape: `mut` — the loop re-checks the selected pair periodically
    // and follows a mid-session renomination (see the block at the loop top).
    let mut constrained = detect_constrained_transport(&pc, session_id).await;
    let mut last_transport_check = std::time::Instant::now();
    // FR-35 P2 — per-peer rate memory: the pair's remembered stable rate
    // seeds the opening ceiling (85 % of it), so the opening keyframe is
    // sized by what the pair proved, not by the fleet constant. Keyed by the
    // nominated pair's remote address (the viewer host).
    let rate_hi_bps = crate::encode::relay_max_hi_bps();
    let rate_peer_key = if constrained && rate_hi_bps > 0 {
        // The pair may not be nominated yet at pump start (the 0.4.27 field
        // run's first packet came 4 s in): no key then means no seed AND no
        // write-back, i.e. the memory silently off for the session. Poll
        // briefly; the pump has nothing to send before the DC opens anyway.
        let mut key = None;
        for _ in 0..20 {
            key = nominated_remote_ip(&pc).await;
            if key.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if key.is_none() {
            info!(
                %session_id,
                "FR-35 rate memory: no nominated pair within 4 s of pump start — memory off for this session"
            );
        }
        // FR-79 V2 — the carrier is half the key: one overlay address can be
        // carried by a direct path, a UDP relay or DERP over TLS on different
        // days, with four times the capacity between the ends of that range.
        match key {
            Some(addr) => {
                let tag = overlay_carrier_tag(&addr).await;
                Some(crate::encode::rate_memory::memory_key(
                    &addr,
                    tag.as_deref(),
                ))
            }
            None => None,
        }
    } else {
        None
    };
    let rate_memory_path = crate::encode::rate_memory::default_path();
    let rate_seed = match (&rate_peer_key, &rate_memory_path) {
        (Some(peer), Some(path)) => crate::encode::rate_memory::RateMemory::load(path)
            .seed_for(peer, crate::encode::rate_memory::now_unix()),
        _ => None,
    };
    if let Some(seed) = rate_seed {
        info!(
            %session_id,
            codec_label,
            peer = rate_peer_key.as_deref().unwrap_or("-"),
            seed_bps = seed,
            hi_bps = rate_hi_bps,
            "FR-35 rate memory: opening ceiling seeded from the pair's remembered stable rate"
        );
    }
    let rate_memory_guard = RateMemoryGuard {
        path: rate_memory_path,
        peer: rate_peer_key,
        stable: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),

        opener_measured: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
    };
    // P3 — persisted-flip rebuild: a relay↔direct renomination that holds for
    // 2 consecutive rechecks (and outside the 60 s cooldown) rebuilds the
    // encoder AND reopens the capturer at the new profile fps — pre-P3 a
    // session that STARTED relayed stayed at 30 fps forever after upgrading
    // to direct (fps was baked into the capture pacer at pump start). The
    // live AIMD ceiling clamp still follows EVERY flip immediately; the
    // tracker only gates the heavyweight rebuild. Escape hatch
    // `ROOMLERD_RATE_PROFILE_REBUILD=0` restores the AIMD-only
    // behaviour.
    let mut flip_tracker = crate::encode::rate_profile::FlipTracker::new(constrained);
    let rate_profile_rebuild = node_env("RATE_PROFILE_REBUILD").as_deref() != Some("0");

    // rc.93 — target fps. Pre-rc.93 this was hardcoded 30, which capped the
    // scrap backend's internal pacer (`scrap_backend::next_frame` sleeps to
    // `1000/target_fps` ms) AND drove a redundant pump-side floor sleep.
    // The fast legacy `media_pump` runs the SAME capturer at 60 with no
    // pump floor and hits ~55 fps; HW encode (vp9_qsv/hevc_qsv ~4-6 ms)
    // easily sustains that. Phase B: default 60 on a direct link, 30 on a
    // constrained relay (which can't sustain 60 fps of HEVC without shedding);
    // an explicit env override wins either way. P3 — `mut`: the persisted-flip
    // rebuild retargets it mid-session.
    let mut target_fps: u32 = ffmpeg_target_fps(constrained);
    // FR-59 P5 — a pair the rate memory remembers as slow opens with fewer
    // pixels and fewer frames. The bitrate levers (P1-P4) can make the
    // encoder TRACK a 400 kbps pipe but cannot make 1920x1200 at 30 fps
    // legible through it — that is ~1.7 KB per frame. Resolved ONCE here,
    // never as a mid-session rung: every rung flip pays a blocking encoder
    // open (0.65-0.87 s measured on Iris Xe) plus a fresh IDR, which is why
    // `priority_relay_cap`'s dims-caps are off by default. Opening at the
    // right size costs neither.
    let slow_link_profile = if constrained {
        crate::encode::rate_profile::slow_link_profile(
            rate_seed,
            crate::encode::slow_link_profile_enabled(),
        )
    } else {
        None
    };
    if let Some(p) = slow_link_profile {
        target_fps = target_fps.min(p.max_fps);
        info!(
            %session_id,
            codec_label,
            remembered_bps = ?rate_seed,
            max_long_edge = p.max_long_edge,
            max_fps = p.max_fps,
            target_fps,
            "FR-59 P5 slow-link profile engaged — the pair is remembered as slow, \
             opening with fewer pixels and fewer frames"
        );
    }
    // FR-119 P2b-2 — the frame-rate grant. `base_fps` is what the session
    // runs at without one (the transport's rate, or the slow-link profile's)
    // and moves only with the transport; `encoder_fps` is the rate the live
    // encoder was built for. With `fps-high` on, the rate-class cache is read
    // once, here, off the runtime, under the probe cache's key: no key (macOS,
    // or the cache switched off) reads as an empty cache, every class
    // unproven. `fps_deny` is read here too (FR-70: no knob in the frame path).
    let mut base_fps = target_fps;
    let mut encoder_fps = target_fps;
    let fps_deny = if fps_high {
        crate::encode::frame_rate::fps_deny_from_env()
    } else {
        Vec::new()
    };
    let fps_cache = if fps_high {
        tokio::task::spawn_blocking(|| {
            let path = crate::encode::fps_class_cache::path()?;
            let key = crate::encode::caps_cache::current_key()?;
            let entries = crate::encode::fps_class_cache::load(
                &path,
                &key,
                crate::encode::caps_cache::now_unix(),
            );
            Some((path, key, entries))
        })
        .await
        .ok()
        .flatten()
    } else {
        None
    };
    let mut fps_state = fps_high.then(|| {
        let verdicts = fps_cache
            .as_ref()
            .map(|(_, _, entries)| {
                entries
                    .iter()
                    .map(|e| (e.class.clone(), e.verdict))
                    .collect()
            })
            .unwrap_or_default();
        crate::encode::frame_rate::RateState::new(target_fps, verdicts)
    });
    let fps_cache = fps_cache.map(|(path, key, _)| (path, key));
    // What the last decision was taken on (the ask, the base rate, the
    // transport, the capture backend and its screen's refresh rate, the
    // encoder, its dims), and when: decided again when any of it moves, and
    // once a second for the pipe's belief.
    type FpsDecidedOn = (
        Option<u32>,
        u32,
        bool,
        &'static str,
        Option<u16>,
        &'static str,
        (u32, u32),
    );
    const FPS_DECIDE_EVERY: Duration = Duration::from_secs(1);
    const FPS_SWAP_RETRY: Duration = Duration::from_secs(10);
    let mut fps_decided_on: Option<FpsDecidedOn> = None;
    let mut fps_decided_at = std::time::Instant::now();
    let downscale = crate::capture::DownscalePolicy::Never;
    info!(
        %session_id,
        codec_label,
        target_fps,
        slow_link = slow_link_profile.is_some(),
        "FFmpeg DC pump starting"
    );
    let mut capturer = capture::open_default_async(
        target_fps,
        downscale,
        media_waiting_hook(session_id, control_dc.clone()),
    )
    .await;
    // FR-80 — a capturer that cannot capture says so, and the controller is
    // told once, here, instead of the operator reading a stall. Every real
    // backend answers `None`, so a healthy session sends nothing.
    if let Some(reason) = capturer.unavailable() {
        spawn_capture_unavailable_notice(session_id, control_dc.clone(), reason.clone());
    }
    // FR-93 P6g — and an arm the compositor shows nothing for still says, at
    // the screen, who is viewing it.
    tell_the_screen(session_id, capturer.arm(), &rc_sessions);
    // FR-93 P1 — and what its input will reach. After the capture opened: a
    // portal capture registers its input route as it opens.
    spawn_input_reach_notice(session_id, control_dc.clone());
    // P3 — bounded reopen backoff for the capture-error arm (500 ms → 10 s
    // on consecutive failures; quiet spell resets). See `ReopenBackoff`.
    let mut reopen_backoff = capture::ReopenBackoff::new();
    // FR-70 M1 — the encoder behind one handle: inline (today's
    // `block_in_place` on a runtime worker) or on its own thread, chosen once
    // per open from the `media_thread` switch. Every call below is the same
    // on both paths.
    let media_thread = crate::encode::media_thread_enabled();
    let mut encoder: Option<crate::encode::ffmpeg::EncoderHandle> = None;
    let mut encoder_dims: Option<(u32, u32)> = None;
    // FR-70 M2 — the dims make-before-break. When the plan moves the
    // resolution, the replacement opens in the background at the NEW dims
    // (`open_rebuilt`, 0.4–2.9 s measured) while the current encoder keeps
    // serving at the OLD dims: the effective target stays pinned to the one
    // the current encoder was built for until the swap. `built_target` is
    // that target — set ONLY when an encoder is built (the inline open) or
    // adopted (the swap, from the target the replacement was opened for),
    // never refreshed from a pass that merely did not need a rebuild: the
    // second field contact (CORPLAP-3, 0.4.73) had it refreshed from the
    // plan's NEW target on the pass where the frame still carried the old
    // cap, so the pin later named a target the live encoder was not built
    // for and the upward move (small → native) fell into the inline open.
    // `pending_dims_open` is the open in flight with the dims it will
    // produce, when it started, and the target those dims came from.
    let mut built_target: Option<TargetResolution> = None;
    /// The open in flight, the dims it will produce, when it started, the
    /// plan target it was opened for (`built_target` at the swap), and the
    /// FR-70 M3a plan it was spawned under (the shadow's staleness reference).
    /// FR-119 P2b-2 — and the frame rate it opens at.
    type PendingDimsOpen = (
        tokio::task::JoinHandle<anyhow::Result<crate::encode::ffmpeg::RebuiltEncoder>>,
        (u32, u32),
        std::time::Instant,
        TargetResolution,
        Option<crate::encode::plan::SwapSpawn>,
        u32,
    );
    let mut pending_dims_open: Option<PendingDimsOpen> = None;
    // FR-119 P2b-2 — after a replacement at another frame rate failed to
    // open, no frame-rate move is opened again before this instant: a rate
    // the backend refuses must not cost an open on every frame.
    let mut fps_retry_at: Option<std::time::Instant> = None;
    let mut dims_swaps: u32 = 0;
    /// Frames the pump may skip after a capture-cap change before it treats
    /// a dims mismatch as real: the backend applies a cap "from the next
    /// frame", so one or two frames at the old dims are still in flight.
    const STALE_FRAME_SKIPS: u32 = 3;
    let mut stale_skips_left: u32 = 0;
    // rc.93 — single keepalive clock, mirroring `media_pump`. The rc.92
    // pacing clock + pump-side floor sleep were REMOVED: the capture
    // backend is the single pacer (scrap sleeps to `1000/target_fps`;
    // SystemContext capture delivers at display rate), so a second
    // pump-side floor just halved fps and amplified idle Nones — that was
    // the real vp9_qsv ~15 fps bug (rc.92's timer theory was a red herring;
    // timeBeginPeriod(1) landed but didn't move fps).
    let mut last_capture_at = std::time::Instant::now();
    let mut last_good_frame: Option<std::sync::Arc<crate::capture::Frame>> = None;
    // FR-93 P3e — a capture waiting on its host (a display switched off).
    let mut capture_wait = CaptureWait::default();
    // rc.187 stale-frame fix, burst-gated 2026-07-27 (see
    // rate_profile::SettleKeyframeGate): the FIRST idle keepalive after a
    // MOTION BURST settles forces a keyframe so a viewer that dropped frames
    // during the motion (backpressure / decode backlog) can resync to the
    // settled state. Isolated blips no longer qualify — a blinking caret
    // (~530 ms) counted as "motion" and forced a ~2 Hz IDR metronome (field
    // DEVBOX→WINHOST-B 2026-07-27: blur→crystal text pulse on all codecs,
    // most visible on av1_nvenc).
    let mut settle_kf = crate::encode::rate_profile::SettleKeyframeGate::from_env();
    // P7 — idle native-rung refinement ("crisp at rest"): when the only
    // reason we're below native is a resolution cap (Smoother; Balanced+relay
    // behind an env opt-in) and the scene settles, lift the cap so the
    // dims-keyed rebuild below ships one crisp native IDR; the first motion
    // burst restores the cap in ~300 ms. Everything downstream is already
    // plumbed: rebuild-on-dims-change → guaranteed IDR of the settled
    // native `last_good_frame` (stored pre-downscale), aimd.force_reapply,
    // video_info resend, encoded_dims → cursor scale. Kill switch
    // `ROOMLERD_IDLE_REFINE=0`; see rate_profile::IdleRefine.
    let mut idle_refine = crate::encode::rate_profile::IdleRefine::from_env();
    // rc.130 — 60 ms (was 1 s). Doubles as the SPARSE-INPUT DRAIN. With the
    // HW encoder's output queue capped to ~1 frame (encoder.rs delay=0 /
    // async_depth=1), re-feeding the last good frame here flushes the held
    // frame within ~60 ms of the screen going idle — so the LAST keystroke's
    // pixels reach the browser promptly instead of waiting up to a full
    // second (the old keepalive value) for the next caret blink to push them
    // out. Fires only on capture-None (no new frame) and, via the rc.111
    // capacity gate above, only when the send channel has room — so it adds
    // ZERO frames under motion (real frames keep resetting last_capture_at).
    // Idle cost: ~16 fps of near-zero-byte static deltas.
    const IDLE_KEEPALIVE: Duration = Duration::from_millis(60);

    let mut frames_captured: u64 = 0;
    let mut frames_encoded: u64 = 0;
    // rc.106 — frames_sent / bytes_written / send_errors are owned by the
    // dedicated send task (spawned below) and shared back as atomics so the
    // heartbeat can still read them. Moving the chunked DC send off the
    // pump's hot path stops a big (IDR / motion) frame from stalling
    // capture+encode on `send().await` — the "hangs every few seconds"
    // under window movement (field DEVBOX: 46 fps with periodic
    // freezes; the inline send blocked the loop ~tens of ms per multi-MB
    // frame).
    let frames_sent = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let bytes_written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let send_errors = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut dc_unopen_drops: u64 = 0;
    // rc.88 — frames dropped because the DC send buffer was over the
    // high-water mark (congested link). Shedding a delta frame keeps the
    // capture/encode loop at cadence instead of stalling on `send().await`
    // — the likely cause of the field's "13 fps under motion".
    let mut frames_dropped_backpressure: u64 = 0;
    // rc.111 — frames skipped at the SOURCE (before capture+encode) because
    // the send channel was full. Distinct from frames_dropped_backpressure
    // (which counts frames encoded THEN dropped at try_send). Skipping before
    // encode is the cheaper, smoother response: no wasted GPU encode and no
    // resync-keyframe churn (the HEVC delta chain stays intact). See the gate
    // at the top of the loop.
    let mut frames_skipped_backpressure: u64 = 0;
    // rc.190 — one-shot (per value) log marker for the relay resolution cap.
    // FR-70 P1 — the last resolution plan (user target, effective target,
    // reason). Any change re-sends `rc:video-info` so the viewer's badge can
    // name the cap in force; a change while the two targets differ is also
    // logged (the rc.190 "cap engaged" line, now keyed on the reason too).
    let mut last_dims_plan: Option<(
        TargetResolution,
        TargetResolution,
        crate::encode::policy::RungReason,
    )> = None;
    // rc.88 — per-stage timing accumulators (µs since last heartbeat) so
    // the field log localises the bottleneck: capture vs encode vs send.
    let mut capture_us: u64 = 0;
    let mut encode_us: u64 = 0;
    let mut send_us: u64 = 0;
    // P7 — downscale stage joins the trio: the Lanczos floor now admits the
    // deeper Smoother shrinks, so avg_scale_ms is the field evidence that
    // the filter fits (or doesn't fit) this host's 30 fps budget. Phase A —
    // averaged over REAL resamples (scale_ops), not window frames.
    let mut scale_us: u64 = 0;
    let mut scale_ops: u64 = 0;
    // FR-65 P0 — the APPLY phase (rate/dims set_bitrate, swap start, adoption).
    // The stage that was never timed, and therefore the stage a 1.3-2.0 s QSV
    // encoder open hid in for months. `apply_us_max` matters more than the sum:
    // an average over a 2 s heartbeat cannot represent a single 2 s outlier.
    let mut apply_us: u64 = 0;
    let mut apply_us_max: u64 = 0;
    // FR-65 P0 — the encoder OPEN phase, separate from `apply`. `apply` times a
    // change to an encoder that already exists; the first pass of a session has
    // none to change, so a 0.5-1 s open landed in no phase at all (field
    // 2026-09-03, four sessions on CORPLAP-1: `iter_ms` 513-1006 against named
    // phases summing to 33-52). Rebuilds come through the same site.
    let mut open_us: u64 = 0;
    let mut open_us_max: u64 = 0;
    // FR-65 — the five regions between the loop top and capture that `other_ms`
    // caught in the field (2026-09-04, all three CORPLAP hosts): passes of
    // 157-782 ms with `open_ms=0` and, on the gate arm, `capture_ms=0` and
    // `encode_ms=0` too. `other_ms` existing is what made them visible; naming
    // them is what makes them actionable. Same move as #1279 made for the open.
    let mut pace_us: u64 = 0;
    let mut stats_us: u64 = 0;
    let mut ctrl_us: u64 = 0;
    let mut swap_us: u64 = 0;
    let mut gate_us: u64 = 0;
    // FR-65 P0 — worst single loop pass in the window, and how many overran.
    let mut iter_us_max: u64 = 0;
    let mut pump_stalls: u32 = 0;
    // FR-79 — `pump_stalls` at the last viewer window, so the window's own
    // stalled-pass count is a delta rather than a running total.
    let mut win_stalls_last: u32 = 0;
    let stall_watch = crate::encode::pump_stall_watch_enabled();
    let stall_warn = Duration::from_millis(crate::encode::pump_stall_warn_ms());
    // Measured at the TOP of the NEXT pass, so every `continue` path in this
    // loop is covered without an RAII guard fighting the borrow checker.
    // FR-65 — one struct rather than the old 7-tuple: with eleven phases a
    // positional tuple is a mismatched-pair waiting to happen, and the
    // subtraction now lives in `PhaseAccum::delta` where it is unit-tested.
    let mut iter_mark: Option<(std::time::Instant, crate::encode::stall::PhaseAccum)> = None;
    // ⚠️ Rate-limited: a stall storm that floods its own log is a second
    // performance problem.
    let mut last_stall_log = crate::clock::instant_before(Duration::from_secs(60));
    // FR-65 P0 — time an apply in place. A macro rather than a closure because
    // it expands textually, so the body keeps its own `enc` mutable borrow.
    macro_rules! timed_apply {
        ($body:expr) => {{
            let __t = std::time::Instant::now();
            let __r = $body;
            let __us = __t.elapsed().as_micros() as u64;
            apply_us += __us;
            if __us > apply_us_max {
                apply_us_max = __us;
            }
            __r
        }};
    }
    // Phase A — pump-local resampler (cached taps + pooled intermediate);
    // see encode::resample module docs.
    let mut resampler = crate::encode::resample::Resampler::new();
    // Phase B — the backend cap last handed to the capturer (change-gated).
    let mut last_output_cap: Option<(u32, u32)> = None;
    // P8 Phase 5 — per-window QP telemetry (record-only): the encoder's
    // own quantizer reports, next to the rung/ceiling the agent CHOSE.
    // This is the dataset that decides whether a closed quality loop
    // replaces the area ladder. None-reporting backends leave qp_n=0.
    let mut qp_sum: u64 = 0;
    let mut qp_max: i32 = 0;
    let mut qp_n: u64 = 0;
    // rc.93 — count Ok(None) ticks (capturer had no new frame). Replaces
    // the rc.92 floor-sleep accumulator now that the pump floor is gone. A
    // high frames_empty *under motion* would mean the capture backend (not
    // the pump) is the fps limiter; near-zero under motion confirms the
    // pump now runs at capture rate like `media_pump`.
    let mut frames_empty: u64 = 0;
    // rc.98 — one-shot confirmation that the encoder actually emits a
    // key-FLAGGED packet (pkt.is_keyframe). On NVENC this only happens with
    // `forced-idr=1`; if this log never fires while the browser reports "A
    // key frame is required", the encoder isn't flagging IDRs.
    let mut first_keyframe_logged = false;
    let mut heartbeat_frames_base: u64 = 0;
    // FR-118 P0 — the encoder's stage totals and the capture backend's
    // readback totals at the last heartbeat, so each heartbeat reports its own
    // window.
    let mut stage_base = crate::encode::ffmpeg::encoder::StageTimes::default();
    let mut readback_base: (u64, u64) = (0, 0);
    let mut last_heartbeat = std::time::Instant::now();
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

    // rc.106 — dedicated DC send task. The chunked `dc.send().await` is
    // flow-controlled by SCTP; on a multi-MB frame (HEVC IDR / high-motion
    // delta) it blocks for tens of ms. Doing that inline in the pump (rc.88)
    // stalled capture+encode → the periodic freeze (field DEVBOX).
    // Hand framed frames to this task over a small bounded channel instead;
    // the pump never blocks on the link (see the `try_send` below). A SINGLE
    // consumer keeps the 16 KiB chunk order intact (the browser reassembler
    // needs it). Depth is small so we stay low-latency — under sustained
    // congestion the pump sheds load (drops + schedules a resync keyframe)
    // rather than building a stale backlog.
    // Deeper queue on the direct/LAN path (localhost under WSL mirrored
    // networking) so high-motion HEVC bursts (big IDR/motion frames) get
    // BUFFERED instead of shed (the "movement stutter"); a constrained relay-TCP
    // path stays shallow to shed fast rather than build a stale backlog. Input
    // rides a SEPARATE DC, so a deeper video queue adds no input lag.
    // 2026-08-26 (field, neo16↔Rozalina): direct 12 → 6. Twelve frames at
    // 40 fps was ~300 ms of standing latency all by itself once the byte
    // gate below started bounding the ledger — the burst-absorption job
    // moved to the byte budget (time-denominated), the frame count is now
    // only the item bound.
    let ffmpeg_send_depth = if constrained { 4 } else { 6 };
    // rc.445 — items carry the send EPOCH they were encoded under; the send
    // task discards stale-epoch frames so a rebuild's first IDR never waits
    // behind pre-rebuild deltas (see `send_epoch`). 2026-08-26 — items also
    // carry their ENQUEUE instant so the send task can report queue-wait
    // (the transport-added latency a viewer actually feels) per heartbeat.
    let (send_tx, mut send_rx) =
        tokio::sync::mpsc::channel::<(u64, std::time::Instant, bytes::Bytes)>(ffmpeg_send_depth);
    // Byte-budget gate (field 2026-08-21, winhost-a/corplap — extended to
    // DIRECT 2026-08-26, neo16↔Rozalina): the channel's FRAME-count bound
    // bounds nothing in BYTES — four native motion frames are ~0.5-1 MB
    // ≈ 2-4 s of a ~2 Mbps relay, and on a LAN a drag burst at a stale
    // maxrate queued 100-345 KB ≈ 100-300+ ms of standing lag. Track the
    // bytes handed to the send task and skip production while more than
    // the path's queue budget is still in flight — lag becomes an
    // immediate, small fps reduction instead. Constrained budget is
    // resolved once (450 ms of the relay ceiling; env/config are
    // process-stable); the DIRECT budget is re-derived per iteration from
    // the AIMD's live applied target (150 ms of it — the target tracks
    // congestion down within ~2 s even while a rebuild-bound encoder's
    // actual maxrate is motion-deferred), falling back to the policy
    // ceiling before the first apply.
    let inflight_bytes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let constrained_queue_budget =
        crate::encode::rate_profile::constrained_queue_budget_bytes(crate::encode::relay_max_bps());
    // FR-59 P2 — process-stable kill switch for denominating that budget in
    // the MEASURED rate instead of the nominal relay ceiling. Resolved once
    // (env/config are process-stable) and read at the gate every iteration.
    let constrained_queue_measured = crate::encode::constrained_queue_measured_enabled();
    // FR-74 P1b — the lag bound the direct gate judges the measured wait
    // against, resolved once like the line above (env/config are process-stable).
    let direct_lag_bound_ms = crate::encode::rate_profile::direct_queue_ms();
    // 2026-08-26 — queue-wait telemetry (P7 of the drag-latency design):
    // enqueue→wire-complete per frame, accumulated by the send task and
    // drained by the heartbeat. Sent frames only — a stale-dropped frame
    // never rode the wire, and its wait would double-count the rebuild
    // gap the epoch discard exists to erase.
    let send_wait_us_sum = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let send_wait_us_max = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // FR-71 T1a — per-viewer-window deltas of the sender-side counters, so the
    // governor's shadow classifier sees THIS window's sends, skips and waits
    // rather than the heartbeat's or the session's totals.
    let mut win_sent_last: u64 = 0;
    let mut win_skips_last: u64 = 0;
    let mut win_sw_sum_last: u64 = 0;
    let mut win_sw_frames_last: u64 = 0;
    let send_wait_frames = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // FR-35 P3 — the opener as a burst probe: bytes sent and the longest
    // queue-wait seen while the opening grace is on. Their ratio is the
    // pipe's burst drain rate — the one number that sizes a crisp opener —
    // and every session measures it for free (P0 had to do it by hand).
    let opener_wait_us_max = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let opener_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let in_opener_grace = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    // The longest blocked send the task has seen since the pump last
    // looked, µs. A separate cell from the heartbeat's max because this
    // one is a CONTROL input drained every loop, while that one is a
    // report drained every 2 s — sharing it would make the rate loop's
    // reaction depend on the logging cadence.
    let send_stall_us = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // FR-74 P1b — the enqueue instant (µs since `head_wait_epoch`, +1 so 0
    // means "nothing at the head") of the frame the send task is writing
    // RIGHT NOW. The completion-based waits above only learn about a frame
    // once it has left the wire, so on a stalled pipe they read stale-low
    // while the queue grows; this cell lets the gate see the live age of
    // the head frame instead. Cleared by the send task after each write.
    let send_head_enqueued_us = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let head_wait_epoch = std::time::Instant::now();
    // The gate's own view of the measured send wait: an EMA over the
    // per-pass average of completed frames' waits (α = 0.3) — separate
    // "last" cursors from the FR-71 window deltas so the two readers never
    // race each other for the same counters.
    let mut direct_wait_ema_ms: f64 = 0.0;
    let mut gate_sw_sum_last: u64 = 0;
    let mut gate_sw_frames_last: u64 = 0;
    // The direct byte gate's reference rate: the last policy ceiling (the
    // AIMD's applied target takes over once it exists). One-shot log the
    // first time the direct gate actually sheds, so a field read can tell
    // "gate bounded the queue" from "gate never engaged".
    let mut last_ceiling_bps: u32 = 0;
    let mut direct_gate_logged = false;
    // P5 (FR-1) — cadence-pacing state: the next consumption slot, and the
    // last paced value logged (changes only — engage / move / release).
    let mut pace_due: Option<std::time::Instant> = None;
    let mut last_paced_logged: Option<Option<u32>> = None;
    // FR-10 — relay IDR thrift: suppress settle-IDRs and space deferred
    // applies on constrained sessions (each such IDR was a 1.2-1.5 s lump
    // on CORPLAP-3's ~2 Mbps relay).
    let relay_idr_thrift = crate::encode::relay_idr_thrift_enabled();
    // Resolved once: a per-frame env read would sit in the hot path.
    let send_stall_threshold = crate::encode::send_stall_threshold();
    let mut send_stalls: u64 = 0;
    // FR-35 P3 — opener grace. The opening keyframe + desktop repair is a
    // burst by design (P0: this path absorbs bursts far above its sustainable
    // rate). Read as congestion it cut the seeded 5.95 Mbps session ×0.85
    // within 1.8 s of connecting (send_wait_max 367 ms, 73 backpressure skips
    // — field 2026-08-30) and the AIMD then climbed back one starved IDR per
    // 5-s step. For the first `OPENER_GRACE` of a constrained session, soft
    // stalls and backpressure skips are counted but not fed to the AIMD; a
    // HARD stall (≥ 1 s) still is.
    // Held at least this long after the first packet and until the send
    // ledger is EMPTY (the opener's tail was still draining 1.1 s after a
    // fixed 2 s ended, and tripped a decrease — field 2026-08-30), capped.
    const OPENER_GRACE: Duration = Duration::from_secs(2);
    // Backstop only. The stuck detector below normally ends the grace far
    // sooner; this bounds the pathological case where the byte gate keeps the
    // grace-end block (further down the loop, past the gate's `continue`) from
    // ever running. Was 6 s — a hot seed pinned the encoder at ~1 fps for the
    // whole window (field 2026-08-30, neo16 → CORPLAP-2: a several-second
    // freeze on connect).
    const OPENER_GRACE_MAX: Duration = Duration::from_secs(3);
    // The opener is expected to DRAIN within ~1 s; if the byte gate stays
    // saturated (inflight pinned, not falling) longer than this, the seed is
    // too hot for this path — end the grace so the AIMD cuts. A smooth soft
    // picture beats a frozen crisp one.
    const OPENER_GRACE_STUCK: Duration = Duration::from_millis(1200);
    // Anchored at the FIRST PACKET, not at pump start: the pump spins for
    // seconds before anything is sent (consent, ICE, the DC opening — the
    // 0.4.27 field run's first packet came 4 s in) and a grace measured from
    // pump start had expired before the opener existed.
    let mut opener_started: Option<std::time::Instant> = None;
    let mut opener_grace_done = false;
    let mut grace_soft_stalls: u32 = 0;
    let mut grace_bp_skips: u32 = 0;
    // FR-35 P3b — set the first time the byte gate saturates during the grace,
    // reset whenever inflight falls below half the budget (the opener is
    // draining). Sustained beyond `OPENER_GRACE_STUCK` ⇒ the seed does not fit.
    let mut grace_congested_since: Option<std::time::Instant> = None;
    let mut last_deferred_apply_at: Option<std::time::Instant> = None;
    let mut settle_kf_suppressed: u64 = 0;

    // P8c — the rate governor owns the four rate controllers this pump
    // previously threaded by hand (see `encode::governor` module docs):
    // the Phase B AIMD (lazily constructed at the first frame's ceiling;
    // driven off SEND-CHANNEL OCCUPANCY — the real DC backpressure
    // signal, since SCTP flow control keeps `buffered_amount()` low even
    // while saturated), the rc.188 viewer-rate fps cap (1 s windows →
    // frame-skip divisor; keyframes never skipped), the rc.186
    // encode-pressure maxrate factor (stepped once per heartbeat), and
    // the 2026-07-27 encode-bound auto-downscale tier (soft slot of the
    // dims plan; kill `ROOMLERD_AUTO_DOWNSCALE=0`). The governor
    // emits continuous bitrate targets; `FfmpegEncoder::set_bitrate`
    // coarsens them to a ladder and applies in-place (NVENC reconfigure)
    // or as a debounced QSV/AMF rebuild whose first frame is an IDR.
    let mut governor = crate::encode::governor::RateGovernor::new(
        target_fps,
        ffmpeg_send_depth,
        crate::encode::governor::GovernorFlags::from_env(),
        // FR-35 — the constrained ceiling learns the pair (0 = off).
        rate_hi_bps,
        rate_seed,
        std::time::Instant::now(),
    );
    if let Some(seed_bps) = governor.open_seed_bps() {
        info!(
            %session_id,
            codec_label,
            seed_bps,
            "FR-59 P8 — the pair is remembered slower than the nominal floor: opening at the \
             remembered rate, floor relief seeded from it, refine lift held while the profile is on"
        );
    }
    // FR-70 M3a — the PLAN, in SHADOW (`encode::plan`). At the top of every
    // pass the pump computes the plan ONCE from the facts it has at that
    // instant and compares it, field by field, against the inline values it
    // goes on to compute in the same pass. Nothing reads the plan: every
    // decision below is still the inline one. The heartbeat's
    // `plan_divergences` is the retirement gate for that inline arithmetic
    // (fleet-zero before M3b flips the loop to read the plan), and a field's
    // first divergence logs once per session with both values. Every knob the
    // inline code reads from env per frame is resolved here, once, so the
    // shadow adds no env read to the frame path (FR-70's rule). No kill
    // switch: it changes no decision, takes no await, and this FR exists to
    // delete switches, not add them.
    let plan_knobs = crate::encode::plan::PlanKnobs::from_env();
    let mut plan_shadow = crate::encode::plan::Shadow::default();
    // rc.443 — consecutive-encode-error escalation (retry → rebuild →
    // clean pump exit); see `encode::EncodeErrorLadder`.
    let mut err_ladder = crate::encode::EncodeErrorLadder::default();
    let mut rebuild_after_encode_error = false;
    // rc.445 — motion-deferred bitrate application for rebuild-bound
    // encoders (QSV/AMF). With the byte gate alive, the AIMD moves DURING
    // motion — and on QSV every ladder move is a BLOCKING encoder open
    // (field-measured 0.65-0.87 s on Iris Xe) plus a fresh IDR: the exact
    // mid-drag freeze the dial-cap removal is killing, re-entering through
    // the bitrate door. NVENC reconfigures in place and applies
    // immediately; QSV/AMF applies are HELD here while significant frames
    // are recent and flushed once the scene quiets (the open then stalls a
    // STATIC image — invisible). The governor's mirror advances at emit
    // time, so heartbeat `target_bps` shows the target while the encoder
    // briefly runs the old maxrate — an accepted, bounded skew.
    let mut deferred_bps: Option<u32> = None;
    // Seeded "a minute ago" so the first apply lands at once — through the
    // boot-safe helper: `Instant::now() - 60 s` panics on a host up for less
    // than a minute, and a session that starts that early is exactly what a
    // viewer's auto-reconnect produces after a reboot (field 2026-09-02,
    // CORPLAP-1: three dead sessions in the first minute after boot).
    let mut last_motion_at = crate::clock::instant_before(Duration::from_secs(60));
    const DEFER_QUIET: Duration = Duration::from_millis(1200);
    // rc.445 — send-queue epoch: bumped on every encoder rebuild so the
    // send task discards frames from the OLD encoder still sitting in the
    // channel. Post-rebuild the first frame is an IDR; making it wait
    // behind up to 450 ms of stale pre-rebuild frames was a visible chunk
    // of the flip gap (and a decode-order hazard shrunk to zero cost).
    let send_epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // rc.445 — remember the session's proven encoder so a rebuild skips
    // the dead cascade prefix (corplap field: an av1_nvenc tiered-open attempt
    // burned ~100-300 ms of every rebuild before av1_qsv opened).
    let mut last_encoder_name: Option<&'static str> = None;
    // P3 (2026-08-27) — background-swap state for rebuild-bound bitrate
    // applies (see the loop-top block). While a replacement opens on a
    // blocking thread the CURRENT encoder keeps producing; `swap_wanted`
    // holds the latest target (latest wins), and the cooldown bounds the
    // IDR rate adoptions can demand (each adoption ships a fresh IDR —
    // the biggest frame in the stream).
    let bg_rebuild = crate::encode::bg_rebuild_enabled();
    // FR-62 — also take rebuild-bound applies off the pump thread on a
    // CONSTRAINED session (a QSV open at <=1 Mbps blocks 1.3-2.0 s, measured).
    // Adoption stays quiet-gated below, so the IDR timing is unchanged.
    let bg_rebuild_constrained = crate::encode::bg_rebuild_constrained_enabled();
    // The rate replacement in flight, and the plan it was spawned under (FR-70
    // M3a: adopted after that plan moved, it is a stale adoption, counted apart).
    let mut pending_swap: Option<(
        tokio::task::JoinHandle<anyhow::Result<crate::encode::ffmpeg::RebuiltEncoder>>,
        Option<crate::encode::plan::SwapSpawn>,
    )> = None;
    let mut swap_wanted: Option<u32> = None;
    let mut last_swap_at = crate::clock::instant_before(Duration::from_secs(60));
    const SWAP_MIN_INTERVAL: Duration = Duration::from_secs(3);
    {
        let video_bytes_dc = video_bytes_dc.clone();
        let frames_sent = frames_sent.clone();
        let bytes_written = bytes_written.clone();
        let send_errors = send_errors.clone();
        let inflight_bytes = inflight_bytes.clone();
        let send_epoch = send_epoch.clone();
        let send_wait_us_sum = send_wait_us_sum.clone();
        let send_wait_us_max = send_wait_us_max.clone();
        let send_wait_frames = send_wait_frames.clone();
        let send_stall_us = send_stall_us.clone();
        let send_head_enqueued_us = send_head_enqueued_us.clone();
        let opener_wait_us_max = opener_wait_us_max.clone();
        let opener_bytes = opener_bytes.clone();
        let in_opener_grace = in_opener_grace.clone();
        let task_session = session_id;
        let goodput_sink = governor.goodput_sink();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            const SCTP_CHUNK_SIZE: usize = 16 * 1024;
            // FR-17 — monotonic per-frame sequence for the framing prefix.
            // Lives in the SEND TASK because that is what actually puts
            // messages on the wire: a counter kept in the pump would drift
            // from the wire the moment a frame is shed after encoding.
            let mut frame_seq: u32 = 0;
            // Measured-rate v2 — time each frame's chunked serialisation
            // and report it; the sink keeps only genuinely blocked sends
            // (≥10 ms of SCTP flow control), so buffer headroom never
            // biases the estimate. Stage-0's busy-period bracketing was
            // structurally unsatisfiable here: per-frame drain (~24 ms)
            // sits just under inter-arrival (~25 ms), so the queue dried
            // between frames and no ≥300 ms period ever formed — field
            // heartbeats read `goodput_samples: "(0, N)"` all session
            // (see `encode::goodput`).
            while let Some(first) = send_rx.recv().await {
                let mut next = Some(first);
                while let Some((epoch, enqueued_at, wire)) = next.take() {
                    let total = wire.len();
                    // rc.445 — a frame from a PREVIOUS encoder epoch is stale
                    // motion the rebuild obsoleted; drop it so the fresh IDR
                    // behind it ships immediately (still settles the ledger).
                    let stale = epoch < send_epoch.load(Relaxed);
                    // Fetch the DC fresh each frame — the same handle the pump's
                    // open-check uses. None means it closed under us (the pump's
                    // open-guard re-requests a keyframe on its side); the frame
                    // is dropped but must still leave the in-flight ledger below.
                    if !stale && let Some(dc) = video_bytes_dc.lock().await.clone() {
                        let ser_start = std::time::Instant::now();
                        // FR-74 P1b — publish the head frame's enqueue instant
                        // so the pump's gate can age it while it is on the wire.
                        send_head_enqueued_us.store(
                            enqueued_at
                                .saturating_duration_since(head_wait_epoch)
                                .as_micros() as u64
                                + 1,
                            Relaxed,
                        );
                        let mut off = 0usize;
                        let mut ok = true;
                        // Ceiling division, floored at one: a zero-length frame
                        // still counts as one message so the receiver sees a
                        // complete frame rather than an empty set it can never
                        // satisfy.
                        let chunk_count = total.div_ceil(SCTP_CHUNK_SIZE).max(1) as u16;
                        let mut chunk_idx: u16 = 0;
                        frame_seq = frame_seq.wrapping_add(1);
                        while off < total {
                            let end = (off + SCTP_CHUNK_SIZE).min(total);
                            // `wire.slice` is zero-copy (shares the Bytes
                            // buffer); FR-17 framing costs one small copy per
                            // message — 8 bytes on 16 KiB, 0.05 % — and only
                            // when the controller negotiated it.
                            let res = if chunk_framing {
                                let framed = chunk_framed(
                                    frame_seq,
                                    chunk_idx,
                                    chunk_count,
                                    &wire.slice(off..end),
                                );
                                dc.send(&bytes::Bytes::from(framed)).await
                            } else {
                                dc.send(&wire.slice(off..end)).await
                            };
                            chunk_idx = chunk_idx.saturating_add(1);
                            if let Err(e) = res {
                                let n = send_errors.fetch_add(1, Relaxed) + 1;
                                tracing::warn!(
                                    session = %task_session, %e, send_errors = n,
                                    "FFmpeg DC pump send task: DC send failed"
                                );
                                ok = false;
                                break;
                            }
                            off = end;
                        }
                        if ok {
                            frames_sent.fetch_add(1, Relaxed);
                            bytes_written.fetch_add(total as u64, Relaxed);
                            // Only a frame that reached the wire measures the
                            // pipe; the sink discards sub-threshold (headroom)
                            // sends itself.
                            goodput_sink.record(total as u64, ser_start.elapsed());
                            // P7 — queue-wait: enqueue→wire-complete. This is
                            // the transport-added latency the viewer feels;
                            // the heartbeat drains it per window.
                            let waited_us = enqueued_at.elapsed().as_micros() as u64;
                            send_wait_us_sum.fetch_add(waited_us, Relaxed);
                            send_wait_us_max.fetch_max(waited_us, Relaxed);
                            send_wait_frames.fetch_add(1, Relaxed);
                            send_stall_us.fetch_max(waited_us, Relaxed);
                            // FR-35 P3 — the opening burst as a probe.
                            if in_opener_grace.load(Relaxed) {
                                opener_wait_us_max.fetch_max(waited_us, Relaxed);
                                opener_bytes.fetch_add(total as u64, Relaxed);
                            }
                        }
                    }
                    // FR-74 P1b — nothing is on the wire between frames.
                    send_head_enqueued_us.store(0, Relaxed);
                    // Byte-budget ledger: the frame left the queue (delivered
                    // into SCTP, failed, or dropped on a closed DC). Increments
                    // strictly precede the frame's entry into the channel, so
                    // this can't underflow.
                    inflight_bytes.fetch_sub(total, Relaxed);
                    // `try_recv` takes exactly what `recv().await` would have
                    // returned immediately. Disconnected falls out here too —
                    // the outer `recv` then returns None and the task exits.
                    next = send_rx.try_recv().ok();
                }
            }
            tracing::debug!(session = %task_session, "FFmpeg DC pump send task exiting (channel closed)");
        });
    }

    loop {
        // FR-65 P0 — close out the PREVIOUS pass. Measuring here rather than at
        // the tail is what makes every `continue` path in this loop count.
        if stall_watch && let Some((started, mark)) = iter_mark.take() {
            let took = started.elapsed();
            let took_us = took.as_micros() as u64;
            if took_us > iter_us_max {
                iter_us_max = took_us;
            }
            // FR-65 P0 — judge the stall on time NOT spent WAITING FOR INPUT.
            //
            // Capture is change-driven, so a quiet screen makes the pass sleep
            // inside capture, and `capture_us` accumulates that wait. At the
            // original 250 ms bar those passes stayed invisible; at the 100 ms
            // bar #1259 introduced they became the majority of the warnings —
            // field 2026-09-03, a direct session logged seven in 45 s, every
            // one shaped `iter_ms=111 capture_ms=101.9`, i.e. 9 ms of work and
            // 102 ms of idling.
            //
            // 🔑 That is not a stall, and a watch that cries about idling is
            // one people learn to ignore — which costs exactly the signal the
            // watch exists for. The instrument's purpose is BLOCKING WORK on a
            // shared runtime; waiting for a frame is the loop idling by design,
            // and it genuinely IS idling: every capture backend hands the work
            // to a thread that owns the `!Send` device and returns a future —
            // oneshot-to-worker for scrap/drm/system-context, `Notify` for wgc.
            //
            // ⚠️ THE COST OF THIS RULE: a pathological capture — a wedged DXGI
            // duplication, an EDR filter stalling the desktop, a driver hang —
            // now CANNOT trip the stall watch, and `pump_stalls` under-counts
            // by construction. `capture_ms` is still logged here and
            // `avg_capture_ms` on the heartbeat, so it is visible to a reader,
            // but nothing ALERTS on it any more. If capture ever needs its own
            // alarm it needs its own threshold, not this one back.
            //
            // The verdict and the phase arithmetic live in
            // `encode::stall::PassTiming` — a pure type on the DEFAULT feature
            // set — because this pump is behind `ffmpeg-encoder`, so every rule
            // written here is invisible to `cargo test -p roomlerd --lib`. Both
            // subtractions below are field-paid judgements (see that module),
            // and each reads like a simplification waiting to happen.
            let pass = crate::encode::stall::PhaseAccum {
                capture_us,
                scale_us,
                encode_us,
                send_us,
                apply_us,
                open_us,
                pace_us,
                stats_us,
                ctrl_us,
                swap_us,
                gate_us,
            }
            .delta(mark, took_us);
            if pass.is_stall(stall_warn.as_micros() as u64) {
                pump_stalls += 1;
                if last_stall_log.elapsed() >= Duration::from_secs(2) {
                    last_stall_log = std::time::Instant::now();
                    // Phase deltas come from the accumulators the pump already
                    // keeps, so the breakdown costs nothing extra. An overrun
                    // whose phases all read ~0 is itself the finding: the time
                    // went somewhere still untimed — which `other_ms` computes
                    // rather than leaving for a reader to subtract by hand.
                    warn!(
                        %session_id,
                        codec_label,
                        constrained,
                        iter_ms = took.as_secs_f64() * 1000.0,
                        capture_ms = pass.capture_us as f64 / 1000.0,
                        scale_ms = pass.scale_us as f64 / 1000.0,
                        encode_ms = pass.encode_us as f64 / 1000.0,
                        send_ms = pass.send_us as f64 / 1000.0,
                        apply_ms = pass.apply_us as f64 / 1000.0,
                        open_ms = pass.open_us as f64 / 1000.0,
                        pace_ms = pass.pace_us as f64 / 1000.0,
                        stats_ms = pass.stats_us as f64 / 1000.0,
                        ctrl_ms = pass.ctrl_us as f64 / 1000.0,
                        swap_ms = pass.swap_us as f64 / 1000.0,
                        gate_ms = pass.gate_us as f64 / 1000.0,
                        other_ms = pass.other_us() as f64 / 1000.0,
                        work_ms = pass.work_us() as f64 / 1000.0,
                        dominant = ?pass.dominant_phase(),
                        target_bps = governor.applied_bps(),
                        "FFmpeg DC pump STALL — one pass exceeded the budget"
                    );
                }
            }
        }
        if stall_watch {
            iter_mark = Some((
                std::time::Instant::now(),
                crate::encode::stall::PhaseAccum {
                    capture_us,
                    scale_us,
                    encode_us,
                    send_us,
                    apply_us,
                    open_us,
                    pace_us,
                    stats_us,
                    ctrl_us,
                    swap_us,
                    gate_us,
                },
            ));
        }
        // rc.443 — owner-liveness beat, FIRST statement of the loop (see
        // the vp9 twin): a wedged blocking encode is the one failure this
        // task cannot log or clean up itself; the beat's absence is how
        // the next joiner detects it and evicts the pipeline.
        pipeline.beat();
        // rc.443 — deferred encoder drop from the error ladder (the error
        // arm holds a live `enc` borrow, so it can't touch `encoder`).
        if rebuild_after_encode_error {
            rebuild_after_encode_error = false;
            encoder = None;
            encoder_dims = None;
        }
        // P3 (2026-08-27) — background bitrate rebuild for rebuild-bound
        // encoders (QSV/AMF): the replacement opens on a blocking thread
        // while the CURRENT encoder keeps producing frames, then swaps in
        // here, between frames — no mid-drag stall, no dead air, and the
        // AIMD's rate DROPS land DURING motion as smaller frames instead
        // of production skips. Replaces the rc.445 motion-defer when
        // `bg_rebuild` is on; the defer machinery stays as the
        // kill-switch fallback (`ROOMLERD_BG_REBUILD=0`).
        // FR-65 — `handle.await` on a finished task is cheap, but `is_finished`
        // is a race: the task can complete between the check and the await, and
        // the adopt itself touches the live encoder. Timed so a swap that turns
        // out to cost something says so instead of landing in `other_ms`.
        // FR-70 M2 — the dims swap: the replacement finished opening; adopt it
        // between frames (a forced IDR rides the adoption) and let the
        // target follow the plan again. A refused or failed open drops the
        // pending state and the next frame takes the inline path, exactly
        // as before M2.
        if let Some((handle, _, _, _, _, _)) = pending_dims_open.as_ref()
            && handle.is_finished()
        {
            let (handle, dims, started, target, spawned, opened_fps) =
                pending_dims_open.take().expect("checked above");
            // FR-119 P2b-2 — whether this open was a frame-rate move, read
            // before an adoption moves `encoder_fps`.
            let fps_move = opened_fps != encoder_fps;
            let mut open_failed = false;
            let open_ms = started.elapsed().as_millis() as u64;
            match handle.await {
                Ok(Ok(rebuilt)) => {
                    // FR-70 M3a — the rate the replacement was opened at. The
                    // shadow judges it and its dims at the controller's next
                    // tick, as it does an inline open — unless the plan moved
                    // while it opened, which makes it a stale adoption.
                    let built_rate = rebuilt.maxrate_bps() as u32;
                    let built_fps = rebuilt.fps();
                    if let Some(enc) = encoder.as_mut() {
                        let from = encoder_dims.unwrap_or((0, 0));
                        let from_fps = encoder_fps;
                        if timed_apply!(enc.adopt_rebuilt(rebuilt).await) {
                            encoder_dims = Some(dims);
                            // FR-119 P2b-2 — the rate it was opened at. Going
                            // up, the capture's pace follows only now, so the
                            // encoder is never fed faster than it was built
                            // for, and never above what the grant still wants
                            // (it may have moved while this opened).
                            encoder_fps = built_fps;
                            if built_fps != from_fps {
                                fps_retry_at = None;
                            }
                            if let Some(state) = fps_state.as_mut() {
                                let pace = built_fps.min(state.want());
                                if pace != target_fps {
                                    capturer.set_target_fps(pace);
                                    target_fps = pace;
                                }
                                state.running_at(target_fps);
                            }
                            log_plan_stale_swap(
                                &session_id,
                                codec_label,
                                plan_shadow.note_dims_swap_adopted(built_rate, dims, spawned),
                            );
                            // The adopted encoder was built for the target
                            // the open was spawned with; the pin follows it
                            // from here, and the capture cap below it.
                            built_target = Some(target);
                            dims_swaps += 1;
                            send_epoch.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            video_info_sent = false;
                            governor.on_encoder_rebuilt();
                            info!(
                                %session_id,
                                codec_label,
                                from_w = from.0,
                                from_h = from.1,
                                to_w = dims.0,
                                to_h = dims.1,
                                from_fps,
                                to_fps = built_fps,
                                open_ms,
                                dims_swaps,
                                "FR-70 M2: dims swap adopted — the picture never froze"
                            );
                        } else {
                            warn!(%session_id, codec_label, "FR-70 M2: replacement refused (backend/chroma changed) — inline re-open next frame");
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!(%session_id, codec_label, %e, open_ms, "FR-70 M2: background open failed — inline re-open next frame");
                    open_failed = true;
                }
                Err(e) => {
                    warn!(%session_id, codec_label, %e, "FR-70 M2: background open task panicked — inline re-open next frame");
                    open_failed = true;
                }
            }
            // FR-119 P2b-2 — a replacement at another frame rate that did not
            // open: no frame-rate move is opened again for a while (a rate the
            // backend refuses must not cost an open on every frame), and a
            // rate above the cap is not granted again this session.
            if open_failed && fps_move {
                fps_retry_at = Some(std::time::Instant::now() + FPS_SWAP_RETRY);
                if let Some(state) = fps_state.as_mut()
                    && state.open_failed()
                {
                    warn!(
                        %session_id,
                        codec_label,
                        opened_fps,
                        "FR-119: the replacement at the granted rate did not open — back to the session's rate for this session"
                    );
                }
            }
        }
        let swap_start = std::time::Instant::now();
        if bg_rebuild {
            if let Some((handle, _)) = pending_swap.as_ref()
                && handle.is_finished()
                // FR-62 — on a CONSTRAINED session HOLD a finished rebuild
                // until the scene is quiet. Adoption ships an IDR, and a
                // mid-motion IDR through a thin pipe is precisely the
                // 2026-08-27 relay regression that gated swaps off here. The
                // open already ran off-thread, so holding costs only memory —
                // and the current encoder keeps producing meanwhile.
                && (!constrained || last_motion_at.elapsed() >= DEFER_QUIET)
            {
                let (handle, spawned) = pending_swap.take().unwrap();
                last_swap_at = std::time::Instant::now();
                match handle.await {
                    Ok(Ok(rebuilt)) => {
                        let maxrate = rebuilt.maxrate_bps();
                        // FR-70 M2 — `adopt_rebuilt` now accepts other dims
                        // (the dims swap below needs it), so the rate swap
                        // guards its own staleness here: a replacement opened
                        // for dims the session has since left is discarded.
                        // FR-119 P2b-2 — and one opened at a frame rate the
                        // session has since left (an fps swap was adopted).
                        let rebuilt_dims = rebuilt.dims();
                        let stale_dims = encoder_dims.is_some_and(|d| d != rebuilt_dims)
                            || rebuilt.fps() != encoder_fps;
                        if let Some(enc) = encoder.as_mut() {
                            if !stale_dims && timed_apply!(enc.adopt_rebuilt(rebuilt).await) {
                                // Stale pre-swap frames yield to the fresh
                                // IDR, exactly like the sync rebuild path.
                                send_epoch.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                // FR-70 M3a — judged at the controller's next
                                // tick, as an inline open is: re-rated there
                                // although the plan held is a divergence. A
                                // plan that moved while it opened (a QSV open
                                // can outlast two AIMD halvings) makes it a
                                // stale adoption instead — counted apart, not
                                // judged.
                                log_plan_stale_swap(
                                    &session_id,
                                    codec_label,
                                    plan_shadow.note_rate_swap_adopted(maxrate as u32, spawned),
                                );
                                video_info_sent = false;
                                info!(
                                    %session_id, codec_label, maxrate_bps = maxrate,
                                    "FFmpeg DC pump: background-rebuilt encoder adopted (bitrate swap, zero stall)"
                                );
                            } else {
                                tracing::debug!(
                                    %session_id, codec_label,
                                    "FFmpeg DC pump: background rebuild stale (dims/backend changed) — discarded"
                                );
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(
                            %session_id, codec_label, %e,
                            "FFmpeg DC pump: background rebuild failed — keeping current encoder"
                        );
                    }
                    Err(e) => {
                        warn!(
                            %session_id, codec_label, %e,
                            "FFmpeg DC pump: background rebuild task panicked — keeping current encoder"
                        );
                    }
                }
            }
            // Relay (field 2026-08-27): never START a swap — its adoption
            // IDR is a multi-second lump through the thin pipe; the apply
            // arms route relay rate moves through the rc.445 defer instead.
            // A transport flip mid-flight also drops any stale wanted value.
            if constrained && !bg_rebuild_constrained {
                swap_wanted = None;
            } else if pending_swap.is_none()
                && let Some(bps) = swap_wanted
                && last_swap_at.elapsed() >= SWAP_MIN_INTERVAL
            {
                swap_wanted = None;
                let spec = match encoder.as_mut() {
                    Some(e) => e.rebuild_spec(bps).await,
                    None => None,
                };
                if let Some(spec) = spec {
                    pending_swap = Some((
                        tokio::task::spawn_blocking(move || {
                            crate::encode::ffmpeg::FfmpegEncoder::open_rebuilt(spec)
                        }),
                        plan_shadow.swap_spawn(),
                    ));
                }
            }
        }
        swap_us += swap_start.elapsed().as_micros() as u64;
        // Relay-escape — twin of the VP9 pump's loop-top block: re-read the
        // selected ICE pair every TRANSPORT_RECHECK_INTERVAL and follow a
        // mid-session renomination. A flip flows into `ceiling` (recomputed
        // per frame from `constrained`) → the AIMD clamps/unclamps live.
        // P3 — a flip that PERSISTS (FlipTracker: 2 consecutive checks, ≥60 s
        // since the last rebuild) additionally rebuilds the encoder and
        // reopens the capturer at the new profile fps, so a relay→direct
        // upgrade no longer stays parked at 30 fps for the session's life.
        // The send-queue depth stays pump-lifetime (bounded channel is fixed
        // at construction — the fps/maxrate/bufsize are the levers that
        // matter). Also refresh the browser stats badge on every flip.
        if last_transport_check.elapsed() >= TRANSPORT_RECHECK_INTERVAL {
            last_transport_check = std::time::Instant::now();
            if !crate::encode::transport_is_constrained() {
                // FR-65 — a stats read, not a free predicate: it walks the
                // stats graph under locks the ICE agent and SCTP association
                // also take, so it is slowest exactly when the session is
                // busiest. Timed so it stops hiding in `other_ms`.
                let stats_start = std::time::Instant::now();
                let relay_now = current_pair_is_relay(&pc, session_id, constrained).await;
                stats_us += stats_start.elapsed().as_micros() as u64;
                if let Some(relay) = relay_now {
                    if relay != constrained {
                        constrained = relay;
                        // Badge-truth: the retry block below re-sends
                        // video-info with the new transport (single send
                        // path, no lost refresh when the control DC hiccups).
                        video_info_sent = false;
                    }
                    if rate_profile_rebuild
                        && let Some(nc) = flip_tracker.observe(relay, std::time::Instant::now())
                    {
                        let new_fps = ffmpeg_target_fps(nc);
                        // FR-119 P2b-2 — the rate without a grant follows the
                        // transport; a grant is decided again against it.
                        base_fps = new_fps;
                        if new_fps != target_fps {
                            info!(
                                %session_id,
                                codec_label,
                                old_fps = target_fps,
                                new_fps,
                                constrained = nc,
                                "FFmpeg DC pump: transport flip persisted — reopening capture + rebuilding encoder at the new rate profile"
                            );
                            target_fps = new_fps;
                            // Reopen the capture pacer at the new rate (the
                            // scrap backend sleeps to 1000/target_fps — an
                            // encoder-only rebuild would stay capped by the
                            // old pacing), then force the encoder rebuild;
                            // its first frame is a key-flagged IDR so the
                            // viewer resyncs cleanly.
                            capturer = capture::open_default_async(
                                target_fps,
                                downscale,
                                media_waiting_hook(session_id, control_dc.clone()),
                            )
                            .await;
                            encoder = None;
                            encoder_dims = None;
                            if let Some(state) = fps_state.as_mut() {
                                state.running_at(target_fps);
                            }
                        }
                    }
                }
            }
        }

        // P5 — a viewer joining/leaving the shared pipeline refreshes the
        // badge (its "viewers" count changed for everyone).
        let viewers = 1 + pipeline.follower_count();
        if viewers != last_viewers {
            last_viewers = viewers;
            video_info_sent = false;
        }
        // FR-119 P1 — a new answer re-sends `rc:video-info`, which carries it.
        // P2b-2: the state moves it on a new ask, a new rate, or a trial
        // starting or ending.
        if let Some(state) = fps_state.as_ref() {
            let told = Some((state.answer(), state.trial_running(), capturer.refresh_hz()));
            if told != fps_told {
                fps_told = told;
                video_info_sent = false;
            }
        }

        // Badge-truth — deliver `rc:video-info` reliably. Attempted whenever
        // undelivered (encoder built + 500 ms since the last try), instead of
        // the old once-at-encoder-build send: on relay sessions the control
        // DC often opens AFTER the first encoder build (Germany RTT), so the
        // one-shot send failed and the badge fell back to a transport-less
        // label — exactly the sessions where seeing "· relay" matters most
        // (field 2026-07-13). A dim rebuild or a transport flip clears
        // `video_info_sent`, so refreshes ride the same path.
        if !video_info_sent
            && last_video_info_attempt.is_none_or(|t| t.elapsed() >= VIDEO_INFO_RETRY)
            && let Some(enc_name) = encoder.as_ref().map(|e| e.name())
        {
            last_video_info_attempt = Some(std::time::Instant::now());
            // rc.199 — native dims for the browser's cap annotation; see the
            // twin block in the VP9-444 pump. Hold the badge until they're
            // known so the first delivered `rc:video-info` is never dimless.
            let (native_w, native_h) =
                unpack_dims(capture_native_dims.load(std::sync::atomic::Ordering::Relaxed));
            if native_w > 0 {
                // FR-33 P3 — see the twin block in the VP9-444 pump.
                // FR-65 — a second stats read on the same graph, added
                // 2026-09-04. It retries every 500 ms until `rc:video-info` is
                // delivered, so on a session whose control DC is slow to open
                // it runs many times; timed for the same reason as the first.
                let stats_start = std::time::Instant::now();
                let reason = lan_capture_reason(&pc, constrained).await;
                stats_us += stats_start.elapsed().as_micros() as u64;
                // FR-70 P1 — the cap in force and why, so the viewer can say
                // "Native selected, capped at 1280×800: slow link" instead of
                // a generic "relay-limited" whose advice (switch to Sharper)
                // does nothing against the slow-link profile. Present only
                // while the effective target differs from the user's; the
                // plan-change site clears `video_info_sent` so this re-sends
                // whenever the cap engages, moves or lifts.
                let cap_reason = last_dims_plan
                    .filter(|(user, effective, _)| effective != user)
                    .map(|(_, _, r)| r.as_str());
                let cap_detail = match cap_reason {
                    Some("slow-link-cap") => {
                        rate_seed.map(|s| format!("remembered {} kbps", s / 1000))
                    }
                    _ => None,
                };
                let payload = video_info_payload(
                    codec.wire_codec(),
                    enc_name,
                    true,
                    // P7 — report the ACTIVE chroma (the 4:4:4 request may
                    // have fallen back to 4:2:0 at open time).
                    if cell_444 {
                        "yuv444"
                    } else {
                        codec.wire_chroma()
                    },
                    constrained,
                    native_w,
                    native_h,
                    viewers,
                    reason,
                    cap_reason,
                    cap_detail.as_deref(),
                    capturer.arm(),
                    // FR-119 P1 — what the stream runs at, the viewer's ask
                    // if it was refused, and (P2b-2) whether a trial runs.
                    fps_state.as_ref().map(|s| {
                        s.video_info_fields()
                            + &crate::encode::frame_rate::refresh_field(capturer.refresh_hz())
                    }),
                );
                // FR-65 — the control-DC lock and send both await; the lock is
                // shared with every other control-plane writer, and a congested
                // DC makes the send slow. Timed together so neither hides.
                let ctrl_start = std::time::Instant::now();
                let cdc = control_dc.lock().await.clone();
                let delivered = match cdc {
                    Some(cdc) => cdc.send_text(payload.clone()).await.is_ok(),
                    None => false,
                };
                ctrl_us += ctrl_start.elapsed().as_micros() as u64;
                if delivered {
                    video_info_sent = true;
                    // P5 — followers' badges mirror the owner's (their
                    // stats chips describe the SAME shared stream).
                    pipeline.publish_video_info(payload);
                }
            }
        }

        // rc.93 — NO pump-side pacing floor (the rc.86→rc.92 floor sleep
        // was the fps bug). The capture backend is the single pacer:
        // scrap_backend sleeps to `1000/target_fps` internally, and the
        // SystemContext worker delivers at display rate. A second floor
        // here just halved the achieved fps and amplified idle Nones. Poll
        // continuously, exactly like the fast `media_pump`.

        // rc.111 — BACKPRESSURE GATE. Gate frame PRODUCTION on the send
        // channel having capacity. When the dedicated send task can't drain
        // the link fast enough (bandwidth-limited / relayed path), the bounded
        // channel (depth FFMPEG_SEND_QUEUE_DEPTH) fills. Pre-rc.111 the pump
        // kept capturing + encoding at full rate and DROPPED the encoded frame
        // at `try_send` (frames_dropped_backpressure) + scheduled a resync
        // keyframe — wasting GPU encode and, worse, the resync IDRs (the
        // LARGEST frames) piled MORE bytes onto an already-congested link,
        // amplifying the stall. Field DEVBOX (RTX 5090, 2560×1600):
        // capture 6 ms + encode 8 ms (fast) but ~37% of encoded frames dropped
        // + resync churn → stutter.
        //
        // Skipping at the source instead: don't capture/encode a frame we
        // can't send. Production auto-paces to the drain rate, the HEVC delta
        // chain stays continuous (no resync keyframe needed — the next encoded
        // frame just deltas from the last ENCODED one across the gap), and the
        // GPU is freed. Single-producer, so capacity()>0 here guarantees the
        // post-encode try_send below won't block; that try_send stays as a
        // safety net for the rare multi-packet frame that overflows mid-send.
        // The 2 ms yield matches the empty-poll pace (precise at the rc.92 1 ms
        // timer resolution) and only fires under genuine congestion.
        //
        // Check is_closed() FIRST: the send task only dies if its receiver is
        // dropped (or it panics). Were that to happen, capacity() stays 0 and
        // the skip-loop would livelock without ever reaching the try_send that
        // detects Closed — so exit the pump here instead, mirroring the
        // try_send Closed arm below.
        if send_tx.is_closed() {
            tracing::warn!(
                %session_id, codec_label,
                "FFmpeg DC pump: send task gone (channel closed) — exiting pump"
            );
            return;
        }
        // 2026-08-26 — the byte budget now bounds BOTH paths; direct
        // re-derives 150 ms of the AIMD's live applied target each
        // iteration (fallback: the last policy ceiling before the first
        // apply; unbounded until either exists).
        //
        // FR-59 P2 (2026-09-01) — constrained re-derives too. Its budget
        // used to be resolved ONCE against `relay_max_bps()`, which makes
        // "450 ms of queue" a claim about a nominal 3 Mbps band rather than
        // about this session's pipe: field CORPLAP-3 → neo16 over a phone
        // hotspot, 168 750 bytes of budget against a MEASURED 395 kbps link
        // is 3.4 SECONDS of standing queue, and the gate never fired while
        // viewer paint age ran 2.3-7.1 s. A held goodput estimate may only
        // ever LOWER the reference rate.
        // FR-70 M3a — the plan, computed ONCE here from the facts the pump has
        // at this instant: the point where M3b's loop will READ it (after the
        // swap adoption and the transport recheck, before the gate), and
        // compared below against each inline value as the pass computes it.
        // The one input that is itself a decision — the governor's standing
        // target — is the controller's, which M4 makes the plan's. This takes
        // the target lock and the pipeline lock once more per pass than the
        // inline reads do; M3b removes both with the reads.
        {
            let (native_w, native_h) =
                unpack_dims(capture_native_dims.load(std::sync::atomic::Ordering::Relaxed));
            let prio = priority.load(std::sync::atomic::Ordering::Relaxed);
            let caps = &plan_knobs.priority_caps;
            let hrd_pct = encoder.as_ref().map_or(plan_knobs.direct_hrd_pct, |e| {
                crate::encode::rate_profile::hrd_pct_for(e.name(), plan_knobs.direct_hrd_pct)
            });
            let inputs = crate::encode::plan::PlanInputs {
                constrained,
                target_fps,
                paced_fps: governor.paced_fps(),
                pipe_bps: governor.pipe_bps(std::time::Instant::now(), constrained),
                ceiling_reference_bps: last_ceiling_bps,
                hrd_pct,
                target_bps: governor.applied_bps(),
                dims: crate::encode::policy::DimsInputs {
                    native_w,
                    native_h,
                    merged_target: pipeline.merged_target(*target_resolution.lock().unwrap()),
                    merged_priority_cap: pipeline.merged_priority_cap_by(
                        crate::encode::priority_relay_cap_for(prio, constrained, caps),
                        |p| crate::encode::priority_relay_cap_for(p, constrained, caps),
                    ),
                    slow_link_cap: slow_link_profile.map(|p| p.max_long_edge),
                    refined: idle_refine.refined(),
                    refined_cap: plan_knobs.refined_cap,
                    soft_cap: governor.auto_res_cap(),
                },
            };
            plan_shadow.produce(&inputs, &plan_knobs);
        }
        let queue_budget = if constrained {
            // FR-59 — the WIDENED pipe estimate, not the goodput-only one.
            // On a link where the agent's own sends never block there is no
            // goodput estimate at all (field 2026-09-02: `None` in every
            // window of a 47-window run at 150 kbit), and this gate could
            // never engage while P1's floor relief — reading the same
            // evidence through `pipe_bps` — did.
            let measured = governor.pipe_bps(std::time::Instant::now(), constrained);
            let reference = crate::encode::rate_profile::constrained_queue_reference_bps(
                crate::encode::relay_max_bps(),
                measured,
                constrained_queue_measured,
            );
            if reference == crate::encode::relay_max_bps() {
                constrained_queue_budget
            } else {
                crate::encode::rate_profile::constrained_queue_budget_bytes(reference)
            }
        } else {
            // FR-74 P1 — the path's ceiling, not the applied target: a budget
            // denominated in the applied target shrank with every cut and
            // then tripped on a single text frame (six cuts to 2.24 Mbps, then
            // 2–3.7 Mbps for minutes on CORPLAP-3, 2026-09-06). Pre-first-pass
            // the ceiling is still 0, which `direct_queue_budget_bytes` reads
            // as "no gate yet".
            crate::encode::rate_profile::direct_queue_budget_bytes(last_ceiling_bps)
        };
        let inflight_now = inflight_bytes.load(std::sync::atomic::Ordering::Relaxed);
        // FR-74 P1b — on a direct path the byte budget is the MEASURED wait's
        // call below the encoder's own reservoir: the 0.4.77 read (CORPLAP-3,
        // AV1, 2026-09-07) tripped the P1 budget on a scroll burst the wire
        // was draining at ≤ 20 ms of viewer age and cut the ceiling twice for
        // it. The wait is the larger of the EMA of completed frames' waits and
        // the live age of the frame on the wire (a stalled pipe completes
        // nothing, so the EMA alone would read stale-low while the queue grew).
        let (hard_budget, measured_wait_ms) = if constrained {
            (queue_budget, 0.0)
        } else {
            {
                let sum_now = send_wait_us_sum.load(std::sync::atomic::Ordering::Relaxed);
                let frames_now = send_wait_frames.load(std::sync::atomic::Ordering::Relaxed);
                let frames = frames_now.saturating_sub(gate_sw_frames_last);
                if frames > 0 {
                    let avg_ms =
                        sum_now.saturating_sub(gate_sw_sum_last) as f64 / frames as f64 / 1000.0;
                    direct_wait_ema_ms = 0.7 * direct_wait_ema_ms + 0.3 * avg_ms;
                }
                gate_sw_sum_last = sum_now;
                gate_sw_frames_last = frames_now;
            }
            let head = send_head_enqueued_us.load(std::sync::atomic::Ordering::Relaxed);
            let head_wait_ms = if head == 0 {
                0.0
            } else {
                head_wait_epoch
                    .elapsed()
                    .as_micros()
                    .saturating_sub((head - 1) as u128) as f64
                    / 1000.0
            };
            let hrd_pct = encoder
                .as_ref()
                .map(|e| crate::encode::ffmpeg::encoder::open_hrd_pct(e.name(), false))
                .unwrap_or_else(crate::encode::rate_profile::direct_hrd_pct);
            (
                crate::encode::rate_profile::direct_queue_hard_budget_bytes(
                    last_ceiling_bps,
                    hrd_pct,
                ),
                direct_wait_ema_ms.max(head_wait_ms),
            )
        };
        let byte_gate = if constrained {
            inflight_now >= queue_budget
        } else {
            crate::encode::rate_profile::direct_gate_trips(
                inflight_now,
                queue_budget,
                hard_budget,
                measured_wait_ms,
                direct_lag_bound_ms,
            )
        };
        // FR-70 M3a — the budget triple and the verdict, against the plan. On
        // a constrained path the pump's hard budget IS its soft one and its
        // gate has no wait bound (the triple reads `(b, b, 0)`), which is what
        // lets one gate function serve both transports.
        log_plan_divergences(
            &session_id,
            codec_label,
            plan_shadow.check_budget(
                queue_budget,
                hard_budget,
                if constrained { 0 } else { direct_lag_bound_ms },
            ),
        );
        log_plan_divergences(
            &session_id,
            codec_label,
            plan_shadow.check_gate_verdict(inflight_now, measured_wait_ms, byte_gate),
        );
        // FR-35 P3b — the opener is draining whenever the ledger dips below half
        // the budget; reset the stuck timer so only a genuinely pinned queue
        // (inflight held high, not falling) is read as "seed too hot".
        if inflight_now < queue_budget / 2 {
            grace_congested_since = None;
        }
        // FR-65 — the gate arm `continue`s BEFORE capture, so a pass that takes
        // it reports `capture_ms=0` and `encode_ms=0` and every millisecond it
        // spends lands in `other_ms`. That is exactly the shape CORPLAP-2
        // produced on 2026-09-04 (662 ms and 782 ms passes with both at zero),
        // and it is why this whole block is timed rather than just its sleep.
        let gate_start = std::time::Instant::now();
        if send_tx.capacity() == 0 || pipeline.followers_congested() || byte_gate {
            if byte_gate && !constrained && !direct_gate_logged {
                direct_gate_logged = true;
                info!(
                    %session_id,
                    codec_label,
                    inflight = inflight_now,
                    budget = queue_budget,
                    hard_budget,
                    measured_wait_ms = format_args!("{measured_wait_ms:.1}"),
                    "FFmpeg DC pump: direct byte-budget gate engaged (bounding queue lag; first time this session)"
                );
            }
            frames_skipped_backpressure += 1;
            // FR-119 P2b-2 — a frame not taken for the link is no evidence
            // about this host's rate.
            if let Some(state) = fps_state.as_mut() {
                state.pause();
            }
            // Phase B — a FULL send channel is the real DC backpressure signal.
            // Drive the multiplicative decrease HERE, before the `continue`, so
            // it runs DURING sustained congestion (the VP9 pump's rc.171
            // starvation-fix rationale) instead of never firing. Apply to the
            // live encoder so the next frame that gets through is already smaller.
            // P5 — a congested FOLLOWER gates production the same way: the
            // shared stream paces to the slowest link (the pre-encode floor;
            // per-viewer delta drops would break that viewer's ref chain).
            // The BYTE budget (third arm, both transports since 2026-08-26)
            // is the same congestion semantic judged in bytes: frame-count
            // depth bounds nothing when native motion frames are 20× rung
            // size, and the queue it allows is pure viewer lag.
            // FR-35 P3b — but distinguish "burst draining" from "seed too hot".
            // This gate `continue`s before the grace-end block far below, so a
            // persistently-saturated queue would keep the grace open (and the
            // AIMD suppressed) for the whole backstop window. If the queue has
            // been pinned longer than a legit opener takes to drain, end the
            // grace NOW so the same-iteration `bp_applied` cuts the live rate.
            if constrained && !opener_grace_done {
                match grace_congested_since {
                    Some(t) if t.elapsed() >= OPENER_GRACE_STUCK => {
                        opener_grace_done = true;
                        in_opener_grace.store(false, std::sync::atomic::Ordering::Relaxed);
                        info!(
                            %session_id,
                            codec_label,
                            stuck_ms = t.elapsed().as_millis() as u64,
                            grace_bp_skips,
                            "FR-35 opener grace cut short — the seed does not fit this path; releasing the AIMD to cut"
                        );
                    }
                    Some(_) => {}
                    None => grace_congested_since = Some(std::time::Instant::now()),
                }
            }
            // FR-35 P3 — inside the opener grace the skips are the opening
            // burst draining, not congestion: skip the frame, keep the AIMD.
            let bp_applied = if constrained && !opener_grace_done {
                grace_bp_skips += 1;
                None
            } else {
                governor.on_backpressure_skip(std::time::Instant::now())
            };
            if let Some(applied) = bp_applied
                && let Some(enc) = encoder.as_mut()
            {
                // rc.445 — congestion here means motion almost surely;
                // rebuild-bound encoders swap in the background (P3,
                // DIRECT only — on a relay a swap's IDR is a multi-second
                // lump through the thin pipe; field 2026-08-27, CORPLAP-3 +
                // CORPLAP-2 got WORSE) or defer (see `deferred_bps`).
                if enc.supports_dynamic_bitrate() {
                    timed_apply!(enc.set_bitrate(applied.bps).await);
                } else if bg_rebuild && !constrained {
                    swap_wanted = Some(applied.bps);
                } else {
                    deferred_bps = Some(applied.bps);
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
            gate_us += gate_start.elapsed().as_micros() as u64;
            continue;
        }
        // Not congested: the gate cost only its own predicate, but record it so
        // the accounting is complete on every pass, not only on the skips.
        gate_us += gate_start.elapsed().as_micros() as u64;

        // P5 (FR-1) — cadence pacing: when the HW encoder can't hold
        // target_fps, consume frames on an even grid at the sustainable
        // rate instead of letting the capture layer drop ~33 % at random
        // phases (the alternating 16/33 ms motion deltas = the residual
        // "steps" judder). Latest-wins capture keeps freshness; slots are
        // scheduled from consumption start, so an encode longer than the
        // interval degrades to natural (still even) cadence, never a
        // burst.
        // FR-70 M3a — the cadence, against the plan.
        log_plan_divergences(
            &session_id,
            codec_label,
            plan_shadow.check_fps(governor.paced_fps().unwrap_or(target_fps)),
        );
        if let Some(paced) = governor.paced_fps() {
            let interval = Duration::from_micros(1_000_000 / paced.max(1) as u64);
            let now = std::time::Instant::now();
            if let Some(due) = pace_due
                && due > now
            {
                // FR-65 — at a paced 2 fps this is ~500 ms of a single pass.
                // Timed AND excluded from `work_us` (see `encode::stall`): it
                // is the loop idling on purpose, exactly like a capture wait,
                // and counting it as work would re-create the warning storm the
                // capture rule removed.
                let pace_start = std::time::Instant::now();
                tokio::time::sleep(due - now).await;
                pace_us += pace_start.elapsed().as_micros() as u64;
            }
            pace_due = Some(std::time::Instant::now() + interval);
        } else {
            pace_due = None;
        }

        // Capture one frame; on transient failure, reuse the last
        // good one as a keepalive so the browser decoder doesn't
        // pause. ScreenCapture's method is `next_frame() -> Result<
        // Option<Frame>>`, not Iterator::next — matches the pattern
        // used by `media_pump_vp9_444_dc` at line ~1741.
        let capture_start = std::time::Instant::now();
        let next = capturer.next_frame().await;
        capture_us += capture_start.elapsed().as_micros() as u64;
        // P7c — set on the real-capture arm; the idle-refine BYTES leg is
        // fed AFTER encode (where the frame's wire cost is known), never
        // for keepalive re-encodes. P8a — `area_judged` marks a frame the
        // AREA leg already judged at capture time (tracked damage over the
        // floor); the bytes leg skips those (one note per frame).
        let mut is_real_frame = false;
        let mut area_judged = false;
        // Did EITHER significance leg count this frame as motion? A real
        // frame that stays false is QUIET EVIDENCE and feeds the refine
        // up-flip tick post-encode (field corplap-3: GDI/scrap-class
        // backends return a frame on EVERY poll — frames_empty=0 — so the
        // keepalive arm never ran and refine was structurally inert).
        let mut frame_significant = false;
        let frame: std::sync::Arc<crate::capture::Frame> = match next {
            Ok(Some(f)) => {
                let arc = std::sync::Arc::new(f);
                last_good_frame = Some(arc.clone());
                // FR-101 P4b-2 — a real capture, never a keepalive: the idle limit's
                // screen leg (free unless a live session has a limit).
                crate::session_idle::note_frame(&arc);
                last_capture_at = std::time::Instant::now();
                capture_wait.on_frame();
                frames_captured += 1;
                is_real_frame = true;
                // Motion continues — the settle gate counts the episode.
                settle_kf.note_real_frame();
                // P8a — AREA significance leg, judged at CAPTURE time on
                // the pre-downscale frame (native coordinate space; also
                // upstream of the viewer-rate divisor skip, so tracked
                // motion counts even when this frame is later shed).
                // Area is rung-invariant — the leg that cannot oscillate.
                // P8a-2 — tracked frames NEVER take the bytes leg: only
                // MAJOR damage (≥ ~40 % of the frame, sustained) restores
                // the cap; smaller damage — typing, popups, windowed
                // terminal scrolls, PiP video — stays at native ("sharp
                // all the time"; the encoder's maxrate + AIMD own load).
                if let Some(area_pm) = arc
                    .damage
                    .area_permille(arc.width as u64 * arc.height as u64)
                {
                    area_judged = true;
                    if idle_refine.area_major(area_pm) {
                        frame_significant = true;
                        if let Some(flip) =
                            idle_refine.note_real_frame_area(std::time::Instant::now(), area_pm)
                        {
                            info!(
                                %session_id,
                                codec_label,
                                ?flip,
                                area_pm,
                                "idle refine: motion burst (damage area) — restoring resolution cap"
                            );
                        }
                    }
                }
                arc
            }
            Ok(None) => {
                // No new frame this tick (DXGI only fires on screen change).
                // Once idle ≥ IDLE_KEEPALIVE, re-encode the last good frame so
                // the browser decoder doesn't pause.
                frames_empty += 1;
                // FR-93 P3e — the display is off (P5f: this user's session is
                // in the background): the controller is told, and no keepalive
                // re-encodes the last frame (a decoded frame would clear the
                // viewer's notice).
                if capture_wait.hold(capturer.waits_for(), session_id, &control_dc) {
                    // P5f — and the pump stays abortable. Mutter's frame wait
                    // blocks in place and never yields, so without this the
                    // loop never reached an await that yields: a viewer that
                    // left during the wait left its pump running, holding
                    // the screencast (GNOME's sharing indicator up) and the
                    // shared pipeline, which took each new viewer on as a
                    // follower of a pump that sent nothing.
                    tokio::task::yield_now().await;
                    continue;
                }
                if last_capture_at.elapsed() >= IDLE_KEEPALIVE
                    && let Some(ref f) = last_good_frame
                {
                    last_capture_at = std::time::Instant::now();
                    // rc.187 (burst-gated) — the FIRST keepalive after a real
                    // motion burst settles is a KEYFRAME. `keyframe_requested`
                    // is consumed by the force block below (which also exempts
                    // it from the decode frame-skip), so this settled frame
                    // lands as a fresh IDR any viewer can decode standalone —
                    // fixing the "window shows the old position after a drag"
                    // freeze without paying an IDR for every caret blink.
                    //
                    // FR-10 — SUPPRESSED on thrifty constrained sessions: on a
                    // reliable ordered DC the settle-IDR is a quality refresh,
                    // not a correctness need (the request-driven resync path
                    // stays), and on a ~2 Mbps relay it was a single ~300 KB
                    // frame ≈ 1.2-1.5 s lump per drag-pause. The gate is
                    // still consumed so episode accounting stays identical.
                    if let Some(burst) = settle_kf.should_fire_on_settle(std::time::Instant::now())
                    {
                        if constrained && relay_idr_thrift {
                            settle_kf_suppressed += 1;
                        } else {
                            keyframe_requested.store(true, std::sync::atomic::Ordering::SeqCst);
                            tracing::info!(
                                %session_id,
                                codec_label,
                                burst,
                                "idle-settle keyframe (motion burst ended)"
                            );
                        }
                    }
                    // P7 — idle-refine tick. Eligible = a cap below native is
                    // actually clamping, the controller left resolution at
                    // Native (an explicit rc:resolution pick is the user's —
                    // never overridden), and the dial/transport scope allows
                    // it. On Up, the cap application below lifts for THIS
                    // keepalive frame — the rebuild ships the settled screen
                    // as a crisp native IDR. The settle-KF above composes:
                    // it resyncs the CURRENT rung at settle+60 ms; the
                    // refined native IDR follows ~1 s later.
                    //
                    // P7b — every term is MERGE-AWARE (field 2026-08-20,
                    // winhost-b: owner=Sharper + follower=Smoother — the P5
                    // floor-merge applied the follower's 1024 cap while
                    // eligibility read only the owner's dial, so the shared
                    // stream parked at the low rung with refine dead). The
                    // clamp check uses the MERGED cap (what the frame path
                    // actually applies), the Native check uses the MERGED
                    // target (a FOLLOWER's explicit pick must also block),
                    // and the scope check requires every CAP-CONTRIBUTING
                    // dial to be refine-applicable. Single-viewer pipelines
                    // reduce exactly to the pre-P7b expression.
                    // P8b — the clamp/Native terms now come from the SAME
                    // `plan_dims` the frame path executes (structurally
                    // un-divergeable); the scope term stays the P7b
                    // merged-dial check.
                    {
                        let now = std::time::Instant::now();
                        let prio = priority.load(std::sync::atomic::Ordering::Relaxed);
                        let (nw, nh) = unpack_dims(
                            capture_native_dims.load(std::sync::atomic::Ordering::Relaxed),
                        );
                        let plan =
                            crate::encode::policy::plan_dims(&crate::encode::policy::DimsInputs {
                                native_w: nw,
                                native_h: nh,
                                merged_target: pipeline
                                    .merged_target(*target_resolution.lock().unwrap()),
                                merged_priority_cap: pipeline.merged_priority_cap(
                                    crate::encode::priority_relay_cap(prio, constrained),
                                    constrained,
                                ),
                                slow_link_cap: slow_link_profile.map(|p| p.max_long_edge),
                                refined: idle_refine.refined(),
                                refined_cap: crate::encode::idle_refine_cap_long_edge(),
                                soft_cap: governor.auto_res_cap(),
                            });
                        // FR-59 P8 — never while the slow-link profile is
                        // in force: a lift to native IS the mid-session
                        // rung flip P5 was resolved once to avoid, and on
                        // the pipe that engaged it the native IDR is 1-2 s
                        // of link time (field 2026-09-02: 1280×800 ↔
                        // 1920×1200 on every heartbeat, one IDR each way).
                        let eligible = nw > 0
                            && plan.capped_below_native
                            && plan.user_native
                            && pipeline.merged_refine_eligible(prio, constrained)
                            && slow_link_profile.is_none();
                        if let Some(flip) = idle_refine.on_keepalive(eligible, constrained, now) {
                            info!(
                                %session_id,
                                codec_label,
                                ?flip,
                                native_w = nw,
                                native_h = nh,
                                "idle refine: scene settled — lifting resolution cap \
                                 (crisp native IDR incoming)"
                            );
                        }
                    }
                    f.clone()
                } else {
                    // rc.99 — pace empty polls with a short sleep before
                    // retrying. rc.93 removed the top-of-loop floor (correctly
                    // — it capped the Some-rate) AND made this `continue`
                    // immediately, on the assumption the capture backend self-
                    // paces. That's TRUE for scrap (internal target_frame_period
                    // sleep) but FALSE for the SystemContext worker, which has
                    // NO pacer: the pump then spins MILLIONS of empty oneshot
                    // round-trips/session (frames_empty ≫ frames_encoded),
                    // saturating the runtime so the real-frame round-trip
                    // latency spikes intermittently → fps swings (field
                    // DEVBOX 2560×1600 SystemContext: cap 7↔117ms,
                    // fps 9↔67, stuttery). A 2 ms sleep paces empties to
                    // ~500/s (vs millions) — precise at 1 ms timer resolution
                    // (win_timer rc.92) — WITHOUT capping the Some-rate (this
                    // only fires when there's no new frame), so it does NOT
                    // regress the rc.93 fps win. ~2 ms adds negligible
                    // frame-catch latency vs a 60 Hz (16 ms) source.
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    continue;
                }
            }
            Err(e) => {
                // P3 — this arm used to bare-`continue`: a DEAD capturer
                // (mode change mid-frame, DDA seat lost to another session)
                // busy-spun the loop at full speed logging once per
                // iteration, and never recovered. Reopen like the other
                // pumps, under the same bounded backoff.
                //
                // FR-93 P6c — the track pump's rule: stopped at the screen
                // ends the session (this pipeline's followers first).
                if capture::stopped_at_screen(&e) {
                    match end_stopped_at_screen(session_id, &rc_sessions, Some(&pipeline)).await {}
                }
                tracing::warn!(%session_id, codec_label, %e, "FFmpeg DC pump: capture error — rebuilding capturer");
                tokio::time::sleep(reopen_backoff.delay()).await;
                capturer = capture::open_default_async(
                    target_fps,
                    downscale,
                    media_waiting_hook(session_id, control_dc.clone()),
                )
                .await;
                // FR-119 P2b-2 — an open applies its own gate; a granted rate
                // above the session's base runs the granted one.
                if fps_state.is_some() && target_fps > base_fps {
                    capturer.set_target_fps(target_fps);
                }
                continue;
            }
        };

        // rc.96 — apply the controller-chosen resolution (`rc:resolution`),
        // bringing the FFmpeg pump to parity with `media_pump_vp9_444_dc`
        // (which already does this). `Native` is a passthrough; `Fixed`
        // downscales (CPU box filter) before encode, so the encoder rebuilds
        // for the smaller dims via the dim-change check below. This shrinks
        // the encode + the wire bytes + the browser-side decode load.
        //
        // NOTE: this runs AFTER the full-resolution capture, so on a host
        // whose bottleneck is the capture/duplication rate (e.g. a 4K panel
        // on a weak iGPU — frames_empty ≫ frames_encoded) it does NOT raise
        // fps; it's a bandwidth/quality lever, not a capture-fps fix. Hosts
        // that are genuinely encode-bound do gain fps from the smaller encode.
        // Publish the native (pre-downscale) dims so the cursor pump can
        // map the OS cursor into the encoded frame's pixel space (rc.183).
        // `frame` here is still native — apply_target_resolution is what
        // downscales it. On HW paths (DownscalePolicy::Never) this is the
        // true monitor resolution; that's every host that hits the DC
        // video pumps in the field.
        let (cap_native_w, cap_native_h) = frame.native_dims();
        let native_dims_packed = pack_dims(cap_native_w, cap_native_h);
        capture_native_dims.store(native_dims_packed, std::sync::atomic::Ordering::Relaxed);
        // P8b — the rung decision moved into `encode::policy::plan_dims`:
        // one composition (P5 merges → refine lift → soft/hard tiers) that
        // BOTH this frame path and the idle-refine eligibility hook consume,
        // so the two can never diverge again (the P7b bug class). Semantics
        // preserved verbatim from rc.190/rc.199/P7: merged target + merged
        // Priority cap; while refined the cap is REPLACED by the refined
        // rung; the encode-bound auto rung fills the soft slot (an explicit
        // controller pick bypasses it by construction).
        let user_target = pipeline.merged_target(*target_resolution.lock().unwrap());
        let dims_plan = crate::encode::policy::plan_dims(&crate::encode::policy::DimsInputs {
            native_w: cap_native_w,
            native_h: cap_native_h,
            merged_target: user_target,
            merged_priority_cap: pipeline.merged_priority_cap(
                crate::encode::priority_relay_cap(
                    priority.load(std::sync::atomic::Ordering::Relaxed),
                    constrained,
                ),
                constrained,
            ),
            // FR-59 P5 — the slow-link profile's long-edge cap. `plan_dims`
            // merges it with the dial's by `min` (a dial that already asked
            // for fewer pixels keeps them) and an explicit operator pick
            // still wins by the existing rules; it is carried separately so
            // the rung can be attributed (FR-70 P1 — before, a profile cap
            // logged and displayed as the dial's).
            slow_link_cap: slow_link_profile.map(|p| p.max_long_edge),
            refined: idle_refine.refined(),
            refined_cap: crate::encode::idle_refine_cap_long_edge(),
            soft_cap: governor.auto_res_cap(),
        });
        let plan_target = dims_plan.effective_target;
        // FR-70 M3a — the geometry, against the plan: the dims this frame's
        // target produces, pin-independent (the pin below is the loop's — which
        // encoder is live — not the plan's).
        log_plan_divergences(
            &session_id,
            codec_label,
            plan_shadow.check_dims(crate::encode::resample::target_dims(
                frame.native_dims(),
                plan_target,
            )),
        );
        // FR-119 P2b-2 — the frame rate: decided again when the ask, the base
        // rate, the transport or the class (capture backend, encoder,
        // geometry) moves, and once a second for the pipe's belief. The
        // capture runs at the lower of what the grant wants and what the live
        // encoder was built for: a move down slows it at once, a move up waits
        // for the replacement below, so the encoder is never fed faster than
        // it was built for.
        if let Some(state) = fps_state.as_mut()
            && let (Some(enc), Some(enc_dims)) = (encoder.as_ref(), encoder_dims)
        {
            let asked = pipeline.merged_fps_ask(viewer_report.fps_ask());
            let on = (
                asked,
                base_fps,
                constrained,
                capturer.backend(),
                capturer.refresh_hz(),
                enc.name(),
                enc_dims,
            );
            if fps_decided_on != Some(on) || fps_decided_at.elapsed() >= FPS_DECIDE_EVERY {
                fps_decided_on = Some(on);
                fps_decided_at = std::time::Instant::now();
                let above = asked.filter(|&a| a > base_fps);
                // The ceiling the asked rate would get here, by the chain the
                // replacement opens at, against what the pipe pushed back.
                let pipe_covers = above.is_none_or(|a| {
                    let at = crate::encode::policy::rate_plan(
                        enc_dims.0,
                        enc_dims.1,
                        cap_native_w,
                        cap_native_h,
                        a,
                        constrained,
                        codec.label(),
                        cell_444,
                        governor.encode_factor(),
                        matches!(
                            dims_plan.reason,
                            crate::encode::policy::RungReason::UserPick
                        ),
                        crate::encode::dial_rate_factor_pct(
                            priority.load(std::sync::atomic::Ordering::Relaxed),
                        ),
                    );
                    crate::encode::frame_rate::pipe_covers(
                        governor.belief_bps(std::time::Instant::now()).2,
                        at.ceiling_bps,
                    )
                });
                let class = crate::encode::frame_rate::ClassKey {
                    backend: capturer.backend().to_string(),
                    // P2b-3 — unknown is 0, and decides nothing.
                    refresh_hz: capturer.refresh_hz().unwrap_or(0),
                    encoder: enc.name().to_string(),
                    long_edge: crate::encode::frame_rate::long_edge_bucket(enc_dims.0, enc_dims.1),
                    fps: asked.unwrap_or(base_fps),
                };
                let inputs = crate::encode::frame_rate::GrantInputs {
                    asked,
                    cap: base_fps,
                    constrained,
                    refresh_hz: capturer.refresh_hz(),
                    denied: above.is_some_and(|a| {
                        crate::encode::frame_rate::fps_denied(&fps_deny, enc.name(), a)
                    }),
                    verdict: None,
                    pipe_covers,
                };
                if state.decide(inputs, class) {
                    info!(
                        %session_id,
                        codec_label,
                        ?asked,
                        base_fps,
                        want = state.want(),
                        refused = ?state.answer().refused,
                        backend = capturer.backend(),
                        encoder = enc.name(),
                        "FR-119: frame rate decided"
                    );
                }
            }
            let pace = state.want().min(encoder_fps);
            if pace != target_fps {
                capturer.set_target_fps(pace);
                target_fps = pace;
                state.running_at(pace);
            }
        }
        // FR-70 M2 — the make-before-break is decided from the PLAN, never
        // from a frame: a live encoder built for `built_target` that the
        // plan has moved away from gets its replacement opened in the
        // background NOW, at the dims the plan's target will produce, while
        // this and every later frame keep being served at the old dims —
        // the target is pinned to `built_target` from this very pass, so
        // the capture cap never moves ahead of the swap. The fourth field
        // contact (CORPLAP-3 on 0.4.74) showed why a frame-driven trigger
        // could not be made right: after an upward swap the frames still in
        // flight carried the OLD cap, and reading a frame's dims as the plan
        // opened a replacement toward those stale dims, then fell into two
        // inline re-opens on top of a swap that had just been adopted. A
        // backend that cannot rebuild off the frame path leaves the pin
        // unset and takes the inline open below, exactly as before M2.
        //
        // FR-119 P2b-2 — a frame-rate move rides the same make-before-break,
        // at the live dims and the same pinned target, and a dims move opened
        // meanwhile carries the wanted rate too. With `fps-high` off the
        // wanted rate is the live encoder's, so nothing here changes.
        let want_fps = fps_state.as_ref().map_or(encoder_fps, |s| s.want());
        if let Some(built) = built_target
            && pending_dims_open.is_none()
            && let Some(enc_dims) = encoder_dims
        {
            let plan_dims = crate::encode::resample::target_dims(frame.native_dims(), plan_target);
            let dims_move = plan_target != built && plan_dims != enc_dims;
            let fps_move = want_fps != encoder_fps
                && fps_retry_at.is_none_or(|t| std::time::Instant::now() >= t);
            let (to_dims, to_target) = if dims_move {
                (plan_dims, plan_target)
            } else {
                (enc_dims, built)
            };
            // A dims move carries the wanted rate only when a frame-rate move
            // is due as well; otherwise the live encoder's, as before.
            let to_fps = if fps_move { want_fps } else { encoder_fps };
            if (dims_move || fps_move)
                && let Some(enc) = encoder.as_mut()
            {
                // FR-70 M3a.2 — open the replacement at the ceiling of the
                // dims it is opened FOR. `last_ceiling_bps` is the old
                // frame's (M2's pin holds frames at the old dims until the
                // swap), so a move DOWN opened the replacement at a rate the
                // controller clamped on its first tick after adoption — the
                // shadow's first genuine finding (2026-10-21, `hevc_vaapi`:
                // opened at 25 M, 8 M one tick later, a second open on a
                // rebuild-bound backend). The same chain the per-frame
                // ceiling runs below, for the target dims; the learner is
                // ASKED (`ceiling_for`), never told, so its nominal stays the
                // frame actually encoded. FR-119 P2b-2: and at the rate it is
                // opened for, by the rate law above 60.
                let target_rate = crate::encode::policy::rate_plan(
                    to_dims.0,
                    to_dims.1,
                    cap_native_w,
                    cap_native_h,
                    to_fps,
                    constrained,
                    codec.label(),
                    cell_444,
                    governor.encode_factor(),
                    matches!(
                        dims_plan.reason,
                        crate::encode::policy::RungReason::UserPick
                    ),
                    crate::encode::dial_rate_factor_pct(
                        priority.load(std::sync::atomic::Ordering::Relaxed),
                    ),
                );
                let target_ceiling = crate::encode::shared_split_ceiling_bps(
                    governor.ceiling_for(target_rate.ceiling_bps, constrained),
                    (1 + pipeline.follower_count()) as u32,
                    crate::encode::area_min_bitrate_bps(to_dims.0, to_dims.1, constrained),
                    constrained,
                    crate::encode::shared_rate_split_enabled(),
                );
                let bps = crate::encode::policy::replacement_open_bps(
                    target_ceiling,
                    governor.applied_bps(),
                    governor.open_seed_bps(),
                );
                if let Some(spec) = enc.rebuild_spec_at(to_dims.0, to_dims.1, to_fps, bps).await {
                    if dims_move {
                        info!(
                            %session_id,
                            codec_label,
                            from_w = enc_dims.0,
                            from_h = enc_dims.1,
                            to_w = to_dims.0,
                            to_h = to_dims.1,
                            from_fps = encoder_fps,
                            to_fps,
                            "FR-70 M2: dims change — opening the replacement in the background, serving at the old dims meanwhile"
                        );
                    } else {
                        info!(
                            %session_id,
                            codec_label,
                            from_fps = encoder_fps,
                            to_fps,
                            "FR-119: frame-rate change — opening the replacement in the background, serving at the old rate meanwhile"
                        );
                    }
                    pending_dims_open = Some((
                        tokio::task::spawn_blocking(move || {
                            crate::encode::ffmpeg::FfmpegEncoder::open_rebuilt(spec)
                        }),
                        to_dims,
                        std::time::Instant::now(),
                        to_target,
                        plan_shadow.swap_spawn(),
                        to_fps,
                    ));
                }
            }
        }
        // While a replacement opens, the capturer's cap and the resampler
        // stay on the dims the live encoder was built for; the plan's
        // target takes over at the swap.
        let effective_target = match (&pending_dims_open, built_target) {
            (Some(_), Some(pinned)) => pinned,
            _ => plan_target,
        };
        // Phase B — hand the effective box to the capture backend so a
        // GPU-capable one can scale BEFORE the readback (applies from the
        // next frame; the CPU resample below stays the fallback + truth).
        // Sits right after the pin, which already knows about a swap
        // spawned on this pass, so the capturer never moves ahead of the
        // live encoder. A cap change leaves a frame or two in flight at the
        // old dims; the stale-frame skip below absorbs them.
        let backend_cap = match effective_target {
            TargetResolution::Native => None,
            TargetResolution::Fixed { width, height } => Some((width, height)),
        };
        if backend_cap != last_output_cap {
            last_output_cap = backend_cap;
            capturer.set_output_cap(backend_cap);
            stale_skips_left = STALE_FRAME_SKIPS;
        }
        // Quiet-tick eligibility (same terms as the keepalive arm, from the
        // SAME plan — see the post-encode site). Computed here where the
        // plan and the frame's native dims are in scope.
        let refine_eligible_now = frame.width > 0
            && dims_plan.capped_below_native
            && dims_plan.user_native
            && pipeline.merged_refine_eligible(
                priority.load(std::sync::atomic::Ordering::Relaxed),
                constrained,
            )
            // FR-59 P8 — same gate as the keepalive arm: no refine lift
            // while the slow-link profile is in force.
            && slow_link_profile.is_none();
        let plan_key = (user_target, effective_target, dims_plan.reason);
        if last_dims_plan != Some(plan_key) {
            if effective_target != user_target {
                info!(
                    %session_id,
                    codec_label,
                    ?user_target,
                    ?effective_target,
                    reason = dims_plan.reason.as_str(),
                    native_w = cap_native_w,
                    native_h = cap_native_h,
                    "FFmpeg DC pump: agent-side relay resolution cap engaged"
                );
            }
            last_dims_plan = Some(plan_key);
            // FR-70 P1 — the badge carries the cap and its reason; refresh it.
            video_info_sent = false;
        }
        // P7 — snapshot the native dims before the downscale shadows `frame`;
        // the CQ bias at the rebuild site is keyed on encode-vs-native area.
        let (native_w, native_h) = frame.native_dims();
        let pre_scale_dims = (frame.width, frame.height);
        let scale_start = std::time::Instant::now();
        let frame = crate::encode::resample::apply_target_resolution(
            &mut resampler,
            frame,
            effective_target,
        );
        scale_us += scale_start.elapsed().as_micros() as u64;
        // Phase A metric fix — average over REAL resamples only (see the
        // vp9 twin): pass-through frames used to dilute avg_scale_ms far
        // below the true per-downscale cost. Compared against the PRE-CALL
        // frame dims, not native: a backend-scaled frame (Phase B) passes
        // through here at ~0 cost and must not count as a CPU resample.
        if (frame.width, frame.height) != pre_scale_dims {
            scale_ops += 1;
        }
        // rc.190 — publish the ACTUAL encoded dims for the cursor pump's
        // native→encoded scaling (the relay cap can pick a smaller target
        // than the controller asked for).
        let encoded_dims_packed = pack_dims(frame.width, frame.height);
        encoded_dims.store(encoded_dims_packed, std::sync::atomic::Ordering::Relaxed);

        // Lazily build / rebuild the encoder when the frame dims change.
        let (w, h) = (frame.width, frame.height);
        // P8b — the rate half of the plan (maxrate ceiling chain + deep-rung
        // CQ bias) also moved into `encode::policy`; semantics verbatim from
        // Phase B / P3 / P7 / rc.186 (codec × chroma factors, relay clamp
        // inside the fn, encode-pressure factor floored at MIN_BITRATE_BPS,
        // CQ bias keyed on encode-vs-native area). Computed from the ACTUAL
        // post-downscale dims so a passthrough frame keeps ceiling truth.
        let rate = crate::encode::policy::rate_plan(
            w,
            h,
            native_w,
            native_h,
            target_fps,
            constrained,
            codec.label(),
            cell_444,
            governor.encode_factor(),
            matches!(
                dims_plan.reason,
                crate::encode::policy::RungReason::UserPick
            ),
            crate::encode::dial_rate_factor_pct(
                priority.load(std::sync::atomic::Ordering::Relaxed),
            ),
        );
        // FR-35 — the plan's ceiling, lifted by what the learner has proven
        // (and by the pair's remembered rate at open).
        let ceiling = governor.effective_ceiling(rate.ceiling_bps, constrained);
        // 2026-08-26 — compute the area-scaled AIMD floor from the ACTUAL
        // encode dims (see `encode::area_min_bitrate_bps` — flat 1.5 M on
        // constrained); it also floors the shared-pipeline egress split.
        let aimd_floor = crate::encode::area_min_bitrate_bps(w, h, constrained);
        // Shared-pipeline egress split: N viewers of ONE constrained encoder
        // send N separate copies over the SAME relay uplink, so divide the
        // ceiling by the live viewer count (see `shared_split_ceiling_bps`).
        // Recomputed every iteration, so it tracks joins/leaves live.
        let ceiling = crate::encode::shared_split_ceiling_bps(
            ceiling,
            (1 + pipeline.follower_count()) as u32,
            aimd_floor,
            constrained,
            crate::encode::shared_rate_split_enabled(),
        );
        // Feed the direct byte gate's fallback reference (constrained uses the
        // fixed relay budget instead, so the split value here is harmless).
        last_ceiling_bps = ceiling;
        let need_rebuild = match encoder_dims {
            Some((ew, eh)) => ew != w || eh != h,
            None => true,
        };
        // FR-70 M2 — a frame whose dims are not the live encoder's while a
        // cap change is still propagating (a frame or two in flight at the
        // old dims after a swap, an adoption, or any cap move) is STALE:
        // skip it, never rebuild for it. Bounded by `stale_skips_left`
        // (reset at every cap change), so a backend that rounds the box
        // differently from the plan self-heals through the inline open
        // below instead of starving the encoder. The make-before-break
        // itself was decided from the plan above; what reaches the inline
        // open here is the first encoder of the session, a backend that
        // cannot rebuild off the frame path, or a host whose native dims
        // changed under a live session.
        if need_rebuild && encoder_dims.is_some() && stale_skips_left > 0 {
            stale_skips_left -= 1;
            // FR-119 P2b-2 — the pump's own drop, not the host's.
            if let Some(state) = fps_state.as_mut() {
                state.pause();
            }
            continue;
        }
        if need_rebuild {
            let cq_bias = rate.cq_bias;
            // Open at the AIMD's current target when it sits below the
            // ceiling — a fresh encoder at the full ceiling would be
            // rebuilt AGAIN one frame later by the governor's forced
            // reapply (two QSV rebuilds back-to-back at a rung flip).
            let open_rate = match governor.applied_bps() {
                // FR-59 P8 — a remembered-slow pair's FIRST open lands at
                // the remembered rate: the governor's first tick applies it
                // one frame later, and an encoder opened at the ceiling
                // would be rebuilt right there (a second blocking QSV open
                // before the first frame).
                0 => governor.open_seed_bps().map_or(ceiling, |s| ceiling.min(s)),
                applied => ceiling.min(applied),
            };
            // FR-65 — the open is BLOCKING (0.62-0.73 s measured on Iris Xe at
            // session start, 2026-09-03) and this pump runs under
            // `tokio::spawn`, i.e. on a SHARED runtime worker. `roomlerd` is one
            // process: overlay, DERP, tunnels and the WS control plane are on
            // those same workers, so a synchronous open here is not merely a
            // late first frame.
            //
            // ⚠️ SIZE THE CLAIM HONESTLY. The runtime is `new_multi_thread()`
            // with no `worker_threads` (main.rs), so it defaults to the core
            // count and blocking one worker is a 1/N capacity hit that
            // work-stealing routes around — severe on a 2-core VM, a cluster
            // node or WSL, modest on a 16-core desktop. It is NOT a whole-
            // runtime stall (that would need a `current_thread` runtime), and
            // the size of the win here is UNMEASURED.
            //
            // `spawn_blocking` + await frees the worker at the same wall-clock
            // TO WITHIN SCHEDULING JITTER — the loop is sequential and had
            // nothing else to do, but it now has to be rescheduled, which is
            // noise against 700 ms and not literally identical.
            //
            // ⚠️ This covers P1's RUNTIME half ONLY. Every open goes through
            // here — the first one and the dims/chroma/backend rebuilds — but
            // the session is still WITHOUT AN ENCODER for the whole open,
            // because the old one is torn down before the new one is built.
            // P1's actual goal is make-before-break, and that needs
            // `rebuild_spec` to carry GEOMETRY so the swap machinery can hold
            // the old encoder live; today it carries only a bitrate and
            // `adopt_rebuilt` discards a dims change. The runtime tax is fixed
            // here; the session-visible stall is not.
            //
            // ⚠️ `spawn_blocking` tasks are UNCANCELLABLE. If the session tears
            // down mid-open the open still runs to completion and the encoder
            // is built and immediately dropped — so a rapid connect/disconnect
            // cycle briefly holds a HW encoder session for a dead session.
            // Harmless today; it would stop being harmless if a host ever runs
            // near the per-adapter encode-session limit.
            //
            // ⚠️ Timed around the AWAIT, not the call, so `open_ms` stays the
            // honest wall-clock cost of getting an encoder.
            let __open_t = std::time::Instant::now();
            let __opened = match tokio::task::spawn_blocking(move || {
                codec.open(
                    w,
                    h,
                    target_fps,
                    open_rate as usize,
                    cq_bias,
                    cell_444,
                    constrained,
                    last_encoder_name,
                )
            })
            .await
            {
                Ok(r) => r,
                // The blocking pool panicked or was shut down. Treated as an
                // open failure so the existing error ladder handles it, rather
                // than as a new failure mode with its own untested path.
                Err(e) => Err(anyhow::anyhow!("encoder open task failed: {e}")),
            };
            {
                let __us = __open_t.elapsed().as_micros() as u64;
                open_us += __us;
                if __us > open_us_max {
                    open_us_max = __us;
                }
            }
            match __opened {
                Ok(enc) => {
                    let encoder_name = enc.name();
                    // rc.445 — the proven backend skips the dead cascade
                    // prefix on the next rebuild, and stale pre-rebuild
                    // frames stop delaying the fresh encoder's IDR.
                    last_encoder_name = Some(encoder_name);
                    send_epoch.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // P7 — record the ACTIVE chroma (a 4:4:4 request may have
                    // fallen back to 4:2:0 inside new_hevc_adaptive); feeds
                    // the maxrate chroma factor and the video-info truth.
                    cell_444 = enc.chroma444();
                    info!(
                        %session_id,
                        codec_label,
                        width = w,
                        height = h,
                        cq_bias,
                        chroma444 = cell_444,
                        encoder = encoder_name,
                        "FFmpeg DC pump: encoder (re)built"
                    );
                    // rc.87/badge-truth — (re)announce the real encoder via
                    // the loop-top retry block (the encoder name may change
                    // across a rebuild if the dispatch cascade lands
                    // elsewhere). The old inline one-shot send here raced
                    // the control-DC open on relay sessions and lost the
                    // message — retry-until-delivered replaced it.
                    video_info_sent = false;
                    // FR-70 M1 — the label is the session's tail, so the
                    // thread reads `rc-enc-<6 hex>` in a profiler.
                    let handle = crate::encode::ffmpeg::EncoderHandle::new(
                        enc,
                        media_thread,
                        &session_id.to_hex()[18..],
                    );
                    if media_thread {
                        info!(
                            %session_id,
                            codec_label,
                            threaded = handle.is_threaded(),
                            "FR-70 M1: encoder handed to its own thread"
                        );
                    }
                    encoder = Some(handle);
                    encoder_dims = Some((w, h));
                    // FR-119 P2b-2 — opened at the capture's pace.
                    encoder_fps = target_fps;
                    if let Some(state) = fps_state.as_mut() {
                        state.running_at(target_fps);
                    }
                    // FR-70 M3a — the loop decided this rate and these dims by
                    // itself; the shadow judges both against the controller's
                    // next target and the plan after its tick below.
                    plan_shadow.note_built(open_rate, (w, h));
                    // FR-70 M2 — this encoder was built for the target that
                    // produced this frame's dims (the pinned one if a swap
                    // was in flight, the plan's otherwise); the pin and the
                    // capture cap follow it from here. An inline open also
                    // supersedes any replacement still opening in the
                    // background (the target moved again, or nothing was
                    // live): dropping the handle detaches that task and its
                    // result is never adopted.
                    built_target = Some(effective_target);
                    pending_dims_open = None;
                    // Phase B — a fresh encoder starts at the full `ceiling`
                    // maxrate; force the AIMD to re-apply its current (possibly
                    // lower) target so we don't snap back up to the ceiling
                    // after a dim change / resolution switch.
                    governor.on_encoder_rebuilt();
                }
                Err(e) => {
                    tracing::error!(
                        %session_id,
                        codec_label,
                        %e,
                        "FFmpeg DC pump: encoder construction failed — exiting pump"
                    );
                    return;
                }
            }
        }
        // (The capture backend's cap — Phase B — is handed over right after
        // the make-before-break pin, above the resample; see there.)

        // A keyframe requested THIS iteration must never be dropped by the
        // decode-pressure frame-skip below (the browser needs the IDR to
        // resync). Tracked here, consumed by the skip gate.
        let mut force_keyframe_this_iter = false;

        // Lock-state transitions force a keyframe so the browser sees
        // a clean refresh when the operator's lock overlay paints or
        // clears. (Gate semantics: the edge is consumed even when no
        // encoder exists this iteration — pre-extraction behaviour.)
        let is_locked_now = matches!(*lock_state_rx.borrow(), lock_state::LockState::Locked);
        if kf_gate.lock_edge(is_locked_now)
            && let Some(enc) = encoder.as_mut()
        {
            enc.request_keyframe().await;
            force_keyframe_this_iter = true;
        }

        // Apply browser-requested keyframe (PLI/RTCP equivalent on DC).
        // P5 — ANY viewer of the shared stream can ask (own atomic, a
        // follower's atomic, or the pipeline's join/resync flag); both
        // sides are consumed every iteration.
        let own_kf = keyframe_requested.swap(false, std::sync::atomic::Ordering::SeqCst);
        let shared_kf = pipeline.take_keyframe_requested();
        if (own_kf || shared_kf)
            && let Some(enc) = encoder.as_mut()
        {
            enc.request_keyframe().await;
            force_keyframe_this_iter = true;
        }

        // Unanswered-force retry — see `kf_policy::KEYFRAME_BACKSTOP`
        // (rc.234: due ONLY while a force is armed, never a metronome).
        if kf_gate.backstop_due(std::time::Instant::now())
            && let Some(enc) = encoder.as_mut()
        {
            enc.request_keyframe().await;
            force_keyframe_this_iter = true;
            if kf_gate.take_backstop_log() {
                info!(
                    %session_id,
                    codec_label,
                    "FFmpeg DC pump: keyframe force retry engaged (unanswered for 4s)"
                );
            }
        }

        // Force-ignored fallback — see `kf_policy::KEYFRAME_FORCE_REBUILD_
        // AFTER`. Arm on the first unanswered force (origin kept); the send
        // loop stands the gate down when a key-flagged packet actually goes
        // out. If the encoder sat on the force past the window (vp9_qsv
        // ignores pict_type=I), rebuild it — the fresh encoder's first
        // frame is a guaranteed flagged IDR, which is exactly what the
        // browser's keyframe gate is starving for. Cooldown per rc.217.
        kf_gate.arm_if_forced(force_keyframe_this_iter, std::time::Instant::now());
        if let crate::encode::kf_policy::RebuildVerdict::Rebuild { pending_ms } =
            kf_gate.rebuild_fallback(std::time::Instant::now())
        {
            warn!(
                %session_id,
                codec_label,
                pending_ms,
                "FFmpeg DC pump: encoder ignored forced keyframe — rebuilding to emit a guaranteed IDR (vp9_qsv-class runtime-force bug)"
            );
            encoder = None;
            encoder_dims = None;
        }

        // rc.188 — viewer-rate fps cap. Once a second, fold the browser's
        // measured decode report (`rc:decodestat`: decoded fps + a struggling
        // bit) into a send-fps cap and derive the frame-skip divisor; then drop
        // (divisor-1) of every `divisor` delta frames so the agent stops sending
        // faster than the viewer can decode (breaking the backlog→IDR→heavier-
        // decode freeze spiral). Keyframes are never skipped. No-op at divisor 1.
        // P5 (inside the fold closure) — the shared stream paces to the
        // SLOWEST viewer: fold every follower's decode report in and take
        // the max divisor. Also steps the spill gate (a sustained large
        // deviation detaches the most deviant follower to its own encoder).
        // FR-71 T1a — hand the governor this window's sender-side facts before
        // it folds the viewer's report, so the plane verdict reads both sides
        // of the same window. Deltas against the running counters (the
        // heartbeat swaps some of them, so it reads the totals, not swaps).
        {
            let sent_now = frames_sent.load(std::sync::atomic::Ordering::Relaxed);
            let sw_sum_now = send_wait_us_sum.load(std::sync::atomic::Ordering::Relaxed);
            let sw_frames_now = send_wait_frames.load(std::sync::atomic::Ordering::Relaxed);
            let sw_frames = sw_frames_now.saturating_sub(win_sw_frames_last);
            let sw_avg_ms = (sw_frames > 0).then(|| {
                sw_sum_now.saturating_sub(win_sw_sum_last) as f64 / sw_frames as f64 / 1000.0
            });
            governor.note_window_sender(crate::encode::governor::WindowSenderStats {
                inflight_bytes: inflight_bytes.load(std::sync::atomic::Ordering::Relaxed),
                budget_bytes: queue_budget,
                gate_skips: frames_skipped_backpressure.saturating_sub(win_skips_last) as u32,
                send_wait_max_ms: send_wait_us_max.load(std::sync::atomic::Ordering::Relaxed)
                    as f64
                    / 1000.0,
                send_wait_avg_ms: sw_avg_ms,
                frames_sent: sent_now.saturating_sub(win_sent_last) as u32,
                // FR-79 — the gate's first condition: was the agent's own loop
                // free this window? A pass that overran its budget means the
                // send task waited on something this window cannot attribute
                // to the pipe.
                stalled_passes: pump_stalls.saturating_sub(win_stalls_last),
            });
            win_stalls_last = pump_stalls;
            win_sent_last = sent_now;
            win_skips_last = frames_skipped_backpressure;
            win_sw_sum_last = sw_sum_now;
            win_sw_frames_last = sw_frames_now;
        }
        let viewer_window = governor.tick_viewer_window(
            std::time::Instant::now(),
            target_fps,
            || viewer_report.take_report(),
            // FR-15 — see the VP9 pump: acted on only when constrained,
            // learned on every transport.
            || viewer_report.take_age(),
            // FR-59 P3 — the viewer's link report (arrival rate + how much
            // its transit queue grew). Needs no clock probe, so it speaks
            // in the windows the age above cannot.
            || viewer_report.take_link(),
            constrained,
            |own_div| pipeline.step_viewer_windows(own_div, target_fps),
            bytes_written.load(std::sync::atomic::Ordering::Relaxed),
        );
        // FR-59 P6 — drained unconditionally (not inside the viewer-window
        // arm): the abandonment is a one-shot from the learner, so a window
        // that does not tick must not swallow the only line that explains
        // why the ceiling moved.
        if let Some(dropped) = governor.take_seed_abandoned() {
            info!(
                %session_id,
                codec_label,
                abandoned_bps = dropped,
                measured_bps = ?governor.blocked_send_bps(std::time::Instant::now()),
                "FR-59 P6: the measured pipe contradicts the learned ceiling — abandoning it \
                 (relay-keyed rate memory can carry a fast day onto a slow one)"
            );
        }
        if let Some(vw) = viewer_window {
            // FR-35 — one line per ceiling step, and the session's stable
            // rate handed to the memory guard for persistence at pump end.
            if let Some(g) = vw.ceiling_grown {
                info!(
                    %session_id,
                    codec_label,
                    from_bps = g.from_bps,
                    to_bps = g.to_bps,
                    "FR-35 ceiling learner: the pair carried the ceiling — stepping it up"
                );
            }
            // FR-35 P3b — the memory wants the rate the pipe actually CARRIED,
            // not just the learner's above-nominal ceiling. On a short/frozen
            // session the learner never rises, so `stable_bps()` is None; fall
            // back to the AIMD's live applied rate so a session whose seed was
            // too hot (the grace was cut short, the AIMD then cut) records the
            // converged rate as a decrease and the pair stops re-seeding hot.
            // FR-70 P1 — between the learner's stable rate and the applied-
            // rate fallback sits what the session actually KNOWS about the
            // pipe: a live measurement, or the prior as it has decayed. The
            // applied rate at the last window is wherever the last decrease
            // left it, which on a lumpy relay drifts the memory DOWN across
            // sessions (200 kbps was an attractor, not a stale day).
            rate_memory_guard.stable.store(
                governor
                    .stable_bps()
                    .or_else(|| governor.pipe_bps(std::time::Instant::now(), constrained))
                    // FR-79 V4 — evidence only: the applied rate used to stand in
                    // here when nothing measured, which is the memory learning
                    // from itself.
                    .unwrap_or(0),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        if let Some(vw) = viewer_window
            && (vw.changed
                || vw.struggling
                || vw.age_over
                || vw.link_congested
                || vw.drain_for_ms.is_some())
        {
            info!(
                %session_id,
                codec_label,
                reported_fps = vw.reported_fps,
                struggling = vw.struggling,
                age_over = vw.age_over,
                link_congested = vw.link_congested,
                link_ceiling_bps = ?vw.link_ceiling_bps,
                drain_for_ms = ?vw.drain_for_ms,
                age_ms = vw.age_ms.map(|(a, _)| a),
                age_floor_ms = vw.age_ms.and(governor.viewer_age().map(|(_, f)| f)),
                cap_fps = vw.cap_fps,
                skip_divisor = vw.skip_divisor,
                frames_skipped_decode = governor.frames_skipped_decode(),
                "FFmpeg DC pump: viewer-rate fps cap"
            );
        }
        // FR-59 P4 — the transit queue is deeper than a rate cut can clear
        // in reasonable time, so stop feeding it and let it drain. Skipping
        // production (rather than discarding what is already queued) is the
        // only lever that reaches a queue living in the relay and the
        // carrier: those bytes are already gone and cannot be recalled.
        // Bounded sub-second, and NO forced keyframe on resume — a pause
        // loses no frames, so the delta chain survives it intact.
        //
        // FR-119 P2b-2 — a frame dropped for the link or the viewer ends the
        // trial's stretch (`TrialMeter::pause`).
        if governor.draining(std::time::Instant::now()) {
            if let Some(state) = fps_state.as_mut() {
                state.pause();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        }
        if governor.should_skip_delta_frame(force_keyframe_this_iter) {
            if let Some(state) = fps_state.as_mut() {
                state.pause();
            }
            continue;
        }

        let Some(enc) = encoder.as_mut() else {
            continue;
        };

        // A frame that sat inside the DataChannel send call longer than the
        // threshold is unambiguous congestion — the pipe refused to drain.
        // It needs no clock sync and no viewer, so it is the one signal that
        // works on a relay, where the goodput clamp is switched off and the
        // age loop depends on a probe the congestion itself biases.
        //
        // Constrained only: on direct the measured ceiling already owns this,
        // and a stall there is the FR-14 episodic case, which wants a
        // different response. Feeding the SAMPLE rather than taking the move
        // lets `pre_encode_tick` below apply it through the normal arms one
        // frame later.
        // FR-35 P3 — end of the opener grace: turn what the send task saw
        // into the pipe's burst drain rate, for the pair memory.
        if !opener_grace_done
            && opener_started.is_some_and(|t| {
                let elapsed = t.elapsed();
                (elapsed >= OPENER_GRACE
                    && inflight_bytes.load(std::sync::atomic::Ordering::Relaxed) == 0)
                    || elapsed >= OPENER_GRACE_MAX
            })
        {
            opener_grace_done = true;
            in_opener_grace.store(false, std::sync::atomic::Ordering::Relaxed);
            let bytes = opener_bytes.load(std::sync::atomic::Ordering::Relaxed);
            let wait_us = opener_wait_us_max.load(std::sync::atomic::Ordering::Relaxed);
            let opener_maxrate = enc.current_maxrate_bps();
            // FR-79 V2 — a burst that queued is measured by the goodput
            // estimator, like every other window, and only from windows the
            // validity gate accepted.
            let measured = governor.blocked_send_bps(std::time::Instant::now());
            // FR-79 V4 — the measurement is the whole contribution. A burst the
            // socket absorbed proves nothing and writes nothing: its old "not
            // slower than this" step ratcheted the memory to the `hi` cap on
            // every host whose opener never queues (CORPLAP-2, all of
            // 2026-09-08 — every opener there had a 0 ms worst wait).
            let target = measured.unwrap_or(0).min(rate_hi_bps.max(1));
            if constrained {
                rate_memory_guard
                    .opener_measured
                    .store(target, std::sync::atomic::Ordering::Relaxed);
                info!(
                    %session_id,
                    codec_label,
                    opener_bytes = bytes,
                    opener_wait_max_ms = wait_us / 1000,
                    opener_maxrate_bps = opener_maxrate,
                    opener_measured_bps = ?measured,
                    growth_target_bps = target,
                    grace_soft_stalls,
                    grace_bp_skips,
                    "FR-35 opener grace over — the opening burst sized the pair memory's next step"
                );
            }
        }
        if let Some(threshold) = send_stall_threshold {
            let stalled_us = send_stall_us.swap(0, std::sync::atomic::Ordering::Relaxed);
            if constrained && stalled_us >= threshold.as_micros() as u64 {
                send_stalls += 1;
                // FR-35 P3 — a soft stall inside the opener grace is the
                // opening burst draining; only a HARD stall is fed.
                let hard =
                    stalled_us >= crate::encode::ceiling_learn::HARD_STALL.as_micros() as u64;
                if !opener_grace_done && !hard {
                    grace_soft_stalls += 1;
                } else {
                    governor.note_send_stall(
                        Duration::from_micros(stalled_us),
                        std::time::Instant::now(),
                    );
                }
            }
        }

        // Phase B — drive the AIMD off send-channel occupancy (the real DC
        // backpressure signal) each frame. Ceiling = the per-resolution,
        // relay-aware maxrate cap; the controller starts there and tracks the
        // link down under congestion / back up on recovery. `set_bitrate`
        // coarsens the target to a ladder before reconfiguring, so applying it
        // every frame is cheap (a no-op unless the coarse bucket moved).
        if let Some(applied) = governor.pre_encode_tick(
            ceiling,
            aimd_floor,
            constrained,
            send_tx.capacity(),
            std::time::Instant::now(),
        ) {
            // P3 — rebuild-bound applies (QSV/AMF) go through the
            // background swap so rate moves land DURING motion with zero
            // stall; NVENC still reconfigures in place. DIRECT only:
            // each adoption ships a fresh IDR, which on a ~2 Mbps relay
            // is a multi-second lump mid-motion (field 2026-08-27, CORPLAP-3 +
            // CORPLAP-2 over the corp relay felt WORSE than the rc.483
            // defer) — relay keeps the rc.445 motion-defer below, the
            // posture that was field-proven there. Also the fallback
            // with the hatch off.
            // FR-35 P3 / FR-62 A2 — defer a constrained INCREASE only when the
            // in-place apply still costs an IDR. Historically every in-place
            // increase was a starved IDR (FR-31) — a blur pulse on a static
            // screen, one per 5-s AIMD step (field 2026-08-30) — so all of them
            // were held and flushed through the spaced quiet arm below. Since A2
            // the NVENC reconfigure ships NO IDR (measured 0/20 on the RTX,
            // default + constrained), so `reconfig_forces_idr()` is false for it
            // and the increase lands LIVE; QSV-CBR (unmeasured `MFXVideoENCODE_Reset`)
            // and every rebuild-bound backend still defer. Decreases always land
            // at once and anchor the spacing so the climb back cannot start on
            // the very next step.
            let held_increase = constrained
                && relay_idr_thrift
                && enc.supports_dynamic_bitrate()
                && enc.reconfig_forces_idr()
                && applied.bps > enc.current_maxrate_bps();
            if held_increase {
                deferred_bps = Some(applied.bps);
            } else if enc.supports_dynamic_bitrate() {
                deferred_bps = None;
                if constrained && relay_idr_thrift {
                    last_deferred_apply_at = Some(std::time::Instant::now());
                }
                timed_apply!(enc.set_bitrate(applied.bps).await);
            } else if bg_rebuild && !constrained {
                swap_wanted = Some(applied.bps);
            } else if last_motion_at.elapsed() >= DEFER_QUIET {
                // FR-10 follow-up (field 2026-08-28): the spacing below
                // guarded only the DEFERRED flush, so this arm — "the
                // scene is quiet, apply now" — rebuilt on EVERY rung the
                // AIMD crossed. At session start nothing has moved yet, so
                // it is always quiet here, and the startup ramp became two
                // or three blocking QSV re-opens inside the first 15 s,
                // each shipping a fresh IDR onto a ~3 Mbps pipe. That is
                // the "always slow right after connecting, then it
                // settles" the operator reported, and the 2 658 ms age
                // spike measured on CORPLAP-3 at 07:29:02Z.
                //
                // The spacing belongs to the ENCODER and the TRANSPORT
                // (this one rebuilds on set_bitrate, and the pipe is thin),
                // not to the arm we happened to arrive through. A large
                // move still lands promptly; a small one is held in
                // `deferred_bps`, which re-evaluates every loop.
                let allow = crate::encode::rebuild_apply_allowed(
                    constrained,
                    relay_idr_thrift,
                    last_deferred_apply_at.map(|t| t.elapsed()),
                    enc.current_maxrate_bps(),
                    applied.bps,
                );
                if allow {
                    deferred_bps = None;
                    last_deferred_apply_at = Some(std::time::Instant::now());
                    // FR-62 — the defer policy has AUTHORISED this apply, so
                    // WHEN it lands is already decided. Run the rebuild
                    // off-thread anyway: the open blocks 1.3-2.0 s on QSV at
                    // <=1 Mbps, and the pump must keep encoding through it. The
                    // IDR rides the quiet-gated adoption above, unchanged.
                    if bg_rebuild && bg_rebuild_constrained && !enc.supports_dynamic_bitrate() {
                        swap_wanted = Some(applied.bps);
                    } else {
                        timed_apply!(enc.set_bitrate(applied.bps).await);
                    }
                } else {
                    deferred_bps = Some(applied.bps);
                }
            } else {
                deferred_bps = Some(applied.bps);
            }
            if applied.changed {
                info!(
                    %session_id,
                    codec_label,
                    ceiling_bps = ceiling,
                    target_bps = applied.bps,
                    deferred = deferred_bps.is_some(),
                    "FFmpeg DC pump set_bitrate (AIMD)"
                );
            }
        } else if let Some(bps) = deferred_bps
            && last_motion_at.elapsed() >= DEFER_QUIET
        {
            // FR-10 — relay IDR thrift: each flush is a re-open whose first
            // frame is an IDR — a single ~300 KB frame ≈ 1.2-1.5 s of a
            // ~2 Mbps relay (field CORPLAP-3 2026-08-27). Thrifty constrained
            // sessions space small moves to ≥15 s; a ≥40 % move (genuine
            // collapse/recovery) still lands promptly. Held targets stay in
            // `deferred_bps` and re-evaluate every loop.
            let allow = crate::encode::rebuild_apply_allowed(
                constrained,
                relay_idr_thrift,
                last_deferred_apply_at.map(|t| t.elapsed()),
                enc.current_maxrate_bps(),
                bps,
            );
            if allow {
                // Quiet flush: the held QSV/AMF target applies now, while the
                // scene is static — the rebuild stalls a frozen image nobody
                // can see, and its first-frame IDR doubles as the post-motion
                // refresh. Jump the (stale) queue for it.
                deferred_bps = None;
                last_deferred_apply_at = Some(std::time::Instant::now());
                if bg_rebuild && bg_rebuild_constrained && !enc.supports_dynamic_bitrate() {
                    // FR-62 — schedule the rebuild off-thread instead of
                    // stalling here. The rationale above ("the rebuild stalls a
                    // frozen image nobody can see") holds only while the scene
                    // stays static for the WHOLE open — and that open is up to
                    // 2 s on QSV at a relay's bitrates, so motion resuming
                    // inside the window is dead air. The quiet-gated adoption
                    // still bumps `send_epoch` and still ships the IDR on a
                    // static scene; only the freeze goes away.
                    swap_wanted = Some(bps);
                    info!(
                        %session_id,
                        codec_label,
                        target_bps = bps,
                        "FFmpeg DC pump: deferred bitrate scheduled (background rebuild)"
                    );
                } else {
                    // The epoch discard exists for a REBUILD's stale queue; an
                    // in-place (NVENC) apply keeps the same encoder and stream.
                    if !enc.supports_dynamic_bitrate() {
                        send_epoch.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    timed_apply!(enc.set_bitrate(bps).await);
                    info!(
                        %session_id,
                        codec_label,
                        target_bps = bps,
                        "FFmpeg DC pump: deferred bitrate applied at quiet"
                    );
                }
            }
        }
        // FR-70 M3a — the controller has ticked: its target becomes the plan's
        // `bitrate_bps` (an epoch move, not a divergence), and an encoder the
        // loop built since the last tick — the inline open above, or a
        // replacement adopted at the loop top while the plan held — is judged
        // against it: was it built at the plan's rate and the plan's dims? A
        // `bitrate` divergence here is an encoder the controller re-rates on
        // its very next tick. A replacement adopted after the plan moved while
        // it opened is a stale adoption, counted apart and not judged.
        log_plan_divergences(
            &session_id,
            codec_label,
            plan_shadow.after_tick(governor.applied_bps()),
        );

        let encode_start = std::time::Instant::now();
        // P5 (FR-1) — the 20-30 ms HW encode (including the BGRA→NV12
        // convert inside `encode_sync`) ran inline on an async worker,
        // stalling every task sharing the runtime — the DC send task's
        // chunk pumping among them. The handle does `block_in_place` on the
        // inline path (synchronous-in-place, other work shifted off this
        // worker for the duration; multi-thread runtime only, which the
        // agent always runs) and, under FR-70 M1's `media_thread`, sends the
        // frame to the encoder's own thread and awaits the packets — the
        // worker is free meanwhile.
        let packets = match enc.encode(&frame).await {
            Ok(p) => {
                err_ladder.on_success();
                p
            }
            Err(e) => {
                // rc.443 — escalate instead of retrying forever: the old
                // bare `continue` turned a persistently-failing HW encoder
                // into a silently frozen stream (field: corplap av1_qsv
                // rejecting a forced IDR). `encoder` can't be dropped here
                // (`enc` borrow is live past this match) — defer to the
                // loop top.
                match err_ladder.on_error() {
                    crate::encode::EncodeErrorAction::Retry => {
                        tracing::warn!(%session_id, codec_label, %e, "FFmpeg DC pump: encode error");
                    }
                    crate::encode::EncodeErrorAction::Rebuild => {
                        tracing::warn!(
                            %session_id, codec_label, %e,
                            consecutive = err_ladder.consecutive(),
                            "FFmpeg DC pump: encode error — rebuilding the encoder (fresh open, first frame IDR)"
                        );
                        rebuild_after_encode_error = true;
                    }
                    crate::encode::EncodeErrorAction::ExitPump => {
                        tracing::error!(
                            %session_id, codec_label, %e,
                            consecutive = err_ladder.consecutive(),
                            "FFmpeg DC pump: encoder unrecoverable after rebuilds — exiting pump (pipeline reaps, viewer renegotiates)"
                        );
                        return;
                    }
                }
                continue;
            }
        };
        let frame_encode_us = encode_start.elapsed().as_micros() as u64;
        encode_us += frame_encode_us;
        frames_encoded += 1;
        // FR-119 P2b-2 — a trial judges every real frame that left the
        // encoder, at its capture time and with its encode time: only an
        // encoder that cannot keep up fails it (a keepalive re-encode is no
        // frame). The state has taken a verdict into account by the time it
        // returns one; persisting it runs off the runtime, next to the probe
        // cache.
        if is_real_frame
            && let Some(state) = fps_state.as_mut()
            && let Some((class, verdict)) = state.frame(frame.monotonic_us, frame_encode_us)
        {
            // P2b-3 — with what it measured, so a field run reads the numbers
            // the verdict was decided on.
            info!(
                %session_id,
                codec_label,
                ?class,
                ?verdict,
                want = state.want(),
                measured = ?state.concluded(),
                "FR-119: the rate-class trial concluded"
            );
            if let Some((path, key)) = fps_cache.clone() {
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = crate::encode::fps_class_cache::record(
                        &path,
                        &key,
                        class,
                        verdict,
                        crate::encode::caps_cache::now_unix(),
                    ) {
                        warn!(%e, "FR-119: the rate-class verdict was not saved; the next session tries the class again");
                    }
                });
            }
        }
        // rc.446 — the deferred-bitrate motion clock, ONE site: any real
        // frame whose encoded cost exceeds trivial-delta size marks motion.
        // rc.445 armed it only on SIGNIFICANCE-floor frames (42 KB scaled),
        // which let light motion slip through — field corplap (GDI + av1):
        // 5-30 KB window-move frames never armed the clock, so two AIMD
        // ladder rebuilds (each a blocking QSV open) landed mid-burst
        // anyway. 4 KB sits above caret/keystroke deltas (0.5-3 KB, which
        // must NOT pin the deferral on always-return backends like GDI)
        // and below any visible motion on any codec.
        const DEFER_MOTION_MIN_BYTES: usize = 4096;
        if is_real_frame
            && packets.iter().map(|p| p.data.len()).sum::<usize>() >= DEFER_MOTION_MIN_BYTES
        {
            last_motion_at = std::time::Instant::now();
        }
        // P8 Phase 5 — fold the encoder's QP reports into the window.
        for pkt in &packets {
            if let Some(q) = pkt.qp {
                qp_sum += q.max(0) as u64;
                qp_max = qp_max.max(q);
                qp_n += 1;
            }
        }

        // P7c — feed the idle-refine machine POST-encode with the frame's
        // wire cost: significance is keyed on encoded bytes (a keystroke
        // delta is ~0.5-3 KB, a scroll frame tens-to-hundreds), which is
        // what made interactive terminals hold the blurry rung under the
        // old capture-time frame COUNTING (field winhost-b 2026-08-20 —
        // every Up died within ~1-2 s of caret/typing frames). Keepalive
        // re-encodes never count (unchanged). A Down here lands one frame
        // later than the old capture-time hook — one extra native frame
        // per burst, negligible. Divisor-skipped frames no longer feed the
        // machine either: the viewer-rate min_fps floor (12) keeps the
        // surviving encoded cadence ≥10 fps at the stock 30/60 fps
        // captures, so sustained motion still trips the window-rate rule
        // (and ≥12.5 fps cadences chain the run rule). Only a sub-16 fps
        // *configured* capture with a struggling viewer could slip both —
        // accepted: that stream is already fps-shedding to protect the
        // same viewer.
        if is_real_frame && !area_judged {
            let wire_bytes: usize = packets.iter().map(|p| p.data.len()).sum();
            // P7c-2 — significance is judged against the RUNG-SCALED floor
            // (`frame` here is the post-downscale encoded frame, so w×h is
            // the encode area). A fixed floor oscillated in the field: small
            // persistent animations were invisible at 1024×640 and visible
            // at native, flipping Up/Down every ~6 s. P8a — this BYTES leg
            // is the fallback for untracked frames AND the Down-guard for
            // small-area/high-byte content (PiP video) on tracked ones;
            // frames the area leg already judged never double-note.
            let encode_area = frame.width as u64 * frame.height as u64;
            if idle_refine.bytes_significant(wire_bytes, encode_area) {
                frame_significant = true;
                if let Some(flip) =
                    idle_refine.note_real_frame(std::time::Instant::now(), wire_bytes, encode_area)
                {
                    info!(
                        %session_id,
                        codec_label,
                        ?flip,
                        wire_bytes,
                        encode_area,
                        "idle refine: motion burst — restoring resolution cap"
                    );
                }
            }
        }
        // QUIET tick — a real frame neither leg counted is stillness
        // evidence (a 48-byte re-encode of an unchanged screen). Field
        // corplap-3 2026-08-21: its GDI/scrap-class capture returns a
        // frame on EVERY poll (frames_empty=0), the keepalive arm never
        // ran, and refine was structurally inert. Judging quiet by the
        // SIGNAL instead of capture cadence fixes that class — and lets
        // the up-flip fire DURING sustained sub-major motion on tracked
        // backends (the un-refined half of the P8a-2 stay-native promise).
        // The keepalive arm keeps its own tick for the fully-idle case.
        if is_real_frame && !frame_significant {
            let now = std::time::Instant::now();
            if let Some(flip) = idle_refine.on_keepalive(refine_eligible_now, constrained, now) {
                info!(
                    %session_id,
                    codec_label,
                    ?flip,
                    native_w,
                    native_h,
                    "idle refine: scene quiet (signal) — lifting resolution cap \
                     (crisp native IDR incoming)"
                );
            }
        }

        // Push each emitted packet through the framer + DC. FFmpeg may
        // emit zero packets for some inputs (buffered B-frame
        // equivalents); we set max_b_frames=0 so this is rare but
        // possible at GOP boundaries.
        let dc_arc = video_bytes_dc.lock().await.clone();
        let Some(dc) = dc_arc else {
            // rc.97 — DC not open yet (offer/answer/ICE/SCTP still setting
            // up). Force a keyframe so that whenever the DC *does* open, the
            // FIRST frame the browser receives is an IDR. Without this the
            // encoder proceeds along its GOP and the first delivered frame is
            // a delta → the browser's WebCodecs decoder rejects it with "A key
            // frame is required after configure() or flush()" → black screen
            // (field: DEVBOX HEVC). media_pump_vp9_444_dc already
            // does this; the FFmpeg pump didn't, so it only rendered when the
            // DC happened to open at a GOP boundary (timing luck). Covers both
            // HEVC and vp9_qsv DC paths.
            keyframe_requested.store(true, std::sync::atomic::Ordering::SeqCst);
            dc_unopen_drops += 1;
            continue;
        };
        // Handle exists but the channel hasn't reached Open yet — same guard.
        if dc.ready_state() != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
            keyframe_requested.store(true, std::sync::atomic::Ordering::SeqCst);
            dc_unopen_drops += 1;
            continue;
        }

        // rc.106 — backpressure moved to the bounded send channel (the
        // `try_send` below sheds load instead of blocking). This block now
        // only powers the one-shot first-key-flagged-packet diagnostic.
        let has_keyframe = packets.iter().any(|p| p.is_keyframe);
        if has_keyframe && !first_keyframe_logged {
            first_keyframe_logged = true;
            // FR-35 P3 — the opener starts here.
            opener_started = Some(std::time::Instant::now());
            info!(
                %session_id, codec_label, encoder = enc.name(),
                "FFmpeg DC pump: first key-flagged packet emitted (rc.98 — confirms IDR flagging; NVENC needs forced-idr=1)"
            );
        }
        // rc.106 — hand each framed packet to the send task rather than
        // chunk-sending inline. `try_send` NEVER blocks the capture/encode
        // loop: if the task is behind (the link can't drain a big motion/IDR
        // frame fast enough) the bounded channel fills and we shed THIS frame,
        // scheduling a resync keyframe for when the queue drains. The send
        // task owns the 16 KiB chunking + the flow-controlled `dc.send().await`
        // (still ≤ 16 KiB per message — the webrtc-data 65535-byte read-buffer
        // cap that rc.85 fixed). A single consumer preserves chunk order for
        // the browser reassembler.
        let send_start = std::time::Instant::now();
        for pkt in packets {
            // FR-1 P7 — process-epoch stamp, same clock as the ffmpeg pump
            // and the rc:clock echo (was: the capture backend's own epoch,
            // which the browser had no way to relate to anything).
            let wire = bytes::Bytes::from(frame_video_bytes(
                &pkt.data,
                pkt.is_keyframe,
                agent_epoch_us(),
            ));
            // P5 — fan the framed packet out to the shared pipeline's
            // followers first (their sync gates + queues are independent of
            // the owner's), then queue it for the owner's own DC.
            pipeline.fan_out(
                &wire,
                pkt.is_keyframe,
                native_dims_packed,
                encoded_dims_packed,
            );
            let wire_len = wire.len();
            match send_tx.try_send((
                send_epoch.load(std::sync::atomic::Ordering::Relaxed),
                std::time::Instant::now(),
                wire,
            )) {
                Ok(()) => {
                    // Byte-budget ledger (constrained gate): counted on entry,
                    // released by the send task once the frame leaves.
                    inflight_bytes.fetch_add(wire_len, std::sync::atomic::Ordering::Relaxed);
                    // A key frame that actually entered the send queue
                    // answers any pending forced-keyframe request (the
                    // force-ignored fallback and the retry stand down).
                    if pkt.is_keyframe {
                        kf_gate.on_key_frame_queued();
                    }
                    if kf_gate.take_resync() {
                        // First frame through after a drop burst — make the
                        // NEXT one a keyframe so the browser resyncs the
                        // deltas it missed during congestion.
                        enc.request_keyframe().await;
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    frames_dropped_backpressure += 1;
                    kf_gate.note_resync_needed();
                    // Phase B — a full channel at try_send (a big IDR / motion
                    // frame the link can't drain) is a secondary congestion
                    // signal; note it to the AIMD (rate-limited MD internally).
                    // `enc` is in scope from the encode above. rc.445 — an
                    // overflow IS motion; rebuild-bound encoders swap in the
                    // background (P3, direct only — see the loop-top block)
                    // or defer.
                    if let Some(applied) = governor.on_send_overflow(std::time::Instant::now()) {
                        if enc.supports_dynamic_bitrate() {
                            timed_apply!(enc.set_bitrate(applied.bps).await);
                        } else if bg_rebuild && !constrained {
                            swap_wanted = Some(applied.bps);
                        } else {
                            deferred_bps = Some(applied.bps);
                        }
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    tracing::warn!(
                        %session_id, codec_label,
                        "FFmpeg DC pump: send task gone — exiting pump"
                    );
                    return;
                }
            }
        }
        send_us += send_start.elapsed().as_micros() as u64;

        // Heartbeat for log-grep observability. rc.88 adds per-stage
        // averages (capture/encode/send ms) so the field can localise
        // the bottleneck behind a low fps, plus the backpressure-drop
        // counter. `_avg_*` are over frames encoded since the last
        // heartbeat.
        if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
            last_heartbeat = std::time::Instant::now();
            // rc.106 — these three are owned by the send task now; snapshot
            // them for the log line.
            let frames_sent = frames_sent.load(std::sync::atomic::Ordering::Relaxed);
            let bytes_written = bytes_written.load(std::sync::atomic::Ordering::Relaxed);
            let send_errors = send_errors.load(std::sync::atomic::Ordering::Relaxed);
            let window_frames = frames_encoded.saturating_sub(heartbeat_frames_base).max(1);
            let avg_capture_ms = (capture_us / window_frames) as f64 / 1000.0;
            // Phase A — per REAL resample (scale_ops), not per window frame:
            // pass-through frames used to dilute this far below the true
            // per-downscale cost (the number Phase C's veto would key on).
            let avg_scale_ms = (scale_us / scale_ops.max(1)) as f64 / 1000.0;
            let avg_encode_ms = (encode_us / window_frames) as f64 / 1000.0;
            let avg_send_ms = (send_us / window_frames) as f64 / 1000.0;
            // P7 (2026-08-26) — queue-wait per window: enqueue→wire-complete
            // for frames that reached the wire. THE drag-latency number the
            // byte gate exists to bound; read avg against max — a fat max
            // with a small avg is one IDR's transit, both fat is a standing
            // queue.
            let sw_frames = send_wait_frames.swap(0, std::sync::atomic::Ordering::Relaxed);
            let send_wait_avg_ms = send_wait_us_sum
                .swap(0, std::sync::atomic::Ordering::Relaxed)
                .checked_div(sw_frames)
                .map(|us| us as f64 / 1000.0)
                .unwrap_or(0.0);
            let send_wait_max_ms =
                send_wait_us_max.swap(0, std::sync::atomic::Ordering::Relaxed) as f64 / 1000.0;
            // FR-17 - read the LIVE channel, not a cached flag: the
            // handle can be replaced mid-session, and a stale copy
            // would mislabel exactly the window someone is measuring.
            let video_dc_ordered = video_bytes_dc.lock().await.as_ref().map(|d| d.ordered());
            // rc.186 — step the encode-pressure controller off this window's
            // avg encode time; the new factor applies to the ceiling from the
            // next frame on (throttles a saturating encoder, restores when it
            // recovers). 2026-07-27 — the same governor heartbeat folds the
            // window into the resolution tier. Fires rarely (≥10 s
            // saturated-at-floor down / ≥60 s deep-headroom up, 60 s
            // cooldown); the dims change lands via the per-frame dims plan →
            // dim-change encoder rebuild.
            // P5 (FR-1) — this pump is definitionally the HW pump
            // (FfmpegEncoder is always a hardware backend), so the
            // fps-first cadence relief applies: is_hw = true.
            if let Some(tier) = governor.heartbeat(
                avg_encode_ms as f32,
                true,
                target_fps,
                std::time::Instant::now(),
            ) {
                tracing::info!(
                    %session_id,
                    codec_label,
                    cap_long_edge = ?tier.cap_long_edge,
                    ewma_encode_ms = tier.ewma_encode_ms,
                    encode_factor = governor.encode_factor(),
                    "encode-bound auto-downscale tier change"
                );
            }
            // P5 — change-gated pace log (engage / move / release), so the
            // field can attribute a cadence shift to this mechanism.
            let paced_now = governor.paced_fps();
            if last_paced_logged != Some(paced_now) {
                last_paced_logged = Some(paced_now);
                tracing::info!(
                    %session_id,
                    codec_label,
                    paced_fps = ?paced_now,
                    target_fps,
                    avg_encode_ms,
                    "FFmpeg DC pump: cadence pace changed (fps-first HW relief)"
                );
            }
            // P8 Phase 4 — count shared / mixed-dial pipeline seconds
            // (the SVC go/no-go dataset). Counted on the OWNER session,
            // whose pump runs the shared pipeline; a heartbeat window is
            // ~HEARTBEAT_INTERVAL of wall time.
            if pipeline.follower_count() > 0 {
                let mixed = pipeline.dials_mixed(
                    priority.load(std::sync::atomic::Ordering::Relaxed),
                    *target_resolution.lock().unwrap(),
                );
                crate::session_telemetry::counters(session_id)
                    .note_shared_window(HEARTBEAT_INTERVAL.as_secs(), mixed);
            }
            // P8 Phase 5 — window QP stats. None-valued fields = the
            // encoder reported no QP this window (openh264/MF, or an
            // FFmpeg encoder without quality-stats side data) — an
            // honest gap, deliberately distinct from a zero QP.
            let avg_qp = (qp_n > 0).then(|| (qp_sum / qp_n) as u32);
            let max_qp = (qp_n > 0).then_some(qp_max);
            // FR-62 A1 — rate-apply counters (in-place writes vs rebuilds) and
            // the IDR total, so the before/after of `encoder_inplace_rate` is
            // one grep; read `idr_count` against `keyframe_requests` to isolate
            // rate-caused IDRs.
            let rate_stats = enc.rate_stats().await;
            // FR-118 P0 — `avg_encode_ms` split into its four steps, and the
            // capture thread's own readback, per frame over this window (0.0
            // when the window had none, like `avg_encode_ms`). The readback runs
            // off the pump's clock on WGC, so `avg_capture_ms` never contained it.
            let [avg_convert_ms, avg_upload_ms, avg_submit_ms, avg_drain_ms] = rate_stats
                .stage
                .window_ms_since(&stage_base)
                .unwrap_or([0.0; 4]);
            stage_base = rate_stats.stage;
            let avg_readback_ms = match capturer.readback_totals() {
                Some(now) => {
                    let ms = capture::readback_window_ms(now, readback_base);
                    readback_base = now;
                    ms
                }
                None => 0.0,
            };
            info!(
                %session_id,
                codec_label,
                target_fps,
                constrained,
                target_bps = governor.applied_bps(),
                width = w,
                height = h,
                encoder = enc.name(),
                frames_captured, frames_encoded, frames_sent, bytes_written,
                send_errors, dc_unopen_drops, frames_dropped_backpressure,
                frames_skipped_backpressure, frames_empty, settle_kf_suppressed,
                avg_capture_ms, avg_scale_ms, avg_encode_ms, avg_send_ms,
                avg_convert_ms, avg_upload_ms, avg_submit_ms, avg_drain_ms,
                avg_readback_ms,
                send_wait_avg_ms, send_wait_max_ms,
                learned_ceiling_bps = governor.learned_ceiling_bps(),
                send_stalls,
                // FR-17 - the NEGOTIATED delivery mode of this
                // session's `video-bytes` channel, so a heartbeat is
                // self-labelling. Without it an ordered-vs-unordered
                // A/B is only attributable by trusting the order the
                // runs happened in, which is an assumption wearing the
                // costume of a measurement.
                dc_ordered = ?video_dc_ordered,
                paced_fps = ?governor.paced_fps(),
                encode_factor = governor.encode_factor(),
                avg_qp = ?avg_qp,
                max_qp = ?max_qp,
                bytes_inflight = inflight_bytes.load(std::sync::atomic::Ordering::Relaxed),
                // Measured-rate v2 — CONSUMED (stage 1): while an
                // estimate holds, `target_bps` above is clamped to 85 %
                // of it. None = no confidence (nothing blocked lately —
                // an unbound link shows counts (0, 0)); rejected counts
                // windows whose blocked time was too thin to trust.
                goodput_bps = ?governor.blocked_send_bps(std::time::Instant::now()),
                goodput_samples = ?governor.goodput_samples(),
                // FR-15 — the viewer's own paint age (window avg) and the
                // learned path floor. The excess between them is what the
                // constrained age loop acts on; None = pre-FR-15 viewer.
                viewer_age_ms = ?governor.viewer_age().map(|(a, _)| a),
                viewer_age_floor_ms = ?governor.viewer_age().map(|(_, f)| f),
                viewer_age_implausible = governor.viewer_age_implausible(),
                // FR-70 M0 — the fused age SPLIT by plane, so an excursion
                // is attributable without reading source: `viewer_ms` is
                // what this browser added after the frame arrived,
                // `sender_ms` is this window's send-queue wait, and
                // `transit_ms` is everything between — the relay included.
                // Finding 4 (2026-09-04: age 4903 with inflight 1485 B and
                // iter_max 28 ms) reads here as transit ≈ 4.9 s. None = a
                // pre-M0 viewer, or a window with no age report.
                age_split = ?governor.viewer_age_split(Some(send_wait_avg_ms)),
                // FR-71 T1a — which plane was the limiter last window, in
                // SHADOW (nothing acts on it until T1b), and windows per
                // verdict: [unknown, clear, overproduced, transit_stalled,
                // viewer_late]. A repeat of finding 4 reads `transit-stalled`
                // here while `target_bps` shows the cut T1b will remove.
                pipe_state = ?governor.pipe_state().map(|s| s.as_str()),
                pipe_states = ?governor.pipe_state_counts(),
                evidence_rejected = ?governor.evidence_rejected(),
                // FR-79 V3b (SHADOW) — the ONE belief beside the old composition:
                // believed / demonstrated floor / pushed-back capacity, and the
                // (deliveries, capacities) that produced them. Nothing reads these
                // yet; they exist so the field can say whether the belief is sane
                // before a loop acts on it.
                pipe_belief = ?governor.belief_bps(std::time::Instant::now()),
                pipe_belief_n = ?governor.belief_counts(),
                pipe_gap_stalls = governor.pipe_gap_stalls(),
                // FR-59 P1 — the floor actually in force once the measured
                // pipe has been shown to sit under the nominal legibility
                // minimum. None = the flat floor stands, which on a slow
                // link is the thing to notice: without this field, "the
                // relief let go" and "nothing was ever measured" read the
                // same, and they need opposite fixes.
                slow_link_floor_bps = ?governor.relieved_floor_bps(),
                // FR-70 P1 — what stands in for a pipe measurement while
                // there is none: the remembered seed, or the last live
                // measurement, DECAYING toward the band on clean windows.
                // None = no prior in force. Read it against `goodput_bps`
                // and `slow_link_floor_bps`: a relief letting go while the
                // goodput stays None is the decay, working — and a session
                // that sits at `prior_bps=Some(200000)` for minutes with
                // both of those unchanged is the pin this phase removed.
                prior_bps = ?governor.prior_bps(),
                // FR-59 P3/P4 — (congested windows, drains ordered, live
                // queue-depth estimate in ms) from the viewer-side loop.
                link_stats = ?governor.link_stats(),
                // FR-62 A1 — rate-apply accounting (in-place writes / rebuilds
                // / IDRs emitted). `inplace_rate` off ⇒ QSV rebuilds, so
                // `rebuilds` tracks rate moves; on ⇒ `rate_moves` does.
                inplace_rate = enc.supports_dynamic_bitrate(),
                rate_moves = rate_stats.rate_moves,
                rebuilds = rate_stats.rebuilds,
                // FR-65 — read this ALONGSIDE the two above, never instead of
                // them: on a direct QSV session a rate move is a background
                // swap and lands ONLY here, so the pair reading zero used to
                // look like "the encoder never moved" when it had moved twice.
                swaps = rate_stats.swaps,
                dims_swaps,
                // FR-70 M3a — the shadow plan: per-field divergences between
                // the plan computed at the top of each pass and the pump's
                // inline values (the retirement gate for M3b reads every
                // field at ZERO, fleet-wide), and how many distinct plans the
                // session has had. A field's first divergence also logs once
                // with both values (`FR-70 M3a: the shadow plan diverged`).
                plan_divergences = %plan_shadow.counts(),
                plan_epoch = plan_shadow.epoch(),
                // Replacements adopted after the plan moved while they opened
                // — a make-before-break lag on a rebuild-bound backend, not a
                // divergence. The first one logs with its three rates.
                plan_stale_swaps = plan_shadow.stale_swaps(),
                idr_count = rate_stats.idr_count,
                // FR-62 A2 — whether the pump is still rationing this encoder's
                // constrained increases. false ⇒ moves land live (NVENC,
                // patched); pair it with a flat `idr_count` to confirm the apply
                // shipped no keyframe, or a rising one to justify the hatch.
                reconfig_forces_idr = enc.reconfig_forces_idr(),
                // FR-65 P0 — the APPLY stage (previously untimed, and therefore
                // where a 1.3-2.0 s QSV open hid), plus the worst single pass in
                // the window and how many passes overran. ⚠️ Read the MAXes, not
                // the mean: one 2 s stall inside a 2 s window is invisible in an
                // average and is exactly the event worth finding.
                apply_ms = apply_us as f64 / 1000.0,
                apply_ms_max = apply_us_max as f64 / 1000.0,
                open_ms = open_us as f64 / 1000.0,
                open_ms_max = open_us_max as f64 / 1000.0,
                iter_ms_max = iter_us_max as f64 / 1000.0,
                pump_stalls,
                "FFmpeg DC pump heartbeat (≈2s window)"
            );
            heartbeat_frames_base = frames_encoded;
            capture_us = 0;
            scale_us = 0;
            scale_ops = 0;
            encode_us = 0;
            send_us = 0;
            // FR-65 P0 — the window's apply/stall stats reset with the rest, so
            // every heartbeat's maxes describe that window alone.
            apply_us = 0;
            apply_us_max = 0;
            open_us = 0;
            open_us_max = 0;
            iter_us_max = 0;
            pump_stalls = 0;
            qp_sum = 0;
            qp_max = 0;
            qp_n = 0;
        }
    }
}

/// FR-70 M3a — log a field's FIRST divergence of the session between the
/// shadow plan and the pump's inline value, with both values. The heartbeat
/// carries the counts; this line is what names the field and the numbers.
#[cfg(feature = "ffmpeg-encoder")]
fn log_plan_divergences(
    session_id: &bson::oid::ObjectId,
    codec_label: &str,
    first: Vec<crate::encode::plan::FirstDivergence>,
) {
    for d in first {
        warn!(
            %session_id,
            codec_label,
            field = d.field,
            plan = %d.plan,
            inline = %d.inline,
            "FR-70 M3a: the shadow plan diverged from the pump's inline value (first time this session for this field)"
        );
    }
}

/// FR-70 M3a — log the session's FIRST replacement adopted after the plan
/// moved while it opened: built at the plan of its spawn, arriving under a
/// later one. Not a divergence (the loop decided nothing the plan did not);
/// the heartbeat's `plan_stale_swaps` carries the count.
#[cfg(feature = "ffmpeg-encoder")]
fn log_plan_stale_swap(
    session_id: &bson::oid::ObjectId,
    codec_label: &str,
    stale: Option<crate::encode::plan::StaleSwap>,
) {
    let Some(s) = stale else {
        return;
    };
    info!(
        %session_id,
        codec_label,
        kind = s.kind,
        built_bps = s.built_bps,
        spawned_bps = s.spawned_bps,
        now_bps = s.now_bps,
        spawned_w = s.spawned_dims.0,
        spawned_h = s.spawned_dims.1,
        now_w = s.now_dims.0,
        now_h = s.now_dims.1,
        "FR-70 M3a: a replacement was adopted after the plan moved while it opened (built at the plan of its spawn; first time this session)"
    );
}

/// The VP9-444 pump's target rate. An explicit `ROOMLERD_VP9_FPS` pins it (30
/// or 60, any other value rounding to the nearer). Otherwise FR-112 P2: **60**,
/// paced down by the pump to what the encoder sustains, or 30 with
/// `ROOMLERD_SW_FPS_60=0` (0.4.141's default, when a CPU-starved host was the
/// reason for it; the pacing now covers that host).
#[cfg(feature = "vp9-444")]
fn vp9_444_target_fps_from_env() -> u32 {
    vp9_444_target_fps(
        node_env("VP9_FPS").and_then(|v| v.trim().parse::<u32>().ok()),
        crate::encode::sw_fps_60_enabled(),
    )
}

/// [`vp9_444_target_fps_from_env`] with its inputs passed in, for the tests.
#[cfg(feature = "vp9-444")]
fn vp9_444_target_fps(pinned: Option<u32>, sw_fps_60: bool) -> u32 {
    match pinned {
        Some(fps) if fps >= 45 => 60,
        Some(_) => 30,
        None if sw_fps_60 => 60,
        None => 30,
    }
}

/// Target fps for the FFmpeg HW DC pump (HEVC / vp9_qsv): explicit env wins,
/// else pick per-session by transport (Phase B).
///
/// An explicit `ROOMLERD_FFMPEG_FPS` ALWAYS wins (clamped 1..=240) — a
/// high-refresh host can force 60 even on a relay, or pin 30 on a direct link.
/// With no override: a direct/LAN link defaults to **60** (HW encode sustains
/// it and the capture backend caps the real delivered rate anyway); a
/// constrained relay-TCP link defaults to **30**, because 60 fps of HEVC
/// overruns the ~1-4 Mbps pipe and just sheds frames. Deliberately distinct
/// from the libvpx VP9-444 pump's `ROOMLERD_VP9_FPS` (default 30 — SW
/// 4:4:4 can't keep up at 60).
///
/// Pre-rc.93 the pump hardcoded 30, which throttled the scrap backend's
/// internal pacer to 30 fps and was the root of the vp9_qsv ~15 fps field bug.
#[cfg(feature = "ffmpeg-encoder")]
fn ffmpeg_target_fps(constrained: bool) -> u32 {
    if let Some(fps) = node_env("FFMPEG_FPS").and_then(|v| v.trim().parse::<u32>().ok()) {
        return fps.clamp(1, 240);
    }
    if constrained { 30 } else { 60 }
}

/// Attach the `input` data-channel message handler. Each inbound payload
/// is parsed as [`input::InputMsg`] and injected via the thread-pinned
/// OS backend. The injector is built once per channel (the first frame
/// may race with initialisation, but `open_default` is synchronous so
/// it's ready before the first real keystroke).
///
/// `lock_state_rx` lets the handler short-circuit injection when the
/// host's input desktop has transitioned to `winsta0\Winlogon` (Win+L
/// lock, UAC, etc.). On those transitions the user-context worker is
/// still attached to `winsta0\Default` and SendInput would silently
/// dispatch to the wrong desktop — events appear to be delivered from
/// the WS side but achieve nothing on the host. Dropping them at this
/// layer keeps the audit trail honest and avoids polluting `enigo`
/// internal state.
///
/// Unparseable payloads are dropped with a debug log — we don't want a
/// flood of warnings if the controller sends an unknown event type.
fn attach_input_handler(
    dc: Arc<RTCDataChannel>,
    lock_state_rx: tokio::sync::watch::Receiver<lock_state::LockState>,
    // P6 — events route through the process-global InputArbiter keyed by
    // session (single fenced injection worker replaces the pre-P6
    // injector-per-session).
    session_id: bson::oid::ObjectId,
) {
    // rc.57 — reset the per-process `to_pixels` diagnostic counter so
    // the FIRST 50 input events of THIS session land at INFO level
    // again. Without the reset, the static counter is exhausted after
    // session 1 and subsequent sessions only log at DEBUG — hiding any
    // session-specific norm/px mismatch (e.g. the Crystal-Clear-OFF
    // auto-downscale path, where the misposition reproduces but the
    // earlier rc.55 field log had no INFO dispatch lines to inspect).
    input::reset_input_diag_counter();
    // Counter for batched suppression logging. Without this, a busy
    // session with the host locked would spam one debug line per
    // mouse-move (~60 Hz when the operator is jiggling). Log every
    // 60th drop so the field gets a steady "yes, the suppression is
    // working" signal without filling the log file.
    let suppressed_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // rc.26 — gate the Locked-state suppression on worker role.
    // SystemContext (LocalSystem) can drive Winlogon via `SendInput`
    // because it holds SE_TCB; suppressing input in that case blocks
    // remote unlock for no benefit. User-context still suppresses
    // (its SendInput cannot reach Winlogon and would silently fail).
    let sys_ctx_worker = is_system_context_worker();
    if sys_ctx_worker {
        info!(
            "input: SystemContext worker — Locked-state suppression disabled (remote unlock enabled)"
        );
    }
    // 2026-08-04 / P6 — if the input DC dies mid-chord (browser crash, tab
    // kill — paths where the viewer's blur-release can't run), release
    // exactly what THIS session still holds (keys AND mouse buttons — the
    // arbiter tracks them), superseding the old blanket 0xe0..=0xe7 sweep.
    dc.on_close(Box::new(move || {
        Box::pin(async move {
            crate::input::arbiter::global().release_held(session_id);
        })
    }));
    dc.on_message(Box::new(move |msg| {
        let lock_state_rx = lock_state_rx.clone();
        let suppressed_count = suppressed_count.clone();
        Box::pin(async move {
            let Ok(text) = std::str::from_utf8(&msg.data) else {
                debug!("input: non-utf8 payload dropped");
                return;
            };
            // FR-16 L4 — a bench probe is the synthetic source's to paint,
            // never an injector's. Outside bench mode it is dropped here.
            #[cfg(feature = "synthetic-frame-source")]
            if crate::capture::synthetic_backend::probe::accept_json(text) {
                return;
            }
            let parsed: input::InputMsg = match serde_json::from_str(text) {
                Ok(v) => v,
                Err(e) => {
                    debug!(%e, "input: parse failed");
                    return;
                }
            };
            // FR-101 P4b-2 — the controller is here, whether or not what it
            // sent is injected (the lock below may suppress it).
            crate::session_telemetry::counters(session_id).note_input_seen();
            // M3 Z-path: drop input early when the host is locked.
            // The browser's auto-reconnect ladder will keep the peer
            // alive across short lock screens; the operator just
            // can't drive the lock UI itself (that's the A1-path
            // future work).
            //
            // rc.26 — A1-path: under SystemContext, allow input
            // through. The injector thread runs as LocalSystem with
            // SE_TCB privilege, so SendInput CAN reach Winlogon's
            // input desktop. This is the "drive lock screen
            // remotely" path documented in
            // `docs/remote-control.md (§19 appendix)`
            // Change C ("refine the suppression policy under
            // SystemContext").
            if !sys_ctx_worker
                && matches!(*lock_state_rx.borrow(), lock_state::LockState::Locked)
            {
                let n = suppressed_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    .wrapping_add(1);
                // rc.25 — promote the FIRST suppressed event of a
                // run to INFO so the field gets a clear signal in
                // the default log level, then drop back to DEBUG
                // every 60th. Pre-rc.25 this was DEBUG-only, which
                // was invisible at the default INFO level and made
                // "input suppressed when admin pwsh hovered"
                // reports hard to confirm from the log.
                if n == 1 {
                    info!(
                        "input: lock_state=Locked — suppressing input (first event); see `lock_state: transition observed` for the observed desktop name"
                    );
                } else if n.is_multiple_of(60) {
                    debug!(
                        suppressed_total = n,
                        "input: host locked — suppressing input events"
                    );
                }
                return;
            }
            // P6 — hand the event to the arbiter (serialized injection,
            // cross-session modifier fencing, floor control, ghosting).
            crate::session_telemetry::counters(session_id).note_input();
            crate::input::arbiter::global().event(session_id, parsed);
        })
    }));
}

/// Send `rc:host_locked` over the stashed `control` data channel.
/// No-op when the channel hasn't opened yet (session in negotiation),
/// when the channel has been torn down, or when the send itself fails
/// — none of those are recoverable from this task and a missing badge
/// is a much softer failure than a panicked emitter.
async fn emit_host_locked(
    stash: &Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    locked: bool,
) {
    let dc = {
        let guard = stash.lock().await;
        match guard.as_ref() {
            Some(dc) => dc.clone(),
            None => return,
        }
    };
    let payload = format!(r#"{{"t":"rc:host_locked","locked":{locked}}}"#);
    if let Err(e) = dc.send_text(payload).await {
        debug!(%e, "rc:host_locked send failed (control DC closed?)");
    }
}

/// FR-97 P3b — the Linux hint's `rc:host_locked`: the same message plus
/// `input: "passes"`, so the viewer says the lock screen takes input rather
/// than "input is suppressed", which is Windows' case. An older viewer ignores
/// the field and shows its chip as before. FR-97 P2d-1 — a Mac's says
/// `input: "unknown"` (`lock_state::LOCK_SCREEN_INPUT`).
///
/// Always compiled (only Linux and a Mac send it) so the wire shape is locked
/// by a test on every OS.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
fn host_locked_advisory_payload(locked: bool, input: &str) -> String {
    format!(r#"{{"t":"rc:host_locked","locked":{locked},"input":"{input}"}}"#)
}

/// FR-108 P1b — tell this session's viewer what display match did on its own
/// (at the unlock, or handing the screen back), as `rc:display-match.state`.
async fn emit_display_match(
    stash: &Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    answer: crate::display_match::Answer,
) {
    let dc = {
        let guard = stash.lock().await;
        match guard.as_ref() {
            Some(dc) => dc.clone(),
            None => return,
        }
    };
    if let Err(e) = dc.send_text(crate::display_match::state_json(answer)).await {
        debug!(%e, "rc:display-match.state send failed (control DC closed?)");
    }
}

/// rc.227 — push one keyboard-layout snapshot to the viewer over the
/// control DC. Returns `false` when the DC is gone (the emitter task
/// uses that as its session-scoped exit — the layout watch channel is
/// process-global and never closes on its own). A not-yet-stashed DC
/// returns `true` (keep waiting for it to open; its `control` arm then
/// sends the current snapshot, FR-97 P3e).
#[cfg(all(
    any(target_os = "windows", target_os = "linux"),
    feature = "enigo-input"
))]
async fn emit_layout(
    stash: &Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    snap: &crate::input::layout::LayoutSnapshot,
) -> bool {
    let dc = {
        let guard = stash.lock().await;
        match guard.as_ref() {
            Some(dc) => dc.clone(),
            None => return true,
        }
    };
    match dc.send_text(layout_json(snap)).await {
        Ok(_) => true,
        Err(e) => {
            debug!(%e, "rc:layout send failed (control DC closed?) — stopping layout emitter");
            false
        }
    }
}

/// rc.227 — one snapshot as its `rc:layout` envelope. `json!`, not
/// `format!`: the tags are dynamic strings.
#[cfg(all(
    any(target_os = "windows", target_os = "linux"),
    feature = "enigo-input"
))]
fn layout_json(snap: &crate::input::layout::LayoutSnapshot) -> String {
    serde_json::json!({
        "t": "rc:layout",
        "active_hkl": snap.active_hkl,
        "active": snap.active_tag,
        "installed": snap
            .installed
            .iter()
            .map(|(hkl, tag)| serde_json::json!({ "hkl": hkl, "tag": tag }))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

/// `control` data-channel handler. Parses JSON `rc:*` envelopes and
/// applies them. Today the only message is `rc:quality` (mutating the
/// shared atomic that the media pump polls before each encode); future
/// types (rc:cursor-shape from agent → controller, rc:bitrate-hint,
/// rc:dpi-change) layer on the same parse-by-`t` switch.
#[allow(clippy::too_many_arguments)]
fn attach_control_handler(
    dc: Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    quality_state: Arc<std::sync::atomic::AtomicU8>,
    target_resolution: Arc<std::sync::Mutex<TargetResolution>>,
    keyframe_requested: Arc<std::sync::atomic::AtomicBool>,
    // rc.188 — written on every `rc:decodestat` (packed decoded fps + a
    // struggling bit via `viewer_rate::pack_report`); the DC video pumps swap+
    // decode it to drive the viewer-rate fps cap.
    viewer_report: Arc<crate::encode::viewer_rate::ViewerFeedback>,
    // rc.199 — per-session Priority dial; the `rc:priority` match arm writes it.
    priority: Arc<std::sync::atomic::AtomicU8>,
) {
    // A handle the on_message closure sends replies through (e.g.
    // rc:logs-fetch.reply) over the same DC. #1740 — WEAK: the closure is
    // stored INSIDE this channel, so a strong clone made the channel own
    // itself, and a session's control channel (with everything its handlers
    // hold) was never freed.
    let dc_for_reply = Arc::downgrade(&dc);
    // rc.130 — min-gap clamp for browser-requested keyframes (rc:keyframe).
    // The atomic itself coalesces (the pump forces at most one IDR per encode
    // regardless of how often it's set) and the browser debounces, but this
    // bounds a misbehaving/old controller to one forced IDR per gap so a
    // resync storm can't pile the LARGEST frames onto a congested link.
    let last_kf_request = Arc::new(std::sync::Mutex::new(None::<std::time::Instant>));
    // rc.191 — display-match cleanup: restore the host's original display
    // mode when the session's control channel closes (normal disconnect,
    // browser tab gone, watchdog pc.close() — all funnel here). The
    // CDS_FULLSCREEN temporary-change semantics additionally auto-restore
    // if the agent PROCESS dies, so every exit path is covered. No-op when
    // display-match never switched anything.
    //
    // Multi-user P3: ownership-gated — only the session that APPLIED the
    // current mode restores it (a closing watcher tab must not revert the
    // driving session's mode).
    dc.on_close(Box::new(move || {
        Box::pin(async move {
            // P6 — the control DC's close is the canonical session-death
            // signal: deregister from the InputArbiter (release-all any
            // held keys, drop off the participants rail, hand the
            // exclusive floor to a surviving session). Idempotent.
            crate::input::arbiter::global().session_closed(session_id);
            // Detach — restore is fire-and-forget (JoinHandle drop is fine).
            drop(tokio::task::spawn_blocking(move || {
                crate::display_match::forget(session_id);
                if crate::display_match::restore_for(session_id) {
                    tracing::info!(session = %session_id, "display-match: restored on session close (owner)");
                }
            }));
        })
    }));
    dc.on_message(Box::new(move |msg| {
        let quality_state = quality_state.clone();
        let target_resolution = target_resolution.clone();
        let keyframe_requested = keyframe_requested.clone();
        let viewer_report = viewer_report.clone();
        let priority = priority.clone();
        let last_kf_request = last_kf_request.clone();
        let dc_for_reply = dc_for_reply.clone();
        Box::pin(async move {
            // Trust-but-verify: a malformed message must never crash
            // the data-channel callback (it'd kill the channel for
            // the rest of the session). Every parse path silently
            // logs and returns on failure.
            let text = match std::str::from_utf8(&msg.data) {
                Ok(t) => t,
                Err(_) => {
                    debug!(%session_id, bytes = msg.data.len(), "control: non-UTF8 payload, dropped");
                    return;
                }
            };
            let val: serde_json::Value = match serde_json::from_str(text) {
                Ok(v) => v,
                Err(e) => {
                    debug!(%session_id, %e, "control: malformed JSON, dropped");
                    return;
                }
            };
            let Some(t) = val.get("t").and_then(|v| v.as_str()) else {
                debug!(%session_id, "control: message missing 't' tag, dropped");
                return;
            };
            match t {
                "rc:quality" => {
                    let Some(q_str) = val.get("quality").and_then(|v| v.as_str()) else {
                        debug!(%session_id, "control: rc:quality missing quality field");
                        return;
                    };
                    let Some(q_val) = quality::from_wire(q_str) else {
                        debug!(%session_id, q = q_str, "control: rc:quality unknown value");
                        return;
                    };
                    let prev = quality_state.swap(q_val, std::sync::atomic::Ordering::Relaxed);
                    if prev != q_val {
                        info!(
                            %session_id,
                            prev = quality::label(prev),
                            new = quality::label(q_val),
                            "control: rc:quality updated"
                        );
                    }
                }
                "rc:priority" => {
                    // rc.199 — the viewer "Priority" dial. Decodes to a
                    // per-session atomic both DC pumps read for the relay
                    // resolution cap: balanced = link-physics cap on a relay,
                    // sharper = native override (the "Sharpness" lever),
                    // smoother = fewer pixels everywhere. Unknown values are
                    // ignored so the dial simply stays where it was.
                    let Some(mode_str) = val.get("mode").and_then(|v| v.as_str()) else {
                        debug!(%session_id, "control: rc:priority missing mode field");
                        return;
                    };
                    let Some(mode_val) = crate::encode::priority::from_wire(mode_str) else {
                        debug!(%session_id, mode = mode_str, "control: rc:priority unknown value");
                        return;
                    };
                    let prev = priority.swap(mode_val, std::sync::atomic::Ordering::Relaxed);
                    if prev != mode_val {
                        info!(
                            %session_id,
                            prev = crate::encode::priority::label(prev),
                            new = crate::encode::priority::label(mode_val),
                            "control: rc:priority updated"
                        );
                    }
                }
                // P6 — floor control. `rc:control.request` asks for the
                // exclusive-mode floor (auto-granted from an idle holder);
                // `rc:control.mode` toggles free|exclusive in-session. Both
                // answer with an `rc:control.state` broadcast to every
                // session (the arbiter owns the reply).
                "rc:control.request" => {
                    crate::input::arbiter::global().request_floor(session_id);
                }
                // FR-27 — the courteous half of the floor protocol. A refused
                // request is now REMEMBERED and broadcast, so the holder can
                // see it and answer instead of the requester having to keep
                // clicking until it happens to land in an idle window.
                //
                // The arbiter validates both: only the current holder may
                // grant, and only to the session that actually asked, so a
                // stale click cannot hand control to whoever asked last.
                "rc:control.grant" => {
                    let to = val
                        .get("session")
                        .and_then(|v| v.as_str())
                        .and_then(|s| bson::oid::ObjectId::parse_str(s).ok());
                    match to {
                        Some(to) => crate::input::arbiter::global().grant_floor(session_id, to),
                        None => {
                            debug!(%session_id, "control: rc:control.grant without a valid session — dropped")
                        }
                    }
                }
                // Sent by the HOLDER to decline, or by the REQUESTER to
                // withdraw; the arbiter accepts it from either.
                "rc:control.dismiss" => {
                    crate::input::arbiter::global().clear_floor_request(session_id);
                }
                "rc:control.mode" => {
                    let mode = val
                        .get("mode")
                        .and_then(|v| v.as_str())
                        .and_then(crate::input::arbiter::Mode::parse);
                    match mode {
                        Some(m) => crate::input::arbiter::global().set_mode(session_id, m),
                        None => {
                            debug!(%session_id, "control: rc:control.mode unknown value — dropped")
                        }
                    }
                }
                "rc:resolution" => {
                    let mode = val.get("mode").and_then(|v| v.as_str()).unwrap_or("");
                    let new_target = match mode {
                        "original" => TargetResolution::Native,
                        "fit" | "custom" => {
                            let raw_w = val.get("width").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                            let raw_h = val.get("height").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                            if raw_w == 0 || raw_h == 0 {
                                debug!(
                                    %session_id, mode,
                                    "control: rc:resolution missing/invalid width/height — dropped"
                                );
                                return;
                            }
                            // MF HEVC encoder requires even-dimensioned
                            // input. A browser sending Fit dimensions
                            // derived from a stage element at
                            // 2154×1077 (the 1077 is odd) would bomb
                            // `MfEncoder::new_hevc` at session rebuild
                            // time, which fail-closed demotes to
                            // NoopEncoder — black screen for the rest
                            // of the session with no way to recover
                            // short of reconnect. Floor to the
                            // nearest-lower even number here so a
                            // browser that forgot to round can't brick
                            // the encoder. Clamp minima to 160×90 —
                            // below that most hardware MFTs reject.
                            let w = (raw_w & !1).max(160);
                            let h = (raw_h & !1).max(90);
                            if (w, h) != (raw_w, raw_h) {
                                debug!(
                                    %session_id, mode,
                                    raw_w, raw_h, w, h,
                                    "control: rc:resolution rounded to even dims"
                                );
                            }
                            TargetResolution::Fixed {
                                width: w,
                                height: h,
                            }
                        }
                        other => {
                            debug!(
                                %session_id, mode = other,
                                "control: rc:resolution unknown mode — dropped"
                            );
                            return;
                        }
                    };
                    let mut slot = target_resolution.lock().unwrap();
                    let prev = *slot;
                    if prev != new_target {
                        *slot = new_target;
                        info!(
                            %session_id,
                            mode,
                            ?prev,
                            new_target = ?new_target,
                            "control: rc:resolution updated"
                        );
                    }
                }
                "rc:fps" => {
                    // FR-119 P1 — the viewer's frame-rate ask. Stored only; the
                    // pump answers in `rc:video-info` (`fps`, and `fps_asked` +
                    // `fps_reason` when it does not grant it), because the pump
                    // is what knows the session's cap and transport.
                    match crate::encode::frame_rate::parse_ask(&val) {
                        Some(fps) => {
                            viewer_report.store_fps_ask(fps);
                            info!(%session_id, fps, "control: rc:fps asked");
                        }
                        None => {
                            debug!(%session_id, "control: rc:fps with no offered rate — dropped");
                        }
                    }
                }
                "rc:logs-fetch" => {
                    // rc.23 diagnostic feature; rc.24 added reply
                    // streaming. Browser requests the tail of the
                    // agent's current rolling log file so the
                    // operator can see what's actually happening on
                    // the host without RDPing in. Single round-trip
                    // for sub-32-KB payloads (rc.23-compatible);
                    // chunked stream for larger ones because a
                    // single SCTP message can't exceed the
                    // negotiated `max_message_size` (65536 default)
                    // — field repro the field-test host 2026-05-13 showed
                    // 1000-line requests silently dropping.
                    let lines = val
                        .get("lines")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(200)
                        .clamp(1, 5000) as usize;
                    let request_id = val
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    info!(
                        %session_id,
                        request_id = ?request_id,
                        lines,
                        "control: rc:logs-fetch received"
                    );
                    let envelopes = match logs_fetch::fetch_tail_chunked(
                        lines,
                        request_id.as_deref(),
                    )
                    .await
                    {
                        Ok(envs) => envs,
                        Err(e) => {
                            warn!(%session_id, %e, "control: rc:logs-fetch fetch_tail_chunked failed");
                            vec![serde_json::json!({
                                "t": "rc:logs-fetch.reply",
                                "ok": false,
                                "error": format!("{e:#}"),
                            })]
                        }
                    };
                    let envelope_count = envelopes.len();
                    info!(
                        %session_id,
                        envelopes = envelope_count,
                        "control: rc:logs-fetch sending reply"
                    );
                    for env in envelopes {
                        let text = match serde_json::to_string(&env) {
                            Ok(s) => s,
                            Err(e) => {
                                debug!(%session_id, %e, "control: rc:logs-fetch.reply serialise failed");
                                continue;
                            }
                        };
                        let Some(dc) = dc_for_reply.upgrade() else {
                            break;
                        };
                        if let Err(e) = dc.send_text(text).await {
                            debug!(%session_id, %e, "control: rc:logs-fetch.reply send failed");
                            // Stop sending the rest of the stream —
                            // browser will get a partial response and
                            // can retry. Better than spamming dead
                            // sends.
                            break;
                        }
                    }
                }
                "rc:decodestat" => {
                    // rc.188 — the viewer's measured decode report: `fps` = frames
                    // it DECODED last window, `struggling` = it dropped frames to a
                    // decode backlog (or its queue is backing up). The DC pumps fold
                    // this into `viewer_rate::ViewerRateController` to cap send-fps to
                    // the viewer's real sustainable rate. Overwrite (not accumulate) —
                    // the pump swaps it to 0 each window, so a stale value simply
                    // decays to "no signal / clean".
                    let fps = val.get("fps").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let struggling = val
                        .get("struggling")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    viewer_report
                        .store_report(crate::encode::viewer_rate::pack_report(fps, struggling));
                    // FR-15 — the viewer's paint-age for the window (avg +
                    // the window's minimum, the floor sample). Absent from
                    // pre-FR-15 viewers and from a window that painted
                    // nothing: leave the age slot at its swap-reset 0 so the
                    // loop reads "no report" rather than a fabricated 0 ms.
                    let age = val.get("age_ms").and_then(|v| v.as_u64());
                    let age_min = val.get("age_min_ms").and_then(|v| v.as_u64());
                    // FR-15 P2 — the viewer's own probe round trip. Without it
                    // the agent has no way to tell a real path floor from a
                    // clock-biased one, which is exactly how the loop ended up
                    // learning 1 ms floors on 86-210 ms relays. Absent (an
                    // older viewer) ⇒ 0 ⇒ the bound is inert and the loop
                    // behaves as it did in 0.4.9.
                    let rtt = val
                        .get("probe_rtt_ms")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    // FR-70 M0 — the window's age at ARRIVAL (last chunk in
                    // the viewer's worker), same clock mapping as `age_ms`.
                    // Absent (pre-M0 viewer) ⇒ 0 ⇒ the slot reads as absent
                    // and the heartbeat's split stays `None`.
                    let arr = val.get("arr_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                    if let (Some(a), Some(m)) = (age, age_min) {
                        viewer_report.store_age(crate::encode::viewer_rate::pack_age_with_arrival(
                            a.min(u16::MAX as u64) as u16,
                            m.min(u16::MAX as u64) as u16,
                            rtt.min(u16::MAX as u64) as u16,
                            arr.min(u16::MAX as u64) as u16,
                        ));
                    }
                    // FR-59 P3 — the viewer's LINK report: bytes/s it
                    // actually received this window, and how much its
                    // transit queue grew (signed ms). Needs no clock
                    // probe, so it survives exactly the conditions that
                    // silence the age above. Both must be present:
                    // `rx_bps` alone says nothing about capacity (see
                    // `viewer_rate::LinkLoop`), and a drift without a
                    // rate cannot bound a ceiling.
                    if let (Some(rx), Some(q)) = (
                        val.get("rx_bps").and_then(|v| v.as_u64()),
                        val.get("queue_ms").and_then(|v| v.as_i64()),
                    ) {
                        viewer_report.store_link(crate::encode::viewer_rate::pack_link(
                            rx.min(u32::MAX as u64) as u32,
                            q.clamp(i16::MIN as i64, i16::MAX as i64) as i16,
                        ));
                    }
                }
                "rc:display-match" => {
                    // rc.191 — viewer asked the host to switch its display to
                    // the largest mode fitting the viewer's stage (makes the
                    // whole pixel chain 1:1 — see `display_match`).
                    // `{enable:false}` restores. FR-108: the DEVICE decides
                    // (its owner's `display_match`, and under `auto` whether
                    // someone is using the screen), and every request gets one
                    // `rc:display-match.state` back. Runs off the callback
                    // thread: ChangeDisplaySettingsExW blocks.
                    let enable = val
                        .get("enable")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let w = val.get("width").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let h = val.get("height").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    if enable && (w == 0 || h == 0) {
                        tracing::debug!("display-match: missing width/height — ignored");
                    } else {
                        let answer = tokio::task::spawn_blocking(move || {
                            if !enable {
                                // P3: only the owning session's toggle-off
                                // restores; a non-owner disabling its OWN match
                                // preference must not revert the mode another
                                // session applied.
                                if crate::display_match::restore_for(session_id) {
                                    tracing::info!("display-match: restored original mode");
                                } else {
                                    tracing::debug!(
                                        "display-match: disable from non-owner session — no-op"
                                    );
                                }
                                return crate::display_match::Answer::Off;
                            }
                            crate::display_match::request_for(session_id, w, h)
                        })
                        .await;
                        if let (Ok(answer), Some(dc)) = (answer, dc_for_reply.upgrade()) {
                            let _ = dc
                                .send_text(crate::display_match::state_json(answer))
                                .await;
                        }
                    }
                }
                // FR-92 — keep busy. The ARBITER decides whether this session
                // may switch it (it holds the INPUT grant, the floor and the
                // session's org policy); the engine then answers EVERY viewer
                // with `rc:keep-busy.state`. A refusal goes to this one only.
                "rc:keep-busy.set" => {
                    match crate::keep_busy::wire::parse_set(&val, crate::keep_busy::wall_ms()) {
                        Ok(req) => crate::input::arbiter::global().keep_busy_set(session_id, req),
                        Err(why) => {
                            debug!(%session_id, why, "control: rc:keep-busy.set malformed");
                            if let Some(dc) = dc_for_reply.upgrade() {
                                let _ = dc
                                    .send_text(crate::keep_busy::state_json(Some("bad_request")))
                                    .await;
                            }
                        }
                    }
                }
                "rc:keep-busy.get" => {
                    if let Some(dc) = dc_for_reply.upgrade()
                        && let Err(e) = dc.send_text(crate::keep_busy::state_json(None)).await
                    {
                        debug!(%session_id, %e, "control: rc:keep-busy.state send failed");
                    }
                }
                "rc:clock" => {
                    // FR-1 P7 — viewer clock probe. Echo `t0` VERBATIM (the
                    // browser computes RTT from its own value; parsing it here
                    // would just add a way to corrupt it) plus our process-epoch
                    // µs — the same clock the DC video wire timestamps are
                    // stamped with, which is what lets the browser turn a frame
                    // timestamp into a true end-to-end age in its HUD.
                    let t0 = val.get("t0").cloned().unwrap_or(serde_json::Value::Null);
                    let reply = clock_echo_json(&t0, agent_epoch_us());
                    if let Some(dc) = dc_for_reply.upgrade()
                        && let Err(e) = dc.send_text(reply).await
                    {
                        debug!(%session_id, %e, "control: rc:clock echo send failed");
                    }
                }
                "rc:keyframe" => {
                    // Browser's decode queue backed up → it dropped deltas and
                    // needs a fresh IDR to resync. Force one (min-gap clamped).
                    // rc.217 — 200 ms → 500 ms: with the #166 worker retrying
                    // at ~4 req/s while gated AND runtime forces now actually
                    // producing IDRs (qsv forced_idr), the old gap allowed up
                    // to 5 big IDRs/s onto a struggling viewer — feeding the
                    // very backlog the resync was meant to clear. 2 IDRs/s is
                    // plenty for resync and halves the burst load.
                    const MIN_KF_GAP: Duration = Duration::from_millis(500);
                    let now = std::time::Instant::now();
                    let mut guard = last_kf_request.lock().unwrap();
                    let allow = guard
                        .map(|t| now.duration_since(t) >= MIN_KF_GAP)
                        .unwrap_or(true);
                    if allow {
                        *guard = Some(now);
                        drop(guard);
                        keyframe_requested.store(true, std::sync::atomic::Ordering::Relaxed);
                        crate::session_telemetry::counters(session_id).note_keyframe();
                        debug!(%session_id, "control: rc:keyframe — forcing IDR (browser decode-backlog resync)");
                    }
                }
                "rc:apps.list" | "rc:apps.focus" | "rc:apps.launch" => {
                    // Remote app selection & launch (virtual-desktop
                    // hosts). Mirror rc:logs-fetch: handle off-thread
                    // (shells out / FFI) then reply over the same control
                    // DC. Every path returns a well-formed *.reply.
                    let t_owned = t.to_string();
                    let val_for_task = val.clone();
                    let reply = tokio::task::spawn_blocking(move || {
                        crate::apps::handle_control_message(&val_for_task)
                    })
                    .await
                    .unwrap_or_else(|e| {
                        serde_json::json!({
                            "t": format!("{t_owned}.reply"),
                            "ok": false,
                            "error": format!("apps handler panicked: {e}"),
                        })
                    });
                    match serde_json::to_string(&reply) {
                        Ok(text) => {
                            if let Some(dc) = dc_for_reply.upgrade()
                                && let Err(e) = dc.send_text(text).await
                            {
                                debug!(%session_id, %e, "control: rc:apps.* reply send failed");
                            }
                        }
                        Err(e) => {
                            debug!(%session_id, %e, "control: rc:apps.* reply serialise failed");
                        }
                    }
                }
                #[cfg(all(
                    any(target_os = "windows", target_os = "linux"),
                    feature = "enigo-input"
                ))]
                "rc:layout.set" => {
                    // rc.227 — the viewer's manual layout picker. Value is
                    // an opaque hex token the agent itself reported in
                    // `rc:layout` (an HKL on Windows; FR-97 P3e, a layout's
                    // hash and its XKB group on X11); request_set_layout
                    // re-validates it against the CURRENT layouts before
                    // activating (never activates arbitrary wire input) and
                    // re-reads — the resulting `rc:layout` push is the
                    // implicit ack. FR-97 P3e — through the arbiter, which
                    // refuses a session that may not type. macOS / non-enigo
                    // builds compile this arm out → the catch-all
                    // debug-drops it, same as old agents.
                    let Some(hkl) = val.get("hkl").and_then(|v| v.as_str()) else {
                        debug!(%session_id, "control: rc:layout.set missing hkl — dropped");
                        return;
                    };
                    if hkl.is_empty() || hkl.len() > 16 || !hkl.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        debug!(%session_id, "control: rc:layout.set malformed hkl — dropped");
                        return;
                    }
                    info!(%session_id, hkl, "control: rc:layout.set — switching remote keyboard layout");
                    crate::input::arbiter::global().layout_set(session_id, hkl.to_string());
                }
                other => {
                    debug!(%session_id, t = other, "control: unknown message type");
                }
            }
        })
    }));
}

/// `cursor` data-channel handler. Spawns a pumper task that polls
/// the OS cursor at 30 Hz and sends `cursor:pos` / `cursor:shape` /
/// `cursor:hide` JSON messages over the DC. Exits when the DC closes
/// (the `send_text` call returns an error). The tracker caches shape
/// bitmaps by HCURSOR handle so repeated polls at the same shape only
/// send position updates — on a static cursor the bitmap pays for
/// itself once per shape change (arrow → I-beam → hand → etc.).
fn attach_cursor_handler(
    dc: Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    // Shared with the media pump so the streamed cursor position tracks
    // the encoded frame's pixel space when the stream is downscaled
    // (rc.183 remote-cursor offset fix). `capture_native_dims` = the
    // native pre-downscale dims the active pump publishes each frame;
    // `encoded_dims` = the dims it ACTUALLY encodes (rc.190 — post
    // controller preference AND agent-side relay/SW caps, so the scale
    // reflects truth rather than re-deriving from TargetResolution).
    capture_native_dims: Arc<std::sync::atomic::AtomicU64>,
    encoded_dims: Arc<std::sync::atomic::AtomicU64>,
    // Ends the poller when the session does, whatever state the channel is
    // left in ([`AgentPeer::session_end`]).
    session_end: tokio_util::sync::CancellationToken,
) -> JoinHandle<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    tokio::spawn(async move {
        // Wait for the DC to be open before starting the pump — a
        // just-constructed RTCDataChannel hasn't completed the SCTP
        // handshake yet.
        let mut tracker = crate::capture::cursor::CursorTracker::new();
        // rc.38 — bumped 33 ms (30 Hz) → 8 ms (120 Hz) after the field-test host
        // field test 2026-05-17 surfaced sluggish cursor tracking even
        // when the controller's local pointermove was timely.
        // Operator perceives "where the cursor is" via:
        //   (a) the synthetic local cursor at the controller's
        //       pointermove position (instant), and
        //   (b) the remote-reported cursor canvas at the agent's
        //       polled position (this poller's cadence).
        // The browser hides (a) once (b) reports a shape, so the
        // poller's cadence dominates "feels-responsive" once the
        // first cursor shape arrives. 120 Hz matches RustDesk and is
        // cheap: each tick is one GetCursorInfo + JSON encode + DC
        // send_text, well under 1 ms even on weak hosts. Idle frames
        // dedupe via the tracker's per-shape cache so we don't burn
        // DC bandwidth on a static cursor.
        // FR-98 C4 — the period is a knob for the field A/B
        // (`ROOMLERD_CURSOR_POLL_MS`), read once per session; 8 ms unless set.
        let poll = crate::capture::cursor::poll_interval(node_env("CURSOR_POLL_MS").as_deref());
        if poll != crate::capture::cursor::DEFAULT_POLL {
            info!(
                poll_ms = poll.as_millis() as u64,
                "cursor poller: custom period (FR-98 C4)"
            );
        }
        let mut ticker = tokio::time::interval(poll);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Emit cursor:hide once when the cursor disappears so the
        // browser can clear its overlay; don't keep re-emitting.
        let mut last_hidden = false;
        loop {
            tokio::select! {
                _ = session_end.cancelled() => return,
                _ = ticker.tick() => {}
            }
            // ⚠️ `Closing` too, not only `Closed`: a channel the device
            // closed itself often stops at `Closing` for good. Where the
            // tracker reports no pointer (Linux, macOS; a Windows host with
            // no cursor showing) nothing is ever sent, so no failed send ends
            // the loop either — it went on at 120 Hz for every dropped
            // session, for the life of the daemon.
            let state = dc.ready_state();
            if channel_gone(state) {
                return;
            }
            // Attached before the channel opens (`on_data_channel` fires
            // first): a send now would fail and end the poller for good, so
            // wait for `Open` (found in review; Windows with a pointer).
            if state == webrtc::data_channel::data_channel_state::RTCDataChannelState::Connecting {
                continue;
            }
            match tracker.poll() {
                Some(tick) => {
                    last_hidden = false;
                    if let Some(shape) = &tick.shape {
                        let b64 = BASE64.encode(&shape.bgra);
                        let msg = serde_json::json!({
                            "t": "cursor:shape",
                            "id": tick.shape_id,
                            "w": shape.width,
                            "h": shape.height,
                            "hx": shape.hotspot_x,
                            "hy": shape.hotspot_y,
                            "bgra": b64,
                            // Optional CSS `cursor` keyword for stock
                            // system cursors ("text", "default", …);
                            // null for app-custom cursors. Lets the
                            // browser render the viewer's native OS
                            // cursor instead of this bitmap. Additive —
                            // old browsers ignore it.
                            "css": shape.css,
                        });
                        if let Ok(s) = serde_json::to_string(&msg) {
                            let _ = dc.send_text(s).await;
                        }
                    }
                    // Express the native-pixel cursor position in the
                    // encoded frame's pixel space so the browser overlay
                    // (which divides by the decoded `mediaIntrinsicW/H`)
                    // lands correctly when the controller downscales.
                    // No-op (scale 1.0) at native resolution. The shape
                    // hotspot is bitmap-local and stays unscaled — the
                    // browser subtracts it after this multiply.
                    let (sx, sy) = cursor_scale_from_dims(
                        capture_native_dims.load(std::sync::atomic::Ordering::Relaxed),
                        encoded_dims.load(std::sync::atomic::Ordering::Relaxed),
                    );
                    let msg = serde_json::json!({
                        "t": "cursor:pos",
                        "id": tick.shape_id,
                        "x": (tick.x as f32 * sx).round() as i32,
                        "y": (tick.y as f32 * sy).round() as i32,
                    });
                    if let Ok(s) = serde_json::to_string(&msg)
                        && dc.send_text(s).await.is_err()
                    {
                        debug!(%session_id, "cursor DC closed — stopping pump");
                        return;
                    }
                }
                None => {
                    if !last_hidden {
                        last_hidden = true;
                        let msg = serde_json::json!({ "t": "cursor:hide" });
                        if let Ok(s) = serde_json::to_string(&msg) {
                            let _ = dc.send_text(s).await;
                        }
                    }
                }
            }
        }
    })
}

/// rc.38 — aspect-preserving downscale target: shrink `(src_w, src_h)` so its
/// LONG edge is ≤ `cap_long_edge`, keeping aspect and rounding DOWN to even
/// dims (encoders reject odd). Sources already within the cap return
/// unchanged. Hoisted to module scope in rc.190 so the RTP pump's SW
/// auto-downscale and the DC pumps' relay/SW resolution caps share the exact
/// same math (fixed 16:9 targets stretched 16:10 panels — see the rc.38 note
/// at the media_pump call site).
pub(crate) fn aspect_preserved_target(src_w: u32, src_h: u32, cap_long_edge: u32) -> (u32, u32) {
    if src_w == 0 || src_h == 0 {
        return (cap_long_edge, cap_long_edge * 9 / 16);
    }
    let long = src_w.max(src_h);
    if long <= cap_long_edge {
        return (src_w, src_h);
    }
    let num = cap_long_edge as u64;
    let new_w = ((src_w as u64) * num / long as u64) as u32;
    let new_h = ((src_h as u64) * num / long as u64) as u32;
    // Encoders require even dims; round DOWN to nearest even.
    (new_w & !1, new_h & !1)
}

/// rc.190 — compose the controller-requested resolution with the agent-side
/// caps, yielding the effective target for [`apply_target_resolution`].
///
/// Two cap tiers with different override semantics:
/// - `hard_cap_long_edge` (the relay-TCP bandwidth cap, B1): PHYSICS. A
///   ~3 Mbps TURN-TCP relay cannot carry a 2560×1600 stream without the
///   blur↔crystallize AIMD sawtooth (field DEVBOX→WINHOST-A 2026-07-16), so it
///   clamps EVERYTHING — including an explicit controller pick — by taking
///   whichever target has the smaller area.
/// - `soft_cap_long_edge` (the SW-encoder speed cap, B2): a performance
///   DEFAULT. It applies only when the controller left resolution at
///   `Native`, mirroring the RTP pump's "operator can override via
///   rc:resolution" contract — an explicit pick wins even above the cap.
///
/// rc.191 — linear scale ABOVE which a controller box request snaps to
/// Native. Field 2026-07-16 (WINHOST-H@1920×1200 + Fit 1672×818): a
/// near-1:1 NON-INTEGER resample is the worst case for any filter —
/// text mush + "pixely" form aliasing — while saving almost no bits.
/// Snapping to Native keeps the chain 1:1 (crisp) whenever the request
/// is within ~15% of the source. Env `ROOMLERD_SNAP_NATIVE_PCT`
/// (percent, default 85; `0` disables snapping).
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn snap_native_scale() -> f32 {
    let pct = tunnel_core::env::node_env("SNAP_NATIVE_PCT")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(85);
    (pct.min(100) as f32) / 100.0
}

/// rc.191 — resolve a controller `Fixed{w,h}` request as an ASPECT-PRESERVING
/// bounding box against the native frame: scale the source uniformly by
/// `min(box_w/native_w, box_h/native_h, 1.0)` and even-align. Two field bugs
/// this kills (2026-07-16):
///
/// * Distortion — `apply_target_resolution` scaled to the EXACT requested
///   dims, so a Fit request shaped like the viewer's stage (e.g. 1672×818)
///   squashed a 16:9/16:10 source by up to ~20%. The controller's letterbox
///   rendering means the browser handles a smaller-than-stage frame fine.
/// * Near-native mush — when the uniform scale lands ≥ `snap_native_scale`,
///   return Native instead: a 0.87× box resample destroys ClearType text for
///   a ~13% pixel saving nobody asked for.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn resolve_user_box(
    user: TargetResolution,
    native_w: u32,
    native_h: u32,
) -> TargetResolution {
    let TargetResolution::Fixed { width, height } = user else {
        return TargetResolution::Native;
    };
    if width == 0 || height == 0 || native_w == 0 || native_h == 0 {
        return TargetResolution::Native;
    }
    let scale = (width as f32 / native_w as f32)
        .min(height as f32 / native_h as f32)
        .min(1.0);
    let snap = snap_native_scale();
    if snap > 0.0 && scale >= snap {
        return TargetResolution::Native;
    }
    let w = ((native_w as f32 * scale) as u32) & !1;
    let h = ((native_h as f32 * scale) as u32) & !1;
    if w == 0 || h == 0 || (w, h) == (native_w, native_h) {
        return TargetResolution::Native;
    }
    TargetResolution::Fixed {
        width: w,
        height: h,
    }
}

/// Pure so the composition rules are unit-tested on the default build.
/// Only the DC pumps (feature-gated) call it, hence the dead_code allow on
/// the signalling-only build (tests don't count for liveness).
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) fn effective_target_resolution(
    user: TargetResolution,
    native_w: u32,
    native_h: u32,
    hard_cap_long_edge: Option<u32>,
    soft_cap_long_edge: Option<u32>,
) -> TargetResolution {
    // rc.191 — controller boxes become aspect-preserving targets (with the
    // near-native snap) BEFORE the cap tiers compose.
    let user = resolve_user_box(user, native_w, native_h);
    // Soft tier: only fills in for an absent controller preference.
    let mut effective = match (user, soft_cap_long_edge) {
        (TargetResolution::Native, Some(cap)) => {
            let (w, h) = aspect_preserved_target(native_w, native_h, cap);
            if (w, h) == (native_w, native_h) {
                TargetResolution::Native
            } else {
                TargetResolution::Fixed {
                    width: w,
                    height: h,
                }
            }
        }
        _ => user,
    };
    // Hard tier: min-area against whatever the soft tier produced.
    if let Some(cap) = hard_cap_long_edge {
        let (cw, ch) = aspect_preserved_target(native_w, native_h, cap);
        if (cw, ch) != (native_w, native_h) {
            let cap_area = (cw as u64) * (ch as u64);
            let keep = match effective {
                TargetResolution::Native => false,
                TargetResolution::Fixed { width, height } => {
                    // apply_target_resolution caps Fixed at native, so
                    // compare the POST-clamP area, not the raw request —
                    // an oversized Fit request (bigger than native) is
                    // really "native" and must not dodge the hard cap.
                    let w = width.min(native_w);
                    let h = height.min(native_h);
                    (w as u64) * (h as u64) <= cap_area
                }
            };
            if !keep {
                effective = TargetResolution::Fixed {
                    width: cw,
                    height: ch,
                };
            }
        }
    }
    effective
}

/// rc.190 (B3) — what the stuck-session watchdog should do this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchdogVerdict {
    /// Peer is fine (or not yet past a deadline) — keep watching.
    Wait,
    /// Peer is dead weight — Terminate the session + close the PC so the
    /// hub frees the slot (fixes the "Being viewed" zombie + AgentBusy).
    Kill,
    /// Session ended through another path (Closed, or Failed which the
    /// state-change handler already Terminates) — watchdog exits.
    Disarm,
}

/// rc.190 (B3) — pure decision core of the stuck-session watchdog, split out
/// so the deadline/state matrix is unit-tested on the default build.
///
/// * Never-connected: a peer that hasn't reached `Connected` within
///   `connect_deadline` (ICE wedged pre-nomination — "pingAllCandidates
///   called with no candidate pairs" — never transitions to `Failed`).
/// * Disconnected-limbo: a formerly-usable peer parked in `Disconnected`
///   past `disconnected_grace` (webrtc-rs may hover there without ever
///   reaching `Failed`; short blips recover to `Connected` well inside the
///   grace and are left alone).
fn session_watchdog_verdict(
    state: RTCPeerConnectionState,
    connected_once: bool,
    since_start: Duration,
    disconnected_for: Option<Duration>,
    connect_deadline: Duration,
    disconnected_grace: Duration,
) -> WatchdogVerdict {
    match state {
        RTCPeerConnectionState::Closed | RTCPeerConnectionState::Failed => WatchdogVerdict::Disarm,
        RTCPeerConnectionState::Connected => WatchdogVerdict::Wait,
        RTCPeerConnectionState::Disconnected => match disconnected_for {
            Some(d) if d >= disconnected_grace => WatchdogVerdict::Kill,
            _ => WatchdogVerdict::Wait,
        },
        // New / Connecting / Unspecified — only the never-connected
        // deadline applies; once the session has been Connected, a return
        // to Connecting (ICE restart) is given the same patience as
        // Disconnected via its own state above.
        _ => {
            if !connected_once && since_start >= connect_deadline {
                WatchdogVerdict::Kill
            } else {
                WatchdogVerdict::Wait
            }
        }
    }
}

/// Pack `(width, height)` into one `u64` (hi 32 = w, lo 32 = h) so the
/// media pumps can publish the current native capture dimensions to the
/// cursor pump through a single lock-free `AtomicU64`. `0` means "no
/// frame captured yet".
fn pack_dims(w: u32, h: u32) -> u64 {
    ((w as u64) << 32) | (h as u64)
}

/// Inverse of `pack_dims`; `(0, 0)` when no frame has been captured yet.
/// rc.199 — the DC video pumps read the native capture dims out of the
/// `capture_native_dims` atomic to stamp `rc:video-info` so the browser can
/// annotate the HUD ("1280×800 · relay-limited (native 2560×1600)").
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
fn unpack_dims(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, (packed & 0xFFFF_FFFF) as u32)
}

/// Per-axis scale factor the frame downscale applies to a captured frame,
/// so the remote-cursor overlay lands on the right pixel when the stream
/// is encoded below native resolution.
///
/// The cursor DC streams the OS cursor position in **native** capture
/// pixels (`GetCursorPos`), but the *video* frame may be downscaled before
/// encode, so the browser sees the **encoded** dimensions
/// (`mediaIntrinsicW/H`, read from the decoded frame) and computes the
/// overlay as `pos.x * visibleW / mediaIntrinsicW`. When native ≠ encoded
/// that overshoots by `native/encoded` (e.g. 1920/1280 = 1.5×) — the
/// field-reported "mouse lands in a different place at non-original
/// resolution" bug (rc.183). Scaling `pos` by this factor on the agent
/// puts the cursor in the same pixel space as the frame, so the browser
/// math is correct with no viewer change.
///
/// rc.190 — computed from the two dims the pump PUBLISHES (native +
/// actually-encoded) instead of re-deriving from `TargetResolution`. The
/// agent-side relay/SW caps can encode smaller than the controller asked,
/// so the ratio of published values is the only mapping that is correct by
/// definition — whatever the pump did, this reflects it.
fn cursor_scale_from_dims(native_dims: u64, encoded_dims: u64) -> (f32, f32) {
    let nw = (native_dims >> 32) as u32;
    let nh = (native_dims & 0xFFFF_FFFF) as u32;
    let ew = (encoded_dims >> 32) as u32;
    let eh = (encoded_dims & 0xFFFF_FFFF) as u32;
    if nw == 0 || nh == 0 || ew == 0 || eh == 0 {
        // Either side unpublished (no frame yet) → don't scale (matches
        // pre-rc.183 behaviour until the first frame lands).
        return (1.0, 1.0);
    }
    if (ew, eh) == (nw, nh) {
        return (1.0, 1.0);
    }
    (ew as f32 / nw as f32, eh as f32 / nh as f32)
}

/// Placeholder handler for data channels that aren't wired to OS output
/// yet (`files`). Logs message sizes so we can see activity without
/// spamming the log with contents.
fn attach_log_only(dc: Arc<RTCDataChannel>, session_id: bson::oid::ObjectId) {
    let label = dc.label().to_string();
    dc.on_message(Box::new(move |msg| {
        debug!(%session_id, %label, bytes = msg.data.len(), "DC msg (unhandled)");
        // FR-101 P4b-2 — a view-only session's input channel lands here: what
        // it sends is never injected, but the person sending it is present,
        // and the idle limit must not end their session under them.
        if label == "input" {
            crate::session_telemetry::counters(session_id).note_input_seen();
        }
        Box::pin(async {})
    }));
}

/// FR-101 P3 — count one clipboard transfer for the session's audit: how
/// many and how many bytes, never what.
#[cfg(feature = "clipboard")]
fn tally_clipboard(session_id: bson::oid::ObjectId, dir: TransferDirection, bytes: usize) {
    let counters = crate::session_telemetry::counters(session_id);
    let tally = match dir {
        TransferDirection::ToHost => &counters.clipboard_to_host,
        TransferDirection::FromHost => &counters.clipboard_from_host,
    };
    tally.add(bytes as u64);
}

/// Wire the `clipboard` DC to the agent's OS clipboard. Parses
/// inbound JSON as [`clipboard::ClipboardIncoming`] and dispatches:
///
/// - `clipboard:write { text }` — replace the OS clipboard with the
///   payload; no response (fire-and-forget).
/// - `clipboard:read { req_id? }` — read current OS clipboard text and
///   reply with `clipboard:content { text, req_id }`. Errors reply
///   with `clipboard:error { message }` so the browser can surface
///   the failure in a toast.
///
/// A single [`crate::clipboard::Clipboard`] is created per session; it
/// owns a thread-pinned `arboard::Clipboard`. On init failure we log
/// and leave the DC as a no-op (browser reads time out, writes are
/// silently dropped — no worse than pre-0.1.33).
#[cfg(feature = "clipboard")]
fn attach_clipboard_handler(
    dc: Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    permissions: roomler_ai_remote_control::permissions::Permissions,
    session_end: &tokio_util::sync::CancellationToken,
) {
    use roomler_ai_remote_control::permissions::Permissions;
    // Session-permission gate (v2 hardening — the CLIPBOARD bit existed
    // since day one but was never enforced agent-side). Deny → a stub
    // handler that answers every request with an error and never
    // touches the OS clipboard.
    if !permissions.contains(Permissions::CLIPBOARD) {
        info!(%session_id, "clipboard: session lacks CLIPBOARD permission — all requests will be rejected");
        let dc_for_handler = dc.clone();
        dc.on_message(Box::new(move |msg| {
            let dc = dc_for_handler.clone();
            Box::pin(async move {
                if !msg.is_string {
                    return;
                }
                // Best-effort correlation ids for the error reply; old
                // UIs drop `clipboard:error` without a req_id, which is
                // an acceptable silent deny.
                let v: Option<serde_json::Value> = std::str::from_utf8(&msg.data)
                    .ok()
                    .and_then(|s| serde_json::from_str(s).ok());
                let reply = serde_json::json!({
                    "t": "clipboard:error",
                    "message": "CLIPBOARD permission not granted for this session",
                    "req_id": v.as_ref().and_then(|v| v.get("req_id")).cloned(),
                    "id": v.as_ref().and_then(|v| v.get("id")).cloned(),
                });
                if let Ok(s) = serde_json::to_string(&reply) {
                    let _ = dc.send_text(s).await;
                }
            })
        }));
        // The stub holds its channel too: let go when the session ends.
        on_session_end(&dc, session_end, || async {});
        return;
    }
    // v2.2 — the process-SHARED clipboard worker (also used by the
    // loopback bridge): one set of echo self-marks process-wide, so a
    // bridge write on this host is never echoed back to a session
    // subscriber watching the same clipboard.
    let Some(cb) = crate::clipboard::Clipboard::shared() else {
        warn!(%session_id, "clipboard: init failed — DC will no-op");
        return;
    };
    // rc.44 — per-session reassembler for `clipboard:write-chunk`
    // envelopes. Shared across all on_message callbacks via the Arc.
    // Browser-side chunker is bounded at 14 KB per envelope; this
    // reassembler enforces the 1 MB total cap per write transaction
    // (see [`clipboard::MAX_CLIPBOARD_BYTES`]). `std::sync::Mutex` is
    // fine here: the lock is held for the duration of one synchronous
    // `feed()` call (push_str + invariant checks) and dropped before
    // the awaited `cb.write()`, so we never hold the guard across an
    // .await point.
    let reassembler = Arc::new(std::sync::Mutex::new(
        crate::clipboard::WriteReassembler::new(),
    ));
    // v2 — inbound image reassembly, serialized outbound image sends
    // (so anonymous binary frames always belong to the last announced
    // header), and the change-watcher forwarder task handle for
    // unsubscribe / DC-close teardown.
    let rich_rx = Arc::new(std::sync::Mutex::new(crate::clipboard::RichRx::new()));
    let img_tx_lock = Arc::new(tokio::sync::Mutex::new(()));
    let watch_task: Arc<std::sync::Mutex<Option<JoinHandle<()>>>> =
        Arc::new(std::sync::Mutex::new(None));
    // Multi-user P3 — THIS session's subscription token on the shared
    // clipboard worker. Tearing down by token removes only OUR feed (the
    // pre-P3 global Unwatch killed every session's).
    let watch_token: Arc<std::sync::Mutex<Option<u64>>> = Arc::new(std::sync::Mutex::new(None));

    // Set once the watch is torn down for good (the channel closed, or the
    // session ended). Read and written under `watch_token`'s lock, so a
    // Subscribe already in flight when the teardown runs installs nothing
    // after it (found in review: its subscription would never be unwatched,
    // and the shared worker would feed it forever).
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // DC close, or the session's end → tear down the watcher + forwarder so
    // the arboard worker stops ticking and the task doesn't outlive the
    // session. Both can fire; the second finds nothing left to stop.
    let stop_watching = {
        let cb = cb.clone();
        let watch_task = watch_task.clone();
        let watch_token = watch_token.clone();
        let stopped = stopped.clone();
        move || {
            {
                let mut token = watch_token.lock().expect("clipboard watch_token poisoned");
                stopped.store(true, std::sync::atomic::Ordering::Release);
                if let Some(id) = token.take() {
                    cb.unwatch(id);
                }
            }
            let old = watch_task
                .lock()
                .expect("clipboard watch_task poisoned")
                .take();
            if let Some(h) = old {
                h.abort();
            }
        }
    };
    {
        let stop_watching = stop_watching.clone();
        dc.on_close(Box::new(move || {
            stop_watching();
            Box::pin(async {})
        }));
    }

    let dc_for_handler = dc.clone();
    dc.on_message(Box::new(move |msg| {
        let dc = dc_for_handler.clone();
        let cb = cb.clone();
        let reassembler = reassembler.clone();
        let rich_rx = rich_rx.clone();
        let img_tx_lock = img_tx_lock.clone();
        let watch_task = watch_task.clone();
        let watch_token = watch_token.clone();
        let stopped = stopped.clone();
        Box::pin(async move {
            // v2 — binary frames are PNG chunks for the in-flight
            // browser → agent image transfer (announced by a preceding
            // `clipboard:img-begin` control frame).
            if !msg.is_string {
                let res = {
                    let mut rx = rich_rx.lock().expect("clipboard rich_rx poisoned");
                    rx.frame(&msg.data)
                };
                if let Err(reason) = res {
                    debug!(%session_id, %reason, "clipboard: dropped binary frame");
                }
                return;
            }
            let Ok(text) = std::str::from_utf8(&msg.data) else {
                debug!(%session_id, bytes = msg.data.len(), "clipboard: non-UTF8 payload ignored");
                return;
            };
            let parsed: Result<crate::clipboard::ClipboardIncoming, _> = serde_json::from_str(text);
            let parsed = match parsed {
                Ok(p) => p,
                Err(e) => {
                    debug!(%session_id, %e, "clipboard: unparseable JSON");
                    return;
                }
            };
            match parsed {
                crate::clipboard::ClipboardIncoming::Write { text, id } => {
                    let bytes = text.len();
                    match cb.write(text).await {
                        Ok(()) => {
                            info!(%session_id, bytes, "clipboard: wrote to host");
                            tally_clipboard(session_id, TransferDirection::ToHost, bytes);
                            // v2 ack — only when the browser stamped an
                            // id (old UIs don't, and never see acks).
                            // The browser gates its deferred Ctrl+V
                            // keystroke on this so the remote app pastes
                            // the NEW clipboard, not the stale one.
                            if let Some(id) = id {
                                let reply = serde_json::json!({
                                    "t": "clipboard:write-ack",
                                    "id": id,
                                    "bytes": bytes,
                                });
                                if let Ok(s) = serde_json::to_string(&reply) {
                                    let _ = dc.send_text(s).await;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(%session_id, %e, "clipboard: write failed");
                            let reply = serde_json::json!({
                                "t": "clipboard:error",
                                "message": format!("{e}"),
                                "id": id,
                            });
                            if let Ok(s) = serde_json::to_string(&reply) {
                                let _ = dc.send_text(s).await;
                            }
                        }
                    }
                }
                crate::clipboard::ClipboardIncoming::WriteChunk {
                    id,
                    seq,
                    text,
                    last,
                } => {
                    let chunk_bytes = text.len();
                    let outcome = {
                        let mut g = reassembler.lock().expect("clipboard reassembler poisoned");
                        g.feed(id.clone(), seq, text, last)
                    };
                    match outcome {
                        crate::clipboard::WriteChunkOutcome::Pending => {
                            debug!(%session_id, id=%id, seq, bytes=chunk_bytes, "clipboard: chunk accepted, awaiting more");
                        }
                        crate::clipboard::WriteChunkOutcome::Complete(full_text) => {
                            let bytes = full_text.len();
                            match cb.write(full_text).await {
                                Ok(()) => {
                                    info!(%session_id, id=%id, bytes, chunks=seq + 1, "clipboard: wrote chunked payload to host");
                                    tally_clipboard(session_id, TransferDirection::ToHost, bytes);
                                    // v2 ack, keyed by the chunk id the
                                    // browser already assigns. Old UIs
                                    // drop the unknown `t` silently.
                                    let reply = serde_json::json!({
                                        "t": "clipboard:write-ack",
                                        "id": id,
                                        "bytes": bytes,
                                    });
                                    if let Ok(s) = serde_json::to_string(&reply) {
                                        let _ = dc.send_text(s).await;
                                    }
                                }
                                Err(e) => {
                                    warn!(%session_id, id=%id, %e, "clipboard: chunked write failed");
                                    let reply = serde_json::json!({
                                        "t": "clipboard:error",
                                        "message": format!("{e}"),
                                        "id": id,
                                    });
                                    if let Ok(s) = serde_json::to_string(&reply) {
                                        let _ = dc.send_text(s).await;
                                    }
                                }
                            }
                        }
                        crate::clipboard::WriteChunkOutcome::Rejected(reason) => {
                            warn!(%session_id, id=%id, %reason, "clipboard: chunk rejected");
                            let reply = serde_json::json!({
                                "t": "clipboard:error",
                                "message": reason,
                                "id": id,
                            });
                            if let Ok(s) = serde_json::to_string(&reply) {
                                let _ = dc.send_text(s).await;
                            }
                        }
                    }
                }
                crate::clipboard::ClipboardIncoming::Read { req_id, accept } => {
                    // v2.2 — native-first rich read: only RTF carries a
                    // document's embedded images, so it outranks html.
                    if accept.iter().any(|a| a == "native") {
                        match cb.read_native().await {
                            Ok(Some(payload)) => {
                                info!(%session_id, rtf_bytes = payload.rtf.len(), "clipboard: read native from host");
                                send_clipboard_native(
                                    &dc,
                                    session_id,
                                    payload,
                                    req_id,
                                    &img_tx_lock,
                                )
                                .await;
                                return;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                debug!(%session_id, %e, "clipboard: native read failed — falling through");
                            }
                        }
                    }
                    // v2.1 — html-first rich read: an html-holding
                    // clipboard also carries a text alt, so html must
                    // be offered BEFORE the plain-text reply.
                    if accept.iter().any(|a| a == "html") {
                        match cb.read_html().await {
                            Ok(Some(payload)) => {
                                info!(%session_id, html_bytes = payload.html.len(), text_bytes = payload.text.len(), "clipboard: read html from host");
                                send_clipboard_html(
                                    &dc,
                                    session_id,
                                    payload,
                                    req_id,
                                    &img_tx_lock,
                                )
                                .await;
                                return;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                debug!(%session_id, %e, "clipboard: html read failed — falling through to text");
                            }
                        }
                    }
                    match cb.read().await {
                        Ok(text) if !text.is_empty() => {
                            let bytes = text.len();
                            tally_clipboard(session_id, TransferDirection::FromHost, bytes);
                            if bytes <= crate::clipboard::CHUNK_BYTES {
                                // Single envelope — back-compat path for
                                // browsers that don't yet handle
                                // `clipboard:content-chunk`. Small payloads
                                // (most common case) fit inside a single
                                // SCTP message comfortably.
                                info!(%session_id, bytes, "clipboard: read from host (single envelope)");
                                let reply = serde_json::json!({
                                    "t": "clipboard:content",
                                    "text": text,
                                    "req_id": req_id,
                                });
                                if let Ok(s) = serde_json::to_string(&reply) {
                                    let _ = dc.send_text(s).await;
                                }
                            } else {
                                // Large payload — chunk it so each
                                // envelope stays under the SCTP ceiling.
                                // Browser reassembles by `req_id` until
                                // `last: true`.
                                let chunks = crate::clipboard::split_into_chunks(&text);
                                let total = chunks.len();
                                info!(%session_id, bytes, chunks = total, "clipboard: read from host (chunked)");
                                for (i, chunk) in chunks.iter().enumerate() {
                                    let reply = serde_json::json!({
                                        "t": "clipboard:content-chunk",
                                        "req_id": req_id,
                                        "seq": i as u32,
                                        "text": chunk,
                                        "last": i + 1 == total,
                                    });
                                    if let Ok(s) = serde_json::to_string(&reply)
                                        && dc.send_text(s).await.is_err()
                                    {
                                        debug!(%session_id, "clipboard: DC closed mid-chunk-send; abandoning");
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(_empty) => {
                            // v2 rich read — no text on the clipboard.
                            // Offer an image when the browser said it can
                            // take one; otherwise (and for old UIs, whose
                            // `accept` is empty) reply empty content.
                            if accept.iter().any(|a| a == "image") {
                                match cb.read_image().await {
                                    Ok(Some(img)) => {
                                        info!(%session_id, w = img.w, h = img.h, bytes = img.png.len(), "clipboard: read image from host");
                                        send_clipboard_image(
                                            &dc,
                                            session_id,
                                            img,
                                            req_id,
                                            &img_tx_lock,
                                        )
                                        .await;
                                        return;
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        warn!(%session_id, %e, "clipboard: image read failed");
                                        let reply = serde_json::json!({
                                            "t": "clipboard:error",
                                            "message": format!("{e}"),
                                            "req_id": req_id,
                                        });
                                        if let Ok(s) = serde_json::to_string(&reply) {
                                            let _ = dc.send_text(s).await;
                                        }
                                        return;
                                    }
                                }
                            }
                            info!(%session_id, "clipboard: read from host (empty)");
                            let reply = serde_json::json!({
                                "t": "clipboard:content",
                                "text": "",
                                "req_id": req_id,
                            });
                            if let Ok(s) = serde_json::to_string(&reply) {
                                let _ = dc.send_text(s).await;
                            }
                        }
                        Err(e) => {
                            warn!(%session_id, %e, "clipboard: read failed");
                            let reply = serde_json::json!({
                                "t": "clipboard:error",
                                "message": format!("{e}"),
                                "req_id": req_id,
                            });
                            if let Ok(s) = serde_json::to_string(&reply) {
                                let _ = dc.send_text(s).await;
                            }
                        }
                    }
                }
                crate::clipboard::ClipboardIncoming::Subscribe { events } => {
                    // Empty events list (defensive) means text-only —
                    // the browser always sends an explicit list.
                    let want_text = events.is_empty() || events.iter().any(|e| e == "text");
                    let want_image = events.iter().any(|e| e == "image");
                    let want_html = events.iter().any(|e| e == "html");
                    let want_native = events.iter().any(|e| e == "native");
                    let (tx, mut rx) =
                        tokio::sync::mpsc::channel::<crate::clipboard::ClipboardChange>(4);
                    let token = match cb.watch(
                        crate::clipboard::WatchEvents {
                            text: want_text,
                            image: want_image,
                            html: want_html,
                            native: want_native,
                        },
                        tx,
                    ) {
                        Ok(t) => t,
                        Err(e) => {
                            warn!(%session_id, %e, "clipboard: subscribe failed (worker gone)");
                            return;
                        }
                    };
                    // A re-subscribe within THIS session replaces only its
                    // own prior subscription (other sessions' feeds are
                    // untouched — the P3 multi-subscriber registry).
                    {
                        let mut installed =
                            watch_token.lock().expect("clipboard watch_token poisoned");
                        // Torn down while this was in flight: nothing may
                        // outlive the teardown (its forwarder ends with the
                        // subscription).
                        if stopped.load(std::sync::atomic::Ordering::Acquire) {
                            drop(installed);
                            cb.unwatch(token);
                            return;
                        }
                        if let Some(old) = installed.replace(token) {
                            cb.unwatch(old);
                        }
                    }
                    info!(%session_id, text = want_text, image = want_image, html = want_html, native = want_native, "clipboard: change subscription installed");
                    let dc_for_events = dc.clone();
                    let img_lock_for_events = img_tx_lock.clone();
                    let handle = tokio::spawn(async move {
                        let mut event_seq: u64 = 0;
                        while let Some(change) = rx.recv().await {
                            event_seq += 1;
                            match change {
                                crate::clipboard::ClipboardChange::Text(text) => {
                                    send_clipboard_text_event(
                                        &dc_for_events,
                                        session_id,
                                        &text,
                                        event_seq,
                                    )
                                    .await;
                                }
                                crate::clipboard::ClipboardChange::Image(img) => {
                                    send_clipboard_image(
                                        &dc_for_events,
                                        session_id,
                                        img,
                                        None,
                                        &img_lock_for_events,
                                    )
                                    .await;
                                }
                                crate::clipboard::ClipboardChange::Html(payload) => {
                                    send_clipboard_html(
                                        &dc_for_events,
                                        session_id,
                                        payload,
                                        None,
                                        &img_lock_for_events,
                                    )
                                    .await;
                                }
                                crate::clipboard::ClipboardChange::Native(payload) => {
                                    send_clipboard_native(
                                        &dc_for_events,
                                        session_id,
                                        *payload,
                                        None,
                                        &img_lock_for_events,
                                    )
                                    .await;
                                }
                            }
                        }
                    });
                    let old = watch_task
                        .lock()
                        .expect("clipboard watch_task poisoned")
                        .replace(handle);
                    if let Some(h) = old {
                        h.abort();
                    }
                }
                crate::clipboard::ClipboardIncoming::Unsubscribe => {
                    if let Some(id) = watch_token
                        .lock()
                        .expect("clipboard watch_token poisoned")
                        .take()
                    {
                        cb.unwatch(id);
                    }
                    let old = watch_task
                        .lock()
                        .expect("clipboard watch_task poisoned")
                        .take();
                    if let Some(h) = old {
                        h.abort();
                    }
                    info!(%session_id, "clipboard: change subscription removed");
                }
                crate::clipboard::ClipboardIncoming::ImgBegin {
                    id,
                    w,
                    h,
                    bytes,
                    format,
                } => {
                    let res = {
                        let mut rx = rich_rx.lock().expect("clipboard rich_rx poisoned");
                        rx.begin_image(id.clone(), w, h, bytes, &format)
                    };
                    match res {
                        Ok(()) => {
                            debug!(%session_id, %id, w, h, bytes, "clipboard: image write begin")
                        }
                        Err(reason) => {
                            warn!(%session_id, %id, %reason, "clipboard: image begin rejected");
                            let reply = serde_json::json!({
                                "t": "clipboard:error",
                                "message": reason,
                                "id": id,
                            });
                            if let Ok(s) = serde_json::to_string(&reply) {
                                let _ = dc.send_text(s).await;
                            }
                        }
                    }
                }
                crate::clipboard::ClipboardIncoming::HtmlBegin {
                    id,
                    html_bytes,
                    text_bytes,
                } => {
                    let res = {
                        let mut rx = rich_rx.lock().expect("clipboard rich_rx poisoned");
                        rx.begin_html(id.clone(), html_bytes, text_bytes)
                    };
                    match res {
                        Ok(()) => {
                            debug!(%session_id, %id, html_bytes, text_bytes, "clipboard: html write begin")
                        }
                        Err(reason) => {
                            warn!(%session_id, %id, %reason, "clipboard: html begin rejected");
                            let reply = serde_json::json!({
                                "t": "clipboard:error",
                                "message": reason,
                                "id": id,
                            });
                            if let Ok(s) = serde_json::to_string(&reply) {
                                let _ = dc.send_text(s).await;
                            }
                        }
                    }
                }
                crate::clipboard::ClipboardIncoming::NativeBegin {
                    id,
                    rtf_bytes,
                    html_bytes,
                    text_bytes,
                } => {
                    let res = {
                        let mut rx = rich_rx.lock().expect("clipboard rich_rx poisoned");
                        rx.begin_native(id.clone(), rtf_bytes, html_bytes, text_bytes)
                    };
                    match res {
                        Ok(()) => {
                            debug!(%session_id, %id, rtf_bytes, html_bytes, text_bytes, "clipboard: native write begin")
                        }
                        Err(reason) => {
                            warn!(%session_id, %id, %reason, "clipboard: native begin rejected");
                            let reply = serde_json::json!({
                                "t": "clipboard:error",
                                "message": reason,
                                "id": id,
                            });
                            if let Ok(s) = serde_json::to_string(&reply) {
                                let _ = dc.send_text(s).await;
                            }
                        }
                    }
                }
                crate::clipboard::ClipboardIncoming::ImgEnd { id }
                | crate::clipboard::ClipboardIncoming::HtmlEnd { id }
                | crate::clipboard::ClipboardIncoming::NativeEnd { id } => {
                    finish_rich_write(&dc, session_id, &cb, &rich_rx, &id).await;
                }
            }
        })
    }));
    // Last, after the callbacks are in place (see `on_session_end`).
    on_session_end(&dc, session_end, move || async move { stop_watching() });
}

/// Complete an inbound rich transfer (`clipboard:img-end` /
/// `clipboard:html-end`): reassemble, write to the OS clipboard in the
/// payload's native shape, ack (or error) with the transfer id.
#[cfg(feature = "clipboard")]
async fn finish_rich_write(
    dc: &Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    cb: &crate::clipboard::Clipboard,
    rich_rx: &Arc<std::sync::Mutex<crate::clipboard::RichRx>>,
    id: &str,
) {
    let assembled = {
        let mut rx = rich_rx.lock().expect("clipboard rich_rx poisoned");
        rx.end(id)
    };
    let result: Result<usize, String> = match assembled {
        Ok(crate::clipboard::RichPayload::Image(img)) => {
            let bytes = img.png.len();
            match cb.write_image(img.png).await {
                Ok(()) => {
                    info!(%session_id, id, bytes, "clipboard: wrote image to host");
                    Ok(bytes)
                }
                Err(e) => Err(format!("{e}")),
            }
        }
        Ok(crate::clipboard::RichPayload::Html(payload)) => {
            let bytes = payload.html.len() + payload.text.len();
            match cb.write_html(payload.html, payload.text).await {
                Ok(()) => {
                    info!(%session_id, id, bytes, "clipboard: wrote html to host");
                    Ok(bytes)
                }
                Err(e) => Err(format!("{e}")),
            }
        }
        Ok(crate::clipboard::RichPayload::Native(payload)) => {
            let bytes = payload.rtf.len() + payload.html.len() + payload.text.len();
            match cb.write_native(*payload).await {
                Ok(()) => {
                    info!(%session_id, id, bytes, "clipboard: wrote native (RTF) to host");
                    Ok(bytes)
                }
                Err(e) => Err(format!("{e}")),
            }
        }
        Err(reason) => Err(reason),
    };
    if let Ok(bytes) = &result {
        tally_clipboard(session_id, TransferDirection::ToHost, *bytes);
    }
    let reply = match result {
        Ok(bytes) => serde_json::json!({
            "t": "clipboard:write-ack",
            "id": id,
            "bytes": bytes,
        }),
        Err(message) => {
            warn!(%session_id, id, %message, "clipboard: rich write failed");
            serde_json::json!({
                "t": "clipboard:error",
                "message": message,
                "id": id,
            })
        }
    };
    if let Ok(s) = serde_json::to_string(&reply) {
        let _ = dc.send_text(s).await;
    }
}

/// v2.2 — stream one NATIVE payload (RTF + html + text) to the
/// browser: `clipboard:native-begin` header, 64 KiB binary frames
/// (rtf, then html UTF-8, then text UTF-8), `clipboard:native-end`
/// trailer. Same serialization lock + backpressure as images/html.
#[cfg(feature = "clipboard")]
async fn send_clipboard_native(
    dc: &Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    payload: crate::clipboard::NativePayload,
    req_id: Option<u64>,
    tx_lock: &tokio::sync::Mutex<()>,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NATIVE_TX_SEQ: AtomicU64 = AtomicU64::new(0);
    const BACKPRESSURE_HIGH: usize = 4 * 1024 * 1024;
    const BACKPRESSURE_MAX_SPINS: u32 = 750;

    let _guard = tx_lock.lock().await;
    let id = format!("anative-{}", NATIVE_TX_SEQ.fetch_add(1, Ordering::Relaxed));
    let rtf_bytes = payload.rtf.len();
    let html_bytes = payload.html.len();
    let text_bytes = payload.text.len();
    debug!(%session_id, %id, rtf_bytes, html_bytes, text_bytes, ?req_id, "clipboard: sending native");
    tally_clipboard(
        session_id,
        TransferDirection::FromHost,
        rtf_bytes + html_bytes + text_bytes,
    );
    let begin = serde_json::json!({
        "t": "clipboard:native-begin",
        "id": id,
        "rtf_bytes": rtf_bytes as u64,
        "html_bytes": html_bytes as u64,
        "text_bytes": text_bytes as u64,
        "req_id": req_id,
    });
    let Ok(s) = serde_json::to_string(&begin) else {
        return;
    };
    if dc.send_text(s).await.is_err() {
        return;
    }
    let mut combined = Vec::with_capacity(rtf_bytes + html_bytes + text_bytes);
    combined.extend_from_slice(&payload.rtf);
    combined.extend_from_slice(payload.html.as_bytes());
    combined.extend_from_slice(payload.text.as_bytes());
    for chunk in combined.chunks(crate::clipboard::IMG_FRAME_BYTES_TX) {
        let mut spins = 0u32;
        while dc.buffered_amount().await > BACKPRESSURE_HIGH {
            tokio::time::sleep(Duration::from_millis(20)).await;
            spins += 1;
            if spins > BACKPRESSURE_MAX_SPINS {
                debug!(%session_id, %id, "clipboard: backpressure stall; abandoning native send");
                return;
            }
        }
        if dc.send(&Bytes::copy_from_slice(chunk)).await.is_err() {
            debug!(%session_id, %id, "clipboard: DC closed mid-native-send; abandoning");
            return;
        }
    }
    let end = serde_json::json!({
        "t": "clipboard:native-end",
        "id": id,
    });
    if let Ok(s) = serde_json::to_string(&end) {
        let _ = dc.send_text(s).await;
    }
}

/// v2.1 — stream one HTML payload (+ its text alt) to the browser:
/// `clipboard:html-begin` header, 64 KiB binary frames (html bytes
/// then text bytes), `clipboard:html-end` trailer. `req_id` present ⇒
/// answers a rich read; absent ⇒ unsolicited change event. Shares the
/// image sender's serialization lock so anonymous binary frames always
/// belong to the last announced header.
#[cfg(feature = "clipboard")]
async fn send_clipboard_html(
    dc: &Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    payload: crate::clipboard::HtmlPayload,
    req_id: Option<u64>,
    tx_lock: &tokio::sync::Mutex<()>,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static HTML_TX_SEQ: AtomicU64 = AtomicU64::new(0);
    const BACKPRESSURE_HIGH: usize = 4 * 1024 * 1024;
    const BACKPRESSURE_MAX_SPINS: u32 = 750;

    let _guard = tx_lock.lock().await;
    let id = format!("ahtml-{}", HTML_TX_SEQ.fetch_add(1, Ordering::Relaxed));
    let html_bytes = payload.html.len();
    let text_bytes = payload.text.len();
    debug!(%session_id, %id, html_bytes, text_bytes, ?req_id, "clipboard: sending html");
    tally_clipboard(
        session_id,
        TransferDirection::FromHost,
        html_bytes + text_bytes,
    );
    let begin = serde_json::json!({
        "t": "clipboard:html-begin",
        "id": id,
        "html_bytes": html_bytes as u64,
        "text_bytes": text_bytes as u64,
        "req_id": req_id,
    });
    let Ok(s) = serde_json::to_string(&begin) else {
        return;
    };
    if dc.send_text(s).await.is_err() {
        return;
    }
    let mut combined = Vec::with_capacity(html_bytes + text_bytes);
    combined.extend_from_slice(payload.html.as_bytes());
    combined.extend_from_slice(payload.text.as_bytes());
    for chunk in combined.chunks(crate::clipboard::IMG_FRAME_BYTES_TX) {
        let mut spins = 0u32;
        while dc.buffered_amount().await > BACKPRESSURE_HIGH {
            tokio::time::sleep(Duration::from_millis(20)).await;
            spins += 1;
            if spins > BACKPRESSURE_MAX_SPINS {
                debug!(%session_id, %id, "clipboard: backpressure stall; abandoning html send");
                return;
            }
        }
        if dc.send(&Bytes::copy_from_slice(chunk)).await.is_err() {
            debug!(%session_id, %id, "clipboard: DC closed mid-html-send; abandoning");
            return;
        }
    }
    let end = serde_json::json!({
        "t": "clipboard:html-end",
        "id": id,
    });
    if let Ok(s) = serde_json::to_string(&end) {
        let _ = dc.send_text(s).await;
    }
}

/// Send one host-clipboard text change to the browser: a single
/// `clipboard:event` when it fits one envelope, else
/// `clipboard:event-chunk`s keyed by a per-subscription event id.
#[cfg(feature = "clipboard")]
async fn send_clipboard_text_event(
    dc: &Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    text: &str,
    event_seq: u64,
) {
    let bytes = text.len();
    tally_clipboard(session_id, TransferDirection::FromHost, bytes);
    if bytes <= crate::clipboard::CHUNK_BYTES {
        debug!(%session_id, bytes, "clipboard: pushing text change");
        let msg = serde_json::json!({
            "t": "clipboard:event",
            "kind": "text",
            "text": text,
        });
        if let Ok(s) = serde_json::to_string(&msg) {
            let _ = dc.send_text(s).await;
        }
        return;
    }
    let chunks = crate::clipboard::split_into_chunks(text);
    let total = chunks.len();
    let event_id = format!("ev-{event_seq}");
    debug!(%session_id, bytes, chunks = total, %event_id, "clipboard: pushing text change (chunked)");
    for (i, chunk) in chunks.iter().enumerate() {
        let msg = serde_json::json!({
            "t": "clipboard:event-chunk",
            "event_id": event_id,
            "seq": i as u32,
            "text": chunk,
            "last": i + 1 == total,
        });
        if let Ok(s) = serde_json::to_string(&msg)
            && dc.send_text(s).await.is_err()
        {
            debug!(%session_id, "clipboard: DC closed mid-event-send; abandoning");
            return;
        }
    }
}

/// Stream one PNG image to the browser: `clipboard:img-begin` header,
/// 64 KiB binary frames under SCTP backpressure, `clipboard:img-end`
/// trailer. `req_id` present ⇒ answers a rich read; absent ⇒
/// unsolicited change event. `tx_lock` serializes image streams so the
/// anonymous binary frames always belong to the last announced header.
#[cfg(feature = "clipboard")]
async fn send_clipboard_image(
    dc: &Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    img: crate::clipboard::PngImage,
    req_id: Option<u64>,
    tx_lock: &tokio::sync::Mutex<()>,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static IMG_TX_SEQ: AtomicU64 = AtomicU64::new(0);
    const BACKPRESSURE_HIGH: usize = 4 * 1024 * 1024;
    // 20 ms × 750 = 15 s of sustained full buffer → the DC is wedged
    // (or the viewer is gone); abandon rather than hold the tx_lock
    // forever.
    const BACKPRESSURE_MAX_SPINS: u32 = 750;

    let _guard = tx_lock.lock().await;
    let id = format!("aimg-{}", IMG_TX_SEQ.fetch_add(1, Ordering::Relaxed));
    let bytes = img.png.len();
    debug!(%session_id, %id, w = img.w, h = img.h, bytes, ?req_id, "clipboard: sending image");
    tally_clipboard(session_id, TransferDirection::FromHost, bytes);
    let begin = serde_json::json!({
        "t": "clipboard:img-begin",
        "id": id,
        "w": img.w,
        "h": img.h,
        "bytes": bytes as u64,
        "format": "png",
        "req_id": req_id,
    });
    let Ok(s) = serde_json::to_string(&begin) else {
        return;
    };
    if dc.send_text(s).await.is_err() {
        return;
    }
    for chunk in img.png.chunks(crate::clipboard::IMG_FRAME_BYTES_TX) {
        let mut spins = 0u32;
        while dc.buffered_amount().await > BACKPRESSURE_HIGH {
            tokio::time::sleep(Duration::from_millis(20)).await;
            spins += 1;
            if spins > BACKPRESSURE_MAX_SPINS {
                debug!(%session_id, %id, "clipboard: backpressure stall; abandoning image send");
                return;
            }
        }
        if dc.send(&Bytes::copy_from_slice(chunk)).await.is_err() {
            debug!(%session_id, %id, "clipboard: DC closed mid-image-send; abandoning");
            return;
        }
    }
    let end = serde_json::json!({
        "t": "clipboard:img-end",
        "id": id,
        "bytes": bytes as u64,
    });
    if let Ok(s) = serde_json::to_string(&end) {
        let _ = dc.send_text(s).await;
    }
}

/// Wire the `files` DC to a per-session file-transfer handler. Strings
/// carry control frames (`files:begin`/`files:end` + agent replies);
/// binary frames are chunk payloads appended to the current in-flight
/// transfer. The handler enforces one active transfer at a time and
/// replies with `files:accepted` / `files:progress` / `files:complete`
/// / `files:error` over the same channel.
///
/// Public so `crates/tests/src/file_dc_tests.rs` can attach the same
/// dispatcher to a loopback DC and lock the wire format end-to-end.
/// The dispatcher itself stays private (free fns below) — only the
/// wiring entry point is needed across crates.
/// Multi-user P3 — the FILES-denied handler: every control frame gets an
/// explicit `files:error` (addressed by the frame's own `id` when present, so
/// the browser's per-transfer waiter rejects instead of timing out) and
/// binary chunks are dropped. Mirrors the clipboard gate's reject-don't-serve
/// posture; installed when the session's grant lacks `Permissions::FILES`.
pub fn attach_files_denied(
    dc: Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    session_end: &tokio_util::sync::CancellationToken,
) {
    info!(
        session = %session_id,
        "files DC attached in DENY mode — session lacks FILES permission"
    );
    let dc_for_handler = dc.clone();
    dc.on_message(Box::new(move |msg| {
        let dc = dc_for_handler.clone();
        Box::pin(async move {
            if !msg.is_string {
                return; // chunk for a transfer that was never accepted
            }
            let id = std::str::from_utf8(&msg.data)
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_string))
                .unwrap_or_default();
            send_files_json(
                &dc,
                &crate::files::FilesOutgoing::Error {
                    id: &id,
                    message: "FILES permission not granted for this session",
                },
            )
            .await;
        })
    }));
    // The stub holds its channel too: let go when the session ends.
    on_session_end(&dc, session_end, || async {});
}

pub fn attach_files_handler(
    dc: Arc<RTCDataChannel>,
    session_id: bson::oid::ObjectId,
    // An upload in flight holds its file open: let go when the session
    // ends, whether or not the channel says it closed.
    session_end: &tokio_util::sync::CancellationToken,
) {
    let handler = crate::files::FilesHandler::new();
    let dc_for_handler = dc.clone();
    let handler_for_close = handler.clone();
    dc.on_close(Box::new(move || {
        let h = handler_for_close.clone();
        Box::pin(async move {
            h.abort().await;
        })
    }));
    let handler_for_end = handler.clone();
    dc.on_message(Box::new(move |msg| {
        let dc = dc_for_handler.clone();
        let handler = handler.clone();
        Box::pin(async move {
            // FR-101 P4b-2 — every message the controller sends here (an
            // upload's chunks, a request to browse or download) is activity
            // for the session's idle limit.
            crate::session_telemetry::counters(session_id).note_transfer();
            if msg.is_string {
                handle_files_control(dc, handler, session_id, &msg.data).await;
            } else {
                handle_files_chunk(dc, handler, session_id, &msg.data).await;
            }
        })
    }));
    // Last, after the callbacks are in place (see `on_session_end`). An
    // upload's state goes, and a download's pump stops (`end_session`).
    on_session_end(&dc, session_end, move || async move {
        handler_for_end.end_session().await;
    });
}

/// Has this channel closed, or begun to? `Closing` counts: a channel closed
/// from the device's own side often stops there for good, without ever
/// reaching `Closed` or firing `on_close` (a race in webrtc-rs's read loop).
fn channel_gone(state: webrtc::data_channel::data_channel_state::RTCDataChannelState) -> bool {
    use webrtc::data_channel::data_channel_state::RTCDataChannelState as S;
    matches!(state, S::Closing | S::Closed)
}

/// When the session ends ([`AgentPeer::session_end`]): let go of the
/// channel's callbacks (they hold the handler, and the handler holds the
/// channel, so otherwise neither is ever freed), then run `teardown` once.
///
/// ⚠️ For what a handler must release even when its channel never says it
/// closed. Its own `on_close` stays as well, for a channel the controller
/// closes while the session goes on; the teardown must be safe to run twice.
///
/// ⚠️ Call it LAST in an attach, after the channel's real callbacks are in
/// place: a channel can still arrive after the session ended (`close` cancels
/// first, and the peer's own close takes a while), and a swap that ran before
/// the real callbacks landed would be overwritten by them (found in review).
/// The callbacks go FIRST, then the teardown, so no new message starts work
/// the teardown has already passed; a message already in flight is the
/// handler's own race to close (see the clipboard's `stopped`).
fn on_session_end<F, Fut>(
    dc: &Arc<RTCDataChannel>,
    session_end: &tokio_util::sync::CancellationToken,
    teardown: F,
) where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let dc = dc.clone();
    let session_end = session_end.clone();
    tokio::spawn(async move {
        session_end.cancelled().await;
        dc.on_message(Box::new(|_| Box::pin(async {})));
        dc.on_close(Box::new(|| Box::pin(async {})));
        teardown().await;
    });
}

async fn handle_files_control(
    dc: Arc<RTCDataChannel>,
    handler: crate::files::FilesHandler,
    session_id: bson::oid::ObjectId,
    data: &[u8],
) {
    let Ok(text) = std::str::from_utf8(data) else {
        debug!(%session_id, bytes = data.len(), "files: non-UTF8 control ignored");
        return;
    };
    let parsed: Result<crate::files::FilesIncoming, _> = serde_json::from_str(text);
    let parsed = match parsed {
        Ok(p) => p,
        Err(e) => {
            debug!(%session_id, %e, "files: unparseable control JSON");
            return;
        }
    };
    match parsed {
        crate::files::FilesIncoming::Begin {
            id,
            name,
            size,
            mime,
            rel_path,
            dest_path,
        } => {
            info!(%session_id, %id, %name, size, ?mime, ?rel_path, ?dest_path, "files: begin");
            match handler
                .begin(
                    id.clone(),
                    name,
                    size,
                    rel_path.as_deref(),
                    dest_path.as_deref(),
                )
                .await
            {
                Ok(path) => {
                    let path_str = path.to_string_lossy();
                    send_files_json(
                        &dc,
                        &crate::files::FilesOutgoing::Accepted {
                            id: &id,
                            path: &path_str,
                        },
                    )
                    .await;
                }
                Err(e) => {
                    warn!(%session_id, %id, %e, "files: begin failed");
                    let msg = format!("{e}");
                    send_files_json(
                        &dc,
                        &crate::files::FilesOutgoing::Error {
                            id: &id,
                            message: &msg,
                        },
                    )
                    .await;
                }
            }
        }
        crate::files::FilesIncoming::End { id } => match handler.end(&id).await {
            Ok((path, bytes)) => {
                info!(%session_id, %id, bytes, path = %path.display(), "files: complete");
                // FR-101 P3 — the audit gets the name's hash, never the name.
                crate::session_telemetry::counters(session_id).note_file(
                    TransferDirection::ToHost,
                    &path
                        .file_name()
                        .map(|n| n.to_string_lossy())
                        .unwrap_or_default(),
                    bytes,
                );
                let path_str = path.to_string_lossy();
                send_files_json(
                    &dc,
                    &crate::files::FilesOutgoing::Complete {
                        id: &id,
                        path: &path_str,
                        bytes,
                    },
                )
                .await;
            }
            Err(e) => {
                warn!(%session_id, %id, %e, "files: end failed");
                let msg = format!("{e}");
                send_files_json(
                    &dc,
                    &crate::files::FilesOutgoing::Error {
                        id: &id,
                        message: &msg,
                    },
                )
                .await;
            }
        },
        crate::files::FilesIncoming::Get { id, path } => {
            info!(%session_id, %id, path = %path, "files: get (download requested)");
            spawn_outgoing_pump(dc.clone(), handler, session_id, id, path);
        }
        crate::files::FilesIncoming::GetFolder { id, path, format } => {
            // v1 only honours `format=zip` (or unset, treated as zip).
            if let Some(f) = format.as_deref()
                && f != "zip"
            {
                warn!(%session_id, %id, format = %f, "files: get-folder unsupported format");
                send_files_json(
                    &dc,
                    &crate::files::FilesOutgoing::Error {
                        id: &id,
                        message: "unsupported folder-download format (only 'zip' is supported)",
                    },
                )
                .await;
                return;
            }
            info!(%session_id, %id, path = %path, "files: get-folder (zip) requested");
            spawn_outgoing_zip_pump(dc.clone(), handler, session_id, id, path);
        }
        crate::files::FilesIncoming::Cancel { id } => {
            // rc.19: try both directions. cancel_outgoing flips a
            // flag if the id matches an in-flight download.
            // cancel_incoming clears upload state + removes the
            // .roomler-partial/<id>/ staging dir + registry entry so
            // the partial doesn't sit until the 24h orphan sweep.
            // Browsers send files:cancel on terminal upload failure
            // (6 reconnect attempts exhausted).
            let out_cancelled = handler.cancel_outgoing(&id).await;
            let in_cancelled = handler.cancel_incoming(&id).await;
            info!(
                %session_id, %id, out_cancelled, in_cancelled,
                "files: cancel requested"
            );
        }
        crate::files::FilesIncoming::Dir { req_id, path } => {
            if !crate::files::is_remote_browse_enabled() {
                info!(%session_id, %req_id, path = %path, "files: dir refused — remote browse disabled");
                send_files_json(
                    &dc,
                    &crate::files::FilesOutgoing::DirError {
                        req_id: &req_id,
                        message: "remote browse disabled by host config",
                    },
                )
                .await;
                return;
            }
            match crate::files::list_dir(&path).await {
                Ok(listing) => {
                    info!(
                        %session_id, %req_id,
                        path = %listing.path,
                        entries = listing.entries.len(),
                        "files: dir listed"
                    );
                    let parent_owned = listing.parent.clone();
                    send_files_json(
                        &dc,
                        &crate::files::FilesOutgoing::DirList {
                            req_id: &req_id,
                            path: &listing.path,
                            parent: parent_owned.as_deref(),
                            entries: &listing.entries,
                        },
                    )
                    .await;
                }
                Err(e) => {
                    warn!(%session_id, %req_id, path = %path, %e, "files: dir failed");
                    let msg = format!("{e}");
                    send_files_json(
                        &dc,
                        &crate::files::FilesOutgoing::DirError {
                            req_id: &req_id,
                            message: &msg,
                        },
                    )
                    .await;
                }
            }
        }
        crate::files::FilesIncoming::Resume {
            id,
            offset,
            sha256_prefix: _,
        } => {
            // rc.19 P2: look up the partial in PARTIAL_REGISTRY (or
            // on-demand stat under Downloads), truncate the data
            // file to a 256 KiB-aligned offset, reinstall
            // IncomingTransfer state in this DC's incoming Mutex,
            // and reply `files:resumed { id, accepted_offset }`.
            // sha256_prefix is reserved for v2 — v1 ignores it.
            match handler.resume_incoming(&id, offset).await {
                Ok(accepted_offset) => {
                    info!(
                        %session_id, %id, requested = %offset,
                        accepted_offset, "files: resume accepted"
                    );
                    send_files_json(
                        &dc,
                        &crate::files::FilesOutgoing::Resumed {
                            id: &id,
                            accepted_offset,
                        },
                    )
                    .await;
                }
                Err(e) => {
                    warn!(%session_id, %id, %offset, %e, "files: resume rejected");
                    let msg = format!("{e}");
                    send_files_json(
                        &dc,
                        &crate::files::FilesOutgoing::Error {
                            id: &id,
                            message: &msg,
                        },
                    )
                    .await;
                }
            }
        }
    }
}

/// Spawn a tokio task that pumps an outgoing single-file download.
/// The task owns the `Arc<RTCDataChannel>` so the DC outlives the
/// stream even if the original `attach_files_handler` closure has
/// returned. It stops through the stop token on `OutgoingTransfer`,
/// which `cancel_outgoing` (the browser) and `end_session` (the session
/// ending) fire; every await races it (#1730).
fn spawn_outgoing_pump(
    dc: Arc<RTCDataChannel>,
    handler: crate::files::FilesHandler,
    session_id: bson::oid::ObjectId,
    id: String,
    requested_path: String,
) {
    tokio::spawn(async move {
        // begin_outgoing validates the path + denylist, opens the
        // file, and stashes outgoing state. Success → send `Offer`
        // and start streaming.
        let offer = match handler.begin_outgoing(id.clone(), &requested_path).await {
            Ok(o) => o,
            Err(e) => {
                warn!(%session_id, %id, path = %requested_path, %e, "files: begin_outgoing failed");
                let msg = format!("{e}");
                send_files_json(
                    &dc,
                    &crate::files::FilesOutgoing::Error {
                        id: &id,
                        message: &msg,
                    },
                )
                .await;
                return;
            }
        };

        // #1730 — from here every message races the stop token too, and the
        // transfer's state (with the updater's guard) goes FIRST on every
        // exit: a last message to a peer that vanished may never be sent.
        if or_stopped(
            &offer.cancel,
            send_files_json(
                &dc,
                &crate::files::FilesOutgoing::Offer {
                    id: &offer.id,
                    name: &offer.name,
                    size: offer.size,
                    mime: offer.mime,
                },
            ),
        )
        .await
        .is_err()
        {
            handler.finish_outgoing(&offer.id).await;
            return;
        }

        let bytes_sent = match pump_outgoing_file(&dc, &handler, &offer, session_id).await {
            Ok(n) => n,
            Err(e) => {
                handler.finish_outgoing(&offer.id).await;
                if offer.cancel.is_cancelled() {
                    info!(%session_id, id = %offer.id, "files: download stopped (cancelled, or the session ended)");
                    return;
                }
                warn!(%session_id, id = %offer.id, %e, "files: pump_outgoing failed");
                let msg = format!("{e}");
                let _ = or_stopped(
                    &offer.cancel,
                    send_files_json(
                        &dc,
                        &crate::files::FilesOutgoing::Error {
                            id: &offer.id,
                            message: &msg,
                        },
                    ),
                )
                .await;
                return;
            }
        };

        // Successful end-of-stream: clear state, then send Eof so the
        // browser closes the writable cleanly.
        info!(
            %session_id, id = %offer.id, bytes_sent, path = %offer.path.display(),
            "files: outgoing complete"
        );
        crate::session_telemetry::counters(session_id).note_file(
            TransferDirection::FromHost,
            &offer.name,
            bytes_sent,
        );
        handler.finish_outgoing(&offer.id).await;
        let _ = or_stopped(
            &offer.cancel,
            send_files_json(
                &dc,
                &crate::files::FilesOutgoing::Eof {
                    id: &offer.id,
                    bytes: bytes_sent,
                },
            ),
        )
        .await;
    });
}

/// Spawn a tokio task that streams a folder as a zip. The zip is
/// produced by `async_zip::tokio::write::ZipFileWriter` writing into
/// the write end of a `tokio::io::duplex` pipe. A second task reads
/// from the pipe and pushes chunks to the DC with backpressure.
/// The bounded duplex buffer (256 KiB) is what gives async_zip
/// natural backpressure: if the DC drains slowly, the pipe fills
/// and async_zip's writes block.
fn spawn_outgoing_zip_pump(
    dc: Arc<RTCDataChannel>,
    handler: crate::files::FilesHandler,
    session_id: bson::oid::ObjectId,
    id: String,
    requested_path: String,
) {
    tokio::spawn(async move {
        let offer = match handler
            .begin_outgoing_zip(id.clone(), &requested_path)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                warn!(%session_id, %id, path = %requested_path, %e, "files: begin_outgoing_zip failed");
                let msg = format!("{e}");
                send_files_json(
                    &dc,
                    &crate::files::FilesOutgoing::Error {
                        id: &id,
                        message: &msg,
                    },
                )
                .await;
                return;
            }
        };

        // #1730 — as the single-file download: every message races the stop
        // token, and the transfer's state goes first on every exit.
        if or_stopped(
            &offer.cancel,
            send_files_json(
                &dc,
                &crate::files::FilesOutgoing::Offer {
                    id: &offer.id,
                    name: &offer.name,
                    size: None, // streaming — total unknown
                    mime: offer.mime,
                },
            ),
        )
        .await
        .is_err()
        {
            handler.finish_outgoing(&offer.id).await;
            return;
        }

        // Bounded duplex pipe: write side fed by async_zip; read
        // side fed to the DC. 256 KiB buffer = ~4 of our 64 KiB
        // chunks before async_zip's writes start blocking. Keeps
        // memory usage low and gives backpressure-free crash
        // protection if the DC is wedged.
        const PIPE_BUFFER: usize = 256 * 1024;
        let (writer_half, reader_half) = tokio::io::duplex(PIPE_BUFFER);
        let cancel = offer.cancel.clone();
        let path = offer.path.clone();
        let walk_cancel = cancel.clone();
        let walk_handle = tokio::spawn(async move {
            crate::files::walk_and_zip(writer_half, &path, walk_cancel).await
        });

        let dc_for_pump = dc.clone();
        let pump_cancel = cancel.clone();
        let id_for_pump = offer.id.clone();
        let pump_handle = tokio::spawn(async move {
            zip_pump_loop(dc_for_pump, reader_half, pump_cancel, id_for_pump).await
        });

        // Wait for both sides. The walk task closes the writer
        // half; the pump task sees EOF and exits.
        let walk_res = walk_handle.await;
        let pump_res = pump_handle.await;

        let total_bytes = match (walk_res, pump_res) {
            (Ok(Ok(_count)), Ok(Ok(bytes_sent))) => bytes_sent,
            (Ok(Err(e)), _) | (_, Ok(Err(e))) => {
                handler.finish_outgoing(&offer.id).await;
                if offer.cancel.is_cancelled() {
                    info!(%session_id, id = %offer.id, "files: zip download stopped (cancelled, or the session ended)");
                    return;
                }
                warn!(%session_id, id = %offer.id, %e, "files: zip pump failed");
                let msg = format!("{e}");
                let _ = or_stopped(
                    &offer.cancel,
                    send_files_json(
                        &dc,
                        &crate::files::FilesOutgoing::Error {
                            id: &offer.id,
                            message: &msg,
                        },
                    ),
                )
                .await;
                return;
            }
            (Err(je), _) | (_, Err(je)) => {
                handler.finish_outgoing(&offer.id).await;
                warn!(%session_id, id = %offer.id, %je, "files: zip pump task panicked");
                let _ = or_stopped(
                    &offer.cancel,
                    send_files_json(
                        &dc,
                        &crate::files::FilesOutgoing::Error {
                            id: &offer.id,
                            message: "zip pump task panicked",
                        },
                    ),
                )
                .await;
                return;
            }
        };

        info!(
            %session_id, id = %offer.id, total_bytes,
            path = %offer.path.display(),
            "files: outgoing zip complete"
        );
        crate::session_telemetry::counters(session_id).note_file(
            TransferDirection::FromHost,
            &offer.name,
            total_bytes,
        );
        handler.finish_outgoing(&offer.id).await;
        let _ = or_stopped(
            &offer.cancel,
            send_files_json(
                &dc,
                &crate::files::FilesOutgoing::Eof {
                    id: &offer.id,
                    bytes: total_bytes,
                },
            ),
        )
        .await;
    });
}

/// Pump bytes from the duplex reader to the DC, applying SCTP
/// backpressure. Returns total bytes sent. Exits on EOF, the stop
/// token (a cancel, or the session's end: every await races it,
/// #1730), or DC failure. Returning drops the reader, which fails the
/// zip writer's next write, so the walk ends too.
async fn zip_pump_loop<S: DownloadSink>(
    dc: S,
    mut reader: tokio::io::DuplexStream,
    stop: tokio_util::sync::CancellationToken,
    id: String,
) -> anyhow::Result<u64> {
    use tokio::io::AsyncReadExt;
    const CHUNK: usize = 64 * 1024;
    const BACKPRESSURE_HIGH: usize = 4 * 1024 * 1024;

    let mut buf = vec![0u8; CHUNK];
    let mut total: u64 = 0;
    let mut last_progress: u64 = 0;
    loop {
        let n = match or_stopped(&stop, reader.read(&mut buf)).await? {
            Ok(0) => break, // EOF — zip writer closed
            Ok(n) => n,
            Err(e) => return Err(anyhow::anyhow!("duplex read: {e}")),
        };
        // Backpressure on SCTP send buffer. ⚠️ After a drop the buffer
        // never drains (only a SACK lowers it), so the channel's state ends
        // the wait too, and the stop token ends it even when the channel
        // never says it closed.
        while or_stopped(&stop, dc.buffered()).await? > BACKPRESSURE_HIGH {
            or_stopped(&stop, tokio::time::sleep(Duration::from_millis(20))).await?;
            if dc.gone() {
                return Err(anyhow::anyhow!("the channel closed"));
            }
        }
        let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
        or_stopped(&stop, dc.send_chunk(&chunk)).await??;
        total += n as u64;
        if total - last_progress >= 256 * 1024 {
            last_progress = total;
            or_stopped(
                &stop,
                dc.send_json(&crate::files::FilesOutgoing::Progress {
                    id: &id,
                    bytes: total,
                }),
            )
            .await?;
        }
    }
    Ok(total)
}

/// Pump a single open file through the DC in 64 KiB chunks. Backs
/// off when the SCTP send buffer is over 4 MiB to avoid OOMing on
/// large files. Every await races the offer's stop token (#1730), so
/// a cancel or the session's end stops it wherever it waits. Returns
/// the total bytes sent on clean stream exit. `session_id` is whose transfer
/// it is: each progress report is activity for the session's idle limit
/// (FR-101 P4b-2), so a long download is never ended as idle.
async fn pump_outgoing_file<S: DownloadSink>(
    dc: &S,
    handler: &crate::files::FilesHandler,
    offer: &crate::files::OutgoingOffer,
    session_id: bson::oid::ObjectId,
) -> anyhow::Result<u64> {
    use tokio::io::AsyncReadExt;
    const CHUNK: usize = 64 * 1024;
    const BACKPRESSURE_HIGH: usize = 4 * 1024 * 1024;
    let stop = &offer.cancel;

    let mut file = or_stopped(stop, handler.open_outgoing(&offer.id)).await??;
    let mut buf = vec![0u8; CHUNK];
    let mut total: u64 = 0;
    let mut last_progress: u64 = 0;
    loop {
        // Backpressure: poll buffered_amount and yield until it
        // drops below the high-watermark.
        // ⚠️ After a drop the buffer never drains (only a SACK lowers it):
        // the channel's state ends the wait too, and the stop token ends
        // it even when the channel never says it closed.
        while or_stopped(stop, dc.buffered()).await? > BACKPRESSURE_HIGH {
            or_stopped(stop, tokio::time::sleep(Duration::from_millis(20))).await?;
            if dc.gone() {
                return Err(anyhow::anyhow!("the channel closed"));
            }
        }
        let n = or_stopped(stop, file.read(&mut buf)).await??;
        if n == 0 {
            break;
        }
        let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
        or_stopped(stop, dc.send_chunk(&chunk)).await??;
        total += n as u64;
        // Progress reports every 256 KiB
        if total - last_progress >= 256 * 1024 {
            last_progress = total;
            crate::session_telemetry::counters(session_id).note_transfer();
            or_stopped(
                stop,
                dc.send_json(&crate::files::FilesOutgoing::Progress {
                    id: &offer.id,
                    bytes: total,
                }),
            )
            .await?;
        }
    }
    Ok(total)
}

async fn handle_files_chunk(
    dc: Arc<RTCDataChannel>,
    handler: crate::files::FilesHandler,
    session_id: bson::oid::ObjectId,
    data: &[u8],
) {
    // Capture the active transfer's id BEFORE we run chunk(); on the
    // error path we need it to address the `files:error` reply
    // correctly. Without this the browser's per-upload promise
    // listener (which filters by id) silently drops the error and
    // the upload spinner spins forever — field repro the field-test host rc.8
    // (2026-05-06).
    let active_id = handler.current_id().await.unwrap_or_default();
    match handler.chunk(data).await {
        Ok(Some(progress)) => {
            send_files_json(
                &dc,
                &crate::files::FilesOutgoing::Progress {
                    id: &progress.id,
                    bytes: progress.bytes,
                },
            )
            .await;
        }
        Ok(None) => {
            // Below the progress-report threshold; nothing to send.
        }
        Err(e) => {
            warn!(%session_id, id = %active_id, %e, "files: chunk failed");
            let msg = format!("{e}");
            send_files_json(
                &dc,
                &crate::files::FilesOutgoing::Error {
                    id: &active_id,
                    message: &msg,
                },
            )
            .await;
            handler.abort().await;
        }
    }
}

async fn send_files_json(dc: &Arc<RTCDataChannel>, msg: &crate::files::FilesOutgoing<'_>) {
    if let Ok(s) = serde_json::to_string(msg) {
        let _ = dc.send_text(s).await;
    }
}

/// #1730 — what a download pump needs of its data channel: the channel
/// itself in production; in the tests, one whose send never returns, which
/// is how a channel whose peer vanished looks from inside the pump.
trait DownloadSink: Send + Sync {
    fn buffered(&self) -> impl std::future::Future<Output = usize> + Send;
    fn send_chunk(
        &self,
        chunk: &bytes::Bytes,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn send_json(
        &self,
        msg: &crate::files::FilesOutgoing<'_>,
    ) -> impl std::future::Future<Output = ()> + Send;
    /// Closed, or begun to ([`channel_gone`]).
    fn gone(&self) -> bool;
}

impl DownloadSink for Arc<RTCDataChannel> {
    async fn buffered(&self) -> usize {
        self.buffered_amount().await
    }
    async fn send_chunk(&self, chunk: &bytes::Bytes) -> anyhow::Result<()> {
        self.send(chunk)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("dc.send failed: {e}"))
    }
    async fn send_json(&self, msg: &crate::files::FilesOutgoing<'_>) {
        send_files_json(self, msg).await
    }
    fn gone(&self) -> bool {
        channel_gone(self.ready_state())
    }
}

/// #1730 — `fut`, unless `stop` fires first. Every await a download makes
/// goes through this: a stop flag read BETWEEN awaits is never read by a pump
/// parked INSIDE one, and after a network drop the channel's send, its
/// `buffered_amount` and a progress message can each park for good. That
/// pump held its file, its channel and the transfer guard the updater defers
/// for, and made the peer's close wait out its whole budget (field, 0.4.107:
/// the file held at +4 m 43 s, `terminated` → `Closed` 5.0 s). Dropping the
/// parked future is what lets go: a lock it waited on is released with it.
async fn or_stopped<T>(
    stop: &tokio_util::sync::CancellationToken,
    fut: impl std::future::Future<Output = T>,
) -> anyhow::Result<T> {
    tokio::select! {
        biased;
        () = stop.cancelled() => Err(anyhow::anyhow!("stopped: cancelled, or the session ended")),
        v = fut => Ok(v),
    }
}

/// Is this the overlay's own TUN interface?
///
/// The names come from `tunnel_core::overlay::tun`: `roomler` on Windows,
/// `roomler0` on Linux, and a kernel-assigned `utunN` on macOS — which we
/// cannot match by name. The masking-srflx failure this guards against
/// needs a host whose STUN is blocked on the physical NIC, which is the
/// corp-Windows case. The macOS candidate is NOT inert, though (#1882: a
/// browser on an overlay node paired with it); keeping it out is the job of
/// the address filter in `crate::rc_overlay`, which the device's
/// `rc_overlay` policy arms by default.
///
/// Prefix-matched rather than compared exactly so a suffixed variant (a
/// second adapter, a `:N` alias) is caught too. Anything else — including a
/// user interface merely CONTAINING "roomler" further in the name — is left
/// alone; a false positive here silently removes a real candidate.
///
/// Multi-org v2: per-org adapters are named `roomler-<suffix>`, so the
/// `roomler-` prefix is ours as well.
pub(crate) fn is_overlay_iface(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    n == "roomler"
        || n.starts_with("roomler-")
        || n.starts_with("roomler0")
        || n.starts_with("roomler.")
}

pub(crate) fn map_ice_servers(servers: &[IceServer]) -> Vec<RTCIceServer> {
    servers
        .iter()
        .map(|s| RTCIceServer {
            urls: s.urls.clone(),
            username: s.username.clone().unwrap_or_default(),
            credential: s.credential.clone().unwrap_or_default(),
        })
        .collect()
}

/// Filter mapped ICE servers to the TURNS-over-TCP relay only, for
/// `ROOMLERD_ICE_RELAY_TCP` mode. Hostile-NAT hosts (WSL2 +
/// wsl-vpnkit, other userspace-VPN stacks) mangle UDP source ports so the
/// TURN allocation refresh fails and the media peer flaps; a single
/// TURNS/TCP connection (handled by the vendored `webrtc-ice` TCP branch)
/// survives it. Keeps only `turns:…?transport=tcp` URLs and drops STUN +
/// plain-UDP TURN. Returns the full mapping unchanged when no TCP-relay
/// URL is present, so the knob can never break connectivity outright.
pub(crate) fn map_ice_servers_relay_tcp(servers: &[IceServer]) -> Vec<RTCIceServer> {
    let all = map_ice_servers(servers);
    let filtered: Vec<RTCIceServer> = all
        .iter()
        .filter_map(|s| {
            let tcp_urls: Vec<String> = s
                .urls
                .iter()
                .filter(|u| {
                    let lu = u.to_ascii_lowercase();
                    lu.starts_with("turns:") && lu.contains("transport=tcp")
                })
                .cloned()
                .collect();
            (!tcp_urls.is_empty()).then(|| RTCIceServer {
                urls: tcp_urls,
                username: s.username.clone(),
                credential: s.credential.clone(),
            })
        })
        .collect();
    if filtered.is_empty() {
        warn!(
            "ICE_RELAY_TCP set but no turns:…?transport=tcp URL available — using all ICE servers"
        );
        all
    } else {
        info!(
            servers = filtered.len(),
            "ICE relay-over-TCP: media pinned to TURNS/TCP relay (hostile-NAT mode)"
        );
        filtered
    }
}

#[cfg(test)]
mod overlay_iface_filter_tests {
    use super::is_overlay_iface;

    #[test]
    fn matches_the_overlay_tun_on_every_platform_we_name_it() {
        // tunnel_core::overlay::tun — `roomler` (Windows), `roomler0` (Linux).
        assert!(is_overlay_iface("roomler"));
        assert!(is_overlay_iface("roomler0"));
        assert!(is_overlay_iface("ROOMLER")); // Windows aliases are case-y
        assert!(is_overlay_iface(" roomler ")); // and can carry whitespace
        assert!(is_overlay_iface("roomler0:1")); // suffixed alias
        // Multi-org v2 — per-org adapters (`roomler-<suffix>`) are overlay
        // ifaces too: their addresses must never leak into ICE candidates.
        assert!(is_overlay_iface("roomler-acme"));
        assert!(is_overlay_iface("ROOMLER-ACME"));
        assert!(is_overlay_iface("roomler-acme:1"));
    }

    /// A false positive silently deletes a real ICE candidate, so the match
    /// must not be a loose "contains".
    #[test]
    fn leaves_every_other_interface_alone() {
        for n in [
            "Wi-Fi",
            "eth0",
            "utun3",
            "vEthernet (Default Switch)",
            "my-roomler-vpn", // contains it, is NOT ours
            "roomlerx",       // near-miss
            "",
        ] {
            assert!(!is_overlay_iface(n), "must not filter {n:?}");
        }
    }
}

#[cfg(test)]
mod ice_relay_tcp_tests {
    use super::{map_ice_servers, map_ice_servers_relay_tcp};
    use roomler_ai_remote_control::signaling::IceServer;

    fn srv(urls: &[&str], with_cred: bool) -> IceServer {
        IceServer {
            urls: urls.iter().map(|s| s.to_string()).collect(),
            username: with_cred.then(|| "u".to_string()),
            credential: with_cred.then(|| "c".to_string()),
        }
    }

    #[test]
    fn stun_redundancy_native_mapping_keeps_both_providers_without_credentials() {
        let servers = roomler_ai_remote_control::turn_creds::default_stun_servers();
        let mapped = map_ice_servers(&servers);
        assert_eq!(mapped.len(), 1);
        assert_eq!(
            mapped[0].urls,
            vec![
                "stun:stun.cloudflare.com:3478",
                "stun:stun.l.google.com:19302"
            ]
        );
        assert!(mapped[0].username.is_empty() && mapped[0].credential.is_empty());
        assert!(
            map_ice_servers(&[]).is_empty(),
            "intentional host-only ICE remains host-only"
        );
    }

    #[test]
    fn relay_tcp_keeps_only_turns_tcp_and_drops_stun_and_udp() {
        let servers = vec![
            srv(&["stun:stun.l.google.com:19302"], false),
            srv(
                &[
                    "turn:coturn.example:443?transport=udp",
                    "turn:coturn.example:3478?transport=tcp",
                    "turns:coturn.example:443?transport=tcp",
                ],
                true,
            ),
        ];
        let out = map_ice_servers_relay_tcp(&servers);
        // Only the server that carries a `turns:…?transport=tcp` URL
        // survives, and only that URL is kept (STUN + UDP + plain-TCP TURN
        // dropped — the vendored ice fork only handles TURNS-over-TCP).
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].urls, vec!["turns:coturn.example:443?transport=tcp"]);
        assert_eq!(out[0].username, "u");
        assert_eq!(out[0].credential, "c");
    }

    #[test]
    fn relay_tcp_falls_back_to_all_when_no_tcp_relay() {
        // No `turns:…?transport=tcp` anywhere → never break connectivity;
        // return the full mapping unchanged.
        let servers = vec![
            srv(&["stun:stun.l.google.com:19302"], false),
            srv(&["turn:coturn.example:3478?transport=udp"], true),
        ];
        let out = map_ice_servers_relay_tcp(&servers);
        assert_eq!(out.len(), map_ice_servers(&servers).len());
        assert_eq!(out.len(), 2);
    }
}

/// Build the `RTCRtpCodecCapability` for the negotiated codec. Matches
/// webrtc-rs's `register_default_codecs` entries byte-for-byte so the
/// internal `payloader_for_codec` lookup resolves and the SDP answer
/// carries the expected payload type.
///
/// Default MediaEngine registrations (webrtc-rs 0.12):
///   video/H264 Constrained Baseline, packetization-mode=1,
///       profile-level-id=42e01f → PT 125
///   video/HEVC empty fmtp              → PT 126
///   video/AV1  profile-id=0            → PT 41
///
/// Unknown codec → H.264 default (paranoia: should never hit because
/// `pick_best_codec` only returns codecs both sides advertise).
fn build_video_codec_cap(codec: &str) -> RTCRtpCodecCapability {
    let feedback = vec![
        RTCPFeedback {
            typ: "goog-remb".to_string(),
            parameter: String::new(),
        },
        RTCPFeedback {
            typ: "ccm".to_string(),
            parameter: "fir".to_string(),
        },
        RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        },
        RTCPFeedback {
            typ: "nack".to_string(),
            parameter: "pli".to_string(),
        },
        RTCPFeedback {
            typ: "transport-cc".to_string(),
            parameter: String::new(),
        },
    ];
    match codec.to_ascii_lowercase().as_str() {
        "av1" => RTCRtpCodecCapability {
            mime_type: "video/AV1".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "profile-id=0".to_string(),
            rtcp_feedback: feedback,
        },
        "h265" | "hevc" => RTCRtpCodecCapability {
            // MIME is "video/HEVC" to match webrtc-rs 0.12's
            // `MIME_TYPE_HEVC` constant (what `register_default_codecs`
            // registers and what `payloader_for_codec` looks up).
            // Using "video/H265" here fails the transceiver's codec
            // match with "unsupported codec type by this transceiver"
            // even though HEVC is identical to H.265 in the spec.
            mime_type: "video/HEVC".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: feedback,
        },
        // #2231 — the RTP track's placeholder on a DataChannel transport
        // whose offer lacks the pump's codec (`rtp_track_codec`). No encoder
        // ever feeds it. Matches webrtc-rs's default VP8 (PT 96, no fmtp).
        "vp8" => RTCRtpCodecCapability {
            mime_type: "video/VP8".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: feedback,
        },
        _ => RTCRtpCodecCapability {
            mime_type: "video/H264".to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
                .to_string(),
            rtcp_feedback: feedback,
        },
    }
}

/// Opus capability for the system-audio track. MUST match webrtc-rs's
/// default MediaEngine Opus registration byte-for-byte — mime
/// `audio/opus`, clock_rate 48000, channels 2, fmtp
/// `minptime=10;useinbandfec=1`, empty rtcp_feedback (PT 111). A
/// mismatch on any field makes the transceiver fail to resolve a
/// payload type and the browser gets an m=audio section it can't bind.
/// (Verified against `crates/vendored/webrtc/.../media_engine/mod.rs`.)
#[cfg(feature = "audio")]
fn build_audio_codec_cap() -> RTCRtpCodecCapability {
    RTCRtpCodecCapability {
        mime_type: "audio/opus".to_string(),
        clock_rate: 48000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_string(),
        rtcp_feedback: vec![],
    }
}

/// Per-session system-audio pump. Captures desktop/system audio,
/// encodes to Opus (48 kHz stereo, 20 ms frames), and writes each
/// packet into the WebRTC Opus track.
///
/// A capture that does not open, an encoder that does not start, or a
/// capture that fails mid-session ends the pump and tells the controller
/// why (`rc:audio-unavailable`, FR-97 P3c-1). The m=audio section stays
/// negotiated and silent, as it always was; before P3c-1 the silence came
/// with no reason, and on Linux a microphone opened in its place.
///
/// Each 20 ms Opus packet is written with a fixed `duration` of 20 ms so
/// the track's RTP timestamps advance at the real audio clock (unlike
/// the video pump, audio frames are inherently fixed-cadence).
///
/// Aborted by `AgentPeer::close()`.
#[cfg(feature = "audio")]
async fn audio_pump(
    session_id: bson::oid::ObjectId,
    audio_track: Arc<TrackLocalStaticSample>,
    control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
) {
    use crate::audio;
    use crate::audio_source::{AudioUnavailable, AudioUnavailableCode};

    // FR-97 P3c-2 — a Linux open can wait on a sound server or on the seat
    // user's helper (up to `audio::pulse`'s 8 s), so it runs off the runtime.
    // Windows keeps the inline open: its WASAPI stream is created, used and
    // dropped on one task (see `CpalLoopbackCapture`'s `Send`).
    #[cfg(target_os = "linux")]
    let opened = tokio::task::spawn_blocking(audio::open_default)
        .await
        .unwrap_or_else(|e| {
            Err(AudioUnavailable::new(
                AudioUnavailableCode::BackendError,
                format!("the audio open did not finish: {e}"),
            ))
        });
    #[cfg(not(target_os = "linux"))]
    let opened = audio::open_default();
    let mut capture = match opened {
        Ok(c) => c,
        Err(reason) => {
            spawn_audio_unavailable_notice(session_id, control_dc, reason);
            return;
        }
    };
    let mut encoder = match audio::opus_encode::OpusEncoder::new() {
        Ok(e) => e,
        Err(e) => {
            warn!(%session_id, %e, "audio: failed to init Opus encoder — audio pump exiting");
            spawn_audio_unavailable_notice(
                session_id,
                control_dc,
                AudioUnavailable::new(
                    AudioUnavailableCode::BackendError,
                    format!("the Opus encoder did not start: {e:#}"),
                ),
            );
            return;
        }
    };

    // 20 ms per Opus frame (960 samples/ch @ 48 kHz). Fixed cadence —
    // the browser's jitter buffer relies on this.
    const FRAME_DURATION: Duration = Duration::from_millis(20);

    let mut frames_captured: u64 = 0;
    let mut packets_sent: u64 = 0;
    let mut write_errors: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut last_heartbeat = std::time::Instant::now();
    const HEARTBEAT: Duration = Duration::from_secs(5);

    info!(%session_id, "audio pump started");

    loop {
        let frame = match capture.next_frame().await {
            Ok(Some(f)) => f,
            Ok(None) => {
                // Capture exhausted (stream torn down). Nothing more to
                // do — exit cleanly.
                info!(
                    %session_id,
                    frames_captured, packets_sent,
                    "audio: capture exhausted — audio pump exiting"
                );
                return;
            }
            Err(e) => {
                warn!(%session_id, %e, "audio: capture error — audio pump exiting");
                spawn_audio_unavailable_notice(
                    session_id,
                    control_dc,
                    AudioUnavailable::new(
                        AudioUnavailableCode::BackendError,
                        format!("audio capture stopped: {e:#}"),
                    ),
                );
                return;
            }
        };
        frames_captured += 1;

        let packets = match encoder.push(&frame.samples, frame.channels, frame.sample_rate) {
            Ok(p) => p,
            Err(e) => {
                warn!(%session_id, %e, "audio: opus encode error — audio pump exiting");
                spawn_audio_unavailable_notice(
                    session_id,
                    control_dc,
                    AudioUnavailable::new(
                        AudioUnavailableCode::BackendError,
                        format!("audio encoding stopped: {e:#}"),
                    ),
                );
                return;
            }
        };

        for packet in packets {
            let len = packet.len() as u64;
            let sample = Sample {
                data: Bytes::from(packet),
                timestamp: SystemTime::now(),
                duration: FRAME_DURATION,
                packet_timestamp: 0,
                prev_dropped_packets: 0,
                prev_padding_packets: 0,
            };
            if let Err(e) = audio_track.write_sample(&sample).await {
                write_errors += 1;
                // Sample once per ~5s heartbeat window rather than per
                // failure; a dead track fails every frame and would flood.
                if write_errors == 1 {
                    warn!(%session_id, %e, "audio: write_sample failed (first)");
                }
            } else {
                packets_sent += 1;
                bytes_sent += len;
            }
        }

        if last_heartbeat.elapsed() >= HEARTBEAT {
            info!(
                %session_id,
                frames_captured,
                packets_sent,
                bytes_sent,
                write_errors,
                "audio pump heartbeat"
            );
            last_heartbeat = std::time::Instant::now();
        }
    }
}

/// Build the `RTCRtpCodecParameters` pinned into the transceiver's
/// codec preferences. Same capability as the track carries; payload
/// type matches the default MediaEngine's PT for that codec.
fn codec_params_for(codec: &str) -> webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecParameters {
    use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecParameters;
    let capability = build_video_codec_cap(codec);
    let payload_type = match codec.to_ascii_lowercase().as_str() {
        "av1" => 41,
        "h265" | "hevc" => 126,
        "vp8" => 96,
        _ => 125,
    };
    RTCRtpCodecParameters {
        capability,
        payload_type,
        ..Default::default()
    }
}

/// #2231 — the codec the RTP video track is created and pinned with.
///
/// On a DataChannel transport the track carries no frame (the DC pump owns the
/// video); it exists only so the SDP answer is valid. The pump's codec comes
/// from `pick_best_codec`, whose fallback is H.264 even when the browser named
/// codecs and none intersects with the agent's RTP set. A Firefox without
/// OpenH264 offers VP8, VP9 and AV1, so an H.264 track left the sender with no
/// codec, and `create_answer` failed ("RTPSender created with no codecs")
/// before the DataChannel the session would use could open. So on a DC
/// transport whose offer lacks the pump's codec, the track takes VP8, which
/// every WebRTC browser must offer (RFC 7742). On the RTP transport the track
/// IS the video, and its codec stays the pump's. Read from the offer itself,
/// the one statement of what this browser will take.
pub fn rtp_track_codec(chosen: &str, transport: Option<&str>, offer_sdp: &str) -> String {
    if !on_data_channel(transport) {
        return chosen.to_string();
    }
    if offer_carries_track(offer_sdp, chosen) || !offer_names(offer_sdp, "VP8") {
        return chosen.to_string();
    }
    "vp8".to_string()
}

/// #2251 — the offer leaves the RTP video track nothing it can send.
///
/// On the RTP transport the track IS the video: it sends the encoder's codec
/// and cannot take another the way the DataChannel's placeholder does
/// (`rtp_track_codec`). An offer with a video section and no `a=rtpmap` for
/// that codec fails `create_answer` ("RTPSender created with no codecs"); the
/// session then ended as a bare `Error`, which the viewer retries, and the
/// same offer failed again. The caller refuses before it builds the peer
/// instead, naming `no_common_codec`.
///
/// False on a DataChannel transport, and for an offer with no `m=video` at
/// all, which is answered without the track.
pub fn rtp_track_unanswerable(track_codec: &str, transport: Option<&str>, offer_sdp: &str) -> bool {
    let has_video = offer_sdp
        .lines()
        .any(|line| line.trim_start().starts_with("m=video "));
    !on_data_channel(transport) && has_video && !offer_carries_track(offer_sdp, track_codec)
}

/// The video codecs an offer names, each once and in its order, for the line
/// a refusal logs. Retransmission and FEC payloads are left out.
pub fn offered_video_codecs(offer_sdp: &str) -> Vec<String> {
    let mut in_video = false;
    let mut out: Vec<String> = Vec::new();
    for line in offer_sdp.lines().map(str::trim) {
        if let Some(media) = line.strip_prefix("m=") {
            in_video = media.starts_with("video ");
            continue;
        }
        if !in_video {
            continue;
        }
        let Some(encoding) = rtpmap_encoding(line) else {
            continue;
        };
        let repair = ["rtx", "red", "ulpfec", "flexfec-03"]
            .iter()
            .any(|r| encoding.eq_ignore_ascii_case(r));
        if !repair && !out.iter().any(|o| o.eq_ignore_ascii_case(encoding)) {
            out.push(encoding.to_string());
        }
    }
    out
}

fn on_data_channel(transport: Option<&str>) -> bool {
    transport.is_some_and(|t| t.starts_with("data-channel-"))
}

/// The encoding of an `a=rtpmap:<pt> <encoding>/<clock>[/<channels>]` line.
fn rtpmap_encoding(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("a=rtpmap:")
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|enc| enc.split('/').next())
}

/// Some `a=rtpmap` line of the offer names `encoding`, in any case.
fn offer_names(offer_sdp: &str, encoding: &str) -> bool {
    offer_sdp
        .lines()
        .filter_map(rtpmap_encoding)
        .any(|enc| enc.eq_ignore_ascii_case(encoding))
}

/// The offer carries what the RTP video track sends for `codec`:
/// `build_video_codec_cap`'s choice, where every codec the track cannot carry
/// (VP9 among them) falls to H.264. HEVC answers to both spellings, RFC
/// 7798's `H265`, which browsers write, and `HEVC`, webrtc-rs's own name.
fn offer_carries_track(offer_sdp: &str, codec: &str) -> bool {
    match codec.to_ascii_lowercase().as_str() {
        "av1" => offer_names(offer_sdp, "AV1"),
        "h265" | "hevc" => offer_names(offer_sdp, "H265") || offer_names(offer_sdp, "HEVC"),
        "vp8" => offer_names(offer_sdp, "VP8"),
        _ => offer_names(offer_sdp, "H264"),
    }
}

#[cfg(test)]
mod codec_cap_tests {
    use super::{
        build_video_codec_cap, codec_params_for, offered_video_codecs, rtp_track_codec,
        rtp_track_unanswerable,
    };

    /// A Firefox without OpenH264, as it offers: VP8, VP9 and AV1 (+ rtx/fec),
    /// with Opus on the audio line.
    const FIREFOX_NO_H264: &str = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 109\r\n\
        a=rtpmap:109 opus/48000/2\r\nm=video 9 UDP/TLS/RTP/SAVPF 120 124 121 125 99\r\n\
        a=rtpmap:120 VP8/90000\r\na=rtpmap:124 rtx/90000\r\na=rtpmap:121 VP9/90000\r\n\
        a=rtpmap:125 rtx/90000\r\na=rtpmap:99 AV1/90000\r\n";
    /// Chromium, with H.264.
    const CHROMIUM: &str = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96 102\r\n\
        a=rtpmap:96 VP8/90000\r\na=rtpmap:102 H264/90000\r\n";

    /// #2231 — on a DataChannel transport the placeholder track takes VP8
    /// when the offer lacks the pump's codec; everything else keeps it.
    #[test]
    fn the_rtp_track_takes_a_codec_the_offer_carries() {
        let dc = Some("data-channel-vp9-444");
        // The field case: a Firefox without OpenH264 on the VP9 DataChannel.
        assert_eq!(rtp_track_codec("h264", dc, FIREFOX_NO_H264), "vp8");
        // Every DataChannel transport, not just VP9's.
        assert_eq!(
            rtp_track_codec("h264", Some("data-channel-hevc"), FIREFOX_NO_H264),
            "vp8"
        );
        // The offer has the pump's codec: nothing changes.
        assert_eq!(rtp_track_codec("h264", dc, CHROMIUM), "h264");
        assert_eq!(rtp_track_codec("av1", dc, FIREFOX_NO_H264), "av1");
        // The RTP transport: the track IS the video, so its codec stays the
        // pump's, whatever the offer (that mismatch is a refusal's business).
        assert_eq!(rtp_track_codec("h264", None, FIREFOX_NO_H264), "h264");
        // No VP8 to move to either: nothing better to do.
        assert_eq!(
            rtp_track_codec("h264", dc, "m=video 9 RTP 99\r\na=rtpmap:99 AV1/90000\r\n"),
            "h264"
        );
        // The encoding name in any case, as an SDP may write it.
        assert_eq!(
            rtp_track_codec(
                "h264",
                dc,
                "m=video 9 RTP 102\r\na=rtpmap:102 h264/90000\r\n"
            ),
            "h264"
        );
        // Opus's line never reads as a video codec.
        assert_eq!(
            rtp_track_codec("h264", dc, "a=rtpmap:109 opus/48000/2\r\n"),
            "h264"
        );
    }

    /// #2251 — on the RTP transport an offer without the track's codec cannot
    /// be answered, and is refused; nothing else is.
    #[test]
    fn the_rtp_track_refuses_an_offer_it_cannot_answer() {
        // The field case: a Firefox without OpenH264, on the RTP track.
        assert!(rtp_track_unanswerable("h264", None, FIREFOX_NO_H264));
        // VP9 is no codec of the RTP track: its track is H.264's, so the same.
        assert!(rtp_track_unanswerable("vp9", None, FIREFOX_NO_H264));
        // The offer carries the track's codec.
        assert!(!rtp_track_unanswerable("h264", None, CHROMIUM));
        assert!(!rtp_track_unanswerable("av1", None, FIREFOX_NO_H264));
        // HEVC under either spelling.
        let h265 = "m=video 9 RTP 49\r\na=rtpmap:49 H265/90000\r\n";
        assert!(!rtp_track_unanswerable("h265", None, h265));
        assert!(!rtp_track_unanswerable("hevc", None, h265));
        assert!(!rtp_track_unanswerable(
            "h265",
            None,
            "m=video 9 RTP 49\r\na=rtpmap:49 HEVC/90000\r\n"
        ));
        assert!(rtp_track_unanswerable("h265", None, CHROMIUM));
        // A DataChannel transport is the placeholder's business, never this.
        assert!(!rtp_track_unanswerable(
            "h264",
            Some("data-channel-vp9-444"),
            FIREFOX_NO_H264
        ));
        // No video section: answered without the track, as test harnesses
        // offer only a DataChannel.
        assert!(!rtp_track_unanswerable(
            "h264",
            None,
            "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        ));
    }

    /// #2251 — the refusal's log line names what the browser offered, video
    /// only, without the repair payloads.
    #[test]
    fn a_refusal_names_the_offers_video_codecs() {
        assert_eq!(offered_video_codecs(FIREFOX_NO_H264), ["VP8", "VP9", "AV1"]);
        assert_eq!(offered_video_codecs(CHROMIUM), ["VP8", "H264"]);
        assert!(offered_video_codecs("a=rtpmap:109 opus/48000/2\r\n").is_empty());
    }

    #[test]
    fn vp8_cap_matches_webrtc_default() {
        let cap = build_video_codec_cap("vp8");
        assert_eq!(cap.mime_type, "video/VP8");
        assert_eq!(cap.clock_rate, 90000);
        assert!(cap.sdp_fmtp_line.is_empty());
        assert_eq!(codec_params_for("vp8").payload_type, 96);
    }

    #[test]
    fn h264_cap_matches_webrtc_default() {
        let cap = build_video_codec_cap("h264");
        assert_eq!(cap.mime_type, "video/H264");
        assert_eq!(cap.clock_rate, 90000);
        assert!(cap.sdp_fmtp_line.contains("profile-level-id=42e01f"));
        assert!(cap.sdp_fmtp_line.contains("packetization-mode=1"));
    }

    #[test]
    fn hevc_cap_has_no_fmtp_line() {
        let cap = build_video_codec_cap("h265");
        assert_eq!(cap.mime_type, "video/HEVC");
        assert!(cap.sdp_fmtp_line.is_empty());
        let alias = build_video_codec_cap("hevc");
        assert_eq!(alias.mime_type, "video/HEVC");
    }

    #[test]
    fn av1_cap_carries_profile_id() {
        let cap = build_video_codec_cap("av1");
        assert_eq!(cap.mime_type, "video/AV1");
        assert_eq!(cap.sdp_fmtp_line, "profile-id=0");
    }

    /// FR-80 — the `rc:media-unavailable` wire shape, locked like
    /// `rc:video-info`'s. The viewer keys its message off `code`, so the
    /// vocabulary is a compatibility surface: a renamed code does not fail,
    /// it changes what an operator reads on the screen that exists to
    /// explain the failure.
    /// FR-93 P2d-2 — `rc:media-waiting` is parsed by the viewer
    /// (`parseControlInbound`): the field names are the contract, and
    /// `waits_ms` is a duration in whole milliseconds, never a time of day.
    #[test]
    fn media_waiting_payload_wire_shape() {
        let payload = super::media_waiting_payload(crate::capture::OpenWait {
            gives_up_in: std::time::Duration::from_millis(117_250),
            why: crate::capture::WaitFor::Dialog { control: false },
        });
        let v: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON");
        assert_eq!(v["t"], "rc:media-waiting", "{payload}");
        assert_eq!(v["for"], "person_at_screen", "{payload}");
        assert_eq!(v["waits_ms"], 117_250, "{payload}");
        assert!(
            v["hint"].as_str().is_some_and(|h| !h.is_empty()),
            "{payload}"
        );
    }

    /// FR-93 P5b — each wait reads as what it is: the dialog for the screen,
    /// the dialog for remote control (P4b, which still asks for the screen
    /// alone after a refusal), and GNOME's lock screen (#2145), which says
    /// where the screen gets unlocked. Every one is valid JSON: the hints are
    /// literals with nothing to escape.
    #[test]
    fn media_waiting_names_what_it_waits_for() {
        use crate::capture::{OpenWait, WaitFor};
        let read = |why| {
            let payload = super::media_waiting_payload(OpenWait {
                gives_up_in: std::time::Duration::from_secs(3600),
                why,
            });
            let v: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON");
            (
                v["for"].as_str().unwrap_or_default().to_string(),
                v["hint"].as_str().unwrap_or_default().to_string(),
                v["waits_ms"].as_u64(),
            )
        };
        let (f, hint, ms) = read(WaitFor::Dialog { control: false });
        assert_eq!(f, "person_at_screen");
        assert!(hint.contains("share their screen"), "{hint}");
        assert_eq!(ms, Some(3_600_000));
        let (f, hint, _) = read(WaitFor::Dialog { control: true });
        assert_eq!(f, "person_at_screen");
        assert!(hint.contains("allow remote control"), "{hint}");
        assert!(hint.contains("just their screen"), "{hint}");
        let (f, hint, _) = read(WaitFor::Unlock);
        assert_eq!(f, "screen_unlock");
        assert!(hint.contains("is locked"), "{hint}");
        assert!(hint.contains("unlocked at the computer"), "{hint}");
        // FR-93 P3e — a display switched off, which input wakes.
        let (f, hint, _) = read(WaitFor::DisplayWake);
        assert_eq!(f, "display_wake");
        assert!(hint.contains("display is off"), "{hint}");
        assert!(hint.contains("wakes it"), "{hint}");
        // FR-93 P5f — this user's session in the background.
        let (f, hint, _) = read(WaitFor::SessionAway);
        assert_eq!(f, "session_away");
        assert!(hint.contains("another user's"), "{hint}");
        assert!(hint.contains("comes back by itself"), "{hint}");
        // FR-93 P5h — the computer going to sleep.
        let (f, hint, _) = read(WaitFor::HostSleep);
        assert_eq!(f, "host_sleep");
        assert!(hint.contains("going to sleep"), "{hint}");
        assert!(hint.contains("once the computer wakes"), "{hint}");
        // FR-95 P2 — a system install's automatic capture: the viewer's own
        // `for`, never the per-user install's sentence.
        let (f, hint, _) = read(WaitFor::GuardLocked);
        assert_eq!(f, "screen_unlock");
        assert!(hint.contains("switched capture on by itself"), "{hint}");
        assert!(hint.contains("unlocked at the computer"), "{hint}");
        assert!(!hint.contains("per-user"), "{hint}");
        let (f, hint, _) = read(WaitFor::GuardAway);
        assert_eq!(f, "session_away");
        assert!(hint.contains("another person's session"), "{hint}");
        assert!(hint.contains("comes back by itself"), "{hint}");
        assert!(
            hint.contains("connect again"),
            "a logout's picture never comes back: {hint}"
        );
    }

    /// FR-93 P3e — a capture waiting on its host is told once per wait, told
    /// again before the viewer's deadline runs out, and a frame (or a "no
    /// frame" that waits for nothing) ends the wait, so the next blank is
    /// told afresh. P5f — each telling comes after a quiet spell.
    #[test]
    fn a_dark_display_is_told_once_and_again_before_the_notice_runs_out() {
        use super::CaptureWait;
        use crate::capture::WaitFor::DisplayWake;
        use std::time::{Duration, Instant};
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let q = CaptureWait::QUIET_BEFORE_TELL;
        let mut w = CaptureWait::default();
        assert_eq!(
            w.on_empty(None, t0),
            None,
            "an idle screen keeps its keepalives"
        );
        assert_eq!(
            w.on_empty(Some(DisplayWake), t0),
            Some((DisplayWake, false)),
            "held at once, not told yet"
        );
        assert_eq!(
            w.on_empty(Some(DisplayWake), t0 + q),
            Some((DisplayWake, true))
        );
        assert_eq!(
            w.on_empty(Some(DisplayWake), t0 + q + s(1)),
            Some((DisplayWake, false)),
            "told once"
        );
        assert!(CaptureWait::RETELL + q < CaptureWait::TOLD_FOR);
        let later = t0 + q + CaptureWait::RETELL;
        assert_eq!(
            w.on_empty(Some(DisplayWake), later),
            Some((DisplayWake, false))
        );
        assert_eq!(
            w.on_empty(Some(DisplayWake), later + q),
            Some((DisplayWake, true)),
            "told again before the viewer's deadline"
        );
        w.on_frame();
        let after = later + q + s(1);
        assert_eq!(
            w.on_empty(Some(DisplayWake), after),
            Some((DisplayWake, false))
        );
        assert_eq!(
            w.on_empty(Some(DisplayWake), after + q),
            Some((DisplayWake, true)),
            "a blank after a frame is told afresh"
        );
        assert_eq!(w.on_empty(None, after + q + s(1)), None);
        let again = after + q + s(2);
        assert_eq!(
            w.on_empty(Some(DisplayWake), again),
            Some((DisplayWake, false))
        );
        assert_eq!(
            w.on_empty(Some(DisplayWake), again + q),
            Some((DisplayWake, true)),
            "and after a no-frame that waited for nothing"
        );
    }

    /// FR-93 P5f — the pump holds at once and tells only after a quiet spell,
    /// so the frames it sent before the wait are counted by the viewer before
    /// the notice arrives. A frame inside the spell means the wait is over,
    /// and the next one starts its own spell.
    #[test]
    fn a_wait_is_told_only_after_a_quiet_spell() {
        use super::CaptureWait;
        use crate::capture::WaitFor::{DisplayWake, SessionAway};
        use std::time::Instant;
        let t0 = Instant::now();
        let q = CaptureWait::QUIET_BEFORE_TELL;
        let mut w = CaptureWait::default();
        assert_eq!(
            w.on_empty(Some(SessionAway), t0),
            Some((SessionAway, false))
        );
        assert_eq!(
            w.on_empty(Some(SessionAway), t0 + q / 2),
            Some((SessionAway, false)),
            "held, not told"
        );
        w.on_frame();
        assert_eq!(
            w.on_empty(Some(SessionAway), t0 + q),
            Some((SessionAway, false)),
            "a frame started the spell again"
        );
        assert_eq!(
            w.on_empty(Some(SessionAway), t0 + q + q / 2),
            Some((SessionAway, false))
        );
        assert_eq!(
            w.on_empty(Some(DisplayWake), t0 + q + q),
            Some((DisplayWake, false)),
            "another wait starts its own spell"
        );
        assert_eq!(
            w.on_empty(Some(DisplayWake), t0 + q * 3),
            Some((DisplayWake, true))
        );
    }

    #[test]
    fn capture_unavailable_payload_wire_shape() {
        use crate::capture::{CaptureUnavailable, CaptureUnavailableCode};
        let payload = super::capture_unavailable_payload(&CaptureUnavailable::new(
            CaptureUnavailableCode::Permission,
            "creating scrap::Capturer: other error",
        ));
        assert!(
            payload.starts_with(r#"{"t":"rc:media-unavailable","code":"permission","#),
            "{payload}"
        );
        assert!(
            payload.contains(r#""detail":"creating scrap::Capturer: other error""#),
            "{payload}"
        );
        assert!(payload.contains(r#""hint":"#), "{payload}");

        for (code, wire) in [
            (CaptureUnavailableCode::Permission, "permission"),
            (CaptureUnavailableCode::NoDisplay, "no_display"),
            (CaptureUnavailableCode::NotBuilt, "not_built"),
            (CaptureUnavailableCode::BackendError, "backend_error"),
            (
                CaptureUnavailableCode::WaylandNotEnabled,
                "wayland_not_enabled",
            ),
            (CaptureUnavailableCode::X11NotEnabled, "x11_not_enabled"),
        ] {
            assert_eq!(code.wire(), wire);
            assert!(!code.hint().is_empty(), "{wire} has no operator sentence");
            // The hint is spliced into the payload unescaped, so every code's
            // sentence must leave it parseable and arrive as written.
            let payload = super::capture_unavailable_payload(&CaptureUnavailable::new(code, "d"));
            let parsed: serde_json::Value = serde_json::from_str(&payload)
                .unwrap_or_else(|e| panic!("{wire}: payload is not JSON ({e}): {payload}"));
            assert_eq!(parsed["code"], wire);
            assert_eq!(parsed["hint"], code.hint(), "{wire}");
        }
    }

    /// A backend error is the backend's own words, and those words are not
    /// ours to trust: a quote or a newline in them must not produce a
    /// payload the viewer cannot parse.
    #[test]
    fn capture_unavailable_detail_is_escaped_and_capped() {
        use crate::capture::{CaptureUnavailable, CaptureUnavailableCode};
        let payload = super::capture_unavailable_payload(&CaptureUnavailable::new(
            CaptureUnavailableCode::BackendError,
            "he said \"no\"\nand a \\ too",
        ));
        assert!(
            payload.contains(r#"he said \"no\" and a \\ too"#),
            "{payload}"
        );
        serde_json::from_str::<serde_json::Value>(&payload).expect("payload must be valid JSON");

        let long = CaptureUnavailable::new(CaptureUnavailableCode::BackendError, "é".repeat(400));
        assert_eq!(
            long.detail.chars().count(),
            200,
            "capped on a CHAR boundary, so a multi-byte error text cannot split a code point"
        );
    }

    /// FR-97 P3b — the Linux lock hint is `rc:host_locked` plus
    /// `input: "passes"`: the viewer's chip says the lock screen takes input.
    /// FR-97 P2d-1 — a Mac's is `input: "unknown"`.
    #[test]
    fn host_locked_advisory_payload_wire_shape() {
        for input in ["passes", "unknown"] {
            for locked in [true, false] {
                let v: serde_json::Value =
                    serde_json::from_str(&super::host_locked_advisory_payload(locked, input))
                        .expect("JSON");
                assert_eq!(v["t"], "rc:host_locked");
                assert_eq!(v["locked"], locked);
                assert_eq!(v["input"], input);
            }
        }
    }

    /// FR-97 P3c-1 — the audio notice's wire shape, which the viewer parses
    /// (`parseControlInbound`, `rc:audio-unavailable`).
    #[test]
    fn audio_unavailable_payload_wire_shape() {
        use crate::audio_source::{AudioUnavailable, AudioUnavailableCode};
        let payload = super::audio_unavailable_payload(&AudioUnavailable::new(
            AudioUnavailableCode::NoMonitor,
            "devices: pipewire, pulse, default",
        ));
        let parsed: serde_json::Value = serde_json::from_str(&payload).expect("JSON");
        assert_eq!(parsed["t"], "rc:audio-unavailable");
        assert_eq!(parsed["code"], "no_monitor");
        assert_eq!(parsed["detail"], "devices: pipewire, pulse, default");
        assert_eq!(parsed["hint"], AudioUnavailableCode::NoMonitor.hint());
        // A backend's own words arrive as written, quotes and newlines too.
        let odd = "he said \"no\"\nand a \\ too";
        let parsed: serde_json::Value = serde_json::from_str(&super::audio_unavailable_payload(
            &AudioUnavailable::new(AudioUnavailableCode::BackendError, odd),
        ))
        .expect("JSON");
        assert_eq!(parsed["detail"], odd);
    }

    #[test]
    fn case_insensitive_selection() {
        assert_eq!(build_video_codec_cap("H264").mime_type, "video/H264");
        assert_eq!(build_video_codec_cap("AV1").mime_type, "video/AV1");
        assert_eq!(build_video_codec_cap("HEVC").mime_type, "video/HEVC");
    }

    #[test]
    fn unknown_codec_defaults_to_h264() {
        // Belt-and-braces: pick_best_codec should never hand us an
        // unknown codec, but if it does we must not panic. (VP8 is known
        // since #2231: the DataChannel's placeholder track. The agent never
        // advertises it for RTP, so pick_best_codec cannot return it.)
        let cap = build_video_codec_cap("theora");
        assert_eq!(cap.mime_type, "video/H264");
    }

    #[test]
    fn codec_params_payload_types_match_default_media_engine() {
        // webrtc-rs 0.12 defaults: H.264 PT 125, HEVC PT 126, AV1 PT 41.
        assert_eq!(codec_params_for("h264").payload_type, 125);
        assert_eq!(codec_params_for("h265").payload_type, 126);
        assert_eq!(codec_params_for("hevc").payload_type, 126);
        assert_eq!(codec_params_for("av1").payload_type, 41);
    }

    #[test]
    fn rtcp_feedback_includes_nack_pli() {
        // All three codecs need NACK+PLI so the browser can request
        // retransmission and keyframes; drop either one and the
        // stream freezes on any loss.
        for codec in ["h264", "h265", "av1"] {
            let cap = build_video_codec_cap(codec);
            assert!(
                cap.rtcp_feedback
                    .iter()
                    .any(|f| f.typ == "nack" && f.parameter == "pli"),
                "codec {codec} missing nack pli"
            );
            assert!(
                cap.rtcp_feedback.iter().any(|f| f.typ == "transport-cc"),
                "codec {codec} missing transport-cc"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::quality::*;

    /// rc.227 / FR-97 P3e — the `rc:layout` envelope as the viewer's
    /// `parseControlInbound` reads it: `active_hkl` and `active` strings, and
    /// `installed` as `{hkl, tag}` objects. One builder serves the emitter and
    /// the control arm's first send, on Windows and on X11.
    #[cfg(all(
        any(target_os = "windows", target_os = "linux"),
        feature = "enigo-input"
    ))]
    #[test]
    fn the_layout_envelope_is_the_one_the_viewer_parses() {
        let snap = crate::input::layout::LayoutSnapshot {
            active_hkl: "1".into(),
            active_tag: "de-DE".into(),
            installed: vec![("0".into(), "en-US".into()), ("1".into(), "de-DE".into())],
        };
        let v: serde_json::Value = serde_json::from_str(&super::layout_json(&snap)).unwrap();
        assert_eq!(v["t"], "rc:layout");
        assert_eq!(v["active_hkl"], "1");
        assert_eq!(v["active"], "de-DE");
        assert_eq!(v["installed"][0]["hkl"], "0");
        assert_eq!(v["installed"][1]["tag"], "de-DE");
        assert_eq!(v["installed"].as_array().map(Vec::len), Some(2));
    }

    /// FR-112 P2b — under the software tier every preference starts the RTP
    /// pump at 60; without it, 0.4.141's targets.
    #[test]
    fn the_rtp_target_is_60_under_the_tier() {
        use crate::encode::EncoderPreference as P;
        for pref in [P::Auto, P::Software, P::Hardware] {
            assert_eq!(super::target_fps_with_tier(pref, true), 60, "{pref:?}");
            assert_eq!(
                super::target_fps_with_tier(pref, false),
                super::target_fps_for(pref),
                "{pref:?}: the kill switch"
            );
        }
        assert_eq!(super::target_fps_with_tier(P::Software, false), 30);
    }

    /// FR-112 P2 — the VP9-444 target: an explicit `ROOMLERD_VP9_FPS` pins it;
    /// otherwise 60 with the software tier on, and 30 with it off.
    #[cfg(feature = "vp9-444")]
    #[test]
    fn the_vp9_target_is_60_unless_pinned_or_switched_off() {
        assert_eq!(super::vp9_444_target_fps(None, true), 60);
        assert_eq!(
            super::vp9_444_target_fps(None, false),
            30,
            "the kill switch: 0.4.141's default"
        );
        assert_eq!(
            super::vp9_444_target_fps(Some(30), true),
            30,
            "a pin wins over the tier"
        );
        assert_eq!(super::vp9_444_target_fps(Some(60), false), 60);
        assert_eq!(
            super::vp9_444_target_fps(Some(50), true),
            60,
            "rounds to the nearer"
        );
        assert_eq!(super::vp9_444_target_fps(Some(40), true), 30);
    }

    // Badge-truth — lock the `rc:video-info` wire shape (both pumps emit
    // through this one builder; the browser's parseControlInbound reads
    // exactly these keys). Runs on the default build.
    #[test]
    fn video_info_payload_wire_shape() {
        assert_eq!(
            super::video_info_payload(
                "h265",
                "hevc_nvenc",
                true,
                "yuv420",
                false,
                1920,
                1080,
                1,
                None,
                None,
                None,
                None,
                None
            ),
            r#"{"t":"rc:video-info","codec":"h265","encoder":"hevc_nvenc","hardware":true,"chroma":"yuv420","transport":"direct","native_w":1920,"native_h":1080,"viewers":1}"#
        );
        assert_eq!(
            super::video_info_payload(
                "vp9", "libvpx", false, "yuv444", true, 2560, 1600, 2, None, None, None, None, None
            ),
            r#"{"t":"rc:video-info","codec":"vp9","encoder":"libvpx","hardware":false,"chroma":"yuv444","transport":"relay","native_w":2560,"native_h":1600,"viewers":2}"#
        );
        // FR-33 P3 — the reason rides as a trailing optional key, so every
        // pre-P3 viewer keeps parsing the message exactly as before.
        assert_eq!(
            super::video_info_payload(
                "vp9",
                "libvpx",
                false,
                "yuv444",
                true,
                2560,
                1600,
                1,
                Some("lan-captured"),
                None,
                None,
                None,
                None
            ),
            r#"{"t":"rc:video-info","codec":"vp9","encoder":"libvpx","hardware":false,"chroma":"yuv444","transport":"relay","native_w":2560,"native_h":1600,"viewers":1,"transport_reason":"lan-captured"}"#
        );
        // FR-70 P1 — the cap and its detail ride as trailing optional keys
        // too; the detail never appears without a reason (a detail with
        // nothing to explain would be a stray string on the badge).
        assert_eq!(
            super::video_info_payload(
                "h265",
                "hevc_qsv",
                true,
                "yuv420",
                true,
                1920,
                1200,
                1,
                None,
                Some("slow-link-cap"),
                Some("remembered 200 kbps"),
                None,
                None
            ),
            r#"{"t":"rc:video-info","codec":"h265","encoder":"hevc_qsv","hardware":true,"chroma":"yuv420","transport":"relay","native_w":1920,"native_h":1200,"viewers":1,"cap_reason":"slow-link-cap","cap_detail":"remembered 200 kbps"}"#
        );
        assert_eq!(
            super::video_info_payload(
                "h265",
                "hevc_qsv",
                true,
                "yuv420",
                true,
                1920,
                1200,
                1,
                None,
                None,
                Some("remembered 200 kbps"),
                None,
                None
            ),
            r#"{"t":"rc:video-info","codec":"h265","encoder":"hevc_qsv","hardware":true,"chroma":"yuv420","transport":"relay","native_w":1920,"native_h":1200,"viewers":1}"#
        );
        // FR-93 P2 — the Linux arm and whether it asked anyone, trailing and
        // optional like the keys above. Only the portal is attended.
        use crate::capture::CaptureArm;
        let arm_of = |arm| {
            super::video_info_payload(
                "vp9", "libvpx", false, "yuv444", false, 1280, 800, 1, None, None, None, arm, None,
            )
        };
        let head = r#"{"t":"rc:video-info","codec":"vp9","encoder":"libvpx","hardware":false,"chroma":"yuv444","transport":"direct","native_w":1280,"native_h":800,"viewers":1"#;
        for (arm, tail) in [
            (
                CaptureArm::Mutter,
                r#","capture_arm":"mutter","attended":false}"#,
            ),
            (
                CaptureArm::Portal,
                r#","capture_arm":"portal","attended":true}"#,
            ),
            (CaptureArm::Drm, r#","capture_arm":"drm","attended":false}"#),
            (CaptureArm::X11, r#","capture_arm":"x11","attended":false}"#),
        ] {
            assert_eq!(arm_of(Some(arm)), format!("{head}{tail}"));
        }
        assert_eq!(arm_of(None), format!("{head}}}"));
    }

    /// FR-119 P1 — the frame-rate answer rides `rc:video-info` as trailing
    /// optional keys, only when `fps-high` is on: with it off the pump passes
    /// `None`, so every payload above stays byte-identical.
    #[test]
    fn video_info_payload_carries_the_frame_rate_answer() {
        let payload = |fps| {
            super::video_info_payload(
                "h265",
                "hevc_nvenc",
                true,
                "yuv420",
                false,
                1920,
                1080,
                1,
                None,
                None,
                None,
                None,
                fps,
            )
        };
        let head = r#"{"t":"rc:video-info","codec":"h265","encoder":"hevc_nvenc","hardware":true,"chroma":"yuv420","transport":"direct","native_w":1920,"native_h":1080,"viewers":1"#;
        let fields = |asked| {
            crate::encode::frame_rate::video_info_fields(&crate::encode::frame_rate::answer(
                asked, 60, false,
            ))
        };
        assert_eq!(
            payload(Some(fields(Some(120)))),
            format!(r#"{head},"fps":60,"fps_asked":120,"fps_reason":"unproven"}}"#)
        );
        assert_eq!(payload(Some(fields(None))), format!(r#"{head},"fps":60}}"#));
        assert_eq!(payload(None), format!("{head}}}"));
    }

    // FR-33 P3 — the reason is named only when the session is relayed AND
    // the viewer's LAN address lies inside a captured prefix; a remote viewer
    // relayed by the corp NAT gets plain "relay".
    #[test]
    fn lan_capture_reason_needs_relay_and_a_viewer_inside_the_captured_prefix() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let captured = |a: std::net::Ipv4Addr| a.octets()[..3] == [192, 168, 68];
        let on_lan = [ip("192.168.68.126")];
        let remote = [ip("37.63.112.129"), ip("10.0.0.5")];
        assert_eq!(
            super::lan_capture_reason_for(true, &on_lan, captured),
            Some("lan-captured")
        );
        assert_eq!(
            super::lan_capture_reason_for(false, &on_lan, captured),
            None,
            "direct: nothing to explain"
        );
        assert_eq!(
            super::lan_capture_reason_for(true, &remote, captured),
            None,
            "off-LAN viewer: the NAT is the reason, not the capture"
        );
        assert_eq!(super::lan_capture_reason_for(true, &[], captured), None);
        assert_eq!(
            super::lan_capture_reason_for(true, &[ip("fe80::1")], captured),
            None,
            "a v6 candidate never matches a v4 capture"
        );
    }

    // rc.183/rc.190 — remote-cursor downscale mapping, now computed from the
    // dims the pump PUBLISHES (native + actually-encoded) so the scale
    // reflects whatever the pump really did (controller pick AND agent-side
    // relay/SW caps alike).
    #[test]
    fn cursor_scale_identity_when_encoded_equals_native() {
        let native = super::pack_dims(1920, 1200);
        assert_eq!(super::cursor_scale_from_dims(native, native), (1.0, 1.0));
    }

    #[test]
    fn cursor_scale_halves_at_half_resolution() {
        let native = super::pack_dims(1920, 1200);
        let encoded = super::pack_dims(960, 600);
        let (sx, sy) = super::cursor_scale_from_dims(native, encoded);
        assert!((sx - 0.5).abs() < 1e-6, "sx={sx}");
        assert!((sy - 0.5).abs() < 1e-6, "sy={sy}");
    }

    #[test]
    fn cursor_scale_fixes_1280_overshoot() {
        // The rc.183 field case: 1920×1200 native, 1280×800 encode. A cursor
        // at native x=1920 must map to encoded x=1280 (the frame's right
        // edge), killing the prior 1.5× overshoot.
        let native = super::pack_dims(1920, 1200);
        let encoded = super::pack_dims(1280, 800);
        let (sx, _sy) = super::cursor_scale_from_dims(native, encoded);
        assert!((1920.0 * sx - 1280.0).abs() < 1.0, "1920*{sx} != ~1280");
    }

    #[test]
    fn cursor_scale_tracks_agent_side_relay_cap() {
        // rc.190 regression: controller asked Native but the relay cap
        // encoded 1280×800 from a 2560×1600 panel. The published encoded
        // dims — not TargetResolution — must drive the scale.
        let native = super::pack_dims(2560, 1600);
        let encoded = super::pack_dims(1280, 800);
        let (sx, sy) = super::cursor_scale_from_dims(native, encoded);
        assert!((sx - 0.5).abs() < 1e-6, "sx={sx}");
        assert!((sy - 0.5).abs() < 1e-6, "sy={sy}");
    }

    #[test]
    fn cursor_scale_identity_before_first_frame() {
        // Either side unpublished (0) must not scale.
        let some = super::pack_dims(1280, 800);
        assert_eq!(super::cursor_scale_from_dims(0, some), (1.0, 1.0));
        assert_eq!(super::cursor_scale_from_dims(some, 0), (1.0, 1.0));
    }

    // rc.190 — agent-side resolution caps (B1 relay hard / B2 SW soft).
    use super::TargetResolution as TR;

    #[test]
    fn aspect_preserved_target_shrinks_long_edge_even_dims() {
        // 4K 16:9 capped at 1920 → exactly 1920×1080.
        assert_eq!(
            super::aspect_preserved_target(3840, 2160, 1920),
            (1920, 1080)
        );
        // 16:10 panel capped at 1280 → 1280×800.
        assert_eq!(
            super::aspect_preserved_target(2560, 1600, 1280),
            (1280, 800)
        );
        // Already within the cap → unchanged.
        assert_eq!(super::aspect_preserved_target(1280, 720, 1920), (1280, 720));
        // Odd results round DOWN to even (1366×768 → cap 1000: 1000×562.3 → 1000×562).
        let (w, h) = super::aspect_preserved_target(1366, 768, 1000);
        assert_eq!(w % 2, 0);
        assert_eq!(h % 2, 0);
    }

    #[test]
    fn caps_native_passthrough_when_no_caps() {
        assert_eq!(
            super::effective_target_resolution(TR::Native, 3840, 2160, None, None),
            TR::Native
        );
    }

    #[test]
    fn soft_cap_fills_in_for_native_only() {
        // B2: libvpx at 4K + controller left Native → capped at 1920 long edge.
        assert_eq!(
            super::effective_target_resolution(TR::Native, 3840, 2160, None, Some(1920)),
            TR::Fixed {
                width: 1920,
                height: 1080
            }
        );
        // Explicit controller pick ABOVE the soft cap wins (operator override).
        let user = TR::Fixed {
            width: 2560,
            height: 1440,
        };
        assert_eq!(
            super::effective_target_resolution(user, 3840, 2160, None, Some(1920)),
            user
        );
        // Native already within the soft cap → stays Native (no pointless Fixed).
        assert_eq!(
            super::effective_target_resolution(TR::Native, 1920, 1200, None, Some(1920)),
            TR::Native
        );
    }

    #[test]
    fn hard_cap_clamps_native_and_oversized_picks() {
        // B1: relay cap 1280 clamps Native on a 2560×1600 panel (the DEVBOX
        // blur↔crystallize field case).
        assert_eq!(
            super::effective_target_resolution(TR::Native, 2560, 1600, Some(1280), None),
            TR::Fixed {
                width: 1280,
                height: 800
            }
        );
        // ...and clamps an explicit pick LARGER than the cap (link physics).
        assert_eq!(
            super::effective_target_resolution(
                TR::Fixed {
                    width: 1920,
                    height: 1200
                },
                2560,
                1600,
                Some(1280),
                None
            ),
            TR::Fixed {
                width: 1280,
                height: 800
            }
        );
        // ...and an oversized Fit request (bigger than native = really
        // native) can't dodge the cap.
        assert_eq!(
            super::effective_target_resolution(
                TR::Fixed {
                    width: 3000,
                    height: 2000
                },
                2560,
                1600,
                Some(1280),
                None
            ),
            TR::Fixed {
                width: 1280,
                height: 800
            }
        );
    }

    #[test]
    fn hard_cap_keeps_smaller_user_pick() {
        // A controller pick BELOW the relay cap is respected verbatim.
        let user = TR::Fixed {
            width: 960,
            height: 600,
        };
        assert_eq!(
            super::effective_target_resolution(user, 2560, 1600, Some(1280), None),
            user
        );
    }

    #[test]
    fn hard_cap_noop_when_native_within_cap() {
        // Small panel over relay → no cap engages.
        assert_eq!(
            super::effective_target_resolution(TR::Native, 1280, 720, Some(1280), None),
            TR::Native
        );
    }

    // rc.191 — aspect-preserving box resolve + near-native snap.
    #[test]
    fn user_box_preserves_source_aspect() {
        // The field distortion case: stage-shaped Fit 1672×818 against a
        // 16:9 source must NOT squash — uniform scale = min(0.87, 0.757).
        let r = super::effective_target_resolution(
            TR::Fixed {
                width: 1672,
                height: 818,
            },
            1920,
            1080,
            None,
            None,
        );
        let TR::Fixed { width, height } = r else {
            panic!("expected Fixed, got {r:?}");
        };
        // Aspect within a pixel of 16:9 after even-align.
        let src_aspect = 1920.0 / 1080.0;
        let out_aspect = width as f32 / height as f32;
        assert!(
            (out_aspect - src_aspect).abs() < 0.01,
            "aspect distorted: {width}x{height}"
        );
        assert!(width <= 1672 && height <= 818, "must fit the box");
    }

    #[test]
    fn near_native_box_snaps_to_native() {
        // Within 15% of the source → 1:1 passthrough instead of a mushy
        // 0.9× resample (needs ambient env unset — tests don't set it).
        assert_eq!(
            super::effective_target_resolution(
                TR::Fixed {
                    width: 1836,
                    height: 1148
                },
                1920,
                1200,
                None,
                None
            ),
            TR::Native
        );
        // A fullscreen-sized box ≥ native is Native outright.
        assert_eq!(
            super::effective_target_resolution(
                TR::Fixed {
                    width: 1920,
                    height: 1200
                },
                1920,
                1080,
                None,
                None
            ),
            TR::Native
        );
    }

    #[test]
    fn snapped_native_still_respects_hard_cap() {
        // Snap must not dodge relay physics: near-native box on a relay
        // session still clamps to the cap.
        assert_eq!(
            super::effective_target_resolution(
                TR::Fixed {
                    width: 1836,
                    height: 1148
                },
                1920,
                1200,
                Some(1280),
                None
            ),
            TR::Fixed {
                width: 1280,
                height: 800
            }
        );
    }

    #[test]
    fn soft_then_hard_compose() {
        // WINHOST-H-over-relay worst case: 4K panel, libvpx, constrained.
        // Soft 1920 fills in for Native, then hard 1280 clamps further.
        assert_eq!(
            super::effective_target_resolution(TR::Native, 3840, 2160, Some(1280), Some(1920)),
            TR::Fixed {
                width: 1280,
                height: 720
            }
        );
    }

    // rc.190 (B3) — stuck-session watchdog decision matrix.
    use super::WatchdogVerdict as WV;
    use std::time::Duration as D;
    use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as PS;

    const DEADLINE: D = D::from_secs(45);
    const GRACE: D = D::from_secs(20);

    #[test]
    fn watchdog_kills_never_connected_after_deadline() {
        // The DEVBOX field case: ICE wedged in Connecting, no Failed ever.
        assert_eq!(
            super::session_watchdog_verdict(
                PS::Connecting,
                false,
                D::from_secs(46),
                None,
                DEADLINE,
                GRACE
            ),
            WV::Kill
        );
        // …but waits patiently before the deadline.
        assert_eq!(
            super::session_watchdog_verdict(
                PS::Connecting,
                false,
                D::from_secs(30),
                None,
                DEADLINE,
                GRACE
            ),
            WV::Wait
        );
    }

    #[test]
    fn watchdog_never_kills_a_connected_peer() {
        assert_eq!(
            super::session_watchdog_verdict(
                PS::Connected,
                true,
                D::from_secs(9999),
                None,
                DEADLINE,
                GRACE
            ),
            WV::Wait
        );
    }

    #[test]
    fn watchdog_connecting_after_connected_is_not_the_never_connected_case() {
        // ICE restart mid-session: state back to Connecting but
        // connected_once=true → the connect deadline must NOT apply.
        assert_eq!(
            super::session_watchdog_verdict(
                PS::Connecting,
                true,
                D::from_secs(9999),
                None,
                DEADLINE,
                GRACE
            ),
            WV::Wait
        );
    }

    #[test]
    fn watchdog_kills_disconnected_limbo_after_grace() {
        assert_eq!(
            super::session_watchdog_verdict(
                PS::Disconnected,
                true,
                D::from_secs(300),
                Some(D::from_secs(21)),
                DEADLINE,
                GRACE
            ),
            WV::Kill
        );
        // A short blip inside the grace recovers on its own — leave it.
        assert_eq!(
            super::session_watchdog_verdict(
                PS::Disconnected,
                true,
                D::from_secs(300),
                Some(D::from_secs(5)),
                DEADLINE,
                GRACE
            ),
            WV::Wait
        );
    }

    #[test]
    fn watchdog_disarms_on_closed_and_failed() {
        // Failed is already Terminated by the state-change handler; Closed
        // is a normal teardown — either way the watchdog stands down.
        for s in [PS::Closed, PS::Failed] {
            assert_eq!(
                super::session_watchdog_verdict(
                    s,
                    false,
                    D::from_secs(9999),
                    None,
                    DEADLINE,
                    GRACE
                ),
                WV::Disarm
            );
        }
    }

    #[test]
    fn pack_dims_round_trips() {
        let packed = super::pack_dims(2560, 1600);
        assert_eq!((packed >> 32) as u32, 2560);
        assert_eq!((packed & 0xFFFF_FFFF) as u32, 1600);
    }

    #[test]
    fn from_wire_accepts_known_values_case_insensitively() {
        assert_eq!(from_wire("low"), Some(LOW));
        assert_eq!(from_wire("LOW"), Some(LOW));
        assert_eq!(from_wire("Low"), Some(LOW));
        assert_eq!(from_wire("auto"), Some(AUTO));
        assert_eq!(from_wire("Auto"), Some(AUTO));
        assert_eq!(from_wire("high"), Some(HIGH));
        assert_eq!(from_wire("HIGH"), Some(HIGH));
    }

    #[test]
    fn from_wire_rejects_unknown_values() {
        assert_eq!(from_wire(""), None);
        assert_eq!(from_wire("medium"), None);
        assert_eq!(from_wire("ultra"), None);
        assert_eq!(from_wire("0"), None);
    }

    #[test]
    fn label_round_trips_known_values() {
        assert_eq!(label(LOW), "low");
        assert_eq!(label(AUTO), "auto");
        assert_eq!(label(HIGH), "high");
        // Sentinel + unknown values fall back to "auto" so logs stay
        // useful even when the atomic gets corrupted.
        assert_eq!(label(0xFF), "auto");
        assert_eq!(label(42), "auto");
    }

    #[test]
    fn target_bitrate_scales_per_quality() {
        // Base = 6 Mbps (rough 1080p target).
        let base = 6_000_000;
        assert_eq!(target_bitrate(LOW, base), 3_000_000);
        assert_eq!(target_bitrate(AUTO, base), 6_000_000);
        assert_eq!(target_bitrate(HIGH, base), 9_000_000);
    }

    #[test]
    fn target_bitrate_low_floors_at_500_kbps() {
        // Even on tiny resolutions Low must produce a usable stream.
        assert_eq!(target_bitrate(LOW, 100_000), 500_000);
        assert_eq!(target_bitrate(LOW, 1_000_000), 500_000);
        assert_eq!(target_bitrate(LOW, 1_500_000), 750_000);
    }

    #[test]
    fn target_bitrate_high_caps_at_50_mbps() {
        // 1920×1200 base is 24 Mbps after the rc.36 bpp/cap bump; High
        // should add 50% giving 36 Mbps (under the 50 Mbps cap).
        assert_eq!(target_bitrate(HIGH, 12_000_000), 18_000_000);
        // 4K60 base saturates MAX_BITRATE_BPS at 40 Mbps; High then
        // multiplies × 1.5 → 60 Mbps which the post-multiply cap
        // clamps back to the rc.36 ceiling of 50 Mbps.
        assert_eq!(target_bitrate(HIGH, 40_000_000), 50_000_000);
        // Very high synthetic base: cap engages.
        assert_eq!(target_bitrate(HIGH, 50_000_000), 50_000_000);
    }
}

#[cfg(test)]
mod video_bytes_wire_tests {
    use super::{
        CHUNK_HEADER_BYTES, agent_epoch_us, chunk_framed, clock_echo_json, frame_video_bytes,
    };

    /// Lock the exact byte layout that `rc-vp9-444-worker.ts`'s
    /// `parseFrameHeader` (lines 260-273 of that file) reads. A typo
    /// or endian flip on either side silently breaks decode; this
    /// test surfaces the mismatch in CI before the field does.
    ///
    /// Layout:
    ///   bytes [0..4)  payload-size, u32 little-endian
    ///   byte  [4]     flags (bit 0 = keyframe)
    ///   bytes [5..13) timestamp_us, u64 little-endian
    ///   bytes [13..)  payload
    #[test]
    fn header_layout_matches_worker_parser() {
        let payload = b"abcdef";
        let out = frame_video_bytes(payload, true, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(out.len(), 13 + payload.len(), "header is 13 bytes");
        // size = 6, little-endian
        assert_eq!(&out[0..4], &[0x06, 0x00, 0x00, 0x00]);
        // flags = 0x01 (keyframe)
        assert_eq!(out[4], 0x01);
        // timestamp = 0xDEADBEEFCAFEBABE little-endian
        assert_eq!(
            &out[5..13],
            &[0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE],
        );
        // payload follows verbatim
        assert_eq!(&out[13..], payload);
    }

    /// FR-17 — lock the 8-byte chunk prefix both workers'
    /// `assembleFrame` reads. This is a wire contract in the same sense
    /// as `header_layout_matches_worker_parser` above, and it matters
    /// MORE than that one: the framed messages are the layer that lets a
    /// receiver notice a gap at all, so a silent endian flip here would
    /// look like corrupt video rather than a parse error.
    ///
    /// Layout:
    ///   bytes [0..4)  frame_seq,   u32 little-endian
    ///   bytes [4..6)  chunk_idx,   u16 little-endian
    ///   bytes [6..8)  chunk_count, u16 little-endian
    ///   bytes [8..)   the 16 KiB slice of the already-framed frame
    #[test]
    fn chunk_prefix_layout_matches_worker_assembler() {
        let payload = b"chunk";
        let out = chunk_framed(0x0102_0304, 0x0A0B, 0x0C0D, payload);
        assert_eq!(out.len(), CHUNK_HEADER_BYTES + payload.len());
        assert_eq!(&out[0..4], &[0x04, 0x03, 0x02, 0x01], "frame_seq LE");
        assert_eq!(&out[4..6], &[0x0B, 0x0A], "chunk_idx LE");
        assert_eq!(&out[6..8], &[0x0D, 0x0C], "chunk_count LE");
        assert_eq!(&out[8..], payload, "payload follows verbatim");
    }

    /// The prefix must not disturb the payload — the assembler
    /// concatenates the slices and hands the result to the SAME
    /// `parseFrameHeader` as before, so a framed session and an unframed
    /// one must reconstruct byte-identical frames. Reassembling the
    /// chunks here is the check that stage A really is behaviour-neutral.
    #[test]
    fn reassembly_reproduces_the_unframed_stream() {
        const CHUNK: usize = 16 * 1024;
        let frame = frame_video_bytes(&vec![7u8; 40_000], true, 42);
        let mut chunks = Vec::new();
        let count = frame.len().div_ceil(CHUNK).max(1) as u16;
        let mut off = 0;
        let mut idx: u16 = 0;
        while off < frame.len() {
            let end = (off + CHUNK).min(frame.len());
            chunks.push(chunk_framed(9, idx, count, &frame[off..end]));
            idx += 1;
            off = end;
        }
        assert_eq!(chunks.len(), 3, "40 000 + 13 bytes spans three messages");
        let mut rebuilt = Vec::new();
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(u32::from_le_bytes(c[0..4].try_into().unwrap()), 9);
            assert_eq!(u16::from_le_bytes(c[4..6].try_into().unwrap()), i as u16);
            assert_eq!(u16::from_le_bytes(c[6..8].try_into().unwrap()), count);
            rebuilt.extend_from_slice(&c[8..]);
        }
        assert_eq!(rebuilt, frame, "framing is transparent to the frame bytes");
    }

    /// A zero-length frame must still be announced as one chunk. The
    /// `.max(1)` in the pumps is what makes that true; without it a
    /// receiver would be told to expect zero chunks and could never
    /// consider the frame complete.
    #[test]
    fn empty_frame_is_announced_as_one_chunk_not_zero() {
        let total = 0usize;
        assert_eq!(total.div_ceil(16 * 1024).max(1), 1);
    }

    #[test]
    fn delta_frames_clear_keyframe_flag() {
        let out = frame_video_bytes(b"x", false, 0);
        assert_eq!(out[4], 0x00, "delta frame must not set the keyframe bit");
    }

    #[test]
    fn empty_payload_still_emits_full_13_byte_header() {
        // Edge case: libvpx can emit zero-byte show=0 hidden frames.
        // We pass them through; the worker drops them via the
        // `size === 0` branch.
        let out = frame_video_bytes(&[], true, 1);
        assert_eq!(out.len(), 13);
        assert_eq!(&out[0..4], &[0, 0, 0, 0]);
    }

    /// FR-1 P7 — the rc:clock echo is a wire contract with the browser's
    /// HUD-age math: `t0` must come back byte-for-byte (RTT correctness)
    /// and `agent_us` must be the bare integer the wire timestamps use.
    #[test]
    fn clock_echo_echoes_t0_verbatim_and_carries_agent_us() {
        let t0 = serde_json::json!(1_756_300_000_000_000.0_f64);
        let v: serde_json::Value = serde_json::from_str(&clock_echo_json(&t0, 42)).unwrap();
        assert_eq!(v["t"], "rc:clock.echo");
        assert_eq!(v["agent_us"], 42);
        assert_eq!(v["t0"], t0);
        // A hostile/odd t0 (string, null) still round-trips rather than
        // erroring — the browser just discards the unusable sample.
        let v2: serde_json::Value =
            serde_json::from_str(&clock_echo_json(&serde_json::json!("x"), 1)).unwrap();
        assert_eq!(v2["t0"], "x");
        let v3: serde_json::Value =
            serde_json::from_str(&clock_echo_json(&serde_json::Value::Null, 1)).unwrap();
        assert!(v3["t0"].is_null());
    }

    #[test]
    fn agent_epoch_is_monotonic() {
        let a = agent_epoch_us();
        let b = agent_epoch_us();
        assert!(b >= a, "process-epoch clock must never run backwards");
    }
}

#[cfg(all(test, any(feature = "vp9-444", feature = "ffmpeg-encoder")))]
mod overlay_tier_tests {
    use super::*;

    #[test]
    fn overlay_range_matches_cgnat_v4_and_mesh_ula_only() {
        // In range: the overlay CGNAT /10 and the exact mesh ULA /48.
        assert!(addr_is_overlay_range("100.64.0.29"));
        assert!(addr_is_overlay_range("100.127.255.254"));
        assert!(addr_is_overlay_range("fd72:6f6f:6d6c::6440:1d"));
        // Out of range: LAN, CGNAT neighbours, foreign ULA (fc00::/7 is NOT
        // enough — only our /48 may trigger a daemon query), mDNS, garbage.
        assert!(!addr_is_overlay_range("192.168.5.10"));
        assert!(!addr_is_overlay_range("100.63.255.255"));
        assert!(!addr_is_overlay_range("100.128.0.1"));
        assert!(!addr_is_overlay_range("fd00:dead:beef::1"));
        assert!(!addr_is_overlay_range("a1b2c3d4-e5f6.local"));
        assert!(!addr_is_overlay_range(""));
    }

    #[tokio::test]
    async fn tier_query_fails_open_for_non_overlay_remote_and_hatch() {
        let sid = bson::oid::ObjectId::new();
        // Non-overlay remote: must return false without touching LocalAPI.
        assert!(!overlay_remote_is_relay_tier("203.0.113.9", sid).await);
        // Escape hatch: overlay remote, detection disabled → false fast,
        // no daemon required (this also keeps the test hermetic on hosts
        // where a real daemon happens to be running).
        // SAFETY: no other test touches this var (set_var is unsafe in
        // edition 2024 because of cross-thread env races).
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "OVERLAY_TIER_DETECT", "0") };
        assert!(!overlay_remote_is_relay_tier("100.64.0.29", sid).await);
        unsafe { tunnel_core::env::test_env::clear("OVERLAY_TIER_DETECT") };
    }
}

/// What a DataChannel handler lets go of when its session ends
/// ([`AgentPeer::session_end`]), whether or not its channel ever says it
/// closed.
#[cfg(test)]
mod session_end_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio_util::sync::CancellationToken;
    use webrtc::data_channel::data_channel_state::RTCDataChannelState as S;

    /// A channel of a peer that is never negotiated: `Connecting` until it is
    /// closed, and then held at `Closing` for good, which is exactly where a
    /// channel the device closed itself is often left.
    async fn lone_channel(label: &str) -> (Arc<RTCPeerConnection>, Arc<RTCDataChannel>) {
        let api = APIBuilder::new().build();
        let pc = Arc::new(
            api.new_peer_connection(RTCConfiguration::default())
                .await
                .expect("a peer connection"),
        );
        let dc = pc
            .create_data_channel(label, None)
            .await
            .expect("a data channel");
        (pc, dc)
    }

    async fn eventually(within: Duration, cond: impl Fn() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    #[test]
    fn closing_counts_as_gone() {
        assert!(!channel_gone(S::Connecting));
        assert!(!channel_gone(S::Open));
        assert!(
            channel_gone(S::Closing),
            "the state a device-side close stops at"
        );
        assert!(channel_gone(S::Closed));
    }

    /// Where the tracker reports no pointer, the poller sends nothing after
    /// its one `cursor:hide`, so no failed send ends it: only the state or
    /// the session can. Red with the check reading only `Closed`: the
    /// channel sits at `Closing` and the poller runs on at 120 Hz. (It waits
    /// through `Connecting` without sending, so this holds where the tracker
    /// does report a pointer too; red on Windows `mf-encoder` without that
    /// wait: its first send ends the poller before anything is closed.)
    #[tokio::test]
    async fn the_cursor_poller_ends_when_its_channel_stops_at_closing() {
        let (_pc, dc) = lone_channel("cursor").await;
        let dims = Arc::new(AtomicU64::new(0));
        let poller = attach_cursor_handler(
            dc.clone(),
            bson::oid::ObjectId::new(),
            dims.clone(),
            dims,
            CancellationToken::new(),
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!poller.is_finished(), "the poller ended on its own");
        dc.close().await.expect("close");
        assert_eq!(dc.ready_state(), S::Closing, "the case under test");
        tokio::time::timeout(Duration::from_secs(2), poller)
            .await
            .expect("the poller ran on at Closing")
            .expect("the poller panicked");
    }

    /// The session's end ends the poller while its channel still looks
    /// alive: a peer torn down fires nothing on its channels. Red without
    /// the session-end arm.
    #[tokio::test]
    async fn the_cursor_poller_ends_with_its_session() {
        let (_pc, dc) = lone_channel("cursor").await;
        let dims = Arc::new(AtomicU64::new(0));
        let end = CancellationToken::new();
        let poller = attach_cursor_handler(
            dc.clone(),
            bson::oid::ObjectId::new(),
            dims.clone(),
            dims,
            end.clone(),
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!poller.is_finished(), "the poller ended on its own");
        assert!(!channel_gone(dc.ready_state()));
        end.cancel();
        tokio::time::timeout(Duration::from_secs(2), poller)
            .await
            .expect("the poller outlived its session")
            .expect("the poller panicked");
    }

    /// The teardown runs once, when the session ends and not before, and the
    /// channel's callbacks are let go: they held the handler, which held the
    /// channel. And they go FIRST: by the time the teardown runs, no new
    /// message can start work behind it. Red without the release (the
    /// callback's capture is never dropped), and with the teardown first
    /// (it still sees the callback held).
    #[tokio::test]
    async fn a_session_end_runs_the_teardown_and_lets_go_of_the_channel() {
        let (_pc, dc) = lone_channel("files").await;
        let held = Arc::new(());
        let in_callback = held.clone();
        dc.on_message(Box::new(move |_| {
            let _still_held = &in_callback;
            Box::pin(async {})
        }));
        let ran = Arc::new(AtomicUsize::new(0));
        let held_at_teardown = Arc::new(AtomicUsize::new(usize::MAX));
        let end = CancellationToken::new();
        let r = ran.clone();
        let (h, seen) = (held.clone(), held_at_teardown.clone());
        on_session_end(&dc, &end, move || async move {
            // Less the teardown's own clone.
            seen.store(Arc::strong_count(&h) - 1, Ordering::SeqCst);
            r.fetch_add(1, Ordering::SeqCst);
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "ran before the session ended"
        );
        assert_eq!(
            Arc::strong_count(&held),
            3,
            "the test, the callback, the teardown"
        );
        end.cancel();
        assert!(
            eventually(Duration::from_secs(2), || ran.load(Ordering::SeqCst) == 1).await,
            "the teardown never ran"
        );
        assert!(
            eventually(Duration::from_secs(2), || Arc::strong_count(&held) == 1).await,
            "the channel's callback was never let go"
        );
        assert_eq!(ran.load(Ordering::SeqCst), 1, "ran more than once");
        assert_eq!(
            held_at_teardown.load(Ordering::SeqCst),
            1,
            "the teardown ran while the channel's callback was still in place"
        );
    }

    /// The files handler is wired to its session's end: when the session
    /// ends, its callbacks (holding the handler, with any upload's open file,
    /// and the channel) are let go. Red without the wiring: nothing drops.
    #[tokio::test]
    async fn the_files_handler_lets_go_when_its_session_ends() {
        let (_pc, dc) = lone_channel("files").await;
        let end = CancellationToken::new();
        attach_files_handler(dc.clone(), bson::oid::ObjectId::new(), &end);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let attached = Arc::strong_count(&dc);
        end.cancel();
        // The message callback's clone and the session-end task's own.
        assert!(
            eventually(Duration::from_secs(2), || Arc::strong_count(&dc)
                <= attached - 2)
            .await,
            "the channel is still held: {} of {attached}",
            Arc::strong_count(&dc)
        );
    }
}

/// #1730 — a download must end where it is PARKED when it is stopped, not
/// at its next check. A dead channel is simulated by a sink whose send (or
/// `buffered_amount`) never returns, the shape a network-dropped session had
/// in the field (0.4.107: the file held at +4 m 43 s).
#[cfg(test)]
mod download_stop_tests {
    use super::*;

    /// A channel whose peer vanished: the send parks for good.
    struct StuckSend {
        parked: Arc<tokio::sync::Notify>,
    }
    impl DownloadSink for StuckSend {
        async fn buffered(&self) -> usize {
            0
        }
        async fn send_chunk(&self, _chunk: &bytes::Bytes) -> anyhow::Result<()> {
            self.parked.notify_one();
            std::future::pending().await
        }
        async fn send_json(&self, _msg: &crate::files::FilesOutgoing<'_>) {}
        fn gone(&self) -> bool {
            false
        }
    }

    /// One whose `buffered_amount` parks (its lock held by a close that
    /// never finishes).
    struct StuckBuffered {
        parked: Arc<tokio::sync::Notify>,
    }
    impl DownloadSink for StuckBuffered {
        async fn buffered(&self) -> usize {
            self.parked.notify_one();
            std::future::pending().await
        }
        async fn send_chunk(&self, _chunk: &bytes::Bytes) -> anyhow::Result<()> {
            Ok(())
        }
        async fn send_json(&self, _msg: &crate::files::FilesOutgoing<'_>) {}
        fn gone(&self) -> bool {
            false
        }
    }

    /// A healthy channel: keeps what it was sent.
    struct Collect {
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    }
    impl DownloadSink for Collect {
        async fn buffered(&self) -> usize {
            0
        }
        async fn send_chunk(&self, chunk: &bytes::Bytes) -> anyhow::Result<()> {
            self.bytes.lock().unwrap().extend_from_slice(chunk);
            Ok(())
        }
        async fn send_json(&self, _msg: &crate::files::FilesOutgoing<'_>) {}
        fn gone(&self) -> bool {
            false
        }
    }

    /// A file in the test's own folder, never the real Downloads (#1724).
    fn a_file(len: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("download.bin");
        let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, body).expect("write the file");
        (dir, path)
    }

    async fn ends_within_2s(
        pump: tokio::task::JoinHandle<anyhow::Result<u64>>,
        what: &str,
    ) -> anyhow::Result<u64> {
        tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .unwrap_or_else(|_| panic!("#1730: {what}"))
            .expect("the pump task")
    }

    #[tokio::test]
    async fn a_download_parked_in_a_send_ends_with_the_session() {
        let (_dir, path) = a_file(512 * 1024);
        let handler = crate::files::FilesHandler::new();
        let offer = handler
            .begin_outgoing("stuck-send".into(), &path.to_string_lossy())
            .await
            .expect("begin_outgoing");
        let parked = Arc::new(tokio::sync::Notify::new());
        let sink = StuckSend {
            parked: parked.clone(),
        };
        let h = handler.clone();
        let pump = tokio::spawn(async move {
            pump_outgoing_file(&sink, &h, &offer, bson::oid::ObjectId::new()).await
        });
        tokio::time::timeout(Duration::from_secs(5), parked.notified())
            .await
            .expect("the pump reached its send");
        handler.end_session().await;
        let done = ends_within_2s(
            pump,
            "the download must end with the session, not stay parked in a send that never returns",
        )
        .await;
        assert!(done.is_err(), "a stopped download says so: {done:?}");
    }

    #[tokio::test]
    async fn a_download_parked_on_the_send_buffer_ends_with_a_browser_cancel() {
        let (_dir, path) = a_file(64 * 1024);
        let handler = crate::files::FilesHandler::new();
        let offer = handler
            .begin_outgoing("stuck-buffer".into(), &path.to_string_lossy())
            .await
            .expect("begin_outgoing");
        let parked = Arc::new(tokio::sync::Notify::new());
        let sink = StuckBuffered {
            parked: parked.clone(),
        };
        let h = handler.clone();
        let pump = tokio::spawn(async move {
            pump_outgoing_file(&sink, &h, &offer, bson::oid::ObjectId::new()).await
        });
        tokio::time::timeout(Duration::from_secs(5), parked.notified())
            .await
            .expect("the pump reached the send buffer");
        assert!(handler.cancel_outgoing("stuck-buffer").await);
        let done = ends_within_2s(pump, "a cancel must end a download parked on the buffer").await;
        assert!(done.is_err(), "{done:?}");
    }

    #[tokio::test]
    async fn a_zip_download_parked_in_a_send_ends_with_its_stop() {
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(256 * 1024);
        writer
            .write_all(&[7u8; 128 * 1024])
            .await
            .expect("feed the pipe");
        let parked = Arc::new(tokio::sync::Notify::new());
        let stop = tokio_util::sync::CancellationToken::new();
        let pump = tokio::spawn(zip_pump_loop(
            StuckSend {
                parked: parked.clone(),
            },
            reader,
            stop.clone(),
            "zip".into(),
        ));
        tokio::time::timeout(Duration::from_secs(5), parked.notified())
            .await
            .expect("the zip pump reached its send");
        stop.cancel();
        let done = ends_within_2s(pump, "the zip pump must end with its stop").await;
        assert!(done.is_err(), "{done:?}");
        drop(writer);
    }

    /// The positive control: a healthy channel gets the whole file, byte for
    /// byte, so the races above never cut a download that is not stopped.
    #[tokio::test]
    async fn a_download_to_a_healthy_channel_sends_the_whole_file() {
        let (_dir, path) = a_file(300 * 1024 + 7);
        let handler = crate::files::FilesHandler::new();
        let offer = handler
            .begin_outgoing("whole".into(), &path.to_string_lossy())
            .await
            .expect("begin_outgoing");
        let got = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Collect { bytes: got.clone() };
        let sent = pump_outgoing_file(&sink, &handler, &offer, bson::oid::ObjectId::new())
            .await
            .expect("the download completes");
        let want = std::fs::read(&path).expect("read the file back");
        assert_eq!(sent, want.len() as u64);
        assert!(*got.lock().unwrap() == want, "the bytes arrived intact");
    }
}

#[cfg(test)]
mod stopped_at_screen_tests {
    use super::*;
    use crate::rc_sessions::RcSessionRegistry;
    use bson::oid::ObjectId;

    fn listed(reg: &RcSessionRegistry, session: ObjectId, kill: crate::rc_sessions::KillSender) {
        reg.insert(
            session,
            "viewer".into(),
            "view|input".into(),
            "org".into(),
            kill,
        );
    }

    /// FR-93 P6c — a pump whose capture the person at the screen stopped ends
    /// its session through the registry, on the kill channel their Disconnect
    /// takes, asks once, and never returns: nothing reopens the capture.
    #[tokio::test(start_paused = true)]
    async fn a_stop_at_the_screen_ends_the_session_once_and_never_returns() {
        let reg = RcSessionRegistry::new();
        let sid = ObjectId::new();
        let (kill, mut killed) = tokio::sync::mpsc::channel(4);
        listed(&reg, sid, kill);
        let held = tokio::time::timeout(
            Duration::from_secs(30),
            end_stopped_at_screen(sid, &reg, None),
        )
        .await;
        assert!(
            held.is_err(),
            "it held until the teardown, which here never comes"
        );
        assert_eq!(
            killed.try_recv().ok(),
            Some(sid),
            "the session's Disconnect"
        );
        assert!(killed.try_recv().is_err(), "asked once, not every second");
    }

    /// P6c — a session not listed yet (its banner entry comes once the peer is
    /// up) is asked again every second until it is.
    #[tokio::test(start_paused = true)]
    async fn a_session_not_listed_yet_is_asked_again_until_it_is() {
        let reg = RcSessionRegistry::new();
        let sid = ObjectId::new();
        let (kill, mut killed) = tokio::sync::mpsc::channel(4);
        let pump = tokio::spawn({
            let reg = reg.clone();
            async move { end_stopped_at_screen(sid, &reg, None).await }
        });
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(killed.try_recv().is_err(), "nothing to end yet");
        listed(&reg, sid, kill);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(killed.try_recv().ok(), Some(sid));
        pump.abort();
    }

    /// P6c — an owner ends its followers' sessions first, and its own only once
    /// they have left: gone first, it would close the pipeline, and a follower
    /// re-dispatching would reopen the capture the person had just stopped.
    // The pipeline registry's test guard is held across awaits on purpose, as
    // in `media_share`'s own tests: it serializes whole tests.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(start_paused = true)]
    async fn an_owner_ends_its_followers_before_itself() {
        let _serial = crate::media_share::test_serial();
        let key = crate::media_share::PipelineKey::FfmpegDc("TEST-P6C-OWNER");
        let (owner, follower) = (ObjectId::new(), ObjectId::new());
        let pipeline = crate::media_share::Pipeline::register(key, owner);
        let sink = crate::media_share::FollowerSink {
            session_id: follower,
            video_bytes_dc: Arc::new(tokio::sync::Mutex::new(None)),
            control_dc: Arc::new(tokio::sync::Mutex::new(None)),
            keyframe_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            target_resolution: Arc::new(std::sync::Mutex::new(TargetResolution::Native)),
            quality_state: Arc::new(std::sync::atomic::AtomicU8::new(2)),
            viewer_report: Arc::new(crate::encode::viewer_rate::ViewerFeedback::new()),
            priority: Arc::new(std::sync::atomic::AtomicU8::new(1)),
            capture_native_dims: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            encoded_dims: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            chunk_framing: false,
        };
        let guard = crate::media_share::try_join(key, sink, 60).expect("the follower joins");
        let reg = RcSessionRegistry::new();
        let (kill, mut killed) = tokio::sync::mpsc::channel(8);
        listed(&reg, owner, kill.clone());
        listed(&reg, follower, kill);
        tokio::select! {
            _ = end_stopped_at_screen(owner, &reg, Some(&pipeline)) => unreachable!("it never returns"),
            () = async {
                assert_eq!(killed.recv().await, Some(follower), "the follower first");
                tokio::time::sleep(Duration::from_millis(500)).await;
                assert!(killed.try_recv().is_err(), "the owner waits while its follower is still on");
                // The follower's own teardown aborts its task, which drops its guard.
                drop(guard);
                assert_eq!(killed.recv().await, Some(owner), "then the owner");
            } => {}
        }
    }
}
