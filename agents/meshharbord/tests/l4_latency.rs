// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-16 L0 — capture → decode latency of a REAL remote-desktop session, in
//! CI, on one clock.
//!
//! The agent side is the production `AgentPeer` with the production media
//! pump, on the synthetic frame source and openh264. The controller side is a
//! plain webrtc-rs peer that receives the RTP track, reassembles access units
//! itself (webrtc-rs' `SampleBuilder` holds a frame until the NEXT packet
//! arrives, which would add a whole frame interval to every reading), decodes
//! them with openh264 and reads the synthetic source's marker back out of the
//! decoded luma. The capture instant of that sequence number is in
//! `synthetic_backend::clock`, in this same process: latency is
//! `decode_done − captured`, no clock offset anywhere.
//!
//! Both peers sit on a webrtc-util `vnet`, so delay, jitter and loss are set
//! per cell and deterministic. The cells and what each must show:
//!
//! | Cell | Link | Must show |
//! |---|---|---|
//! | `clean` | no delay | frames flow at ≥ 0.75× the source rate, p50 under a generous debug-build bound |
//! | `delay100` | +100 ms one way | p50 rises by ≥ 80 ms: the metric sees the network |
//! | `gate50` | a planted 50 ms capture-stage hold | p50 rises by ≥ 20 ms: the metric sees the pipeline. This is the negative control a gate needs; a harness that cannot be made to fail is not one |
//! | `lossy` | +20 ms, 3 % of media packets dropped | the session survives and keeps decoding; its numbers are reported |
//! | `probe` | no delay, L4 probes on | a probe sent on the `input` channel comes back painted into decoded frames |
//! | `probe50` | +50 ms one way, L4 probes on | the probe round trip rises by ≥ 80 ms: it crosses the link in both directions |
//! | `gate_lgcy` / `gate_slot` | an emulated 25 fps event-driven source behind each capture gate (FR-98 C1) | the slot-first gate's p50 is lower by ≥ a quarter period: the clock starts when a frame lands in the slot, so a frame the legacy gate holds there counts its wait |
//! | `playout0` | no delay; the agent's `playout-delay` 0/0 switch left unset, which is on by default (FR-98 C6) | the extension is negotiated and on every video packet at 0/0, without costing frames. In every other cell (the switch forced off) the answer does not negotiate it at all, though the controller offers it as Chrome does |
//! | `replay` | no delay; the transport as the daemon reads it (FR-101 P1a) | the controller's first SRTCP PLI, replayed into the live session a moment after a keyframe the agent cut on its own, cuts no keyframe: the replay window refuses it. In this cell and every other but `legacy`, the agent's ClientHello offers exactly the two ECDHE-AES-128-GCM suites |
//! | `legacy` | no delay; both FR-101 switches back (`MESHHARBORD_DTLS_LEGACY_SUITES=1`, `MESHHARBORD_SRTP_REPLAY_WINDOW=0`), which is every session before P1a | the DTLS half's negative control: the ClientHello offers the CBC suites again. A replay is refused here too. With no window set, webrtc-srtp's session supplies its own 64, so replay protection was never off, before FR-101 or after |
//! | `unguarded` | no delay; replay protection switched off outright through the setting engine, which no production setting does | the replay half's negative control: each replay cuts a keyframe, so a refusal in the other cells is the window's doing, not a blind instrument |
//! | `cadence` | no delay; the synthetic source's frames in bursts and pauses (gaps of 33, 33 and 200 ms, repeated), as damage-driven frames come (#2284) | each frame's RTP timestamp steps the way its arrival does, within p50 10 ms and p95 40 ms. A timestamp that lags one frame misses every change in the gaps by the whole change. Every cell prints the same error; at a fixed rate it is near zero either way. Its pauses count as freezes, which this cell does not assert on |
//!
//! The FR-101 cells read the wire itself. A tap on the link parses the DTLS
//! hellos out of the cleartext handshake records, and keeps the
//! controller's first SRTCP PLI exactly as it crossed, to deliver it to the
//! agent again later. The agent answers the offer, so it is the DTLS client,
//! as it is against a browser: its ClientHello is the one a browser sees.
//!
//! The two `probe` cells are L4 in process. A bench viewer sends
//! `{"t":"probe","seq":N}` on the input DataChannel; the synthetic source
//! paints the last probe it saw into a second marker, bottom-right; the
//! viewer times send → the first decoded frame carrying `N`. That is input
//! to photon through the real agent, minus the host's own input stack and
//! the viewer's display, which the field half of L4 covers.
//!
//! Absolute numbers here are from an unoptimised build on a CI runner. The
//! field numbers come from L4 in the real viewer; this file is the gate that
//! catches a regression in the pipeline, and proves it can.

#![cfg(all(feature = "openh264-encoder", feature = "synthetic-frame-source"))]

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use meshharbor_remote_control::permissions::Permissions;
use meshharbor_remote_control::signaling::ClientMsg;
use meshharbord::capture::gate::GateMode;
use meshharbord::capture::synthetic_backend::{self, clock, marker};
use meshharbord::encode::EncoderPreference;
use meshharbord::peer::{AgentPeer, l0};
use meshharbord::rc_overlay::RcOverlay;
use meshharbord::rc_transport::{self, Policy};
use tokio::sync::{Mutex, mpsc};
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::dtls::cipher_suite::CipherSuiteId;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use webrtc::rtp::codecs::h264::H264Packet;
use webrtc::rtp::packetizer::Depacketizer;
use webrtc::rtp_transceiver::RTCRtpTransceiverInit;
use webrtc::rtp_transceiver::rtp_codec::RTPCodecType;
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::util::vnet::chunk::Chunk;
use webrtc::util::vnet::net::{Net, NetConfig};
use webrtc::util::vnet::router::{Router, RouterConfig};

const AGENT_IP: &str = "1.2.3.4";
const CONTROLLER_IP: &str = "1.2.3.5";

/// The software track pump's frame rate (`peer.rs` `TARGET_FPS_SW`).
const SOURCE_FPS: f64 = 30.0;

/// How long a cell streams, and how much of the start it ignores (ICE,
/// DTLS, the first IDR, the encoder's opening ramp).
const RUN: Duration = Duration::from_secs(8);
const WARMUP: Duration = Duration::from_millis(1_500);

/// A gap between two decoded frames longer than this is a freeze (FR-16).
const FREEZE: Duration = Duration::from_millis(200);

/// How often a probe cell sends a probe: at least three frame intervals
/// apart, so every probe gets a frame of its own, plus a jitter of up to one
/// frame interval. Without the jitter a 100 ms period is exactly three
/// frames, every probe lands on the same phase of the capture clock, and a
/// cell reports one arbitrary point of the wait for the next capture
/// (anywhere in 0–33 ms) instead of its distribution: two cells then differ
/// by up to a frame interval for no reason at all.
const PROBE_EVERY: Duration = Duration::from_millis(100);
const PROBE_JITTER_MS: u64 = 34;

/// The clean cell must decode at least this share of the source rate. Not
/// 0.9: an unoptimised build on a busy machine measured 20 fps (a parallel
/// repo-wide grep on the same box), and a gate that flakes under load gets
/// ignored. A real cadence regression (half the rate) still fails it.
const CLEAN_FPS_FLOOR: f64 = 0.75;

/// FR-101 P1a's replay cells. Each keyframe past the warm-up triggers one
/// replay, `REPLAY_AFTER_IDR` after it, and a keyframe within `REPLAY_ANSWER`
/// of the replay is the agent obeying it. Nothing else cuts one in that
/// window: the encoder's own period is about two seconds at any rate (60 frames
/// at 30 fps, 120 at the software tier's 60, FR-112 P2b: a period left at 60
/// frames put a keyframe every second inside this window, which is how this
/// cell caught it), and a clean link never makes the controller ask.
///
/// Where replays are refused, only that period triggers them: three in a
/// run at 30 fps, two at the clean cell's fps floor. Where they are obeyed,
/// each answer triggers the next. `REPLAY_AFTER_IDR` is longer than the
/// agent's one honoured PLI per 500 ms (`peer.rs` `MIN_KEYFRAME_GAP`), so
/// every replay in that chain can be answered. A first cut that waited for
/// the encoder's period instead (an obeyed replay restarts it) fit only two
/// replays in the run on the CI runner: exactly the assertion's floor.
const REPLAY_AFTER_IDR: Duration = Duration::from_millis(600);
const REPLAY_ANSWER: Duration = Duration::from_millis(500);

/// One link condition.
#[derive(Clone, Copy, Debug)]
struct Cell {
    name: &'static str,
    delay: Duration,
    jitter: Duration,
    /// Per-mille of agent→controller packets dropped.
    loss_permille: u32,
    /// The synthetic source's planted capture-stage hold.
    gate: Duration,
    /// L4 in process: send bench probes on an `input` DataChannel and time
    /// each one to the first decoded frame that carries it.
    probe: bool,
    /// FR-98 C1: the synthetic source emulates an event-driven source
    /// behind this capture gate, and the clock starts when a frame lands.
    compositor: Option<synthetic_backend::TestCompositor>,
    /// FR-98 C6: force the agent's `playout-delay` 0/0 switch for this
    /// session. Every cell forces it off but `playout0`, which leaves it
    /// unset (`None` reads the environment, whose default is on), so the
    /// other cells keep the path an off switch gives byte-identical.
    playout_zero: Option<bool>,
    /// FR-101 P1a: force the agent's transport policy (`None` reads the
    /// environment: the hardened default here).
    transport: Option<Policy>,
    /// FR-101 P1a: replay the controller's first SRTCP PLI into the agent,
    /// a moment after each keyframe past the warm-up.
    replay_pli: bool,
    /// Switch the session's SRTP and SRTCP replay protection off outright,
    /// through the setting engine: the replay half's negative control. No
    /// production setting does this, and none ever did. It takes effect
    /// only where the policy sets no window (`transport` with 0).
    replay_off: bool,
    /// #2284: the synthetic source's frames come on this repeating pattern
    /// of gaps instead of at a fixed rate, the way damage-driven frames do.
    cadence: Option<&'static [Duration]>,
}

/// #2284: the `cadence` cell's frames, three at a time and then a pause.
/// Every change between 33 and 200 ms is a step a lagging timestamp misses.
const CADENCE: [Duration; 3] = [
    Duration::from_millis(33),
    Duration::from_millis(33),
    Duration::from_millis(200),
];

/// What the controller saw of the `playout-delay` extension.
#[derive(Debug, Default, Clone, Copy)]
struct PlayoutSeen {
    /// The answer negotiated the extension at all.
    negotiated: bool,
    /// Packets carrying min = max = 0.
    zero: u64,
    /// Packets carrying any other value.
    other: u64,
    /// Packets without it, on a session that negotiated it.
    without: u64,
}

/// One ClientHello, as it crossed the link.
#[derive(Debug, Clone)]
struct Hello {
    from: IpAddr,
    version: u16,
    suites: Vec<u16>,
    /// The SRTP protection profiles its `use_srtp` extension offers.
    srtp: Vec<u16>,
}

/// What the DTLS handshake offered and chose, read off the wire.
#[derive(Debug, Default, Clone)]
struct DtlsSeen {
    /// Every ClientHello: the first, and the one that returns the server's
    /// cookie.
    client_hellos: Vec<Hello>,
    /// The suite the ServerHello chose.
    chose: Option<u16>,
}

impl DtlsSeen {
    fn summary(&self) -> String {
        let hex = |v: &[u16]| {
            v.iter()
                .map(|x| format!("{x:04x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        match self.client_hellos.first() {
            Some(h) => format!(
                "DTLS {:04x} offers [{}] srtp [{}], chose {}",
                h.version,
                hex(&h.suites),
                hex(&h.srtp),
                self.chose
                    .map_or_else(|| "-".to_owned(), |s| format!("{s:04x}"))
            ),
            None => "no ClientHello seen".to_owned(),
        }
    }
}

/// The tap on the link (FR-101 P1a): the DTLS hellos, and the controller's
/// first SRTCP PLI exactly as it crossed, kept to be delivered again.
#[derive(Default)]
struct Wire {
    dtls: std::sync::Mutex<DtlsSeen>,
    pli: std::sync::Mutex<Option<Box<dyn Chunk + Send + Sync>>>,
}

impl Wire {
    fn observe(&self, c: &(dyn Chunk + Send + Sync), controller: IpAddr) {
        // Both in: stop copying payloads, every video packet passes here.
        if self.dtls.lock().unwrap().chose.is_some() && self.pli.lock().unwrap().is_some() {
            return;
        }
        let data = c.user_data();
        match data.first() {
            // RFC 7983: a first byte in 20..=63 is DTLS.
            Some(20..=63) => {
                for (kind, body) in dtls_wire::handshakes(&data) {
                    let mut seen = self.dtls.lock().unwrap();
                    match kind {
                        dtls_wire::CLIENT_HELLO => {
                            if let Some((version, suites, srtp)) = dtls_wire::client_hello(body) {
                                seen.client_hellos.push(Hello {
                                    from: c.get_source_ip(),
                                    version,
                                    suites,
                                    srtp,
                                });
                            }
                        }
                        dtls_wire::SERVER_HELLO => {
                            seen.chose = seen.chose.or(dtls_wire::server_hello_suite(body));
                        }
                        _ => {}
                    }
                }
            }
            // SRTCP keeps the first 8 bytes in the clear: V=2 with FMT 1,
            // then PT 206, is a picture-loss indication.
            Some(0x81) if data.get(1) == Some(&206) && c.get_source_ip() == controller => {
                let mut pli = self.pli.lock().unwrap();
                if pli.is_none() {
                    *pli = Some(c.clone_to());
                }
            }
            _ => {}
        }
    }

    /// A copy of the captured PLI, to deliver again.
    fn pli(&self) -> Option<Box<dyn Chunk + Send + Sync>> {
        self.pli.lock().unwrap().as_ref().map(|c| c.clone_to())
    }
}

/// The DTLS 1.2 hellos, parsed out of a datagram. Only what travels in the
/// clear: handshake records in epoch 0 (RFC 6347 §4.1, §4.2.2).
mod dtls_wire {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    const HANDSHAKE: u8 = 22;
    /// RFC 5764 §4.1.1.
    const USE_SRTP: u16 = 14;

    struct Reader<'a>(&'a [u8]);

    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            Some(head)
        }
        fn u8(&mut self) -> Option<u8> {
            self.take(1).map(|b| b[0])
        }
        fn u16(&mut self) -> Option<u16> {
            self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
        }
        fn u24(&mut self) -> Option<usize> {
            self.take(3)
                .map(|b| (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
        }
        fn vec8(&mut self) -> Option<&'a [u8]> {
            let n = self.u8()?;
            self.take(n.into())
        }
        fn vec16(&mut self) -> Option<&'a [u8]> {
            let n = self.u16()?;
            self.take(n.into())
        }
    }

    fn u16s(b: &[u8]) -> Vec<u16> {
        b.chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    /// The whole handshake messages in one datagram, as (type, body). A
    /// fragment of a larger message is skipped: a hello fits in one record.
    pub fn handshakes(datagram: &[u8]) -> Vec<(u8, &[u8])> {
        let mut out = Vec::new();
        let mut r = Reader(datagram);
        // Record: type, version, epoch, 48-bit sequence, length.
        while let (Some(kind), Some(_), Some(epoch), Some(_)) =
            (r.u8(), r.u16(), r.u16(), r.take(6))
        {
            let Some(fragment) = r.vec16() else { break };
            if kind != HANDSHAKE || epoch != 0 {
                continue;
            }
            let mut h = Reader(fragment);
            // Message: type, length, message_seq, fragment offset and length.
            while let (Some(msg), Some(len), Some(_), Some(offset), Some(frag_len)) =
                (h.u8(), h.u24(), h.u16(), h.u24(), h.u24())
            {
                let Some(body) = h.take(frag_len) else { break };
                if offset == 0 && frag_len == len {
                    out.push((msg, body));
                }
            }
        }
        out
    }

    /// What a ClientHello offers: its version, cipher suites and SRTP
    /// protection profiles.
    pub fn client_hello(body: &[u8]) -> Option<(u16, Vec<u16>, Vec<u16>)> {
        let mut r = Reader(body);
        let version = r.u16()?;
        r.take(32)?; // random
        r.vec8()?; // session id
        r.vec8()?; // cookie, DTLS only
        let suites = u16s(r.vec16()?);
        r.vec8()?; // compression methods
        let mut srtp = Vec::new();
        let mut exts = Reader(r.vec16().unwrap_or_default());
        while let (Some(kind), Some(data)) = (exts.u16(), exts.vec16()) {
            if kind == USE_SRTP {
                srtp = Reader(data).vec16().map(u16s).unwrap_or_default();
            }
        }
        Some((version, suites, srtp))
    }

    /// The cipher suite a ServerHello chose.
    pub fn server_hello_suite(body: &[u8]) -> Option<u16> {
        let mut r = Reader(body);
        r.u16()?; // version
        r.take(32)?; // random
        r.vec8()?; // session id
        r.u16()
    }
}

/// What one cell measured.
#[derive(Debug, Default)]
struct Run {
    latencies_ms: Vec<f64>,
    /// Probe round trips: send → the first decoded frame carrying it.
    probe_ms: Vec<f64>,
    decoded: usize,
    freezes: usize,
    idr: usize,
    window: Duration,
    playout: PlayoutSeen,
    dtls: DtlsSeen,
    /// Replayed PLIs, and how many of them a keyframe answered.
    replays: usize,
    replays_answered: usize,
    /// #2284: per step from one frame to the next, how far the RTP clock's
    /// step strayed from the arrival step, in ms.
    step_err_ms: Vec<f64>,
}

/// The `p`-quantile of `samples`, NaN when empty.
fn quantile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return f64::NAN;
    }
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() - 1) as f64 * p).round() as usize;
    v[i]
}

impl Run {
    fn pct(&self, p: f64) -> f64 {
        quantile(&self.latencies_ms, p)
    }

    fn probe_pct(&self, p: f64) -> f64 {
        quantile(&self.probe_ms, p)
    }

    fn fps(&self) -> f64 {
        self.decoded as f64 / self.window.as_secs_f64().max(0.001)
    }

    fn line(&self, cell: &Cell) -> String {
        let probe = if cell.probe {
            format!(
                " | L4 probes={} p50={:.1}ms p95={:.1}ms",
                self.probe_ms.len(),
                self.probe_pct(0.50),
                self.probe_pct(0.95)
            )
        } else {
            String::new()
        };
        format!(
            "L0 {:<9} decoded={:>3} fps={:>5.1} p50={:>6.1}ms p95={:>6.1}ms max={:>6.1}ms freezes={} idr={}{probe} | ts-step err p50={:.1}ms p95={:.1}ms",
            cell.name,
            self.decoded,
            self.fps(),
            self.pct(0.50),
            self.pct(0.95),
            self.pct(1.0),
            self.freezes,
            self.idr,
            quantile(&self.step_err_ms, 0.50),
            quantile(&self.step_err_ms, 0.95)
        )
    }
}

/// Reassembles access units from RTP by sequence number, and releases one
/// the moment its marker packet completes it: no waiting for the next
/// frame's first packet. A frame whose packets never all arrive is skipped
/// once frames behind it are complete, and the caller asks for a keyframe.
#[derive(Default)]
struct Assembler {
    /// Unwrapped sequence → (timestamp, marker, payload).
    pkts: BTreeMap<u64, (u32, bool, Bytes)>,
    next: Option<u64>,
    /// The highest sequence seen, raw and unwrapped. A late packet is placed
    /// relative to it and never moves it.
    highest_raw: Option<u16>,
    highest: u64,
}

impl Assembler {
    fn unwrap_seq(&mut self, seq: u16) -> u64 {
        let Some(top) = self.highest_raw else {
            self.highest_raw = Some(seq);
            self.highest = seq as u64 + (1 << 16);
            return self.highest;
        };
        let delta = seq.wrapping_sub(top) as i16 as i64;
        let s = (self.highest as i64 + delta) as u64;
        if delta > 0 {
            self.highest_raw = Some(seq);
            self.highest = s;
        }
        s
    }

    /// Push one packet; return the access units it completed, each with its
    /// RTP timestamp, and whether a frame had to be skipped.
    fn push(
        &mut self,
        seq: u16,
        ts: u32,
        marker: bool,
        payload: Bytes,
    ) -> (Vec<(u32, Vec<u8>)>, bool) {
        let s = self.unwrap_seq(seq);
        if self.next.is_some_and(|n| s < n) {
            return (Vec::new(), false); // a late retransmit of a frame already released or skipped
        }
        self.pkts.insert(s, (ts, marker, payload));
        let mut out = Vec::new();
        let mut skipped = false;
        while let Some(start) = self.next.or_else(|| self.pkts.keys().next().copied()) {
            match self.complete_from(start) {
                Some((end, au_ts, au)) => {
                    self.pkts.retain(|&k, _| k > end);
                    self.next = Some(end + 1);
                    out.push((au_ts, au));
                }
                None => {
                    // Skip a frame only when a LATER frame is already whole:
                    // its packets are not coming back.
                    let Some(later) = self.next_frame_start_after(start) else {
                        break;
                    };
                    if self.complete_from(later).is_none() {
                        break;
                    }
                    self.pkts.retain(|&k, _| k >= later);
                    self.next = Some(later);
                    skipped = true;
                }
            }
        }
        (out, skipped)
    }

    /// The packets `start..=marker` if all are present and share a timestamp.
    fn complete_from(&self, start: u64) -> Option<(u64, u32, Vec<u8>)> {
        let (ts0, _, _) = self.pkts.get(&start)?;
        // A fresh depacketizer per attempt: it buffers FU-A fragments, and an
        // attempt that stops at a missing packet must not leave half a NAL
        // behind for the next one.
        let mut depacketizer = H264Packet::default();
        let mut au = Vec::new();
        let mut s = start;
        loop {
            let (ts, marker, payload) = self.pkts.get(&s)?;
            if ts != ts0 {
                return None;
            }
            let part = depacketizer.depacketize(payload).ok()?;
            au.extend_from_slice(&part);
            if *marker {
                return Some((s, *ts0, au));
            }
            s += 1;
        }
    }

    /// The first held packet after `start` whose predecessor is a marker or
    /// carries another timestamp: where the next frame begins.
    fn next_frame_start_after(&self, start: u64) -> Option<u64> {
        let ts0 = self.pkts.get(&start).map(|p| p.0);
        self.pkts
            .range(start + 1..)
            .find(|(k, (ts, _, _))| {
                Some(*ts) != ts0
                    && self
                        .pkts
                        .get(&(*k - 1))
                        .is_none_or(|(pts, pmarker, _)| *pmarker || pts != ts)
            })
            .map(|(k, _)| *k)
    }
}

/// A picture-loss indication for `ssrc`: what a browser sends when it
/// cannot decode, and what makes the agent cut a keyframe.
fn pli(ssrc: u32) -> [Box<dyn webrtc::rtcp::packet::Packet + Send + Sync>; 1] {
    [Box::new(PictureLossIndication {
        sender_ssrc: 0,
        media_ssrc: ssrc,
    })]
}

/// Does this Annex-B access unit carry an IDR slice (NAL type 5)?
fn has_idr(au: &[u8]) -> bool {
    au.windows(4)
        .any(|w| w[0] == 0 && w[1] == 0 && w[2] == 1 && (w[3] & 0x1F) == 5)
        || au
            .windows(5)
            .any(|w| w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 1 && (w[4] & 0x1F) == 5)
}

/// A tiny deterministic generator for the loss filter, so a cell drops the
/// same packets on every run.
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

async fn vnet_pair(
    cell: &Cell,
    wire: &Arc<Wire>,
) -> Result<(Arc<Net>, Arc<Net>, Arc<Mutex<Router>>)> {
    let wan = Arc::new(Mutex::new(Router::new(RouterConfig {
        cidr: "1.2.3.0/24".to_owned(),
        min_delay: cell.delay,
        max_jitter: cell.jitter,
        ..Default::default()
    })?));
    // The tap first, so it sees a packet before a loss filter drops it.
    {
        let wire = Arc::clone(wire);
        let controller: IpAddr = CONTROLLER_IP.parse()?;
        wan.lock()
            .await
            .add_chunk_filter(Box::new(move |c: &(dyn Chunk + Send + Sync)| {
                wire.observe(c, controller);
                true
            }))
            .await;
    }
    if cell.loss_permille > 0 {
        let permille = cell.loss_permille as u64;
        let rng = std::sync::Mutex::new(XorShift(0x9E37_79B9_7F4A_7C15));
        let agent_ip: IpAddr = AGENT_IP.parse()?;
        wan.lock()
            .await
            .add_chunk_filter(Box::new(move |c: &(dyn Chunk + Send + Sync)| {
                // Media direction only: agent → controller.
                if c.get_source_ip() != agent_ip {
                    return true;
                }
                rng.lock().unwrap().next() % 1000 >= permille
            }))
            .await;
    }
    let mut nets = Vec::new();
    for ip in [AGENT_IP, CONTROLLER_IP] {
        let net = Arc::new(Net::new(Some(NetConfig {
            static_ips: vec![ip.to_owned()],
            ..Default::default()
        })));
        let nic = net.get_nic()?;
        wan.lock().await.add_net(Arc::clone(&nic)).await?;
        nic.lock().await.set_router(Arc::clone(&wan)).await?;
        nets.push(net);
    }
    wan.lock().await.start().await?;
    let controller = nets.pop().unwrap();
    let agent = nets.pop().unwrap();
    Ok((agent, controller, wan))
}

fn ice_timeouts(s: &mut SettingEngine) {
    s.set_ice_timeouts(
        Some(Duration::from_secs(5)),
        Some(Duration::from_secs(10)),
        Some(Duration::from_millis(200)),
    );
}

async fn controller_peer(net: Arc<Net>) -> Result<Arc<RTCPeerConnection>> {
    let mut engine = MediaEngine::default();
    engine.register_default_codecs()?;
    // Offer `playout-delay` the way Chrome does, so the agent's answer
    // decides whether it is negotiated (FR-98 C6).
    meshharbord::rtp_playout::register(&mut engine)?;
    // The browser's receive-side interceptors: NACK generation and receiver
    // reports, so loss behaves as it does against Chrome.
    let registry = register_default_interceptors(Registry::new(), &mut engine)?;
    let mut setting = SettingEngine::default();
    setting.set_vnet(Some(net));
    ice_timeouts(&mut setting);
    let api = APIBuilder::new()
        .with_media_engine(engine)
        .with_interceptor_registry(registry)
        .with_setting_engine(setting)
        .build();
    let pc = Arc::new(api.new_peer_connection(RTCConfiguration::default()).await?);
    pc.add_transceiver_from_kind(
        RTPCodecType::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            send_encodings: vec![],
        }),
    )
    .await?;
    Ok(pc)
}

/// Run one cell end to end and return what it measured.
async fn run_cell(cell: Cell) -> Result<Run> {
    synthetic_backend::set_test_gate(cell.gate);
    synthetic_backend::set_test_compositor(cell.compositor);
    synthetic_backend::set_test_cadence(cell.cadence);
    meshharbord::rtp_playout::set_test_override(cell.playout_zero);
    rc_transport::set_test_override(cell.transport);
    let wire = Arc::new(Wire::default());
    let (agent_net, controller_net, wan) = vnet_pair(&cell, &wire).await?;
    // The agent's end of the link, where a replayed packet is delivered.
    let agent_nic = agent_net.get_nic()?;
    let replay_off = cell.replay_off;
    l0::set_setting_engine_hook(Some(Arc::new(move |s: &mut SettingEngine| {
        s.set_vnet(Some(Arc::clone(&agent_net)));
        ice_timeouts(s);
        if replay_off {
            s.disable_srtp_replay_protection(true);
            s.disable_srtcp_replay_protection(true);
        }
    })));

    // A probe cell needs INPUT: the agent attaches its input handler, the
    // one place a probe is read, only for a session that holds it.
    let permissions = if cell.probe {
        Permissions::VIEW | Permissions::INPUT
    } else {
        Permissions::VIEW
    };
    let (tx, mut rx) = mpsc::channel::<ClientMsg>(1024);
    let agent = AgentPeer::new(
        bson::oid::ObjectId::new(),
        &[],
        tx,
        EncoderPreference::Software,
        "h264".into(),
        "h264".into(), // the RTP track's codec: on the RTP transport, the pump's
        None,          // the RTP track, as a browser without a DC cell gets
        None,
        false,
        false,
        permissions,
        "l0-harness".into(),
        None,
        RcOverlay::default(),
        meshharbord::rc_sessions::RcSessionRegistry::new(),
        // FR-102 P9d — the carrier-ready signal; the L4 harness does not read
        // it, so a throwaway sender is correct.
        mpsc::channel(1).0,
    )
    .await
    .context("AgentPeer::new")?;

    let pc = controller_peer(controller_net).await?;

    // L4: the channel a bench viewer sends its probes on, created before the
    // offer with the viewer's own reliability profile (unordered, no
    // retransmits: `useRemoteControl.ts`).
    let input_dc = if cell.probe {
        Some(
            pc.create_data_channel(
                "input",
                Some(RTCDataChannelInit {
                    ordered: Some(false),
                    max_retransmits: Some(0),
                    ..Default::default()
                }),
            )
            .await?,
        )
    } else {
        None
    };
    // Probe sequence → send instant, and (decode-done instant, round trip).
    let sent: Arc<std::sync::Mutex<HashMap<u16, Instant>>> = Arc::default();
    let probe_rtts: Arc<std::sync::Mutex<Vec<(Instant, Duration)>>> = Arc::default();

    // Decoded frames: (decode-done instant, latency).
    let results: Arc<std::sync::Mutex<Vec<(Instant, Duration)>>> = Arc::default();
    // When each IDR arrived.
    let idr_at: Arc<std::sync::Mutex<Vec<Instant>>> = Arc::default();
    let playout: Arc<std::sync::Mutex<PlayoutSeen>> = Arc::default();
    // #2284: each access unit's RTP timestamp and arrival instant.
    let steps: Arc<std::sync::Mutex<Vec<(u32, Instant)>>> = Arc::default();
    {
        let results = Arc::clone(&results);
        let idr_at = Arc::clone(&idr_at);
        let sent = Arc::clone(&sent);
        let probe_rtts = Arc::clone(&probe_rtts);
        let playout = Arc::clone(&playout);
        let steps = Arc::clone(&steps);
        let pc_weak = Arc::downgrade(&pc);
        pc.on_track(Box::new(move |track, _, _| {
            let results = Arc::clone(&results);
            let idr_at = Arc::clone(&idr_at);
            let sent = Arc::clone(&sent);
            let probe_rtts = Arc::clone(&probe_rtts);
            let playout = Arc::clone(&playout);
            let steps = Arc::clone(&steps);
            let pc_weak = pc_weak.clone();
            Box::pin(async move {
                let ssrc = track.ssrc();
                // FR-98 C6: the id the answer gave `playout-delay`, if any.
                let playout_id = track
                    .params()
                    .header_extensions
                    .iter()
                    .find(|e| e.uri == meshharbord::rtp_playout::URI)
                    .map(|e| e.id as u8);
                playout.lock().unwrap().negotiated = playout_id.is_some();
                tokio::spawn(async move {
                    let mut asm = Assembler::default();
                    let mut decoder = match openh264::decoder::Decoder::new() {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("L0: openh264 decoder: {e}");
                            return;
                        }
                    };
                    let mut last_pli = Instant::now() - Duration::from_secs(1);
                    let ask_keyframe = |last_pli: &mut Instant| {
                        if last_pli.elapsed() < Duration::from_millis(500) {
                            return None;
                        }
                        *last_pli = Instant::now();
                        pc_weak.upgrade()
                    };
                    // Ask for a keyframe at once: the first IDR may have been
                    // written before the track was bound.
                    if let Some(pc) = ask_keyframe(&mut last_pli) {
                        let _ = pc.write_rtcp(&pli(ssrc)).await;
                    }
                    while let Ok((pkt, _)) = track.read_rtp().await {
                        if let Some(id) = playout_id {
                            use webrtc::util::Unmarshal;
                            let mut seen = playout.lock().unwrap();
                            match pkt.header.get_extension(id) {
                                Some(mut raw) => {
                                    match webrtc::rtp::extension::playout_delay_extension::PlayoutDelayExtension::unmarshal(&mut raw) {
                                        Ok(p) if p.min_delay == 0 && p.max_delay == 0 => seen.zero += 1,
                                        _ => seen.other += 1,
                                    }
                                }
                                None => seen.without += 1,
                            }
                        }
                        let (aus, skipped) = asm.push(
                            pkt.header.sequence_number,
                            pkt.header.timestamp,
                            pkt.header.marker,
                            pkt.payload.clone(),
                        );
                        let mut want_keyframe = skipped;
                        for (au_ts, au) in aus {
                            // #2284: each frame's RTP time against when it
                            // arrived, the comparison a receiver's jitter
                            // estimate makes.
                            steps.lock().unwrap().push((au_ts, Instant::now()));
                            if has_idr(&au) {
                                idr_at.lock().unwrap().push(Instant::now());
                            }
                            let (seq, probe) = match decoder.decode(&au) {
                                Ok(Some(pic)) => {
                                    use openh264::formats::YUVSource;
                                    let (w, h) = pic.dimensions();
                                    let (w, h) = (w as u32, h as u32);
                                    let (ys, _, _) = pic.strides();
                                    let y = pic.y();
                                    (
                                        marker::decode_luma(y, w, h, ys),
                                        if cell.probe {
                                            marker::decode_luma_at(
                                                marker::Corner::BottomRight,
                                                y,
                                                w,
                                                h,
                                                ys,
                                            )
                                        } else {
                                            None
                                        },
                                    )
                                }
                                Ok(None) => (None, None),
                                Err(_) => {
                                    want_keyframe = true;
                                    (None, None)
                                }
                            };
                            let done = Instant::now();
                            if let Some(seq) = seq
                                && let Some(captured) = clock::captured_at(seq)
                                && captured <= done
                            {
                                results.lock().unwrap().push((done, done - captured));
                            }
                            // The FIRST frame carrying a probe ends its round
                            // trip; removing it keeps the frames after it,
                            // which carry it too, from counting again.
                            if let Some(p) = probe
                                && let Some(at) = sent.lock().unwrap().remove(&p)
                            {
                                probe_rtts.lock().unwrap().push((done, done - at));
                            }
                        }
                        if want_keyframe && let Some(pc) = ask_keyframe(&mut last_pli) {
                            let _ = pc.write_rtcp(&pli(ssrc)).await;
                        }
                    }
                });
            })
        }));
    }

    // Offer with every candidate in it (vnet gathers at once), then trickle
    // the agent's candidates the other way once the answer is applied.
    let offer = pc.create_offer(None).await?;
    let mut gathered = pc.gathering_complete_promise().await;
    pc.set_local_description(offer).await?;
    let _ = gathered.recv().await;
    let offer_sdp = pc
        .local_description()
        .await
        .ok_or_else(|| anyhow!("no local description"))?
        .sdp;
    let answer = agent
        .handle_offer(offer_sdp)
        .await
        .context("handle_offer")?;
    pc.set_remote_description(RTCSessionDescription::answer(answer)?)
        .await?;
    let ice_pc = Arc::clone(&pc);
    let trickle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let ClientMsg::Ice { candidate, .. } = msg
                && let Ok(init) = serde_json::from_value::<RTCIceCandidateInit>(candidate)
            {
                let _ = ice_pc.add_ice_candidate(init).await;
            }
        }
    });

    // L4: once the channel opens, a probe every PROBE_EVERY plus jitter,
    // each stamped just before it is sent.
    let prober = input_dc.map(|dc| {
        let sent = Arc::clone(&sent);
        let (open_tx, open_rx) = tokio::sync::oneshot::channel::<()>();
        dc.on_open(Box::new(move || {
            let _ = open_tx.send(());
            Box::pin(async {})
        }));
        tokio::spawn(async move {
            if open_rx.await.is_err() {
                return;
            }
            let mut rng = XorShift(0xD1B5_4A32_D192_ED03);
            loop {
                let jitter = Duration::from_millis(rng.next() % PROBE_JITTER_MS);
                tokio::time::sleep(PROBE_EVERY + jitter).await;
                let seq = next_probe_seq();
                sent.lock().unwrap().insert(seq, Instant::now());
                if dc
                    .send_text(format!(r#"{{"t":"probe","seq":{seq}}}"#))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    });

    // FR-101 P1a: deliver the controller's first PLI to the agent again,
    // exactly as it crossed the link, REPLAY_AFTER_IDR after each keyframe.
    // A replay accepted is a keyframe within REPLAY_ANSWER; a replay refused
    // is nothing at all.
    let injected: Arc<std::sync::Mutex<Vec<Instant>>> = Arc::default();
    let replayer = cell.replay_pli.then(|| {
        let wire = Arc::clone(&wire);
        let idr_at = Arc::clone(&idr_at);
        let results = Arc::clone(&results);
        let injected = Arc::clone(&injected);
        tokio::spawn(async move {
            let mut last: Option<Instant> = None;
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let Some(first) = results.lock().unwrap().first().map(|r| r.0) else {
                    continue;
                };
                let now = Instant::now();
                // A keyframe past the warm-up, newer than the last replay
                // (each keyframe triggers one), and long enough ago.
                let due = idr_at.lock().unwrap().iter().any(|&t| {
                    t >= first + WARMUP && last.is_none_or(|l| t > l) && t + REPLAY_AFTER_IDR <= now
                });
                if !due {
                    continue;
                }
                let Some(pli) = wire.pli() else { continue };
                agent_nic.lock().await.on_inbound_chunk(pli).await;
                let at = Instant::now();
                injected.lock().unwrap().push(at);
                last = Some(at);
            }
        })
    });

    tokio::time::sleep(RUN).await;

    if let Some(prober) = prober {
        prober.abort();
    }
    if let Some(replayer) = replayer {
        replayer.abort();
    }
    agent.close().await;
    let _ = pc.close().await;
    trickle.abort();
    l0::set_setting_engine_hook(None);
    synthetic_backend::set_test_gate(Duration::ZERO);
    synthetic_backend::set_test_compositor(None);
    synthetic_backend::set_test_cadence(None);
    meshharbord::rtp_playout::set_test_override(None);
    rc_transport::set_test_override(None);
    let _ = wan.lock().await.stop().await;

    let samples = results.lock().unwrap().clone();
    let Some(&(first, _)) = samples.first() else {
        return Err(anyhow!("cell {}: no frame was decoded at all", cell.name));
    };
    let from = first + WARMUP;
    let kept: Vec<_> = samples.iter().filter(|(t, _)| *t >= from).collect();
    let probe_ms = probe_rtts
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _)| *t >= from)
        .map(|(_, rtt)| rtt.as_secs_f64() * 1e3)
        .collect();
    let idrs = idr_at.lock().unwrap().clone();
    let injected = injected.lock().unwrap().clone();
    let mut run = Run {
        latencies_ms: kept.iter().map(|(_, l)| l.as_secs_f64() * 1e3).collect(),
        probe_ms,
        decoded: kept.len(),
        idr: idrs.len(),
        playout: *playout.lock().unwrap(),
        dtls: wire.dtls.lock().unwrap().clone(),
        replays: injected.len(),
        replays_answered: injected
            .iter()
            .filter(|&&i| idrs.iter().any(|&t| t > i && t <= i + REPLAY_ANSWER))
            .count(),
        ..Default::default()
    };
    if let (Some(a), Some(b)) = (kept.first(), kept.last()) {
        run.window = b.0 - a.0;
    }
    run.freezes = kept.windows(2).filter(|w| w[1].0 - w[0].0 > FREEZE).count();
    run.step_err_ms = step_errors(&steps.lock().unwrap(), from);
    Ok(run)
}

/// #2284: for each step from one access unit to the next (both past `from`),
/// how far the RTP clock's step (90 kHz) strays from the arrival step, in ms.
/// A sender that stamps each frame with its own time keeps this near zero; one
/// that stamps it with the previous frame's time is off by every change in
/// the gaps between frames.
fn step_errors(steps: &[(u32, Instant)], from: Instant) -> Vec<f64> {
    let kept: Vec<_> = steps.iter().filter(|(_, at)| *at >= from).collect();
    kept.windows(2)
        .map(|w| {
            let rtp_ms = w[1].0.wrapping_sub(w[0].0) as f64 / 90.0;
            let arrival_ms = (w[1].1 - w[0].1).as_secs_f64() * 1e3;
            (rtp_ms - arrival_ms).abs()
        })
        .collect()
}

const fn cell(name: &'static str, delay_ms: u64, loss_permille: u32, gate_ms: u64) -> Cell {
    Cell {
        name,
        delay: Duration::from_millis(delay_ms),
        jitter: Duration::ZERO,
        loss_permille,
        gate: Duration::from_millis(gate_ms),
        probe: false,
        compositor: None,
        playout_zero: Some(false),
        transport: None,
        replay_pli: false,
        replay_off: false,
        cadence: None,
    }
}

/// FR-98 C1's cells: a 25 fps source behind a 25 fps gate. A whole number of
/// milliseconds per period (40), so the legacy gate's arithmetic is exact
/// and only its sleeps drift, and frames land three quarters of a period
/// ahead of the cadence the legacy gate keeps.
const GATE_FPS: u32 = 25;

fn gate_cell(name: &'static str, gate: GateMode) -> Cell {
    Cell {
        compositor: Some(synthetic_backend::TestCompositor {
            source_fps: GATE_FPS,
            target_fps: GATE_FPS,
            lead: 0.75,
            gate,
        }),
        ..cell(name, 0, 0, 0)
    }
}

/// The next probe number. Process-wide, so no cell can match a probe the
/// previous cell left painted in the agent's bottom-right marker. Starts at
/// 1: an all-zero word is a black grid.
fn next_probe_seq() -> u16 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    (NEXT.fetch_add(1, Ordering::Relaxed) & 0x0FFF) as u16
}

#[test]
fn l0_capture_to_decode_latency_sees_the_network_and_the_pipeline() {
    // SAFETY: the only test in this binary, and no thread of ours exists yet:
    // the runtime is built below. These are read when a session opens.
    // `test_env::set` clears every other spelling of each suffix first, so an
    // inherited value under a retired prefix cannot decide the run.
    unsafe {
        tunnel_core::env::test_env::set("SYNTHETIC_FRAMES", "1");
        tunnel_core::env::test_env::set("BENCH", "1");
        tunnel_core::env::test_env::set("ENCODER", "software");
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");

    let clean = cell("clean", 0, 0, 0);
    let delay100 = cell("delay100", 100, 0, 0);
    let gate50 = cell("gate50", 0, 0, 50);
    let lossy = Cell {
        jitter: Duration::from_millis(5),
        ..cell("lossy", 20, 30, 0)
    };
    let probe_clean = Cell {
        probe: true,
        ..cell("probe", 0, 0, 0)
    };
    let probe_delay50 = Cell {
        probe: true,
        ..cell("probe50", 50, 0, 0)
    };

    let gate_legacy = gate_cell("gate_lgcy", GateMode::Legacy);
    let gate_slot = gate_cell("gate_slot", GateMode::SlotFirst);

    // FR-98 C6: the switch unset, so this cell is the default, which is on.
    let playout0 = Cell {
        playout_zero: None,
        ..cell("playout0", 0, 0, 0)
    };
    // FR-101 P1a: the transport as the daemon reads it, both of its switches
    // back, and replay protection switched off outright.
    let replay = Cell {
        replay_pli: true,
        ..cell("replay", 0, 0, 0)
    };
    let unhardened = Cell {
        replay_pli: true,
        transport: Some(Policy {
            replay_window: 0,
            gcm_only: false,
        }),
        ..cell("legacy", 0, 0, 0)
    };
    let unguarded = Cell {
        replay_pli: true,
        replay_off: true,
        transport: Some(Policy {
            replay_window: 0,
            gcm_only: true,
        }),
        ..cell("unguarded", 0, 0, 0)
    };
    // #2284: damage-driven frames, in bursts and pauses.
    let cadence = Cell {
        cadence: Some(&CADENCE),
        ..cell("cadence", 0, 0, 0)
    };

    let cells = [
        clean,
        delay100,
        gate50,
        lossy,
        probe_clean,
        probe_delay50,
        gate_legacy,
        gate_slot,
        playout0,
        replay,
        unhardened,
        unguarded,
        cadence,
    ];
    let mut runs = Vec::new();
    for c in cells {
        let run = rt.block_on(run_cell(c)).unwrap_or_else(|e| panic!("{e:#}"));
        let replays = if c.replay_pli {
            format!(
                " | replays {}/{} answered | {}",
                run.replays_answered,
                run.replays,
                run.dtls.summary()
            )
        } else {
            String::new()
        };
        println!("{} | playout {:?}{replays}", run.line(&c), run.playout);
        runs.push(run);
    }

    // FR-101 P1a, the DTLS half: in every cell but `legacy` the agent's
    // ClientHello offers exactly the two ECDHE-AES-128-GCM suites, and the
    // handshake settles on one of them. Read off the wire, so a reordered
    // engine setup or a webrtc upgrade that drops the setting fails here.
    let gcm: Vec<u16> = rc_transport::GCM_SUITES.iter().map(|&s| s as u16).collect();
    let agent_ip: IpAddr = AGENT_IP.parse().unwrap();
    for (c, run) in cells.iter().zip(&runs) {
        if !c.transport.unwrap_or_default().gcm_only {
            continue;
        }
        let d = &run.dtls;
        assert!(
            !d.client_hellos.is_empty(),
            "{}: the tap saw no ClientHello: {}",
            c.name,
            d.summary()
        );
        for h in &d.client_hellos {
            assert!(
                h.from == agent_ip && h.suites == gcm && !h.srtp.is_empty(),
                "{}: want the agent's ClientHello offering exactly {gcm:04x?} with use_srtp, saw {h:04x?}",
                c.name
            );
        }
        assert!(
            d.chose.is_some_and(|s| gcm.contains(&s)),
            "{}: the handshake settled on {:04x?}",
            c.name,
            d.chose
        );
    }

    let [
        clean_run,
        delay_run,
        gate_run,
        lossy_run,
        probe_run,
        probe50_run,
        legacy_run,
        slot_run,
        playout_run,
        replay_run,
        unhardened_run,
        unguarded_run,
        cadence_run,
    ] = <[Run; 13]>::try_from(runs).unwrap();

    // #2284: on frames that come in bursts and pauses, each frame's RTP time
    // steps the way its arrival does. A sender that stamps a frame with the
    // previous frame's time misses every change between 33 and 200 ms by the
    // whole change, which is what a receiver's jitter estimate reads as
    // network jitter. Enough steps that a pass is not an empty one.
    let errs = &cadence_run.step_err_ms;
    let (e50, e95) = (quantile(errs, 0.50), quantile(errs, 0.95));
    assert!(
        errs.len() >= 20 && e50 <= 10.0 && e95 <= 40.0,
        "cadence: over {} frame steps the RTP clock strayed from the arrivals by p50 \
         {e50:.1} ms, p95 {e95:.1} ms (want ≥ 20 steps, ≤ 10 ms and ≤ 40 ms): a frame stamped \
         with the previous frame's time is off by every change in the gaps",
        errs.len()
    );

    // FR-101 P1a, the SRTCP half (AC2). With replay protection switched off
    // outright, the agent obeys a replayed PLI and cuts a keyframe each time:
    // the instrument sees a replay accepted, so it can see one refused.
    assert!(
        unguarded_run.replays >= 2 && unguarded_run.replays_answered >= 2,
        "unguarded: {} of {} replayed PLIs cut a keyframe, want ≥ 2 of ≥ 2: a replay that \
         is accepted does not show, so a refused one proves nothing",
        unguarded_run.replays_answered,
        unguarded_run.replays
    );
    // The daemon's transport refuses it. So does the one every session had
    // before P1a: with no window set, webrtc-srtp's session supplies 64 of
    // its own (`Session::new`). FR-101's P0 evidence read the fallback in
    // `Context::new`, which a session never reaches.
    for (run, name) in [(&replay_run, "replay"), (&unhardened_run, "legacy")] {
        assert!(
            run.replays >= 2,
            "{name}: only {} replays went out",
            run.replays
        );
        assert_eq!(
            run.replays_answered, 0,
            "{name}: {} of {} replayed PLIs cut a keyframe through the replay window",
            run.replays_answered, run.replays
        );
    }
    // The DTLS half's negative control: with the switch back, the CBC suites
    // are offered again, so what the tap reads is the wire.
    let cbc = [
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha as u16,
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha as u16,
    ];
    assert!(
        unhardened_run
            .dtls
            .client_hellos
            .iter()
            .any(|h| cbc.iter().all(|s| h.suites.contains(s))),
        "legacy: the ClientHello does not offer the CBC suites {cbc:04x?}: {}",
        unhardened_run.dtls.summary()
    );
    // Hardened or not, a session still flows.
    for (run, name) in [
        (&replay_run, "replay"),
        (&unhardened_run, "legacy"),
        (&unguarded_run, "unguarded"),
    ] {
        assert!(
            run.fps() >= SOURCE_FPS * CLEAN_FPS_FLOOR,
            "{name}: {:.1} fps decoded",
            run.fps()
        );
    }

    // FR-98 C6. Off (forced here; the default is on), the agent does not even
    // register the extension, so an answer to an offer that carries it
    // negotiates nothing and the session is byte-identical to before.
    assert!(
        !clean_run.playout.negotiated,
        "clean: the answer negotiated playout-delay with the switch off: {:?}",
        clean_run.playout
    );
    // Unset, which is on, it is negotiated and on every video packet, at 0/0.
    let p = playout_run.playout;
    assert!(
        p.negotiated && p.zero > 0 && p.other == 0 && p.without == 0,
        "playout0: want playout-delay 0/0 on every packet, saw {p:?}"
    );
    assert!(
        playout_run.fps() >= SOURCE_FPS * CLEAN_FPS_FLOOR,
        "playout0: {:.1} fps decoded: writing the extension must not cost frames",
        playout_run.fps()
    );

    // `clean`: frames flow at the source rate, through a real pipeline.
    assert!(
        clean_run.fps() >= SOURCE_FPS * CLEAN_FPS_FLOOR,
        "clean: {:.1} fps decoded, want ≥ {:.1}",
        clean_run.fps(),
        SOURCE_FPS * CLEAN_FPS_FLOOR
    );
    assert!(
        clean_run.pct(0.5) < 150.0,
        "clean: p50 {:.1} ms on a loopback link means the pipeline itself is stuck",
        clean_run.pct(0.5)
    );
    assert_eq!(
        clean_run.freezes, 0,
        "clean: a loopback link must not freeze"
    );

    // `delay100`: the metric sees the network.
    let d = delay_run.pct(0.5) - clean_run.pct(0.5);
    assert!(
        d >= 80.0,
        "delay100: p50 rose by {d:.1} ms, want ≥ 80: the metric does not see the link"
    );

    // `gate50`: the negative control. A planted 50 ms hold in the capture
    // stage must move the number, or this harness gates nothing.
    let g = gate_run.pct(0.5) - clean_run.pct(0.5);
    assert!(
        g >= 20.0,
        "gate50: p50 rose by {g:.1} ms, want ≥ 20: the metric does not see the pipeline"
    );

    // `lossy`: the session survives loss and keeps decoding.
    assert!(
        lossy_run.decoded > 0 && lossy_run.fps() >= SOURCE_FPS * 0.3,
        "lossy: {:.1} fps decoded — the session did not survive 3 % loss",
        lossy_run.fps()
    );

    // `probe`: L4 in process. A probe sent on the input channel comes back
    // painted into a decoded frame: the round trip exists end to end. About
    // 45 are measured after the warm-up; 20 is the floor.
    assert!(
        probe_run.probe_ms.len() >= 20,
        "probe: {} round trips measured, want ≥ 20 — probes are not reaching the \
         source, or not coming back in the picture",
        probe_run.probe_ms.len()
    );
    assert!(
        probe_run.probe_pct(0.5) < 200.0,
        "probe: p50 {:.1} ms on a loopback link",
        probe_run.probe_pct(0.5)
    );

    // `probe50`: 50 ms each way must cost the round trip about 100 ms. Only a
    // probe that really crosses the link in BOTH directions moves by more
    // than the one-way 50, so this is what proves the instrument measures a
    // round trip and not either half of one.
    let r = probe50_run.probe_pct(0.5) - probe_run.probe_pct(0.5);
    assert!(
        r >= 80.0,
        "probe50: the round trip rose by {r:.1} ms, want ≥ 80: the probe does not \
         cross the link both ways"
    );

    // `gate_lgcy` vs `gate_slot`: FR-98 C1. Frames that land ahead of the
    // legacy cadence wait for it, and the slot-first gate hands them out on
    // arrival. With exact arithmetic the legacy wait would be locked at 30 ms;
    // a real sleep overshoots, so the cadence drifts and the wait saws
    // through the period instead, averaging about half of it. A quarter of a
    // period is the bound, half the expected difference.
    let period_ms = 1000.0 / f64::from(GATE_FPS);
    for (run, name) in [(&legacy_run, "gate_lgcy"), (&slot_run, "gate_slot")] {
        assert!(
            run.fps() >= f64::from(GATE_FPS) * CLEAN_FPS_FLOOR,
            "{name}: {:.1} fps decoded from a {GATE_FPS} fps source",
            run.fps()
        );
    }
    let c1 = legacy_run.pct(0.5) - slot_run.pct(0.5);
    assert!(
        c1 >= period_ms / 4.0,
        "FR-98 C1: the slot-first gate cut p50 by {c1:.1} ms, want ≥ {:.1} (a quarter \
         of the {period_ms:.0} ms period): the gate does not see frames that wait in the slot",
        period_ms / 4.0
    );
}
