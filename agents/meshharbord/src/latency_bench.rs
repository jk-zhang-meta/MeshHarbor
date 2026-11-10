// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Test-only remote-control latency and sender packet-drop instrumentation.
//!
//! Compiled ONLY when the non-default `rc-latency-bench` Cargo feature is
//! enabled (never in `default`, `full`, or `full-hw` builds). Even when
//! compiled in, every hook stays off unless the runtime environment variables
//! `MESHHARBORD_LATENCY_BENCH=1` or `MESHHARBORD_TEST_VIDEO_DROP_PCT` are set.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bson::oid::ObjectId;
use webrtc::interceptor::stream_info::StreamInfo;
use webrtc::interceptor::{
    Attributes, Error as InterceptorError, Interceptor, InterceptorBuilder, RTCPReader, RTCPWriter,
    RTPReader, RTPWriter,
};

use crate::capture::bench_marker::{self, Corner};

static DROP_ARMED: AtomicBool = AtomicBool::new(false);
static LAST_RTP_TIMESTAMP: AtomicU32 = AtomicU32::new(0);
static RTP_PKTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static RTP_PKTS_DROPPED: AtomicU64 = AtomicU64::new(0);
static RTCP_PLI_TOTAL: AtomicU64 = AtomicU64::new(0);
static RTCP_NACK_LOST_TOTAL: AtomicU64 = AtomicU64::new(0);
static RC_KEYFRAME_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Returns `true` when `MESHHARBORD_LATENCY_BENCH` is `"1"` or `"true"`.
pub fn bench_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("MESHHARBORD_LATENCY_BENCH")
            .map(|v| {
                let s = v.trim();
                s == "1" || s.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false)
    })
}

/// Parses a drop percentage string (e.g. `"0"`, `"2"`, `"5"`, `"2.5"`) into
/// per-mille (`0..=1000`). Invalid or negative values resolve to `0`.
pub fn parse_drop_pct_to_permille(raw: &str) -> u32 {
    let trimmed = raw.trim().trim_end_matches('%').trim();
    let Ok(pct) = trimmed.parse::<f64>() else {
        return 0;
    };
    if !pct.is_finite() || pct <= 0.0 {
        return 0;
    }
    ((pct * 10.0).round() as u32).min(1000)
}

/// Configured sender-side video RTP packet drop rate in per-mille (`0..=1000`),
/// read from `MESHHARBORD_TEST_VIDEO_DROP_PCT`. Defaults to `0` (disabled).
pub fn video_drop_permille() -> u32 {
    static PERMILLE: OnceLock<u32> = OnceLock::new();
    *PERMILLE.get_or_init(|| {
        std::env::var("MESHHARBORD_TEST_VIDEO_DROP_PCT")
            .map(|v| parse_drop_pct_to_permille(&v))
            .unwrap_or(0)
    })
}

/// Wallclock microseconds since `UNIX_EPOCH`.
pub fn unix_epoch_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// Arm or disarm the sender-side packet dropper (disarmed during initial
/// connection handshake until the first connected frame is sent).
pub fn set_drop_armed(armed: bool) {
    DROP_ARMED.store(armed, Ordering::Relaxed);
}

/// Reset per-session packet/keyframe counters at `AgentPeer::new`.
pub fn reset_session_counters() {
    DROP_ARMED.store(false, Ordering::Relaxed);
    LAST_RTP_TIMESTAMP.store(0, Ordering::Relaxed);
    RTP_PKTS_TOTAL.store(0, Ordering::Relaxed);
    RTP_PKTS_DROPPED.store(0, Ordering::Relaxed);
    RTCP_PLI_TOTAL.store(0, Ordering::Relaxed);
    RTCP_NACK_LOST_TOTAL.store(0, Ordering::Relaxed);
    RC_KEYFRAME_TOTAL.store(0, Ordering::Relaxed);
}

/// Returns `(total_video_rtp_packets, dropped_video_rtp_packets)`.
pub fn rtp_packet_counts() -> (u64, u64) {
    (
        RTP_PKTS_TOTAL.load(Ordering::Relaxed),
        RTP_PKTS_DROPPED.load(Ordering::Relaxed),
    )
}

/// Returns the 32-bit RTP timestamp of the most recently written video RTP packet.
pub fn last_rtp_timestamp() -> u32 {
    LAST_RTP_TIMESTAMP.load(Ordering::Relaxed)
}

/// Append a JSON line to `MESHHARBORD_LATENCY_BENCH_JSONL` if configured.
pub fn log_event(val: serde_json::Value) {
    static FILE: OnceLock<Mutex<Option<std::fs::File>>> = OnceLock::new();
    let mutex = FILE.get_or_init(|| {
        let f = std::env::var("MESHHARBORD_LATENCY_BENCH_JSONL")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .and_then(|path| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path.trim())
                    .ok()
            });
        Mutex::new(f)
    });
    if let Ok(mut guard) = mutex.lock()
        && let Some(ref mut file) = *guard
    {
        let _ = writeln!(file, "{val}");
        let _ = file.flush();
    }
}

/// Record a session stage timestamp in the JSONL log.
pub fn note_stage(session_id: ObjectId, stage: &'static str, extra: serde_json::Value) {
    if !bench_enabled() && video_drop_permille() == 0 {
        return;
    }
    log_event(serde_json::json!({
        "event": "stage",
        "session_id": session_id.to_hex(),
        "stage": stage,
        "agent_us": crate::peer::agent_epoch_us(),
        "wall_us": unix_epoch_us(),
        "extra": extra,
    }));
}

/// Record a `rc:clock` probe arrival and reply on the agent.
pub fn note_clock_probe(session_id: ObjectId, t0: &serde_json::Value, agent_us: u64) {
    if !bench_enabled() && video_drop_permille() == 0 {
        return;
    }
    log_event(serde_json::json!({
        "event": "clock_probe",
        "session_id": session_id.to_hex(),
        "t0": t0,
        "agent_us": agent_us,
        "wall_us": unix_epoch_us(),
    }));
}

/// Record an incoming RTCP PLI/FIR packet on the agent.
pub fn note_rtcp_pli(session_id: ObjectId, honoured: bool) {
    let total = RTCP_PLI_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    if !bench_enabled() && video_drop_permille() == 0 {
        return;
    }
    log_event(serde_json::json!({
        "event": "rtcp_pli",
        "session_id": session_id.to_hex(),
        "honoured": honoured,
        "pli_total": total,
        "agent_us": crate::peer::agent_epoch_us(),
        "wall_us": unix_epoch_us(),
    }));
}

/// Record an incoming RTCP TransportLayerNack packet on the agent.
pub fn note_rtcp_nack(session_id: ObjectId, lost_packets: u32, triggered_invalidation: bool) {
    let total = RTCP_NACK_LOST_TOTAL.fetch_add(u64::from(lost_packets), Ordering::Relaxed)
        + u64::from(lost_packets);
    if !bench_enabled() && video_drop_permille() == 0 {
        return;
    }
    log_event(serde_json::json!({
        "event": "rtcp_nack",
        "session_id": session_id.to_hex(),
        "lost_packets": lost_packets,
        "triggered_invalidation": triggered_invalidation,
        "nack_lost_total": total,
        "agent_us": crate::peer::agent_epoch_us(),
        "wall_us": unix_epoch_us(),
    }));
}

/// Record an incoming `rc:keyframe` control-channel message on the agent.
pub fn note_rc_keyframe(session_id: ObjectId, honoured: bool) {
    let total = RC_KEYFRAME_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    if !bench_enabled() && video_drop_permille() == 0 {
        return;
    }
    log_event(serde_json::json!({
        "event": "rc_keyframe",
        "session_id": session_id.to_hex(),
        "honoured": honoured,
        "rc_keyframe_total": total,
        "agent_us": crate::peer::agent_epoch_us(),
        "wall_us": unix_epoch_us(),
    }));
}

/// Record a transmitted video frame in the JSONL log.
#[allow(clippy::too_many_arguments)]
pub fn note_frame_tx(
    session_id: ObjectId,
    frame_seq: u32,
    capture_agent_us: u64,
    capture_wall_us: u64,
    encode_start_agent_us: u64,
    encode_done_agent_us: u64,
    write_done_agent_us: u64,
    frame_bytes: u64,
    is_keyframe: bool,
    rtp_timestamp: u32,
    frame_rtp_pkts: u64,
    frame_rtp_dropped: u64,
    total_rtp_pkts: u64,
    total_rtp_dropped: u64,
) {
    if !bench_enabled() && video_drop_permille() == 0 {
        return;
    }
    log_event(serde_json::json!({
        "event": "frame_tx",
        "session_id": session_id.to_hex(),
        "frame_seq": frame_seq,
        "capture_agent_us": capture_agent_us,
        "capture_wall_us": capture_wall_us,
        "encode_start_agent_us": encode_start_agent_us,
        "encode_done_agent_us": encode_done_agent_us,
        "write_done_agent_us": write_done_agent_us,
        "frame_bytes": frame_bytes,
        "is_keyframe": is_keyframe,
        "rtp_timestamp": rtp_timestamp,
        "frame_rtp_pkts": frame_rtp_pkts,
        "frame_rtp_dropped": frame_rtp_dropped,
        "total_rtp_pkts": total_rtp_pkts,
        "total_rtp_dropped": total_rtp_dropped,
        "pli_total": RTCP_PLI_TOTAL.load(Ordering::Relaxed),
        "rc_keyframe_total": RC_KEYFRAME_TOTAL.load(Ordering::Relaxed),
    }));
}

/// Stamp a 24-bit frame sequence number (`0..16_777_216`) into the bottom-left
/// (low 12 bits) and bottom-right (high 12 bits) corners of `frame` using
/// [`bench_marker::paint_bgra_at`].
pub fn stamp_frame_markers(frame: &mut Arc<crate::capture::Frame>, seq: u32) {
    let f = Arc::make_mut(frame);
    let low12 = (seq & 0x0FFF) as u16;
    let high12 = ((seq >> 12) & 0x0FFF) as u16;
    bench_marker::paint_bgra_at(
        Corner::BottomLeft,
        &mut f.data,
        f.width,
        f.height,
        f.stride,
        low12,
    );
    bench_marker::paint_bgra_at(
        Corner::BottomRight,
        &mut f.data,
        f.width,
        f.height,
        f.stride,
        high12,
    );
}

/// Decode a 24-bit frame sequence number from a luma plane whose bottom-left
/// and bottom-right corners were stamped by [`stamp_frame_markers`].
pub fn decode_frame_markers_luma(y: &[u8], w: u32, h: u32, stride: usize) -> Option<u32> {
    let low12 = u32::from(bench_marker::decode_luma_at(
        Corner::BottomLeft,
        y,
        w,
        h,
        stride,
    )?);
    let high12 = u32::from(bench_marker::decode_luma_at(
        Corner::BottomRight,
        y,
        w,
        h,
        stride,
    )?);
    Some((high12 << 12) | low12)
}

/// Deterministic PRNG for reproducible sender-side packet loss.
struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn should_drop(&mut self, permille: u32) -> bool {
        if permille == 0 {
            return false;
        }
        (self.next_u64() % 1000) < u64::from(permille)
    }
}

struct VideoDropRtpWriter {
    inner: Arc<dyn RTPWriter + Send + Sync>,
    drop_permille: u32,
    rng: Mutex<XorShift64>,
}

#[async_trait]
impl RTPWriter for VideoDropRtpWriter {
    async fn write(
        &self,
        pkt: &webrtc::rtp::packet::Packet,
        attributes: &Attributes,
    ) -> std::result::Result<usize, InterceptorError> {
        LAST_RTP_TIMESTAMP.store(pkt.header.timestamp, Ordering::Relaxed);
        RTP_PKTS_TOTAL.fetch_add(1, Ordering::Relaxed);
        if self.drop_permille > 0 && DROP_ARMED.load(Ordering::Relaxed) {
            let drop = self
                .rng
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .should_drop(self.drop_permille);
            if drop {
                RTP_PKTS_DROPPED.fetch_add(1, Ordering::Relaxed);
                return Ok(pkt.payload.len());
            }
        }
        self.inner.write(pkt, attributes).await
    }
}

/// WebRTC interceptor that records outbound video RTP timestamps/packet counts
/// and drops video RTP packets at `video_drop_permille()`.
#[derive(Clone, Copy)]
pub struct VideoPacketDropInterceptor {
    drop_permille: u32,
}

impl InterceptorBuilder for VideoPacketDropInterceptor {
    fn build(
        &self,
        _id: &str,
    ) -> std::result::Result<Arc<dyn Interceptor + Send + Sync>, InterceptorError> {
        Ok(Arc::new(*self))
    }
}

#[async_trait]
impl Interceptor for VideoPacketDropInterceptor {
    async fn bind_rtcp_reader(
        &self,
        reader: Arc<dyn RTCPReader + Send + Sync>,
    ) -> Arc<dyn RTCPReader + Send + Sync> {
        reader
    }

    async fn bind_rtcp_writer(
        &self,
        writer: Arc<dyn RTCPWriter + Send + Sync>,
    ) -> Arc<dyn RTCPWriter + Send + Sync> {
        writer
    }

    async fn bind_local_stream(
        &self,
        info: &StreamInfo,
        writer: Arc<dyn RTPWriter + Send + Sync>,
    ) -> Arc<dyn RTPWriter + Send + Sync> {
        if info.mime_type.to_ascii_lowercase().starts_with("video/") {
            Arc::new(VideoDropRtpWriter {
                inner: writer,
                drop_permille: self.drop_permille,
                rng: Mutex::new(XorShift64(0x9E37_79B9_7F4A_7C15)),
            })
        } else {
            writer
        }
    }

    async fn unbind_local_stream(&self, _info: &StreamInfo) {}

    async fn bind_remote_stream(
        &self,
        _info: &StreamInfo,
        reader: Arc<dyn RTPReader + Send + Sync>,
    ) -> Arc<dyn RTPReader + Send + Sync> {
        reader
    }

    async fn unbind_remote_stream(&self, _info: &StreamInfo) {}

    async fn close(&self) -> std::result::Result<(), InterceptorError> {
        Ok(())
    }
}

/// Register [`VideoPacketDropInterceptor`] onto `registry` when
/// `bench_enabled()` or `video_drop_permille() > 0`.
pub fn register_interceptor(
    mut registry: webrtc::interceptor::registry::Registry,
    session_id: ObjectId,
) -> webrtc::interceptor::registry::Registry {
    reset_session_counters();
    let drop_permille = video_drop_permille();
    if bench_enabled() || drop_permille > 0 {
        tracing::info!(
            %session_id,
            bench_enabled = bench_enabled(),
            drop_permille,
            "rc-latency-bench: installing VideoPacketDropInterceptor"
        );
        registry.add(Box::new(VideoPacketDropInterceptor { drop_permille }));
    }
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Damage, Frame};

    #[test]
    fn parse_drop_pct_handles_integers_floats_and_invalid_inputs() {
        assert_eq!(parse_drop_pct_to_permille("0"), 0);
        assert_eq!(parse_drop_pct_to_permille("2"), 20);
        assert_eq!(parse_drop_pct_to_permille("2%"), 20);
        assert_eq!(parse_drop_pct_to_permille("5"), 50);
        assert_eq!(parse_drop_pct_to_permille("2.5"), 25);
        assert_eq!(parse_drop_pct_to_permille("-1"), 0);
        assert_eq!(parse_drop_pct_to_permille("abc"), 0);
        assert_eq!(parse_drop_pct_to_permille("150"), 1000);
    }

    #[test]
    fn stamp_and_decode_24bit_frame_markers_roundtrip() {
        let (w, h) = (640u32, 360u32);
        let stride = w * 4;
        for &seq in &[0u32, 1, 42, 3000, 4095, 4096, 123_456, 0x00FF_FFFF] {
            let mut frame = Arc::new(Frame {
                width: w,
                height: h,
                stride,
                data: vec![0x40u8; (stride * h) as usize],
                monotonic_us: 0,
                monitor: 0,
                damage: Damage::Unknown,
                pixel_format: crate::capture::PixelFormat::Bgra,
                source: None,
            });
            stamp_frame_markers(&mut frame, seq);
            // Convert BGRA to luma (same BT.601 approximation or B channel since marker is greyscale).
            let luma: Vec<u8> = frame.data.chunks_exact(4).map(|px| px[0]).collect();
            let decoded = decode_frame_markers_luma(&luma, w, h, w as usize);
            assert_eq!(decoded, Some(seq), "failed round-trip for seq={seq}");
        }
    }

    #[test]
    fn xorshift_drop_rates_match_configured_permille_within_tolerance() {
        for &(permille, tol) in &[(0u32, 0i64), (20u32, 35i64), (50u32, 50i64)] {
            let mut rng = XorShift64(0x9E37_79B9_7F4A_7C15);
            let n = 10_000u64;
            let dropped = (0..n).filter(|_| rng.should_drop(permille)).count() as i64;
            let expected = (n * u64::from(permille) / 1000) as i64;
            assert!(
                (dropped - expected).abs() <= tol,
                "permille={permille}: dropped={dropped}, expected={expected}"
            );
        }
    }

    #[tokio::test]
    async fn drop_interceptor_before_default_interceptors_allows_nack_retransmit() {
        use webrtc::api::interceptor_registry::register_default_interceptors;
        use webrtc::api::media_engine::MediaEngine;
        use webrtc::interceptor::registry::Registry;
        use webrtc::interceptor::stream_info::RTCPFeedback;
        use webrtc::rtcp::transport_feedbacks::transport_layer_nack::{
            NackPair, TransportLayerNack,
        };

        struct RecordingRtpWriter {
            seqs: Mutex<Vec<u16>>,
        }

        #[async_trait]
        impl RTPWriter for RecordingRtpWriter {
            async fn write(
                &self,
                pkt: &webrtc::rtp::packet::Packet,
                _attributes: &Attributes,
            ) -> std::result::Result<usize, InterceptorError> {
                self.seqs.lock().unwrap().push(pkt.header.sequence_number);
                Ok(pkt.payload.len())
            }
        }

        struct NoopRtcpWriter;

        #[async_trait]
        impl RTCPWriter for NoopRtcpWriter {
            async fn write(
                &self,
                _pkts: &[Box<dyn webrtc::rtcp::packet::Packet + Send + Sync>],
                _attributes: &Attributes,
            ) -> std::result::Result<usize, InterceptorError> {
                Ok(0)
            }
        }

        struct CannedNackRtcpReader {
            media_ssrc: u32,
            missing_seq: u16,
        }

        #[async_trait]
        impl RTCPReader for CannedNackRtcpReader {
            async fn read(
                &self,
                _buf: &mut [u8],
                _attributes: &Attributes,
            ) -> std::result::Result<
                (
                    Vec<Box<dyn webrtc::rtcp::packet::Packet + Send + Sync>>,
                    Attributes,
                ),
                InterceptorError,
            > {
                let nack = TransportLayerNack {
                    sender_ssrc: 0x2222_3333,
                    media_ssrc: self.media_ssrc,
                    nacks: vec![NackPair {
                        packet_id: self.missing_seq,
                        lost_packets: 0,
                    }],
                };
                Ok((vec![Box::new(nack)], Attributes::new()))
            }
        }

        reset_session_counters();
        let mut engine = MediaEngine::default();
        engine.register_default_codecs().unwrap();

        // Exact production registration order: VideoPacketDropInterceptor FIRST
        // (innermost / closest to network writer), default interceptors SECOND
        // (outermost / closest to TrackLocal).
        let mut registry = Registry::new();
        registry.add(Box::new(VideoPacketDropInterceptor {
            drop_permille: 1000,
        }));
        let registry = register_default_interceptors(registry, &mut engine).unwrap();
        let interceptor = registry.build("test-peer").unwrap();

        let ssrc = 0x1122_3344u32;
        let missing_seq = 42u16;
        let rtcp_reader: Arc<dyn RTCPReader + Send + Sync> = Arc::new(CannedNackRtcpReader {
            media_ssrc: ssrc,
            missing_seq,
        });
        let bound_rtcp_reader = interceptor.bind_rtcp_reader(rtcp_reader).await;
        let _bound_rtcp_writer = interceptor.bind_rtcp_writer(Arc::new(NoopRtcpWriter)).await;

        let net_writer = Arc::new(RecordingRtpWriter {
            seqs: Mutex::new(Vec::new()),
        });
        let stream_info = StreamInfo {
            ssrc,
            payload_type: 96,
            mime_type: "video/H264".to_string(),
            clock_rate: 90_000,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: String::new(),
            }],
            ..Default::default()
        };
        let bound_rtp_writer = interceptor
            .bind_local_stream(&stream_info, net_writer.clone())
            .await;

        // 1. Arm 100% drop and send seq=42. Because NACK ResponderInterceptor is
        // outer to VideoDropRtpWriter, ResponderInterceptor caches seq=42 first,
        // then VideoDropRtpWriter drops it before `net_writer`.
        set_drop_armed(true);
        let pkt = webrtc::rtp::packet::Packet {
            header: webrtc::rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number: missing_seq,
                timestamp: 9000,
                ssrc,
                ..Default::default()
            },
            payload: bytes::Bytes::from_static(&[0x65, 0x88, 0x84, 0x21]),
        };
        bound_rtp_writer
            .write(&pkt, &Attributes::new())
            .await
            .unwrap();
        assert!(
            net_writer.seqs.lock().unwrap().is_empty(),
            "initial packet should be dropped before reaching network writer"
        );
        assert_eq!(rtp_packet_counts(), (1, 1));

        // 2. While dropper is STILL armed (100% drop), feed an incoming RTCP
        // TransportLayerNack for seq=42. ResponderInterceptor resends seq=42
        // through VideoDropRtpWriter, which drops the retransmission too!
        let mut rtcp_buf = [0u8; 1500];
        bound_rtcp_reader
            .read(&mut rtcp_buf, &Attributes::new())
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if rtp_packet_counts() == (2, 2) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for NACK retransmission to traverse VideoDropRtpWriter"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            net_writer.seqs.lock().unwrap().is_empty(),
            "retransmitted packet should also be subject to VideoDropRtpWriter"
        );

        // 3. Disarm dropper and feed a second RTCP TransportLayerNack for seq=42.
        // Now the NACK retransmission passes through VideoDropRtpWriter to `net_writer`.
        set_drop_armed(false);
        bound_rtcp_reader
            .read(&mut rtcp_buf, &Attributes::new())
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if net_writer.seqs.lock().unwrap().as_slice() == [missing_seq] {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for NACK retransmission of dropped packet"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(rtp_packet_counts(), (3, 2));
        let _ = interceptor.close().await;
    }
}
