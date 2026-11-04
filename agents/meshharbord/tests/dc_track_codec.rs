// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #2231 — a DataChannel session answers an offer that has no H.264.
//!
//! A Firefox without OpenH264 offers VP8, VP9 and AV1. On the VP9 DataChannel
//! the agent's video never touches the RTP track, but the track is still
//! created, and `pick_best_codec`'s fallback made it H.264: the sender had no
//! codec in common with the offer, and `create_answer` failed ("unable to
//! populate media section, RTPSender created with no codecs") before the
//! DataChannel the session would use could open. Measured in the field on
//! agent 0.4.136 with Playwright's Firefox (#2231).
//!
//! Both peers are the real thing: the production `AgentPeer`, and a webrtc-rs
//! "browser" whose media engine registers VP8 alone, offering a recvonly video
//! transceiver and a DataChannel the way the viewer does. The second test keeps
//! the failure itself: the H.264 track still cannot answer that offer, so the
//! first one cannot pass for a reason other than the track's codec.

use anyhow::{Context, Result, anyhow};
use meshharbor_remote_control::permissions::Permissions;
use meshharbor_remote_control::signaling::ClientMsg;
use meshharbord::encode::EncoderPreference;
use meshharbord::peer::{AgentPeer, rtp_track_codec, rtp_track_unanswerable};
use meshharbord::rc_overlay::RcOverlay;
use tokio::sync::mpsc;
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::{MIME_TYPE_VP8, MediaEngine};
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::rtp_transceiver::RTCRtpTransceiverInit;
use webrtc::rtp_transceiver::rtp_codec::{
    RTCRtpCodecCapability, RTCRtpCodecParameters, RTPCodecType,
};
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;

const TRANSPORT: &str = "data-channel-vp9-444";

/// The offer of a browser that decodes VP8 and no H.264.
async fn vp8_only_offer() -> Result<String> {
    let mut engine = MediaEngine::default();
    engine.register_codec(
        RTCRtpCodecParameters {
            capability: RTCRtpCodecCapability {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            payload_type: 96,
            ..Default::default()
        },
        RTPCodecType::Video,
    )?;
    let api = APIBuilder::new().with_media_engine(engine).build();
    let pc = api.new_peer_connection(RTCConfiguration::default()).await?;
    pc.add_transceiver_from_kind(
        RTPCodecType::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            send_encodings: vec![],
        }),
    )
    .await?;
    pc.create_data_channel("video-bytes", None).await?;
    let offer = pc.create_offer(None).await?;
    pc.close().await?;
    if offer.sdp.contains("H264") {
        return Err(anyhow!("the fixture offer must carry no H.264"));
    }
    Ok(offer.sdp)
}

async fn agent(track_codec: String) -> Result<(AgentPeer, mpsc::Receiver<ClientMsg>)> {
    let (tx, rx) = mpsc::channel::<ClientMsg>(256);
    let agent = AgentPeer::new(
        bson::oid::ObjectId::new(),
        &[],
        tx,
        EncoderPreference::Software,
        // The pump's codec: `pick_best_codec`'s fallback when VP8/VP9/AV1 meets
        // the agent's RTP `["h264"]`.
        "h264".into(),
        track_codec,
        Some(TRANSPORT.into()),
        None,
        false,
        false,
        Permissions::VIEW,
        "dc-track-codec".into(),
        None,
        RcOverlay::default(),
        meshharbord::rc_sessions::RcSessionRegistry::new(),
        // FR-102 P9d — this test never drives the peer to Connected, so the
        // carrier observation never fires; a throwaway sender is the honest
        // value.
        mpsc::channel(1).0,
    )
    .await
    .context("AgentPeer::new")?;
    Ok((agent, rx))
}

#[tokio::test]
async fn a_dc_session_answers_an_offer_without_h264() -> Result<()> {
    let offer = vp8_only_offer().await?;
    let track_codec = rtp_track_codec("h264", Some(TRANSPORT), &offer);
    assert_eq!(
        track_codec, "vp8",
        "the placeholder track moves to a codec the offer carries"
    );
    let (agent, _rx) = agent(track_codec).await?;
    let answer = agent.handle_offer(offer).await;
    // A WebRTC peer frees nothing on drop: close it whatever the answer was.
    agent.close().await;
    let answer = answer.context("the agent must answer a VP8-only offer on the DataChannel")?;
    assert!(
        answer.contains("VP8/90000"),
        "the answer's video line is VP8: {answer}"
    );
    assert!(
        answer.contains("m=application"),
        "the DataChannel survives the answer"
    );
    Ok(())
}

/// The failure this fixes, kept: an H.264 track cannot answer the same offer.
/// #2251 — and on the RTP transport, where the track cannot move to VP8, it is
/// exactly the offer the agent now refuses before building a peer.
#[tokio::test]
async fn the_h264_track_cannot_answer_that_offer() -> Result<()> {
    let offer = vp8_only_offer().await?;
    assert!(
        rtp_track_unanswerable("h264", None, &offer),
        "the RTP transport refuses the offer its H.264 track cannot answer"
    );
    assert!(
        !rtp_track_unanswerable("h264", Some(TRANSPORT), &offer),
        "the DataChannel transport answers it with the VP8 placeholder"
    );
    let (agent, _rx) = agent("h264".into()).await?;
    let answer = agent.handle_offer(offer).await;
    agent.close().await;
    let err = answer
        .err()
        .context("an H.264 track answered a VP8-only offer")?;
    assert!(
        format!("{err:#}").contains("no codecs"),
        "the field's error, not another: {err:#}"
    );
    Ok(())
}
