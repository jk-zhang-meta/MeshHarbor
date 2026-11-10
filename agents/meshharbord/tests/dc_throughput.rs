// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-119 P0(c) — how many bits per second the vendored webrtc-rs data channel
//! carries, before any codec is involved.
//!
//! High refresh multiplies the bitrate: 4K at 144 fps on a direct path wants on
//! the order of 100 Mbps where 4K at 60 wants 48. The video DC (`video-bytes`)
//! is SCTP over DTLS over ICE in the vendored webrtc-rs, and nothing has measured
//! what that stack can carry. If it cannot carry D2, the transport is the
//! limiter, and a move to webrtc-rs 0.20 becomes a separate decision (FR-119,
//! open decision 3). This measures it.
//!
//! Two `RTCPeerConnection`s in one process, over **real loopback UDP** (kernel
//! sockets, host candidates, mDNS off), so the number is the stack's own
//! ceiling on this machine's CPU, with no network in the way: an upper bound
//! for a LAN path. The sender does what the production send task does
//! (`media_pump_ffmpeg_dc`): it awaits `send` on 16 KiB messages back to back,
//! and SCTP's flow control is what holds it back. The receiver counts bytes.
//!
//! A measurement, not a check: CI runners are too noisy for a throughput
//! assertion, so the test is ignored by default and its numbers go into
//! FR-119's field log with the machine they ran on.
//!
//! ```text
//! cargo test -p meshharbord --release --test dc_throughput -- --ignored --nocapture
//! ```
//!
//! ⚠️ Both peers are `close()`d: dropping a webrtc-rs peer frees nothing
//! (`docs/tunnels.md`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use tokio::sync::Notify;
use webrtc::api::APIBuilder;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::ice::network_type::NetworkType;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;

/// The production send task's message size (`SCTP_CHUNK_SIZE` in `peer.rs`).
const CHUNK: usize = 16 * 1024;

async fn loopback_peer() -> Result<Arc<RTCPeerConnection>> {
    let mut setting = SettingEngine::default();
    setting.set_include_loopback_candidate(true);
    setting.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);
    setting.set_network_types(vec![NetworkType::Udp4]);
    let api = APIBuilder::new().with_setting_engine(setting).build();
    Ok(Arc::new(
        api.new_peer_connection(RTCConfiguration::default()).await?,
    ))
}

/// Offer/answer with every candidate in the SDP (no trickle).
async fn connect(offerer: &RTCPeerConnection, answerer: &RTCPeerConnection) -> Result<()> {
    let offer = offerer.create_offer(None).await?;
    let mut gathered = offerer.gathering_complete_promise().await;
    offerer.set_local_description(offer).await?;
    let _ = gathered.recv().await;
    let offer = offerer
        .local_description()
        .await
        .ok_or_else(|| anyhow!("no local offer"))?;
    answerer.set_remote_description(offer).await?;
    let answer = answerer.create_answer(None).await?;
    let mut gathered = answerer.gathering_complete_promise().await;
    answerer.set_local_description(answer).await?;
    let _ = gathered.recv().await;
    let answer = answerer
        .local_description()
        .await
        .ok_or_else(|| anyhow!("no local answer"))?;
    offerer.set_remote_description(answer).await?;
    Ok(())
}

struct Measured {
    ordered: bool,
    sent_bytes: u64,
    received_bytes: u64,
    secs: f64,
}

impl Measured {
    fn mbps(&self) -> f64 {
        self.received_bytes as f64 * 8.0 / self.secs / 1e6
    }
}

/// Send for `run`, then give the receiver a moment to drain, and report what
/// arrived over the time it took.
async fn measure(ordered: bool, run: Duration) -> Result<Measured> {
    let sender = loopback_peer().await?;
    let receiver = loopback_peer().await?;

    let received = Arc::new(AtomicU64::new(0));
    let first_byte_at = Arc::new(std::sync::Mutex::new(None::<Instant>));
    let last_byte_at = Arc::new(std::sync::Mutex::new(None::<Instant>));
    {
        let received = Arc::clone(&received);
        let first_byte_at = Arc::clone(&first_byte_at);
        let last_byte_at = Arc::clone(&last_byte_at);
        receiver.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let received = Arc::clone(&received);
            let first_byte_at = Arc::clone(&first_byte_at);
            let last_byte_at = Arc::clone(&last_byte_at);
            Box::pin(async move {
                dc.on_message(Box::new(move |msg| {
                    let now = Instant::now();
                    first_byte_at.lock().unwrap().get_or_insert(now);
                    *last_byte_at.lock().unwrap() = Some(now);
                    received.fetch_add(msg.data.len() as u64, Ordering::Relaxed);
                    Box::pin(async {})
                }));
            })
        }));
    }

    let dc = sender
        .create_data_channel(
            "video-bytes",
            Some(RTCDataChannelInit {
                ordered: Some(ordered),
                ..Default::default()
            }),
        )
        .await?;
    let opened = Arc::new(Notify::new());
    {
        let opened = Arc::clone(&opened);
        dc.on_open(Box::new(move || {
            opened.notify_one();
            Box::pin(async {})
        }));
    }

    connect(&sender, &receiver).await?;
    tokio::time::timeout(Duration::from_secs(15), opened.notified())
        .await
        .context("the data channel never opened")?;

    let payload = Bytes::from(vec![0xA5u8; CHUNK]);
    let mut sent_bytes = 0u64;
    let started = Instant::now();
    while started.elapsed() < run {
        dc.send(&payload).await?;
        sent_bytes += CHUNK as u64;
    }
    // Let what is in flight land, without counting idle time: the window is
    // first byte to last byte at the receiver.
    let drain_until = Instant::now() + Duration::from_secs(3);
    while received.load(Ordering::Relaxed) < sent_bytes && Instant::now() < drain_until {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let received_bytes = received.load(Ordering::Relaxed);
    let first = (*first_byte_at.lock().unwrap()).unwrap_or(started);
    let last = (*last_byte_at.lock().unwrap()).unwrap_or(started);
    let secs = last
        .saturating_duration_since(first)
        .as_secs_f64()
        .max(1e-3);

    sender.close().await?;
    receiver.close().await?;
    Ok(Measured {
        ordered,
        sent_bytes,
        received_bytes,
        secs,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, not a check: run with --ignored --nocapture (and --release)"]
async fn the_data_channel_ceiling_over_loopback() -> Result<()> {
    for ordered in [true, false] {
        for round in 1..=3 {
            let m = measure(ordered, Duration::from_secs(5)).await?;
            println!(
                "dc_throughput ordered={} round={round}: {:.1} Mbit/s ({} of {} bytes over {:.2} s)",
                m.ordered,
                m.mbps(),
                m.received_bytes,
                m.sent_bytes,
                m.secs
            );
            // The one thing worth asserting anywhere: bytes arrived.
            assert!(m.received_bytes > 0, "nothing arrived");
        }
    }
    Ok(())
}
