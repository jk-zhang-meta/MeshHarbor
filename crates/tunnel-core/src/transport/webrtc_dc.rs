// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `webrtc-dc-v1` transport — WebRTC SCTP DataChannels.
//!
//! [`TunnelPeer`] wraps an `RTCPeerConnection` and pre-negotiates a
//! fixed pool of 8 ordered + reliable DataChannels with deterministic
//! stream IDs (100, 102, 104, … 114). Each `meshharbor forward`
//! invocation owns one `TunnelPeer`; multiple concurrent TCP flows
//! multiplex onto the pool via [`crate::mux`]'s 4-byte `flow_id`
//! prefix. Per plan §"What changed from v1" #1 (DC-per-flow was wrong;
//! pool + framing is the v1 default).
//!
//! SCTP rwnd is set to 8 MiB via the vendored webrtc-0.12.0 fork's
//! `SettingEngine::set_sctp_max_receive_buffer_size`. Upstream
//! hardcodes 0 which falls back to a 1 MiB default and caps
//! single-stream DC throughput at ~80 Mbps on 100 ms RTT paths. Lock
//! the patch contract here so a future webrtc bump that drops the
//! setter is caught by `compile_with_sctp_rwnd_setter` below.

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::oneshot;
use webrtc::api::APIBuilder;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

/// Number of pre-negotiated DataChannels per peer. Plan §"Performance
/// levers" #4 locks this at 8; the multiplex framing in `crate::mux`
/// fans many TCP flows onto these channels.
pub const POOL_SIZE: u8 = 8;

/// First SCTP stream id used by the pool. Subsequent channels use
/// the next even ids (102, 104, …). Even ids by webrtc-rs convention
/// for offerer-initiated streams.
pub const POOL_BASE_STREAM_ID: u16 = 100;

/// SCTP receive window advertised to the peer. 8 MiB lifts the
/// upstream 1 MiB cap that capped single-stream throughput at ~80
/// Mbps over 100 ms RTT. Locked here, enforced via the vendored
/// fork's SettingEngine setter.
pub const SCTP_RECV_BUFFER_BYTES: u32 = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("webrtc: {0}")]
    Webrtc(#[from] webrtc::Error),
    #[error("data channel pool incomplete: {0}/{1} channels open")]
    PoolIncomplete(u8, u8),
    #[error("invalid SDP: {0}")]
    InvalidSdp(String),
    #[error("invalid ICE candidate: {0}")]
    InvalidIceCandidate(String),
}

/// One end of a tunnel peer connection. Owns the `RTCPeerConnection`
/// plus the pre-negotiated DC pool. Both offerer and answerer
/// construct identical peers — DCs are pre-negotiated by stream id
/// so SDP renegotiation isn't needed per flow.
pub struct TunnelPeer {
    pc: Arc<RTCPeerConnection>,
    dc_pool: Vec<Arc<RTCDataChannel>>,
}

impl TunnelPeer {
    /// Construct a peer with the standard 8-channel DC pool.
    /// Side-effects: builds an `APIBuilder` with `SettingEngine`
    /// configured for 8 MiB SCTP rwnd; allocates 8 negotiated DCs
    /// with deterministic stream ids.
    pub async fn new(ice_servers: Vec<RTCIceServer>) -> Result<Self, PeerError> {
        let mut setting_engine = SettingEngine::default();
        // The vendored fork's lock-in test guarantees this setter
        // round-trips. If the API ever drops, this line stops
        // compiling — caught at build time, not at runtime.
        setting_engine.set_sctp_max_receive_buffer_size(SCTP_RECV_BUFFER_BYTES);
        // mDNS is a BROWSER privacy feature: Chrome hides its LAN host
        // candidates behind `.local` names so a page can't learn your private
        // IP. Both ends of a tunnel are our own agents exchanging real
        // addresses, so we neither publish nor need to resolve those — and
        // `MulticastDnsMode` defaults to `QueryOnly`, which still binds
        // `0.0.0.0:5353` per agent. Disabling it removes ~2/3 of the sockets
        // an agent holds (see the `Drop` impl for the leak this compounded)
        // and stops us contending for a port the OS resolver already owns on
        // Windows — the same unreliability `roomlerd`'s
        // `mdns_resolve` module exists to route around.
        setting_engine.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);

        let api = APIBuilder::new()
            .with_setting_engine(setting_engine)
            .build();

        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };
        let pc = Arc::new(api.new_peer_connection(config).await?);

        let mut dc_pool = Vec::with_capacity(POOL_SIZE as usize);
        for idx in 0..POOL_SIZE {
            let stream_id = POOL_BASE_STREAM_ID + (idx as u16) * 2;
            let init = RTCDataChannelInit {
                ordered: Some(true),
                negotiated: Some(stream_id),
                ..Default::default()
            };
            let label = format!("tunnel-{idx}");
            let dc = pc.create_data_channel(&label, Some(init)).await?;
            dc_pool.push(dc);
        }

        Ok(Self { pc, dc_pool })
    }

    /// Access channel `idx` (0..POOL_SIZE). Returns `None` for
    /// out-of-range indexes so the caller can map a wire-side
    /// `dc_index` to a graceful reject.
    pub fn dc(&self, idx: u8) -> Option<Arc<RTCDataChannel>> {
        self.dc_pool.get(idx as usize).cloned()
    }

    /// Number of DCs in the pool. Always [`POOL_SIZE`] in v1; exposed
    /// so wire-level `rc:tunnel.opened.dc_pool_size` doesn't have to
    /// reach for the constant.
    pub fn pool_size(&self) -> u8 {
        POOL_SIZE
    }

    /// Borrow the underlying `RTCPeerConnection`. Useful for the WS
    /// handler that needs to wire `on_ice_candidate` callbacks to the
    /// signaling stream.
    pub fn peer_connection(&self) -> Arc<RTCPeerConnection> {
        Arc::clone(&self.pc)
    }

    /// Offerer side: generate the SDP offer + set as local
    /// description. Caller forwards the returned offer over the
    /// `rc:tunnel.open` / standard `rc:sdp.offer` wire path.
    pub async fn create_offer(&self) -> Result<RTCSessionDescription, PeerError> {
        let offer = self.pc.create_offer(None).await?;
        self.pc.set_local_description(offer.clone()).await?;
        Ok(offer)
    }

    /// Answerer side: install the remote offer + generate an answer
    /// + set as local description.
    pub async fn accept_offer(&self, offer_sdp: &str) -> Result<RTCSessionDescription, PeerError> {
        let offer = RTCSessionDescription::offer(offer_sdp.to_string())
            .map_err(|e| PeerError::InvalidSdp(e.to_string()))?;
        self.pc.set_remote_description(offer).await?;
        let answer = self.pc.create_answer(None).await?;
        self.pc.set_local_description(answer.clone()).await?;
        Ok(answer)
    }

    /// Offerer side: install the remote answer. Completes the SDP
    /// handshake; ICE candidate exchange continues in parallel.
    pub async fn accept_answer(&self, answer_sdp: &str) -> Result<(), PeerError> {
        let answer = RTCSessionDescription::answer(answer_sdp.to_string())
            .map_err(|e| PeerError::InvalidSdp(e.to_string()))?;
        self.pc.set_remote_description(answer).await?;
        Ok(())
    }

    /// Add a remote ICE candidate. `candidate_init_json` is the JSON
    /// blob the peer emitted via its `on_ice_candidate` callback
    /// (carried over the wire as `rc:ice.candidate`).
    pub async fn add_remote_ice_candidate(
        &self,
        candidate_init: RTCIceCandidateInit,
    ) -> Result<(), PeerError> {
        self.pc.add_ice_candidate(candidate_init).await?;
        Ok(())
    }

    /// Resolve once every DC in the pool reaches the `open` state.
    /// Useful in tests + the CLI's `diagnose` subcommand. Returns
    /// `PoolIncomplete` if any DC closes before all reach `open`.
    pub async fn wait_pool_open(&self) -> Result<(), PeerError> {
        let (tx, rx) = oneshot::channel::<()>();
        let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
        let opened = Arc::new(std::sync::atomic::AtomicU8::new(0));
        for dc in &self.dc_pool {
            let opened = Arc::clone(&opened);
            let tx = Arc::clone(&tx);
            dc.on_open(Box::new(move || {
                let opened = Arc::clone(&opened);
                let tx = Arc::clone(&tx);
                Box::pin(async move {
                    let n = opened.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if n == POOL_SIZE
                        && let Some(tx) = tx.lock().await.take()
                    {
                        let _ = tx.send(());
                    }
                })
            }));
        }
        rx.await.map_err(|_| {
            PeerError::PoolIncomplete(opened.load(std::sync::atomic::Ordering::SeqCst), POOL_SIZE)
        })?;
        Ok(())
    }

    /// Convenience: send a small message on a specific DC. Caller
    /// retains responsibility for backpressure (see `crate::forward`
    /// for the watermark-driven pump that wraps this).
    pub async fn send(&self, dc_idx: u8, data: Bytes) -> Result<usize, PeerError> {
        let dc = self
            .dc(dc_idx)
            .ok_or_else(|| PeerError::PoolIncomplete(self.dc_pool.len() as u8, POOL_SIZE))?;
        let n = dc.send(&data).await?;
        Ok(n)
    }

    /// Has the peer connection reached the `connected` state? Used
    /// by the CLI's `diagnose` subcommand and by the WS handler to
    /// gate `TcpForwardRequest` until ICE finishes.
    pub fn is_connected(&self) -> bool {
        matches!(
            self.pc.connection_state(),
            RTCPeerConnectionState::Connected
        )
    }

    /// Forward `RTCIceCandidate` events from the local agent to the
    /// caller-provided async closure. Wire it to whatever signaling
    /// channel the WS handler exposes.
    pub fn on_local_ice_candidate<F>(&self, handler: F)
    where
        F: Fn(
                Option<RTCIceCandidate>,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + Sync
            + 'static,
    {
        self.pc.on_ice_candidate(Box::new(move |c| handler(c)));
    }

    /// Release the peer connection and everything the ICE agent owns.
    ///
    /// **Dropping a `TunnelPeer` is not enough.** An `RTCPeerConnection`'s
    /// UDP sockets — one host candidate per local address, plus the
    /// webrtc-ice mDNS listener on `0.0.0.0:5353` — are owned by tasks the
    /// agent spawned, not by this struct, so they outlive the `Arc` and are
    /// only freed by `close()`. See the `Drop` impl below for what that cost
    /// in the field.
    ///
    /// Idempotent: webrtc-rs `close()` on an already-closed PC is a no-op,
    /// so the explicit call and the `Drop` net can both fire.
    pub async fn close(&self) {
        if let Err(e) = self.pc.close().await {
            tracing::debug!(%e, "tunnel peer close failed (already closed?)");
        }
    }
}

/// Field fix (2026-08-22) — **the peer connection MUST be closed, and Drop is
/// the only place every path funnels through.**
///
/// `TunnelPeer` is built inside `run_tunnel_session`, which has many `?`
/// early returns; a session that fails during ICE or the DC-pool wait never
/// reaches an explicit teardown. Nothing closed the PC on those paths, and
/// because the ICE agent's sockets belong to spawned tasks rather than to
/// this struct, dropping the `Arc` freed nothing.
///
/// Measured on devbox the day this was found: `roomlerd` held **15,446 UDP
/// sockets** after 12 h — 10,367 of them on `0.0.0.0:5353`, the rest one per
/// local address per leaked agent — which is the entire 16,384-port ephemeral
/// range. Every socket allocation on the host then failed with `WSAENOBUFS`,
/// so **the whole machine lost DNS** (`ping 1.1.1.1` fine, every name
/// unresolvable). With flows retrying at ~1 s backoff the observed rate was
/// ~1 socket/second, i.e. a host wedged in under five hours. The blast radius
/// is every application on the box, not just roomler.
///
/// `Drop` cannot await, so this spawns the close. Outside a runtime there is
/// nothing to spawn onto — that only happens in teardown paths where the
/// process is going away anyway, so the sockets die with it.
impl Drop for TunnelPeer {
    fn drop(&mut self) {
        let pc = Arc::clone(&self.pc);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = pc.close().await;
            });
        }
    }
}

// Compile-time lock — if the vendored SCTP rwnd setter is ever
// removed (e.g. upstream bump), this call stops compiling and the
// build fails loud. Easier-to-grep than a runtime check.
#[allow(dead_code)]
fn compile_with_sctp_rwnd_setter() {
    let mut s = SettingEngine::default();
    s.set_sctp_max_receive_buffer_size(SCTP_RECV_BUFFER_BYTES);
}

// Compile-time invariants on the pool. Cross-referenced from the
// wire protocol (`ServerMsg::TunnelOpened.dc_pool_size: u8` and
// `sctp_rwnd_bytes: u32`). Renaming or shrinking these constants
// without updating the call sites listed below is a wire break.
const _: () = assert!(POOL_SIZE > 0, "pool must be non-empty");
const _: () = assert!(POOL_SIZE <= 64, "pool > 64 risks SCTP stream churn");
const _: () = {
    let highest = POOL_BASE_STREAM_ID + (POOL_SIZE as u16 - 1) * 2;
    assert!(highest < 1024, "high stream ids reserved for future media");
};
// If you change SCTP_RECV_BUFFER_BYTES, also update:
//   * crates/api/src/ws/tunnel.rs (sctp_rwnd_bytes in ServerMsg::TunnelOpened)
//   * crates/remote_control/src/signaling.rs comment block
//   * crates/vendored/webrtc/Cargo.toml patch notes
const _: () = assert!(SCTP_RECV_BUFFER_BYTES == 8 * 1024 * 1024);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::Duration;
    use webrtc::data_channel::data_channel_message::DataChannelMessage;

    /// Two peers handshake locally without any signaling server,
    /// then verify (a) all 8 DCs reach `open` on the answerer side,
    /// (b) a ping sent from offerer.dc(3) is received on
    /// answerer.dc(3). Locks the pool-pre-negotiation contract: with
    /// `negotiated: Some(stream_id)` set identically on both ends,
    /// no extra DC creation messages are sent over SCTP.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_peer_handshake_opens_full_pool() {
        let offerer = TunnelPeer::new(vec![]).await.expect("offerer");
        let answerer = TunnelPeer::new(vec![]).await.expect("answerer");

        // ICE candidate forwarding (no real signaling — just bridge
        // the two peers directly through Arc-clones).
        let answerer_pc = answerer.peer_connection();
        offerer.on_local_ice_candidate(move |c| {
            let pc = Arc::clone(&answerer_pc);
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc.add_ice_candidate(init).await;
                }
            })
        });
        let offerer_pc = offerer.peer_connection();
        answerer.on_local_ice_candidate(move |c| {
            let pc = Arc::clone(&offerer_pc);
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc.add_ice_candidate(init).await;
                }
            })
        });

        // SDP exchange.
        let offer = offerer.create_offer().await.expect("create_offer");
        let answer = answerer
            .accept_offer(&offer.sdp)
            .await
            .expect("accept_offer");
        offerer
            .accept_answer(&answer.sdp)
            .await
            .expect("accept_answer");

        // Both sides should see all 8 DCs open. 30s (not 10s) so a loaded CI
        // runner — many loopback WebRTC/QUIC peer tests run concurrently, incl.
        // the rc.152 UDP echo tests — has headroom for ICE to complete; the
        // handshake takes <1s locally, so a real hang still fails fast enough.
        let off_wait = tokio::time::timeout(Duration::from_secs(30), offerer.wait_pool_open());
        let ans_wait = tokio::time::timeout(Duration::from_secs(30), answerer.wait_pool_open());
        let (a, b) = tokio::join!(off_wait, ans_wait);
        a.expect("offerer pool timeout")
            .expect("offerer pool error");
        b.expect("answerer pool timeout")
            .expect("answerer pool error");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ping_roundtrip_on_pooled_dc() {
        let offerer = TunnelPeer::new(vec![]).await.unwrap();
        let answerer = TunnelPeer::new(vec![]).await.unwrap();

        let answerer_pc = answerer.peer_connection();
        offerer.on_local_ice_candidate(move |c| {
            let pc = Arc::clone(&answerer_pc);
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc.add_ice_candidate(init).await;
                }
            })
        });
        let offerer_pc = offerer.peer_connection();
        answerer.on_local_ice_candidate(move |c| {
            let pc = Arc::clone(&offerer_pc);
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc.add_ice_candidate(init).await;
                }
            })
        });

        // Install a receive handler on dc(3) of the answerer BEFORE
        // the handshake completes — `on_message` survives the open
        // transition.
        let received = Arc::new(AtomicU8::new(0));
        let r2 = Arc::clone(&received);
        let ans_dc = answerer.dc(3).unwrap();
        ans_dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let r = Arc::clone(&r2);
            Box::pin(async move {
                assert_eq!(msg.data.as_ref(), b"ping");
                r.fetch_add(1, Ordering::SeqCst);
            })
        }));

        // SDP handshake.
        let offer = offerer.create_offer().await.unwrap();
        let answer = answerer.accept_offer(&offer.sdp).await.unwrap();
        offerer.accept_answer(&answer.sdp).await.unwrap();

        // Wait for pool open on both sides, then send.
        let _ = tokio::time::timeout(Duration::from_secs(30), offerer.wait_pool_open())
            .await
            .expect("offerer timeout");
        let _ = tokio::time::timeout(Duration::from_secs(30), answerer.wait_pool_open())
            .await
            .expect("answerer timeout");

        let off_dc = offerer.dc(3).unwrap();
        off_dc.send(&Bytes::from_static(b"ping")).await.unwrap();

        // Wait for receive (poll up to 5 s).
        for _ in 0..50 {
            if received.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            received.load(Ordering::SeqCst),
            1,
            "did not receive ping on answerer.dc(3) within 5s"
        );
    }

    // Pool size + stream id + rwnd constants now locked via
    // compile-time `const _: () = assert!(...)` at module level
    // (above). Runtime tests removed — they ran on every test
    // invocation but couldn't catch anything the compile-time
    // asserts don't catch first.
    #[tokio::test]
    async fn dc_idx_out_of_range_returns_none() {
        let peer = TunnelPeer::new(vec![]).await.unwrap();
        assert!(peer.dc(POOL_SIZE).is_none());
        assert!(peer.dc(POOL_SIZE + 1).is_none());
        assert!(peer.dc(0).is_some());
        assert!(peer.dc(POOL_SIZE - 1).is_some());
    }
}
