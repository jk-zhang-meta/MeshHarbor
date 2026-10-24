// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Agent-side answerer for the `roomler` WebRTC handshake.
//!
//! Mirror of `roomler-cli`'s offerer-side [`TunnelPeer`] usage —
//! same crate type, just the answerer half of the handshake. One
//! `AgentTunnelPeer` per active tunnel session (server-issued
//! `tunnel_session_id`).
//!
//! Lifecycle:
//!
//! 1. Server emits `ServerMsg::TunnelSdpOffer { session_id, sdp }`.
//!    Agent's signaling loop calls
//!    [`AgentTunnelPeer::accept_offer`] which constructs the peer,
//!    installs the ICE-candidate forwarder, sets remote-describe,
//!    generates the answer, and returns it for the caller to ship
//!    as `ClientMsg::TunnelSdpAnswer`.
//! 2. Server trickles ICE via `ServerMsg::TunnelIce`. Agent calls
//!    [`AgentTunnelPeer::add_remote_ice`] for each.
//! 3. The DC pool opens (both ends pre-negotiated identical stream
//!    ids). A background task `await`s
//!    [`tunnel_core::transport::webrtc_dc::TunnelPeer::wait_pool_open`],
//!    then installs a [`FlowDemux`] on each DC and parks them in the
//!    `flow_demuxes` field so the acceptor can register per-flow
//!    mailboxes.
//! 4. Server emits `ServerMsg::TcpForwardForward` for each new flow.
//!    `crate::tunnel::acceptor::handle_forward_request` consults the
//!    ACL, dials dst, calls [`AgentTunnelPeer::register_flow`] to
//!    bind the flow to a DC, and spawns
//!    `tunnel_core::forward::run_flow` to drive the bytes.
//! 5. Either side tears down the tunnel via `TunnelTerminate` →
//!    [`AgentTunnelPeer::close`] drops every flow + DC.
//! 6. Or the client is simply gone (#1754): the peer reports it on the
//!    org loop's [`super::reap`] channel — a pool DC's `on_close` within
//!    milliseconds of a clean remote close, the peer connection's
//!    `Failed` ~30 s into silence — and the loop's reap arm removes and
//!    closes it exactly as a terminate would have.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bson::oid::ObjectId;
use roomler_ai_remote_control::signaling::{ClientMsg, IceServer};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};
use tunnel_core::forward::{FlowCancel, FlowCanceller, FlowDemux};
use tunnel_core::transport::webrtc_dc::{PeerError, TunnelPeer};
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;

use super::reap::{self, ReapSender, ReapSignal, TunnelReap};

/// Per-session answerer state. Cheap to construct (it just wraps the
/// peer) — heavy work happens inside [`accept_offer`] and the
/// background `wait_pool_open` task.
pub struct AgentTunnelPeer {
    session_id: ObjectId,
    peer: Arc<TunnelPeer>,
    /// `FlowDemux` per DC index. Populated by the `wait_pool_open`
    /// task once every DC reaches `open`. Empty until then.
    flow_demuxes: Arc<Mutex<Vec<FlowDemux>>>,
    /// Resolves once the pool is fully open and `flow_demuxes` is
    /// populated. Cloned out via [`pool_ready`] so the acceptor can
    /// wait for it before serving the first flow.
    pool_ready: Arc<tokio::sync::Notify>,
    /// #2129 — ends this peer's live flows when the peer is closed. Every
    /// flow `run_flow`-driven by the acceptor holds a handle onto it; a flow
    /// whose app/target is idle cannot end on its own when the session goes
    /// away (its DC pins the mailbox sender), so [`close`](Self::close) fires
    /// this so the flow stops and frees its dst socket + DC reference.
    flow_canceller: FlowCanceller,
}

impl AgentTunnelPeer {
    /// Build the peer + accept the SDP offer + generate an SDP answer
    /// in one step. `ice_servers` is forwarded verbatim from the
    /// server's `TunnelOpened` (the server collects them centrally).
    /// `outbound_tx` is the agent's WS outbound channel — the peer
    /// uses it to trickle local ICE candidates back to the server.
    /// `reap_tx` is the org loop's [`super::reap`] channel — where the
    /// peer reports that its client is gone (#1754).
    pub async fn accept_offer(
        session_id: ObjectId,
        offer_sdp: &str,
        ice_servers: Vec<IceServer>,
        outbound_tx: mpsc::Sender<ClientMsg>,
        reap_tx: ReapSender,
    ) -> Result<(Self, String), PeerError> {
        let rtc_ice_servers: Vec<RTCIceServer> = ice_servers
            .into_iter()
            .map(|s| RTCIceServer {
                urls: s.urls,
                username: s.username.unwrap_or_default(),
                credential: s.credential.unwrap_or_default(),
            })
            .collect();
        let peer = Arc::new(TunnelPeer::new(rtc_ice_servers).await?);

        // Trickle local candidates → outbound channel as
        // `rc:tunnel.ice`. Drop is fine on a closed channel — means
        // the WS is gone, and the next state transition will tear
        // the peer down.
        {
            let outbound = outbound_tx.clone();
            peer.on_local_ice_candidate(move |c| {
                let outbound = outbound.clone();
                Box::pin(async move {
                    let Some(c) = c else {
                        return;
                    };
                    let init = match c.to_json() {
                        Ok(i) => i,
                        Err(e) => {
                            warn!(%e, "local candidate to_json failed");
                            return;
                        }
                    };
                    let candidate = match serde_json::to_value(&init) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(%e, "local candidate serialise failed");
                            return;
                        }
                    };
                    if let Err(e) = outbound
                        .send(ClientMsg::TunnelIce {
                            session_id,
                            candidate,
                        })
                        .await
                    {
                        debug!(%session_id, %e, "tunnel ICE trickle dropped (channel closed)");
                    }
                })
            });
        }

        // #1754 — the agent's OWN observation that the client is gone,
        // independent of any terminate the client or the server sends.
        // Nothing else removes a peer from the loop's session map, so a
        // client that never sent its terminate (an older CLI, a crash, a
        // network that vanished) used to leave the peer — every ICE
        // socket, the whole DC pool — in the map for the life of the WS.
        //
        // Two signals, one fast and one certain:
        //  * a pool DC's `on_close`: the remote closed its peer cleanly and
        //    every channel's read loop hit EOF, within milliseconds;
        //  * the peer connection's `Failed`: ICE has not heard the remote
        //    for its disconnected + failed timeouts (5 s + 25 s in the
        //    vendored webrtc-ice) while both ends ping every 2 s. It is
        //    terminal — tunnel-core has no ICE restart — and it frees
        //    nothing by itself: only `close()` releases the sockets.
        // `Closed` is also reported; it only follows a LOCAL close, so it
        // is the net under any close that skipped the map. NOT
        // `Disconnected`: that is five seconds of silence, which a relay
        // hiccup or a laptop's Wi-Fi roam produces and recovers from on
        // its own, and a healthy tunnel must never be torn down for it.
        //
        // Idle is not gone. An open tunnel with no flow traffic for hours
        // still exchanges ICE binding requests every 2 s and DC keepalives
        // every 20 s, so neither signal can fire while the client lives.
        //
        // The handlers capture the sender, the id and a latch — never the
        // peer — so no handler keeps its own connection alive (the cycle
        // #1740 found in the RC control channel), and the latch makes a
        // peer report ONCE however many of its nine handlers fire. The
        // channels get their handler here, before the handshake: a
        // channel's read loop (the only thing that fires `on_close`) only
        // starts when it opens, so nothing can fire early, and there is no
        // window between a channel opening and its handler being armed.
        let reported = Arc::new(AtomicBool::new(false));
        {
            let reap = reap_tx.clone();
            let reported = Arc::clone(&reported);
            peer.peer_connection()
                .on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
                    let signal = match s {
                        RTCPeerConnectionState::Failed => Some(ReapSignal::PcFailed),
                        RTCPeerConnectionState::Closed => Some(ReapSignal::PcClosed),
                        _ => None,
                    };
                    if let Some(signal) = signal
                        && !reported.swap(true, Ordering::SeqCst)
                    {
                        reap::notify(&reap, TunnelReap { session_id, signal });
                    }
                    Box::pin(async {})
                }));
        }
        for idx in 0..peer.pool_size() {
            let Some(dc) = peer.dc(idx) else {
                continue;
            };
            let reap = reap_tx.clone();
            let reported = Arc::clone(&reported);
            dc.on_close(Box::new(move || {
                if !reported.swap(true, Ordering::SeqCst) {
                    reap::notify(
                        &reap,
                        TunnelReap {
                            session_id,
                            signal: ReapSignal::DcClosed,
                        },
                    );
                }
                Box::pin(async {})
            }));
        }

        // Generate the answer. set_local_description happens inside.
        let answer = peer.accept_offer(offer_sdp).await?;

        let flow_demuxes = Arc::new(Mutex::new(Vec::new()));
        let pool_ready = Arc::new(tokio::sync::Notify::new());

        // Background task: wait for the DC pool to open, then build
        // the FlowDemuxes. Spawned here so the SDP/ICE path doesn't
        // block on the long async wait_pool_open call.
        let demuxes_for_task = Arc::clone(&flow_demuxes);
        let pool_ready_for_task = Arc::clone(&pool_ready);
        let peer_for_task = Arc::clone(&peer);
        tokio::spawn(async move {
            match peer_for_task.wait_pool_open().await {
                Ok(()) => {
                    let pool_size = peer_for_task.pool_size();
                    let mut demuxes = Vec::with_capacity(pool_size as usize);
                    for idx in 0..pool_size {
                        let Some(dc) = peer_for_task.dc(idx) else {
                            warn!(%session_id, idx, "pool_open succeeded but dc({idx}) None — pool corrupt");
                            return;
                        };
                        // Agent target side has no session throughput aggregate
                        // (the `flows` verb reports the daemon's CLIENT flows).
                        demuxes.push(FlowDemux::install(dc, None).await);
                    }
                    // Idle keepalive: mirror the client — webrtc-dc has no
                    // built-in keepalive, so send a tiny frame over dc(0)
                    // periodically to keep the TURN-relay permission / NAT
                    // mapping warm. Detached; self-exits when the pool drops.
                    if let Some(first) = demuxes.first() {
                        tunnel_core::forward::spawn_dc_keepalive(first.dc());
                    }
                    *demuxes_for_task.lock().await = demuxes;
                    info!(%session_id, pool_size, "agent tunnel DC pool open + demuxes installed");
                    pool_ready_for_task.notify_waiters();
                }
                Err(e) => {
                    warn!(%session_id, %e, "agent tunnel pool failed to open");
                }
            }
        });

        Ok((
            Self {
                session_id,
                peer,
                flow_demuxes,
                pool_ready,
                flow_canceller: FlowCanceller::new(),
            },
            answer.sdp,
        ))
    }

    /// Forward a remote ICE candidate from the server into the peer.
    pub async fn add_remote_ice(&self, candidate: serde_json::Value) -> Result<(), PeerError> {
        let init: RTCIceCandidateInit = serde_json::from_value(candidate).map_err(|e| {
            PeerError::InvalidIceCandidate(format!("candidate JSON shape mismatch: {e}"))
        })?;
        self.peer.add_remote_ice_candidate(init).await
    }

    /// Wait until the DC pool is fully open + every demux is
    /// installed. Idempotent; resolves immediately if already ready.
    pub async fn wait_pool_ready(&self, timeout: std::time::Duration) -> bool {
        if !self.flow_demuxes.lock().await.is_empty() {
            return true;
        }
        let notified = self.pool_ready.notified();
        tokio::pin!(notified);
        let waited = tokio::time::timeout(timeout, notified.as_mut()).await;
        if waited.is_err() {
            return false;
        }
        // Double-check — `notify_waiters` only wakes pending waiters,
        // not new ones, so a slow consumer that registered between
        // wake + check could see an empty Vec. Re-read to be sure.
        !self.flow_demuxes.lock().await.is_empty()
    }

    /// Number of DCs in the pool. Stable at [`tunnel_core::transport::
    /// webrtc_dc::POOL_SIZE`] once the pool opens; 0 before that.
    pub async fn pool_size(&self) -> u8 {
        self.flow_demuxes.lock().await.len() as u8
    }

    /// Borrow the [`FlowDemux`] for `dc_index`. None if the pool
    /// hasn't fully opened yet OR the index is out of range. Caller
    /// should use [`wait_pool_ready`] before invoking.
    pub async fn demux(&self, dc_index: u8) -> Option<FlowDemux> {
        let guard = self.flow_demuxes.lock().await;
        guard.get(dc_index as usize).cloned()
    }

    /// #2129 — a handle the acceptor hands to each `run_flow`, so that
    /// [`close`](Self::close) ends the flow even if its app/target is idle.
    pub fn flow_cancel(&self) -> FlowCancel {
        self.flow_canceller.handle()
    }

    /// Build a `HalfCloseSink` that emits `ClientMsg::TcpHalfClose
    /// { direction: DstToSrc }` over the agent's WS outbound channel.
    /// The agent's "local" side of a flow is the dialed destination,
    /// so when its TCP read half hits EOF the half-close direction is
    /// always `DstToSrc` (destination → source = agent → client).
    pub fn half_close_sink(
        &self,
        outbound_tx: mpsc::Sender<ClientMsg>,
    ) -> tunnel_core::forward::HalfCloseSink {
        let session_id = self.session_id;
        Arc::new(move |flow_id: u32| {
            let outbound = outbound_tx.clone();
            tokio::spawn(async move {
                let _ = outbound
                    .send(ClientMsg::TcpHalfClose {
                        session_id,
                        flow_id,
                        direction: roomler_ai_remote_control::signaling::Direction::DstToSrc,
                    })
                    .await;
            });
        })
    }

    /// Close the peer + drop every flow. Idempotent. Caller is
    /// responsible for removing the peer from any agent-side session
    /// map before calling; this is just the resource teardown.
    /// Synchronous cut for a shared lease, independent of the signaling pump.
    pub fn stop_serving(&self) {
        self.flow_canceller.cancel();
    }
    pub async fn close(&self) {
        // #2129 — end every live flow FIRST, so an idle flow's pump returns
        // (closing its dst socket and releasing its DC reference) instead of
        // hanging on a session that is going away. Every real teardown path
        // reaches this one method — the terminate arm, the #1754 reap and the
        // WS-disconnect sweep (`close_all_tunnel_peers`) — so the trigger
        // lives in one place. A peer that is KEPT (never closed) keeps its
        // flows: the cancel is tied to `close`, not to any loop exit.
        self.flow_canceller.cancel();
        if let Err(e) = self.peer.peer_connection().close().await {
            debug!(session_id = %self.session_id, %e, "TunnelPeer close errored");
        }
        self.flow_demuxes.lock().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roomler_ai_remote_control::signaling::CloseReason;
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc::error::TryRecvError;
    use tunnel_core::transport::webrtc_dc::TunnelPeer as CoreTunnelPeer;

    /// A local offerer (= the CLI's role) + answerer (= this module's
    /// role) pair with no signaling server: ICE is bridged by draining the
    /// answerer's outbound channel into the offerer and by a closure on
    /// the offerer, and the answerer reports on `reap_rx`.
    struct Pair {
        session_id: ObjectId,
        offerer: CoreTunnelPeer,
        answerer: AgentTunnelPeer,
        reap_rx: mpsc::Receiver<TunnelReap>,
        drain: tokio::task::JoinHandle<()>,
    }

    /// Headroom for ICE on a loaded runner (the handshake takes <1 s
    /// locally) — the same figure `webrtc_dc`'s pool tests use.
    const POOL_READY: Duration = Duration::from_secs(30);

    async fn open_pair() -> Pair {
        let session_id = ObjectId::new();

        // Build the offerer locally — same code path as the CLI.
        let offerer = CoreTunnelPeer::new(vec![]).await.unwrap();
        let offer = offerer.create_offer().await.unwrap();

        // Outbound channel the answerer uses to trickle its local ICE
        // candidates; the drain task below bridges them into the offerer.
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<ClientMsg>(64);
        let (reap_tx, reap_rx) = mpsc::channel::<TunnelReap>(reap::TUNNEL_REAP_CAP);

        let (answerer, answer_sdp) = AgentTunnelPeer::accept_offer(
            session_id,
            &offer.sdp,
            vec![],
            outbound_tx.clone(),
            reap_tx,
        )
        .await
        .unwrap();
        assert!(!answer_sdp.is_empty(), "answer SDP must be non-empty");

        offerer.accept_answer(&answer_sdp).await.unwrap();

        // Bridge offerer → answerer ICE candidates.
        let answerer_pc = answerer.peer.peer_connection();
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

        // Drain answerer → offerer ICE candidates (the answerer's
        // accept_offer installed a closure that pushes them into
        // outbound_tx as ClientMsg::TunnelIce).
        let offerer_pc = offerer.peer_connection();
        let drain = tokio::spawn(async move {
            while let Some(msg) = outbound_rx.recv().await {
                if let ClientMsg::TunnelIce { candidate, .. } = msg
                    && let Ok(init) = serde_json::from_value::<RTCIceCandidateInit>(candidate)
                {
                    let _ = offerer_pc.add_ice_candidate(init).await;
                }
            }
        });

        Pair {
            session_id,
            offerer,
            answerer,
            reap_rx,
            drain,
        }
    }

    /// Verifies the answerer reaches `pool_ready` and exposes a non-empty
    /// pool.
    #[tokio::test(flavor = "multi_thread")]
    async fn answerer_reaches_pool_ready() {
        let p = open_pair().await;
        let ready = p.answerer.wait_pool_ready(POOL_READY).await;
        p.drain.abort();

        assert!(
            ready,
            "answerer pool did not reach ready within {POOL_READY:?}"
        );
        assert!(p.answerer.pool_size().await > 0);
        assert!(p.answerer.demux(0).await.is_some());
        p.answerer.close().await;
        p.offerer.close().await;
    }

    /// #1754 — the fast path: a client that closes its peer cleanly (the
    /// CLI's Ctrl-C, `roomler kill` on a daemon-run forward) is reported
    /// within milliseconds through a pool DC's `on_close`, whether or not
    /// its `rc:tunnel.terminate` ever reaches us. Also locks the latch:
    /// nine handlers fire, ONE report arrives.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_that_closes_cleanly_is_reaped_at_once() {
        let mut p = open_pair().await;
        assert!(p.answerer.wait_pool_ready(POOL_READY).await, "pool ready");
        assert!(
            matches!(p.reap_rx.try_recv(), Err(TryRecvError::Empty)),
            "nothing is reaped while the pair is up"
        );

        p.offerer.close().await;

        let reap = tokio::time::timeout(Duration::from_secs(2), p.reap_rx.recv())
            .await
            .expect("the client's clean close is reported within 2 s")
            .expect("reap channel open");
        assert_eq!(reap.session_id, p.session_id);
        assert_eq!(
            reap.signal,
            ReapSignal::DcClosed,
            "a clean remote close arrives as a channel EOF, not as ICE Failed"
        );

        // The other seven channels closed too; the latch swallowed them.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            matches!(p.reap_rx.try_recv(), Err(TryRecvError::Empty)),
            "one peer reports once"
        );

        p.drain.abort();
        p.answerer.close().await;
    }

    /// #1754 positive control — idle is not gone. Two open peers exchange
    /// no flow traffic for longer than ICE's whole disconnected + failed
    /// horizon (5 s + 25 s); the binding requests both ends send every 2 s
    /// keep the pair `Connected`, so nothing is reaped. Then the client
    /// closes, and the same channel reports it at once — so the silence
    /// above was the design, not a harness that cannot hear.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_idle_but_live_client_is_never_reaped() {
        /// Past the 30 s at which a SILENT remote is `Failed`.
        const IDLE: Duration = Duration::from_secs(35);

        let mut p = open_pair().await;
        assert!(p.answerer.wait_pool_ready(POOL_READY).await, "pool ready");

        tokio::time::sleep(IDLE).await;

        assert!(
            matches!(p.reap_rx.try_recv(), Err(TryRecvError::Empty)),
            "an idle but live client must never be reaped"
        );
        assert!(
            p.answerer.peer.is_connected(),
            "the idle pair is still Connected after {IDLE:?}"
        );

        p.offerer.close().await;
        let reap = tokio::time::timeout(Duration::from_secs(2), p.reap_rx.recv())
            .await
            .expect("after the idle stretch a real close is still reported at once")
            .expect("reap channel open");
        assert_eq!(reap.signal, ReapSignal::DcClosed);

        p.drain.abort();
        p.answerer.close().await;
    }

    /// #1754 — the certain path: a client that VANISHES without closing
    /// (a crash, a pulled cable, a laptop shut) is reported when ICE gives
    /// it up as `Failed`, ~30 s in, and not at the 5 s `Disconnected`
    /// horizon that a live client crosses during an ordinary blip.
    ///
    /// The client runs on a current-thread runtime of its own; parking
    /// that thread freezes every task on it — no keepalive answers, no
    /// clean close, sockets still bound — which is exactly a dead client
    /// as the agent sees it. Two runtimes so that freezing one cannot
    /// touch the agent side.
    #[test]
    fn a_client_that_vanishes_is_reaped_when_ice_fails() {
        let session_id = ObjectId::new();
        let (offer_tx, offer_rx) = tokio::sync::oneshot::channel::<String>();
        let (answer_tx, answer_rx) = tokio::sync::oneshot::channel::<String>();
        let (to_agent, mut from_client) = mpsc::unbounded_channel::<RTCIceCandidateInit>();
        let (to_client, mut from_agent) = mpsc::unbounded_channel::<RTCIceCandidateInit>();
        let (freeze_tx, freeze_rx) = tokio::sync::oneshot::channel::<()>();
        let thaw = Arc::new(AtomicBool::new(false));
        let thaw_for_client = Arc::clone(&thaw);

        let client = std::thread::Builder::new()
            .name("vanishing-client".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("client runtime");
                rt.block_on(async move {
                    let offerer = CoreTunnelPeer::new(vec![]).await.expect("offerer");
                    offerer.on_local_ice_candidate(move |c| {
                        let tx = to_agent.clone();
                        Box::pin(async move {
                            if let Some(c) = c
                                && let Ok(init) = c.to_json()
                            {
                                let _ = tx.send(init);
                            }
                        })
                    });
                    let offer = offerer.create_offer().await.expect("offer");
                    offer_tx.send(offer.sdp).expect("offer to the agent side");
                    let answer = answer_rx.await.expect("answer from the agent side");
                    offerer.accept_answer(&answer).await.expect("accept_answer");
                    let pc = offerer.peer_connection();
                    tokio::spawn(async move {
                        while let Some(init) = from_agent.recv().await {
                            let _ = pc.add_ice_candidate(init).await;
                        }
                    });
                    let _ = tokio::time::timeout(POOL_READY, offerer.wait_pool_open()).await;

                    let _ = freeze_rx.await;
                    // This is the runtime's only thread: parked, nothing on
                    // it runs again until the agent side is done.
                    while !thaw_for_client.load(Ordering::SeqCst) {
                        std::thread::park();
                    }
                    // Thawed: let the offerer close on its own runtime so
                    // the test leaves no sockets behind.
                    offerer.close().await;
                });
            })
            .expect("client thread");

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("agent runtime");
        rt.block_on(async move {
            let offer_sdp = offer_rx.await.expect("offer");
            let (outbound_tx, mut outbound_rx) = mpsc::channel::<ClientMsg>(64);
            let (reap_tx, mut reap_rx) = mpsc::channel::<TunnelReap>(reap::TUNNEL_REAP_CAP);
            let (answerer, answer_sdp) =
                AgentTunnelPeer::accept_offer(session_id, &offer_sdp, vec![], outbound_tx, reap_tx)
                    .await
                    .expect("accept_offer");
            answer_tx.send(answer_sdp).expect("answer to the client");

            // client → agent candidates, on the agent's runtime.
            let answerer_pc = answerer.peer.peer_connection();
            tokio::spawn(async move {
                while let Some(init) = from_client.recv().await {
                    let _ = answerer_pc.add_ice_candidate(init).await;
                }
            });
            // agent → client candidates (the answerer trickles them as
            // ClientMsg::TunnelIce), handed to the client's runtime.
            tokio::spawn(async move {
                while let Some(msg) = outbound_rx.recv().await {
                    if let ClientMsg::TunnelIce { candidate, .. } = msg
                        && let Ok(init) = serde_json::from_value::<RTCIceCandidateInit>(candidate)
                    {
                        let _ = to_client.send(init);
                    }
                }
            });

            assert!(answerer.wait_pool_ready(POOL_READY).await, "pool ready");
            assert!(
                matches!(reap_rx.try_recv(), Err(TryRecvError::Empty)),
                "nothing is reaped while the pair is up"
            );

            freeze_tx.send(()).expect("freeze the client");
            let frozen_at = Instant::now();

            let reap = tokio::time::timeout(Duration::from_secs(45), reap_rx.recv())
                .await
                .expect("a vanished client is reaped within 45 s")
                .expect("reap channel open");
            let took = frozen_at.elapsed();
            assert_eq!(reap.session_id, session_id);
            assert_eq!(
                reap.signal,
                ReapSignal::PcFailed,
                "a silent client is given up by ICE, not seen as a clean close"
            );
            // ICE reports `Disconnected` after 5 s of silence and `Failed`
            // only after 30 s. A reap well before that is a reap on
            // `Disconnected` — the blip a live client survives.
            assert!(
                took >= Duration::from_secs(20),
                "reaped {took:?} after the client froze — that is the Disconnected horizon, not Failed"
            );

            answerer.close().await;
        });

        thaw.store(true, Ordering::SeqCst);
        client.thread().unpark();
        client.join().expect("client thread");
    }

    /// A connected loopback TCP pair: `(accepted, the_other_end)`. `run_flow`
    /// drives the accepted side; the test holds the other end so it can watch
    /// for EOF/RST when `run_flow` drops its half.
    async fn loopback_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let far = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (near, _) = l.accept().await.unwrap();
        (near, far)
    }

    /// Spawn a live, idle exit-side flow on the peer's demux(0), dialed at a
    /// loopback "dst". Returns the flow task and the far ("dst") end the test
    /// watches. The peer's own cancel handle drives it, so closing the peer
    /// must end it (#2129).
    async fn spawn_idle_exit_flow(
        peer: &AgentTunnelPeer,
    ) -> (tokio::task::JoinHandle<CloseReason>, tokio::net::TcpStream) {
        let (dst_tcp, far) = loopback_pair().await;
        let demux = peer.demux(0).await.expect("demux(0) present");
        let (from_dc, stats) = demux.register(1).await;
        let dc = demux.dc();
        let noop: tunnel_core::forward::HalfCloseSink = Arc::new(|_fid: u32| {});
        let flow = tokio::spawn(tunnel_core::forward::run_flow(
            dst_tcp,
            dc,
            1,
            from_dc,
            noop,
            stats,
            peer.flow_cancel(),
        ));
        (flow, far)
    }

    /// #2129 — a real teardown (`AgentTunnelPeer::close`, which every exit
    /// path reaches: the terminate arm, the #1754 reap, the WS-disconnect
    /// sweep) ends the peer's LIVE flows. An idle flow's `run_flow` cannot end
    /// on its own — its DC pins the mailbox sender and its dst is idle — so
    /// `close()` must cancel it: the dst socket closes (no CLOSE-WAIT) and the
    /// pump returns. Run under a timeout so a regression fails red.
    #[tokio::test(flavor = "multi_thread")]
    async fn closing_the_peer_ends_its_live_flows() {
        let p = open_pair().await;
        assert!(p.answerer.wait_pool_ready(POOL_READY).await, "pool ready");

        let (mut flow, mut far) = spawn_idle_exit_flow(&p.answerer).await;

        // Idle: the flow must not end while its session is up.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !flow.is_finished(),
            "a live flow does not end while its session is up"
        );

        // A real teardown.
        p.answerer.close().await;

        let (reason, dst_eof) = tokio::time::timeout(Duration::from_secs(2), async {
            let reason = (&mut flow).await.unwrap();
            let mut b = [0u8; 1];
            let eof = matches!(far.read(&mut b).await, Ok(0) | Err(_));
            (reason, eof)
        })
        .await
        .expect("close() must end the live flow within 2 s");
        assert!(
            matches!(reason, CloseReason::ServerTerminated),
            "the flow reports the teardown, got {reason:?}"
        );
        assert!(
            dst_eof,
            "the dst socket must be closed, not left in CLOSE-WAIT"
        );

        p.drain.abort();
        p.offerer.close().await;
    }

    /// #2129 — the exclusion. A peer that is KEPT (never `close()`d — e.g. one
    /// preserved across a control-WS reattach) keeps its live flows: the
    /// cancel is tied to `close()`, not to any particular loop exit. So the
    /// flow runs and its dst stays open for as long as the peer is kept. This
    /// is the exit-side analogue of the #1754 suite's "nothing is reaped while
    /// the pair is up".
    #[tokio::test(flavor = "multi_thread")]
    async fn a_kept_peer_keeps_its_live_flows() {
        let p = open_pair().await;
        assert!(p.answerer.wait_pool_ready(POOL_READY).await, "pool ready");

        let (mut flow, mut far) = spawn_idle_exit_flow(&p.answerer).await;

        // The peer is never closed — well past the point a teardown would have
        // ended the flow, it is still running and the dst is still open.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!flow.is_finished(), "a kept peer's flow must not end");
        let mut b = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), far.read(&mut b))
                .await
                .is_err(),
            "the dst socket stays open while the peer is kept"
        );

        // Now close for real so the test leaks nothing.
        p.answerer.close().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut flow).await;
        p.drain.abort();
        p.offerer.close().await;
    }
}
