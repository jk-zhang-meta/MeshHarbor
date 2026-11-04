// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Agent-side QUIC session peer (`quic-v1` transport).
//!
//! The QUIC analogue of [`crate::tunnel::peer::AgentTunnelPeer`]: one
//! per active tunnel session. Where the WebRTC peer pre-negotiates a
//! fixed DC pool + demuxes by `flow_id` prefix, QUIC gives each flow a
//! native bidirectional stream — so this peer's job is just:
//!
//! 1. Stand up a quinn **server** endpoint with an ephemeral
//!    self-signed cert (fingerprint shipped to the client over signaling
//!    so it can pin — there's no CA).
//! 2. Run an **accept loop** that authenticates the one client
//!    connection by the server-minted token, then reads each inbound
//!    flow stream's `flow_id` preamble and hands the stream to whichever
//!    forward is waiting for it.
//! 3. Expose [`take_flow`] so [`crate::tunnel::acceptor`] can, after
//!    dialing the destination + sending `TcpForwardAccept`, grab the
//!    client-opened QUIC stream for that `flow_id` and drive
//!    [`tunnel_core::forward::run_flow_quic`].
//!
//! Lifecycle: `ServerMsg::TunnelQuicSetup` → [`setup`] → reply
//! `ClientMsg::TunnelQuicReady { cert_fingerprint, addrs }` →
//! `ServerMsg::TcpForwardForward` per flow → acceptor dials + `take_flow`
//! → `run_flow_quic`. `TunnelTerminate` → [`close`]. Or no terminate at all
//! (#1754): the accept loop serves exactly ONE connection, so when it ends —
//! the client closed, or quinn idle-timed the connection out 30 s after the
//! client's 8 s keepalives stopped — the session is over, and the loop
//! reports that on the org loop's [`super::reap`] channel so the signaling
//! loop drops the peer, and with it the endpoint's socket and, on the
//! relayed flavours, the TURN allocation.
//!
//! **Rendezvous** uses two maps so it's order-independent: a stream may
//! arrive before OR after the acceptor registers interest (the client
//! opens the stream right after `TcpForwardAccept`, but the accept loop
//! and the acceptor run concurrently). `waiters` holds pending forwards;
//! `ready` stashes streams that arrived first.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bson::oid::ObjectId;
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, info, warn};
use tunnel_core::transport::quic::{self, QuicPeer, RecvStream, SendStream};
use tunnel_core::transport::relay::{RelayConn, RelayUdpSocket};

use super::reap::{ReapSender, ReapSignal, TunnelReap};

/// The two stream halves of one QUIC flow.
pub type FlowStreams = (SendStream, RecvStream);

/// Order-independent rendezvous between the accept loop (which produces
/// streams) and [`take_flow`] (which consumes them).
#[derive(Default)]
struct Rendezvous {
    /// Forwards awaiting their stream (registered by `take_flow`).
    waiters: HashMap<u32, oneshot::Sender<FlowStreams>>,
    /// Streams that arrived before a waiter registered.
    ready: HashMap<u32, FlowStreams>,
}

pub struct AgentQuicPeer {
    session_id: ObjectId,
    cert_fingerprint: String,
    local_addr: SocketAddr,
    rendezvous: Arc<Mutex<Rendezvous>>,
    accept_task: tokio::task::JoinHandle<()>,
    /// Keep the endpoint alive for the life of the session (dropping it
    /// closes the quinn endpoint). `_peer` is read only via the accept
    /// task's clone; held here so the session owns its lifetime.
    _peer: Arc<QuicPeer>,
    /// Phase 3d: present when this peer rides a TURN relay
    /// (QUIC-over-TURN). Held so [`permit`](Self::permit) can install a
    /// TURN permission for the client's relay address by sending one
    /// bootstrap datagram through the same allocation the endpoint uses.
    /// `None` for a direct (host-candidate) peer.
    relay: Option<Arc<dyn RelayConn>>,
    /// R4 — `Some(self pubkey hex)` when this peer serves the
    /// `quic-derp-v1` flavor; shipped in `TunnelQuicReady.derp_pubkey` so
    /// the client knows which DERP identity to dial. `None` on the
    /// TURN/direct paths.
    derp_pubkey_hex: Option<String>,
}

/// Spawn the accept loop shared by [`AgentQuicPeer::setup`],
/// [`AgentQuicPeer::setup_over_relay`] and [`AgentQuicPeer::setup_over_derp`]:
/// accept ONE client connection, validate `quic_auth_token`, then
/// rendezvous each inbound flow stream to whichever
/// [`AgentQuicPeer::take_flow`] waiter wants it (stashing streams that
/// arrive before their waiter registers).
///
/// #1754 — when the loop ends, for any reason, it reports the session on
/// `reap_tx`. It serves exactly one connection, so its end is unambiguous:
/// the client closed, quinn idle-timed the connection out (30 s, with the
/// client's 8 s keepalives gone), the client failed auth, or the endpoint
/// closed under it. An idle but live client never ends it — quinn's
/// keepalive is below its idle timeout by design. Our own `close()` ABORTS
/// the task, so it never reports a close the loop already did.
fn spawn_accept_loop(
    peer: Arc<QuicPeer>,
    session_id: ObjectId,
    quic_auth_token: String,
    rendezvous: Arc<Mutex<Rendezvous>>,
    reap_tx: ReapSender,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        serve_one_connection(peer, session_id, quic_auth_token, rendezvous).await;
        // Already on a task of our own, so the send can simply be awaited;
        // it fails only when the org loop itself is gone.
        if reap_tx
            .send(TunnelReap {
                session_id,
                signal: ReapSignal::QuicConnEnded,
            })
            .await
            .is_err()
        {
            debug!(%session_id, "agent quic: connection ended but the org loop is gone");
        }
    })
}

/// The body of the accept task: one connection, authenticated, served
/// until it ends.
async fn serve_one_connection(
    peer: Arc<QuicPeer>,
    session_id: ObjectId,
    quic_auth_token: String,
    rendezvous: Arc<Mutex<Rendezvous>>,
) {
    let conn = match peer.accept().await {
        Some(Ok(c)) => c,
        Some(Err(e)) => {
            warn!(%session_id, %e, "agent quic: accept failed");
            return;
        }
        None => {
            debug!(%session_id, "agent quic: endpoint closed before connect");
            return;
        }
    };
    // The server is no longer in the byte path — this token is what
    // authorizes the dialing client (cert-pinning already
    // authenticated US to them).
    if let Err(e) = quic::server_authenticate(&conn, &quic_auth_token).await {
        warn!(%session_id, %e, "agent quic: client auth FAILED — dropping connection");
        conn.close(1u32.into(), b"auth failed");
        return;
    }
    info!(%session_id, "agent quic: client authenticated; serving flow streams");
    loop {
        match quic::accept_flow(&conn).await {
            Ok((flow_id, send, recv)) => {
                let mut rdv = rendezvous.lock().await;
                if let Some(tx) = rdv.waiters.remove(&flow_id) {
                    // A forward is already waiting — hand it over.
                    if tx.send((send, recv)).is_err() {
                        debug!(%session_id, flow_id, "agent quic: forward dropped before stream");
                    }
                } else {
                    // Stream beat the forward — stash it.
                    rdv.ready.insert(flow_id, (send, recv));
                }
            }
            Err(e) => {
                debug!(%session_id, %e, "agent quic: accept_flow loop ended");
                break;
            }
        }
    }
}

impl AgentQuicPeer {
    /// Bind a quinn server endpoint for this session + spawn the accept
    /// loop. `bind` is the local socket to listen on (`0.0.0.0:0` in
    /// production so all interfaces are reachable; tests use
    /// `127.0.0.1:0`). The loop accepts ONE client connection,
    /// validates `quic_auth_token`, then rendezvouses inbound flow
    /// streams. Ship [`cert_fingerprint`] + [`addrs`] to the client in
    /// `ClientMsg::TunnelQuicReady`. `reap_tx` is the org loop's
    /// [`super::reap`] channel, reported on when the connection ends
    /// (#1754).
    pub fn setup(
        session_id: ObjectId,
        quic_auth_token: String,
        bind: SocketAddr,
        reap_tx: ReapSender,
    ) -> Result<Self> {
        let (peer, cert_fingerprint) =
            QuicPeer::server(bind).context("agent quic: server endpoint")?;
        let local_addr = peer.local_addr().context("agent quic: local_addr")?;
        let peer = Arc::new(peer);
        let rendezvous: Arc<Mutex<Rendezvous>> = Arc::new(Mutex::new(Rendezvous::default()));
        let accept_task = spawn_accept_loop(
            Arc::clone(&peer),
            session_id,
            quic_auth_token,
            Arc::clone(&rendezvous),
            reap_tx,
        );

        Ok(Self {
            session_id,
            cert_fingerprint,
            local_addr,
            rendezvous,
            accept_task,
            _peer: peer,
            relay: None,
            derp_pubkey_hex: None,
        })
    }

    /// Phase 3d: like [`setup`](Self::setup) but stand the quinn server
    /// endpoint up over a TURN-relayed datagram conn (QUIC-over-TURN) for
    /// symmetric-NAT / UDP-restricted nets where a direct host candidate
    /// is unreachable. `relay` is a live allocation (from
    /// [`tunnel_core::transport::relay::allocate_relay_from_ice`]); we
    /// wrap it in a [`RelayUdpSocket`] for quinn and keep a clone so
    /// [`permit`](Self::permit) can bootstrap the client's TURN
    /// permission. [`addrs`](Self::addrs) then reports the **relayed**
    /// address coturn handed out — what the client dials (over its own
    /// relay). The accept loop + auth + rendezvous are identical to the
    /// direct path.
    pub fn setup_over_relay(
        session_id: ObjectId,
        quic_auth_token: String,
        relay: Arc<dyn RelayConn>,
        reap_tx: ReapSender,
    ) -> Result<Self> {
        let local_addr = relay
            .local_addr()
            .context("agent quic relay: relayed local_addr")?;
        let sock = Arc::new(
            RelayUdpSocket::new(Arc::clone(&relay)).context("agent quic relay: socket bridge")?,
        );
        let (peer, cert_fingerprint) = QuicPeer::server_over_abstract_socket(sock)
            .context("agent quic relay: server endpoint over relay")?;
        let peer = Arc::new(peer);
        let rendezvous: Arc<Mutex<Rendezvous>> = Arc::new(Mutex::new(Rendezvous::default()));
        let accept_task = spawn_accept_loop(
            Arc::clone(&peer),
            session_id,
            quic_auth_token,
            Arc::clone(&rendezvous),
            reap_tx,
        );

        Ok(Self {
            session_id,
            cert_fingerprint,
            local_addr,
            rendezvous,
            accept_task,
            _peer: peer,
            relay: Some(relay),
            derp_pubkey_hex: None,
        })
    }

    /// R4 — like [`setup_over_relay`](Self::setup_over_relay) but the quinn
    /// server endpoint rides a DERP-backed conn (`DerpMux::tunnel_conn_for`
    /// toward the CLIENT's pubkey) with the MTU-clamped derp transport
    /// config. No TURN allocation, no [`permit`](Self::permit) step — DERP
    /// is pubkey-addressed and has no permission model. `self_pubkey_hex`
    /// is this node's own DERP identity, shipped in `TunnelQuicReady` so
    /// the client knows whom to dial back over its own mux.
    pub fn setup_over_derp(
        session_id: ObjectId,
        quic_auth_token: String,
        relay: Arc<dyn RelayConn>,
        self_pubkey_hex: String,
        reap_tx: ReapSender,
    ) -> Result<Self> {
        let local_addr = relay
            .local_addr()
            .context("agent quic derp: synth local_addr")?;
        let sock = Arc::new(
            RelayUdpSocket::new(Arc::clone(&relay)).context("agent quic derp: socket bridge")?,
        );
        let (peer, cert_fingerprint) = QuicPeer::server_over_derp(sock)
            .context("agent quic derp: server endpoint over derp conn")?;
        let peer = Arc::new(peer);
        let rendezvous: Arc<Mutex<Rendezvous>> = Arc::new(Mutex::new(Rendezvous::default()));
        let accept_task = spawn_accept_loop(
            Arc::clone(&peer),
            session_id,
            quic_auth_token,
            Arc::clone(&rendezvous),
            reap_tx,
        );

        Ok(Self {
            session_id,
            cert_fingerprint,
            local_addr,
            rendezvous,
            accept_task,
            _peer: peer,
            relay: Some(relay),
            derp_pubkey_hex: Some(self_pubkey_hex),
        })
    }

    /// R4 — this peer's DERP identity when serving `quic-derp-v1`.
    pub fn derp_pubkey_hex(&self) -> Option<&str> {
        self.derp_pubkey_hex.as_deref()
    }

    /// SHA-256 fingerprint (hex) of the ephemeral cert — pinned by the
    /// client, shipped in `ClientMsg::TunnelQuicReady`.
    pub fn cert_fingerprint(&self) -> &str {
        &self.cert_fingerprint
    }

    /// Dialable candidate addresses for the client.
    ///
    /// Bound to a specific IP (tests / explicit bind) means it is
    /// already dialable, so advertise it as-is. Bound to `0.0.0.0`
    /// (production) means we enumerate real host candidates (the primary
    /// egress interface IP with the bound port) via
    /// [`quic::host_candidates`]; the bare `0.0.0.0:port` the endpoint
    /// listens on is NOT dialable by a remote client. This is the
    /// Phase-2 (Tier 1) host-candidate step; Phase 2b appends STUN
    /// server-reflexive candidates for NAT'd hosts. If no egress route
    /// is found we fall back to the bound address so same-host dials
    /// still resolve (a failed remote dial degrades to webrtc-dc-v1).
    pub fn addrs(&self) -> Vec<String> {
        if self.local_addr.ip().is_unspecified() {
            let cands = quic::host_candidates(self.local_addr.port());
            if cands.is_empty() {
                vec![self.local_addr.to_string()]
            } else {
                cands.into_iter().map(|a| a.to_string()).collect()
            }
        } else {
            vec![self.local_addr.to_string()]
        }
    }

    /// Phase 3d: install a TURN permission for `client_addr` by sending
    /// one bootstrap datagram to it through this peer's relay allocation.
    /// The agent is the QUIC *server* and never sends first, so without a
    /// pre-installed permission for the client's relay address coturn
    /// silently drops the client's opening Initials. Called from the
    /// signaling loop on `rc:tunnel.quic.candidate`. The stray byte is
    /// discarded by the client's quinn as a too-short packet; QUIC's
    /// Initial retransmission covers any install/handshake race. A no-op
    /// (`Ok`) for a direct (non-relay) peer — there is nothing to permit.
    pub async fn permit(&self, client_addr: SocketAddr) -> Result<()> {
        match &self.relay {
            Some(relay) => {
                relay
                    .send_to(b"\x00", client_addr)
                    .await
                    .with_context(|| format!("agent quic: permit bootstrap to {client_addr}"))?;
                debug!(session_id = %self.session_id, %client_addr, "agent quic: TURN permission installed");
                Ok(())
            }
            None => {
                debug!(session_id = %self.session_id, %client_addr, "agent quic: permit on direct peer — ignoring");
                Ok(())
            }
        }
    }

    /// Register interest in `flow_id`'s inbound QUIC stream and await it.
    /// The client opens the stream right after it receives
    /// `TcpForwardAccept`; this races the accept loop, so we check the
    /// `ready` stash first (stream already arrived) before parking a
    /// waiter. Times out so a client that never opens the stream doesn't
    /// leak the forward.
    pub async fn take_flow(&self, flow_id: u32, timeout: Duration) -> Result<FlowStreams> {
        let rx = {
            let mut rdv = self.rendezvous.lock().await;
            if let Some(streams) = rdv.ready.remove(&flow_id) {
                return Ok(streams);
            }
            let (tx, rx) = oneshot::channel();
            rdv.waiters.insert(flow_id, tx);
            rx
        };
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(streams)) => Ok(streams),
            Ok(Err(_)) => {
                self.rendezvous.lock().await.waiters.remove(&flow_id);
                bail!("agent quic: flow {flow_id} rendezvous sender dropped")
            }
            Err(_) => {
                self.rendezvous.lock().await.waiters.remove(&flow_id);
                bail!("agent quic: flow {flow_id} stream not opened within {timeout:?}")
            }
        }
    }

    /// Tear down the accept loop. The endpoint closes when the last
    /// `Arc<QuicPeer>` drops with `self`. Idempotent.
    pub fn close(&self) {
        self.accept_task.abort();
        debug!(session_id = %self.session_id, "agent quic peer closed");
    }

    /// #1754 — has the one connection this peer serves already ended?
    /// The accept task's end IS that event (see [`spawn_accept_loop`]);
    /// the task reports on the reap channel as its last act, so this
    /// reads true a poll after the report lands. Read by the R3 reclaim —
    /// a whole reconnect later — so a peer whose client went away while
    /// it was parked across a control-WS reattach is dropped rather than
    /// re-adopted; its report on the reap channel is answered by an
    /// empty map either way.
    pub fn accept_ended(&self) -> bool {
        self.accept_task.is_finished()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::error::TryRecvError;
    use tunnel_core::transport::quic::QuicPeer as ClientQuicPeer;

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// A reap channel for tests that only need to hand a sender over.
    fn reap_channel() -> (ReapSender, mpsc::Receiver<TunnelReap>) {
        mpsc::channel(super::super::reap::TUNNEL_REAP_CAP)
    }

    /// Full in-process exercise of the agent QUIC session machinery (no
    /// signaling server): set up the peer, connect a pinned + token-
    /// authed client, open a flow stream, and verify the agent's
    /// `take_flow` rendezvous yields the stream and the bytes arrive.
    /// Covers BOTH rendezvous orderings via the stash + waiter paths.
    #[tokio::test(flavor = "multi_thread")]
    async fn agent_quic_rendezvous_delivers_authed_flow() {
        let session_id = ObjectId::new();
        let token = "session-token-xyz";
        let (reap_tx, _reap_rx) = reap_channel();
        let agent =
            AgentQuicPeer::setup(session_id, token.to_string(), loopback(), reap_tx).unwrap();
        let fingerprint = agent.cert_fingerprint().to_string();
        let addr: SocketAddr = agent.addrs()[0].parse().unwrap();

        // Client: pin the agent's cert, connect, authenticate.
        let client = ClientQuicPeer::client(loopback(), &fingerprint).unwrap();
        let conn = client.connect(addr).await.unwrap();
        quic::client_authenticate(&conn, token).await.unwrap();

        // Concurrently: agent waits for flow 5, client opens it + sends.
        // join! makes the ordering irrelevant — the two-map rendezvous
        // resolves whichever side lands first.
        let (taken, _opened) = tokio::join!(agent.take_flow(5, Duration::from_secs(10)), async {
            let (mut send, _recv) = quic::open_flow(&conn, 5).await.unwrap();
            send.write_all(b"hello over quic flow").await.unwrap();
            send.finish().unwrap();
        });

        let (_a_send, mut a_recv) = taken.expect("agent must receive flow 5's stream");
        // quinn's RecvStream has its own read_to_end(size_limit) → Vec.
        let buf = a_recv.read_to_end(64 * 1024).await.unwrap();
        assert_eq!(
            &buf, b"hello over quic flow",
            "flow bytes must arrive intact"
        );

        agent.close();
    }

    /// #1754 — a client that drops its connection and endpoint (a crash,
    /// a `roomler kill` on a CLI too old to send `rc:tunnel.terminate`)
    /// ends the accept loop, and the loop reports the session on the
    /// reap channel so the signaling loop drops the peer — endpoint socket
    /// and all. Nothing is reported while the client lives, and
    /// `accept_ended` flips with the report.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_that_drops_its_connection_is_reaped() {
        let session_id = ObjectId::new();
        let token = "session-token-gone";
        let (reap_tx, mut reap_rx) = reap_channel();
        let agent =
            AgentQuicPeer::setup(session_id, token.to_string(), loopback(), reap_tx).unwrap();
        let fingerprint = agent.cert_fingerprint().to_string();
        let addr: SocketAddr = agent.addrs()[0].parse().unwrap();

        let client = ClientQuicPeer::client(loopback(), &fingerprint).unwrap();
        let conn = client.connect(addr).await.unwrap();
        quic::client_authenticate(&conn, token).await.unwrap();
        // One flow, so the connection is unmistakably in service.
        let (taken, _opened) = tokio::join!(agent.take_flow(3, Duration::from_secs(10)), async {
            let (mut send, _recv) = quic::open_flow(&conn, 3).await.unwrap();
            send.write_all(b"one flow").await.unwrap();
            send.finish().unwrap();
        });
        taken.expect("agent must receive flow 3's stream");
        assert!(
            matches!(reap_rx.try_recv(), Err(TryRecvError::Empty)),
            "nothing is reaped while the client lives"
        );
        assert!(
            !agent.accept_ended(),
            "the accept loop serves a live client"
        );

        // The client goes away: its last connection handle and its
        // endpoint drop, with no terminate sent to anyone.
        drop(conn);
        drop(client);

        let reap = tokio::time::timeout(Duration::from_secs(10), reap_rx.recv())
            .await
            .expect("a dropped client is reported within 10 s")
            .expect("reap channel open");
        assert_eq!(reap.session_id, session_id);
        assert_eq!(reap.signal, ReapSignal::QuicConnEnded);
        // The task sends its report as its last act, so `accept_ended`
        // trails the message by the task's final poll — the reclaim reads
        // it a whole reconnect later, but here give it a moment.
        for _ in 0..100 {
            if agent.accept_ended() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            agent.accept_ended(),
            "the accept task ends with (just after) its report"
        );

        agent.close();
    }

    /// A client presenting the WRONG token must NOT get its flow served:
    /// the accept loop closes the connection after auth fails, so
    /// `take_flow` times out (no stream is ever rendezvoused).
    #[tokio::test(flavor = "multi_thread")]
    async fn agent_quic_rejects_bad_token_so_no_flow() {
        let session_id = ObjectId::new();
        let (reap_tx, _reap_rx) = reap_channel();
        let agent = AgentQuicPeer::setup(
            session_id,
            "the-real-token".to_string(),
            loopback(),
            reap_tx,
        )
        .unwrap();
        let addr: SocketAddr = agent.addrs()[0].parse().unwrap();
        let client = ClientQuicPeer::client(loopback(), agent.cert_fingerprint()).unwrap();
        let conn = client.connect(addr).await.unwrap();
        // Wrong token → agent auth fails → connection closed.
        let _ = quic::client_authenticate(&conn, "WRONG-token").await;

        // No flow should ever be delivered; take_flow times out fast.
        let r = agent.take_flow(7, Duration::from_millis(800)).await;
        assert!(
            r.is_err(),
            "no flow may be served to an unauthenticated client"
        );
        agent.close();
    }

    /// Phase 3d: the agent's QUIC-over-relay path. The agent peer stands
    /// up its quinn server over a [`RelayConn`] (here two loopback UDP
    /// sockets stand in for two coturn allocations — the real
    /// permission-gated TURN path is proven in tunnel-core's
    /// `quinn_runs_over_two_turn_allocations`), reports its relay addr via
    /// `addrs()`, `permit`s the client's relay addr, and a client riding
    /// its own relay socket connects + authenticates + delivers a flow
    /// through the same rendezvous the direct path uses.
    #[tokio::test(flavor = "multi_thread")]
    async fn agent_quic_over_relay_delivers_flow() {
        use tunnel_core::transport::relay::UdpRelayConn;

        let agent_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let agent_relay_addr = agent_sock.local_addr().unwrap();
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_relay_addr = client_sock.local_addr().unwrap();
        let agent_relay: Arc<dyn RelayConn> = Arc::new(UdpRelayConn(agent_sock));
        let client_relay: Arc<dyn RelayConn> = Arc::new(UdpRelayConn(client_sock));

        let session_id = ObjectId::new();
        let token = "relay-session-token";
        let (reap_tx, _reap_rx) = reap_channel();
        let agent = AgentQuicPeer::setup_over_relay(
            session_id,
            token.to_string(),
            Arc::clone(&agent_relay),
            reap_tx,
        )
        .unwrap();
        assert_eq!(
            agent.addrs(),
            vec![agent_relay_addr.to_string()],
            "a relay peer advertises its relayed address (not 0.0.0.0/host)"
        );
        let fingerprint = agent.cert_fingerprint().to_string();

        // What the signaling candidate handler does: permit the client's
        // relay addr (no-op over plain UDP, but exercises the path).
        agent.permit(client_relay_addr).await.unwrap();

        // Client endpoint over ITS relay socket, pinned to the agent cert.
        let csock = Arc::new(RelayUdpSocket::new(Arc::clone(&client_relay)).unwrap());
        let client = ClientQuicPeer::client_over_abstract_socket(csock, &fingerprint).unwrap();

        let (taken, _drive) =
            tokio::join!(agent.take_flow(9, Duration::from_secs(10)), async move {
                let conn = client.connect(agent_relay_addr).await.unwrap();
                quic::client_authenticate(&conn, token).await.unwrap();
                let (mut send, _recv) = quic::open_flow(&conn, 9).await.unwrap();
                send.write_all(b"flow bytes over the relay").await.unwrap();
                send.finish().unwrap();
                // Hold the connection open until the agent has read the flow.
                tokio::time::sleep(Duration::from_millis(300)).await;
            });

        let (_a_send, mut a_recv) = taken.expect("agent must receive flow 9 over the relay");
        let buf = a_recv.read_to_end(64 * 1024).await.unwrap();
        assert_eq!(
            &buf, b"flow bytes over the relay",
            "flow bytes must survive the relay socket bridge"
        );
        agent.close();
    }
}
