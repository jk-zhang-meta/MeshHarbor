// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! DERP client carrier — a pubkey-addressed relay for the both-UDP-blocked
//! overlay tier (NAT-traversal Phase D).
//!
//! Two nodes BOTH on all-UDP-blocked networks (a strict corp firewall that
//! permits only TCP/TLS-443) can't use single-relay — exactly one side must be
//! the raw-UDP dialer and neither has UDP. DERP breaks it: both peers dial OUT
//! to a rendezvous relay ([`crate::ws::derp`] on the server, addressed by WG
//! pubkey), so no UDP, no inbound, no TURN permission model.
//!
//! # Two pieces
//!
//! - [`DerpConn`] — a [`RelayConn`] PINNED to one peer pubkey. `send_to` frames
//!   `[peer_pubkey || payload]`; `recv_from` yields that peer's demuxed
//!   payloads. Because it is pubkey-pinned, EVERY received datagram is from the
//!   one peer, so the [`Carrier::Relay`](crate::overlay::wg::Carrier)
//!   recv-source discard is always correct — this is exactly why RAW WG rides
//!   DERP (unlike single-relay, which needed QUIC to recover the observed
//!   source under symmetric NAT).
//! - [`DerpMux`] — the per-node demux + fan-out. ONE per node: it owns the
//!   shared outbound queue and the `src_pubkey → DerpConn` inbound registry,
//!   and vends a [`DerpConn`] per peer. It is transport-agnostic (pure
//!   channels) — the owner (the agent's WS task, DERP-3) drains
//!   [`DerpMux::outbound`] into the `/derp` WSS and feeds inbound WS frames to
//!   [`DerpMux::deliver`]. That keeps `tunnel-core` free of a WebSocket
//!   dependency and makes the whole thing unit-testable without a socket.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;

use crate::transport::relay::RelayConn;

/// 32-byte WireGuard public key — the DERP addressing unit.
pub type DerpPubKey = [u8; 32];

/// Depth of a node's shared outbound WS queue (frames waiting to hit the wire).
/// Bounded so a stalled WS can't grow memory without bound; overflow drops the
/// frame (WG/QUIC are loss-tolerant — a dropped carrier datagram retransmits).
///
/// FR-18 — this bound is a MEMORY bound, not a latency one, and the difference
/// cost us seconds: 512 frames is ~33 ms of a 160 Mbps link but ~1.8 s of a
/// 3 Mbps relay, which is exactly where the corp-VPN hosts live. Latency is
/// bounded in TIME by [`queue_max_age`] at the writer instead, so this stays
/// large enough to absorb a legitimate burst.
const OUTBOUND_QUEUE: usize = 512;

/// FR-18 — a queued carrier frame plus the instant it was enqueued. The WS
/// writer discards frames older than [`queue_max_age`] rather than sending
/// them: a real-time carrier must shed stale load, and a frame that has already
/// waited longer than its useful life is worse than nothing (it occupies the
/// wire that the CURRENT frame needs, and the receiver would discard it).
pub type OutboundFrame = (Instant, Vec<u8>);

/// FR-18 — how long a frame may wait in the outbound queue before the writer
/// drops it instead of sending. Bounds this layer's latency contribution
/// independently of the link rate. `0` disables the check entirely (the
/// pre-FR-18 behaviour) — the kill switch.
///
/// Default 100 ms: comfortably above a healthy relay's queueing (measured
/// sub-ms on a drained pipe) and far below the multi-second stalls that
/// motivated it.
pub fn queue_max_age() -> Option<Duration> {
    let ms = crate::env::node_env("DERP_QUEUE_MAX_AGE_MS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(100);
    (ms > 0).then(|| Duration::from_millis(ms))
}

/// Depth of a single peer's inbound payload queue. Same drop-on-overflow.
const INBOUND_QUEUE: usize = 256;

/// #27 — depth of the mux→runtime event queue. Tiny on purpose: the consumer
/// coalesces per peer anyway, and [`MuxEvent::Unrouted`] is level-triggered in
/// practice (a demoted peer keeps sending until we follow it), so dropping a
/// notice under burst costs at most one more inbound frame's worth of delay,
/// never the signal itself.
const EVENT_QUEUE: usize = 32;

// A late carrier-intent control frame is not evidence that a WG peer has
// demoted. This stays wire-shape-only because the mux does not own WG keys;
// the live WG owner performs the actual HMAC/nonce/epoch checks.
fn is_follow_control(payload: &[u8]) -> bool {
    payload.len() == 160 && payload.starts_with(b"RMDISCO1")
        && matches!(payload[8], 3..=6) && payload[9..16] == [0; 7]
}

/// #27/#28 — something happened on this mux that the RUNTIME must react to.
/// One channel rather than one per signal, so a mux acquired later (the
/// coordinator arms each as it arrives) can never be half-wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxEvent {
    /// #27 — a peer is relaying to us over DERP and we hold no [`DerpConn`] for
    /// it, which means that peer has demoted and we have not followed. Carries
    /// the RELAY-STAMPED source pubkey (see [`DerpMux::deliver`]).
    Unrouted(DerpPubKey),
    /// #28 — the `/derp` WS reconnected and re-registered after an outage.
    /// EDGE-triggered (a `mark_up` that changes nothing emits nothing), so the
    /// startup `mark_up` on a mux that was never down is silent.
    ///
    /// Worth waking the runtime for because every DERP build made while the WS
    /// was down was WITHHELD (`try_build_derp` refuses over a dead WS — a
    /// carrier born there convicts one-way and rebuilds forever), and those
    /// peers otherwise wait for the next establish walk. Field 2026-08-24: the
    /// WS was back in 1.5 s and the floor still took **5 s** more, because the
    /// walk runs on the 5 s tick.
    Recovered,
}

/// A [`RelayConn`] over a DERP relay, PINNED to one peer pubkey.
///
/// `send_to` ignores its `SocketAddr` argument (DERP is pubkey-addressed, not
/// IP-addressed) and frames `[peer_pubkey || payload]` onto the node's shared
/// outbound queue. `recv_from` returns this peer's next demuxed payload tagged
/// with a stable synthetic source address — the carrier only needs a
/// CONSISTENT remote, not a routable one.
pub struct DerpConn {
    peer_pubkey: DerpPubKey,
    /// The node's shared WS write queue (cloned from the [`DerpMux`]).
    ws_out: mpsc::Sender<OutboundFrame>,
    /// This peer's demuxed inbound payloads (the mux routes frames whose
    /// `src_pubkey == peer_pubkey` here).
    inbound: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    /// The node WS's liveness. When the WS is down, `send_to` returns `Err` so
    /// the [`Carrier::Relay`](crate::overlay::wg::Carrier) `dead` latch fires
    /// and the health sweep rebuilds — never silently queue onto a dead WS.
    alive: Arc<AtomicBool>,
    /// Stable synthetic addresses derived from the pubkeys. Same-family (v4),
    /// nonzero port, unique per peer — cosmetic for the raw carrier (the `dst`
    /// is discarded), but keeps a future QUIC-over-DERP path valid (quinn
    /// rejects a family-mismatched or zero-port remote).
    synth_local: SocketAddr,
    synth_peer: SocketAddr,
    /// #32 — the mux's route table, WHICH slot this conn owns, and OUR sender
    /// in it, so [`Drop`] can retire exactly our own route and never a newer
    /// one (nor the other consumer's).
    peers: PeerTable,
    route: RouteKind,
    self_tx: mpsc::Sender<Vec<u8>>,
}

/// #32 — which of a peer's inbound routes a [`DerpConn`] owns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RouteKind {
    /// The WG/carrier consumer ([`DerpMux::conn_for`]).
    Wg,
    /// R4's tunnel consumer ([`DerpMux::tunnel_conn_for`]).
    Tunnel,
    /// FR-90 P2d-2c — one Hive replica stream, by its tag
    /// ([`DerpMux::hive_conn_for`]).
    Hive(HiveStreamTag),
}

/// FR-90 P2d-2c — the prefix of a Hive replica stream's payload on the DERP
/// leg, ahead of its [`HiveStreamTag`] and the QUIC packet. Eight bytes, like
/// the disco magic: WireGuard's header never opens on it, disco's magic is
/// another, and a QUIC packet that does is a 2^-64 event.
pub const HIVE_MAGIC: &[u8; 8] = b"RMHIVE01";

/// F2 — a STANDBY copy: a WG data datagram its sender ALSO carries on a
/// direct carrier it currently suspects, duplicated here so the stream rides
/// out the suspicion. It goes to the peer's standby sink and nowhere else; a
/// miss is counted, never `Unrouted`, because the sender has not demoted and
/// #27 must not follow a suspicion. Sent only to a peer that announced it
/// takes standby copies: an older receiver would route it as a demotion.
pub const STANDBY_MAGIC: &[u8; 8] = b"RMSTBY01";

/// FR-90 P2d-2c — which Hive stream a payload belongs to: its grant's id, 12
/// bytes. A peer pair carries any number of streams at once (two sessions,
/// a renewal beside the grant it replaces), where the tunnel's route is one
/// per peer.
pub type HiveStreamTag = [u8; 12];

/// The bytes a Hive frame carries ahead of its packet.
const HIVE_HEADER_LEN: usize = HIVE_MAGIC.len() + std::mem::size_of::<HiveStreamTag>();

/// #32 — a route must not outlive the conn that consumes it.
///
/// The table was written and never cleaned: the vend methods insert, "last one
/// wins" replaces, and nothing ever removes. That is safe only while a dropped
/// `DerpConn` also closes its channel — and `deliver` only *reports* a miss
/// when `try_send` FAILS, so a route left pointing at a channel that is somehow
/// still open would swallow frames in a queue nobody drains, silently. Making
/// the route's lifetime the consumer's lifetime is the invariant `deliver`
/// already assumes; nothing enforced it.
///
/// Same class as "an `RTCPeerConnection` must be `close()`d": bookkeeping
/// outliving its owner.
impl Drop for DerpConn {
    fn drop(&mut self) {
        let mut peers = self.peers.lock().unwrap();
        let Some(routes) = peers.get_mut(&self.peer_pubkey) else {
            return;
        };
        // ⚠️ Only OUR slot, and only if it is STILL ours. A rebuild registers
        // the new conn BEFORE the old one drops ("last one wins"), so clearing
        // blindly would unregister the LIVE consumer — turning a hypothetical
        // silent drop into a guaranteed one. And the two slots are independent
        // consumers: a WG carrier going away must not take R4's tunnel route
        // with it.
        match self.route {
            RouteKind::Hive(tag) => {
                if routes
                    .hive
                    .get(&tag)
                    .is_some_and(|tx| tx.same_channel(&self.self_tx))
                {
                    routes.hive.remove(&tag);
                }
            }
            RouteKind::Wg | RouteKind::Tunnel => {
                let slot = if self.route == RouteKind::Wg {
                    &mut routes.wg
                } else {
                    &mut routes.tunnel
                };
                if slot
                    .as_ref()
                    .is_some_and(|tx| tx.same_channel(&self.self_tx))
                {
                    *slot = None;
                }
            }
        }
        if routes.wg.is_none()
            && routes.tunnel.is_none()
            && routes.hive.is_empty()
            && routes.standby.is_none()
        {
            peers.remove(&self.peer_pubkey);
        }
    }
}

/// #32 — the route table, shared with every [`DerpConn`] so a conn can retire
/// its own route on drop (see that `Drop` impl).
type PeerTable = Arc<Mutex<HashMap<DerpPubKey, PeerRoutes>>>;

/// One peer's inbound routes on the mux — the WG/carrier consumer (today's
/// [`DerpMux::conn_for`]) and, since R4, an optional TUNNEL consumer
/// ([`DerpMux::tunnel_conn_for`]) carrying QUIC for the tunnel's
/// `quic-derp-v1` flavor over the SAME established `/derp` WS. Split per
/// frame by [`classify_payload`]; with no tunnel consumer registered the
/// behavior is byte-identical to the pre-R4 single-route mux.
#[derive(Default)]
struct PeerRoutes {
    wg: Option<mpsc::Sender<Vec<u8>>>,
    tunnel: Option<mpsc::Sender<Vec<u8>>>,
    /// FR-90 P2d-2c — Hive replica streams to this peer, by tag; split from
    /// the rest by [`HIVE_MAGIC`] before anything else is read.
    hive: HashMap<HiveStreamTag, mpsc::Sender<Vec<u8>>>,
    /// F2 — the standby sink for [`STANDBY_MAGIC`] copies from this peer.
    standby: Option<mpsc::Sender<Vec<u8>>>,
}

/// Which consumer an inbound DERP payload belongs to: WireGuard and disco to
/// the carrier, everything else to a tunnel consumer, by the whole 4-byte
/// WireGuard header (#2002). Since FR-115 P4a-2 the definition (and its
/// history) lives in `remote_control::derp_frame`, so the regional PoP
/// relays read frames by this very function; the path here is unchanged.
pub use roomler_ai_remote_control::derp_frame::payload_is_wg_or_disco;
// The disco magic, from the same module; the feature-gated test below
// asserts it equals `overlay::disco::MAGIC`.
#[cfg(test)]
use roomler_ai_remote_control::derp_frame::DISCO_MAGIC;

/// R4 — everything the tunnel driver needs to run the `quic-derp-v1` flavor:
/// the node's established DERP mux + its own pubkey (hex, as it travels on
/// the wire). Built by the daemon (an overlay node); the standalone CLI has
/// no overlay identity and passes `None`, keeping the classic ladder.
#[derive(Clone)]
pub struct DerpTunnelHandle {
    pub mux: Arc<DerpMux>,
    pub self_pubkey_hex: String,
}

/// Parse a 64-char lowercase-hex DERP/WG pubkey off the wire. `None` on any
/// malformation — the caller falls back rather than panicking on peer input.
pub fn parse_pubkey_hex(s: &str) -> Option<DerpPubKey> {
    let bytes = hex::decode(s.trim()).ok()?;
    bytes.try_into().ok()
}

/// Hex-encode a DERP pubkey for the wire.
pub fn pubkey_hex(pk: &DerpPubKey) -> String {
    hex::encode(pk)
}

/// A stable, non-routable synthetic `SocketAddr` derived from a pubkey:
/// `127.<pk0>.<pk1>.<pk2|1>:<pk3pk4 | 0x8000>`. Deterministic + unique enough
/// per peer; only used as a carrier "remote" placeholder.
fn synth_addr(pk: &DerpPubKey) -> SocketAddr {
    let ip = Ipv4Addr::new(127, pk[0], pk[1], pk[2].max(1));
    let port = u16::from_be_bytes([pk[3], pk[4]]) | 0x8000;
    SocketAddr::new(IpAddr::V4(ip), port)
}

impl DerpConn {
    /// This conn's stable synthetic PEER address — the placeholder `dst` a
    /// [`Carrier::relay`](crate::overlay::wg::Carrier) is built with. The DERP
    /// carrier discards it on recv (pubkey-pinned), so it only needs to be
    /// consistent and valid.
    pub fn synth_peer(&self) -> SocketAddr {
        self.synth_peer
    }
}

#[async_trait]
impl RelayConn for DerpConn {
    // DERP is always the server's `/derp` WebSocket, i.e. TCP — which is why
    // it reads slower than a coturn UDP hop and why the two must not both
    // print a bare "relay". The mux owns the URL, not the per-peer conn, so
    // `relay_server` stays `None` here rather than guessing.
    fn relay_transport(&self) -> crate::transport::relay::RelayTransport {
        crate::transport::relay::RelayTransport::Tcp
    }

    async fn send_to(&self, buf: &[u8], _dst: SocketAddr) -> io::Result<usize> {
        if !self.alive.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "derp ws down",
            ));
        }
        let mut frame = Vec::with_capacity(32 + HIVE_HEADER_LEN + buf.len());
        frame.extend_from_slice(&self.peer_pubkey);
        if let RouteKind::Hive(tag) = &self.route {
            frame.extend_from_slice(HIVE_MAGIC);
            frame.extend_from_slice(tag);
        }
        frame.extend_from_slice(buf);
        match self.ws_out.try_send((Instant::now(), frame)) {
            Ok(()) => Ok(buf.len()),
            // Backpressure: drop this datagram (loss-tolerant carrier). NOT an
            // error — a full transient queue must not latch the carrier dead.
            Err(mpsc::error::TrySendError::Full(_)) => Ok(buf.len()),
            // The WS write task is gone → the carrier IS dead. Return `Err` so
            // the `dead` latch fires and the sweep rebuilds.
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "derp ws closed",
            )),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.inbound.lock().await;
        match rx.recv().await {
            Some(payload) => {
                let n = payload.len().min(buf.len());
                buf[..n].copy_from_slice(&payload[..n]);
                Ok((n, self.synth_peer))
            }
            None => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "derp inbound closed",
            )),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.synth_local)
    }
}

/// The per-node DERP demux + fan-out. Owns the shared outbound queue and the
/// `src_pubkey → inbound` registry; vends a [`DerpConn`] per peer. ONE per node.
///
/// Transport-agnostic: the owner drives the actual WSS by draining the receiver
/// returned from [`DerpMux::new`] into the socket and feeding inbound WS frames
/// to [`DerpMux::deliver`]. On WS loss it calls [`DerpMux::mark_down`]; after a
/// reconnect + re-register, [`DerpMux::mark_up`]. The outbound receiver lives
/// for the mux's whole life (across reconnects), so a reconnect never severs
/// the `DerpConn`→WS path.
pub struct DerpMux {
    self_pubkey: DerpPubKey,
    ws_out: mpsc::Sender<OutboundFrame>,
    alive: Arc<AtomicBool>,
    /// When the CURRENT outage began (`None` while up). Lets the evidence
    /// path distinguish a reconnect blip from a sustained WSS outage — the
    /// U1 healer must not clear force-DERP pins on a flap (Phase A1).
    down_since: Mutex<Option<Instant>>,
    peers: PeerTable,
    /// #27/#28 — where this mux reports [`MuxEvent`]s to the runtime. `None`
    /// until the runtime arms it (tests, and the tunnel-only paths that never
    /// demote, leave it unset).
    events_tx: Mutex<Option<mpsc::Sender<MuxEvent>>>,
    /// Lifetime count of frames dropped by `deliver`, split by cause. Read by
    /// the LocalAPI/diagnostics; the point is that neither drop is silent any
    /// more (they both were — see the `deliver` doc).
    dropped_unrouted: Arc<std::sync::atomic::AtomicU64>,
    dropped_backpressure: Arc<std::sync::atomic::AtomicU64>,
    /// FR-18 — OUTBOUND frames the WS writer discarded because they had waited
    /// longer than [`queue_max_age`]. Deliberately a separate counter from the
    /// inbound ones above: a rising `dropped_stale` with steady delivered fps is
    /// the carrier shedding load correctly, which reads nothing like a drop
    /// caused by a full queue or a missing route.
    dropped_stale: Arc<std::sync::atomic::AtomicU64>,
    /// FR-90 P2d-2c — Hive frames dropped: no stream by that tag (it ended
    /// here first), a full queue, or a frame cut short. A counter of its own,
    /// since none of these says anything about the carrier the overlay reads
    /// `dropped_unrouted` for.
    dropped_hive: Arc<std::sync::atomic::AtomicU64>,
    /// F2 — STANDBY copies with no standby sink to take them.
    dropped_standby: Arc<std::sync::atomic::AtomicU64>,
}

impl DerpMux {
    /// Create a mux for a node with `self_pubkey`. Returns the mux and the
    /// outbound frame receiver the WS owner must drain for the mux's lifetime.
    /// Starts `alive = true` (the owner sets it `false`/`true` around a
    /// reconnect).
    pub fn new(self_pubkey: DerpPubKey) -> (Arc<Self>, mpsc::Receiver<OutboundFrame>) {
        let (ws_out, ws_out_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mux = Arc::new(Self {
            self_pubkey,
            ws_out,
            alive: Arc::new(AtomicBool::new(true)),
            down_since: Mutex::new(None),
            peers: Arc::new(Mutex::new(HashMap::new())),
            events_tx: Mutex::new(None),
            dropped_unrouted: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dropped_backpressure: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dropped_stale: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dropped_hive: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dropped_standby: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        (mux, ws_out_rx)
    }

    /// #27/#28 — install the runtime's [`MuxEvent`] sink. A SETTER rather than
    /// a subscribe-and-return because a node holds several muxes (central + one
    /// per relay region) and the runtime wants ONE channel for all of them; the
    /// coordinator installs this on every mux as it arrives. A second call
    /// replaces the sender, so a runtime rebuild re-points cleanly.
    pub fn set_event_sink(&self, tx: mpsc::Sender<MuxEvent>) {
        *self.events_tx.lock().unwrap() = Some(tx);
    }

    /// The channel depth callers should use for [`Self::set_event_sink`].
    pub const EVENT_SINK_DEPTH: usize = EVENT_QUEUE;

    /// #27 — `(unrouted, backpressure)` inbound-drop counts for this mux,
    /// cumulative for its lifetime.
    pub fn drop_counts(&self) -> (u64, u64) {
        (
            self.dropped_unrouted.load(Ordering::Relaxed),
            self.dropped_backpressure.load(Ordering::Relaxed),
        )
    }

    /// FR-18 — the WS owner calls this when it discards a frame that waited
    /// past [`queue_max_age`]. The mux owns the counter (not the writer task)
    /// because the writer is rebuilt on every reconnect and the count must
    /// survive that.
    pub fn note_stale_drop(&self) {
        self.dropped_stale.fetch_add(1, Ordering::Relaxed);
    }

    /// FR-18 — lifetime count of outbound frames shed for staleness.
    pub fn stale_drops(&self) -> u64 {
        self.dropped_stale.load(Ordering::Relaxed)
    }

    /// The first frame to send on a fresh `/derp` WS: this node's own pubkey
    /// (the server validates it against the node's `overlay_nodes` row).
    pub fn registration_frame(&self) -> Vec<u8> {
        self.self_pubkey.to_vec()
    }

    /// Vend a [`DerpConn`] pinned to `peer_pubkey`, registering its inbound
    /// route. A later `conn_for` for the same peer (a carrier rebuild) replaces
    /// the route — last one wins, so stale inbound senders never accumulate.
    pub fn conn_for(&self, peer_pubkey: DerpPubKey) -> DerpConn {
        let (in_tx, in_rx) = mpsc::channel(INBOUND_QUEUE);
        self.peers
            .lock()
            .unwrap()
            .entry(peer_pubkey)
            .or_default()
            .wg = Some(in_tx.clone());
        self.build_conn(peer_pubkey, in_rx, RouteKind::Wg, in_tx)
    }

    /// R4 — vend a [`DerpConn`] for the TUNNEL's `quic-derp-v1` flavor toward
    /// `peer_pubkey`, sharing this mux's established `/derp` WS with the WG
    /// carrier for the same peer. Inbound frames are split per packet by
    /// [`payload_is_wg_or_disco`]; outbound framing is identical (the far
    /// end's mux does the same split). Last one wins per peer, like
    /// [`Self::conn_for`] — a new tunnel session replaces the previous
    /// session's route.
    pub fn tunnel_conn_for(&self, peer_pubkey: DerpPubKey) -> DerpConn {
        let (in_tx, in_rx) = mpsc::channel(INBOUND_QUEUE);
        self.peers
            .lock()
            .unwrap()
            .entry(peer_pubkey)
            .or_default()
            .tunnel = Some(in_tx.clone());
        self.build_conn(peer_pubkey, in_rx, RouteKind::Tunnel, in_tx)
    }

    /// FR-90 P2d-2c — vend a [`DerpConn`] for one Hive replica stream toward
    /// `peer_pubkey`, tagged `tag` (its grant's id), on this mux's established
    /// `/derp` WS. Its payloads travel as `[HIVE_MAGIC || tag || packet]`, and
    /// [`Self::deliver`] routes them by `(src, tag)` before anything else, so
    /// any number of streams share a pair, and none of them touches the
    /// peer's WG or tunnel route. ⚠️ Not [`Self::tunnel_conn_for`]: that
    /// route is one per peer, last one wins, so a stream on it would take a
    /// `quic-derp-v1` tunnel's route between the same two devices.
    pub fn hive_conn_for(&self, peer_pubkey: DerpPubKey, tag: HiveStreamTag) -> DerpConn {
        let (in_tx, in_rx) = mpsc::channel(INBOUND_QUEUE);
        self.peers
            .lock()
            .unwrap()
            .entry(peer_pubkey)
            .or_default()
            .hive
            .insert(tag, in_tx.clone());
        self.build_conn(peer_pubkey, in_rx, RouteKind::Hive(tag), in_tx)
    }

    /// FR-90 P2d-2c — Hive frames this mux dropped, cumulative.
    pub fn hive_drops(&self) -> u64 {
        self.dropped_hive.load(Ordering::Relaxed)
    }

    /// F2 — register `peer_pubkey`'s standby sink: its [`STANDBY_MAGIC`]
    /// copies arrive on the returned receiver with the magic stripped. A second
    /// call replaces the first (whose receiver then sees its channel close).
    pub fn standby_route(&self, peer_pubkey: DerpPubKey) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
        self.peers
            .lock()
            .unwrap()
            .entry(peer_pubkey)
            .or_default()
            .standby = Some(tx);
        rx
    }

    /// F2 — retire `peer_pubkey`'s standby sink; later copies are counted drops.
    pub fn clear_standby(&self, peer_pubkey: &DerpPubKey) {
        let mut peers = self.peers.lock().unwrap();
        let Some(routes) = peers.get_mut(peer_pubkey) else {
            return;
        };
        routes.standby = None;
        if routes.wg.is_none() && routes.tunnel.is_none() && routes.hive.is_empty() {
            peers.remove(peer_pubkey);
        }
    }

    /// F2 — STANDBY copies that found no standby sink.
    pub fn standby_drops(&self) -> u64 {
        self.dropped_standby.load(Ordering::Relaxed)
    }

    /// F2 — send one STANDBY copy of a WG data datagram to `peer_pubkey`.
    /// Loss-tolerant like every DERP send: a down mux or a full queue drops
    /// the copy (`false`), while the direct original is still in flight.
    pub fn send_standby(&self, peer_pubkey: &DerpPubKey, datagram: &[u8]) -> bool {
        if !self.alive.load(Ordering::Relaxed) {
            return false;
        }
        let mut frame = Vec::with_capacity(32 + STANDBY_MAGIC.len() + datagram.len());
        frame.extend_from_slice(peer_pubkey);
        frame.extend_from_slice(STANDBY_MAGIC);
        frame.extend_from_slice(datagram);
        self.ws_out.try_send((Instant::now(), frame)).is_ok()
    }

    fn build_conn(
        &self,
        peer_pubkey: DerpPubKey,
        in_rx: mpsc::Receiver<Vec<u8>>,
        route: RouteKind,
        self_tx: mpsc::Sender<Vec<u8>>,
    ) -> DerpConn {
        DerpConn {
            peer_pubkey,
            ws_out: self.ws_out.clone(),
            inbound: AsyncMutex::new(in_rx),
            alive: Arc::clone(&self.alive),
            synth_local: synth_addr(&self.self_pubkey),
            synth_peer: synth_addr(&peer_pubkey),
            peers: Arc::clone(&self.peers),
            route,
            self_tx,
        }
    }

    /// This node's own DERP pubkey (the WG identity the mux registered with).
    pub fn self_pubkey(&self) -> DerpPubKey {
        self.self_pubkey
    }

    /// Route one inbound relay frame `[src_pubkey(32) || payload]` to the
    /// [`DerpConn`] registered for `src_pubkey`.
    ///
    /// #27 — the no-conn branch used to be a bare `if let Some(…)` with no
    /// `else`, and the queue-full branch a `let _ = try_send`: **two silent
    /// drops in four lines**, and the first of them was a 100 %-loss black
    /// hole. A peer only ever relays to us once it has DEMOTED to DERP (both
    /// ends prefer direct), so a frame arriving for a peer we hold no
    /// [`DerpConn`] for means *we have not followed it yet* — measured
    /// 2026-08-24 as **69 s** of mutual blackout on a VPN transition, because
    /// the far end had no netstate Major of its own and sat out
    /// `POKE_SILENCE_AFTER` + its tier deadline before demoting independently.
    ///
    /// So the miss is now REPORTED, not dropped in silence: the src pubkey goes
    /// to [`Self::subscribe_unrouted`] and the runtime follows that peer onto
    /// DERP. Trusting it is sound because the relay STAMPS `src_pubkey` from
    /// the sender's authenticated registration — it is not sender-chosen (see
    /// `api::ws::derp::forward_frame`) — so this can only name a node that is
    /// registered in this network and permitted by its ACL to reach us.
    ///
    /// The frame itself is still dropped: we have nowhere to put it, and WG
    /// retransmits. The signal, not the payload, is what matters.
    pub fn deliver(&self, frame: &[u8]) {
        if frame.len() < 32 {
            return;
        }
        let mut src = [0u8; 32];
        src.copy_from_slice(&frame[..32]);
        let payload = &frame[32..];
        // FR-90 P2d-2c — a Hive stream's frame goes to the route its tag
        // names, and nowhere else. A miss is counted, never `Unrouted`: that
        // event means a WG peer to follow onto DERP, and a Hive stream that
        // ended here first is nothing of the kind.
        if let Some(rest) = payload.strip_prefix(HIVE_MAGIC.as_slice()) {
            let tag: Option<HiveStreamTag> = rest
                .get(..std::mem::size_of::<HiveStreamTag>())
                .and_then(|t| t.try_into().ok());
            let tx = tag.and_then(|tag| {
                let peers = self.peers.lock().unwrap();
                peers.get(&src).and_then(|r| r.hive.get(&tag).cloned())
            });
            let delivered = tx.is_some_and(|tx| {
                tx.try_send(rest[std::mem::size_of::<HiveStreamTag>()..].to_vec())
                    .is_ok()
            });
            if !delivered {
                self.dropped_hive.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        // F2 — a STANDBY copy goes to the peer's standby sink and nowhere
        // else. A miss is counted, never `Unrouted`: its sender is still on
        // its direct carrier, merely suspecting it, so #27 must not follow.
        if let Some(rest) = payload.strip_prefix(STANDBY_MAGIC.as_slice()) {
            let tx = {
                let peers = self.peers.lock().unwrap();
                peers.get(&src).and_then(|r| r.standby.clone())
            };
            if tx.is_none_or(|tx| tx.try_send(rest.to_vec()).is_err()) {
                self.dropped_standby.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        // R4 split: a non-WG/non-disco payload goes to the peer's TUNNEL
        // consumer when one is registered. Tunnel drops are counted but
        // never emit `Unrouted` — that event means "peer demoted, follow it
        // onto DERP" and would send the overlay runtime chasing a carrier
        // condition that doesn't exist; QUIC's own loss recovery owns the
        // tunnel side.
        let (wg_tx, tunnel_tx) = {
            let peers = self.peers.lock().unwrap();
            match peers.get(&src) {
                Some(r) => (r.wg.clone(), r.tunnel.clone()),
                None => (None, None),
            }
        };
        // No tunnel consumer ⇒ pre-R4 behavior: everything falls through to
        // the WG route (boringtun discards non-WG bytes; the Unrouted
        // semantics below stay exactly as shipped in #27).
        if !payload_is_wg_or_disco(payload)
            && let Some(tx) = tunnel_tx
        {
            if tx.try_send(payload.to_vec()).is_err() {
                self.dropped_backpressure.fetch_add(1, Ordering::Relaxed);
                crate::evidence::DERP_INBOUND_BACKPRESSURE.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        match wg_tx {
            Some(tx) => {
                if tx.try_send(payload.to_vec()).is_err() {
                    // Full (the peer's carrier is not draining) or closed (the
                    // `DerpConn` was dropped when a better tier replaced this
                    // carrier — the registration outlives it by design, "last
                    // one wins"). A CLOSED channel is the same demote-lag
                    // condition as a missing one, so it reports too.
                    self.dropped_backpressure.fetch_add(1, Ordering::Relaxed);
                    crate::evidence::DERP_INBOUND_BACKPRESSURE.fetch_add(1, Ordering::Relaxed);
                    if !is_follow_control(payload) { self.emit(MuxEvent::Unrouted(src)); }
                }
            }
            None => {
                self.dropped_unrouted.fetch_add(1, Ordering::Relaxed);
                crate::evidence::DERP_INBOUND_UNROUTED.fetch_add(1, Ordering::Relaxed);
                if !is_follow_control(payload) { self.emit(MuxEvent::Unrouted(src)); }
            }
        }
    }

    /// Report a [`MuxEvent`], if anyone is listening. Never blocks and never
    /// errors: a full queue means a signal is already pending, which is
    /// exactly what this one would have said.
    fn emit(&self, ev: MuxEvent) {
        let tx = self.events_tx.lock().unwrap().clone();
        if let Some(tx) = tx {
            let _ = tx.try_send(ev);
        }
    }

    /// Mark the node WS down — subsequent `DerpConn::send_to` calls error so the
    /// carrier's `dead` latch fires and the sweep rebuilds. The first
    /// `mark_down` of an outage stamps `down_since`; repeats keep the
    /// original stamp so `down_for` measures the whole outage.
    pub fn mark_down(&self) {
        self.alive.store(false, Ordering::Relaxed);
        let mut since = self.down_since.lock().unwrap();
        if since.is_none() {
            *since = Some(Instant::now());
        }
    }

    /// Mark the node WS up again (after a reconnect + re-register).
    ///
    /// #28 — emits [`MuxEvent::Recovered`] on the down→up EDGE only. The WS
    /// owner calls this after every successful connect, including the first, so
    /// a level-triggered emit would fire a spurious walk at startup; `swap`
    /// makes the edge the condition rather than a comment.
    pub fn mark_up(&self) {
        let was_down = !self.alive.swap(true, Ordering::Relaxed);
        *self.down_since.lock().unwrap() = None;
        if was_down {
            self.emit(MuxEvent::Recovered);
        }
    }

    /// Whether the node WS is currently up.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// How long the WS has been down, or `None` while it is up.
    pub fn down_for(&self) -> Option<Duration> {
        if self.is_alive() {
            return None;
        }
        self.down_since.lock().unwrap().map(|t| t.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> DerpPubKey {
        [b; 32]
    }

    /// #32 — a route must not outlive the conn that consumes it. Once the last
    /// reference to a `DerpConn` goes, the next frame for that peer must be
    /// REPORTED (so the demote-follow can act) rather than routed into a queue
    /// nobody drains.
    ///
    /// The surviving-`Arc` shape is the one worth exercising: a carrier holds
    /// its conn behind an `Arc`, and until every clone is gone the conn is
    /// still a legitimate consumer.
    #[tokio::test]
    async fn a_dropped_conn_retires_its_route_even_with_a_live_arc() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let (tx, mut rx) = mpsc::channel(DerpMux::EVENT_SINK_DEPTH);
        mux.set_event_sink(tx);
        let base = mux.drop_counts();

        let carrier: Arc<DerpConn> = Arc::new(mux.conn_for(pk(0x02)));
        let survivor = Arc::clone(&carrier);

        // A WG frame (first byte 1..=4 ⇒ the WG/disco consumer).
        let mut frame = pk(0x02).to_vec();
        frame.extend_from_slice(&[1, 0, 0, 0]);
        mux.deliver(&frame);
        assert!(
            rx.try_recv().is_err(),
            "while the conn is live the frame routes and must stay silent"
        );

        drop(carrier); // the direct tier is promoted: the carrier is replaced…
        mux.deliver(&frame);
        assert!(
            rx.try_recv().is_err(),
            "a still-referenced conn is still a valid consumer"
        );

        drop(survivor); // …and now the last reference goes.
        mux.deliver(&frame);
        assert_eq!(
            rx.try_recv().ok(),
            Some(MuxEvent::Unrouted(pk(0x02))),
            "a retired route must make the next frame REPORT, not vanish"
        );
        assert_eq!(
            mux.drop_counts().0 - base.0,
            1,
            "and be counted as unrouted"
        );
    }

    #[tokio::test]
    async fn follow_control_miss_never_demotes_but_real_wg_still_reports_and_live_routes_work() {
        let (mux, _out) = DerpMux::new(pk(1));
        let (tx, mut events) = mpsc::channel(16); mux.set_event_sink(tx);
        let mut payload=vec![0u8;160];payload[..8].copy_from_slice(b"RMDISCO1");payload[8]=6;
        let frame=|body:&[u8]| {let mut f=pk(2).to_vec();f.extend_from_slice(body);f};
        mux.deliver(&frame(&payload));
        assert!(events.try_recv().is_err(), "late proof with no route carries no intent");
        mux.deliver(&frame(&[1,0,0,0]));
        assert_eq!(events.try_recv().unwrap(), MuxEvent::Unrouted(pk(2)));
        let conn=mux.conn_for(pk(2));
        mux.deliver(&frame(&payload));
        let mut buf=[0u8;256];let (n,_)=conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n],payload.as_slice(), "live owner must receive the proof for cryptographic checks");
        assert!(events.try_recv().is_err());
        // Backpressure is a drop, never a carrier decision for control bytes.
        for _ in 0..300 { mux.deliver(&frame(&payload)); }
        assert!(events.try_recv().is_err());
    }

    /// #32 — "last one wins" must survive the retirement, and the two consumers
    /// are INDEPENDENT. A rebuild registers the new conn before the old one
    /// drops, so a blind clear would unregister the live one; and a WG carrier
    /// going away must not take R4's tunnel route with it.
    #[tokio::test]
    async fn retirement_spares_a_rebuild_and_the_other_consumer() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let (tx, mut rx) = mpsc::channel(DerpMux::EVENT_SINK_DEPTH);
        mux.set_event_sink(tx);

        // (a) rebuild: old drops AFTER new registered ⇒ new survives.
        let old = mux.conn_for(pk(0x02));
        let new = mux.conn_for(pk(0x02));
        drop(old);
        let mut wg = pk(0x02).to_vec();
        wg.extend_from_slice(&[1, 0, 0, 0]);
        mux.deliver(&wg);
        assert!(rx.try_recv().is_err(), "the NEW route is live — no report");
        let mut buf = [0u8; 32];
        let (n, _) = new.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[1, 0, 0, 0], "and the frame reaches it");

        // (b) independence: dropping the WG conn must leave the tunnel route.
        let tunnel = mux.tunnel_conn_for(pk(0x02));
        drop(new);
        let mut quic = pk(0x02).to_vec();
        quic.extend_from_slice(&[0xC0, 1, 2, 3]); // QUIC long header ⇒ tunnel
        mux.deliver(&quic);
        let (n, _) = tunnel.recv_from(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            &[0xC0, 1, 2, 3],
            "the tunnel consumer must survive the WG carrier's retirement"
        );
    }

    fn frame(src: DerpPubKey, payload: &[u8]) -> Vec<u8> {
        let mut f = src.to_vec();
        f.extend_from_slice(payload);
        f
    }

    /// The local disco-magic copy must never drift from the canonical one —
    /// a drift would silently re-route disco frames into the tunnel consumer
    /// and break carrier liveness for exactly the peers using the derp leg.
    #[cfg(feature = "overlay")]
    #[test]
    fn disco_magic_matches_the_canonical_module() {
        assert_eq!(DISCO_MAGIC, crate::overlay::disco::MAGIC);
    }

    /// R4 — per-frame demux: WG (first byte 1..=4) and disco (8-byte magic)
    /// reach the WG consumer; QUIC-shaped payloads (short header 0x40+, long
    /// header 0xC0+) reach the TUNNEL consumer when registered. A QUIC short
    /// header may start with 0x52 ('R'), so the disco test is the full magic.
    #[tokio::test]
    async fn deliver_splits_wg_disco_and_tunnel_per_frame() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let peer = pk(0x02);
        let wg_conn = mux.conn_for(peer);
        let tun_conn = mux.tunnel_conn_for(peer);

        let wg_payload = [1u8, 0, 0, 0, 0xAA]; // WG handshake-init shape
        let quic_short = [0x52u8, 9, 9, 9, 9]; // 'R' but NOT the disco magic
        let quic_long = [0xC3u8, 0, 0, 0, 1];
        // #2002 — a short header whose fixed bit quinn greased, opening on a
        // WireGuard type byte; its connection ID follows.
        let quic_greased = [0x03u8, 0x9c, 0x41, 0x7e, 0x2d];
        let mut disco = DISCO_MAGIC.to_vec();
        disco.extend_from_slice(&[7; 24]);

        mux.deliver(&frame(peer, &wg_payload));
        mux.deliver(&frame(peer, &quic_short));
        mux.deliver(&frame(peer, &quic_long));
        mux.deliver(&frame(peer, &quic_greased));
        mux.deliver(&frame(peer, &disco));

        let mut buf = [0u8; 128];
        let (n, _) = wg_conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &wg_payload, "WG frame → WG consumer");
        let (n, _) = tun_conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &quic_short, "QUIC short header → tunnel");
        let (n, _) = tun_conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &quic_long, "QUIC long header → tunnel");
        // Bounded: read by its first byte alone, this frame went to the WG
        // consumer, and an unbounded read would wait for it forever.
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), tun_conn.recv_from(&mut buf))
            .await
            .expect("a greased QUIC short header → tunnel")
            .unwrap();
        assert_eq!(
            &buf[..n],
            &quic_greased,
            "a greased QUIC short header → tunnel"
        );
        let (n, _) = wg_conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &disco[..], "disco magic → WG consumer");
    }

    /// #2002 — WireGuard is its whole 4-byte header: each of its four
    /// message types with three zero bytes, and nothing that only shares the
    /// first byte. quinn greases QUIC's fixed bit by default, so a short
    /// header can open on 1..=4 too, and only its connection ID follows.
    #[test]
    fn only_a_wireguard_header_is_taken_for_wireguard() {
        for t in 1..=4u8 {
            assert!(
                payload_is_wg_or_disco(&[t, 0, 0, 0, 0xAA, 0xBB]),
                "WireGuard type {t}"
            );
            assert!(
                !payload_is_wg_or_disco(&[t, 0x9c, 0x41, 0x7e, 0x2d]),
                "a greased QUIC short header opening on {t}"
            );
            assert!(
                !payload_is_wg_or_disco(&[t, 0, 0, 1, 0x2d]),
                "type {t} with a nonzero reserved byte"
            );
        }
        assert!(!payload_is_wg_or_disco(&[1, 0, 0]), "a header cut short");
        assert!(!payload_is_wg_or_disco(&[0, 0, 0, 0, 1]), "type 0 is none");
        assert!(!payload_is_wg_or_disco(&[5, 0, 0, 0, 1]), "type 5 is none");
        let mut disco = DISCO_MAGIC.to_vec();
        disco.extend_from_slice(&[7; 24]);
        assert!(payload_is_wg_or_disco(&disco), "disco");
    }

    /// FR-90 P2d-2c — a Hive stream's payload, as it travels: the magic, its
    /// tag, then the packet.
    fn hive(tag: &HiveStreamTag, packet: &[u8]) -> Vec<u8> {
        let mut v = HIVE_MAGIC.to_vec();
        v.extend_from_slice(tag);
        v.extend_from_slice(packet);
        v
    }

    /// The next payload `conn` receives, within 2 s.
    async fn next(conn: &DerpConn) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), conn.recv_from(&mut buf))
            .await
            .expect("a payload within 2 s")
            .unwrap();
        buf[..n].to_vec()
    }

    /// Whether `conn` receives anything within 100 ms.
    async fn hears_anything(conn: &DerpConn) -> bool {
        let mut buf = [0u8; 256];
        tokio::time::timeout(Duration::from_millis(100), conn.recv_from(&mut buf))
            .await
            .is_ok()
    }

    /// FR-90 P2d-2c — a Hive conn frames each payload as
    /// `[peer || HIVE_MAGIC || tag || packet]`.
    /// F2 — a STANDBY copy reaches the peer's standby sink, magic stripped,
    /// and no other consumer; with no sink it is a counted drop that reports
    /// no `Unrouted` (#27 must not follow a suspicion); a WG conn retiring
    /// leaves the sink in place; `send_standby` frames
    /// `[peer || STANDBY_MAGIC || datagram]`.
    #[tokio::test]
    async fn a_standby_copy_reaches_only_the_standby_sink_and_never_reports_unrouted() {
        let (mux, mut out_rx) = DerpMux::new(pk(0x01));
        let (ev_tx, mut ev_rx) = mpsc::channel(DerpMux::EVENT_SINK_DEPTH);
        mux.set_event_sink(ev_tx);
        let peer = pk(0x02);
        let mut copy = STANDBY_MAGIC.to_vec();
        copy.extend_from_slice(&[4, 0, 0, 0, 9, 9]);

        mux.deliver(&frame(peer, &copy));
        assert_eq!(mux.standby_drops(), 1, "no sink yet: a counted drop");
        let mut sink = mux.standby_route(peer);
        let wg_conn = mux.conn_for(peer);
        mux.deliver(&frame(peer, &copy));
        assert_eq!(sink.recv().await.unwrap(), [4, 0, 0, 0, 9, 9]);
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), wg_conn.recv_from(&mut buf))
                .await
                .is_err(),
            "the WG consumer never sees a standby copy"
        );
        drop(wg_conn);
        mux.deliver(&frame(peer, &copy));
        assert_eq!(sink.recv().await.unwrap(), [4, 0, 0, 0, 9, 9], "the sink outlives the WG route");
        mux.clear_standby(&peer);
        mux.deliver(&frame(peer, &copy));
        assert_eq!(mux.standby_drops(), 2);
        assert!(ev_rx.try_recv().is_err(), "a standby copy never reports Unrouted");

        assert!(mux.send_standby(&peer, &[4, 1, 2]));
        let (_, f) = out_rx.recv().await.unwrap();
        let mut want = peer.to_vec();
        want.extend_from_slice(STANDBY_MAGIC);
        want.extend_from_slice(&[4, 1, 2]);
        assert_eq!(f, want);
        mux.mark_down();
        assert!(!mux.send_standby(&peer, &[4, 1, 2]), "a down mux drops the copy");
    }

    #[tokio::test]
    async fn a_hive_conn_frames_its_magic_and_its_tag() {
        let (mux, mut out_rx) = DerpMux::new(pk(0x01));
        let h = mux.hive_conn_for(pk(0x02), [9; 12]);
        h.send_to(&[0x41, 1, 2], h.synth_peer()).await.unwrap();
        let (_, f) = out_rx.recv().await.unwrap();
        let mut want = pk(0x02).to_vec();
        want.extend_from_slice(&hive(&[9; 12], &[0x41, 1, 2]));
        assert_eq!(f, want);
    }

    /// FR-90 P2d-2c — Hive streams to one peer carry by their tags, each its
    /// own packets with the header stripped; neither the WG nor the tunnel
    /// consumer sees a Hive frame, nor a Hive route the tunnel's; a frame for a
    /// tag nobody holds, or cut short, is dropped and counted, and reports no
    /// `Unrouted` (that event sends the overlay after a WG peer).
    #[tokio::test]
    async fn hive_streams_to_one_peer_carry_by_tag_and_apart() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let (ev_tx, mut ev_rx) = mpsc::channel(DerpMux::EVENT_SINK_DEPTH);
        mux.set_event_sink(ev_tx);
        let peer = pk(0x02);
        let wg_conn = mux.conn_for(peer);
        let tun_conn = mux.tunnel_conn_for(peer);
        let (t1, t2) = ([1u8; 12], [2u8; 12]);
        let h1 = mux.hive_conn_for(peer, t1);
        let h2 = mux.hive_conn_for(peer, t2);
        let quic = [0xC3u8, 0, 0, 0, 1];

        mux.deliver(&frame(peer, &hive(&t2, &quic)));
        mux.deliver(&frame(peer, &hive(&t1, &[0x41, 7, 7])));
        mux.deliver(&frame(peer, &quic));
        mux.deliver(&frame(peer, &hive(&[3; 12], &quic)));
        mux.deliver(&frame(peer, HIVE_MAGIC));

        assert_eq!(
            next(&h1).await,
            [0x41, 7, 7],
            "t1's packet, header stripped"
        );
        assert_eq!(next(&h2).await, quic, "t2's");
        assert_eq!(next(&tun_conn).await, quic, "the tunnel's own packet");
        assert!(!hears_anything(&tun_conn).await, "and no Hive frame");
        assert!(!hears_anything(&wg_conn).await, "the WG consumer sees none");
        assert!(!hears_anything(&h1).await && !hears_anything(&h2).await);
        assert_eq!(
            mux.hive_drops(),
            2,
            "a tag nobody holds, and a frame cut short"
        );
        assert!(ev_rx.try_recv().is_err(), "no Unrouted for a Hive miss");
    }

    /// FR-90 P2d-2c — a dropped Hive conn retires its own tag's route only: a
    /// newer conn for the same tag, the peer's other streams and its tunnel
    /// route stay, and the peer's entry goes with its last route.
    #[tokio::test]
    async fn a_hive_route_retires_alone() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let peer = pk(0x02);
        let tun_conn = mux.tunnel_conn_for(peer);
        let old = mux.hive_conn_for(peer, [1; 12]);
        let renewed = mux.hive_conn_for(peer, [1; 12]);
        let other = mux.hive_conn_for(peer, [2; 12]);
        drop(old);
        mux.deliver(&frame(peer, &hive(&[1; 12], &[0x41])));
        assert_eq!(next(&renewed).await, [0x41], "the newer conn for the tag");
        drop(renewed);
        mux.deliver(&frame(peer, &hive(&[1; 12], &[0x42])));
        mux.deliver(&frame(peer, &hive(&[2; 12], &[0x43])));
        mux.deliver(&frame(peer, &[0xC3, 1]));
        assert_eq!(mux.hive_drops(), 1, "the retired tag");
        assert_eq!(next(&other).await, [0x43], "the other stream");
        assert_eq!(next(&tun_conn).await, [0xC3, 1], "the tunnel route");
        drop(other);
        assert!(
            mux.peers.lock().unwrap().contains_key(&peer),
            "the tunnel's still"
        );
        drop(tun_conn);
        assert!(
            !mux.peers.lock().unwrap().contains_key(&peer),
            "the peer's entry goes with its last route"
        );

        // A peer with Hive routes only: one going leaves the other's.
        let first = mux.hive_conn_for(peer, [4; 12]);
        let last = mux.hive_conn_for(peer, [5; 12]);
        drop(first);
        mux.deliver(&frame(peer, &hive(&[5; 12], &[0x44])));
        assert_eq!(
            next(&last).await,
            [0x44],
            "a peer's last Hive route outlives the other"
        );
    }

    /// R4 — with NO tunnel consumer registered the mux behaves exactly as
    /// pre-R4: every payload (including QUIC-shaped ones) goes to the WG
    /// route, and misses report `Unrouted` as shipped in #27.
    #[tokio::test]
    async fn deliver_without_tunnel_consumer_is_pre_r4_behavior() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let peer = pk(0x02);
        let wg_conn = mux.conn_for(peer);

        let quic_short = [0x52u8, 9, 9, 9, 9];
        mux.deliver(&frame(peer, &quic_short));
        let mut buf = [0u8; 64];
        let (n, _) = wg_conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &quic_short, "no tunnel route ⇒ WG consumer");

        // An unknown peer still reports Unrouted (the #27 contract).
        let (ev_tx, mut ev_rx) = mpsc::channel(DerpMux::EVENT_SINK_DEPTH);
        mux.set_event_sink(ev_tx);
        mux.deliver(&frame(pk(0x03), &quic_short));
        assert_eq!(ev_rx.try_recv().unwrap(), MuxEvent::Unrouted(pk(0x03)));
    }

    /// Phase A1 — `down_for` measures the WHOLE outage (repeated
    /// `mark_down`s keep the original stamp) and clears on `mark_up`, so
    /// the evidence path can apply hysteresis without flap noise.
    #[test]
    fn down_for_spans_the_outage_and_clears_on_up() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        assert!(mux.is_alive());
        assert_eq!(mux.down_for(), None, "up ⇒ no outage duration");

        mux.mark_down();
        let first = mux.down_for().expect("down ⇒ Some(elapsed)");
        std::thread::sleep(Duration::from_millis(15));
        mux.mark_down(); // a repeat must NOT reset the stamp
        let later = mux.down_for().expect("still down");
        assert!(
            later >= first + Duration::from_millis(10),
            "repeated mark_down must keep the original outage start"
        );

        mux.mark_up();
        assert!(mux.is_alive());
        assert_eq!(mux.down_for(), None, "up again ⇒ cleared");
        mux.mark_down();
        assert!(
            mux.down_for().expect("fresh outage") < later,
            "a NEW outage restarts the clock"
        );
    }

    /// #27 — the black hole. A frame from a peer we hold NO conn for used to be
    /// dropped with no log, no counter and no signal; it is the 100 %-loss half
    /// of a one-sided demote to DERP (measured 69 s in the field). It must now
    /// report the src, and a routable frame must NOT report.
    #[tokio::test]
    async fn unroutable_inbound_reports_the_src_and_routable_does_not() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let (tx, mut rx) = mpsc::channel(DerpMux::EVENT_SINK_DEPTH);
        mux.set_event_sink(tx);

        // No conn for 0x02 — the demote-lag case.
        let mut frame = pk(0x02).to_vec();
        frame.extend_from_slice(&[1, 2, 3]);
        mux.deliver(&frame);
        assert_eq!(
            rx.try_recv().ok(),
            Some(MuxEvent::Unrouted(pk(0x02))),
            "unroutable src reported"
        );
        assert_eq!(mux.drop_counts().0, 1, "counted as unrouted");

        // A live conn for 0x03 — routed, and deliberately SILENT.
        let _conn = mux.conn_for(pk(0x03));
        let mut frame = pk(0x03).to_vec();
        frame.extend_from_slice(&[4, 5, 6]);
        mux.deliver(&frame);
        assert!(
            rx.try_recv().is_err(),
            "a routable frame must never look like a demote signal"
        );
        assert_eq!(mux.drop_counts(), (1, 0), "no new drops");

        // A short frame is malformed, not a demote signal.
        mux.deliver(&[0u8; 8]);
        assert!(rx.try_recv().is_err());
    }

    /// #28 — `mark_up` emits `Recovered` on the down→up EDGE only. The WS owner
    /// calls it after EVERY successful connect, including the first on a mux
    /// that starts alive, so a level-triggered emit would fire a pointless
    /// establish walk at every startup.
    #[tokio::test]
    async fn mark_up_emits_recovered_only_on_the_down_to_up_edge() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let (tx, mut rx) = mpsc::channel(DerpMux::EVENT_SINK_DEPTH);
        mux.set_event_sink(tx);

        // Startup shape: the mux is born alive and the WS owner marks it up.
        assert!(mux.is_alive());
        mux.mark_up();
        assert!(
            rx.try_recv().is_err(),
            "a mark_up that changes nothing must not wake the runtime"
        );

        // A real outage → recovery.
        mux.mark_down();
        assert!(rx.try_recv().is_err(), "going down is not a recovery");
        mux.mark_up();
        assert_eq!(rx.try_recv().ok(), Some(MuxEvent::Recovered));
        assert_eq!(mux.down_for(), None, "and the outage clock cleared");

        // Redundant repeats stay quiet.
        mux.mark_up();
        assert!(rx.try_recv().is_err());
    }

    /// #27/#32 — a peer whose DERP carrier was replaced by a better tier must
    /// report, or exactly the peers that once used DERP stay silently dark.
    ///
    /// ⚠️ The CLASSIFICATION changed with #32, and that is the point. It used
    /// to land in the closed-channel (backpressure) branch, because the route
    /// outlived its conn and `deliver` only noticed when `try_send` failed. The
    /// route is now retired on drop, so this is a genuine MISS — which is also
    /// the only shape that reports when something still holds an `Arc` to the
    /// conn and the channel therefore is not closed at all.
    #[tokio::test]
    async fn a_replaced_carrier_reports_as_unrouted() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let (tx, mut rx) = mpsc::channel(DerpMux::EVENT_SINK_DEPTH);
        mux.set_event_sink(tx);
        let base = mux.drop_counts();

        let conn = mux.conn_for(pk(0x02));
        drop(conn); // a better tier replaced this carrier

        let mut frame = pk(0x02).to_vec();
        frame.extend_from_slice(&[1]);
        mux.deliver(&frame);

        assert_eq!(rx.try_recv().ok(), Some(MuxEvent::Unrouted(pk(0x02))));
        let now = mux.drop_counts();
        assert_eq!(
            (now.0 - base.0, now.1 - base.1),
            (1, 0),
            "the route is retired, so this is a MISS — not backpressure"
        );
    }

    #[tokio::test]
    async fn deliver_routes_by_src_and_conn_receives_payload() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let conn = mux.conn_for(pk(0x02)); // pinned to peer 0x02

        // A frame from peer 0x02 → routed to this conn as raw payload.
        let mut frame = pk(0x02).to_vec();
        frame.extend_from_slice(&[9, 8, 7]);
        mux.deliver(&frame);

        let mut buf = [0u8; 64];
        let (n, src) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[9, 8, 7]);
        assert_eq!(src, synth_addr(&pk(0x02)), "recv tagged with the peer addr");
    }

    #[tokio::test]
    async fn send_to_frames_peer_pubkey_prefix() {
        let (mux, mut out_rx) = DerpMux::new(pk(0x01));
        let conn = mux.conn_for(pk(0x02));

        conn.send_to(&[1, 2, 3], "127.0.0.1:9".parse().unwrap())
            .await
            .unwrap();

        let (queued_at, framed) = out_rx.recv().await.unwrap();
        assert_eq!(&framed[..32], &pk(0x02), "outbound frame targets the peer");
        assert_eq!(&framed[32..], &[1, 2, 3]);
        // FR-18 — the enqueue stamp is what lets the WS writer shed stale
        // frames; a frame that arrives without one cannot be aged out.
        assert!(queued_at.elapsed() < Duration::from_secs(5));
    }

    /// FR-18 — the queue-age bound is the kill switch AND the latency
    /// contract, so both ends of it are locked here rather than left to the
    /// deployment to discover.
    #[test]
    fn queue_max_age_defaults_on_and_zero_disables() {
        // Default (no env set in the test process): the bound is active and
        // small enough to matter on a 3 Mbps relay.
        let d = queue_max_age().expect("age bound on by default");
        assert!(
            d >= Duration::from_millis(20) && d <= Duration::from_millis(500),
            "default {d:?} is outside the useful band"
        );
    }

    #[tokio::test]
    async fn send_to_errors_when_ws_down_so_dead_latch_fires() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let conn = mux.conn_for(pk(0x02));
        mux.mark_down();
        let err = conn
            .send_to(&[1], "127.0.0.1:9".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn deliver_drops_unknown_src_and_short_frame() {
        let (mux, _out_rx) = DerpMux::new(pk(0x01));
        let _conn = mux.conn_for(pk(0x02));
        // Unknown src 0x03 → dropped (no panic, no delivery).
        let mut frame = pk(0x03).to_vec();
        frame.extend_from_slice(&[1]);
        mux.deliver(&frame);
        // Short frame (< 32) → dropped.
        mux.deliver(&[0u8; 10]);
    }

    #[test]
    fn synth_addr_is_v4_nonzero_port_and_peer_unique() {
        let a = synth_addr(&pk(0xAA));
        let b = synth_addr(&{
            let mut k = pk(0xAA);
            k[4] = 0x01; // differ in a byte the port derives from
            k
        });
        assert!(a.is_ipv4() && a.port() != 0);
        assert_ne!(a, b, "distinct pubkeys → distinct synthetic addrs");
    }
}

